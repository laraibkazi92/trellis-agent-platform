# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for the per-user agent-memory isolation option.

Covers:
  - MemoryManager.is_isolated_per_user(): TTL caching + fail-open to the shared bank on etcd read errors.
  - MemoryManager.bank_for(): shared agent bank vs "{agent}:{user}" keyed bank, and the
    degradation to the shared bank when no user identity is in scope (workflow/system runs).
  - recall/retain round-trips carrying the isolated bank id into the Hindsight client.
  - build_agent()'s recall instruction resolving the bank AT RECALL TIME from user_id_var,
    so flipping the flag applies to already-cached agents once the TTL expires.
  - The /admin/feature-flags/agent-memory-isolation toggle endpoint and dashboard state.

All Hindsight/etcd interaction is faked, following tests/test_memory.py,
tests/test_agent_delegation_access.py, and tests/test_admin_agent_visibility.py —
nothing here touches the network.
"""

import asyncio
from types import SimpleNamespace

import core.memory as memory_mod
from core import agent_factory, host
from core.auth import user_id_var
from core.memory import (
    MEMORY_FLAG_KEY,
    MEMORY_ISOLATION_FLAG_KEY,
    MemoryManager,
    _FLAG_TTL_SECONDS,
)
from core.routers import admin


class _FakeIdentityMgr:
    """Sync identity manager fake: only get_config is needed for flag gating."""

    def __init__(self, config=None, error=None):
        self.config = config or {}
        self.error = error
        self.get_config_calls = []

    def get_config(self, key, default=None):
        self.get_config_calls.append((key, default))
        if self.error is not None:
            raise self.error
        return self.config.get(key, default)


class _FakeHindsight:
    """Fake Hindsight client exposing the async arecall/aretain surface."""

    def __init__(self, recall_response=None):
        self.recall_response = recall_response
        self.recall_calls = []
        self.retain_calls = []

    async def arecall(self, **kwargs):
        self.recall_calls.append(kwargs)
        return self.recall_response

    async def aretain(self, **kwargs):
        self.retain_calls.append(kwargs)


def _patch_client(monkeypatch, client):
    monkeypatch.setattr(MemoryManager, "_get_client", lambda self: client)


def _isolated_mgr(config=None):
    return MemoryManager(_FakeIdentityMgr(config=config))


# --- Feature gating: is_isolated_per_user --------------------------------------

def test_isolation_flag_defaults_off():
    assert _isolated_mgr().is_isolated_per_user() is False


def test_isolation_flag_true_when_set():
    mgr = _isolated_mgr(config={MEMORY_ISOLATION_FLAG_KEY: True})
    assert mgr.is_isolated_per_user() is True
    assert mgr._identity_mgr.get_config_calls == [(MEMORY_ISOLATION_FLAG_KEY, False)]


def test_isolation_flag_cached_within_ttl(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(memory_mod.time, "monotonic", lambda: clock["t"])
    mgr = _isolated_mgr(config={MEMORY_ISOLATION_FLAG_KEY: True})

    assert mgr.is_isolated_per_user() is True
    clock["t"] += _FLAG_TTL_SECONDS - 1.0  # still inside the TTL window
    assert mgr.is_isolated_per_user() is True
    assert len(mgr._identity_mgr.get_config_calls) == 1  # second call served from cache


def test_isolation_flag_cache_expires_after_ttl(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(memory_mod.time, "monotonic", lambda: clock["t"])
    ident = _FakeIdentityMgr(config={MEMORY_ISOLATION_FLAG_KEY: True})
    mgr = MemoryManager(ident)

    assert mgr.is_isolated_per_user() is True
    clock["t"] += _FLAG_TTL_SECONDS + 1.0
    ident.config[MEMORY_ISOLATION_FLAG_KEY] = False  # admin toggled isolation off
    assert mgr.is_isolated_per_user() is False  # re-read after TTL expiry
    assert len(ident.get_config_calls) == 2


def test_isolation_flag_fails_open_to_shared_bank_on_etcd_read_error():
    mgr = MemoryManager(_FakeIdentityMgr(error=RuntimeError("etcd unavailable")))
    assert mgr.is_isolated_per_user() is False
    # The failed read is cached too: a second rapid call stays False without re-raising.
    assert mgr.is_isolated_per_user() is False
    assert len(mgr._identity_mgr.get_config_calls) == 1


# --- Bank selection: bank_for ---------------------------------------------------

def test_bank_for_returns_agent_name_when_isolation_off():
    mgr = _isolated_mgr()
    assert mgr.bank_for("agent-a", "user-1") == "agent-a"


def test_bank_for_combines_agent_and_user_when_isolation_on():
    mgr = _isolated_mgr(config={MEMORY_ISOLATION_FLAG_KEY: True})
    assert mgr.bank_for("agent-a", "user-1") == "agent-a:user-1"


def test_bank_for_degrades_to_shared_bank_without_user():
    """A missing/empty user identity cannot key a private bank and degrades to the
    shared agent bank (workflow identities like svc_agent_*/webhook are truthy and
    get their own workflow-keyed bank instead)."""
    mgr = _isolated_mgr(config={MEMORY_ISOLATION_FLAG_KEY: True})
    assert mgr.bank_for("agent-a", None) == "agent-a"
    assert mgr.bank_for("agent-a", "") == "agent-a"


# --- recall/retain carry the isolated bank into the client ----------------------

def test_recall_carries_isolated_bank_id(monkeypatch):
    client = _FakeHindsight(recall_response=[{"text": "private fact"}])
    _patch_client(monkeypatch, client)
    mgr = _isolated_mgr(config={MEMORY_ISOLATION_FLAG_KEY: True})

    out = asyncio.run(mgr.recall(bank=mgr.bank_for("agent-a", "user-1"), query="q"))

    assert out == "## Relevant context from past interactions\n- private fact"
    assert client.recall_calls[0]["bank_id"] == "agent-a:user-1"


def test_retain_carries_isolated_bank_id(monkeypatch):
    client = _FakeHindsight()
    _patch_client(monkeypatch, client)
    mgr = _isolated_mgr(config={MEMORY_ISOLATION_FLAG_KEY: True})

    asyncio.run(mgr.retain(bank=mgr.bank_for("agent-a", "user-1"), user_msg="q", agent_output="a"))

    assert client.retain_calls[0]["bank_id"] == "agent-a:user-1"


# --- build_agent recall instruction: recall-time bank resolution -----------------

MEMORY_AGENT_CONFIG = {
    "name": "memory-agent",
    "model": "gemini-3-flash-preview",
    "thinking_level": "medium",
    "agent_memory": True,
}


class FakeBuildIdentity:
    """Covers the config/skills reads build_agent() makes for a plain user agent."""

    def get_agent_config(self, name):
        return dict(MEMORY_AGENT_CONFIG) if name == "memory-agent" else None

    def get_agent_skills(self, name):
        return ""


class FakeBuiltAgent:
    """Stand-in for pydantic_ai.Agent that captures the @agent.instructions callback,
    which is the recall closure under test (same pattern as
    tests/test_agent_delegation_access.py, plus instruction capture)."""

    def __init__(self, model, **kwargs):
        self.kwargs = kwargs
        self._function_toolset = SimpleNamespace(add_tool=lambda *a, **k: None)
        self.instruction_funcs = []

    def instructions(self, func):
        self.instruction_funcs.append(func)
        return func

    def tool(self, name=None, description=None):
        def decorator(f):
            return f
        return decorator


def _setup_build_agent(monkeypatch, flag_identity):
    """Hermetic build_agent() harness (mirrors _setup_build_agent_common in
    tests/test_agent_delegation_access.py) that wires a REAL MemoryManager over fakes."""
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.setattr(agent_factory, "_hub_tools_cache", [], raising=False)
    monkeypatch.setattr(agent_factory, "_external_mcp_tools", {}, raising=False)
    monkeypatch.setattr(agent_factory, "Agent", FakeBuiltAgent)
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeBuildIdentity())

    async def fake_get_hub_client():
        return object()

    async def fake_discover_external_mcps(force=False):
        return None

    monkeypatch.setattr(agent_factory, "get_hub_client", fake_get_hub_client)
    monkeypatch.setattr(agent_factory, "discover_external_mcps", fake_discover_external_mcps)

    mgr = MemoryManager(flag_identity)
    monkeypatch.setattr(memory_mod, "get_memory_manager", lambda: mgr)
    return mgr


def _recall_closure(monkeypatch, flag_identity):
    client = _FakeHindsight(recall_response=[{"text": "remembered"}])
    _patch_client(monkeypatch, client)
    mgr = _setup_build_agent(monkeypatch, flag_identity)

    agent = asyncio.run(agent_factory.build_agent("memory-agent"))
    assert len(agent.instruction_funcs) == 1  # memory branch wired at build time
    return mgr, client, agent.instruction_funcs[0]


def test_recall_closure_uses_isolated_bank_for_current_user(monkeypatch):
    ident = _FakeIdentityMgr(config={
        MEMORY_FLAG_KEY: True,
        MEMORY_ISOLATION_FLAG_KEY: True,
    })
    _, client, recall = _recall_closure(monkeypatch, ident)

    ctx = SimpleNamespace(prompt="what did we decide?", messages=[])
    token = user_id_var.set("user-7")
    try:
        out = asyncio.run(recall(ctx))
    finally:
        user_id_var.reset(token)

    assert out == "## Relevant context from past interactions\n- remembered"
    assert client.recall_calls[0]["bank_id"] == "memory-agent:user-7"


def test_recall_closure_uses_shared_bank_when_isolation_off(monkeypatch):
    ident = _FakeIdentityMgr(config={MEMORY_FLAG_KEY: True})
    _, client, recall = _recall_closure(monkeypatch, ident)

    token = user_id_var.set("user-7")
    try:
        asyncio.run(recall(SimpleNamespace(prompt="q", messages=[])))
    finally:
        user_id_var.reset(token)

    assert client.recall_calls[0]["bank_id"] == "memory-agent"


def test_recall_closure_resolves_bank_at_recall_time_not_build_time(monkeypatch):
    """The bank must not be frozen at build time: an admin flipping the isolation flag
    applies to a cached agent on the next recall once the flag TTL expires."""
    clock = {"t": 100.0}
    monkeypatch.setattr(memory_mod.time, "monotonic", lambda: clock["t"])
    ident = _FakeIdentityMgr(config={MEMORY_FLAG_KEY: True})
    _, client, recall = _recall_closure(monkeypatch, ident)

    token = user_id_var.set("user-7")
    try:
        asyncio.run(recall(SimpleNamespace(prompt="q", messages=[])))
        assert client.recall_calls[-1]["bank_id"] == "memory-agent"  # shared at build time

        ident.config[MEMORY_ISOLATION_FLAG_KEY] = True  # flag flips post-build
        clock["t"] += _FLAG_TTL_SECONDS + 1.0  # flag cache expires
        asyncio.run(recall(SimpleNamespace(prompt="q2", messages=[])))
        assert client.recall_calls[-1]["bank_id"] == "memory-agent:user-7"
    finally:
        user_id_var.reset(token)


def test_recall_closure_falls_back_to_shared_bank_without_user(monkeypatch):
    """Without a user identity the isolated closure still recalls — from the shared bank
    (isolation degrades instead of disabling memory)."""
    ident = _FakeIdentityMgr(config={
        MEMORY_FLAG_KEY: True,
        MEMORY_ISOLATION_FLAG_KEY: True,
    })
    _, client, recall = _recall_closure(monkeypatch, ident)

    token = user_id_var.set(None)
    try:
        asyncio.run(recall(SimpleNamespace(prompt="q", messages=[])))
    finally:
        user_id_var.reset(token)

    assert client.recall_calls[0]["bank_id"] == "memory-agent"


# --- host.py sync retain wiring --------------------------------------------------

class RecordingMemoryManager:
    def __init__(self):
        self.bank_for_calls = []
        self.retain_calls = []

    def active_for(self, cfg):
        return True

    def bank_for(self, agent_name, user_id):
        self.bank_for_calls.append((agent_name, user_id))
        return f"{agent_name}:{user_id}" if user_id else agent_name

    async def retain(self, bank, user_msg, agent_output):
        self.retain_calls.append((bank, user_msg, agent_output))


class _FakeHostIdentity:
    def get_disabled_standard_agents(self):
        return []

    def get_agent_config(self, name):
        return {"name": "general-agent", "type": "user_agent", "external": True, "allowed_tools": []}

    def record_agent_run_state(self, agent_name, run_id, state, metadata):
        return True

    def record_usage(self, user_id, input_tokens, output_tokens):
        pass

    def record_agent_usage(self, user_id, agent_name, input_tokens, output_tokens):
        pass


class _FakeHostHealth:
    def get_status(self, entity_type, name):
        return {"status": "Online"}

    def record_event(self, *args, **kwargs):
        pass


class _FakeHostAgent:
    async def run(self, prompt, message_history=None, deps=None):
        return SimpleNamespace(output="general reply", usage=None)


def _run_sync_chat(monkeypatch, fake_mem, user_id):
    monkeypatch.setattr(host, "identity_mgr", _FakeHostIdentity())

    async def fake_get_agent(name):
        return _FakeHostAgent()

    monkeypatch.setattr(host, "get_agent", fake_get_agent)
    monkeypatch.setattr(host, "health_monitor", _FakeHostHealth())
    monkeypatch.setattr(host, "get_memory_manager", lambda: fake_mem)

    token = user_id_var.set(user_id)
    try:
        request = host.ChatRequest(
            model="general-agent",
            messages=[host.ChatMessage(role="user", content="What's the status?")],
        )

        async def scenario():
            response = await host.chat_completions(request)
            await host._drain_background_tasks(timeout=1.0)  # let the spawned retain run
            return response

        return asyncio.run(scenario())
    finally:
        user_id_var.reset(token)


def test_sync_retain_uses_bank_for_with_request_user(monkeypatch):
    fake_mem = RecordingMemoryManager()

    response = _run_sync_chat(monkeypatch, fake_mem, user_id="user-1")

    assert response["choices"][0]["message"]["content"] == "general reply"
    assert fake_mem.bank_for_calls == [("general-agent", "user-1")]
    assert fake_mem.retain_calls == [("general-agent:user-1", "What's the status?", "general reply")]


def test_sync_retain_degrades_to_shared_bank_without_user(monkeypatch):
    fake_mem = RecordingMemoryManager()

    _run_sync_chat(monkeypatch, fake_mem, user_id=None)

    assert fake_mem.bank_for_calls == [("general-agent", None)]
    assert fake_mem.retain_calls[0][0] == "general-agent"


# --- Admin toggle endpoint + dashboard state -------------------------------------

class FakeAdminIdentity:
    """In-memory stand-in for the flag reads/writes the admin router uses."""

    BRANDING_KEYS = (
        "name",
        "favicon_url",
        "logo_url",
        "login_logo_url",
        "login_title",
        "login_subtitle",
        "login_disclaimer",
        "accent_color",
        "accent_color_dark",
    )

    def __init__(self, agent_memory_enabled=False, isolated=False):
        self.flags = {
            "agent_memory_enabled": agent_memory_enabled,
            "agent_memory_isolated_per_user": isolated,
        }
        self.tunables = {}

    def list_all_users(self):
        return []

    def list_all_keys(self):
        return []

    def list_agents(self):
        return []

    def get_agent_memory_enabled(self):
        return self.flags["agent_memory_enabled"]

    def get_agent_memory_isolated_per_user(self):
        return self.flags["agent_memory_isolated_per_user"]

    def set_agent_memory_isolated_per_user(self, enabled):
        self.flags["agent_memory_isolated_per_user"] = bool(enabled)

    def get_rules_evaluation_timeout(self):
        return None

    def get_rules_evaluation_model(self):
        return None

    def get_rules_evaluation_provider(self):
        return None

    def get_rules_evaluation_base_url(self):
        return None

    def get_rules_confidence_threshold(self):
        return None

    def get_branding(self, key):
        return None

    def get_tunable(self, name):
        return self.tunables.get(name)

    def set_tunable(self, name, value):
        self.tunables[name] = value

    def clear_tunable(self, name):
        self.tunables.pop(name, None)


class FakeAdminRequest:
    def __init__(self, session=None):
        self.session = session if session is not None else {}


def _admin_session():
    return {"user": {"email": "admin@example.com"}}


def test_toggle_agent_memory_isolation_persists_and_redirects(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeAdminIdentity()
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeAdminRequest(session=_admin_session())
    response = asyncio.run(admin.toggle_agent_memory_isolation(request, enabled="true"))

    assert fake_identity.flags["agent_memory_isolated_per_user"] is True
    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    assert "isolation enabled" in request.session["flash_msg"]


def test_toggle_agent_memory_isolation_requires_admin(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeAdminIdentity()
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeAdminRequest(session={"user": {"email": "not-admin@example.com"}})
    response = asyncio.run(admin.toggle_agent_memory_isolation(request, enabled="true"))

    assert response.status_code == 303
    assert fake_identity.flags["agent_memory_isolated_per_user"] is False
    assert request.session["flash_msg"] == "Unauthorized access."


def test_admin_dashboard_supplies_and_renders_isolation_flag_state(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeAdminIdentity(agent_memory_enabled=True, isolated=True)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    captured = {}

    def fake_template_response(request=None, name=None, context=None):
        captured["name"] = name
        captured["context"] = context
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(admin.templates, "TemplateResponse", fake_template_response)

    request = FakeAdminRequest(session=_admin_session())
    asyncio.run(admin.admin_dashboard(request))

    assert captured["name"] == "admin.html"
    assert captured["context"]["feature_flags"] == {
        "agent_memory_enabled": True,
        "agent_memory_isolated_per_user": True,
    }

    html = admin.templates.env.get_template("admin.html").render(
        request=SimpleNamespace(url=SimpleNamespace(path="/admin")),
        csrf_token="test-csrf",
        **captured["context"],
    )
    assert 'action="/admin/feature-flags/agent-memory-isolation"' in html
    assert "Per-User Memory Isolation" in html
