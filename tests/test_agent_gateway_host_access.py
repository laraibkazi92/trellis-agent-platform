"""Tests for Phase 2 (Gateway MCP & Host API Enforcement) — see
__spec_docs/internal_external_agents_spec.md.

Covers:
  - core.agent_search.search_agents excluding external: False agents from candidates
    (both the embedding-ranked path and the keyword fallback path).
  - core.gateway._get_visible_agents omitting external: False agents.
  - core.gateway.use_agent returning the exact access-denied string for external: False.
  - core.host chat_completions raising 403 with the exact detail message for
    external: False, and proceeding normally for external: True.
"""
import asyncio
from types import SimpleNamespace

import pytest

from core import agent_search
from core import gateway
from core import host
from core.auth import user_id_var


# --- core.agent_search.search_agents ----------------------------------------

class FakeIdentityManagerSearch:
    def __init__(self, agent_configs):
        self._agent_configs = agent_configs

    def get_all_agent_configs(self):
        return dict(self._agent_configs)

    def get_all_agent_embeddings(self):
        return {}

    def get_disabled_standard_agents(self):
        return []

    def get_all_health_statuses(self, kind):
        return {}


def test_search_agents_excludes_external_false_keyword_fallback(monkeypatch):
    fake_identity = FakeIdentityManagerSearch({
        "general-agent": {"name": "general-agent", "description": "handles general requests", "type": "user_agent"},
        "data-parser": {
            "name": "data-parser",
            "description": "parses raw input",
            "type": "user_agent",
            "external": False,
        },
    })
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: None)

    results = asyncio.run(agent_search.search_agents("general requests", limit=0))

    names = [r["name"] for r in results]
    assert "general-agent" in names
    assert "data-parser" not in names


def test_search_agents_excludes_external_false_embedding_path(monkeypatch):
    fake_identity = FakeIdentityManagerSearch({
        "general-agent": {"name": "general-agent", "description": "handles general requests", "type": "user_agent"},
        "data-parser": {
            "name": "data-parser",
            "description": "parses raw input",
            "type": "user_agent",
            "external": False,
        },
    })
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0 if b else 0.0)

    results = asyncio.run(agent_search.search_agents("general requests", limit=0))

    names = [r["name"] for r in results]
    assert "general-agent" in names
    assert "data-parser" not in names


def test_search_agents_includes_external_true_normally(monkeypatch):
    fake_identity = FakeIdentityManagerSearch({
        "general-agent": {"name": "general-agent", "description": "handles general requests", "type": "user_agent", "external": True},
    })
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: None)

    results = asyncio.run(agent_search.search_agents("general requests", limit=0))

    assert [r["name"] for r in results] == ["general-agent"]


# --- core.gateway._get_visible_agents ----------------------------------------

class FakeHTTPResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class FakeHTTPClient:
    def __init__(self, payload):
        self._payload = payload

    async def get(self, url, timeout=None):
        return FakeHTTPResponse(200, self._payload)


def test_get_visible_agents_omits_external_false(monkeypatch):
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
        {"name": "data-parser", "description": "parses input", "type": "user_agent", "is_configured": True, "external": False},
    ]

    async def fake_discover_agents(user_id=None):
        return discovered

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)
    monkeypatch.setattr(gateway.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient({"agents": {
            "general-agent": {"status": "Online"},
            "data-parser": {"status": "Online"},
        }})
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents())

    names = [a["name"] for a in visible]
    assert "general-agent" in names
    assert "data-parser" not in names


# --- core.gateway.use_agent ---------------------------------------------------

def _patch_no_call(monkeypatch, target, attr):
    async def _fail(*args, **kwargs):
        raise AssertionError(f"{attr} should not have been called")
    monkeypatch.setattr(target, attr, _fail)


class FakeContext:
    def __init__(self):
        self.progress_messages = []

    async def report_progress(self, current=None, total=None, message=None):
        self.progress_messages.append(message)


def test_use_agent_denies_external_false(monkeypatch):
    monkeypatch.setattr(gateway.identity_mgr, "get_agent_config", lambda name: {"name": name, "external": False})
    _patch_no_call(monkeypatch, gateway, "is_agent_configured")

    ctx = FakeContext()
    result = asyncio.run(gateway.use_agent(ctx, "data-parser", "parse this"))

    assert result == "SYSTEM: Access denied. Agent 'data-parser' is internal and cannot be called directly."


def test_use_agent_allows_external_true(monkeypatch):
    monkeypatch.setattr(gateway.identity_mgr, "get_agent_config", lambda name: {"name": name, "external": True})

    async def fake_is_agent_configured(agent_name, user_id):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    monkeypatch.setattr(gateway, "is_agent_configured", fake_is_agent_configured)

    class FakeStreamResponse:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def raise_for_status(self):
            pass

        async def aiter_lines(self):
            import json as _json
            yield _json.dumps({"choices": [{"message": {"content": "hello there"}}]})

    class FakeHTTPStreamClient:
        def stream(self, method, url, **kwargs):
            return FakeStreamResponse()

    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(http_client=FakeHTTPStreamClient())), raising=False)

    ctx = FakeContext()
    result = asyncio.run(gateway.use_agent(ctx, "general-agent", "hello"))

    assert result == "hello there"


# --- core.host chat_completions -----------------------------------------------

def _make_request(model):
    return host.ChatRequest(model=model, messages=[host.ChatMessage(role="user", content="hi")])


def test_chat_completions_denies_external_false(monkeypatch):
    monkeypatch.setattr(host.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(host.identity_mgr, "get_agent_config", lambda name: {"name": name, "type": "user_agent", "external": False})
    _patch_no_call(monkeypatch, host, "get_agent")

    request = _make_request("data-parser")

    with pytest.raises(host.HTTPException) as exc_info:
        asyncio.run(host.chat_completions(request))

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Access denied: Agent 'data-parser' is internal and cannot be called directly."


def test_chat_completions_exempts_supervisor(monkeypatch):
    monkeypatch.setattr(host.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(host.identity_mgr, "get_agent_config", lambda name: {"name": name, "type": "user_agent", "external": False})
    monkeypatch.setattr(host.health_monitor, "get_status", lambda kind, name: {"status": "Online"})
    monkeypatch.setattr(host.health_monitor, "record_event", lambda *a, **k: None)

    class FakeResult:
        output = "supervisor reply"
        usage = None

    async def fake_get_agent(name):
        class FakeAgent:
            async def run(self, *a, **k):
                return FakeResult()
        return FakeAgent()

    monkeypatch.setattr(host, "get_agent", fake_get_agent)

    import core.memory as memory_module
    monkeypatch.setattr(memory_module, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False))

    request = _make_request("supervisor")

    result = asyncio.run(host.chat_completions(request))

    assert result["choices"][0]["message"]["content"] == "supervisor reply"


def test_chat_completions_allows_external_true(monkeypatch):
    monkeypatch.setattr(host.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(host.identity_mgr, "get_agent_config", lambda name: {"name": name, "type": "user_agent", "external": True})
    monkeypatch.setattr(host.health_monitor, "get_status", lambda kind, name: {"status": "Online"})
    monkeypatch.setattr(host.health_monitor, "record_event", lambda *a, **k: None)

    class FakeResult:
        output = "general reply"
        usage = None

    async def fake_get_agent(name):
        class FakeAgent:
            async def run(self, *a, **k):
                return FakeResult()
        return FakeAgent()

    monkeypatch.setattr(host, "get_agent", fake_get_agent)

    import core.memory as memory_module
    monkeypatch.setattr(memory_module, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False))

    request = _make_request("general-agent")

    result = asyncio.run(host.chat_completions(request))

    assert result["choices"][0]["message"]["content"] == "general reply"
