# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for Phase 2 of __spec_docs/cycle4_hub_agent_factory_hardening_plan.md.

Covers core/agent_factory.py hardening:
  - Task 2.1 (C4a): the tool wrappers built by `_register_mcp_tool` and the
    `HUB_URL` read in `get_hub_client()` run their sync health/etcd calls via
    `asyncio.to_thread` (off the event-loop thread).
  - Task 2.2 (C4b): `FrameworkAgentRegistry.get_compiled()` reads a pre-built
    in-memory eligibility snapshot instead of making sync etcd calls per
    dispatch; snapshot refreshes are fail-open.
  - Task 2.3 (C5): `manage_agent` rejects unknown actions, evicts the cache on
    "reload", and leaves the cache alone on "enable".

All tests are hermetic: every etcd-backed seam (`get_identity_manager`,
`get_health_monitor`, `get_hub_client`, `FastMCPClient`) is monkeypatched and
`_agent_cache` / `_supervisor_registry` are replaced with fresh objects.
"""
import asyncio
import copy
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from core import agent_factory, tool_access
from core.auth import user_id_var
from core.models import MCPToolDefinition
from subagents_pydantic_ai import SubAgentConfig


# --- shared fakes ------------------------------------------------------------


def _grant_bound_tool(monkeypatch, *tools, agent="supervisor", groups=()):
    """Give the run a verified token whose agent's allowlist names the bound tools.

    The bound-tool gate is the evaluator now, so a wrapper test needs both halves:
    a run token (agent + groups) and the agent record whose allowlist grants the
    target. No policy document means no group rules.
    """
    from core import auth, agent_token, tool_access

    class _NoPolicy:
        def put(self, key, value):
            raise AssertionError(f"no write expected: {key}")

        def get(self, key, **_kwargs):
            return None, None

    monkeypatch.setenv("AGENT_TOKEN_SECRET", "bound-tool-unit-secret-0123456789abcdef")
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    monkeypatch.setattr(tool_access, "_client", lambda: _NoPolicy())
    tool_access.reset_snapshot()
    monkeypatch.setattr(
        auth,
        "get_identity_manager",
        lambda: SimpleNamespace(get_agent_config=lambda name: {"allowed_tools": list(tools)}),
    )
    agent_token.mint_for_run(agent, "user-1", run_id="run-health", groups=groups)

class FakeAgent:
    """Stand-in for pydantic_ai.Agent that captures @agent.tool_plain-decorated
    coroutine functions into a plain dict (same pattern as
    tests/test_supervisor_two_tier.py)."""

    def __init__(self):
        self.tools: Dict[str, Any] = {}

    def tool_plain(self, name=None, description=None):
        def decorator(func):
            self.tools[name or func.__name__] = func
            return func
        return decorator


def _build_fake_agent() -> FakeAgent:
    fake_agent = FakeAgent()
    agent_factory._register_admin_tools(fake_agent)
    return fake_agent


class FakeHealthMonitor:
    def get_status(self, entity_type, name):
        return {"status": "Online"}


class RaisingHealthMonitor:
    def get_status(self, entity_type, name):
        raise AssertionError("health monitor must not be touched for a pre-populated snapshot")


# --- Task 2.1: off-loop sync calls in wrappers / get_hub_client --------------

def test_tool_wrapper_health_check_runs_off_loop(monkeypatch):
    """`_register_mcp_tool`'s wrapper must offload the sync health lookup to a
    worker thread via asyncio.to_thread instead of blocking the event loop."""

    class RecordingToolAgent:
        def __init__(self):
            self.tools = {}

        def tool(self, name=None, description=None):
            def deco(fn):
                self.tools[name or fn.__name__] = fn
                return fn
            return deco

    fake_agent = RecordingToolAgent()
    mcp_tool = SimpleNamespace(name="opsctl", description="Inspects nodes.")

    main_thread_id = threading.get_ident()
    recorded: Dict[str, Any] = {}

    class FakeHealth:
        def get_status(self, entity_type, name):
            recorded["thread_id"] = threading.get_ident()
            recorded["args"] = (entity_type, name)
            return {"status": "Online"}

    class FakeHubClient:
        async def call_tool(self, name, arguments):
            return SimpleNamespace(content=["ok"])

    fake_health = FakeHealth()

    async def fake_get_hub_client():
        return FakeHubClient()

    monkeypatch.setattr(agent_factory, "get_health_monitor", lambda: fake_health)
    monkeypatch.setattr(agent_factory, "get_hub_client", fake_get_hub_client)
    _grant_bound_tool(monkeypatch, "opsctl")
    user_id_var.set("user-1")

    agent_factory._register_mcp_tool(fake_agent, mcp_tool)
    wrapper = fake_agent.tools["opsctl"]

    result = asyncio.run(wrapper(None))

    assert recorded["thread_id"] != main_thread_id
    assert recorded["args"] == ("tool", "opsctl")
    assert result == ["ok"]


def test_external_mcp_tool_wrapper_health_check_runs_off_loop(monkeypatch):
    """`_register_external_mcp_tool`'s wrapper must also offload the sync health
    lookup to a worker thread via asyncio.to_thread."""

    class RecordingToolAgent:
        def __init__(self):
            self.tools = {}

        def tool(self, name=None, description=None):
            def deco(fn):
                self.tools[name or fn.__name__] = fn
                return fn
            return deco

    fake_agent = RecordingToolAgent()
    mcp_tool = SimpleNamespace(name="clusters_get_all", description="Lists clusters.")

    main_thread_id = threading.get_ident()
    recorded: Dict[str, Any] = {}

    class FakeHealth:
        def get_status(self, entity_type, name):
            recorded["thread_id"] = threading.get_ident()
            recorded["args"] = (entity_type, name)
            return {"status": "Online"}

    class FakeExternalClient:
        async def call_tool(self, name, arguments):
            return SimpleNamespace(content=["ok"])

    async def fake_get_external_mcp_client(mcp_name, user_id):
        return FakeExternalClient()

    monkeypatch.setattr(agent_factory, "get_health_monitor", lambda: FakeHealth())
    monkeypatch.setattr(agent_factory, "get_external_mcp_client", fake_get_external_mcp_client)
    _grant_bound_tool(monkeypatch, "mcp__srv__clusters_get_all")
    user_id_var.set("user-1")

    agent_factory._register_external_mcp_tool(fake_agent, "srv", mcp_tool)
    wrapper = fake_agent.tools["clusters_get_all"]

    result = asyncio.run(wrapper(None))

    assert recorded["thread_id"] != main_thread_id
    assert recorded["args"] == ("tool", "clusters_get_all")
    assert result == ["ok"]


def test_get_hub_client_config_read_off_loop(monkeypatch):
    """`get_hub_client()` must read HUB_URL from the identity manager on a worker
    thread, then construct/cache the client with the resolved URL."""
    monkeypatch.setattr(agent_factory, "_hub_client", None)
    monkeypatch.setattr(agent_factory, "_hub_tools_cache", [])

    main_thread_id = threading.get_ident()
    recorded: Dict[str, Any] = {}
    constructed: Dict[str, Any] = {}

    class FakeIdentity:
        def get_config(self, key, default=None):
            recorded["thread_id"] = threading.get_ident()
            recorded["args"] = (key, default)
            return "http://hub/mcp"

    class FakeFastMCPClient:
        def __init__(self, url):
            constructed["url"] = url

        async def __aenter__(self):
            return self

        async def list_tools(self):
            return []

    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeIdentity())
    monkeypatch.setattr(agent_factory, "FastMCPClient", FakeFastMCPClient)

    client = asyncio.run(agent_factory.get_hub_client())

    assert recorded["thread_id"] != main_thread_id
    assert recorded["args"] == ("HUB_URL", agent_factory.DEFAULT_HUB_URL)
    assert constructed["url"] == "http://hub/mcp"
    assert client is agent_factory._hub_client
    assert agent_factory._hub_tools_cache == []


# --- Task 2.2: snapshot-backed get_compiled / fail-open refresh --------------

def test_get_compiled_reads_snapshot_without_etcd(monkeypatch):
    """A pre-populated eligibility snapshot must gate get_compiled() entirely:
    no identity-manager or health-monitor call, None for restricted names,
    fail-open delegation for clean/unknown names."""

    class RaisingIdentity:
        def __getattr__(self, name):
            raise AssertionError(f"identity manager must not be touched (accessed {name!r})")

    registry = agent_factory.FrameworkAgentRegistry(RaisingIdentity(), RaisingHealthMonitor())
    registry._set_snapshot_for_testing({
        "disabled-agent": {"disabled": True, "offline": False, "external": True},
        "offline-agent": {"disabled": False, "offline": True, "external": True},
        "internal-agent": {"disabled": False, "offline": False, "external": False},
        "clean-agent": {"disabled": False, "offline": False, "external": True},
    })

    sentinel = object()
    delegated = []

    def fake_get_compiled(self, name):
        delegated.append(name)
        return sentinel

    monkeypatch.setattr(agent_factory.DynamicAgentRegistry, "get_compiled", fake_get_compiled)

    assert registry.get_compiled("disabled-agent") is None
    assert registry.get_compiled("offline-agent") is None
    assert registry.get_compiled("internal-agent") is None
    assert registry.get_compiled("clean-agent") is sentinel
    assert registry.get_compiled("not-in-snapshot") is sentinel
    assert delegated == ["clean-agent", "not-in-snapshot"]


def test_registry_snapshot_refresh_fail_open():
    """If the bulk etcd reads blow up, _refresh_snapshot() must swallow the error
    and keep the previous snapshot in place."""

    class ExplodingIdentity:
        def get_all_agent_configs(self):
            raise RuntimeError("etcd unavailable")

        def get_all_health_statuses(self, entity_type):
            raise RuntimeError("etcd unavailable")

        def get_disabled_standard_agents(self):
            raise RuntimeError("etcd unavailable")

    registry = agent_factory.FrameworkAgentRegistry(ExplodingIdentity(), RaisingHealthMonitor())
    previous = {"disabled": False, "offline": False, "external": True}
    registry._set_snapshot_for_testing({"a": previous})

    registry._refresh_snapshot()

    assert registry._snapshot.get("a") == previous


def test_registry_snapshot_refresh_derives_eligibility(monkeypatch):
    """The real refresh derivation must mark disabled/internal/currently-offline
    agents as ineligible while leaving recovered and healthy ones routable."""

    now_iso = datetime.now(timezone.utc).isoformat()

    class FakeIdentity:
        def get_all_agent_configs(self):
            return {
                "internal-agent": {"external": False},
                "offline-agent": {},
                "recovered-agent": {},
                "ok-agent": {},
            }

        def get_all_health_statuses(self, entity_type):
            assert entity_type == "agent"
            return {
                "offline-agent": {"status": "Offline", "last_failure_time": now_iso},
                "recovered-agent": {"status": "Offline", "last_failure_time": "2020-01-01T00:00:00Z"},
            }

        def get_disabled_standard_agents(self):
            return ["ghost"]

    registry = agent_factory.FrameworkAgentRegistry(
        FakeIdentity(), SimpleNamespace(cooldown_seconds=60)
    )

    sentinel = object()
    delegated = []

    def fake_get_compiled(self, name):
        delegated.append(name)
        return sentinel

    monkeypatch.setattr(agent_factory.DynamicAgentRegistry, "get_compiled", fake_get_compiled)

    registry._refresh_snapshot()

    assert registry.get_compiled("internal-agent") is None
    assert registry.get_compiled("offline-agent") is None
    assert registry.get_compiled("ghost") is None
    assert registry.get_compiled("recovered-agent") is sentinel
    assert registry.get_compiled("ok-agent") is sentinel
    assert delegated == ["recovered-agent", "ok-agent"]


# --- Task 2.3: honest manage_agent -------------------------------------------

class FakeManageIdentity:
    """Records disabled-state toggles and answers the bulk reads used by
    _refresh_snapshot()."""

    def __init__(self):
        self.toggles = []

    def get_agent_config(self, name):
        return {"name": name, "type": "user_agent"}

    def toggle_disabled_standard_agent(self, name, disabled):
        self.toggles.append((name, disabled))

    def toggle_disabled_workflow(self, name, disabled):
        self.toggles.append((name, disabled))

    def get_all_agent_configs(self):
        return {}

    def get_all_health_statuses(self, entity_type):
        return {}

    def get_disabled_standard_agents(self):
        return []


def _build_manage_agent_case(monkeypatch):
    fake_identity = FakeManageIdentity()
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    cached_agent = object()
    monkeypatch.setattr(agent_factory, "_agent_cache", {"some-agent": cached_agent})

    registry = agent_factory.FrameworkAgentRegistry(fake_identity, FakeHealthMonitor())
    registry.register(
        SubAgentConfig(name="some-agent", description="d", instructions=""),
        object(),
    )
    assert registry.exists("some-agent") is True
    monkeypatch.setattr(agent_factory, "_supervisor_registry", registry)

    fake_agent = _build_fake_agent()
    return fake_identity, fake_agent, registry, cached_agent


def test_manage_agent_rejects_unknown_action(monkeypatch):
    """An unrecognized action must return an explicit SYSTEM error and must never
    toggle the agent's disabled state."""
    fake_identity = FakeManageIdentity()
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    fake_agent = _build_fake_agent()
    result = asyncio.run(fake_agent.tools["manage_agent"]("some-agent", "delete"))

    assert result.startswith("SYSTEM: Unknown action")
    assert fake_identity.toggles == []


def test_manage_agent_reload_evicts_cached_agent(monkeypatch):
    """`reload` must toggle the agent enabled and actually evict the stale cached
    build (both `_agent_cache` and the supervisor registry)."""
    fake_identity, fake_agent, registry, _ = _build_manage_agent_case(monkeypatch)

    asyncio.run(fake_agent.tools["manage_agent"]("some-agent", "reload"))

    assert "some-agent" not in agent_factory._agent_cache
    assert registry.exists("some-agent") is False
    assert fake_identity.toggles == [("some-agent", False)]


def test_manage_agent_enable_does_not_evict(monkeypatch):
    """`enable` must toggle the agent enabled but keep the cached build (an enable
    changes routability, not the agent's identity)."""
    fake_identity, fake_agent, registry, cached_agent = _build_manage_agent_case(monkeypatch)

    asyncio.run(fake_agent.tools["manage_agent"]("some-agent", "enable"))

    assert agent_factory._agent_cache.get("some-agent") is cached_agent
    assert registry.exists("some-agent") is True
    assert fake_identity.toggles == [("some-agent", False)]


def test_manage_agent_disable_refreshes_snapshot(monkeypatch):
    """`disable` must toggle the agent disabled and refresh the registry snapshot
    exactly once so dispatch stops routing to it immediately."""
    toggles = []
    refresh_calls = []

    class FakeDisableIdentity:
        def get_agent_config(self, name):
            return {"name": name, "type": "user_agent"}

        def toggle_disabled_standard_agent(self, name, disabled):
            toggles.append((name, disabled))
            return True

    class FakeRegistry:
        def _refresh_snapshot(self):
            refresh_calls.append(threading.get_ident())

    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeDisableIdentity())
    monkeypatch.setattr(agent_factory, "get_supervisor_registry", lambda: FakeRegistry())

    fake_agent = _build_fake_agent()
    result = asyncio.run(fake_agent.tools["manage_agent"]("some-agent", "disable"))

    assert result == "Agent some-agent disabled."
    assert toggles == [("some-agent", True)]
    assert len(refresh_calls) == 1


def test_manage_agent_contention_reports_in_band(monkeypatch):
    """An exhausted CAS loop must surface as an in-band SYSTEM message, not an
    exception that fails the whole chat turn -- and must not evict or refresh."""
    from core.auth import EtcdContentionError

    fake_identity, fake_agent, registry, cached_agent = _build_manage_agent_case(monkeypatch)

    def contended_toggle(name, disabled):
        raise EtcdContentionError("contended")

    monkeypatch.setattr(fake_identity, "toggle_disabled_standard_agent", contended_toggle)
    refresh_calls = []
    monkeypatch.setattr(registry, "_refresh_snapshot", lambda: refresh_calls.append(1))

    result = asyncio.run(fake_agent.tools["manage_agent"]("some-agent", "reload"))

    assert result.startswith("SYSTEM: Could not reload agent 'some-agent'")
    assert agent_factory._agent_cache.get("some-agent") is cached_agent
    assert registry.exists("some-agent") is True
    assert refresh_calls == []


def test_manage_agent_snapshot_refresh_timeout_is_bounded(monkeypatch, caplog):
    """When etcd is degraded, manage_agent must not block on the snapshot refresh:
    the bounded wait times out, logs a warning, and the toggle still succeeds."""
    toggles = []

    class FakeTimeoutIdentity:
        def get_agent_config(self, name):
            return {"name": name, "type": "user_agent"}

        def toggle_disabled_standard_agent(self, name, disabled):
            toggles.append((name, disabled))
            return True

    class FakeRegistry:
        def _refresh_snapshot(self):
            time.sleep(0.3)

    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeTimeoutIdentity())
    monkeypatch.setattr(agent_factory, "get_supervisor_registry", lambda: FakeRegistry())
    monkeypatch.setattr(agent_factory, "_registry_refresh_timeout", lambda: 0.05)

    fake_agent = _build_fake_agent()

    with caplog.at_level(logging.WARNING, logger="core.agent_factory"):
        result = asyncio.run(fake_agent.tools["manage_agent"]("some-agent", "disable"))

    assert result == "Agent some-agent disabled."
    assert toggles == [("some-agent", True)]
    assert "timed out" in caplog.text


def test_registry_refresh_runs_on_dedicated_executor(monkeypatch):
    """The bounded snapshot refresh must run on its own single-thread executor
    rather than the shared default executor that serves every other to_thread call."""
    recorded: Dict[str, Any] = {}

    class FakeIdentity:
        def get_agent_config(self, name):
            return {"name": name, "type": "user_agent"}

        def toggle_disabled_standard_agent(self, name, disabled):
            return True

    class FakeRegistry:
        def _refresh_snapshot(self):
            recorded["thread_name"] = threading.current_thread().name

    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeIdentity())
    monkeypatch.setattr(agent_factory, "get_supervisor_registry", lambda: FakeRegistry())

    fake_agent = _build_fake_agent()
    result = asyncio.run(fake_agent.tools["manage_agent"]("some-agent", "disable"))

    assert result == "Agent some-agent disabled."
    assert recorded["thread_name"].startswith("registry-refresh")
    assert recorded["thread_name"] != threading.current_thread().name


def test_registry_refresh_hang_is_isolated_from_default_executor(monkeypatch, caplog):
    """A hung snapshot refresh must fail open within its timeout while leaving the
    shared default executor free, so unrelated asyncio.to_thread work is unaffected."""
    release = threading.Event()
    recorded: Dict[str, Any] = {}

    class FakeRegistry:
        def _refresh_snapshot(self):
            recorded["thread_name"] = threading.current_thread().name
            release.wait(timeout=10)

    isolated_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="registry-refresh")
    monkeypatch.setattr(agent_factory, "_registry_refresh_executor", isolated_executor)
    monkeypatch.setattr(agent_factory, "get_supervisor_registry", lambda: FakeRegistry())
    monkeypatch.setattr(agent_factory, "_registry_refresh_timeout", lambda: 0.2)

    async def scenario():
        refresh_task = asyncio.ensure_future(agent_factory._refresh_registry_snapshot_bounded())
        start = time.monotonic()
        default_result = await asyncio.wait_for(asyncio.to_thread(lambda: "ok"), timeout=2.0)
        default_elapsed = time.monotonic() - start
        await asyncio.wait_for(refresh_task, timeout=2.0)
        return default_result, default_elapsed

    try:
        with caplog.at_level(logging.WARNING, logger="core.agent_factory"):
            default_result, default_elapsed = asyncio.run(scenario())
    finally:
        release.set()
        isolated_executor.shutdown(wait=True)

    assert default_result == "ok"
    assert default_elapsed < 1.0
    assert recorded["thread_name"].startswith("registry-refresh")
    assert "timed out" in caplog.text


# --- Phase 4: framework LLM defaults on the build path -----------------------

class FakeBuildIdentity:
    """Minimal identity manager for `build_agent` (blank-config agent builds)."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def get_agent_config(self, name):
        return dict(self.config)

    def get_agent_skills(self, name):
        return ""


class FakeBuildAgent:
    def __init__(self, model, **kwargs):
        self.model = model
        self.kwargs = kwargs


class FakeBuildMemory:
    def active_for(self, config):
        return False


class FakeToolSet:
    def __init__(self):
        self.tools: Dict[str, Any] = {}

    def add_tool(self, tool):
        self.tools[tool.name] = tool


class FakeSchemaAgent(FakeBuildAgent):
    """`build_agent`'s Agent stand-in for MCP registration: `Tool.from_schema` needs a
    `_function_toolset` to land in."""

    def __init__(self, model, **kwargs):
        super().__init__(model, **kwargs)
        self._function_toolset = FakeToolSet()
        self.tools: Dict[str, Any] = {}

    def tool(self, name=None, description=None):
        def decorator(fn):
            self.tools[name or fn.__name__] = fn
            return fn

        return decorator


def _install_build_stubs(monkeypatch, config, defaults=None, *, discovered=None, remote_mcps=None):
    """Stub every etcd/network seam `build_agent` touches.

    ``discovered`` / ``remote_mcps`` pre-populate the discovery caches (central MCP
    servers and edge-exported ones respectively) so registration runs for real.

    Returns a dict of recorders: ``resolve_model`` args, ``build_model_settings``
    args, and the framework-defaults reads.
    """
    import core.memory as core_memory

    recorded: Dict[str, Any] = {
        "resolve_model": [],
        "build_model_settings": [],
        "defaults_reads": 0,
        "api_key_providers": [],
    }
    sentinel = object()

    def fake_get_framework_defaults():
        recorded["defaults_reads"] += 1
        return defaults if defaults is not None else agent_factory.llm_defaults.FrameworkDefaults()

    def fake_resolve_model(provider, model, base_url=None, api_key=None):
        recorded["resolve_model"].append((provider, model, base_url))
        return sentinel

    def fake_build_model_settings(provider, model, thinking_level):
        recorded["build_model_settings"].append((provider, model, thinking_level))
        return None

    def fake_get_provider_api_key(provider):
        recorded["api_key_providers"].append(provider)
        return "test-key"

    async def fake_get_hub_client():
        return SimpleNamespace()

    async def fake_discover_external_mcps():
        return None

    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeBuildIdentity(config))
    monkeypatch.setattr(agent_factory.llm_defaults, "get_framework_defaults", fake_get_framework_defaults)
    monkeypatch.setattr(agent_factory, "resolve_model", fake_resolve_model)
    monkeypatch.setattr(agent_factory, "build_model_settings", fake_build_model_settings)
    monkeypatch.setattr(
        agent_factory.llm_factory, "get_provider_api_key", fake_get_provider_api_key
    )
    monkeypatch.setattr(agent_factory, "Agent", FakeSchemaAgent)
    monkeypatch.setattr(agent_factory, "get_hub_client", fake_get_hub_client)
    monkeypatch.setattr(agent_factory, "discover_external_mcps", fake_discover_external_mcps)
    monkeypatch.setattr(agent_factory, "_hub_tools_cache", [])
    monkeypatch.setattr(agent_factory, "_external_mcp_tools", discovered or {})
    monkeypatch.setattr(agent_factory, "_external_remote_mcps", remote_mcps or {})
    monkeypatch.setattr(core_memory, "get_memory_manager", lambda: FakeBuildMemory())

    recorded["sentinel"] = sentinel
    return recorded


def test_build_agent_uses_framework_default_pair(monkeypatch, caplog):
    """provider/model both blank -> the framework default pair is used, and the
    INFO line names the resolved source (A9)."""
    defaults = agent_factory.llm_defaults.FrameworkDefaults("deepseek", "deepseek-chat", None)
    recorded = _install_build_stubs(
        monkeypatch,
        {"name": "blank-agent", "provider": None, "model": None},
        defaults=defaults,
    )

    with caplog.at_level(logging.INFO, logger="core.agent_factory"):
        agent = asyncio.run(agent_factory.build_agent("blank-agent"))

    assert isinstance(agent, FakeBuildAgent)
    assert agent.model is recorded["sentinel"]
    assert recorded["resolve_model"] == [("deepseek", "deepseek-chat", None)]
    assert recorded["build_model_settings"] == [("deepseek", "deepseek-chat", None)]
    assert recorded["defaults_reads"] == 1
    assert recorded["api_key_providers"] == ["deepseek"]
    assert "LLM config unresolved for agent 'blank-agent'" in caplog.text
    assert "deepseek/deepseek-chat (source=framework)" in caplog.text


def test_build_agent_provider_only_uses_registry_default(monkeypatch):
    """A set provider with a blank model resolves to that provider's registry
    default when no framework default applies (D6 still reads once)."""
    recorded = _install_build_stubs(
        monkeypatch,
        {"name": "provider-only", "provider": "google", "model": ""},
        defaults=agent_factory.llm_defaults.FrameworkDefaults(),
    )

    asyncio.run(agent_factory.build_agent("provider-only"))

    assert recorded["resolve_model"] == [("google", "gemini-2.5-flash", None)]
    assert recorded["build_model_settings"] == [("google", "gemini-2.5-flash", None)]


def test_build_agent_explicit_pair_skips_defaults_read(monkeypatch):
    """A fully-specified agent must never read the framework defaults (D6/G4)."""
    recorded = _install_build_stubs(
        monkeypatch,
        {"name": "explicit-agent", "provider": "deepseek", "model": "deepseek-reasoner"},
    )

    def exploding_defaults():
        raise AssertionError("explicit configs must not read the framework defaults")

    monkeypatch.setattr(agent_factory.llm_defaults, "get_framework_defaults", exploding_defaults)

    asyncio.run(agent_factory.build_agent("explicit-agent"))

    assert recorded["defaults_reads"] == 0
    assert recorded["resolve_model"] == [("deepseek", "deepseek-reasoner", None)]
    assert recorded["build_model_settings"] == [("deepseek", "deepseek-reasoner", None)]


def test_build_agent_inherits_framework_base_url(monkeypatch):
    """Case D: a blank agent inherits the framework provider/model *and* base_url."""
    defaults = agent_factory.llm_defaults.FrameworkDefaults(
        "openai-compatible", "llama3.2:3b", "http://ep/v1"
    )
    recorded = _install_build_stubs(
        monkeypatch,
        {"name": "inherit-endpoint", "provider": None, "model": None},
        defaults=defaults,
    )

    asyncio.run(agent_factory.build_agent("inherit-endpoint"))

    assert recorded["resolve_model"] == [("openai-compatible", "llama3.2:3b", "http://ep/v1")]
    assert recorded["build_model_settings"] == [("openai-compatible", "llama3.2:3b", None)]


def test_build_agent_effective_model_reaches_model_settings(monkeypatch):
    """`build_model_settings` must see the effective model, not the blank config
    model (the Gemini budget lookup keys off the real id)."""
    defaults = agent_factory.llm_defaults.FrameworkDefaults("deepseek", "deepseek-chat", None)
    recorded = _install_build_stubs(
        monkeypatch,
        {"name": "settings-agent", "provider": None, "model": None, "thinking_level": "high"},
        defaults=defaults,
    )

    asyncio.run(agent_factory.build_agent("settings-agent"))

    assert recorded["build_model_settings"] == [("deepseek", "deepseek-chat", "high")]


# --- LLM-defaults etcd watch (Phase 4) ---------------------------------------

def test_llm_defaults_watch_resets_cache_and_evicts_agents(monkeypatch):
    """A framework-default change must drop the TTL cache and every built agent, else
    an admin edit would not reach agents already cached in the serving process."""
    from core import llm_defaults

    calls = {"reset": 0, "evict": 0}
    monkeypatch.setattr(llm_defaults, "reset_defaults_cache", lambda: calls.__setitem__("reset", calls["reset"] + 1))
    monkeypatch.setattr(agent_factory, "evict_all_agents", lambda: calls.__setitem__("evict", calls["evict"] + 1))

    agent_factory._on_llm_defaults_change(SimpleNamespace(events=[]))

    assert calls == {"reset": 1, "evict": 1}


def test_install_llm_defaults_watch_is_idempotent(monkeypatch):
    registered = []

    class FakeClient:
        def add_watch_prefix_callback(self, prefix, callback):
            registered.append(prefix)
            return len(registered)

    class FakeIdentity:
        client = FakeClient()

    monkeypatch.setattr(agent_factory, "_llm_defaults_watch_id", None)
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeIdentity())

    agent_factory.install_llm_defaults_watch()
    agent_factory.install_llm_defaults_watch()

    assert registered == ["/config/framework/default_llm_"]


# --- Phase 6: provider-facing root-union normalization -----------------------

META_TOOL = "tenant_account_tools"

# The workload's meta-tool shape: a root union with no top-level `properties`. Gemini
# silently drops it, so the model calls the tool with no arguments at all.
ROOT_UNION_SCHEMA = {
    "type": "object",
    "oneOf": [
        {
            "properties": {"action": {"const": "get"}, "id": {"type": "integer"}},
            "required": ["action", "id"],
        },
        {
            "properties": {"action": {"const": "list_actions"}},
            "required": ["action"],
        },
    ],
}

FLATTENED_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"const": "get"},
        "id": {"type": "integer"},
    },
    "required": ["action"],
}


def _build_agent_with_central_mcp(monkeypatch, provider: str, model: str, schema: dict):
    """`build_agent` over one discovered central MCP server carrying ``schema``."""
    tool = MCPToolDefinition(
        name=META_TOOL, description="Tenant tools.", inputSchema=copy.deepcopy(schema)
    )
    _install_build_stubs(
        monkeypatch,
        {"name": "mcp-agent", "provider": provider, "model": model, "allowed_mcps": ["srv"]},
        discovered={"srv": [tool]},
    )
    agent = asyncio.run(agent_factory.build_agent("mcp-agent"))
    return agent, tool


def _registered_schema(agent) -> dict:
    return agent._function_toolset.tools[META_TOOL].function_schema.json_schema


def test_central_mcp_root_union_is_flattened_for_google(monkeypatch):
    agent, tool = _build_agent_with_central_mcp(
        monkeypatch, "google", "gemini-2.5-flash", ROOT_UNION_SCHEMA
    )

    assert _registered_schema(agent) == FLATTENED_SCHEMA
    # Central MCPs are fixed by the same rule as edge MCPs; the catalog stays verbatim.
    assert tool.inputSchema == ROOT_UNION_SCHEMA


def test_central_mcp_root_union_is_unchanged_for_openai(monkeypatch):
    agent, tool = _build_agent_with_central_mcp(
        monkeypatch, "openai", "gpt-4o", ROOT_UNION_SCHEMA
    )

    assert _registered_schema(agent) == ROOT_UNION_SCHEMA
    assert tool.inputSchema == ROOT_UNION_SCHEMA


def test_central_mcp_non_union_schema_is_unchanged_for_google(monkeypatch):
    schema = {
        "type": "object",
        "properties": {"id": {"type": "integer"}},
        "required": ["id"],
    }

    agent, tool = _build_agent_with_central_mcp(monkeypatch, "google", "gemini-2.5-flash", schema)

    assert _registered_schema(agent) == schema
    assert tool.inputSchema == schema


# --- Phase 3 (v0.7.1): bare `allowed_tools` names register no MCP tools ------
#
# Build-time twin of `core.allowlist.permits_tool`: an MCP tool is granted by its
# server (`allowed_mcps`, including `<site>__*`) or by its own full `mcp__...`
# reference. A bare name belongs to the framework/hub tool of that name, so it must
# not register a same-named MCP tool -- exposing it would only produce a call the
# call-time allowlist then denies.

DEV = "deploy"
SIBLING = "sibling"
CENTRAL = "devops"
EDGE_KEY = "dc1__devops"


def _mcp_tool(name: str) -> MCPToolDefinition:
    return MCPToolDefinition(
        name=name,
        description=f"{name} tool.",
        inputSchema={"type": "object", "properties": {}},
    )


def _registered_names(agent) -> set[str]:
    return set(agent._function_toolset.tools)


def test_a_bare_allowed_tools_name_registers_no_mcp_tool(monkeypatch):
    """`allowed_tools: [deploy]` + an MCP server exporting `deploy`: not registered."""
    _install_build_stubs(
        monkeypatch,
        {"name": "bare-name-agent", "allowed_tools": [DEV]},
        discovered={CENTRAL: [_mcp_tool(DEV), _mcp_tool(SIBLING)]},
    )

    agent = asyncio.run(agent_factory.build_agent("bare-name-agent"))

    # Neither the same-named tool nor its sibling: a bare entry grants no MCP tool.
    assert _registered_names(agent) == set()


def test_a_bare_allowed_tools_name_still_registers_the_hub_tool_of_that_name(monkeypatch):
    """The same entry does register the framework/hub tool that owns the name."""
    _install_build_stubs(
        monkeypatch, {"name": "hub-tool-agent", "allowed_tools": [DEV]}, discovered={}
    )
    monkeypatch.setattr(agent_factory, "_hub_tools_cache", [_mcp_tool(DEV)])

    agent = asyncio.run(agent_factory.build_agent("hub-tool-agent"))

    assert _registered_names(agent) == {DEV}


def test_allowed_mcps_registers_the_servers_tools_under_their_exposed_names(monkeypatch):
    """The server grant keeps today's exposed names (`tool.name`, not the prefix)."""
    _install_build_stubs(
        monkeypatch,
        {"name": "server-grant-agent", "allowed_mcps": [CENTRAL]},
        discovered={CENTRAL: [_mcp_tool(DEV), _mcp_tool(SIBLING)]},
    )

    agent = asyncio.run(agent_factory.build_agent("server-grant-agent"))

    assert _registered_names(agent) == {DEV, SIBLING}


def test_a_full_mcp_reference_registers_only_that_tool_under_its_prefixed_name(monkeypatch):
    _install_build_stubs(
        monkeypatch,
        {"name": "narrowed-agent", "allowed_tools": [f"mcp__{CENTRAL}__{DEV}"]},
        discovered={CENTRAL: [_mcp_tool(DEV), _mcp_tool(SIBLING)]},
    )

    agent = asyncio.run(agent_factory.build_agent("narrowed-agent"))

    assert _registered_names(agent) == {f"mcp__{CENTRAL}__{DEV}"}


def test_an_edge_mcp_wildcard_registers_the_four_part_names(monkeypatch):
    _install_build_stubs(
        monkeypatch,
        {"name": "wildcard-agent", "allowed_mcps": ["dc1__*"]},
        discovered={EDGE_KEY: [_mcp_tool(DEV)]},
        remote_mcps={EDGE_KEY: ("dc1", "devops")},
    )

    agent = asyncio.run(agent_factory.build_agent("wildcard-agent"))

    # Legacy semantics, pinned: an edge export is always 4-part namespaced.
    assert _registered_names(agent) == {f"mcp__dc1__devops__{DEV}"}


def test_a_bare_allowed_tools_name_registers_no_edge_mcp_tool(monkeypatch):
    _install_build_stubs(
        monkeypatch,
        {"name": "bare-name-edge-agent", "allowed_tools": [DEV]},
        discovered={EDGE_KEY: [_mcp_tool(DEV)]},
        remote_mcps={EDGE_KEY: ("dc1", "devops")},
    )

    agent = asyncio.run(agent_factory.build_agent("bare-name-edge-agent"))

    assert _registered_names(agent) == set()


# --- bound-tool gating: the ONE evaluator ------------------------------------
#
# Bound tools never reach `use_tool`, so the wrapper itself asks core.tool_access:
# the agent and its groups come from the run's token, the allowlist from that agent's
# record. `shadow` records and executes, `enforce` refuses, `off` relaxes the group
# rules only, and an evaluator crash fails closed.

DENIED = "SYSTEM: Access denied. Tool '{name}' is not permitted for this principal."
BOUND_SECRET = "bound-tool-unit-secret-0123456789abcdef"


class FakePolicyEtcd:
    """The policy document plus the shared shadow ring."""

    def __init__(self):
        self.policy = None
        self.shared_ring = None
        self.revision = 1
        self.reads = 0

    def get(self, key, **_kwargs):
        import json

        if key == tool_access.POLICY_PATH:
            self.reads += 1
            if self.policy is None:
                return None, None
            meta = type("M", (), {"mod_revision": self.revision})()
            return json.dumps(self.policy).encode("utf-8"), meta
        if key == tool_access.SHADOW_DENIAL_PATH:
            return self.shared_ring, None
        return None, None

    def put(self, key, value):
        if key == tool_access.SHADOW_DENIAL_PATH:
            self.shared_ring = value.encode("utf-8") if isinstance(value, str) else value

    def add_watch_callback(self, key, callback):
        return 1

    def cancel_watch(self, watch_id):
        pass


@pytest.fixture
def bound_authz(monkeypatch):
    """Install a fake policy registry + agent records; ``install(...)`` re-configures."""
    from core import auth, tool_access

    fake_policy = FakePolicyEtcd()
    monkeypatch.setattr(tool_access, "_client", lambda: fake_policy)
    monkeypatch.setattr(tool_access, "_last_shadow_persist", 0.0)
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    monkeypatch.setenv("AGENT_TOKEN_SECRET", BOUND_SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv("DEV_MODE", raising=False)
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()
    for var in (auth.agent_token_var, auth.user_id_var, auth.run_id_var):
        var.set(None)

    records = {"supervisor": {"allowed_tools": ["opsctl"]}}

    class FakeRegistry:
        def get_agent_config(self, name):
            return records.get(name)

    monkeypatch.setattr(auth, "get_identity_manager", lambda: FakeRegistry())

    def install(*, policy=None, allowed_tools=None, agent="supervisor", mode=None, groups=()):
        if policy is not None:
            fake_policy.policy = policy
            fake_policy.revision += 1
        if allowed_tools is not None:
            records[agent] = {"allowed_tools": list(allowed_tools)}
        if mode is not None:
            monkeypatch.setenv(tool_access.MODE_ENV, mode)
        tool_access.reset_snapshot()
        from core import agent_token

        agent_token.mint_for_run(agent, "user-1", run_id="run-1", groups=groups)
        return fake_policy

    yield install

    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()
    for var in (auth.agent_token_var, auth.user_id_var, auth.run_id_var):
        var.set(None)


def _rules(*rules):
    return {"rules": [dict(rule) for rule in rules]}


class RecordingHubClient:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return SimpleNamespace(content=["ok"])


class RecordingToolAgent:
    def __init__(self):
        self.tools = {}

    def tool(self, name=None, description=None):
        def deco(fn):
            self.tools[name or fn.__name__] = fn
            return fn

        return deco


def _install_hub_tool(monkeypatch, *, health="Online"):
    """Register one hub-backed bound tool; returns (wrapper, hub client)."""
    client = RecordingHubClient()

    async def fake_get_hub_client():
        return client

    monkeypatch.setattr(
        agent_factory, "get_health_monitor", lambda: SimpleNamespace(get_status=lambda *a: {"status": health})
    )
    monkeypatch.setattr(agent_factory, "get_hub_client", fake_get_hub_client)

    fake_agent = RecordingToolAgent()
    agent_factory._register_mcp_tool(
        fake_agent, SimpleNamespace(name="opsctl", description="Inspects nodes.")
    )
    return fake_agent.tools["opsctl"], client


def test_a_bound_tool_in_the_allowlist_runs(monkeypatch, bound_authz):
    bound_authz()
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    assert asyncio.run(wrapper(None)) == ["ok"]
    assert [name for name, _ in client.calls] == ["opsctl"]


def test_a_bound_tool_outside_the_allowlist_is_denied(monkeypatch, bound_authz):
    bound_authz(allowed_tools=["netctl"])
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    assert asyncio.run(wrapper(None)) == DENIED.format(name="opsctl")
    assert client.calls == []


def test_a_bound_tool_denial_comes_from_the_real_evaluator(monkeypatch, bound_authz, caplog):
    """Pin the wiring, not just the string: the verdict is the evaluator's own.

    The shadow ring is empty in enforce mode, so the evidence that the ONE evaluator
    decided is its tagged message -- ``access_denied [bound_tool]``, naming the agent
    and the reference. A wrapper with a private check of its own would hand the model
    the same string and leave no such record.
    """
    bound_authz(allowed_tools=["netctl"])
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    with caplog.at_level("WARNING", logger="core.agent_factory"):
        assert asyncio.run(wrapper(None)) == DENIED.format(name="opsctl")

    assert client.calls == []
    messages = [record.getMessage() for record in caplog.records]
    assert any("bound_tool: denied 'opsctl'" in message for message in messages)
    assert any("access_denied [bound_tool]" in message for message in messages)
    assert any("agent 'supervisor'" in message for message in messages)


def test_a_run_without_a_token_is_denied(monkeypatch, bound_authz):
    """Enforce mode: no verified token means no bound tool, whoever built the wrapper."""
    from core import auth

    bound_authz()
    auth.agent_token_var.set(None)
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    assert asyncio.run(wrapper(None)).startswith("SYSTEM: Access denied.")
    assert client.calls == []


def test_a_group_rule_admits_a_matching_token(monkeypatch, bound_authz):
    bound_authz(policy=_rules({"targets": ["opsctl"], "groups": ["ops"]}), groups=["ops"])
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    assert asyncio.run(wrapper(None)) == ["ok"]


def test_a_group_rule_denies_a_non_matching_token(monkeypatch, bound_authz):
    bound_authz(policy=_rules({"targets": ["opsctl"], "groups": ["ops"]}), groups=["sre"])
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    assert asyncio.run(wrapper(None)) == DENIED.format(name="opsctl")
    assert client.calls == []


def test_shadow_records_the_bound_tool_surface_and_still_executes(monkeypatch, bound_authz):
    bound_authz(
        policy=_rules({"targets": ["opsctl"], "groups": ["ops"], "name": "platform-ops"}),
        mode="shadow",
        groups=["sre"],
    )
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    assert asyncio.run(wrapper(None)) == ["ok"]

    [entry] = tool_access.recent_shadow_denials()
    assert entry["surface"] == "bound_tool"
    assert entry["agent"] == "supervisor"
    assert entry["target"] == "opsctl"
    assert entry["rule"] == "platform-ops"
    assert entry["groups"] == ["sre"]
    assert entry["mode"] == "shadow"


def test_off_skips_the_group_rules(monkeypatch, bound_authz):
    bound_authz(policy=_rules({"targets": ["opsctl"], "groups": ["ops"]}), mode="off")
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    assert asyncio.run(wrapper(None)) == ["ok"]
    assert tool_access.recent_shadow_denials() == []


def test_a_central_mcp_bound_tool_is_gated_by_its_registry_name(monkeypatch, bound_authz):
    bound_authz(
        policy=_rules({"targets": ["mcp__srv__clusters_get_all"], "groups": ["ops"]}),
        allowed_tools=["mcp__srv__clusters_get_all"],
        groups=["ops"],
    )
    user_id_var.set("user-1")
    calls = []

    class FakeExternalClient:
        async def call_tool(self, name, arguments):
            calls.append((name, arguments))
            return SimpleNamespace(content=["ok"])

    async def fake_get_external_mcp_client(mcp_name, user_id):
        return FakeExternalClient()

    monkeypatch.setattr(
        agent_factory, "get_health_monitor", lambda: SimpleNamespace(get_status=lambda *a: {"status": "Online"})
    )
    monkeypatch.setattr(agent_factory, "get_external_mcp_client", fake_get_external_mcp_client)

    fake_agent = RecordingToolAgent()
    # Registered under its bare name, but the evaluator sees `mcp__<server>__<tool>`.
    agent_factory._register_external_mcp_tool(
        fake_agent, "srv", SimpleNamespace(name="clusters_get_all", description="Lists clusters.")
    )
    wrapper = fake_agent.tools["clusters_get_all"]

    assert asyncio.run(wrapper(None)) == ["ok"]
    assert [name for name, _ in calls] == ["clusters_get_all"]


def test_an_edge_mcp_bound_tool_is_gated_by_its_four_part_name(monkeypatch, bound_authz):
    bound_authz(
        policy=_rules({"targets": ["mcp__site__mcp__read__x"], "groups": ["ops"]}),
        allowed_tools=["mcp__site__mcp__read__x"],
        groups=["ops"],
    )
    user_id_var.set("user-1")
    calls = []

    async def fake_call_edge_mcp(site, mcp, tool, arguments, user_id, agent_token=None):
        calls.append(f"mcp__{site}__{mcp}__{tool}")
        return {"content": ["ok"]}

    monkeypatch.setattr(agent_factory, "call_edge_mcp", fake_call_edge_mcp)

    fake_agent = RecordingToolAgent()
    agent_factory._register_remote_mcp_tool(
        fake_agent, "site", "mcp", SimpleNamespace(name="read__x", description="Edge tool.")
    )
    wrapper = fake_agent.tools["mcp__site__mcp__read__x"]

    assert asyncio.run(wrapper(None)) == ["ok"]
    assert calls == ["mcp__site__mcp__read__x"]

    # A token without the group is refused by the same rule.
    from core import agent_token

    agent_token.mint_for_run("supervisor", "user-1", run_id="run-2", groups=["sre"])
    assert asyncio.run(wrapper(None)) == DENIED.format(name="mcp__site__mcp__read__x")
    assert calls == ["mcp__site__mcp__read__x"]


def test_an_evaluator_crash_fails_closed(monkeypatch, bound_authz):
    """An evaluator crash must deny the call, not execute it and not raise."""
    bound_authz()

    def boom(*_args, **_kwargs):
        raise RuntimeError("evaluator unavailable")

    # The gate is async now (the policy read must leave the event loop).
    async def boom_async(*_args, **_kwargs):
        raise RuntimeError("evaluator unavailable")

    monkeypatch.setattr(tool_access, "authorize_claims_async", boom_async)
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    result = asyncio.run(wrapper(None))

    assert result == "SYSTEM: Error checking tool access for 'opsctl'. Please try again later."
    assert client.calls == []