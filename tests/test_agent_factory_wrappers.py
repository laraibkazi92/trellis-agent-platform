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

from core import agent_factory
from core.auth import user_id_var
from core.models import MCPToolDefinition
from subagents_pydantic_ai import SubAgentConfig


# --- shared fakes ------------------------------------------------------------

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


# --- Phase 1 (v0.7.1): bound-tool gating -------------------------------------
#
# Bound tools never reach `use_tool`, so the wrappers themselves ask the policy
# engine. Every case stubs the authz registry and the run context; `off` must stay a
# byte-for-byte no-op, `shadow` records and executes, `enforcing` refuses.

DENIED = "SYSTEM: Access denied. Tool '{name}' is not permitted for this principal."


class FakeAuthzRegistry:
    """Authz-only registry stand-in (policy, both modes, the shared deny ring)."""

    def __init__(self, *, policy=None, mode="off", bound_mode="off"):
        self.policy = {} if policy is None else policy
        self.mode = mode
        self.bound_mode = bound_mode
        self.denies = []
        self.policy_reads = 0

    def get_tool_policies(self):
        self.policy_reads += 1
        return self.policy

    def get_tool_authz_mode(self):
        return self.mode

    def get_bound_tools_mode(self):
        return self.bound_mode

    def get_principal_groups(self):
        return {}

    def append_tool_authz_deny(self, entry, cap: int = 200):
        self.denies.insert(0, entry)
        del self.denies[cap:]

    def get_tool_authz_denies(self):
        return list(self.denies)

    def clear_tool_authz_denies(self):
        self.denies.clear()


@pytest.fixture(autouse=True)
def _hermetic_authz_registry(monkeypatch):
    """Never let a wrapper test read (or write) the real authz registry.

    Every bound-tool call now asks the policy engine, and `tool_authz` imports
    `get_identity_manager` from `core.auth` lazily -- patching `agent_factory`'s own
    binding is not enough. Without this stub the pre-existing tests fail on a host
    with `bound_tools_mode=enforcing` and write synthetic entries into the live deny
    ring under `shadow`.
    """
    from core import auth, tool_authz

    fake = FakeAuthzRegistry()
    monkeypatch.setattr(auth, "get_identity_manager", lambda: fake)
    tool_authz.reset_cache()
    yield
    tool_authz.reset_cache()


@pytest.fixture
def bound_authz(monkeypatch):
    """Install a fake authz registry and a clean run context; ``install(**cfg)``."""
    from core import auth, tool_authz

    for var in (auth.agent_token_var, auth.user_id_var, auth.run_id_var):
        var.set(None)
    # Persist every denial instead of the production one-per-second sample.
    monkeypatch.setattr(tool_authz, "_DENY_PERSIST_MIN_INTERVAL_S", 0.0)
    monkeypatch.setattr(tool_authz, "_last_deny_persist", {})

    def install(**kwargs):
        fake = FakeAuthzRegistry(**kwargs)
        monkeypatch.setattr(auth, "get_identity_manager", lambda: fake)
        tool_authz.reset_cache()
        tool_authz.clear_shadow_denies()
        return fake

    yield install

    tool_authz.reset_cache()
    tool_authz.clear_shadow_denies()
    for var in (auth.agent_token_var, auth.user_id_var, auth.run_id_var):
        var.set(None)


class RecordingHubClient:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return SimpleNamespace(content=["ok"])


def _install_hub_tool(monkeypatch, *, health="Online"):
    """Register one hub-backed bound tool; returns (wrapper, hub client)."""

    class RecordingToolAgent:
        def __init__(self):
            self.tools = {}

        def tool(self, name=None, description=None):
            def deco(fn):
                self.tools[name or fn.__name__] = fn
                return fn

            return deco

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


def test_bound_tool_off_runs_and_records_nothing(monkeypatch, bound_authz):
    from core import tool_authz

    fake = bound_authz(policy={}, mode="off", bound_mode="off")
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    result = asyncio.run(wrapper(None))

    assert result == ["ok"]
    assert [name for name, _ in client.calls] == ["opsctl"]
    assert fake.denies == []
    assert tool_authz.shadow_denies() == []


def test_bound_tool_shadow_executes_and_records_the_surface(monkeypatch, bound_authz):
    from core import tool_authz

    fake = bound_authz(policy={}, mode="off", bound_mode="shadow")
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    result = asyncio.run(wrapper(None))

    # Shadow never changes behavior: the tool still ran.
    assert result == ["ok"]
    assert [name for name, _ in client.calls] == ["opsctl"]

    [entry] = tool_authz.shadow_denies()
    assert fake.denies[0] == entry
    assert entry["surface"] == tool_authz.BOUND_TOOL_SURFACE
    assert entry["mode"] == "shadow"
    assert entry["principal"] == "user:user-1"
    assert entry["tool"] == "opsctl"
    assert entry["scope"] == "tools:call"


def test_bound_tool_enforcing_denies_without_calling_the_hub(monkeypatch, bound_authz):
    bound_authz(policy={}, mode="off", bound_mode="enforcing")
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    result = asyncio.run(wrapper(None))

    assert result == DENIED.format(name="opsctl")
    assert client.calls == []


def test_bound_tool_enforcing_allows_a_granted_tool(monkeypatch, bound_authz):
    bound_authz(
        policy={
            "default_action": "deny",
            "rules": [{"tools": ["opsctl"], "allow_principals": ["agent:supervisor"]}],
        },
        bound_mode="enforcing",
    )
    from core import agent_token

    # A real agent-run token: the bound-tool principal is `agent:<name>`, as in use_tool.
    monkeypatch.setenv("AGENT_TOKEN_SECRET", "bound-tool-unit-secret-0123456789abcdef")
    agent_token.mint_for_run("supervisor", "user-1", run_id="run-1")
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    result = asyncio.run(wrapper(None))

    assert result == ["ok"]
    assert [name for name, _ in client.calls] == ["opsctl"]


def test_bound_tool_enforcing_uses_the_agent_principal_not_the_user(monkeypatch, bound_authz):
    from core import agent_token

    bound_authz(
        policy={
            "default_action": "deny",
            "rules": [{"tools": ["opsctl"], "allow_principals": ["user:user-1"]}],
        },
        bound_mode="enforcing",
    )
    monkeypatch.setenv("AGENT_TOKEN_SECRET", "bound-tool-unit-secret-0123456789abcdef")
    agent_token.mint_for_run("supervisor", "user-1", run_id="run-1")
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    # A user-scoped rule does not grant an agent-driven bound call (same as use_tool).
    assert asyncio.run(wrapper(None)) == DENIED.format(name="opsctl")
    assert client.calls == []


def test_external_mcp_bound_tool_is_gated_by_its_registry_name(monkeypatch, bound_authz):
    bound_authz(
        policy={
            "default_action": "deny",
            "rules": [{"tools": ["mcp__srv__clusters_get_all"], "allow_principals": ["*"]}],
        },
        bound_mode="enforcing",
    )
    user_id_var.set("user-1")

    class RecordingToolAgent:
        def __init__(self):
            self.tools = {}

        def tool(self, name=None, description=None):
            def deco(fn):
                self.tools[name or fn.__name__] = fn
                return fn

            return deco

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
    # Registered under its bare name, but the policy namespace is `mcp__<server>__<tool>`.
    agent_factory._register_external_mcp_tool(
        fake_agent, "srv", SimpleNamespace(name="clusters_get_all", description="Lists clusters.")
    )
    wrapper = fake_agent.tools["clusters_get_all"]

    assert asyncio.run(wrapper(None)) == ["ok"]
    assert [name for name, _ in calls] == ["clusters_get_all"]

    # The same server/tool pair with no rule is denied.
    bound_authz(policy={"default_action": "deny", "rules": []}, bound_mode="enforcing")
    assert asyncio.run(wrapper(None)) == DENIED.format(name="mcp__srv__clusters_get_all")
    assert [name for name, _ in calls] == ["clusters_get_all"]


def test_edge_mcp_bound_tool_is_gated_by_its_four_part_name(monkeypatch, bound_authz):
    bound_authz(
        policy={
            "default_action": "deny",
            "rules": [{"tools": ["mcp__site__mcp__read__x"], "allow_principals": ["*"]}],
        },
        bound_mode="enforcing",
    )
    user_id_var.set("user-1")

    class RecordingToolAgent:
        def __init__(self):
            self.tools = {}

        def tool(self, name=None, description=None):
            def deco(fn):
                self.tools[name or fn.__name__] = fn
                return fn

            return deco

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

    bound_authz(policy={"default_action": "deny", "rules": []}, bound_mode="enforcing")
    assert asyncio.run(wrapper(None)) == DENIED.format(name="mcp__site__mcp__read__x")
    assert calls == ["mcp__site__mcp__read__x"]




def test_bound_tool_check_failure_fails_closed(monkeypatch, bound_authz):
    """An evaluator crash must deny the call, not execute it and not raise."""
    from core import tool_authz

    bound_authz(policy={"default_action": "deny", "rules": []}, bound_mode="enforcing")

    def boom(*_args, **_kwargs):
        raise RuntimeError("policy engine unavailable")

    monkeypatch.setattr(tool_authz, "evaluate", boom)
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    result = asyncio.run(wrapper(None))

    assert result == "SYSTEM: Error checking tool access for 'opsctl'. Please try again later."
    assert client.calls == []


def test_bound_tool_mode_is_independent_of_the_use_tool_mode(monkeypatch, bound_authz):
    """use_tool enforcing must not gate bound tools while their own switch is off."""
    bound_authz(policy={"default_action": "deny", "rules": []}, mode="enforcing", bound_mode="off")
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    assert asyncio.run(wrapper(None)) == ["ok"]
    assert [name for name, _ in client.calls] == ["opsctl"]


def test_bound_tool_off_makes_no_registry_read_once_warm(monkeypatch, bound_authz):
    """The default mode must stay a no-I/O fast path after the cache is warm."""
    from core import tool_authz

    fake = bound_authz(policy={}, mode="off", bound_mode="off")
    user_id_var.set("user-1")
    wrapper, client = _install_hub_tool(monkeypatch)

    assert asyncio.run(wrapper(None)) == ["ok"]
    reads_after_first = fake.policy_reads

    assert asyncio.run(wrapper(None)) == ["ok"]
    assert fake.policy_reads == reads_after_first
    assert tool_authz.cached_mode_for_surface(tool_authz.BOUND_TOOL_SURFACE) == "off"
