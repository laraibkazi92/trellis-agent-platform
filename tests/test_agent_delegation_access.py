"""Tests for Phase 3 (Supervisor Dispatch & A2A In-Process Delegation Isolation) — see
__spec_docs/internal_external_agents_spec.md.

Covers:
  - FrameworkAgentRegistry.get_compiled() returning None for external: False agents, so the
    supervisor's task() tool can never compile/dispatch to them.
  - get_agent() not registering external: False agents into the shared _supervisor_registry.
  - build_agent()'s A2A loop skipping a2a_access targets with internal: False, while still
    injecting targets with internal: True.
"""
import asyncio
import logging
from types import SimpleNamespace
from typing import Dict, Optional

from core import agent_factory
from subagents_pydantic_ai import SubAgentConfig
from subagents_pydantic_ai.types import CompiledSubAgent


# --- FrameworkAgentRegistry.get_compiled -------------------------------------

class FakeIdentityManagerRegistry:
    def __init__(self, agent_configs):
        self._agent_configs = agent_configs

    def get_disabled_standard_agents(self):
        return []

    def get_agent_config(self, name):
        return self._agent_configs.get(name)


class FakeHealthMonitor:
    def get_status(self, kind, name):
        return {"status": "Online"}


def _seed_compiled(registry: agent_factory.FrameworkAgentRegistry, name: str):
    """Directly seed the base DynamicAgentRegistry's compiled-agent map, bypassing
    register()'s Agent-instance requirement — we only care about get_compiled()'s
    override behavior here, not agent construction."""
    config = SubAgentConfig(name=name, description="d", instructions="")
    registry.agents[name] = object()
    registry.configs[name] = config
    registry._compiled[name] = CompiledSubAgent(name=name, description="d", agent=object(), config=config)


def test_get_compiled_returns_none_for_external_false():
    fake_identity = FakeIdentityManagerRegistry({
        "internal-worker": {"name": "internal-worker", "external": False, "internal": True},
    })
    registry = agent_factory.FrameworkAgentRegistry(fake_identity, FakeHealthMonitor())
    registry._set_snapshot_for_testing({
        "internal-worker": {"disabled": False, "offline": False, "external": False},
    })
    _seed_compiled(registry, "internal-worker")

    assert registry.get_compiled("internal-worker") is None


def test_get_compiled_returns_compiled_for_external_true():
    fake_identity = FakeIdentityManagerRegistry({
        "general-agent": {"name": "general-agent", "external": True, "internal": True},
    })
    registry = agent_factory.FrameworkAgentRegistry(fake_identity, FakeHealthMonitor())
    registry._set_snapshot_for_testing({
        "general-agent": {"disabled": False, "offline": False, "external": True},
    })
    _seed_compiled(registry, "general-agent")

    assert registry.get_compiled("general-agent") is not None


def test_get_compiled_returns_compiled_when_config_missing():
    """Fail-open only for genuinely legacy/missing configs, matching the
    `.get(key, True) is False` defensive-default pattern used elsewhere in this spec."""
    fake_identity = FakeIdentityManagerRegistry({})
    registry = agent_factory.FrameworkAgentRegistry(fake_identity, FakeHealthMonitor())
    _seed_compiled(registry, "legacy-agent")

    assert registry.get_compiled("legacy-agent") is not None


# --- get_agent() supervisor-registry gating ----------------------------------

class FakeIdentityManagerGetAgent:
    def __init__(self, cfg):
        self._cfg = cfg

    def get_agent_config(self, name):
        return dict(self._cfg) if name == self._cfg.get("name") else None


def test_get_agent_does_not_register_external_false_in_supervisor_registry(monkeypatch):
    monkeypatch.setattr(agent_factory, "_agent_cache", {}, raising=False)
    monkeypatch.setattr(agent_factory, "_agent_locks", {}, raising=False)

    fake_identity = FakeIdentityManagerGetAgent({"name": "internal-worker", "description": "worker", "external": False})
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    fresh_registry = agent_factory.FrameworkAgentRegistry(fake_identity, FakeHealthMonitor())
    monkeypatch.setattr(agent_factory, "_supervisor_registry", fresh_registry, raising=False)

    sentinel_agent = object()

    async def fake_build_agent(name):
        return sentinel_agent

    monkeypatch.setattr(agent_factory, "build_agent", fake_build_agent)

    result = asyncio.run(agent_factory.get_agent("internal-worker"))

    assert result is sentinel_agent
    assert fresh_registry.exists("internal-worker") is False


def test_get_agent_registers_external_true_in_supervisor_registry(monkeypatch):
    monkeypatch.setattr(agent_factory, "_agent_cache", {}, raising=False)
    monkeypatch.setattr(agent_factory, "_agent_locks", {}, raising=False)

    fake_identity = FakeIdentityManagerGetAgent({"name": "general-agent", "description": "general", "external": True})
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    fresh_registry = agent_factory.FrameworkAgentRegistry(fake_identity, FakeHealthMonitor())
    monkeypatch.setattr(agent_factory, "_supervisor_registry", fresh_registry, raising=False)

    sentinel_agent = object()

    async def fake_build_agent(name):
        return sentinel_agent

    monkeypatch.setattr(agent_factory, "build_agent", fake_build_agent)

    result = asyncio.run(agent_factory.get_agent("general-agent"))

    assert result is sentinel_agent
    assert fresh_registry.exists("general-agent") is True


# --- build_agent() A2A delegation loop ---------------------------------------

CALLER_CONFIG = {
    "name": "triage-lead",
    "model": "gemini-3-flash-preview",
    "thinking_level": "medium",
    "a2a_access": ["data-parser", "front-door-bot"],
}

TARGET_CONFIGS = {
    "data-parser": {"name": "data-parser", "description": "Parses raw input.", "internal": True},
    "front-door-bot": {"name": "front-door-bot", "description": "User entrypoint.", "internal": False},
}


class FakeIdentityManagerA2A:
    def get_agent_config(self, name: str) -> Optional[Dict]:
        if name == "triage-lead":
            return dict(CALLER_CONFIG)
        target = TARGET_CONFIGS.get(name)
        return dict(target) if target else None

    def get_agent_skills(self, name: str) -> str:
        return f"skills for {name}"

    def get_config(self, key: str, default=None):
        return default


class FakeBuiltAgent:
    """Stand-in for pydantic_ai.Agent capturing constructor kwargs — build_agent's later
    steps (memory hook, hub/MCP tool registration) only need `.instructions`, `.tool`, and
    `._function_toolset.add_tool` to exist, not a real running agent."""

    def __init__(self, model, **kwargs):
        self.model = model
        self.kwargs = kwargs
        self._function_toolset = SimpleNamespace(add_tool=lambda *a, **k: None, tools={})

    def instructions(self, func):
        return func

    def tool(self, name=None, description=None):
        def decorator(f):
            return f
        return decorator


class FakeSubAgentCapability:
    """Stand-in for subagents_pydantic_ai.SubAgentCapability — the real capability eagerly
    compiles a pydantic_ai.Agent per subagent at construction time (requires a real,
    resolvable model string), which is unnecessary overhead for testing the a2a_access
    filtering logic in build_agent() itself."""

    def __init__(self, subagents=None, default_model=None):
        self.subagents = subagents
        self.default_model = default_model


def _setup_build_agent_common(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.setattr(agent_factory, "_hub_tools_cache", [], raising=False)
    monkeypatch.setattr(agent_factory, "_external_mcp_tools", {}, raising=False)
    monkeypatch.setattr(agent_factory, "Agent", FakeBuiltAgent)
    monkeypatch.setattr(agent_factory, "SubAgentCapability", FakeSubAgentCapability)

    async def fake_get_hub_client():
        return object()

    async def fake_discover_external_mcps(force=False):
        return None

    monkeypatch.setattr(agent_factory, "get_hub_client", fake_get_hub_client)
    monkeypatch.setattr(agent_factory, "discover_external_mcps", fake_discover_external_mcps)

    import core.memory as memory_module
    monkeypatch.setattr(memory_module, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False))


def test_build_agent_skips_internal_false_a2a_target(monkeypatch, caplog):
    _setup_build_agent_common(monkeypatch)
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeIdentityManagerA2A())

    with caplog.at_level(logging.WARNING, logger="core.agent_factory"):
        agent = asyncio.run(agent_factory.build_agent("triage-lead"))

    subagent_caps = [c for c in agent.kwargs["capabilities"] if isinstance(c, FakeSubAgentCapability)]
    assert len(subagent_caps) == 1
    names = [sa["name"] for sa in subagent_caps[0].subagents]
    assert names == ["data-parser"]

    assert "front-door-bot" in caplog.text
    assert "internal=False" in caplog.text


def test_build_agent_injects_internal_true_a2a_target(monkeypatch):
    _setup_build_agent_common(monkeypatch)
    monkeypatch.setattr(
        agent_factory,
        "get_identity_manager",
        lambda: FakeIdentityManagerA2A(),
    )
    caller_only_config = dict(CALLER_CONFIG)
    caller_only_config["a2a_access"] = ["data-parser"]

    class FakeIdentityManagerSingleTarget(FakeIdentityManagerA2A):
        def get_agent_config(self, name):
            if name == "triage-lead":
                return dict(caller_only_config)
            return super().get_agent_config(name)

    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeIdentityManagerSingleTarget())

    agent = asyncio.run(agent_factory.build_agent("triage-lead"))

    subagent_caps = [c for c in agent.kwargs["capabilities"] if isinstance(c, FakeSubAgentCapability)]
    assert len(subagent_caps) == 1
    names = [sa["name"] for sa in subagent_caps[0].subagents]
    assert names == ["data-parser"]


# --- evict_agent() reverse-dependency (a2a_access) propagation ---------------
#
# Covers the staleness gap where build_agent()'s A2A loop compiles a caller's reachable
# subagents once, at build time, into a static SubAgentCapability. If a target's `internal`
# flag flips to False after the caller was already built and cached, evicting only the
# target left the caller's stale, still-working delegation path in place indefinitely.
# evict_agent() must also evict any OTHER cached agent whose a2a_access references the
# evicted agent, recursively, with cycle protection.

class FakeIdentityManagerEvict:
    """Minimal identity manager stand-in exposing only what evict_agent() needs:
    get_all_agent_configs()."""

    def __init__(self, configs: Dict[str, Dict]):
        self._configs = configs

    def get_all_agent_configs(self) -> Dict[str, Dict]:
        return {name: dict(cfg) for name, cfg in self._configs.items()}


def _seed_cache_and_registry(monkeypatch, names):
    """Populate _agent_cache and a fresh _supervisor_registry with sentinel agents for
    each name in `names`, mirroring how get_agent() would have left things after a
    successful build."""
    fake_cache = {name: object() for name in names}
    monkeypatch.setattr(agent_factory, "_agent_cache", fake_cache, raising=False)

    fresh_registry = agent_factory.FrameworkAgentRegistry(
        FakeIdentityManagerRegistry({}), FakeHealthMonitor()
    )
    for name in names:
        config = SubAgentConfig(name=name, description="d", instructions="")
        fresh_registry.agents[name] = object()
        fresh_registry.configs[name] = config
        fresh_registry._compiled[name] = CompiledSubAgent(name=name, description="d", agent=object(), config=config)
    monkeypatch.setattr(agent_factory, "_supervisor_registry", fresh_registry, raising=False)
    return fake_cache, fresh_registry


def test_evict_agent_cascades_to_caller_via_a2a_access(monkeypatch):
    """A has a2a_access: ["B"]. Evicting B must also evict A (the caller), since A's
    already-compiled SubAgentCapability may still contain a working delegation path to B."""
    cache, registry = _seed_cache_and_registry(monkeypatch, ["A", "B"])
    fake_identity = FakeIdentityManagerEvict({
        "A": {"name": "A", "a2a_access": ["B"]},
        "B": {"name": "B", "a2a_access": []},
    })
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    agent_factory.evict_agent("B")

    assert "B" not in cache
    assert "A" not in cache
    assert registry.exists("A") is False
    assert registry.exists("B") is False


def test_evict_agent_does_not_over_evict_unrelated_agents(monkeypatch):
    """Regression guard: evicting B when no other agent references B in a2a_access must
    only evict B — an unrelated agent C must be left untouched."""
    cache, registry = _seed_cache_and_registry(monkeypatch, ["B", "C"])
    fake_identity = FakeIdentityManagerEvict({
        "B": {"name": "B", "a2a_access": []},
        "C": {"name": "C", "a2a_access": []},
    })
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    agent_factory.evict_agent("B")

    assert "B" not in cache
    assert "C" in cache
    assert registry.exists("C") is True


def test_evict_agent_cascades_through_chain(monkeypatch):
    """Chain A -> B -> C (A's a2a_access references B, B's references C). Evicting C must
    cascade-evict B (direct caller of C) and A (indirect caller, via B) too."""
    cache, registry = _seed_cache_and_registry(monkeypatch, ["A", "B", "C"])
    fake_identity = FakeIdentityManagerEvict({
        "A": {"name": "A", "a2a_access": ["B"]},
        "B": {"name": "B", "a2a_access": ["C"]},
        "C": {"name": "C", "a2a_access": []},
    })
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    agent_factory.evict_agent("C")

    assert cache == {}
    assert registry.exists("A") is False
    assert registry.exists("B") is False
    assert registry.exists("C") is False


def test_evict_agent_handles_a2a_access_cycle_without_infinite_loop(monkeypatch):
    """A cycle (A references B, B references A) must terminate cleanly rather than
    recursing forever, and must still evict both agents in the cycle."""
    cache, registry = _seed_cache_and_registry(monkeypatch, ["A", "B"])
    fake_identity = FakeIdentityManagerEvict({
        "A": {"name": "A", "a2a_access": ["B"]},
        "B": {"name": "B", "a2a_access": ["A"]},
    })
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    agent_factory.evict_agent("A")

    assert cache == {}
    assert registry.exists("A") is False
    assert registry.exists("B") is False


def test_evict_agent_is_defensive_when_config_fetch_fails(monkeypatch):
    """If fetching all agent configs raises (e.g. a transient etcd error), evict_agent must
    still successfully evict the originally-requested agent rather than propagating the
    exception — only the reverse-dependency cascade is best-effort."""
    cache, registry = _seed_cache_and_registry(monkeypatch, ["A", "B"])

    class BrokenIdentityManager:
        def get_all_agent_configs(self):
            raise RuntimeError("etcd unavailable")

    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: BrokenIdentityManager())

    agent_factory.evict_agent("B")

    assert "B" not in cache
    assert "A" in cache  # cascade couldn't run, but the direct eviction still succeeded
    assert registry.exists("B") is False
