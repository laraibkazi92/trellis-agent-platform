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
    _seed_compiled(registry, "internal-worker")

    assert registry.get_compiled("internal-worker") is None


def test_get_compiled_returns_compiled_for_external_true():
    fake_identity = FakeIdentityManagerRegistry({
        "general-agent": {"name": "general-agent", "external": True, "internal": True},
    })
    registry = agent_factory.FrameworkAgentRegistry(fake_identity, FakeHealthMonitor())
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


def test_build_agent_skips_internal_false_a2a_target(monkeypatch, capsys):
    _setup_build_agent_common(monkeypatch)
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeIdentityManagerA2A())

    agent = asyncio.run(agent_factory.build_agent("triage-lead"))

    subagent_caps = [c for c in agent.kwargs["capabilities"] if isinstance(c, FakeSubAgentCapability)]
    assert len(subagent_caps) == 1
    names = [sa["name"] for sa in subagent_caps[0].subagents]
    assert names == ["data-parser"]

    captured = capsys.readouterr()
    assert "front-door-bot" in captured.out
    assert "internal=False" in captured.out


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
