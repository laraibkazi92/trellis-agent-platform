# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for Phase 3 (Supervisor Dispatch & A2A In-Process Delegation Isolation) — see
__spec_docs/internal_external_agents_spec.md.

Covers:
  - FrameworkAgentRegistry.get_compiled() returning None for external: False agents, so the
    supervisor's task() tool can never compile/dispatch to them.
  - get_agent() not registering external: False agents into the shared _supervisor_registry.
  - build_agent()'s A2A loop skipping a2a_access targets with internal: False, while still
    injecting targets with internal: True.
  - v0.7.1: delegation child tokens — a sub-agent runs under a token minted for it (both
    delegation paths), so the hub checks ITS allowlist, not the caller's.
"""
import asyncio
import logging
from types import SimpleNamespace
from typing import Dict, Optional

import pytest

from core import agent_factory, agent_token, auth, hub, tool_access
from core.models import ToolConfig
from subagents_pydantic_ai import SubAgentConfig
from subagents_pydantic_ai.types import CompiledSubAgent

from _llm_key_seam import install_provider_keys


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
    install_provider_keys(monkeypatch)
    monkeypatch.setattr(agent_factory, "_hub_tools_cache", [], raising=False)
    monkeypatch.setattr(agent_factory, "_external_mcp_tools", {}, raising=False)
    monkeypatch.setattr(agent_factory, "Agent", FakeBuiltAgent)
    monkeypatch.setattr(agent_factory, "SubAgentCapability", FakeSubAgentCapability)

    async def fake_get_hub_client():
        return object()

    async def fake_discover_external_mcps(force=False):
        return None

    monkeypatch.setattr(
        auth,
        "get_identity_manager",
        lambda: SimpleNamespace(
            get_agent_config=lambda name: {"allowed_tools": ["text_stats"]}
        ),
    )
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
    # build_agent must hand the capability a resolved Model instance, not a bare
    # model-name string (subagents-pydantic-ai raises on strings under pydantic-ai 2.31).
    from pydantic_ai.models import Model as _Model
    assert isinstance(subagent_caps[0].default_model, _Model)

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


# --- v0.7.1 Phase 3: delegation child tokens ---------------------------------
#
# A delegated sub-agent used to inherit the caller's token, so every tool call it made
# was authorized against the CALLER's allowlist. `_delegated_run` mints a token for the
# child agent, installs it in `agent_token_var` (the only channel — no tool argument
# carries it) and restores the parent's when the child run ends, however it ends.

SECRET = "delegation-token-unit-secret-0123456789abcdef"


@pytest.fixture
def delegation_tokens(monkeypatch):
    """Real minting/verification, enforced, with a clean run context per test."""
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv("DEV_MODE", raising=False)
    for var in (auth.agent_token_var, auth.user_id_var, auth.run_id_var):
        var.set(None)
    yield
    for var in (auth.agent_token_var, auth.user_id_var, auth.run_id_var):
        var.set(None)


@pytest.fixture
def no_group_rules(monkeypatch):
    """An empty tool-access policy: no group rules, so the allowlist alone decides."""
    from core import tool_access

    class _NoPolicy:
        def put(self, key, value):
            raise AssertionError(f"no write expected: {key}")

        def get(self, key, **_kwargs):
            return None, None

    monkeypatch.setattr(tool_access, "_client", lambda: _NoPolicy())
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()
    yield
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()


def _parent_token(agent="supervisor", run_id="run-parent", email="dev@example.com"):
    return agent_token.mint_for_run(
        agent,
        "user-1",
        user_email=email,
        groups=["ops", "dev"],
        run_id=run_id,
    )


def test_delegated_run_mints_a_token_for_the_target_agent(delegation_tokens):
    """The child's token names the TARGET agent, carries a fresh run id with the
    parent's run id as `p`, and inherits `u`/`e`/`g` from the parent."""
    _parent_token()
    seen: Dict[str, object] = {}

    async def child_run():
        seen["claims"] = agent_token.verify(auth.agent_token_var.get())
        seen["run_id_var"] = auth.run_id_var.get()

    async def scenario():
        async with agent_factory._delegated_run("data-parser") as child_run_id:
            await child_run()
            return child_run_id

    child_run_id = asyncio.run(scenario())

    claims = seen["claims"]
    assert claims.agent == "data-parser"
    assert claims.parent_run_id == "run-parent"
    assert claims.run_id == child_run_id != "run-parent"
    assert claims.user_id == "user-1"
    assert claims.user_email == "dev@example.com"
    assert claims.groups == ("dev", "ops")
    assert seen["run_id_var"] == child_run_id


async def _claims_probe():
    return agent_token.verify(auth.agent_token_var.get())


def test_delegated_run_restores_the_parent_token(delegation_tokens):
    parent = _parent_token()

    async def scenario():
        inside = await agent_factory._run_as_delegate("data-parser", _claims_probe)
        return inside, auth.agent_token_var.get(), auth.run_id_var.get()

    inside, token, run_id = asyncio.run(scenario())

    assert inside.agent == "data-parser"
    assert token == parent
    assert run_id == "run-parent"


def test_delegated_run_restores_the_parent_token_when_the_child_raises(delegation_tokens):
    parent = _parent_token()

    async def scenario():
        with pytest.raises(RuntimeError):
            async with agent_factory._delegated_run("data-parser"):
                raise RuntimeError("child exploded")
        return auth.agent_token_var.get(), auth.run_id_var.get()

    token, run_id = asyncio.run(scenario())

    assert token == parent
    assert run_id == "run-parent"


def test_delegated_run_restores_the_parent_token_when_the_child_is_cancelled(delegation_tokens):
    """Cancellation unwinds through the seam's `finally`, so the caller keeps its token."""
    parent = _parent_token()
    entered = asyncio.Event()
    restored: Dict[str, object] = {}

    async def scenario():
        async def delegation():
            try:
                async with agent_factory._delegated_run("data-parser"):
                    entered.set()
                    await asyncio.Event().wait()  # parked until cancelled
            except asyncio.CancelledError:
                restored["token"] = auth.agent_token_var.get()
                restored["run_id"] = auth.run_id_var.get()
                raise

        task = asyncio.create_task(delegation())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())

    assert restored == {"token": parent, "run_id": "run-parent"}


def test_nested_delegation_chains_each_parent_run_id(delegation_tokens):
    """A -> B -> C: C's `p` is B's run id, and each level restores its own parent."""
    _parent_token(agent="agent-a", run_id="run-a")
    seen: Dict[str, object] = {}

    async def scenario():
        async with agent_factory._delegated_run("agent-b") as run_b:
            seen["b"] = agent_token.verify(auth.agent_token_var.get())
            async with agent_factory._delegated_run("agent-c") as run_c:
                seen["c"] = agent_token.verify(auth.agent_token_var.get())
            seen["after_c"] = agent_token.verify(auth.agent_token_var.get())
            seen["run_c"] = run_c
        seen["after_b"] = agent_token.verify(auth.agent_token_var.get())
        seen["run_b"] = run_b

    asyncio.run(scenario())

    assert seen["b"].agent == "agent-b"
    assert seen["b"].parent_run_id == "run-a"
    assert seen["c"].agent == "agent-c"
    assert seen["c"].parent_run_id == seen["run_b"]
    assert seen["c"].run_id == seen["run_c"]
    assert seen["after_c"].agent == "agent-b"  # inner scope closed, middle one intact
    assert seen["after_b"].agent == "agent-a"


def test_delegation_without_a_parent_token_mints_nothing(delegation_tokens):
    """No parent token means no child token: the child runs as it always did."""
    minted = []

    async def scenario():
        async with agent_factory._delegated_run("data-parser") as child_run_id:
            minted.append(child_run_id)
            minted.append(auth.agent_token_var.get())
        minted.append(auth.agent_token_var.get())

    asyncio.run(scenario())

    assert minted == [None, None, None]


def test_child_token_reaches_the_hub_tool_call(delegation_tokens, no_group_rules, monkeypatch):
    """The bound-tool wrapper forwards whatever token is installed, so a delegated
    child's call arrives at the hub as ITS token, not the caller's."""
    captured = []
    auth.user_id_var.set("user-1")

    class RecordingHubClient:
        async def call_tool(self, name, arguments):
            captured.append(arguments)
            return SimpleNamespace(content=["ok"])

    class RecordingToolAgent:
        def __init__(self):
            self.tools = {}

        def tool(self, name=None, description=None):
            def deco(fn):
                self.tools[name or fn.__name__] = fn
                return fn

            return deco

    async def fake_get_hub_client():
        return RecordingHubClient()

    async def scenario():
        _parent_token()
        async with agent_factory._delegated_run("data-parser"):
            await recording_agent.tools["text_stats"](None)

    monkeypatch.setattr(
        auth,
        "get_identity_manager",
        lambda: SimpleNamespace(
            get_agent_config=lambda name: {"allowed_tools": ["text_stats"]}
        ),
    )
    monkeypatch.setattr(agent_factory, "get_hub_client", fake_get_hub_client)
    monkeypatch.setattr(
        agent_factory,
        "get_health_monitor",
        lambda: SimpleNamespace(get_status=lambda *a: {"status": "Online"}),
    )
    recording_agent = RecordingToolAgent()
    agent_factory._register_mcp_tool(
        recording_agent, SimpleNamespace(name="text_stats", description="Stats.")
    )

    asyncio.run(scenario())

    [arguments] = captured
    claims = agent_token.verify(arguments["__agent_token"])
    assert claims.agent == "data-parser"
    assert claims.parent_run_id == "run-parent"


class FakeHubRegistry:
    """Only the read `hub._authorize_call` makes: the caller agent's record."""

    def __init__(self, configs: Dict[str, Dict]):
        self._configs = configs

    def get_agent_config(self, name):
        return self._configs.get(name)


def test_hub_authorizes_the_child_against_its_own_allowlist(
    delegation_tokens, no_group_rules, monkeypatch
):
    """The real hub decision: the parent's manifest grants `text_stats`, the child's
    does not, and the child's token is what reaches the hub mid-delegation."""
    monkeypatch.setattr(
        hub,
        "identity_mgr",
        FakeHubRegistry({
            "supervisor": {"name": "supervisor", "allowed_tools": ["text_stats"]},
            "data-parser": {"name": "data-parser", "allowed_tools": []},
        }),
    )
    tool = ToolConfig(
        name="text_stats", description="Stats.", runtime="python", entrypoint="main.py"
    )
    outcome: Dict[str, object] = {}

    async def scenario():
        parent = _parent_token()
        assert (await hub._authorize_call(tool, parent))[1] is None
        async with agent_factory._delegated_run("data-parser"):
            outcome["child_token"] = auth.agent_token_var.get()
            claims, outcome["denial"] = await hub._authorize_call(
                tool, auth.agent_token_var.get()
            )
            outcome["child_agent"] = claims.agent
        # ... and the parent's own grant is intact again once the child is done.
        return (await hub._authorize_call(tool, auth.agent_token_var.get()))[1]

    parent_after = asyncio.run(scenario())

    assert outcome["child_agent"] == "data-parser"
    # The evaluator's own message names the agent and the target it refused.
    assert "access_denied" in outcome["denial"]["error"]
    assert "'data-parser'" in outcome["denial"]["error"]
    assert "'text_stats'" in outcome["denial"]["error"]
    assert parent_after is None


def test_a_delegated_child_is_authorized_by_its_own_token(delegation_tokens, monkeypatch):
    """The bound-tool gate answers for the CHILD mid-delegation: its own allowlist and
    the groups its token inherited from the parent's claims (never a record read)."""
    from types import SimpleNamespace

    from core import tool_access

    class _NoPolicy:
        def put(self, key, value):
            raise AssertionError(f"no write expected: {key}")

        def get(self, key, **_kwargs):
            return None, None

    monkeypatch.setattr(tool_access, "_client", lambda: _NoPolicy())
    tool_access.reset_snapshot()
    monkeypatch.setattr(
        auth,
        "get_identity_manager",
        lambda: SimpleNamespace(
            get_agent_config=lambda name: {"allowed_tools": ["text_stats"] if name == "data-parser" else []}
        ),
    )
    seen = {}

    async def scenario():
        _parent_token()  # supervisor: no tools of its own
        seen["parent"] = await agent_factory._bound_tool_denial("text_stats")
        async with agent_factory._delegated_run("data-parser"):
            claims = agent_token.verify(auth.agent_token_var.get())
            seen["child_groups"] = claims.groups
            seen["child"] = await agent_factory._bound_tool_denial("text_stats")
        return await agent_factory._bound_tool_denial("text_stats")

    seen["parent_after"] = asyncio.run(scenario())

    # The parent is refused, the child is granted, and the parent's refusal is back.
    assert seen["parent"] is not None
    assert seen["child"] is None
    assert seen["parent_after"] is not None
    # Groups travel in the token, inherited from the parent claims at mint.
    assert seen["child_groups"] == ("dev", "ops")


# --- seam installation on both delegation paths ------------------------------

class FakeChildAgent:
    """Records the delegation claims visible when a run entry point is called."""

    def __init__(self):
        self.runs = []
        self.iterations = []
        self.streams = []
        self.sync_runs = []
        self.sync_streams = []
        self.events = []

    async def run(self, prompt):
        self.runs.append(agent_token.verify(auth.agent_token_var.get()))
        return f"ran: {prompt}"

    def run_sync(self, prompt):
        self.sync_runs.append(agent_token.verify(auth.agent_token_var.get()))
        return f"ran: {prompt}"

    def iter(self, prompt):
        return self._scope(self.iterations)

    def run_stream(self, prompt):
        return self._scope(self.streams)

    def run_stream_sync(self, prompt):
        return self._sync_scope(self.sync_streams)

    async def run_stream_events(self, prompt):
        self.events.append(agent_token.verify(auth.agent_token_var.get()))
        yield "event"

    def _scope(self, sink):
        class FakeRun:
            async def __aenter__(self):
                sink.append(agent_token.verify(auth.agent_token_var.get()))
                return self

            async def __aexit__(self, *exc_info):
                return None

        return FakeRun()

    def _sync_scope(self, sink):
        class FakeRun:
            def __enter__(self):
                sink.append(agent_token.verify(auth.agent_token_var.get()))
                return self

            def __exit__(self, *exc_info):
                return None

        return FakeRun()


def test_supervisor_dispatch_runs_the_child_under_its_own_token(delegation_tokens, monkeypatch):
    """`FrameworkAgentRegistry.get_compiled()` hands the supervisor's task() tool an
    agent whose runs carry the child's token (`run`, plus the library's `iter` retry
    path and the streaming context manager)."""
    fake_identity = FakeIdentityManagerRegistry({})
    registry = agent_factory.FrameworkAgentRegistry(fake_identity, FakeHealthMonitor())
    child = FakeChildAgent()
    registry.register(SubAgentConfig(name="data-parser", description="d", instructions=""), child)

    compiled_once = registry.get_compiled("data-parser")
    compiled_twice = registry.get_compiled("data-parser")

    async def scenario():
        _parent_token()
        await compiled_once.agent.run("parse it")
        async with compiled_once.agent.iter("parse it"):
            pass
        async with compiled_once.agent.run_stream("parse it"):
            pass
        return auth.agent_token_var.get()

    parent_after = asyncio.run(scenario())

    assert compiled_once.agent is not child  # wrapped, never mutated in place
    assert registry.agents["data-parser"] is child  # the stored entry is untouched
    assert compiled_once.agent is not compiled_twice.agent  # one proxy per dispatch
    claims, iter_claims, stream_claims = child.runs[0], child.iterations[0], child.streams[0]
    assert claims.agent == "data-parser"
    assert claims.parent_run_id == "run-parent"
    assert iter_claims.agent == "data-parser"
    assert stream_claims.agent == "data-parser"
    assert parent_after is not None
    assert agent_token.verify(parent_after).agent == "supervisor"


def test_every_remaining_run_entry_point_is_scoped_too(delegation_tokens, monkeypatch):
    """`run_sync` / `run_stream_sync` / `run_stream_events` must not be a way around
    the seam: a caller that reaches one of them still calls as the child."""
    fake_identity = FakeIdentityManagerRegistry({})
    registry = agent_factory.FrameworkAgentRegistry(fake_identity, FakeHealthMonitor())
    child = FakeChildAgent()
    registry.register(SubAgentConfig(name="data-parser", description="d", instructions=""), child)
    wrapped = registry.get_compiled("data-parser").agent

    async def scenario():
        _parent_token()
        wrapped.run_sync("parse it")
        with wrapped.run_stream_sync("parse it"):
            pass
        events = [event async for event in wrapped.run_stream_events("parse it")]
        return events, auth.agent_token_var.get(), auth.run_id_var.get()

    events, parent_after, parent_run_id = asyncio.run(scenario())

    claims = child.sync_runs[0]
    assert claims.agent == "data-parser"
    assert claims.parent_run_id == "run-parent"
    assert child.sync_streams[0].agent == "data-parser"
    # The async generator installs the token for the whole iteration, not per event.
    assert child.events[0].agent == "data-parser"
    assert events == ["event"]
    assert agent_token.verify(parent_after).agent == "supervisor"
    assert parent_run_id == "run-parent"


def test_a_missing_entry_point_is_not_silently_unwrapped():
    """A wrapped agent without `run_sync` raises rather than running unscoped."""

    class MinimalChild:
        async def run(self, prompt):
            return prompt

    wrapped = agent_factory._DelegatedAgent("data-parser", MinimalChild())

    with pytest.raises(AttributeError):
        wrapped.run_sync("parse it")


def _mint_failure(monkeypatch):
    """Make `mint_for_run` fail the way a missing or rotated key does."""
    def boom(*_args, **_kwargs):
        raise agent_token.AgentTokenError(
            "missing_secret", "AGENT_TOKEN_SECRET is not set"
        )

    monkeypatch.setattr(agent_token, "mint_for_run", boom)


def test_enforce_refuses_to_delegate_when_no_child_token_can_be_minted(
    delegation_tokens, monkeypatch
):
    """Fail closed: the child must never inherit the parent's allowlist.

    Before this, a mint failure fell back to the parent's token, which silently gave
    the sub-agent every tool the caller had. In enforce mode the delegation tool now
    gets the error and the child never runs.
    """
    parent = _parent_token()
    _mint_failure(monkeypatch)
    ran = []

    async def child():
        ran.append(True)

    async def scenario():
        with pytest.raises(agent_token.AgentTokenError):
            await agent_factory._run_as_delegate("data-parser", child)
        with pytest.raises(agent_token.AgentTokenError):
            async with agent_factory._delegated_run("data-parser"):
                ran.append(True)
        return auth.agent_token_var.get(), auth.run_id_var.get()

    token, run_id = asyncio.run(scenario())

    assert ran == []  # the child never ran at all
    assert token == parent  # and the caller's context is untouched
    assert run_id == "run-parent"


def test_log_mode_keeps_the_documented_parent_token_fallback(
    delegation_tokens, monkeypatch, caplog
):
    """In `log` mode a mint failure still falls back to the parent's token.

    Nothing is authorized in that posture, and a rollout must not be the one thing
    that breaks delegation -- but it has to be loud about it.
    """
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    parent = _parent_token()
    _mint_failure(monkeypatch)
    seen = {}

    async def child():
        seen["claims"] = agent_token.verify(auth.agent_token_var.get())

    async def scenario():
        async with agent_factory._delegated_run("data-parser") as child_run_id:
            await child()
            return child_run_id

    with caplog.at_level(logging.WARNING, logger="core.agent_factory"):
        child_run_id = asyncio.run(scenario())

    assert child_run_id is None
    assert seen["claims"].agent == "supervisor"  # the documented fallback
    assert "parent's token" in caplog.text
    assert auth.agent_token_var.get() == parent


def test_a2a_subagent_agent_factory_wraps_the_compiled_agent(monkeypatch):
    """build_agent's A2A path compiles its subagents through a factory that returns the
    library's own agent, wrapped — `agent_factory` is dropped so the compile cannot
    recurse, and `ask_parent` is left to the toolset's run-time injection."""
    compiled_agent = FakeChildAgent()
    seen: Dict[str, object] = {}

    def fake_compile(config, default_model):
        seen["config"] = config
        seen["default_model"] = default_model
        return CompiledSubAgent(
            name=config["name"],
            description=config["description"],
            agent=compiled_agent,
            config=config,
        )

    monkeypatch.setattr(agent_factory, "_compile_subagent", fake_compile)
    factory = agent_factory._delegating_subagent_factory("data-parser", "sentinel-model")
    wrapped = factory(
        SubAgentConfig(
            name="data-parser",
            description="Parses input.",
            instructions="You parse.",
            can_ask_questions=True,
            agent_factory=lambda config: compiled_agent,
        )
    )

    assert isinstance(wrapped, agent_factory._DelegatedAgent)
    assert wrapped._delegation_agent is compiled_agent
    assert "agent_factory" not in seen["config"]
    assert seen["config"]["can_ask_questions"] is False
    assert seen["default_model"] == "sentinel-model"


def test_build_agent_wires_the_seam_into_every_a2a_subagent(monkeypatch):
    _setup_build_agent_common(monkeypatch)
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeIdentityManagerA2A())

    agent = asyncio.run(agent_factory.build_agent("triage-lead"))

    [capability] = [
        c for c in agent.kwargs["capabilities"] if isinstance(c, FakeSubAgentCapability)
    ]
    [subagent] = [sa for sa in capability.subagents if sa["name"] == "data-parser"]
    assert callable(subagent["agent_factory"])
