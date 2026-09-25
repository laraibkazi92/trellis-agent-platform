"""Phase 4 regression tests — see __spec_docs/cycle4_hub_agent_factory_hardening_plan.md
"Phase 4: Discovery — collapse legacy requirement aggregators (I3 + I9-discovery)".

`get_agent_required_secrets` / `get_agent_optional_secrets` / `get_agent_secret_groups` /
`get_agent_required_variables` used to each re-implement requirement aggregation with
sequential per-tool awaits. They are now thin wrappers over `_fetch_agent_tool_mcp_configs`
(concurrent `asyncio.to_thread` fetches) + the shared pure `_resolve_agent_requirements`,
returning sorted lists (raw list, no sorting, for secret_groups) and dropping failed
per-tool/MCP fetches (fail-soft, unless ``strict=True`` is passed to re-raise) instead
of raising.
"""
import asyncio
import threading

import pytest

from core import discovery
from core.models import IdentityType


def _patch_aggregator_identities(monkeypatch, tool_configs=None, mcp_configs=None):
    """Patch the per-agent aggregators' only I/O seam: identity_mgr's tool/MCP lookups.

    Mirrors the fake style of tests/test_discovery_configuration.py (which patches
    ``discovery.identity_mgr`` methods directly -- no real etcd involved).
    """
    tool_configs = tool_configs or {}
    mcp_configs = mcp_configs or {}

    monkeypatch.setattr(discovery.identity_mgr, "get_tool_config", lambda name: tool_configs.get(name))
    monkeypatch.setattr(discovery.identity_mgr, "get_mcp_config", lambda name: mcp_configs.get(name))


# --- Task 4.1: aggregator wrappers ------------------------------------------------

MIXED_AGENT_CONFIG = {
    "name": "mixed-agent",
    "type": "user_agent",
    "secrets": {"general": ["GEN_S"], "user": ["USER_S"]},
    "variables": ["AGENT_VAR"],
    "allowed_tools": ["direct-tool", "mcp__srv__some_tool"],
    "allowed_mcps": ["srv2"],
}


def test_required_secrets_wrapper_matches_legacy_semantics(monkeypatch):
    """One config exercising every aggregation branch simultaneously: own dict-shaped
    secrets, a direct tool (secrets + optional_secrets + variables + secret_groups), an
    ``mcp__``-prefixed allowed_tools entry, and an allowed_mcps entry -- asserting all
    four wrappers produce the same sorted/raw results the legacy bodies did."""
    _patch_aggregator_identities(
        monkeypatch,
        tool_configs={
            "direct-tool": {
                "secrets": ["TOOL_S"],
                "optional_secrets": ["TOOL_OPT"],
                "variables": ["TOOL_V"],
                "secret_groups": [{"label": "Tool Group", "options": []}],
            },
        },
        mcp_configs={
            "srv": {
                "secrets": ["MCP_S"],
                "secret_groups": [{"label": "Mcp Group", "options": []}],
            },
            "srv2": {
                "secrets": {"general": ["MCP2_S"], "user": ["MCP2_U"]},
                "optional_secrets": ["MCP2_OPT"],
                "variables": {"general": ["MCP2_V"]},
                "secret_groups": [{"label": "Srv2 Group", "options": []}],
            },
        },
    )

    assert asyncio.run(discovery.get_agent_required_secrets(MIXED_AGENT_CONFIG)) == sorted(
        ["GEN_S", "USER_S", "TOOL_S", "MCP_S", "MCP2_S", "MCP2_U"]
    )
    assert asyncio.run(discovery.get_agent_optional_secrets(MIXED_AGENT_CONFIG)) == sorted(
        ["TOOL_OPT", "MCP2_OPT"]
    )
    assert asyncio.run(discovery.get_agent_required_variables(MIXED_AGENT_CONFIG)) == sorted(
        ["AGENT_VAR", "TOOL_V", "MCP2_V"]
    )
    assert asyncio.run(discovery.get_agent_secret_groups(MIXED_AGENT_CONFIG)) == [
        {"label": "Tool Group", "options": []},
        {"label": "Mcp Group", "options": []},
        {"label": "Srv2 Group", "options": []},
    ]


def test_secret_groups_wrapper_resolves_mcp_prefixed_tools(monkeypatch):
    """Parity with tests/test_discovery_configuration.py's secret-groups test: an agent
    referencing an MCP only via an ``mcp__``-prefixed allowed_tools entry gets its owning
    MCP's secret_groups -- and, unlike the legacy body, no tool lookup is attempted for
    the ``mcp__`` name at all (it is routed straight to the MCP fetch helper)."""
    tool_lookups = []
    mcp_lookups = []

    def fake_get_tool_config(name):
        tool_lookups.append(name)
        return None

    def fake_get_mcp_config(name):
        mcp_lookups.append(name)
        return {"secret_groups": [{"label": "Example API Environment Credentials", "options": []}]}

    monkeypatch.setattr(discovery.identity_mgr, "get_tool_config", fake_get_tool_config)
    monkeypatch.setattr(discovery.identity_mgr, "get_mcp_config", fake_get_mcp_config)

    config = {"allowed_tools": ["mcp__example-mcp__clusters_get_all"], "allowed_mcps": []}
    groups = asyncio.run(discovery.get_agent_secret_groups(config))

    assert groups == [{"label": "Example API Environment Credentials", "options": []}]
    assert "mcp__example-mcp__clusters_get_all" not in tool_lookups
    assert all(not name.startswith("mcp__") for name in tool_lookups)
    assert mcp_lookups == ["example-mcp"]


def test_aggregators_fetch_concurrently(monkeypatch):
    """The aggregator's per-tool fetches genuinely overlap: all three fake lookups
    rendezvous at a shared ``threading.Barrier(3)`` that only releases once every
    lookup is in flight. A sequential implementation would block on the first
    ``barrier.wait()``, hit the 2s timeout, and raise ``BrokenBarrierError`` -- so
    ``released`` would never collect all three names (the default fail-soft swallows
    that error, failing the assertion instead of hanging the test)."""
    loop_thread_id = threading.get_ident()
    barrier = threading.Barrier(3, timeout=2)
    released = []

    def fake_get_tool_config(name):
        barrier.wait()
        released.append((name, threading.get_ident()))
        return {}

    monkeypatch.setattr(discovery.identity_mgr, "get_tool_config", fake_get_tool_config)

    config = {"allowed_tools": ["t1", "t2", "t3"], "allowed_mcps": []}
    asyncio.run(discovery.get_agent_required_secrets(config))

    assert {name for name, _ in released} == {"t1", "t2", "t3"}
    assert all(thread_id != loop_thread_id for _, thread_id in released)


def test_aggregator_fetch_fails_soft_by_default(monkeypatch):
    """Default behavior: one tool lookup raising must be dropped (with the other
    tool's config still contributing) rather than failing the whole aggregation."""
    def fake_get_tool_config(name):
        if name == "bad":
            raise RuntimeError("etcd down")
        return {"secrets": ["GOOD_S"]}

    monkeypatch.setattr(discovery.identity_mgr, "get_tool_config", fake_get_tool_config)

    config = {"allowed_tools": ["good", "bad"], "allowed_mcps": []}
    assert asyncio.run(discovery.get_agent_required_secrets(config)) == ["GOOD_S"]


def test_aggregator_fetch_strict_reraises_lookup_failure(monkeypatch):
    """``strict=True`` (the write/launch paths) restores the legacy loud-failure
    behavior: a failed lookup propagates instead of being silently dropped."""
    def fake_get_tool_config(name):
        if name == "bad":
            raise RuntimeError("etcd down")
        return {"secrets": ["GOOD_S"]}

    monkeypatch.setattr(discovery.identity_mgr, "get_tool_config", fake_get_tool_config)

    config = {"allowed_tools": ["good", "bad"], "allowed_mcps": []}
    with pytest.raises(RuntimeError, match="etcd down"):
        asyncio.run(discovery.get_agent_required_secrets(config, strict=True))


def test_aggregators_dedupe_repeated_mcp_lookups(monkeypatch):
    """An MCP referenced both via an ``mcp__``-prefixed allowed_tools entry and via
    allowed_mcps is fetched exactly once, but its requirements are absorbed for each
    reference (raw duplicates preserved, matching legacy list semantics)."""
    mcp_calls = []

    def fake_get_mcp_config(name):
        mcp_calls.append(name)
        return {"secret_groups": [{"label": "G", "options": []}]}

    monkeypatch.setattr(discovery.identity_mgr, "get_mcp_config", fake_get_mcp_config)

    config = {"allowed_tools": ["mcp__srv__a"], "allowed_mcps": ["srv"]}
    groups = asyncio.run(discovery.get_agent_secret_groups(config))

    assert mcp_calls == ["srv"]
    assert groups == [{"label": "G", "options": []}, {"label": "G", "options": []}]


def test_wrapper_uses_background_context_for_dict_requirements(monkeypatch):
    """A background agent's dict-shaped requirements resolve ``general`` +
    ``background`` (never ``user``), whichever wrapper is called."""
    _patch_aggregator_identities(monkeypatch)

    config = {
        "type": "background_agent",
        "secrets": {"general": ["GEN"], "user": ["U"], "background": ["BG"]},
        "allowed_tools": [],
        "allowed_mcps": [],
    }

    assert asyncio.run(discovery.get_agent_required_secrets(config)) == ["BG", "GEN"]


# --- Task 4.2: bulk background-identity resolution in discover_agents -------------


def _patch_bulk_identities_with_workflow_stores(monkeypatch, agent_configs, workflow_secrets, fail_for=None):
    """Same bulk-fake shape as tests/test_discovery_configuration.py's
    ``_patch_bulk_identities``, except ``get_identity_config`` resolves WORKFLOW
    identities from a per-agent-name store (keyed by ``identity.id``) so each
    background agent's own secrets can be told apart. Records every WORKFLOW
    ``(identity.id, category)`` lookup and raises for identities in ``fail_for``."""
    calls = []
    fail_for = fail_for or set()

    monkeypatch.setattr(discovery.identity_mgr, "get_all_agent_configs", lambda: agent_configs)
    monkeypatch.setattr(discovery.identity_mgr, "get_all_agent_skills", lambda: {})
    monkeypatch.setattr(discovery.identity_mgr, "get_all_health_statuses", lambda entity_type: {})
    monkeypatch.setattr(discovery.identity_mgr, "get_all_tool_configs", lambda: {})
    monkeypatch.setattr(discovery.identity_mgr, "get_all_mcp_configs", lambda: {})

    def fake_get_identity_config(identity, category, keys=None):
        if identity.type == IdentityType.WORKFLOW:
            calls.append((identity.id, category))
            if identity.id in fail_for:
                raise RuntimeError(f"etcd down for {identity.id}")
            if category == "secrets":
                return workflow_secrets.get(identity.id, {})
        return {}

    monkeypatch.setattr(discovery.identity_mgr, "get_identity_config", fake_get_identity_config)
    return calls


def _two_background_agent_configs():
    return {
        "wf-a": {"name": "wf-a", "type": "background_agent", "secrets": ["A_KEY"], "allowed_tools": [], "allowed_mcps": []},
        "wf-b": {"name": "wf-b", "type": "background_agent", "secrets": ["B_KEY"], "allowed_tools": [], "allowed_mcps": []},
    }


def test_discover_agents_background_identities_all_resolved(monkeypatch):
    """Two background agents with distinct secrets must each be evaluated against
    their own workflow identity store -- proving the pre-loop gather wired
    ``bg_config_secrets`` per agent name instead of both being resolved from one
    identity (or from the human user's secrets), and fetched each identity's secrets
    and variables exactly once."""
    calls = _patch_bulk_identities_with_workflow_stores(
        monkeypatch,
        _two_background_agent_configs(),
        {"wf-a": {"A_KEY": "***"}, "wf-b": {}},
    )

    agents = asyncio.run(discovery.discover_agents(user_id="user-123", include_background=True))
    by_name = {agent["name"]: agent for agent in agents}

    assert by_name["wf-a"]["is_configured"] is True
    assert by_name["wf-b"]["is_configured"] is False
    assert "B_KEY" in by_name["wf-b"]["missing_secrets"]

    for name in ("wf-a", "wf-b"):
        assert calls.count((name, "secrets")) == 1
        assert calls.count((name, "variables")) == 1


def test_discover_agents_background_identity_failure_isolated(monkeypatch):
    """A workflow identity whose secrets/variables fetch raises must fall back to
    ``{}`` for that agent only -- the other agent still resolves, and no exception
    escapes ``discover_agents`` (the pre-Phase-4 per-agent awaits used to propagate)."""
    _patch_bulk_identities_with_workflow_stores(
        monkeypatch,
        _two_background_agent_configs(),
        {"wf-a": {"A_KEY": "***"}, "wf-b": {}},
        fail_for={"wf-b"},
    )

    agents = asyncio.run(discovery.discover_agents(user_id="user-123", include_background=True))
    by_name = {agent["name"]: agent for agent in agents}

    assert by_name["wf-a"]["is_configured"] is True
    assert by_name["wf-b"]["is_configured"] is False
    assert "B_KEY" in by_name["wf-b"]["missing_secrets"]


def test_discover_agents_skips_background_identity_fetches_when_excluded(monkeypatch):
    """``include_background=False`` must not fetch any WORKFLOW identity configs at all
    (the prefetch is gated on the same flag as the loop's background filter)."""
    calls = _patch_bulk_identities_with_workflow_stores(
        monkeypatch,
        _two_background_agent_configs(),
        {"wf-a": {"A_KEY": "***"}},
    )

    agents = asyncio.run(discovery.discover_agents(user_id="user-123", include_background=False))

    assert agents == []
    assert calls == []
