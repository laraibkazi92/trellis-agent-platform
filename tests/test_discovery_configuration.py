"""Phase C regression tests — see __spec_docs/rules_engine_hardening_plan.md §2C.

Before Phase C, neither `is_agent_configured` nor `discover_agents` ever called
`_unsatisfied_secret_group_keys`, so an agent depending on a tool/MCP that declares
`secret_groups` (e.g. netctl's per-environment username/password picker) with zero
fully-configured options would incorrectly report `is_configured: True` -- the same
bug `tests/test_tool_search.py` already regression-tests for `is_tool_configured`.
These tests exercise the same scenario one level up, through the two agent-level
entry points that now share `_resolve_agent_requirements`/`_evaluate_agent_configuration`
with `is_tool_configured`.
"""
import asyncio

from core import discovery
from core.models import Identity, IdentityType


NETCTL_LIKE_TOOL_CONFIG = {
    "name": "netctl",
    "secrets": [],
    "optional_secrets": [
        "EXAMPLE-API_STAGING_USERNAME", "EXAMPLE-API_STAGING_PASSWORD",
        "EXAMPLE-API_PRODUCTION_USERNAME", "EXAMPLE-API_PRODUCTION_PASSWORD",
    ],
    "secret_groups": [
        {
            "label": "Example API Environment Credentials",
            "options": [
                {"value": "staging", "fields": [
                    {"key": "EXAMPLE-API_STAGING_USERNAME", "label": "Username"},
                    {"key": "EXAMPLE-API_STAGING_PASSWORD", "label": "Password"},
                ]},
                {"value": "production", "fields": [
                    {"key": "EXAMPLE-API_PRODUCTION_USERNAME", "label": "Username"},
                    {"key": "EXAMPLE-API_PRODUCTION_PASSWORD", "label": "Password"},
                ]},
            ],
        }
    ],
}

AGENT_WITH_SECRET_GROUP_TOOL = {
    "name": "example-agent",
    "type": "user_agent",
    "allowed_tools": ["netctl"],
    "allowed_mcps": [],
}


# --- is_agent_configured -------------------------------------------------------

def _patch_agent_identities(monkeypatch, agent_config=None, tool_config=None, mcp_config=None,
                             global_secrets=None, global_variables=None,
                             user_secrets=None, user_variables=None):
    monkeypatch.setattr(discovery.identity_mgr, "get_agent_config", lambda name: agent_config)
    monkeypatch.setattr(discovery.identity_mgr, "get_tool_config", lambda name: tool_config)
    monkeypatch.setattr(discovery.identity_mgr, "get_mcp_config", lambda name: mcp_config)

    def fake_get_identity_config(identity, category, keys=None):
        if identity.type == IdentityType.SYSTEM:
            store = global_secrets if category == "secrets" else global_variables
        else:
            store = user_secrets if category == "secrets" else user_variables
        return store or {}

    monkeypatch.setattr(discovery.identity_mgr, "get_identity_config", fake_get_identity_config)


def test_is_agent_configured_no_secret_group_option_satisfied_is_not_configured(monkeypatch):
    """Regression for the Phase C bug: an agent whose only attached tool declares
    secret_groups (no plain `secrets`) with zero options fully configured must report
    configured=False, listing the group's field keys as missing -- previously
    is_agent_configured never checked secret_groups at all and would report True."""
    _patch_agent_identities(
        monkeypatch,
        agent_config=AGENT_WITH_SECRET_GROUP_TOOL,
        tool_config=NETCTL_LIKE_TOOL_CONFIG,
        global_secrets={},
        user_secrets={},
    )

    result = asyncio.run(discovery.is_agent_configured("example-agent", "user-123"))

    assert result["configured"] is False
    assert "EXAMPLE-API_STAGING_USERNAME" in result["missing_secrets"]
    assert "EXAMPLE-API_PRODUCTION_USERNAME" in result["missing_secrets"]


def test_is_agent_configured_one_secret_group_option_fully_set_is_configured(monkeypatch):
    _patch_agent_identities(
        monkeypatch,
        agent_config=AGENT_WITH_SECRET_GROUP_TOOL,
        tool_config=NETCTL_LIKE_TOOL_CONFIG,
        global_secrets={},
        user_secrets={
            "EXAMPLE-API_PRODUCTION_USERNAME": "***",
            "EXAMPLE-API_PRODUCTION_PASSWORD": "***",
        },
    )

    result = asyncio.run(discovery.is_agent_configured("example-agent", "user-123"))

    assert result["configured"] is True
    assert result["missing_secrets"] == []


def test_is_agent_configured_partial_secret_group_option_is_not_configured(monkeypatch):
    """A half-filled option (only the username saved, not the password) must not count
    as satisfied -- exercises the early-exit guard added in Phase C, since there are no
    plain required_secrets/variables here at all, only an unsatisfied secret_group."""
    _patch_agent_identities(
        monkeypatch,
        agent_config=AGENT_WITH_SECRET_GROUP_TOOL,
        tool_config=NETCTL_LIKE_TOOL_CONFIG,
        global_secrets={},
        user_secrets={"EXAMPLE-API_PRODUCTION_USERNAME": "***"},
    )

    result = asyncio.run(discovery.is_agent_configured("example-agent", "user-123"))

    assert result["configured"] is False


def test_is_agent_configured_plain_required_secret_still_checked(monkeypatch):
    """Non-regression: a plain required secret (no secret_groups involved at all) is
    still resolved and checked exactly as before Phase C."""
    agent_config = {"name": "plain-agent", "type": "user_agent", "allowed_tools": ["netctl"], "allowed_mcps": []}
    tool_config = {"name": "netctl", "secrets": ["SOME_REQUIRED_SECRET"], "optional_secrets": [], "secret_groups": []}
    _patch_agent_identities(
        monkeypatch,
        agent_config=agent_config,
        tool_config=tool_config,
        global_secrets={},
        user_secrets={},
    )

    result = asyncio.run(discovery.is_agent_configured("plain-agent", "user-123"))

    assert result["configured"] is False
    assert result["missing_secrets"] == ["SOME_REQUIRED_SECRET"]


def test_is_agent_configured_satisfied_by_global_secret(monkeypatch):
    agent_config = {"name": "plain-agent", "type": "user_agent", "allowed_tools": ["netctl"], "allowed_mcps": []}
    tool_config = {"name": "netctl", "secrets": ["SOME_REQUIRED_SECRET"], "optional_secrets": [], "secret_groups": []}
    _patch_agent_identities(
        monkeypatch,
        agent_config=agent_config,
        tool_config=tool_config,
        global_secrets={"SOME_REQUIRED_SECRET": "***"},
        user_secrets={},
    )

    result = asyncio.run(discovery.is_agent_configured("plain-agent", "user-123"))

    assert result["configured"] is True


def test_is_agent_configured_supervisor_always_configured(monkeypatch):
    result = asyncio.run(discovery.is_agent_configured("supervisor", "user-123"))
    assert result == {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}


def test_is_agent_configured_unknown_agent_not_configured(monkeypatch):
    _patch_agent_identities(monkeypatch, agent_config=None)
    result = asyncio.run(discovery.is_agent_configured("does-not-exist", "user-123"))
    assert result["configured"] is False


def test_is_agent_configured_no_requirements_at_all_is_configured(monkeypatch):
    """The early-exit optimization: an agent with no allowed_tools/allowed_mcps and no
    own secrets/variables must short-circuit to configured=True without needing any
    identity fetch (asserted implicitly -- user_secrets=None would blow up if the fake
    were ever called with a non-system identity and mishandled it, but the real
    assertion here is just the correctness of the early return)."""
    agent_config = {"name": "no-requirements-agent", "type": "user_agent", "allowed_tools": [], "allowed_mcps": []}
    _patch_agent_identities(monkeypatch, agent_config=agent_config, global_secrets={}, global_variables={})

    result = asyncio.run(discovery.is_agent_configured("no-requirements-agent", "user-123"))

    assert result == {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}


# --- discover_agents ------------------------------------------------------------

def _patch_bulk_identities(monkeypatch, agent_configs, tool_configs=None, mcp_configs=None,
                            global_secrets=None, global_variables=None,
                            user_secrets=None, user_variables=None, health=None, skills=None):
    monkeypatch.setattr(discovery.identity_mgr, "get_all_agent_configs", lambda: agent_configs)
    monkeypatch.setattr(discovery.identity_mgr, "get_all_agent_skills", lambda: skills or {})
    monkeypatch.setattr(discovery.identity_mgr, "get_all_health_statuses", lambda entity_type: health or {})
    monkeypatch.setattr(discovery.identity_mgr, "get_all_tool_configs", lambda: tool_configs or {})
    monkeypatch.setattr(discovery.identity_mgr, "get_all_mcp_configs", lambda: mcp_configs or {})

    def fake_get_identity_config(identity, category, keys=None):
        if identity.type == IdentityType.SYSTEM:
            store = global_secrets if category == "secrets" else global_variables
        else:
            store = user_secrets if category == "secrets" else user_variables
        return store or {}

    monkeypatch.setattr(discovery.identity_mgr, "get_identity_config", fake_get_identity_config)


def test_discover_agents_no_secret_group_option_satisfied_is_not_configured(monkeypatch):
    """Same regression as the is_agent_configured test above, exercised through
    discover_agents's separate bulk-prefetch resolution path -- both callers now share
    the same evaluator, so both must agree."""
    _patch_bulk_identities(
        monkeypatch,
        agent_configs={"example-agent": AGENT_WITH_SECRET_GROUP_TOOL},
        tool_configs={"netctl": NETCTL_LIKE_TOOL_CONFIG},
        global_secrets={},
        user_secrets={},
    )

    agents = asyncio.run(discovery.discover_agents(user_id="user-123"))

    assert len(agents) == 1
    agent = agents[0]
    assert agent["is_configured"] is False
    assert "EXAMPLE-API_STAGING_USERNAME" in agent["missing_secrets"]
    assert "EXAMPLE-API_PRODUCTION_USERNAME" in agent["missing_secrets"]


def test_discover_agents_one_secret_group_option_fully_set_is_configured(monkeypatch):
    _patch_bulk_identities(
        monkeypatch,
        agent_configs={"example-agent": AGENT_WITH_SECRET_GROUP_TOOL},
        tool_configs={"netctl": NETCTL_LIKE_TOOL_CONFIG},
        global_secrets={},
        user_secrets={
            "EXAMPLE-API_PRODUCTION_USERNAME": "***",
            "EXAMPLE-API_PRODUCTION_PASSWORD": "***",
        },
    )

    agents = asyncio.run(discovery.discover_agents(user_id="user-123"))

    agent = agents[0]
    assert agent["is_configured"] is True
    assert agent["missing_secrets"] == []
    # The secret_groups shape used to render the per-field "is_set" picker is unaffected.
    group = agent["secret_groups"][0]
    production_option = next(o for o in group["options"] if o["value"] == "production")
    assert all(f["is_set"] for f in production_option["fields"])


def test_discover_agents_required_secrets_excludes_grouped_keys(monkeypatch):
    """A key that's both individually listed under a tool's `secrets` AND part of a
    secret_group is resolved via the group-satisfaction check, not double-counted as a
    bare required secret missing independently of its group -- same guarantee
    is_tool_configured already provides, now also true for the agent-level aggregate."""
    tool_config = {
        "name": "netctl",
        "secrets": ["EXAMPLE-API_PRODUCTION_USERNAME"],
        "optional_secrets": [],
        "secret_groups": [
            {
                "label": "Environment",
                "options": [
                    {"value": "production", "fields": [{"key": "EXAMPLE-API_PRODUCTION_USERNAME", "label": "Username"}]},
                ],
            }
        ],
    }
    agent_config = {"name": "example-agent", "type": "user_agent", "allowed_tools": ["netctl"], "allowed_mcps": []}
    _patch_bulk_identities(
        monkeypatch,
        agent_configs={"example-agent": agent_config},
        tool_configs={"netctl": tool_config},
        global_secrets={},
        user_secrets={"EXAMPLE-API_PRODUCTION_USERNAME": "***"},
    )

    agents = asyncio.run(discovery.discover_agents(user_id="user-123"))

    agent = agents[0]
    assert agent["is_configured"] is True
    assert agent["required_secrets"] == []


def test_discover_agents_plain_required_secret_still_checked(monkeypatch):
    """Non-regression: discover_agents's ordinary (non-secret_group) resolution is
    unchanged by routing through the shared evaluator."""
    agent_config = {"name": "plain-agent", "type": "user_agent", "allowed_tools": ["netctl"], "allowed_mcps": []}
    tool_config = {"name": "netctl", "secrets": ["SOME_REQUIRED_SECRET"], "optional_secrets": [], "secret_groups": []}
    _patch_bulk_identities(
        monkeypatch,
        agent_configs={"plain-agent": agent_config},
        tool_configs={"netctl": tool_config},
        global_secrets={},
        user_secrets={},
    )

    agents = asyncio.run(discovery.discover_agents(user_id="user-123"))

    agent = agents[0]
    assert agent["is_configured"] is False
    assert agent["missing_secrets"] == ["SOME_REQUIRED_SECRET"]
    assert agent["required_secrets"] == ["SOME_REQUIRED_SECRET"]


def test_discover_agents_supervisor_excluded(monkeypatch):
    _patch_bulk_identities(monkeypatch, agent_configs={"supervisor": {"name": "supervisor", "type": "user_agent"}})
    agents = asyncio.run(discovery.discover_agents(user_id="user-123"))
    assert agents == []


# --- coverage gaps flagged by Phase C review: allowed_mcps, mcp__-prefixed tools, ------
# --- and background agents, all combined with secret_groups --------------------------

MCP_WITH_SECRET_GROUP = {
    "name": "example-mcp",
    "secrets": [],
    "optional_secrets": [],
    "secret_groups": [
        {
            "label": "Environment",
            "options": [
                {"value": "production", "fields": [{"key": "DEVOPS_MCP_PRODUCTION_TOKEN", "label": "Token"}]},
            ],
        }
    ],
}


def test_is_agent_configured_allowed_mcps_secret_group_unsatisfied(monkeypatch):
    """secret_groups reached via `allowed_mcps` directly (not via allowed_tools) must
    still be checked for satisfaction."""
    agent_config = {"name": "example-agent", "type": "user_agent", "allowed_tools": [], "allowed_mcps": ["example-mcp"]}
    _patch_agent_identities(
        monkeypatch,
        agent_config=agent_config,
        mcp_config=MCP_WITH_SECRET_GROUP,
        global_secrets={},
        user_secrets={},
    )

    result = asyncio.run(discovery.is_agent_configured("example-agent", "user-123"))

    assert result["configured"] is False
    assert "DEVOPS_MCP_PRODUCTION_TOKEN" in result["missing_secrets"]


def test_is_agent_configured_mcp_prefixed_tool_resolves_secret_groups_via_owning_mcp(monkeypatch):
    """An MCP referenced only via an `mcp__`-prefixed `allowed_tools` entry (not
    `allowed_mcps`) must still contribute its owning MCP's secret_groups -- this is the
    "more complete" behavior _resolve_agent_requirements preserves from discover_agents's
    original inline logic (see §2C.3 item 5), as opposed to get_agent_secret_groups,
    which deliberately skips this path."""
    agent_config = {
        "name": "example-agent",
        "type": "user_agent",
        "allowed_tools": ["mcp__example-mcp__clusters_get_all"],
        "allowed_mcps": [],
    }
    _patch_agent_identities(
        monkeypatch,
        agent_config=agent_config,
        tool_config=None,
        mcp_config=MCP_WITH_SECRET_GROUP,
        global_secrets={},
        user_secrets={},
    )

    result = asyncio.run(discovery.is_agent_configured("example-agent", "user-123"))

    assert result["configured"] is False
    assert "DEVOPS_MCP_PRODUCTION_TOKEN" in result["missing_secrets"]


def test_is_agent_configured_background_agent_secret_group_unsatisfied(monkeypatch):
    """A background agent resolves its identity as Identity(id=agent_name, type=WORKFLOW)
    rather than Identity.from_string(user_id) -- confirm the secret_groups check and the
    corrected early-exit guard both still work correctly on that identity branch."""
    agent_config = {
        "name": "devops-workflow",
        "type": "background_agent",
        "allowed_tools": ["netctl"],
        "allowed_mcps": [],
    }
    _patch_agent_identities(
        monkeypatch,
        agent_config=agent_config,
        tool_config=NETCTL_LIKE_TOOL_CONFIG,
        global_secrets={},
        user_secrets={},  # the workflow identity's own store, per fake_get_identity_config
    )

    result = asyncio.run(discovery.is_agent_configured("devops-workflow", "user-123"))

    assert result["configured"] is False
    assert "EXAMPLE-API_STAGING_USERNAME" in result["missing_secrets"]


def test_discover_agents_allowed_mcps_secret_group_unsatisfied(monkeypatch):
    agent_config = {"name": "example-agent", "type": "user_agent", "allowed_tools": [], "allowed_mcps": ["example-mcp"]}
    _patch_bulk_identities(
        monkeypatch,
        agent_configs={"example-agent": agent_config},
        mcp_configs={"example-mcp": MCP_WITH_SECRET_GROUP},
        global_secrets={},
        user_secrets={},
    )

    agents = asyncio.run(discovery.discover_agents(user_id="user-123"))

    agent = agents[0]
    assert agent["is_configured"] is False
    assert "DEVOPS_MCP_PRODUCTION_TOKEN" in agent["missing_secrets"]


def test_discover_agents_mcp_prefixed_tool_resolves_secret_groups_via_owning_mcp(monkeypatch):
    agent_config = {
        "name": "example-agent",
        "type": "user_agent",
        "allowed_tools": ["mcp__example-mcp__clusters_get_all"],
        "allowed_mcps": [],
    }
    _patch_bulk_identities(
        monkeypatch,
        agent_configs={"example-agent": agent_config},
        mcp_configs={"example-mcp": MCP_WITH_SECRET_GROUP},
        global_secrets={},
        user_secrets={},
    )

    agents = asyncio.run(discovery.discover_agents(user_id="user-123"))

    agent = agents[0]
    assert agent["is_configured"] is False
    assert "DEVOPS_MCP_PRODUCTION_TOKEN" in agent["missing_secrets"]


def test_get_agent_secret_groups_resolves_mcp_prefixed_tool_via_owning_mcp(monkeypatch):
    """Regression for an adversarial-review finding on Phase C: get_agent_secret_groups
    (used by core/routers/marketplace.py's configure-agent save handler) previously
    `continue`d past any mcp__-prefixed allowed_tools entry, never resolving its owning
    MCP's secret_groups at all -- inert before Phase C (is_agent_configured never
    checked group satisfaction), but a real lockout afterward: an agent in this exact
    shape (confirmed to exist in this repo, e.g. workspace/agents/
    acme-logs-investigator referencing logs only via mcp__-prefixed tools)
    would report "not configured" with secret_groups fields the save handler could
    never see to persist. Fixed to mirror get_agent_required_secrets's existing
    mcp__-prefix resolution."""
    monkeypatch.setattr(discovery.identity_mgr, "get_tool_config", lambda name: None)
    monkeypatch.setattr(discovery.identity_mgr, "get_mcp_config", lambda name: MCP_WITH_SECRET_GROUP)

    config = {"allowed_tools": ["mcp__example-mcp__clusters_get_all"], "allowed_mcps": []}
    groups = asyncio.run(discovery.get_agent_secret_groups(config))

    assert groups == MCP_WITH_SECRET_GROUP["secret_groups"]


def test_discover_agents_background_agent_secret_group_unsatisfied(monkeypatch):
    """Background agents resolve their current secrets via a per-workflow
    Identity(id=name, type=WORKFLOW) fetch inside the loop, not the pre-fetched human
    user secrets -- confirm the shared evaluator is wired correctly on that branch too."""
    agent_config = {
        "name": "devops-workflow",
        "type": "background_agent",
        "allowed_tools": ["netctl"],
        "allowed_mcps": [],
    }
    _patch_bulk_identities(
        monkeypatch,
        agent_configs={"devops-workflow": agent_config},
        tool_configs={"netctl": NETCTL_LIKE_TOOL_CONFIG},
        global_secrets={},
        user_secrets={},  # the workflow identity's own store, per fake_get_identity_config
    )

    agents = asyncio.run(discovery.discover_agents(user_id="user-123", include_background=True))

    agent = agents[0]
    assert agent["is_configured"] is False
    assert "EXAMPLE-API_STAGING_USERNAME" in agent["missing_secrets"]
