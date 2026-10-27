# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import asyncio

from core import discovery
from core import tool_search


TOOL_CONFIGS = {
    "opsctl": {
        "name": "opsctl",
        "description": "Executes opsctl CLI commands for connector diagnostics and metrics.",
        "public": True,
        "inputs": {
            "args": {"type": "array", "description": "CLI arguments", "required": True},
        },
        "secrets": [],
        "optional_secrets": ["EXAMPLE-API_PRODUCTION_USERNAME"],
        "secret_groups": [],
    },
    "netctl": {
        "name": "netctl",
        "description": "Inspects cluster nodes, tenants, and connectors read-only.",
        "public": True,
        "inputs": {
            "environment": {"type": "string", "description": "Target environment", "required": True},
        },
        "secrets": ["SOME_REQUIRED_SECRET"],
        "optional_secrets": [],
        "secret_groups": [],
    },
    "system_restart": {
        "name": "system_restart",
        "description": "Restarts internal system services. Do not expose.",
        "public": False,
        "inputs": {},
    },
}

MCP_CONFIGS = {
    "example-mcp": {
        "name": "example-mcp",
        "public": False,
        "public_tools": ["clusters_get_all"],
        "tools": [
            {
                "name": "clusters_get_all",
                "description": "List all clusters and tenants.",
                "inputSchema": {"properties": {"env": {"type": "string"}}, "required": []},
            },
            {
                "name": "internal_admin_tool",
                "description": "Internal admin operation, never whitelisted.",
                "inputSchema": {},
            },
        ],
    },
}


def _patch_registry(monkeypatch, tool_configs=None, mcp_configs=None, embeddings=None, health=None):
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_tool_configs", lambda: tool_configs or {})
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_mcp_configs", lambda: mcp_configs or {})
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_tool_embeddings", lambda: embeddings or {})
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_health_statuses", lambda entity_type: health or {})


def test_internal_tools_never_returned(monkeypatch):
    _patch_registry(monkeypatch, tool_configs=TOOL_CONFIGS, mcp_configs=MCP_CONFIGS)
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)

    results = asyncio.run(tool_search.search_tools("cluster tenants and connectors"))
    names = {r["name"] for r in results}

    assert "system_restart" not in names
    assert "mcp__example-mcp__internal_admin_tool" not in names
    assert "opsctl" in names
    assert "netctl" in names
    assert "mcp__example-mcp__clusters_get_all" in names


def test_mcp_tool_public_via_whitelist_and_via_server_public_flag(monkeypatch):
    mcp_configs = {
        "example-mcp": {**MCP_CONFIGS["example-mcp"], "public": False},
        "fully-public-mcp": {
            "name": "fully-public-mcp",
            "public": True,
            "public_tools": [],
            "tools": [{"name": "anything_here", "description": "Anything.", "inputSchema": {}}],
        },
    }
    _patch_registry(monkeypatch, tool_configs={}, mcp_configs=mcp_configs)
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)

    results = asyncio.run(tool_search.search_tools("anything"))
    names = {r["name"] for r in results}

    assert "mcp__example-mcp__clusters_get_all" in names
    assert "mcp__example-mcp__internal_admin_tool" not in names
    assert "mcp__fully-public-mcp__anything_here" in names


def test_keyword_fallback_ranks_best_match_first(monkeypatch):
    _patch_registry(monkeypatch, tool_configs=TOOL_CONFIGS, mcp_configs={})
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)

    results = asyncio.run(tool_search.search_tools("inspects cluster nodes tenants connectors"))

    assert results[0]["name"] == "netctl"


def test_cosine_ranking_places_matching_tool_first(monkeypatch):
    embeddings = {
        "opsctl": [1.0, 0.0, 0.0],
        "netctl": [0.0, 1.0, 0.0],
    }
    _patch_registry(monkeypatch, tool_configs=TOOL_CONFIGS, mcp_configs={}, embeddings=embeddings)
    # Query vector matches netctl's embedding exactly, and is orthogonal to opsctl's.
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: [0.0, 1.0, 0.0])

    results = asyncio.run(tool_search.search_tools("query"))

    assert results[0]["name"] == "netctl"


def test_unconfigured_tool_reports_missing_secrets(monkeypatch):
    _patch_registry(monkeypatch, tool_configs=TOOL_CONFIGS, mcp_configs={})
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)

    async def fake_is_tool_configured(tool_name, user_id=None):
        if tool_name == "netctl":
            return {
                "configured": False,
                "missing_secrets": ["SOME_REQUIRED_SECRET"],
                "missing_variables": [],
                "optional_missing_secrets": [],
            }
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    monkeypatch.setattr(tool_search, "is_tool_configured", fake_is_tool_configured)

    results = asyncio.run(tool_search.search_tools("netctl", user_id="user-123"))
    netctl_result = next(r for r in results if r["name"] == "netctl")
    opsctl_result = next(r for r in results if r["name"] == "opsctl")

    assert netctl_result["configured"] is False
    assert "SOME_REQUIRED_SECRET" in netctl_result["description"]
    assert opsctl_result["configured"] is True


def test_no_user_id_skips_configuration_check(monkeypatch):
    _patch_registry(monkeypatch, tool_configs=TOOL_CONFIGS, mcp_configs={})
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)

    async def _fail_if_called(tool_name, user_id=None):
        raise AssertionError("is_tool_configured should not be called when user_id is None")

    monkeypatch.setattr(tool_search, "is_tool_configured", _fail_if_called)

    results = asyncio.run(tool_search.search_tools("opsctl"))

    assert all(r["configured"] is True for r in results)


def test_search_tools_end_to_end_with_real_is_tool_configured(monkeypatch):
    """Exercises search_tools against the real (unstubbed) is_tool_configured, covering the
    seam where an MCP Tool Card's `mcp__{server}__{tool}` name must resolve back through
    is_tool_configured's own mcp__ prefix parsing to the owning MCP's config."""
    mcp_configs = {
        "example-mcp": {
            "name": "example-mcp",
            "public": True,
            "public_tools": [],
            "secrets": ["DEVOPS_MCP_TOKEN"],
            "tools": [
                {"name": "clusters_get_all", "description": "List all clusters.", "inputSchema": {}},
            ],
        },
    }
    _patch_registry(monkeypatch, tool_configs={}, mcp_configs=mcp_configs)
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)
    monkeypatch.setattr(discovery.identity_mgr, "get_mcp_config", lambda name: mcp_configs.get(name))
    monkeypatch.setattr(discovery.identity_mgr, "get_tool_config", lambda name: None)
    monkeypatch.setattr(discovery.identity_mgr, "get_identity_config", lambda identity, category, keys=None: {})

    results = asyncio.run(tool_search.search_tools("cluster", user_id="user-123"))

    assert len(results) == 1
    assert results[0]["name"] == "mcp__example-mcp__clusters_get_all"
    assert results[0]["configured"] is False
    assert "DEVOPS_MCP_TOKEN" in results[0]["description"]


# --- is_tool_configured -------------------------------------------------------------

def _patch_discovery_identities(monkeypatch, tool_config=None, mcp_config=None, global_secrets=None,
                                 global_variables=None, user_secrets=None, user_variables=None):
    monkeypatch.setattr(discovery.identity_mgr, "get_tool_config", lambda name: tool_config)
    monkeypatch.setattr(discovery.identity_mgr, "get_mcp_config", lambda name: mcp_config)

    def fake_get_identity_config(identity, category, keys=None):
        if getattr(identity, "id", None) == "system":
            store = global_secrets if category == "secrets" else global_variables
        else:
            store = user_secrets if category == "secrets" else user_variables
        return store or {}

    monkeypatch.setattr(discovery.identity_mgr, "get_identity_config", fake_get_identity_config)


def test_is_tool_configured_missing_user_secret(monkeypatch):
    _patch_discovery_identities(
        monkeypatch,
        tool_config=TOOL_CONFIGS["netctl"],
        global_secrets={},
        user_secrets={},
    )

    result = asyncio.run(discovery.is_tool_configured("netctl", user_id="user-123"))

    assert result["configured"] is False
    assert result["missing_secrets"] == ["SOME_REQUIRED_SECRET"]


def test_is_tool_configured_satisfied_by_global_system_secret(monkeypatch):
    _patch_discovery_identities(
        monkeypatch,
        tool_config=TOOL_CONFIGS["netctl"],
        global_secrets={"SOME_REQUIRED_SECRET": "***"},
        user_secrets={},
    )

    result = asyncio.run(discovery.is_tool_configured("netctl", user_id="user-123"))

    assert result["configured"] is True
    assert result["missing_secrets"] == []


def test_is_tool_configured_satisfied_by_user_secret(monkeypatch):
    _patch_discovery_identities(
        monkeypatch,
        tool_config=TOOL_CONFIGS["netctl"],
        global_secrets={},
        user_secrets={"SOME_REQUIRED_SECRET": "***"},
    )

    result = asyncio.run(discovery.is_tool_configured("netctl", user_id="user-123"))

    assert result["configured"] is True


def test_is_tool_configured_mcp_tool_resolves_owning_mcp(monkeypatch):
    mcp_config = {
        "name": "example-mcp",
        "secrets": ["DEVOPS_MCP_TOKEN"],
        "optional_secrets": [],
        "secret_groups": [],
    }
    _patch_discovery_identities(
        monkeypatch,
        mcp_config=mcp_config,
        global_secrets={},
        user_secrets={},
    )

    result = asyncio.run(discovery.is_tool_configured("mcp__example-mcp__clusters_get_all", user_id="user-123"))

    assert result["configured"] is False
    assert result["missing_secrets"] == ["DEVOPS_MCP_TOKEN"]


def test_is_tool_configured_unknown_tool_returns_not_configured(monkeypatch):
    _patch_discovery_identities(monkeypatch, tool_config=None, mcp_config=None)

    result = asyncio.run(discovery.is_tool_configured("does-not-exist", user_id="user-123"))

    assert result["configured"] is False


NETCTL_LIKE_CONFIG = {
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


def test_is_tool_configured_no_secret_group_option_satisfied_is_not_configured(monkeypatch):
    """Regression test: opsctl/netctl declare all credentials as optional_secrets +
    secret_groups (no plain `secrets`). Excluding grouped keys from BOTH required and
    optional secrets (as a naive port of is_agent_configured would) means a user with
    zero environment credentials configured would incorrectly get configured=True —
    this is exactly the scenario the spec's own verification checklist requires to
    report "Missing: EXAMPLE-API_..." (spec Phase 2, verification item 4)."""
    _patch_discovery_identities(
        monkeypatch,
        tool_config=NETCTL_LIKE_CONFIG,
        global_secrets={},
        user_secrets={},
    )

    result = asyncio.run(discovery.is_tool_configured("netctl", user_id="user-123"))

    assert result["configured"] is False
    assert "EXAMPLE-API_STAGING_USERNAME" in result["missing_secrets"]
    assert "EXAMPLE-API_PRODUCTION_USERNAME" in result["missing_secrets"]


def test_is_tool_configured_one_secret_group_option_fully_set_is_configured(monkeypatch):
    _patch_discovery_identities(
        monkeypatch,
        tool_config=NETCTL_LIKE_CONFIG,
        global_secrets={},
        user_secrets={
            "EXAMPLE-API_PRODUCTION_USERNAME": "***",
            "EXAMPLE-API_PRODUCTION_PASSWORD": "***",
        },
    )

    result = asyncio.run(discovery.is_tool_configured("netctl", user_id="user-123"))

    assert result["configured"] is True
    assert result["missing_secrets"] == []


def test_is_tool_configured_partial_secret_group_option_is_not_configured(monkeypatch):
    """A half-filled option (e.g. only the username saved, not the password) must not
    count as satisfied."""
    _patch_discovery_identities(
        monkeypatch,
        tool_config=NETCTL_LIKE_CONFIG,
        global_secrets={},
        user_secrets={"EXAMPLE-API_PRODUCTION_USERNAME": "***"},
    )

    result = asyncio.run(discovery.is_tool_configured("netctl", user_id="user-123"))

    assert result["configured"] is False


def test_is_tool_configured_secret_group_keys_excluded_from_plain_required_secrets(monkeypatch):
    """A key that's both individually listed under `secrets` AND part of a secret_group
    is resolved via the group-satisfaction check, not double-counted as a bare required
    secret missing independently of its group."""
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
    _patch_discovery_identities(
        monkeypatch,
        tool_config=tool_config,
        global_secrets={},
        user_secrets={"EXAMPLE-API_PRODUCTION_USERNAME": "***"},
    )

    result = asyncio.run(discovery.is_tool_configured("netctl", user_id="user-123"))

    assert result["configured"] is True
    assert result["missing_secrets"] == []


def test_is_tool_configured_no_user_id_reports_global_requirements_only(monkeypatch):
    _patch_discovery_identities(
        monkeypatch,
        tool_config=TOOL_CONFIGS["netctl"],
        global_secrets={},
    )

    result = asyncio.run(discovery.is_tool_configured("netctl", user_id=None))

    assert result["configured"] is False
    assert result["missing_secrets"] == ["SOME_REQUIRED_SECRET"]


# --- the search read-filter: front door vs an agent run ------------------------ #


def _install_group_policy(monkeypatch, target, group="ops"):
    """A policy with one group rule, read through the module's registry seam."""
    import json

    from core import auth as auth_module
    from core import agent_token, tool_access

    policy = {"rules": [{"targets": [target], "groups": [group]}]}

    class FakeEtcd:
        def get(self, key, **_kwargs):
            if key == tool_access.POLICY_PATH:
                meta = type("M", (), {"mod_revision": 1})()
                return json.dumps(policy).encode("utf-8"), meta
            return None, None

        def put(self, key, value):
            raise AssertionError(f"no write expected: {key}")

    monkeypatch.setenv("AGENT_TOKEN_SECRET", "tool-search-unit-secret-0123456789abcdef")
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    monkeypatch.setattr(tool_access, "_client", lambda: FakeEtcd())
    tool_access.reset_snapshot()
    monkeypatch.setattr(auth_module, "agent_token_var", _FreshVar())
    return agent_token


class _FreshVar:
    """A context var per test, so no token leaks in from another test."""

    def __init__(self):
        import contextvars

        self._var = contextvars.ContextVar("test-agent-token", default=None)

    def get(self):
        return self._var.get()

    def set(self, value):
        return self._var.set(value)


def test_the_front_door_keeps_its_cards_when_no_token_carries_groups(monkeypatch):
    """No verified token ⇒ no group claims ⇒ the read filter must not run.

    Applying a group rule to an empty group set on the front door would hide cards
    from the very users who do hold the group (the search runs before any run minted
    a token). Execution still enforces the rule when the tool is called.
    """
    _install_group_policy(monkeypatch, "opsctl")
    _patch_registry(monkeypatch, tool_configs=TOOL_CONFIGS, mcp_configs={})
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)

    results = asyncio.run(tool_search.search_tools("opsctl connector diagnostics"))
    names = {r["name"] for r in results}

    assert "opsctl" in names


def test_an_agent_run_still_filters_cards_by_its_group_rules(monkeypatch):
    """An agent run's cards ARE narrowed: its token carries the groups to decide with."""
    agent_token = _install_group_policy(monkeypatch, "opsctl")
    _patch_registry(monkeypatch, tool_configs=TOOL_CONFIGS, mcp_configs={})
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)

    from core import auth as auth_module

    auth_module.agent_token_var.set(
        agent_token.mint("agent-a", user_id="user-1", groups=("sre",))
    )

    results = asyncio.run(tool_search.search_tools("opsctl connector diagnostics"))
    names = {r["name"] for r in results}

    assert "opsctl" not in names  # the rule admits `ops` only

    auth_module.agent_token_var.set(
        agent_token.mint("agent-a", user_id="user-1", groups=("ops",))
    )
    allowed = {
        r["name"]
        for r in asyncio.run(tool_search.search_tools("opsctl connector diagnostics"))
    }
    assert "opsctl" in allowed
