# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, List, Optional

import pytest

from core import auth, gateway, tool_authz, tool_search
from core.auth import user_id_var
from core.tool_search import execute_whitelisted_tool


class FakeContext:
    """Stand-in for fastmcp.Context — only report_progress is exercised."""

    def __init__(self):
        self.progress_messages = []

    async def report_progress(self, current=None, total=None, message=None):
        self.progress_messages.append(message)


@dataclass
class FakeCallToolResult:
    data: Any = None
    structured_content: Optional[dict] = None
    content: Optional[List[Any]] = None
    is_error: bool = False


class FakeTextContent:
    """Duck-types mcp.types.TextContent (only `.text` is read by extract_tool_output)."""

    def __init__(self, text):
        self.text = text


class FakeMCPClient:
    """Stand-in for fastmcp.Client — records the call and returns a canned result."""

    def __init__(self, result):
        self._result = result
        self.calls = []

    async def call_tool(self, name, arguments, raise_on_error=True):
        self.calls.append((name, arguments, raise_on_error))
        return self._result


def _patch_no_call(monkeypatch, target, attr):
    async def _fail(*args, **kwargs):
        raise AssertionError(f"{attr} should not have been called")
    monkeypatch.setattr(target, attr, _fail)


# --- search_tools -----------------------------------------------------------

def test_search_tools_delegates_to_ranked_search_and_reports_progress(monkeypatch):
    cards = [
        {"name": "netctl", "description": "Inspect cluster nodes.", "parameters": {}, "configured": True, "status": "Online", "source": "local"},
    ]

    async def fake_ranked(query, limit=8, user_id=None, principal=None):
        assert query == "inspect cluster nodes"
        assert user_id == "user-1"
        assert principal == "user:user-1"
        return cards

    monkeypatch.setattr(gateway, "_search_tools_ranked", fake_ranked)
    user_id_var.set("user-1")

    ctx = FakeContext()
    results = asyncio.run(gateway.search_tools(ctx, "inspect cluster nodes"))

    assert results == cards
    assert any("Found 1 tool" in (m or "") for m in ctx.progress_messages)


# --- use_tool: Authorization Guard ------------------------------------------

def test_use_tool_denies_unwhitelisted_local_tool(monkeypatch):
    monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: {"name": name, "public": False})
    _patch_no_call(monkeypatch, gateway, "is_tool_configured")
    _patch_no_call(monkeypatch, gateway, "get_hub_client")
    user_id_var.set("user-1")

    ctx = FakeContext()
    result = asyncio.run(gateway.use_tool(ctx, "system_restart", {}))

    assert result == "SYSTEM: Access denied. Tool 'system_restart' is internal and not exposed for direct execution."


def test_use_tool_denies_unknown_tool(monkeypatch):
    monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: None)
    _patch_no_call(monkeypatch, gateway, "is_tool_configured")
    user_id_var.set("user-1")

    ctx = FakeContext()
    result = asyncio.run(gateway.use_tool(ctx, "does_not_exist", {}))

    assert "Access denied" in result


def test_use_tool_denies_malformed_mcp_name(monkeypatch):
    _patch_no_call(monkeypatch, gateway, "is_tool_configured")
    user_id_var.set("user-1")

    ctx = FakeContext()
    result = asyncio.run(gateway.use_tool(ctx, "mcp__onlyserver", {}))

    assert "Access denied" in result


def test_use_tool_denies_non_whitelisted_mcp_tool(monkeypatch):
    # The MCP server exists and is a known registry entry, but neither `public: true`
    # nor `public_tools` covers this specific tool name — must still deny.
    monkeypatch.setattr(
        gateway.identity_mgr,
        "get_mcp_config",
        lambda name: {"name": name, "public": False, "public_tools": ["clusters_get_all"]},
    )
    _patch_no_call(monkeypatch, gateway, "is_tool_configured")
    _patch_no_call(monkeypatch, gateway, "get_external_mcp_client")
    user_id_var.set("user-1")

    ctx = FakeContext()
    result = asyncio.run(gateway.use_tool(ctx, "mcp__example-mcp__internal_admin_tool", {}))

    assert result == "SYSTEM: Access denied. Tool 'mcp__example-mcp__internal_admin_tool' is internal and not exposed for direct execution."


# --- use_tool: Configuration Guard -------------------------------------------

def test_use_tool_reports_missing_configuration(monkeypatch):
    monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: {"name": name, "public": True})

    async def fake_is_tool_configured(tool_name, user_id=None):
        return {
            "configured": False,
            "missing_secrets": ["EXAMPLE-API_PRODUCTION_USERNAME", "EXAMPLE-API_PRODUCTION_PASSWORD"],
            "missing_variables": [],
            "optional_missing_secrets": [],
        }

    monkeypatch.setattr(gateway, "is_tool_configured", fake_is_tool_configured)
    _patch_no_call(monkeypatch, gateway, "get_hub_client")
    user_id_var.set("user-1")

    ctx = FakeContext()
    result = asyncio.run(gateway.use_tool(ctx, "opsctl", {"args": ["connector", "detail"]}))

    assert result.startswith("SYSTEM: Tool 'opsctl' requires configuration before it can be used.")
    assert "EXAMPLE-API_PRODUCTION_USERNAME" in result
    assert "/configuration" in result


# --- use_tool: Execution Routing ---------------------------------------------

def test_use_tool_executes_local_hub_tool_and_returns_structured_output(monkeypatch):
    monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: {"name": name, "public": True})

    async def fake_configured(tool_name, user_id=None):
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    monkeypatch.setattr(gateway, "is_tool_configured", fake_configured)

    fake_client = FakeMCPClient(FakeCallToolResult(data={"stdout": "{}", "stderr": "", "exit_code": 0}))

    async def fake_get_hub_client():
        return fake_client

    monkeypatch.setattr(gateway, "get_hub_client", fake_get_hub_client)
    user_id_var.set("user-42")

    ctx = FakeContext()
    result = asyncio.run(gateway.use_tool(ctx, "opsctl", {"args": ["--help"]}))

    assert result == {"stdout": "{}", "stderr": "", "exit_code": 0}
    name, arguments, raise_on_error = fake_client.calls[0]
    assert name == "opsctl"
    token = arguments.pop("__agent_token", None)
    assert token is None or token.startswith("t1.")
    assert arguments == {"args": ["--help"], "__user_id": "user-42"}
    assert raise_on_error is False


def test_use_tool_routes_external_mcp_tool_by_prefixed_name(monkeypatch):
    monkeypatch.setattr(
        gateway.identity_mgr,
        "get_mcp_config",
        lambda name: {"name": name, "public": False, "public_tools": ["clusters_get_all"]},
    )

    async def fake_configured(tool_name, user_id=None):
        assert tool_name == "mcp__example-mcp__clusters_get_all"
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    monkeypatch.setattr(gateway, "is_tool_configured", fake_configured)

    fake_client = FakeMCPClient(FakeCallToolResult(structured_content={"clusters": []}))

    async def fake_get_external_mcp_client(server_name, user_id):
        assert server_name == "example-mcp"
        assert user_id == "user-42"
        return fake_client

    monkeypatch.setattr(gateway, "get_external_mcp_client", fake_get_external_mcp_client)
    user_id_var.set("user-42")

    ctx = FakeContext()
    result = asyncio.run(gateway.use_tool(ctx, "mcp__example-mcp__clusters_get_all", {"env": "staging"}))

    assert result == {"clusters": []}
    name, arguments, raise_on_error = fake_client.calls[0]
    assert name == "clusters_get_all"
    assert arguments == {"env": "staging"}
    assert raise_on_error is False


def test_use_tool_falls_back_to_text_content_when_unstructured(monkeypatch):
    monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: {"name": name, "public": True})

    async def fake_configured(tool_name, user_id=None):
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    monkeypatch.setattr(gateway, "is_tool_configured", fake_configured)

    fake_client = FakeMCPClient(FakeCallToolResult(content=[FakeTextContent("plain text output")]))

    async def fake_get_hub_client():
        return fake_client

    monkeypatch.setattr(gateway, "get_hub_client", fake_get_hub_client)
    user_id_var.set("user-1")

    ctx = FakeContext()
    result = asyncio.run(gateway.use_tool(ctx, "opsctl", {"args": ["--help"]}))

    assert result == "plain text output"


def test_use_tool_surfaces_execution_errors(monkeypatch, caplog):
    monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: {"name": name, "public": True})

    async def fake_configured(tool_name, user_id=None):
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    monkeypatch.setattr(gateway, "is_tool_configured", fake_configured)

    async def fake_get_hub_client():
        raise ConnectionError("hub unreachable")

    monkeypatch.setattr(gateway, "get_hub_client", fake_get_hub_client)
    user_id_var.set("user-1")

    ctx = FakeContext()
    with caplog.at_level(logging.ERROR, logger="core.tool_search"):
        result = asyncio.run(gateway.use_tool(ctx, "opsctl", {"args": ["--help"]}))

    assert result == "SYSTEM: Error executing tool 'opsctl'. Please try again later."
    assert "hub unreachable" not in result
    assert "hub unreachable" in caplog.text


# --- tool authorization (core.tool_authz) seams ------------------------------
#
# `execute_whitelisted_tool` runs whitelist -> authorization -> configuration ->
# dispatch, and `search_tools` filters candidates before ranking. Both reach the
# authz engine through the lazily imported `core.auth.get_identity_manager`, so a
# fake registry makes these tests free of etcd, network and sleeps.

class FakeAuthzRegistry:
    """Registry stand-in carrying only the three tool-authz reads."""

    def __init__(self, *, policy=None, mode="off", groups=None):
        self.policy = {} if policy is None else policy
        self.mode = mode
        self.groups = {} if groups is None else groups
        self.policy_reads = 0

    def get_tool_policies(self):
        self.policy_reads += 1
        return self.policy

    def get_tool_authz_mode(self):
        return self.mode

    def get_principal_groups(self):
        return self.groups


class FakeToolRegistry:
    """The two registry lookups the whitelist guard performs."""

    def __init__(self, tool_configs=None, mcp_configs=None):
        self.tool_configs = tool_configs or {}
        self.mcp_configs = mcp_configs or {}

    def get_tool_config(self, name):
        return self.tool_configs.get(name)

    def get_mcp_config(self, name):
        return self.mcp_configs.get(name)


@pytest.fixture(autouse=True)
def _authz_isolation():
    """The authz snapshot/ring/caller-group state is process global; isolate it."""
    tool_authz.reset_cache()
    tool_authz.clear_shadow_denies()
    tool_authz.clear_request_groups()
    yield
    tool_authz.reset_cache()
    tool_authz.clear_shadow_denies()
    tool_authz.clear_request_groups()


def _install_authz(monkeypatch, *, policy=None, mode="off"):
    fake = FakeAuthzRegistry(policy=policy, mode=mode)
    monkeypatch.setattr(auth, "get_identity_manager", lambda: fake)
    tool_authz.reset_cache()
    return fake


def _authz_policy(*rules):
    return {"default_action": "deny", "rules": list(rules)}


def _authz_rule(tools, principals=("*",), scopes=None):
    rule = {"tools": list(tools), "allow_principals": list(principals)}
    if scopes is not None:
        rule["scopes"] = list(scopes)
    return rule


PUBLIC_OPSCTL = {"opsctl": {"name": "opsctl", "public": True}}


def _configured_ok(calls=None):
    async def fake_configured(tool_name, user_id=None):
        if calls is not None:
            calls.append(tool_name)
        return {
            "configured": True,
            "missing_secrets": [],
            "missing_variables": [],
            "optional_missing_secrets": [],
        }

    return fake_configured


def _forbidden_hub():
    async def _fail():
        raise AssertionError("get_hub_client must not be touched")

    return _fail


# --- execute_whitelisted_tool: authorization guard ---------------------------

def test_execute_whitelisted_tool_denies_principal_without_a_matching_rule(monkeypatch):
    _install_authz(monkeypatch, policy=_authz_policy(), mode="enforcing")
    configured_calls = []

    result = asyncio.run(
        execute_whitelisted_tool(
            "opsctl",
            {"args": ["--help"]},
            "user-1",
            identity_manager=FakeToolRegistry(PUBLIC_OPSCTL),
            is_configured=_configured_ok(configured_calls),
            get_hub_client_fn=_forbidden_hub(),
            principal="user:alice",
        )
    )

    assert result == "SYSTEM: Access denied. Tool 'opsctl' is not permitted for this principal."
    assert configured_calls == []  # denial happens before the configuration guard


def test_execute_whitelisted_tool_uses_the_principal_kwarg(monkeypatch):
    _install_authz(
        monkeypatch,
        policy=_authz_policy(_authz_rule(["opsctl"], ["user:bob"])),
        mode="enforcing",
    )
    registry = FakeToolRegistry(PUBLIC_OPSCTL)

    denied = asyncio.run(
        execute_whitelisted_tool(
            "opsctl",
            {"args": ["--help"]},
            "user-1",
            identity_manager=registry,
            is_configured=_configured_ok(),
            get_hub_client_fn=_forbidden_hub(),
            principal="user:alice",
        )
    )
    assert denied == "SYSTEM: Access denied. Tool 'opsctl' is not permitted for this principal."

    fake_client = FakeMCPClient(FakeCallToolResult(data={"stdout": "ok"}))

    async def fake_get_hub_client():
        return fake_client

    allowed = asyncio.run(
        execute_whitelisted_tool(
            "opsctl",
            {"args": ["--help"]},
            "user-1",
            identity_manager=registry,
            is_configured=_configured_ok(),
            get_hub_client_fn=fake_get_hub_client,
            principal="user:bob",
        )
    )

    assert allowed == {"stdout": "ok"}
    assert len(fake_client.calls) == 1


def test_execute_whitelisted_tool_shadow_executes_and_records_the_denial(monkeypatch):
    _install_authz(monkeypatch, policy=_authz_policy(), mode="shadow")
    fake_client = FakeMCPClient(FakeCallToolResult(data={"stdout": "{}"}))

    async def fake_get_hub_client():
        return fake_client

    result = asyncio.run(
        execute_whitelisted_tool(
            "opsctl",
            {"args": ["--help"]},
            "user-1",
            identity_manager=FakeToolRegistry(PUBLIC_OPSCTL),
            is_configured=_configured_ok(),
            get_hub_client_fn=fake_get_hub_client,
            principal="user:alice",
        )
    )

    assert result == {"stdout": "{}"}  # shadow still executes
    entries = tool_authz.shadow_denies()
    assert [(e["principal"], e["tool"], e["scope"]) for e in entries] == [
        ("user:alice", "opsctl", "tools:call")
    ]


def test_execute_whitelisted_tool_with_authz_off_is_unchanged(monkeypatch):
    _install_authz(monkeypatch, policy=_authz_policy(), mode="off")
    fake_client = FakeMCPClient(
        FakeCallToolResult(data={"stdout": "{}", "stderr": "", "exit_code": 0})
    )

    async def fake_get_hub_client():
        return fake_client

    result = asyncio.run(
        execute_whitelisted_tool(
            "opsctl",
            {"args": ["--help"]},
            "user-42",
            identity_manager=FakeToolRegistry(PUBLIC_OPSCTL),
            is_configured=_configured_ok(),
            get_hub_client_fn=fake_get_hub_client,
            principal="user:alice",
        )
    )

    assert result == {"stdout": "{}", "stderr": "", "exit_code": 0}
    name, arguments, raise_on_error = fake_client.calls[0]
    assert name == "opsctl"
    arguments.pop("__agent_token", None)
    assert arguments == {"args": ["--help"], "__user_id": "user-42"}
    assert raise_on_error is False
    assert tool_authz.shadow_denies() == []


def test_execute_whitelisted_tool_fails_closed_when_authz_raises(monkeypatch):
    _install_authz(monkeypatch, policy=_authz_policy(), mode="enforcing")
    configured_calls = []

    def boom(*args, **kwargs):
        raise RuntimeError("policy engine exploded")

    monkeypatch.setattr(tool_authz, "allowed", boom)

    result = asyncio.run(
        execute_whitelisted_tool(
            "opsctl",
            {"args": ["--help"]},
            "user-1",
            identity_manager=FakeToolRegistry(PUBLIC_OPSCTL),
            is_configured=_configured_ok(configured_calls),
            get_hub_client_fn=_forbidden_hub(),
            principal="user:alice",
        )
    )

    assert result == "SYSTEM: Error checking tool access for 'opsctl'. Please try again later."
    assert configured_calls == []


# --- search_tools: pre-rank authorization filter -----------------------------

SEARCH_TOOL_CONFIGS = {
    "opsctl": {
        "name": "opsctl",
        "description": "Executes opsctl CLI commands for connector diagnostics and metrics.",
        "public": True,
        "inputs": {},
    },
    "netctl": {
        "name": "netctl",
        "description": "Inspects cluster nodes, tenants, and connectors read-only.",
        "public": True,
        "inputs": {},
    },
    "system_restart": {
        "name": "system_restart",
        "description": "Restarts internal system services. Do not expose.",
        "public": False,
        "inputs": {},
    },
}


def _patch_search_registry(monkeypatch):
    mgr = tool_search.identity_mgr
    monkeypatch.setattr(mgr, "get_all_tool_configs", lambda: SEARCH_TOOL_CONFIGS)
    monkeypatch.setattr(mgr, "get_all_mcp_configs", lambda: {})
    monkeypatch.setattr(mgr, "get_all_tool_embeddings", lambda: {})
    monkeypatch.setattr(mgr, "get_all_health_statuses", lambda entity_type: {})
    # Force the keyword ranker so ranking is deterministic without embeddings.
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)


def test_search_tools_filters_denied_tools_before_ranking(monkeypatch):
    _patch_search_registry(monkeypatch)
    _install_authz(
        monkeypatch, policy=_authz_policy(_authz_rule(["netctl"])), mode="enforcing"
    )

    results = asyncio.run(
        tool_search.search_tools("cluster nodes", limit=0, principal="user:bob")
    )
    assert [r["name"] for r in results] == ["netctl"]

    # opsctl ranks first for this query, so a limit of 1 only returns netctl if the
    # filter ran before ranking.
    ranked = asyncio.run(
        tool_search.search_tools(
            "opsctl CLI commands", limit=1, principal="user:bob"
        )
    )
    assert [r["name"] for r in ranked] == ["netctl"]


def test_search_tools_keeps_denied_tools_and_records_them_in_shadow(monkeypatch):
    _patch_search_registry(monkeypatch)
    _install_authz(monkeypatch, policy=_authz_policy(), mode="shadow")

    results = asyncio.run(
        tool_search.search_tools("cluster nodes", limit=0, principal="user:bob")
    )

    assert {r["name"] for r in results} == {"opsctl", "netctl"}
    entries = tool_authz.shadow_denies()  # newest first
    assert {e["tool"] for e in entries} == {"opsctl", "netctl"}
    assert {e["scope"] for e in entries} == {"tools:read"}


def test_search_tools_with_authz_off_returns_all_candidates_and_records_nothing(monkeypatch):
    _patch_search_registry(monkeypatch)
    _install_authz(monkeypatch, policy=_authz_policy(), mode="off")

    results = asyncio.run(
        tool_search.search_tools("cluster nodes", limit=0, principal="user:bob")
    )

    assert {r["name"] for r in results} == {"opsctl", "netctl"}
    assert tool_authz.shadow_denies() == []


def test_use_tool_forwards_the_user_principal(monkeypatch):
    monkeypatch.setattr(
        gateway.identity_mgr, "get_tool_config",
        lambda name: {"name": name, "public": True},
    )
    seen = {}

    async def fake_execute(tool_name, arguments, user_id, **kwargs):
        seen.update(tool_name=tool_name, user_id=user_id, **kwargs)
        return "ok"

    monkeypatch.setattr(gateway, "execute_whitelisted_tool", fake_execute)
    user_id_var.set("user-1")

    result = asyncio.run(gateway.use_tool(FakeContext(), "opsctl", {"x": 1}))

    assert result == "ok"
    assert seen["principal"] == "user:user-1"
    assert seen["user_id"] == "user-1"


# --- use_tool: the minted gateway token carries the caller's identity ---------
#
# Identity is minted once, at the run/mint seam, and every downstream hop reads it
# from the token's claims. The gateway's system token is no exception: it carries the
# user id, email and groups so the hub/relay/edge can attribute the call without a
# request body.

GATEWAY_SECRET = "gateway-tool-execution-unit-secret-012345678"


def _install_mint_identity(monkeypatch, user_id, record):
    """Fake the identity-manager read the mint performs, once."""
    auth.agent_token_var.set(None)
    monkeypatch.setenv("AGENT_TOKEN_SECRET", GATEWAY_SECRET)
    # Hermetic: a developer's shell/dev deployment must not turn "no record" into the
    # DEV_USER_EMAIL fallback.
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.delenv("DEV_USER_EMAIL", raising=False)
    seen = []

    def fake_get_user(identity):
        seen.append(identity)
        return record

    monkeypatch.setattr(gateway.identity_mgr, "get_user", fake_get_user)
    return seen


def test_use_tool_mints_a_gateway_token_with_the_callers_email_and_groups(monkeypatch):
    from core import agent_token

    monkeypatch.setattr(
        gateway.identity_mgr, "get_tool_config",
        lambda name: {"name": name, "public": True},
    )
    seen = _install_mint_identity(
        monkeypatch, "user-1", {"email": "ops@example.com", "groups": ["ops", "sre", "ops"]}
    )

    minted = {}

    async def fake_execute(tool_name, arguments, user_id, **kwargs):
        # Read the contextvar where the run set it (asyncio.run isolates contexts).
        minted["token"] = auth.agent_token_var.get()
        return "ok"

    monkeypatch.setattr(gateway, "execute_whitelisted_tool", fake_execute)
    user_id_var.set("user-1")

    assert asyncio.run(gateway.use_tool(FakeContext(), "opsctl", {"x": 1})) == "ok"

    claims = agent_token.verify(minted["token"])
    assert claims.agent == "gateway"
    # An ordinary agent token: no elevated principal, so the hub/relay treat the front
    # door like any other caller (its grant is the tool's own public exposure).
    assert claims.principal is None
    assert claims.user_id == "user-1"
    assert claims.user_email == "ops@example.com"
    # Sorted and de-duplicated, exactly as the token claim requires.
    assert claims.groups == ("ops", "sre")
    # Resolved ONCE, at mint -- never per call.
    assert seen == ["user-1"]


def test_use_tool_mints_without_email_when_the_record_has_none(monkeypatch):
    """An unreadable/empty record must not fail the tool call."""
    from core import agent_token

    monkeypatch.setattr(
        gateway.identity_mgr, "get_tool_config",
        lambda name: {"name": name, "public": True},
    )
    _install_mint_identity(monkeypatch, "user-1", None)

    minted = {}

    async def fake_execute(tool_name, arguments, user_id, **kwargs):
        minted["token"] = auth.agent_token_var.get()
        return "ok"

    monkeypatch.setattr(gateway, "execute_whitelisted_tool", fake_execute)
    user_id_var.set("user-1")

    assert asyncio.run(gateway.use_tool(FakeContext(), "opsctl", {"x": 1})) == "ok"

    claims = agent_token.verify(minted["token"])
    assert claims.user_email is None
    assert claims.groups == ()
