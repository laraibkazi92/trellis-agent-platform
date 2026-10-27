# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, List, Optional

import pytest

from core import auth, gateway, tool_access, tool_search
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

    async def fake_ranked(query, limit=8, user_id=None):
        assert query == "inspect cluster nodes"
        assert user_id == "user-1"
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


# --- the evaluator seams ------------------------------------------------------
#
# `execute_whitelisted_tool` asks `core.tool_access` exactly once: the agent and its
# groups come from the run's token, the allowlist from that agent's record, and a
# caller with NO record (the gateway front door) is granted by the target's own
# published exposure. `search_tools` applies the group rules to the public catalog.
# A fake policy registry keeps all of it free of etcd, network and sleeps.


class FakePolicyEtcd:
    """The policy document plus the shared shadow ring."""

    def __init__(self):
        self.policy = None
        self.shared_ring = None
        self.error = None
        self.revision = 1

    def get(self, key, **_kwargs):
        import json

        if self.error is not None:
            raise RuntimeError(self.error)
        if key == tool_access.POLICY_PATH:
            if self.policy is None:
                return None, None
            meta = type("M", (), {"mod_revision": self.revision})()
            return json.dumps(self.policy).encode("utf-8"), meta
        if key == tool_access.SHADOW_DENIAL_PATH:
            return self.shared_ring, None
        return None, None

    def put(self, key, value):
        if self.error is not None:
            raise RuntimeError(self.error)
        payload = value.encode("utf-8") if isinstance(value, str) else value
        if key == tool_access.SHADOW_DENIAL_PATH:
            self.shared_ring = payload

    def add_watch_callback(self, key, callback):
        return 1

    def cancel_watch(self, watch_id):
        pass


@pytest.fixture(autouse=True)
def _front_door_env(monkeypatch):
    """`use_tool` mints for the caller it serves; the evaluator then reads records.

    ``gateway`` has no agent record (that is what makes it the front door), and the
    user record read at mint is faked so no test touches etcd.
    """
    monkeypatch.setenv("AGENT_TOKEN_SECRET", GATEWAY_SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.delenv("DEV_USER_EMAIL", raising=False)
    monkeypatch.setattr(gateway.identity_mgr, "get_agent_config", lambda name: None)
    monkeypatch.setattr(gateway.identity_mgr, "get_user", lambda user_id: None)
    auth.agent_token_var.set(None)
    user_id_var.set(None)
    yield
    auth.agent_token_var.set(None)
    user_id_var.set(None)


@pytest.fixture(autouse=True)
def tool_access_policy(monkeypatch):
    """A per-test policy document (absent by default: no group rules)."""
    import json

    fake = FakePolicyEtcd()
    monkeypatch.setattr(tool_access, "_client", lambda: fake)
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    monkeypatch.setattr(tool_access, "_last_shadow_persist", 0.0)
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()
    yield fake
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()


def _policy(*rules):
    return {"rules": [dict(rule) for rule in rules]}


def _rule(targets, groups=("ops",), name=None):
    rule = {"targets": list(targets), "groups": list(groups)}
    if name is not None:
        rule["name"] = name
    return rule


class FakeToolRegistry:
    """The two registry lookups the front-door exposure rule performs."""

    def __init__(self, tool_configs=None, mcp_configs=None, agent_configs=None):
        self.tool_configs = tool_configs or {}
        self.mcp_configs = mcp_configs or {}
        self.agent_configs = agent_configs or {}

    def get_tool_config(self, name):
        return self.tool_configs.get(name)

    def get_mcp_config(self, name):
        return self.mcp_configs.get(name)

    def get_agent_config(self, name):
        return self.agent_configs.get(name)


def _public_opsctl():
    return {"opsctl": {"name": "opsctl", "public": True}}


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


def _run_execute(*, tool="opsctl", registry=None, configured=None, hub=None):
    return asyncio.run(
        execute_whitelisted_tool(
            tool,
            {"args": ["--help"]},
            "user-1",
            identity_manager=registry or FakeToolRegistry(_public_opsctl()),
            is_configured=configured or _configured_ok(),
            get_hub_client_fn=hub or _forbidden_hub(),
        )
    )


# --- execute_whitelisted_tool: the front door ---------------------------------


def test_the_front_door_executes_a_published_tool():
    fake_client = FakeMCPClient(FakeCallToolResult(data={"stdout": "ok"}))

    async def fake_get_hub_client():
        return fake_client

    result = _run_execute(hub=fake_get_hub_client)

    assert result == {"stdout": "ok"}
    assert len(fake_client.calls) == 1


def test_the_front_door_is_denied_an_internal_tool():
    configured_calls = []

    result = _run_execute(
        registry=FakeToolRegistry({"opsctl": {"name": "opsctl", "public": False}}),
        configured= _configured_ok(configured_calls),
    )

    assert result == (
        "SYSTEM: Access denied. Tool 'opsctl' is internal and not exposed for "
        "direct execution."
    )
    assert configured_calls == []  # denial happens before the configuration guard


def test_an_unknown_tool_is_denied():
    assert "Access denied" in _run_execute(registry=FakeToolRegistry({}))


def test_a_malformed_mcp_name_is_denied():
    assert "Access denied" in _run_execute(tool="mcp__onlyserver")


def test_a_group_rule_denies_the_front_door(tool_access_policy):
    tool_access_policy.policy = _policy(_rule(["opsctl"], name="platform-ops"))

    result = _run_execute()

    assert "not permitted for this principal" in result


def _gateway_call_with_groups(monkeypatch, record):
    """Drive `gateway.use_tool` so the minted token carries the record's groups."""
    monkeypatch.setattr(
        gateway.identity_mgr, "get_user", lambda user_id: record
    )
    # The front door has no agent record of its own, and the configuration check is a
    # registry read as well: both are faked so this test never reaches a live etcd.
    monkeypatch.setattr(gateway.identity_mgr, "get_agent_config", lambda name: None)
    monkeypatch.setattr(gateway, "is_tool_configured", _configured_ok())
    monkeypatch.setattr(
        gateway.identity_mgr, "get_tool_config", lambda name: {"name": name, "public": True}
    )
    fake_client = FakeMCPClient(FakeCallToolResult(data={"stdout": "ok"}))

    async def fake_get_hub_client():
        return fake_client

    monkeypatch.setattr(gateway, "get_hub_client", fake_get_hub_client)
    user_id_var.set("user-1")
    return asyncio.run(gateway.use_tool(FakeContext(), "opsctl", {"args": ["--help"]}))


def test_a_group_rule_admits_the_callers_group(monkeypatch, tool_access_policy):
    """The front door's groups come from the token the gateway minted (claim "g")."""
    tool_access_policy.policy = _policy(_rule(["opsctl"], name="platform-ops"))

    result = _gateway_call_with_groups(
        monkeypatch, {"email": "ops@example.com", "groups": ["ops"]}
    )

    assert result == {"stdout": "ok"}


def test_a_group_rule_denies_a_caller_without_the_group(monkeypatch, tool_access_policy):
    tool_access_policy.policy = _policy(_rule(["opsctl"], name="platform-ops"))

    result = _gateway_call_with_groups(
        monkeypatch, {"email": "ops@example.com", "groups": ["support"]}
    )

    assert "not permitted for this principal" in result


def test_shadow_executes_and_records_the_host_surface(monkeypatch, tool_access_policy):
    monkeypatch.setenv(tool_access.MODE_ENV, "shadow")
    tool_access_policy.policy = _policy(_rule(["opsctl"], name="platform-ops"))
    fake_client = FakeMCPClient(FakeCallToolResult(data={"stdout": "{}"}))

    async def fake_get_hub_client():
        return fake_client

    result = _run_execute(hub=fake_get_hub_client)

    assert result == {"stdout": "{}"}  # shadow still executes
    [entry] = tool_access.recent_shadow_denials()
    # No run token in this direct call, so no agent is invented: the front door.
    assert (entry["agent"], entry["target"], entry["surface"]) == (None, "opsctl", "host")
    assert entry["reason"] == tool_access.REASON_GROUP_DENIED


def test_off_skips_the_group_rules(monkeypatch, tool_access_policy):
    monkeypatch.setenv(tool_access.MODE_ENV, "off")
    tool_access_policy.policy = _policy(_rule(["opsctl"]))
    fake_client = FakeMCPClient(FakeCallToolResult(data={"stdout": "{}"}))

    async def fake_get_hub_client():
        return fake_client

    assert _run_execute(hub=fake_get_hub_client) == {"stdout": "{}"}
    assert tool_access.recent_shadow_denials() == []


def test_an_unreadable_policy_fails_closed(tool_access_policy):
    tool_access_policy.error = "etcd is unreachable"
    tool_access_policy.policy = _policy(_rule(["opsctl"]))

    result = _run_execute()

    assert "not permitted for this principal" in result  # never dispatched


def test_an_evaluator_exception_fails_closed(monkeypatch):
    async def boom(*args, **kwargs):
        raise RuntimeError("evaluator exploded")

    # The gate is async now (the policy read must leave the event loop).
    monkeypatch.setattr(tool_access, "authorize_claims_async", boom)

    result = _run_execute()

    assert result == "SYSTEM: Error checking tool access for 'opsctl'. Please try again later."


# --- execute_whitelisted_tool: an agent with a record ------------------------


def test_an_agent_record_uses_the_allowlist_not_the_public_flag():
    """A bindable (non-public) tool is usable by the agent whose manifest names it."""
    from core import agent_token

    auth.agent_token_var.set(agent_token.mint("researcher", user_id="user-1"))
    fake_client = FakeMCPClient(FakeCallToolResult(data={"stdout": "ok"}))

    async def fake_get_hub_client():
        return fake_client

    result = _run_execute(
        registry=FakeToolRegistry(
            {"opsctl": {"name": "opsctl", "public": False}},
            agent_configs={"researcher": {"allowed_tools": ["opsctl"]}},
        ),
        hub=fake_get_hub_client,
    )

    assert result == {"stdout": "ok"}


def test_an_agent_outside_its_allowlist_is_denied():
    from core import agent_token

    auth.agent_token_var.set(agent_token.mint("researcher", user_id="user-1"))

    result = _run_execute(
        registry=FakeToolRegistry(
            _public_opsctl(), agent_configs={"researcher": {"allowed_tools": ["netctl"]}}
        )
    )

    assert "not permitted for this principal" in result


# --- search_tools: the group-rule filter over the public catalog -------------

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


def _search_token(*, agent="gateway", groups=()):
    from core import agent_token

    auth.agent_token_var.set(agent_token.mint(agent, user_id="user-1", groups=groups))


def test_search_tools_filters_group_denied_tools_before_ranking(
    monkeypatch, tool_access_policy
):
    _patch_search_registry(monkeypatch)
    tool_access_policy.policy = _policy(_rule(["opsctl"], name="platform-ops"))
    _search_token(groups=[])

    results = asyncio.run(tool_search.search_tools("cluster nodes", limit=0))
    assert [r["name"] for r in results] == ["netctl"]

    # opsctl ranks first for this query, so a limit of 1 only returns netctl if the
    # filter ran before ranking.
    ranked = asyncio.run(tool_search.search_tools("opsctl CLI commands", limit=1))
    assert [r["name"] for r in ranked] == ["netctl"]


def test_search_tools_admits_a_matching_group(monkeypatch, tool_access_policy):
    _patch_search_registry(monkeypatch)
    tool_access_policy.policy = _policy(_rule(["opsctl"], groups=["ops"]))
    _search_token(groups=["ops"])

    results = asyncio.run(tool_search.search_tools("cluster nodes", limit=0))

    assert {r["name"] for r in results} == {"opsctl", "netctl"}


def test_search_tools_keeps_denied_tools_and_records_them_in_shadow(
    monkeypatch, tool_access_policy
):
    _patch_search_registry(monkeypatch)
    monkeypatch.setenv(tool_access.MODE_ENV, "shadow")
    tool_access_policy.policy = _policy(_rule(["opsctl"]))
    _search_token()

    results = asyncio.run(tool_search.search_tools("cluster nodes", limit=0))

    assert {r["name"] for r in results} == {"opsctl", "netctl"}
    entries = tool_access.recent_shadow_denials()
    assert [entry["target"] for entry in entries] == ["opsctl"]
    assert entries[0]["surface"] == "host"


def test_search_tools_with_the_switch_off_returns_every_candidate(
    monkeypatch, tool_access_policy
):
    _patch_search_registry(monkeypatch)
    monkeypatch.setenv(tool_access.MODE_ENV, "off")
    tool_access_policy.policy = _policy(_rule(["opsctl"]))
    _search_token()

    results = asyncio.run(tool_search.search_tools("cluster nodes", limit=0))

    assert {r["name"] for r in results} == {"opsctl", "netctl"}
    assert tool_access.recent_shadow_denials() == []


def test_search_tools_never_shows_an_internal_tool(monkeypatch):
    _patch_search_registry(monkeypatch)

    results = asyncio.run(tool_search.search_tools("restart internal services", limit=0))

    assert "system_restart" not in {r["name"] for r in results}


def test_use_tool_passes_the_user_to_the_executor(monkeypatch):
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
    assert seen["tool_name"] == "opsctl"
    assert seen["user_id"] == "user-1"
    # No principal is threaded through any more: the evaluator reads the token.
    assert "principal" not in seen

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
    # An ordinary agent token: the hub/relay treat the front door like any other caller
    # (its grant is the tool's own public exposure). No elevated-principal claim exists.
    assert not hasattr(claims, "principal")
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
