# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Phase 6 — Comprehensive Verification & Regression Test Suite for Direct Tool Gateway
Execution (see __spec_docs/direct_tool_gateway_execution_spec.md).

Exercises the layers *together* rather than re-testing any single layer in isolation —
that's already covered by tests/test_models.py, tests/test_tool_search.py,
tests/test_gateway_tool_execution.py, and tests/test_supervisor_two_tier.py. Five groups
mirror the spec's Phase 6 checklist verbatim:

  Test 1 — Model validation of `public`/`public_tools` defaults.
  Test 2 — Whitelisting security: internal tools are hidden from `search_tools` AND
           rejected by `use_tool` on BOTH implementations (gateway + supervisor).
  Test 3 — Unconfigured-tool diagnostics: missing-credential responses never raise,
           on both `use_tool` implementations, including when a guard itself errors.
  Test 4 — Gateway direct execution: arguments forwarded verbatim (plus `__user_id`
           injection), stdout/JSON returned intact and unmodified.
  Test 5 — Supervisor two-tier routing: `search_tools`/`use_tool` are registered
           alongside `search_agents`, and a full Tier-1 `search_tools` -> `use_tool`
           round trip resolves with no agent delegation involved.

A final `TestLiveRegistry` class re-validates Test 1/2/3's security properties against
the REAL etcd registry state left by Phases 1-5 (no mocks) — read-only only (no Hub
subprocess execution, no secret mutation), and skips itself automatically if the
etcd-backed registry isn't reachable, so the rest of the suite still passes standalone.
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import pytest

from core.models import ToolConfig, MCPConfig
from core import gateway, agent_factory
from core.auth import user_id_var, IdentityManager
import core.tool_search as tool_search_module
import core.discovery as discovery_module


# =============================================================================
# Test 1: Model validation of `public` and `public_tools` fields with defaults.
# =============================================================================

def _tool_kwargs(**overrides):
    kwargs = dict(name="opsctl", description="Acme Operations CLI", runtime="python", entrypoint="wrapper.py")
    kwargs.update(overrides)
    return kwargs


class TestModelValidation:
    def test_tool_config_defaults_to_internal(self):
        assert ToolConfig(**_tool_kwargs()).public is False

    def test_tool_config_can_be_marked_public(self):
        assert ToolConfig(**_tool_kwargs(public=True)).public is True

    def test_mcp_config_defaults_to_internal_with_empty_whitelist(self):
        config = MCPConfig(name="example-mcp")
        assert config.public is False
        assert config.public_tools == []

    def test_mcp_config_server_wide_public(self):
        assert MCPConfig(name="example-mcp", public=True).public is True

    def test_mcp_config_per_tool_whitelist_without_server_wide_public(self):
        config = MCPConfig(name="example-mcp", public_tools=["clusters_get_all"])
        assert config.public is False
        assert config.public_tools == ["clusters_get_all"]


# =============================================================================
# Shared fakes (mirror the harnesses already established in
# tests/test_gateway_tool_execution.py and tests/test_supervisor_two_tier.py)
# =============================================================================

class FakeContext:
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


class FakeMCPClient:
    def __init__(self, result):
        self._result = result
        self.calls = []

    async def call_tool(self, name, arguments, raise_on_error=True):
        self.calls.append((name, arguments, raise_on_error))
        return self._result


class FakeAgent:
    """Stand-in for pydantic_ai.Agent — captures `@agent.tool_plain(...)`-decorated
    coroutines by name so they can be invoked directly, exactly as
    tests/test_supervisor_two_tier.py's Group A already does."""

    def __init__(self):
        self.tools: Dict[str, Any] = {}

    def tool_plain(self, name=None, description=None):
        def decorator(func):
            self.tools[name or func.__name__] = func
            return func
        return decorator


def _build_fake_supervisor() -> FakeAgent:
    fake_agent = FakeAgent()
    agent_factory._register_admin_tools(fake_agent)
    return fake_agent


REGISTRY_FIXTURE = {
    "tool_configs": {
        "netctl": {"name": "netctl", "description": "Inspect cluster nodes and tenants.", "public": True, "inputs": {}},
        "system_restart": {"name": "system_restart", "description": "Restart internal system services.", "public": False, "inputs": {}},
    },
    "mcp_configs": {
        "example-mcp": {
            "name": "example-mcp",
            "public": False,
            "public_tools": ["clusters_get_all"],
            "tools": [
                {"name": "clusters_get_all", "description": "List all clusters.", "inputSchema": {}},
                {"name": "internal_admin_tool", "description": "Restart internal system services.", "inputSchema": {}},
            ],
        },
    },
}


def _patch_search_registry(monkeypatch):
    monkeypatch.setattr(tool_search_module.identity_mgr, "get_all_tool_configs", lambda: REGISTRY_FIXTURE["tool_configs"])
    monkeypatch.setattr(tool_search_module.identity_mgr, "get_all_mcp_configs", lambda: REGISTRY_FIXTURE["mcp_configs"])
    monkeypatch.setattr(tool_search_module.identity_mgr, "get_all_tool_embeddings", lambda: {})
    monkeypatch.setattr(tool_search_module.identity_mgr, "get_all_health_statuses", lambda kind: {})
    monkeypatch.setattr(tool_search_module, "embed_text", lambda text, task_type: None)  # force keyword fallback


# =============================================================================
# Test 2: Whitelisting security — internal tools hidden from search_tools AND
# rejected by use_tool on both the gateway and the supervisor implementations.
# =============================================================================

class TestWhitelistingSecurity:
    def test_search_tools_never_surfaces_internal_tools_even_on_exact_keyword_match(self, monkeypatch):
        _patch_search_registry(monkeypatch)
        # Query text matches the internal tool's description verbatim ("restart internal
        # system services") — a naive keyword ranker would rank it first. It must still
        # never appear because `public` is False.
        results = asyncio.run(tool_search_module.search_tools("restart internal system services", limit=10))
        names = [r["name"] for r in results]
        assert "system_restart" not in names
        assert "mcp__example-mcp__internal_admin_tool" not in names

    def test_search_tools_surfaces_only_whitelisted_local_and_mcp_tools(self, monkeypatch):
        _patch_search_registry(monkeypatch)
        results = asyncio.run(tool_search_module.search_tools("cluster tenants", limit=10))
        names = {r["name"] for r in results}
        assert names == {"netctl", "mcp__example-mcp__clusters_get_all"}

    def test_gateway_use_tool_denies_internal_local_tool(self, monkeypatch):
        monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: REGISTRY_FIXTURE["tool_configs"].get(name))
        user_id_var.set("user-1")
        result = asyncio.run(gateway.use_tool(FakeContext(), "system_restart", {}))
        assert result == "SYSTEM: Access denied. Tool 'system_restart' is internal and not exposed for direct execution."

    def test_gateway_use_tool_denies_non_whitelisted_mcp_tool(self, monkeypatch):
        monkeypatch.setattr(gateway.identity_mgr, "get_mcp_config", lambda name: REGISTRY_FIXTURE["mcp_configs"].get(name))
        user_id_var.set("user-1")
        result = asyncio.run(gateway.use_tool(FakeContext(), "mcp__example-mcp__internal_admin_tool", {}))
        assert "Access denied" in result

    def test_supervisor_use_tool_denies_internal_local_tool(self, monkeypatch):
        from types import SimpleNamespace
        fake_identity = SimpleNamespace(get_tool_config=lambda name: REGISTRY_FIXTURE["tool_configs"].get(name))
        monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)
        fake_agent = _build_fake_supervisor()
        user_id_var.set("user-1")
        result = asyncio.run(fake_agent.tools["use_tool"]("system_restart", {}))
        assert result == "SYSTEM: Access denied. Tool 'system_restart' is internal and not exposed for direct execution."

    def test_supervisor_use_tool_denies_non_whitelisted_mcp_tool(self, monkeypatch):
        from types import SimpleNamespace
        fake_identity = SimpleNamespace(get_mcp_config=lambda name: REGISTRY_FIXTURE["mcp_configs"].get(name))
        monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)
        fake_agent = _build_fake_supervisor()
        user_id_var.set("user-1")
        result = asyncio.run(fake_agent.tools["use_tool"]("mcp__example-mcp__internal_admin_tool", {}))
        assert "Access denied" in result

    def test_gateway_use_tool_denies_unknown_and_malformed_names(self, monkeypatch):
        monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: None)
        user_id_var.set("user-1")
        assert "Access denied" in asyncio.run(gateway.use_tool(FakeContext(), "does_not_exist", {}))
        assert "Access denied" in asyncio.run(gateway.use_tool(FakeContext(), "mcp__onlyserver", {}))


# =============================================================================
# Test 3: Unconfigured tool detection — missing credentials return clear
# diagnostic strings, never an unhandled exception, on both implementations.
# =============================================================================

class TestUnconfiguredToolDiagnostics:
    def test_gateway_use_tool_reports_missing_secrets_without_raising(self, monkeypatch):
        monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: {"name": name, "public": True})

        async def fake_not_configured(tool_name, user_id=None):
            return {"configured": False, "missing_secrets": ["EXAMPLE-API_STAGING_USERNAME"], "missing_variables": [], "optional_missing_secrets": []}

        monkeypatch.setattr(gateway, "is_tool_configured", fake_not_configured)
        user_id_var.set("user-1")

        result = asyncio.run(gateway.use_tool(FakeContext(), "opsctl", {"args": ["connector", "detail"]}))
        assert result.startswith("SYSTEM: Tool 'opsctl' requires configuration before it can be used.")
        assert "EXAMPLE-API_STAGING_USERNAME" in result
        assert "/configuration" in result

    def test_supervisor_use_tool_reports_missing_secrets_without_raising(self, monkeypatch):
        from types import SimpleNamespace
        fake_identity = SimpleNamespace(get_tool_config=lambda name: {"name": name, "public": True})
        monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)
        fake_agent = _build_fake_supervisor()

        async def fake_not_configured(tool_name, user_id=None):
            return {"configured": False, "missing_secrets": ["EXAMPLE-API_PRODUCTION_PASSWORD"], "missing_variables": [], "optional_missing_secrets": []}

        monkeypatch.setattr(discovery_module, "is_tool_configured", fake_not_configured)
        user_id_var.set("user-1")

        result = asyncio.run(fake_agent.tools["use_tool"]("opsctl", {"args": ["connector", "detail"]}))
        assert result.startswith("SYSTEM: Tool 'opsctl' requires configuration before it can be used.")
        assert "EXAMPLE-API_PRODUCTION_PASSWORD" in result

    def test_gateway_use_tool_catches_configuration_guard_exception(self, monkeypatch, caplog):
        """Even if the configuration check itself blows up, use_tool must degrade to a
        SYSTEM error string rather than propagate — the gateway is a public entrypoint."""
        monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: {"name": name, "public": True})

        async def raising_is_tool_configured(tool_name, user_id=None):
            raise RuntimeError("etcd unreachable")

        monkeypatch.setattr(gateway, "is_tool_configured", raising_is_tool_configured)
        user_id_var.set("user-1")

        with caplog.at_level(logging.ERROR, logger="core.tool_search"):
            result = asyncio.run(gateway.use_tool(FakeContext(), "opsctl", {"args": ["--help"]}))

        assert result == "SYSTEM: Error checking configuration for tool 'opsctl'. Please try again later."
        assert "etcd unreachable" not in result
        assert "etcd unreachable" in caplog.text

    def test_search_tools_annotates_unconfigured_results_instead_of_raising(self, monkeypatch):
        _patch_search_registry(monkeypatch)

        async def fake_not_configured(tool_name, user_id=None):
            return {"configured": False, "missing_secrets": ["EXAMPLE-API_STAGING_USERNAME"], "missing_variables": [], "optional_missing_secrets": []}

        monkeypatch.setattr(tool_search_module, "is_tool_configured", fake_not_configured)

        results = asyncio.run(tool_search_module.search_tools("cluster tenants", limit=10, user_id="user-1"))
        netctl_card = next(r for r in results if r["name"] == "netctl")
        assert netctl_card["configured"] is False
        assert "EXAMPLE-API_STAGING_USERNAME" in netctl_card["description"]


# =============================================================================
# Test 4: Gateway direct tool execution — input parameters are forwarded to the
# Hub verbatim and the structured stdout payload is returned intact.
# =============================================================================

class TestGatewayDirectExecution:
    def test_arguments_forwarded_verbatim_plus_user_id_injection(self, monkeypatch):
        monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: {"name": name, "public": True})

        async def fake_configured(tool_name, user_id=None):
            return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

        monkeypatch.setattr(gateway, "is_tool_configured", fake_configured)

        stdout_payload = {"stdout": '{"connectors": [{"name": "my-conn", "status": "UP"}]}', "stderr": "", "exit_code": 0}
        fake_client = FakeMCPClient(FakeCallToolResult(data=stdout_payload))

        async def fake_get_hub_client():
            return fake_client

        monkeypatch.setattr(gateway, "get_hub_client", fake_get_hub_client)
        user_id_var.set("user-42")

        sent_args = {"args": ["connector", "detail", "--name", "my-conn", "--env", "production"]}
        result = asyncio.run(gateway.use_tool(FakeContext(), "opsctl", sent_args))

        # Output is returned byte-for-byte identical to what the Hub produced — no
        # re-serialization, truncation, or LLM-style summarization of the stdout JSON.
        assert result == stdout_payload
        assert result["stdout"] == stdout_payload["stdout"]

        name, forwarded_arguments, raise_on_error = fake_client.calls[0]
        assert name == "opsctl"
        # The gateway mints a `gateway` principal token when a secret is configured
        # (another suite may leave DEV_MODE/AGENT_TOKEN_SECRET in the environment).
        token = forwarded_arguments.pop("__agent_token", None)
        assert token is None or token.startswith("t1.")
        assert forwarded_arguments == {**sent_args, "__user_id": "user-42"}
        assert raise_on_error is False

    def test_error_exit_code_surfaces_intact_not_raised(self, monkeypatch):
        """core/hub.py's run_tool bakes failures into exit_code/stderr rather than raising
        an MCP-level error — confirm use_tool passes that dict through untouched."""
        monkeypatch.setattr(gateway.identity_mgr, "get_tool_config", lambda name: {"name": name, "public": True})

        async def fake_configured(tool_name, user_id=None):
            return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

        monkeypatch.setattr(gateway, "is_tool_configured", fake_configured)

        error_payload = {"stdout": "", "stderr": "Error: connector 'ghost-conn' not found", "exit_code": 1}
        fake_client = FakeMCPClient(FakeCallToolResult(data=error_payload))

        async def fake_get_hub_client():
            return fake_client

        monkeypatch.setattr(gateway, "get_hub_client", fake_get_hub_client)
        user_id_var.set("user-1")

        result = asyncio.run(gateway.use_tool(FakeContext(), "opsctl", {"args": ["connector", "detail", "--name", "ghost-conn"]}))
        assert result == error_payload
        assert result["exit_code"] == 1


# =============================================================================
# Test 5: Supervisor two-tier routing — search_tools/use_tool are registered and
# callable in the supervisor's toolset, and a Tier-1 request resolves end-to-end
# via search_tools -> use_tool with zero agent delegation.
# =============================================================================

class TestSupervisorTwoTierRouting:
    def test_toolset_contains_both_tiers(self):
        fake_agent = _build_fake_supervisor()
        # Tier 1 (direct execution) and Tier 2 (agent delegation) must coexist.
        assert "search_tools" in fake_agent.tools
        assert "use_tool" in fake_agent.tools
        assert "search_agents" in fake_agent.tools

    def test_tier1_search_then_execute_round_trip_never_touches_agent_delegation(self, monkeypatch):
        """Simulates the spec's own 'list all clusters in preprod' example: search_tools locates
        netctl, use_tool executes it directly against the Hub — no search_agents/task call."""
        from types import SimpleNamespace
        fake_identity = SimpleNamespace(get_tool_config=lambda name: {"name": name, "public": True})
        monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)
        fake_agent = _build_fake_supervisor()

        card = {"name": "netctl", "description": "Inspect cluster nodes.", "parameters": {}, "configured": True, "status": "Online", "source": "local"}

        async def fake_ranked_search(query, limit=8, user_id=None, principal=None):
            return [card]

        monkeypatch.setattr(tool_search_module, "search_tools", fake_ranked_search)

        async def fake_configured(tool_name, user_id=None):
            return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

        monkeypatch.setattr(discovery_module, "is_tool_configured", fake_configured)

        calls = []

        class FakeResult:
            data = {"clusters": ["cluster-preprod-1", "cluster-preprod-2"]}
            structured_content = None
            content = None

        class FakeHubClient:
            async def call_tool(self, name, arguments, raise_on_error=True):
                calls.append((name, arguments, raise_on_error))
                return FakeResult()

        async def fake_get_hub_client():
            return FakeHubClient()

        monkeypatch.setattr(agent_factory, "get_hub_client", fake_get_hub_client)
        user_id_var.set("user-99")

        # Step 1: discovery.
        found = asyncio.run(fake_agent.tools["search_tools"]("list all clusters in preprod"))
        assert found == [card]
        assert found[0]["configured"] is True

        # Step 2: direct execution of the discovered tool — no task()/search_agents involved.
        result = asyncio.run(fake_agent.tools["use_tool"]("netctl", {"environment": "preprod", "args": ["cluster", "list"]}))

        assert result == {"clusters": ["cluster-preprod-1", "cluster-preprod-2"]}
        name, arguments, raise_on_error = calls[0]
        assert name == "netctl"
        token = arguments.pop("__agent_token", None)
        assert token is None or token.startswith("t1.")
        assert arguments == {
            "environment": "preprod", "args": ["cluster", "list"],
            "__user_id": "user-99",
        }
        assert raise_on_error is False


# =============================================================================
# Live registry validation — read-only re-checks of Phase 1-5's real etcd state.
# No secrets are mutated and no Hub subprocess is executed (that end-to-end path was
# already manually live-validated in Phase 3/5's completion notes); this class only
# re-proves the security/discovery properties above hold against the real registry,
# not just mocked fixtures. Skips itself if the registry is unreachable.
# =============================================================================

def _live_identity_mgr() -> Optional[IdentityManager]:
    import os
    try:
        mgr = IdentityManager(host=os.getenv("ETCD_HOST", "127.0.0.1"), port=int(os.getenv("ETCD_PORT", 2379)))
        mgr.get_all_tool_configs()
        return mgr
    except Exception:
        return None


_LIVE_MGR = _live_identity_mgr()


@pytest.mark.skipif(_LIVE_MGR is None, reason="etcd registry not reachable from this environment")
class TestLiveRegistry:
    def test_opsctl_and_netctl_are_public_with_indexed_embeddings(self):
        tool_configs = _LIVE_MGR.get_all_tool_configs()
        assert tool_configs.get("opsctl", {}).get("public") is True
        assert tool_configs.get("netctl", {}).get("public") is True

        embeddings = _LIVE_MGR.get_all_tool_embeddings()
        assert len(embeddings.get("opsctl", [])) > 0
        assert len(embeddings.get("netctl", [])) > 0

    def test_operator_agents_are_fully_decommissioned(self):
        agent_configs = _LIVE_MGR.get_all_agent_configs()
        assert "opsctl-operator" not in agent_configs
        assert "netctl-operator" not in agent_configs

    def test_search_tools_surfaces_only_genuinely_public_tools(self):
        tool_configs = _LIVE_MGR.get_all_tool_configs()
        public_names = {name for name, cfg in tool_configs.items() if cfg.get("public") is True}
        assert {"opsctl", "netctl"}.issubset(public_names)

        # Full ranked list (limit<=0) — every local-tool result must correspond to a
        # tool actually marked public in the live registry; nothing internal leaks.
        results = asyncio.run(tool_search_module.search_tools("opsctl netctl connector cluster diagnostics", limit=0))
        for card in results:
            if card["source"] == "local":
                assert card["name"] in public_names

    def test_gateway_use_tool_denies_a_real_internal_tool(self):
        tool_configs = _LIVE_MGR.get_all_tool_configs()
        internal_candidates = [name for name, cfg in tool_configs.items() if cfg.get("public") is not True]
        if not internal_candidates:
            pytest.skip("no internal (non-public) tool present in the live registry to test against")
        user_id_var.set("dev@acme.com")
        result = asyncio.run(gateway.use_tool(FakeContext(), internal_candidates[0], {}))
        assert result == f"SYSTEM: Access denied. Tool '{internal_candidates[0]}' is internal and not exposed for direct execution."

    def test_use_tool_reports_real_missing_devops_credentials_without_raising(self, monkeypatch):
        """As of this phase no identity in the live registry has EXAMPLE-API_* credentials
        configured (verified directly against etcd), so the real Configuration Guard for
        `opsctl` is exercised end-to-end here. Defensively guards against the assumption
        ever becoming false (e.g. someone configures real DevOps credentials for this
        identity later): `get_hub_client` is patched to raise if reached, so a change in
        live credential state fails this test loudly instead of silently executing a real
        Hub subprocess against production infrastructure."""

        async def _fail_if_execution_reached():
            raise AssertionError(
                "Configuration Guard unexpectedly passed — this identity now has real "
                "EXAMPLE-API_* credentials configured, so 'opsctl' would have executed for "
                "real. Update/skip this test rather than let it silently call the Hub."
            )

        monkeypatch.setattr(gateway, "get_hub_client", _fail_if_execution_reached)
        user_id_var.set("dev@acme.com")
        result = asyncio.run(gateway.use_tool(FakeContext(), "opsctl", {"args": ["connector", "detail"]}))
        assert result.startswith("SYSTEM: Tool 'opsctl' requires configuration before it can be used.")
        assert "EXAMPLE-API_" in result
        assert "/configuration" in result
