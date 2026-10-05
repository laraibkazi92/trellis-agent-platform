# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Real MCP wire-protocol smoke test for core/gateway.py's FastMCP server.

Every other test in this repo (e.g. tests/test_agent_gateway_host_access.py) calls
the underlying async functions behind an @mcp.tool(...) decorator directly, as plain
coroutines -- this never exercises FastMCP's actual tool dispatch/serialization layer
at all. That leaves a real gap: a passing suite proves the Python-level function
signatures are compatible with the installed fastmcp/mcp versions, but does NOT prove
a real MCP client can connect to this repo's server and successfully call a tool over
the wire.

This test closes that gap using FastMCP's own in-memory transport: `fastmcp.Client`
accepts a `FastMCP` server instance directly (see fastmcp.client.client.Client's
`transport` docstring -- "FastMCP: In-process FastMCP server") and drives the full
client/server protocol handshake, request serialization, tool dispatch, and response
parsing in-process, with no subprocess and no real network socket. This is the
standard, fast, deterministic way to test a FastMCP server's actual wire behavior.

All of gateway.py's own internal dependencies (etcd via identity_mgr, the rules
engine's own identity_mgr, Host's /health liveness ping) are monkeypatched using the
exact same pattern tests/test_agent_gateway_host_access.py already established for
this module (_patch_gateway_etcd, faking `discover_agents`) -- the new thing this
test adds on top of that established mocking foundation is the real fastmcp.Client
<-> FastMCP server round-trip, which no existing test exercises.
"""
import asyncio
from types import SimpleNamespace

from fastmcp import Client

from core import agent_search
from core import gateway


def _empty_agent_search_identity(monkeypatch):
    """An empty catalog makes _build_candidates() return [] immediately, so
    core.gateway.search_agents can return [] with zero LLM/embedding/etcd work.
    (Phase 6/I8 made agent_search and gateway share one IdentityManager singleton, so
    this patch is visible to gateway's helpers too.)"""
    monkeypatch.setattr(agent_search.identity_mgr, "get_all_agent_configs", lambda: {})
    monkeypatch.setattr(agent_search.identity_mgr, "get_all_agent_embeddings", lambda: {})
    monkeypatch.setattr(agent_search.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(agent_search.identity_mgr, "get_all_health_statuses", lambda kind: {})


def _patch_gateway_etcd(monkeypatch, disabled=(), agent_configs=None, agent_health=None, tool_health=None):
    """Verbatim copy of tests/test_agent_gateway_host_access.py's helper of the same
    name -- mocks the shared module-level identity_mgr so _get_visible_agents()'s bulk
    etcd fetch never touches a real etcd. Because agent_search/gateway share the same
    instance (Phase 6/I8), callers that need a different catalog must apply this helper
    first and their own method patches afterwards (last write wins)."""
    monkeypatch.setattr(gateway.identity_mgr, "get_disabled_standard_agents", lambda: list(disabled))
    monkeypatch.setattr(gateway.identity_mgr, "get_all_agent_configs", lambda: dict(agent_configs or {}))

    def fake_get_all_health_statuses(entity_type):
        if entity_type == "agent":
            return dict(agent_health or {})
        return dict(tool_health or {})

    monkeypatch.setattr(gateway.identity_mgr, "get_all_health_statuses", fake_get_all_health_statuses)


def test_search_agents_tool_round_trips_through_real_mcp_client(monkeypatch):
    """A real fastmcp.Client, connected in-process to this repo's actual `mcp`
    FastMCP server object (core.gateway.mcp -- the same object a real MCP client
    connects to), calls the real `search_agents` tool over the actual MCP protocol
    (JSON-RPC request -> FastMCP's tool dispatcher -> our async function -> MCP-typed
    response -> client-side parsing). An empty agent catalog is the fastest way to
    reach a real, asserted response without also needing to fake a Host HTTP server.
    """
    _empty_agent_search_identity(monkeypatch)

    async def run():
        client = Client(gateway.mcp)
        async with client:
            tools = await client.list_tools()
            tool_names = {t.name for t in tools}
            assert "search_agents" in tool_names, (
                f"search_agents not registered on the real FastMCP server; got {tool_names}"
            )

            return await client.call_tool("search_agents", {"query": "anything"})

    result = asyncio.run(run())

    # `result.data`/`result.structured_content` are what fastmcp.Client parsed back
    # out of the MCP response after a genuine JSON-RPC call_tool request/response
    # cycle -- not a Python-level return value handed back in-process. `meta` carries
    # real protocol negotiation info (serverInfo name/version), confirming a real
    # handshake happened, not just a direct function call.
    assert result.is_error is False
    assert result.data == []
    assert result.structured_content == {"result": []}
    assert result.meta["io.modelcontextprotocol/serverInfo"]["name"] == "Agent Gateway"


def test_search_agents_tool_returns_real_results_through_mcp_client(monkeypatch):
    """Same in-process MCP round-trip, but with one real candidate agent in the fake
    etcd catalog and a simulated Host-unreachable liveness failure (gateway's real,
    documented failure-surfacing behavior), confirming a non-trivial result list
    survives real MCP JSON-RPC serialization/deserialization intact (dict shape,
    string fields) and that gateway's Error-sentinel path is reachable through a real
    client, not just via a direct Python call."""
    # Phase 6 (Cycle 4, I8) made agent_search.identity_mgr and gateway.identity_mgr the
    # same shared singleton, so _patch_gateway_etcd's empty-catalog get_all_agent_configs
    # patch must be applied BEFORE this test's own catalog patch -- last write wins.
    _patch_gateway_etcd(monkeypatch)
    monkeypatch.setattr(
        agent_search.identity_mgr,
        "get_all_agent_configs",
        lambda: {
            "general-agent": {
                "name": "general-agent",
                "description": "Handles general purpose requests.",
                "type": "user_agent",
                "external": True,
                "rules": {},
            }
        },
    )
    monkeypatch.setattr(agent_search.identity_mgr, "get_all_agent_embeddings", lambda: {})
    monkeypatch.setattr(agent_search.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(agent_search.identity_mgr, "get_all_health_statuses", lambda kind: {})
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: None)

    async def fake_discover_agents(user_id=None, agent_configs=None, agent_health=None):
        return [
            {"name": "general-agent", "description": "Handles general purpose requests.",
             "type": "user_agent", "is_configured": True, "external": True}
        ]

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)

    class _RaisingHTTPClient:
        async def get(self, url, timeout=None):
            raise ConnectionError("no Host in this test environment")

    monkeypatch.setattr(
        gateway,
        "app",
        SimpleNamespace(state=SimpleNamespace(http_client=_RaisingHTTPClient())),
        raising=False,
    )

    async def run():
        client = Client(gateway.mcp)
        async with client:
            return await client.call_tool("search_agents", {"query": "general request", "limit": 5})

    result = asyncio.run(run())

    assert result.is_error is False
    assert isinstance(result.data, list)
    assert len(result.data) == 1
    assert result.data[0]["name"] == "Error"
    assert result.data[0]["description"] == "Host API temporarily unreachable. Please try again later."
    assert "no Host in this test environment" not in result.data[0]["description"]
