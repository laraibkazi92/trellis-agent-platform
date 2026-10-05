# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, List, Optional

from core import gateway
from core.auth import user_id_var


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
