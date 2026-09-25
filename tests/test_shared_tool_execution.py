"""Tests for `core.tool_search.execute_whitelisted_tool` (Cycle 4, Phase 3, Task 3.2).

The shared executor deduplicates the gateway/supervisor `use_tool` flows:
Authorization Guard (`public` whitelist) -> Configuration Guard (`is_configured`) ->
dispatch (external `mcp__` client vs local Hub client, with `__user_id` threaded only
into the local path) -> `extract_tool_output`. Guard denials and execution failures are
returned as `SYSTEM: ...` strings, never raised.

Fakes mirror `tests/test_gateway_tool_execution.py`.
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import Any, List, Optional

from core import tool_search


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


def test_execute_whitelisted_tool_denies_internal_tool(monkeypatch):
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_tool_config",
        lambda name: {"name": "system_restart", "public": False},
    )

    async def _fail_is_configured(tool_name, user_id=None):
        raise AssertionError("is_configured must not be called for a denied tool")

    async def _fail_client(*args, **kwargs):
        raise AssertionError("no client getter may be called for a denied tool")

    result = asyncio.run(tool_search.execute_whitelisted_tool(
        "system_restart",
        {},
        "user-1",
        is_configured=_fail_is_configured,
        get_hub_client_fn=_fail_client,
        get_external_mcp_client_fn=_fail_client,
    ))

    assert result == "SYSTEM: Access denied. Tool 'system_restart' is internal and not exposed for direct execution."


def test_execute_whitelisted_tool_surfaces_whitelist_check_errors(monkeypatch, caplog):
    def _raise(name):
        raise RuntimeError("etcd down")

    monkeypatch.setattr(tool_search.identity_mgr, "get_tool_config", _raise)

    async def _fail(*args, **kwargs):
        raise AssertionError("no downstream step may run after a whitelist-check error")

    with caplog.at_level(logging.ERROR, logger="core.tool_search"):
        result = asyncio.run(tool_search.execute_whitelisted_tool(
            "opsctl",
            {},
            "user-1",
            is_configured=_fail,
            get_hub_client_fn=_fail,
            get_external_mcp_client_fn=_fail,
        ))

    assert result == "SYSTEM: Error checking tool access for 'opsctl'. Please try again later."
    assert "etcd down" not in result
    assert "etcd down" in caplog.text


def test_execute_whitelisted_tool_denies_malformed_mcp_name(monkeypatch):
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_mcp_config",
        lambda name: {"name": "onlyserver", "public": True},
    )

    async def _fail(*args, **kwargs):
        raise AssertionError("no downstream step may run for a malformed mcp__ name")

    result = asyncio.run(tool_search.execute_whitelisted_tool(
        "mcp__onlyserver",
        {},
        "user-1",
        is_configured=_fail,
        get_hub_client_fn=_fail,
        get_external_mcp_client_fn=_fail,
    ))

    assert result == "SYSTEM: Access denied. Tool 'mcp__onlyserver' is internal and not exposed for direct execution."


def test_execute_whitelisted_tool_reports_unconfigured(monkeypatch):
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_tool_config",
        lambda name: {"name": "opsctl", "public": True},
    )

    async def fake_is_configured(tool_name, user_id=None):
        return {"configured": False, "missing_secrets": ["EXAMPLE_TOKEN"], "missing_variables": ["EXAMPLE_REGION"]}

    async def _fail_client(*args, **kwargs):
        raise AssertionError("no client getter may be called for an unconfigured tool")

    result = asyncio.run(tool_search.execute_whitelisted_tool(
        "opsctl",
        {},
        "user-1",
        is_configured=fake_is_configured,
        get_hub_client_fn=_fail_client,
        get_external_mcp_client_fn=_fail_client,
    ))

    assert result == (
        "SYSTEM: Tool 'opsctl' requires configuration before it can be used. "
        "Missing: EXAMPLE_TOKEN, EXAMPLE_REGION. Configure at /configuration"
    )


def test_execute_whitelisted_tool_dispatches_and_threads_user_id(monkeypatch):
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_tool_config",
        lambda name: {"name": name, "public": True},
    )
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_mcp_config",
        lambda name: {"name": name, "public": True},
    )

    async def fake_is_configured(tool_name, user_id=None):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    external_calls = []
    external_client = FakeMCPClient(FakeCallToolResult(data={"ok": 1}))

    async def fake_get_external_mcp_client(server_name, user_id):
        external_calls.append((server_name, user_id))
        return external_client

    hub_client = FakeMCPClient(FakeCallToolResult(data={"ok": 2}))

    async def fake_get_hub_client():
        return hub_client

    mcp_result = asyncio.run(tool_search.execute_whitelisted_tool(
        "mcp__example-mcp__clusters_get_all",
        {"a": 1},
        "user-1",
        is_configured=fake_is_configured,
        get_hub_client_fn=fake_get_hub_client,
        get_external_mcp_client_fn=fake_get_external_mcp_client,
    ))

    assert external_calls == [("example-mcp", "user-1")]
    assert external_client.calls == [("clusters_get_all", {"a": 1}, False)]
    assert mcp_result == {"ok": 1}

    hub_result = asyncio.run(tool_search.execute_whitelisted_tool(
        "opsctl",
        {"a": 1},
        "user-1",
        is_configured=fake_is_configured,
        get_hub_client_fn=fake_get_hub_client,
        get_external_mcp_client_fn=fake_get_external_mcp_client,
    ))

    assert hub_client.calls == [("opsctl", {"a": 1, "__user_id": "user-1"}, False)]
    assert hub_result == {"ok": 2}


def test_execute_whitelisted_tool_surfaces_execution_errors(monkeypatch, caplog):
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_tool_config",
        lambda name: {"name": "opsctl", "public": True},
    )

    async def fake_is_configured(tool_name, user_id=None):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    async def failing_get_hub_client():
        raise ConnectionError("hub unreachable")

    with caplog.at_level(logging.ERROR, logger="core.tool_search"):
        result = asyncio.run(tool_search.execute_whitelisted_tool(
            "opsctl",
            {},
            "user-1",
            is_configured=fake_is_configured,
            get_hub_client_fn=failing_get_hub_client,
        ))

    assert result == "SYSTEM: Error executing tool 'opsctl'. Please try again later."
    assert "hub unreachable" not in result
    assert "hub unreachable" in caplog.text


def test_execute_whitelisted_tool_handles_malformed_status(monkeypatch):
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_tool_config",
        lambda name: {"name": "opsctl", "public": True},
    )

    async def fake_is_configured(tool_name, user_id=None):
        return []

    async def _fail_client(*args, **kwargs):
        raise AssertionError("no client getter may be called when readiness is malformed")

    result = asyncio.run(tool_search.execute_whitelisted_tool(
        "opsctl",
        {},
        "user-1",
        is_configured=fake_is_configured,
        get_hub_client_fn=_fail_client,
        get_external_mcp_client_fn=_fail_client,
    ))

    assert result == "SYSTEM: Error checking configuration for tool 'opsctl'. Please try again later."


def test_execute_whitelisted_tool_surfaces_extraction_errors(monkeypatch, caplog):
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_tool_config",
        lambda name: {"name": "opsctl", "public": True},
    )

    async def fake_is_configured(tool_name, user_id=None):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    class ExplodingResult:
        @property
        def data(self):
            raise RuntimeError("boom")

    async def fake_get_hub_client():
        return FakeMCPClient(ExplodingResult())

    with caplog.at_level(logging.ERROR, logger="core.tool_search"):
        result = asyncio.run(tool_search.execute_whitelisted_tool(
            "opsctl",
            {},
            "user-1",
            is_configured=fake_is_configured,
            get_hub_client_fn=fake_get_hub_client,
        ))

    assert result == "SYSTEM: Error executing tool 'opsctl'. Please try again later."
    assert "boom" not in result
    assert "boom" in caplog.text


def test_execute_whitelisted_tool_handles_non_iterable_missing_fields(monkeypatch):
    """A syntactically valid status with non-iterable missing_* values must degrade
    to the generic 'required configuration' message instead of raising TypeError."""
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_tool_config",
        lambda name: {"name": "opsctl", "public": True},
    )

    async def fake_is_configured(tool_name, user_id=None):
        return {"configured": False, "missing_secrets": 5}

    async def _fail_client(*args, **kwargs):
        raise AssertionError("no client getter may be called for an unconfigured tool")

    result = asyncio.run(tool_search.execute_whitelisted_tool(
        "opsctl",
        {},
        "user-1",
        is_configured=fake_is_configured,
        get_hub_client_fn=_fail_client,
        get_external_mcp_client_fn=_fail_client,
    ))

    assert result == (
        "SYSTEM: Tool 'opsctl' requires configuration before it can be used. "
        "Missing: required configuration. Configure at /configuration"
    )


def test_execute_whitelisted_tool_stringifies_non_string_missing_entries(monkeypatch):
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_tool_config",
        lambda name: {"name": "opsctl", "public": True},
    )

    async def fake_is_configured(tool_name, user_id=None):
        return {"configured": False, "missing_secrets": [123], "missing_variables": ["EXAMPLE_REGION"]}

    async def _fail_client(*args, **kwargs):
        raise AssertionError("no client getter may be called for an unconfigured tool")

    result = asyncio.run(tool_search.execute_whitelisted_tool(
        "opsctl",
        {},
        "user-1",
        is_configured=fake_is_configured,
        get_hub_client_fn=_fail_client,
        get_external_mcp_client_fn=_fail_client,
    ))

    assert result == (
        "SYSTEM: Tool 'opsctl' requires configuration before it can be used. "
        "Missing: 123, EXAMPLE_REGION. Configure at /configuration"
    )


def test_execute_whitelisted_tool_treats_string_missing_field_as_single_label(monkeypatch):
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_tool_config",
        lambda name: {"name": "opsctl", "public": True},
    )

    async def fake_is_configured(tool_name, user_id=None):
        return {"configured": False, "missing_secrets": "EXAMPLE_TOKEN", "missing_variables": ["EXAMPLE_REGION"]}

    async def _fail_client(*args, **kwargs):
        raise AssertionError("no client getter may be called for an unconfigured tool")

    result = asyncio.run(tool_search.execute_whitelisted_tool(
        "opsctl",
        {},
        "user-1",
        is_configured=fake_is_configured,
        get_hub_client_fn=_fail_client,
        get_external_mcp_client_fn=_fail_client,
    ))

    assert result == (
        "SYSTEM: Tool 'opsctl' requires configuration before it can be used. "
        "Missing: EXAMPLE_TOKEN, EXAMPLE_REGION. Configure at /configuration"
    )


def test_execute_whitelisted_tool_extracts_text_fallback(monkeypatch):
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_tool_config",
        lambda name: {"name": "opsctl", "public": True},
    )

    async def fake_is_configured(tool_name, user_id=None):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    client = FakeMCPClient(FakeCallToolResult(
        data=None,
        structured_content=None,
        content=[FakeTextContent("plain text output")],
    ))

    async def fake_get_hub_client():
        return client

    result = asyncio.run(tool_search.execute_whitelisted_tool(
        "opsctl",
        {},
        "user-1",
        is_configured=fake_is_configured,
        get_hub_client_fn=fake_get_hub_client,
    ))

    assert result == "plain text output"


def _public_tool_config(name: str) -> dict:
    return {
        "name": name,
        "description": f"{name} description",
        "inputs": {"arg": {"type": "string", "description": "", "required": True}},
        "public": True,
    }


def test_search_tools_survives_malformed_and_failing_readiness_checks(monkeypatch, caplog):
    """One malformed/non-dict readiness result, one non-iterable-missing result, and
    one raising readiness call must not fail the whole search: unknown statuses stay
    unannotated and configured=True, while the malformed dict is reported as missing
    generic configuration."""
    tool_configs = {
        "bad_list": _public_tool_config("bad_list"),
        "bad_dict": _public_tool_config("bad_dict"),
        "explodes": _public_tool_config("explodes"),
        "healthy": _public_tool_config("healthy"),
        "missing": _public_tool_config("missing"),
    }

    monkeypatch.setattr(tool_search.identity_mgr, "get_all_tool_configs", lambda: tool_configs)
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_mcp_configs", lambda: {})
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_tool_embeddings", lambda: {})
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_health_statuses", lambda entity_type: {})

    def fake_embed_text(text, task_type="retrieval_document"):
        return None

    monkeypatch.setattr(tool_search, "embed_text", fake_embed_text)

    async def fake_is_tool_configured(tool_name, user_id=None):
        if tool_name == "bad_list":
            return []
        if tool_name == "bad_dict":
            return {"configured": False, "missing_secrets": 5}
        if tool_name == "explodes":
            raise RuntimeError("etcd hiccup")
        if tool_name == "missing":
            return {"configured": False, "missing_secrets": ["EXAMPLE_TOKEN"], "missing_variables": ["EXAMPLE_REGION"]}
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    monkeypatch.setattr(tool_search, "is_tool_configured", fake_is_tool_configured)

    with caplog.at_level(logging.WARNING, logger="core.tool_search"):
        results = asyncio.run(tool_search.search_tools("tool", limit=0, user_id="user-1"))

    by_name = {r["name"]: r for r in results}
    assert set(by_name) == set(tool_configs)

    assert by_name["healthy"]["configured"] is True
    assert "[Missing configuration" not in by_name["healthy"]["description"]

    assert by_name["bad_list"]["configured"] is True
    assert by_name["bad_list"]["description"] == "bad_list description"

    assert by_name["explodes"]["configured"] is True
    assert by_name["explodes"]["description"] == "explodes description"

    assert by_name["bad_dict"]["configured"] is False
    assert by_name["bad_dict"]["description"].endswith(
        "[Missing configuration: required configuration. Configure at /configuration]"
    )

    assert by_name["missing"]["configured"] is False
    assert by_name["missing"]["description"].endswith(
        "[Missing configuration: EXAMPLE_TOKEN, EXAMPLE_REGION. Configure at /configuration]"
    )

    assert "bad_list" in caplog.text
    assert "explodes" in caplog.text
