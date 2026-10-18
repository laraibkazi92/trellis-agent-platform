# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Gateway MCP error sanitization (Workstream A hardening cycle).

The externally exposed /mcp surface must never interpolate raw exception text
(Host URL/port, etcd endpoints, upstream response bodies) into strings returned
to MCP clients. Each failure path returns a stable generic message and logs the
raw detail with ``logger.error(..., exc_info=True)`` instead.
"""
import asyncio
import logging
from types import SimpleNamespace

import httpx
import pytest

from core import gateway
from core.auth import user_id_var


class FakeContext:
    """Stand-in for fastmcp.Context — only report_progress is exercised."""

    async def report_progress(self, current=None, total=None, message=None):
        pass


def _patch_external_agent(monkeypatch, configured=None, configured_error=None):
    monkeypatch.setattr(
        gateway.identity_mgr, "get_agent_config", lambda name: {"name": name, "external": True}
    )

    async def fake_is_agent_configured(agent_name, user_id):
        if configured_error is not None:
            raise configured_error
        return configured

    monkeypatch.setattr(gateway, "is_agent_configured", fake_is_agent_configured)


def _patch_http_client(monkeypatch, http_client):
    monkeypatch.setattr(
        gateway,
        "app",
        SimpleNamespace(state=SimpleNamespace(http_client=http_client)),
        raising=False,
    )


class RaisingGetClient:
    async def get(self, url, timeout=None):
        raise httpx.ConnectError("Connect call failed ('etcd-cluster.internal', 2379)")


def test_check_host_liveness_exception_returns_generic_and_logs_detail(monkeypatch, caplog):
    _patch_http_client(monkeypatch, RaisingGetClient())

    with caplog.at_level(logging.ERROR, logger="core.gateway"):
        result = asyncio.run(gateway._check_host_liveness_error())

    assert result == {
        "name": "Error",
        "description": "Host API temporarily unreachable. Please try again later.",
    }
    assert "etcd-cluster.internal" not in result["description"]
    assert "etcd-cluster.internal" in caplog.text


def test_use_agent_config_check_exception_returns_generic_and_logs_detail(monkeypatch, caplog):
    _patch_external_agent(
        monkeypatch,
        configured_error=RuntimeError("etcd3 grpc connect 10.0.0.5:2379 failed"),
    )
    user_id_var.set("user-1")

    with caplog.at_level(logging.ERROR, logger="core.gateway"):
        result = asyncio.run(gateway.use_agent(FakeContext(), "general-agent", "hello"))

    assert result == "SYSTEM: Error checking agent configuration for 'general-agent'. Please try again later."
    assert "10.0.0.5" not in result
    assert "10.0.0.5" in caplog.text


class FakeStreamResponse:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *a):
        return False


class FakeStreamingClient:
    def __init__(self, response):
        self._response = response

    def stream(self, method, url, **kwargs):
        return FakeStreamResponse(self._response)


class RaisingStreamClient:
    def stream(self, method, url, **kwargs):
        raise httpx.ConnectError("http://host-internal:8000")


def _internal_error_response(status_code, body):
    request = httpx.Request("POST", "http://host-internal:8000/v1/chat/completions")
    return httpx.Response(status_code, text=body, request=request)


class _FakeAsyncByteStream(httpx.AsyncByteStream):
    """A real streaming body. An httpx.Response built around this buffers nothing, so
    .text raises ResponseNotRead until the stream is read -- exactly what the host's
    streaming /v1/chat/completions response does on a non-2xx status."""

    def __init__(self, body: bytes):
        self._body = body

    async def __aiter__(self):
        yield self._body

    async def aclose(self):
        pass


class _FailingAsyncByteStream(httpx.AsyncByteStream):
    """A body that fails the moment it is read -- e.g. the host resetting the connection
    while flushing an error response."""

    async def __aiter__(self):
        raise httpx.ReadError("connection reset")
        yield b""  # pragma: no cover -- unreachable; makes __aiter__ an async generator

    async def aclose(self):
        pass


def _internal_streaming_error_response(status_code, body):
    request = httpx.Request("POST", "http://host-internal:8000/v1/chat/completions")
    return httpx.Response(status_code, stream=_FakeAsyncByteStream(body), request=request)


def _internal_unreadable_error_response(status_code):
    request = httpx.Request("POST", "http://host-internal:8000/v1/chat/completions")
    return httpx.Response(status_code, stream=_FailingAsyncByteStream(), request=request)


def test_use_agent_http_status_error_returns_generic_and_logs_body(monkeypatch, caplog):
    _patch_external_agent(
        monkeypatch,
        configured={"configured": True, "missing_secrets": [], "missing_variables": []},
    )
    _patch_http_client(
        monkeypatch,
        FakeStreamingClient(_internal_error_response(500, "traceback: internal detail")),
    )
    user_id_var.set("user-1")

    with caplog.at_level(logging.ERROR, logger="core.gateway"):
        result = asyncio.run(gateway.use_agent(FakeContext(), "general-agent", "hello"))

    assert result == "SYSTEM: Error calling agent 'general-agent'. Please try again later."
    assert "traceback: internal detail" not in result
    assert "traceback: internal detail" in caplog.text


def test_use_agent_streaming_error_body_is_buffered_before_logging(monkeypatch, caplog):
    """use_agent streams from the host, so a non-2xx response arrives with its body
    unread: the old handler's ``e.response.text`` raised httpx.ResponseNotRead, which
    escaped as "Attempted to access streaming response content, without having called
    read()" and hid the real status. The body must be buffered while the stream is
    still open, so the handler can log it as intended."""
    _patch_external_agent(
        monkeypatch,
        configured={"configured": True, "missing_secrets": [], "missing_variables": []},
    )
    response = _internal_streaming_error_response(500, b"traceback: internal detail")

    # Precondition: genuinely unread, so the un-fixed handler would have raised here.
    with pytest.raises(httpx.ResponseNotRead):
        response.text

    _patch_http_client(monkeypatch, FakeStreamingClient(response))
    user_id_var.set("user-1")

    with caplog.at_level(logging.ERROR, logger="core.gateway"):
        result = asyncio.run(gateway.use_agent(FakeContext(), "general-agent", "hello"))

    assert result == "SYSTEM: Error calling agent 'general-agent'. Please try again later."
    assert "traceback: internal detail" not in result
    assert "traceback: internal detail" in caplog.text


def test_use_agent_503_survives_an_unreadable_error_body(monkeypatch):
    """Buffering the error body is only for logging. If the read itself fails, the
    status raise_for_status() already produced must still drive the mapping -- here the
    503 branch -- instead of falling through to the generic connection-failure message."""
    _patch_external_agent(
        monkeypatch,
        configured={"configured": True, "missing_secrets": [], "missing_variables": []},
    )
    _patch_http_client(
        monkeypatch,
        FakeStreamingClient(_internal_unreadable_error_response(503)),
    )
    user_id_var.set("user-1")

    result = asyncio.run(gateway.use_agent(FakeContext(), "general-agent", "hello"))

    assert result == (
        "SYSTEM: The agent 'general-agent' is currently offline due to technical "
        "failures and cannot process requests."
    )


def test_use_agent_connect_failure_returns_generic_and_logs_detail(monkeypatch, caplog):
    _patch_external_agent(
        monkeypatch,
        configured={"configured": True, "missing_secrets": [], "missing_variables": []},
    )
    _patch_http_client(monkeypatch, RaisingStreamClient())
    user_id_var.set("user-1")

    with caplog.at_level(logging.ERROR, logger="core.gateway"):
        result = asyncio.run(gateway.use_agent(FakeContext(), "general-agent", "hello"))

    assert result == "SYSTEM: Failed to connect to agent 'general-agent'. Please try again later."
    assert "host-internal" not in result
    assert "host-internal" in caplog.text
