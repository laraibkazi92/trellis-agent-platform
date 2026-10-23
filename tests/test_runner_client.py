# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""RunnerClient error mapping over ``httpx.MockTransport``.

The hub branches on these codes (retry vs report vs fail closed), so the mapping
from HTTP status to ``RunnerCallError.code``/``retryable`` is a contract, not an
implementation detail. No socket, no runner process: the transport is faked.
"""

import asyncio
import json

import httpx
import pytest

from core.execution.client import RunnerCallError, RunnerClient, RunnerUnavailable
from core.execution.contract import ExecRequest, ExecResult


def make_request(**overrides) -> ExecRequest:
    body = dict(
        kind="tool",
        target="echo",
        manifest_digest="0" * 64,
        env={"ECHO_TOKEN": "s3cret"},
        input='{"text":"hi"}',
        deadline_ms=5000,
    )
    body.update(overrides)
    return ExecRequest(**body)


def exec_with(handler, *, request=None, token=None):
    transport = httpx.MockTransport(handler)

    async def scenario():
        async with RunnerClient(transport=transport, token=token) as client:
            return await client.exec(request or make_request())

    return asyncio.run(scenario())


def test_exec_parses_a_200_result():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v1/exec"
        body = json.loads(request.content)
        assert body["target"] == "echo"
        assert body["manifest_digest"] == "0" * 64
        return httpx.Response(
            200,
            json={
                "exit_code": 0,
                "stdout": '{"ok": true}',
                "stderr": "",
                "stdout_truncated": True,
                "stderr_truncated": False,
                "duration_ms": 42,
                "container_id": "abc123",
            },
        )

    result = exec_with(handler)

    assert isinstance(result, ExecResult)
    assert result.exit_code == 0
    assert result.stdout == '{"ok": true}'
    assert result.stderr == ""
    assert result.stdout_truncated is True
    assert result.duration_ms == 42
    assert result.container_id == "abc123"


@pytest.mark.parametrize(
    "status,code",
    [
        (400, "invalid_request"),
        (404, "unknown_target"),
        (409, "manifest_stale"),
        (429, "capacity_exhausted"),
        (503, "runtime_missing"),
        (504, "timeout"),
    ],
)
def test_error_status_maps_to_code(status, code):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            json={"detail": {"code": code, "message": "refused", "retryable": status == 429}},
        )

    with pytest.raises(RunnerCallError) as excinfo:
        exec_with(handler)

    error = excinfo.value
    assert error.code == code
    assert error.message == "refused"
    assert error.status == status
    # Capacity is the only retryable outcome: stamina retries it in the hub.
    assert error.retryable is (status == 429)
    assert f"{code}: refused" in str(error)


def test_status_derived_code_when_the_body_has_no_structured_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"detail": "image is missing"})

    with pytest.raises(RunnerCallError) as excinfo:
        exec_with(handler)

    assert excinfo.value.code == "runtime_missing"
    assert excinfo.value.status == 503
    assert excinfo.value.message


def test_plain_text_error_still_maps_by_status():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400, content=b"<html>bad request</html>", headers={"content-type": "text/html"}
        )

    with pytest.raises(RunnerCallError) as excinfo:
        exec_with(handler)

    assert excinfo.value.code == "invalid_request"
    assert "bad request" in excinfo.value.message
    assert excinfo.value.retryable is False


def test_unclassified_status_falls_back_to_internal():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, content=b"upstream died")

    with pytest.raises(RunnerCallError) as excinfo:
        exec_with(handler)

    assert excinfo.value.code == "internal"
    assert excinfo.value.status == 502
    assert excinfo.value.retryable is False


@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectError("connection refused"),
        httpx.ReadError("socket closed"),
    ],
)
def test_transport_failure_is_runner_unavailable(error):
    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    with pytest.raises(RunnerUnavailable) as excinfo:
        exec_with(handler)

    assert excinfo.value.code == "runner_unavailable"
    assert "unreachable" in str(excinfo.value)


def test_read_timeout_is_a_timeout_call_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    with pytest.raises(RunnerCallError) as excinfo:
        exec_with(handler)

    assert excinfo.value.code == "timeout"
    assert excinfo.value.retryable is False


def test_bearer_token_is_sent(monkeypatch):
    monkeypatch.setenv("RUNNER_TOKEN", "tok-123")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"exit_code": 0, "stdout": "{}", "stderr": ""})

    exec_with(handler)

    assert seen["authorization"] == "Bearer tok-123"


def test_no_bearer_without_a_token(monkeypatch):
    monkeypatch.delenv("RUNNER_TOKEN", raising=False)
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"exit_code": 0, "stdout": "{}", "stderr": ""})

    exec_with(handler)

    assert seen["authorization"] is None
