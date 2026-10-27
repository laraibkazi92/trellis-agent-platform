# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""``RunnerConsoleBackend``: `execute` becomes a runner-owned container call.

The runner client is faked in memory (no socket, no container), so these tests pin
the request the agent's shell becomes, the mapping back onto the local backend's
``ExecuteResponse`` shape, and that a runner outage is an error *result* rather than
an exception inside the agent turn.
"""

import asyncio

import pytest
from pydantic_ai_backends.backends.local import DEFAULT_EXECUTE_TIMEOUT

from core.console_backend import RunnerConsoleBackend, _run_sync
from core.execution.client import RunnerCallError, RunnerUnavailable
from core.execution.contract import ExecResult

MAX_OUTPUT = 100_000
CONSOLE_SECRET = "console-runner-unit-secret-0123456789abcdef"


@pytest.fixture(autouse=True)
def _console_authorized(monkeypatch):
    """`execute` asks the evaluator before it asks the runner.

    These tests pin the request shape, so the run gets a valid token whose agent's
    allowlist carries the console tool -- the pre-runner gate itself is covered in
    tests/test_enforcement_matrix.py.
    """
    from core import agent_token, tool_access

    class _NoPolicy:
        def put(self, key, value):
            raise AssertionError(f"no write expected: {key}")

        def get(self, key, **_kwargs):
            return None, None

    monkeypatch.setenv("AGENT_TOKEN_SECRET", CONSOLE_SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    monkeypatch.setattr(tool_access, "_client", lambda: _NoPolicy())
    tool_access.reset_snapshot()
    monkeypatch.setattr(
        agent_token,
        "current_token",
        lambda: agent_token.mint("console-agent", user_id="user-1"),
    )
    from core import auth

    auth.agent_token_var.set(agent_token.mint("console-agent", user_id="user-1"))
    monkeypatch.setattr(
        auth,
        "get_identity_manager",
        lambda: __import__("types").SimpleNamespace(
            get_agent_config=lambda name: {"allowed_tools": ["execute"]}
        ),
    )
    yield
    auth.agent_token_var.set(None)


class FakeRunnerClient:
    """The two runner methods the backend uses, recorded in memory."""

    def __init__(self, result: ExecResult | None = None, error: BaseException | None = None):
        self.result = result or ExecResult(exit_code=0, stdout="", stderr="")
        self.error = error
        self.requests = []
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        self.closed = True
        return False

    async def exec(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.result


def _backend(client: FakeRunnerClient, *, enable_execute: bool = True) -> RunnerConsoleBackend:
    return RunnerConsoleBackend(
        root_dir="/tmp/opencode/console-runner-test",
        enable_execute=enable_execute,
        client_factory=lambda: client,
    )


def test_execute_sends_a_console_request():
    client = FakeRunnerClient(ExecResult(exit_code=0, stdout="hi\n", stderr=""))
    backend = _backend(client)

    backend.execute("echo hi", timeout=5)

    assert len(client.requests) == 1
    request = client.requests[0]
    assert request.kind == "console"
    assert request.target == "console"
    assert request.command == "echo hi"
    assert request.env == {}
    assert request.deadline_ms == 5_000


def test_console_request_carries_no_identity(monkeypatch):
    """Identity is the token's, not the body's (v0.7.1 Phase 2).

    The user id, email and run id that used to ride the request now come from the
    verified claims, so the console container is attributed from the token alone.
    """
    client = FakeRunnerClient(ExecResult(exit_code=0, stdout="", stderr=""))
    backend = _backend(client)

    backend.execute("echo hi", timeout=5)

    request = client.requests[0]
    for field in ("agent", "user_id", "user_email", "run_id"):
        assert field not in request.model_dump(), field
    # The run's token is the only identity carrier, and it is refreshed per call.
    assert "agent_token" in request.model_dump()


def test_execute_defaults_the_deadline_to_the_library_timeout():
    client = FakeRunnerClient()
    backend = _backend(client)

    backend.execute("echo hi")

    assert client.requests[0].deadline_ms == DEFAULT_EXECUTE_TIMEOUT * 1000


def test_execute_maps_stdout_stderr_and_exit_code():
    client = FakeRunnerClient(
        ExecResult(exit_code=3, stdout="out\n", stderr="warn\n")
    )
    backend = _backend(client)

    response = backend.execute("false")

    # The local backend concatenates stdout+stderr: keep the exact same shape.
    assert response.output == "out\nwarn\n"
    assert response.exit_code == 3
    assert response.truncated is False


def test_a_runner_failure_becomes_an_error_response():
    client = FakeRunnerClient(error=RunnerCallError("session_not_found", "gone"))
    backend = _backend(client)

    response = asyncio.run(backend.async_execute("echo hi"))

    assert response.output.startswith("Error: ")
    assert "console command could not run" in response.output
    assert response.exit_code == 1
    assert response.truncated is False


def test_an_unreachable_runner_becomes_an_error_response():
    client = FakeRunnerClient(error=RunnerUnavailable("runner is unreachable"))
    backend = _backend(client)

    response = backend.execute("echo hi")

    assert response.output.startswith("Error: ")
    assert response.exit_code == 1


def test_a_denial_never_reaches_the_runner():
    client = FakeRunnerClient()
    backend = _backend(client)
    backend._execute_denial = lambda command: "Permission denied for execute on 'rm -rf /'"

    response = backend.execute("rm -rf /")

    assert response == type(response)(
        output="Error: Permission denied for execute on 'rm -rf /'",
        exit_code=1,
        truncated=False,
    )
    assert client.requests == []


def test_a_run_without_the_execute_grant_is_denied_and_never_reaches_the_runner(monkeypatch):
    """The console gate is deny-by-default: no `execute` in the record, no container."""
    import types

    from core import auth, tool_access

    client = FakeRunnerClient()
    backend = _backend(client)
    tool_access.reset_snapshot()
    monkeypatch.setattr(
        auth,
        "get_identity_manager",
        lambda: types.SimpleNamespace(
            get_agent_config=lambda name: {"allowed_tools": ["read_file"]}
        ),
    )

    response = backend.execute("echo hi", timeout=5)

    assert "access_denied" in response.output
    assert "'execute'" in response.output
    assert response.exit_code == 1
    assert client.requests == []


def test_a_registry_failure_during_the_gate_returns_an_error_response(monkeypatch):
    """A failed access check must not raise out of the agent's shell tool."""
    import types

    from core import auth, tool_access

    client = FakeRunnerClient()
    backend = _backend(client)
    tool_access.reset_snapshot()

    def boom(name):
        raise RuntimeError("etcd unavailable")

    monkeypatch.setattr(
        auth,
        "get_identity_manager",
        lambda: types.SimpleNamespace(get_agent_config=boom),
    )

    response = backend.execute("echo hi", timeout=5)

    assert response.output.startswith("Error: access check failed")
    assert "etcd unavailable" in response.output
    assert response.exit_code == 1
    assert client.requests == []


def test_execute_from_inside_a_running_loop_uses_a_fresh_thread():
    """The sync path may be called on the loop thread; nesting ``asyncio.run`` fails."""
    client = FakeRunnerClient(ExecResult(exit_code=0, stdout="ok", stderr=""))
    backend = _backend(client)

    async def scenario():
        return backend.execute("echo ok", timeout=5)

    response = asyncio.run(scenario())

    assert response.output == "ok"
    assert response.exit_code == 0
    assert len(client.requests) == 1


def test_run_sync_works_without_a_running_loop():
    result = _run_sync(asyncio.sleep(0, result="ok"))

    assert result == "ok"
