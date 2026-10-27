# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""``core.tool_runtime.execute_tool`` -- container per call, the only path.

The runner client is monkeypatched (no socket, no Docker). What is pinned is the
contract between the hub/edge and the runner -- declared env keys only, the
manifest digest, deadline, target -- and that every runner failure lands on the
result shapes callers already handle.
"""

import asyncio
import json

import pytest

from core import tool_runtime
from core.execution import client as client_module
from core.execution.client import RunnerCallError, RunnerUnavailable
from core.execution.contract import ExecResult
from core.execution.spec import manifest_digest
from core.models import ToolConfig


class FakeRunnerClient:
    """Async-context-manager stand-in for ``RunnerClient``."""

    def __init__(self, *, result=None, error=None) -> None:
        self.result = result
        self.error = error
        self.requests = []
        self.entered = 0
        self.exited = 0

    async def __aenter__(self):
        self.entered += 1
        return self

    async def __aexit__(self, *exc_info):
        self.exited += 1
        return False

    async def exec(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.result


@pytest.fixture(autouse=True)
def container_env(monkeypatch):
    # An edge has no etcd; keeps the tunable lookup from probing one.
    monkeypatch.setenv("TRELLIS_EDGE_MODE", "1")
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "300")


def install_runner(monkeypatch, *, result=None, error=None) -> FakeRunnerClient:
    fake = FakeRunnerClient(result=result, error=error)
    monkeypatch.setattr(client_module, "RunnerClient", lambda *a, **k: fake)
    return fake


def make_config(**overrides) -> ToolConfig:
    data = dict(
        name="echo",
        description="d",
        runtime="python",
        entrypoint="echo.py",
        timeout_seconds=5,
        secrets={"general": ["API_KEY"]},
        variables={"user": ["SERVICE_URL"]},
    )
    data.update(overrides)
    return ToolConfig(**data)


def run_tool(tmp_path, config, *, env=None, **kwargs):
    tool_dir = tmp_path / "echo"
    tool_dir.mkdir(exist_ok=True)
    (tool_dir / config.entrypoint).write_text('print("{}")\n', encoding="utf-8")
    health = []

    def on_health(is_success, error_message=None):
        health.append((is_success, error_message))

    result = asyncio.run(
        tool_runtime.execute_tool(
            config,
            tool_dir,
            {"q": "x"},
            env={} if env is None else env,
            on_health=on_health,
            **kwargs,
        )
    )
    return result, health


# --------------------------------------------------------------------------- #
# happy path / request shape
# --------------------------------------------------------------------------- #


def test_container_call_sends_declared_env_digest_deadline_and_target(tmp_path, monkeypatch):
    config = make_config()
    fake = install_runner(
        monkeypatch, result=ExecResult(exit_code=0, stdout='{"count": 3}', stderr="")
    )

    result, health = run_tool(
        tmp_path,
        config,
        env={
            "API_KEY": "a",
            "SERVICE_URL": "https://example.test",
            "TRELLIS_USER_EMAIL": "u@example.com",
            "NOT_DECLARED": "smuggled",
            "PATH": "/usr/bin",
        },
        agent_token="t1.the.run.token",
    )

    assert result == {"count": 3}
    assert health == [(True, None)]
    assert fake.entered == 1 and fake.exited == 1

    request = fake.requests[0]
    assert request.kind == "tool"
    assert request.target == "echo"
    assert request.manifest_digest == manifest_digest(config)
    assert request.deadline_ms == 5000
    assert request.input == json.dumps({"q": "x"})
    # The body carries no identity (v0.7.1 Phase 2): the runner derives it from
    # the token's claims. TRELLIS_USER_* still reach the tool through the declared
    # env above.
    for field in ("agent", "user_id", "user_email", "run_id"):
        assert field not in request.model_dump(), field
    assert request.agent_token == "t1.the.run.token"
    # Declared keys only; the runner re-sanitizes the base environment itself.
    assert request.env == {
        "API_KEY": "a",
        "SERVICE_URL": "https://example.test",
        "TRELLIS_USER_EMAIL": "u@example.com",
    }


def test_container_call_carries_no_env_when_nothing_is_declared(tmp_path, monkeypatch):
    config = make_config(secrets=[], variables=[])
    fake = install_runner(monkeypatch, result=ExecResult(exit_code=0, stdout="{}", stderr=""))

    run_tool(tmp_path, config, env={"API_KEY": "a", "OTHER": "b"})

    assert fake.requests[0].env == {}


# --------------------------------------------------------------------------- #
# runner error mapping
# --------------------------------------------------------------------------- #


def test_capacity_exhausted_is_retried(tmp_path, monkeypatch):
    install_runner(
        monkeypatch, error=RunnerCallError("capacity_exhausted", "no slots", 429)
    )

    with pytest.raises(tool_runtime.TransientToolError) as excinfo:
        run_tool(tmp_path, make_config())

    assert "echo" in str(excinfo.value)


def test_timeout_returns_the_existing_timeout_shape(tmp_path, monkeypatch):
    install_runner(monkeypatch, error=RunnerCallError("timeout", "deadline hit", 504))

    result, health = run_tool(tmp_path, make_config())

    assert result == {"error": "Tool execution timed out after 5s."}
    assert health == [(False, "Tool execution timed out after 5s.")]


def test_runner_unavailable_reports_a_sandbox_failure(tmp_path, monkeypatch):
    install_runner(
        monkeypatch, error=RunnerUnavailable("socket /run/trellis/runner.sock missing")
    )

    result, health = run_tool(tmp_path, make_config())

    assert result["error"] == (
        "Sandbox unavailable (runner_unavailable): "
        "socket /run/trellis/runner.sock missing"
    )
    assert result["sandbox"]["backend"] == "container"
    assert result["sandbox"]["code"] == "runner_unavailable"
    assert result["sandbox"]["remediation"]
    assert health and health[0][0] is False


@pytest.mark.parametrize("code", ["runtime_missing", "image_missing", "runner_path_mismatch"])
def test_preflight_failures_fail_closed(tmp_path, monkeypatch, code):
    install_runner(monkeypatch, error=RunnerCallError(code, "broke", 503))

    result, _health = run_tool(tmp_path, make_config())

    assert result["error"] == f"Sandbox unavailable ({code}): broke"
    assert result["sandbox"]["code"] == code


@pytest.mark.parametrize("code", ["invalid_request", "unknown_target", "manifest_stale"])
def test_other_runner_errors_use_the_error_shape(tmp_path, monkeypatch, code):
    install_runner(monkeypatch, error=RunnerCallError(code, "nope", 400))

    result, _health = run_tool(tmp_path, make_config())

    assert result == {"error": f"Tool 'echo' could not run ({code}): nope"}


# --------------------------------------------------------------------------- #
# result normalisation (unchanged from the legacy path)
# --------------------------------------------------------------------------- #


def test_non_json_stdout_becomes_the_output_warning_shape(tmp_path, monkeypatch):
    install_runner(monkeypatch, result=ExecResult(exit_code=0, stdout="plain text", stderr=""))

    result, health = run_tool(tmp_path, make_config())

    assert result == {
        "output": "plain text",
        "warning": "Output was not valid JSON: plain text",
        "truncated": False,
    }
    assert health[0][0] is False


def test_transient_stderr_with_retry_enabled_raises(tmp_path, monkeypatch):
    install_runner(
        monkeypatch,
        result=ExecResult(exit_code=1, stdout="", stderr="dial tcp: connection refused\n"),
    )

    with pytest.raises(tool_runtime.TransientToolError) as excinfo:
        run_tool(tmp_path, make_config(retry_on_transient=True))

    assert "connection refused" in str(excinfo.value)


def test_transient_stderr_with_retry_disabled_returns_an_error(tmp_path, monkeypatch):
    install_runner(
        monkeypatch,
        result=ExecResult(exit_code=1, stdout="", stderr="dial tcp: connection refused\n"),
    )

    result, health = run_tool(tmp_path, make_config(retry_on_transient=False))

    assert result == {
        "error": "Tool exited with code 1: dial tcp: connection refused",
        "stderr": "dial tcp: connection refused",
    }
    assert health[0][0] is False


# --------------------------------------------------------------------------- #
# the runner is the only execution path
# --------------------------------------------------------------------------- #


def test_runner_failure_is_the_only_failure_mode(tmp_path, monkeypatch):
    """There is no local fallback: a dead runner is reported, nothing is forked.

    The legacy in-process backends are gone, so a runner that cannot start the
    container must surface as a sandbox failure -- never as a tool that quietly ran
    on the hub/edge host instead.
    """
    install_runner(monkeypatch, error=RunnerUnavailable("socket /run/trellis/runner.sock missing"))

    spawned = []

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        spawned.append(cmd)
        raise AssertionError("execute_tool must not spawn the tool itself")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result, health = run_tool(tmp_path, make_config())

    assert spawned == []
    assert result["sandbox"]["backend"] == "container"
    assert result["sandbox"]["code"] == "runner_unavailable"
    assert "Sandbox unavailable (runner_unavailable)" in result["error"]
    assert health and health[0][0] is False


def test_no_host_side_sandbox_exists_to_fall_back_to():
    """Structural guard: the in-process backends must be gone, not just unreachable.

    Monkeypatching ``asyncio.create_subprocess_exec`` only proves one code path does
    not spawn; a re-introduced bwrap/Landlock fallback could fork through another
    entry point (``os.posix_spawn``, a helper binary, a re-imported module). Pin the
    structure instead: ``core.tool_runtime`` has no sandbox or subprocess machinery,
    and ``core.sandbox`` no longer imports.
    """
    import importlib

    assert importlib.import_module("core.tool_runtime") is tool_runtime
    for attribute in ("subprocess", "sandbox"):
        assert not hasattr(tool_runtime, attribute), (
            f"core.tool_runtime.{attribute} is back: a host-side execution path "
            "must not exist -- every tool call goes to the runner"
        )

    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("core.sandbox")
