# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for core.hub.run_tool.

Pins the contracts the hub still owns now that every tool call is a runner
container (``core.tool_runtime``):
- stamina re-invocation never mutates the caller's arguments, so `__user_id`
  (and therefore scoped secret injection / execution tokens) survives retries.
- the runner is the only execution path: a failure there is a sandbox failure,
  never a local subprocess.
- per-tool `timeout_seconds` becomes the runner deadline, and a runner timeout is
  reported once, not retried.
- transient-stderr retries are gated by `retry_on_transient`.
- tool usage is recorded exactly once per invocation, not once per stamina
  retry attempt.
- the tool handler never logs raw kwargs (`RECEIVED KWARGS` is deleted).
- oversized results are bounded before they reach the model.
- background tasks spawned for usage recording are drained on shutdown.
"""

import asyncio
import json

import pytest

from core import agent_token, hub
from core.execution import client as client_module
from core.execution.client import RunnerCallError, RunnerUnavailable
from core.execution.contract import ExecResult
from core.models import ToolConfig

SECRET = "hub-tool-execution-unit-secret-0123456789ab"


@pytest.fixture(autouse=True)
def _reset_registered_tools():
    """register_tools() reconciles against process-global state; reset it per test."""
    hub._registered_tools.clear()
    hub._unreadable_tool_names.clear()
    yield
    hub._registered_tools.clear()
    hub._unreadable_tool_names.clear()


@pytest.fixture(autouse=True)
def _hermetic_tool_access(monkeypatch):
    """Keep the evaluator hermetic and in its rollout window.

    Every hub call asks ``core.tool_access`` once. These tests are about execution,
    not authorization, so the policy registry is faked (no document ⇒ no group rules,
    zero etcd reads) and ``ENFORCE_AGENT_TOKENS`` is ``log``: a call without a token is
    logged and runs, exactly like the pre-token posture these cases describe.
    """
    from core import tool_access

    class _NoPolicy:
        """An empty registry: no policy document, so the allowlist alone decides."""

        def put(self, key, value):
            raise AssertionError(f"no write expected: {key}")

        def get(self, key, **_kwargs):
            return None, None

    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    monkeypatch.setattr(tool_access, "_client", lambda: _NoPolicy())
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()
    yield
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()


ENTRYPOINT_SOURCE = "import json, sys\nprint(json.dumps({}))\n"


class FakeRunnerClient:
    """Async-context-manager stand-in for ``RunnerClient``: no socket, no Docker.

    ``outcomes`` is consumed in call order; an ``Exception`` instance is raised, an
    ``ExecResult`` is returned, and a call past the end fails the test.
    """

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
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
        if not self.outcomes:
            raise AssertionError("unexpected extra runner call")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class BlockingRunnerClient(FakeRunnerClient):
    """``exec`` parks until released, so cancellation can be exercised."""

    def __init__(self):
        super().__init__([])
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def exec(self, request):
        self.requests.append(request)
        self.started.set()
        await self.release.wait()
        return ExecResult(exit_code=0, stdout="{}", stderr="")


class FakeIdentityManager:
    """Records identity lookups so retry attempts can be asserted on."""

    def __init__(self, resolved_config=None):
        self.resolved_config_calls = []
        self.execution_token_calls = []
        self.get_config_calls = []
        self.get_user_calls = []
        self.get_agent_config_calls = []
        self.record_tool_usage_calls = []
        self._resolved_config = {"API_KEY": "v"} if resolved_config is None else resolved_config

    def get_resolved_config(self, identity, category, keys=None):
        self.resolved_config_calls.append({"identity": identity, "category": category, "keys": keys})
        return self._resolved_config

    def generate_execution_token(self, identity):
        self.execution_token_calls.append(identity)
        return "tok"

    def get_config(self, key, default=None):
        self.get_config_calls.append(key)
        return "http://host.local"

    def get_user(self, identity):
        self.get_user_calls.append(identity)
        return {"email": "u@example.com"}

    def get_agent_config(self, name):
        # Hermetic: the agent-token gate resolves the agent's allowlist off-loop.
        self.get_agent_config_calls.append(name)
        return {"name": name, "allowed_tools": ["tmpltool"]}

    def record_tool_usage(self, user_id, tool_name):
        self.record_tool_usage_calls.append((user_id, tool_name))


class FakeMCP:
    """Stand-in for FastMCP that captures registered tool handlers."""

    def __init__(self):
        self.handlers = {}

    def tool(self, name=None, description=None):
        def decorator(fn):
            self.handlers[name] = fn
            return fn

        return decorator


def make_config(**kw):
    return ToolConfig(name="tmpltool", description="d", runtime="python", entrypoint="main.py", **kw)


def make_tool_dir(tmp_path):
    (tmp_path / "main.py").write_text(ENTRYPOINT_SOURCE)
    return tmp_path


def install_fake_runner(monkeypatch, *outcomes):
    """Point ``core.tool_runtime`` at a scripted runner client."""
    fake = FakeRunnerClient(outcomes)
    monkeypatch.setattr(client_module, "RunnerClient", lambda *a, **k: fake)
    return fake


def install_fake_identity(monkeypatch, resolved_config=None):
    fake = FakeIdentityManager(resolved_config=resolved_config)
    for method in (
        "get_resolved_config",
        "generate_execution_token",
        "get_config",
        "get_user",
        "get_agent_config",
        "record_tool_usage",
    ):
        monkeypatch.setattr(hub.identity_mgr, method, getattr(fake, method))
    return fake


def install_fake_health(monkeypatch):
    events = []

    def fake_record_event(entity_type, name, is_success, error_details=None):
        events.append({"entity_type": entity_type, "name": name, "is_success": is_success, "error_details": error_details})
        return {}

    monkeypatch.setattr(hub.health_monitor, "record_event", fake_record_event)
    return events


async def _run_tool_scenario(config, tool_dir, arguments):
    """Await run_tool, then drain fire-and-forget background tasks deterministically."""
    result = await hub.run_tool(config, tool_dir, arguments)
    await asyncio.gather(*hub._background_tasks, return_exceptions=True)
    return result


def ok_result(**kwargs):
    return ExecResult(exit_code=0, stdout='{"ok": true}', stderr="", **kwargs)


def transient_result():
    return ExecResult(exit_code=1, stdout="", stderr="connection refused")


# --------------------------------------------------------------------------- #
# retries and identity
# --------------------------------------------------------------------------- #


def test_run_tool_preserves_user_id_across_retries(monkeypatch, tmp_path):
    monkeypatch.setenv("DEV_MODE", "false")
    fake_identity = install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    runner = install_fake_runner(monkeypatch, transient_result(), ok_result())

    result = asyncio.run(
        _run_tool_scenario(make_config(secrets=["API_KEY"]), make_tool_dir(tmp_path), {"__user_id": "user-1"})
    )

    assert result == {"ok": True}
    assert len(runner.requests) == 2
    # v0.6 removed the FRAMEWORK_* injection: a tool never receives a
    # framework loopback credential, so no execution token is minted.
    assert fake_identity.execution_token_calls == []
    resolved_user_ids = [call["identity"] for call in fake_identity.resolved_config_calls]
    assert resolved_user_ids.count("user-1") >= 2
    # No user-record read for identity: without a token there is no email to inject.
    assert fake_identity.get_user_calls == []
    assert ("user-1", "tmpltool") in fake_identity.record_tool_usage_calls


def test_run_tool_records_usage_once_across_retries(monkeypatch, tmp_path):
    fake_identity = install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    runner = install_fake_runner(monkeypatch, transient_result(), ok_result())

    result = asyncio.run(
        _run_tool_scenario(make_config(secrets=["API_KEY"]), make_tool_dir(tmp_path), {"__user_id": "user-1"})
    )

    assert result == {"ok": True}
    assert len(runner.requests) == 2
    assert fake_identity.record_tool_usage_calls == [("user-1", "tmpltool")]


def test_run_tool_does_not_mutate_caller_arguments(monkeypatch, tmp_path):
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    runner = install_fake_runner(monkeypatch, ok_result())

    arguments = {"__user_id": "user-1", "q": "x"}
    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), arguments))

    assert result == {"ok": True}
    assert arguments == {"__user_id": "user-1", "q": "x"}
    # The framework's own fields are stripped before the payload crosses the socket.
    assert json.loads(runner.requests[0].input) == {"q": "x"}


def test_tool_env_identity_comes_from_the_verified_token(monkeypatch, tmp_path):
    """A verified token is the only identity authority: the body cannot override it."""
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    fake_identity = install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    runner = install_fake_runner(monkeypatch, ok_result())
    token = agent_token.mint(
        "agent-a", user_id="alice", user_email="alice@corp.example", groups=["ops"]
    )

    result = asyncio.run(
        _run_tool_scenario(
            make_config(secrets=["API_KEY"]),
            make_tool_dir(tmp_path),
            {"__user_id": "mallory", "__agent_token": token},
        )
    )

    assert result == {"ok": True}
    env = runner.requests[0].env
    assert env["TRELLIS_USER_ID"] == "alice"
    assert env["TRELLIS_USER_EMAIL"] == "alice@corp.example"
    # ... and the forged body user never reaches secret resolution, usage or a
    # per-call record read (the claims already carry the identity).
    assert {call["identity"] for call in fake_identity.resolved_config_calls} == {"alice"}
    assert fake_identity.get_user_calls == []
    assert fake_identity.record_tool_usage_calls == [("alice", "tmpltool")]


def test_tool_env_ignores_the_body_user_when_a_token_does_not_verify(monkeypatch, tmp_path):
    """A presented-but-invalid token drops the caller's identity entirely."""
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    fake_identity = install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    runner = install_fake_runner(monkeypatch, ok_result())

    result = asyncio.run(
        _run_tool_scenario(
            make_config(secrets=["API_KEY"]),
            make_tool_dir(tmp_path),
            {"__user_id": "mallory", "__agent_token": "t1.forged.signature"},
        )
    )

    assert result == {"ok": True}
    # No identity -> no secret injection scoped to a user, no TRELLIS_USER_* env.
    assert fake_identity.resolved_config_calls == []
    assert "TRELLIS_USER_ID" not in runner.requests[0].env
    assert "TRELLIS_USER_EMAIL" not in runner.requests[0].env
    assert fake_identity.record_tool_usage_calls == []


def test_off_mode_falls_back_to_the_body_user_id(monkeypatch, tmp_path):
    """The documented dev/rollout fallback: nothing is verified in ``off``."""
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "off")
    monkeypatch.setenv("DEV_MODE", "true")
    fake_identity = install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    runner = install_fake_runner(monkeypatch, ok_result())

    asyncio.run(
        _run_tool_scenario(
            make_config(secrets=["API_KEY"]), make_tool_dir(tmp_path), {"__user_id": "user-1"}
        )
    )

    env = runner.requests[0].env
    assert env["TRELLIS_USER_ID"] == "user-1"
    # Identity is the token's alone, and this run has none: no email is invented from
    # the user record (v0.7.1 Phase 4 dropped that fallback).
    assert "TRELLIS_USER_EMAIL" not in env


def test_run_tool_args_carry_no_identity_fields_across_retries(monkeypatch, tmp_path):
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    runner = install_fake_runner(monkeypatch, transient_result(), ok_result())

    result = asyncio.run(
        _run_tool_scenario(make_config(secrets=["API_KEY"]), make_tool_dir(tmp_path), {"__user_id": "svc_agent_triage"})
    )

    assert result == {"ok": True}
    assert len(runner.requests) == 2
    for request in runner.requests:
        payload = json.loads(request.input)
        # v0.6: agent identity travels in the verified token, never as a stdin field.
        assert "__agent_name" not in payload
        assert "__user_id" not in payload
        # v0.7.1: the runner request body carries no identity at all. The runner
        # derives user/email/groups/agent/run from the token's claims.
        dumped = request.model_dump()
        for field in ("agent", "user_id", "user_email", "run_id"):
            assert field not in dumped, field
    # A background run's own identity still reaches the tool's environment.
    assert runner.requests[0].env["TRELLIS_USER_ID"] == "svc_agent_triage"


def test_run_tool_skips_retry_when_retry_on_transient_false(monkeypatch, tmp_path):
    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)
    runner = install_fake_runner(monkeypatch, transient_result())

    result = asyncio.run(_run_tool_scenario(make_config(retry_on_transient=False), make_tool_dir(tmp_path), {}))

    assert "connection refused" in result["error"]
    assert len(runner.requests) == 1
    assert any(event["is_success"] is False for event in health_events)


def test_run_tool_handler_reports_retry_exhaustion_and_records_usage_once(monkeypatch, tmp_path):
    config = make_config()
    tool_dir = make_tool_dir(tmp_path)
    fake_identity = install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: {"tmpltool": (config, tool_dir)})
    monkeypatch.setattr(hub, "mcp", fake_mcp)
    runner = install_fake_runner(monkeypatch, transient_result(), transient_result(), transient_result())

    hub.register_tools()
    handler = fake_mcp.handlers["tmpltool"]

    async def _scenario():
        result = await handler(q="x", __user_id="user-1")
        await asyncio.gather(*hub._background_tasks, return_exceptions=True)
        return result

    result = asyncio.run(_scenario())

    assert result["error"].startswith("Tool failed after retries:")
    assert len(runner.requests) == 3
    assert fake_identity.record_tool_usage_calls == [("user-1", "tmpltool")]


# --------------------------------------------------------------------------- #
# the runner is the only execution path
# --------------------------------------------------------------------------- #


def test_run_tool_reports_runner_unavailable_as_a_sandbox_failure(monkeypatch, tmp_path):
    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)
    install_fake_runner(monkeypatch, RunnerUnavailable("socket /run/trellis/runner.sock missing"))

    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert result["error"].startswith("Sandbox unavailable (runner_unavailable)")
    assert result["sandbox"] == {
        "backend": "container",
        "code": "runner_unavailable",
        "remediation": "Check that the runner service is up and its socket is mounted.",
    }
    assert any(event["is_success"] is False for event in health_events)


def test_run_tool_never_falls_back_to_a_local_subprocess(monkeypatch, tmp_path):
    """A dead runner is a failure, not a reason to fork the tool on the hub host."""
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    install_fake_runner(monkeypatch, RunnerUnavailable("no socket"))

    spawned = []

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        spawned.append(cmd)
        raise AssertionError("the hub must not spawn tool processes")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert "Sandbox unavailable" in result["error"]
    assert spawned == []


def test_run_tool_timeout_is_reported_once_and_not_retried(monkeypatch, tmp_path):
    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)
    runner = install_fake_runner(monkeypatch, RunnerCallError("timeout", "deadline hit", 504))

    result = asyncio.run(
        _run_tool_scenario(make_config(timeout_seconds=5), make_tool_dir(tmp_path), {})
    )

    assert result == {"error": "Tool execution timed out after 5s."}
    assert len(runner.requests) == 1
    failed = [event for event in health_events if event["is_success"] is False]
    assert len(failed) == 1
    assert failed[0]["entity_type"] == "tool"
    assert failed[0]["name"] == "tmpltool"
    assert "timed out" in failed[0]["error_details"]


def test_run_tool_per_tool_timeout_becomes_the_runner_deadline(monkeypatch, tmp_path):
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "30")
    runner = install_fake_runner(monkeypatch, ok_result())

    asyncio.run(_run_tool_scenario(make_config(timeout_seconds=1), make_tool_dir(tmp_path), {}))

    assert runner.requests[0].deadline_ms == 1000


def test_run_tool_cancellation_does_not_record_a_health_event(monkeypatch, tmp_path):
    """Cancelling the handler (MCP disconnect / shutdown) is not a tool failure."""
    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)
    runner = BlockingRunnerClient()
    monkeypatch.setattr(client_module, "RunnerClient", lambda *a, **k: runner)

    async def _scenario():
        task = asyncio.create_task(hub.run_tool(make_config(), make_tool_dir(tmp_path), {}))
        try:
            await asyncio.wait_for(runner.started.wait(), timeout=2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            runner.release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await asyncio.gather(*hub._background_tasks, return_exceptions=True)

    asyncio.run(_scenario())

    assert len(runner.requests) == 1
    assert health_events == []


# --------------------------------------------------------------------------- #
# result normalisation
# --------------------------------------------------------------------------- #


def test_run_tool_transient_stderr_still_retries(monkeypatch, tmp_path):
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    runner = install_fake_runner(monkeypatch, transient_result(), ok_result())

    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert result == {"ok": True}
    assert len(runner.requests) == 2


def test_run_tool_logs_truncation_warning(monkeypatch, tmp_path, caplog):
    """Oversized outputs are summarised, and the warning goes through the logger."""
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    oversized = json.dumps({"data": "x" * 200_000})
    install_fake_runner(monkeypatch, ExecResult(exit_code=0, stdout=oversized, stderr=""))

    config = make_config()
    with caplog.at_level("WARNING", logger="core.tool_runtime"):
        result = asyncio.run(_run_tool_scenario(config, make_tool_dir(tmp_path), {}))

    assert "error" in result
    assert "safety" in result["error"].lower()
    assert "exceeded safety limit" in caplog.text
    assert config.name in caplog.text


def test_run_tool_stderr_log_bounded_but_result_full(monkeypatch, tmp_path, caplog):
    """The stderr warning is truncated for the log line, while the error dict
    returned to the caller preserves the full stderr payload."""
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    install_fake_runner(
        monkeypatch, ExecResult(exit_code=1, stdout="", stderr="x" * 5000)
    )

    config = make_config()
    with caplog.at_level("WARNING", logger="core.tool_runtime"):
        result = asyncio.run(_run_tool_scenario(config, make_tool_dir(tmp_path), {}))

    assert result["stderr"] == "x" * 5000
    stderr_records = [record for record in caplog.records if "stderr" in record.getMessage()]
    assert len(stderr_records) == 1
    logged = stderr_records[0].getMessage()
    assert "[truncated]" in logged
    assert len(logged) <= 2100


def test_run_tool_truncates_a_flooded_stdout_preview(monkeypatch, tmp_path):
    """A non-JSON flood is previewed at 90k and marked truncated."""
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    install_fake_runner(
        monkeypatch, ExecResult(exit_code=0, stdout="x" * 120_000, stderr="", stdout_truncated=True)
    )

    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert "output truncated by hub" in result["output"]
    assert result["truncated"] is True
    assert len(result["output"]) == 90000 + len(hub.TRUNCATION_MARKER.decode())
    assert result["warning"].startswith("Output was not valid JSON: ")
    assert len(result["warning"]) <= 2048 + len("Output was not valid JSON: ")


def test_oversized_valid_json_is_bounded(monkeypatch, tmp_path):
    """A valid JSON payload over the 96k safety net is summarised, not forwarded."""
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    oversized = json.dumps({"data": "x" * 10_000_000})
    install_fake_runner(monkeypatch, ExecResult(exit_code=0, stdout=oversized, stderr=""))

    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert len(json.dumps(result)) < 100_000
    assert "safety" in result["error"].lower()
    assert result["partial_data_preview"].endswith("[TRUNCATED DUE TO SAFETY LIMITS]")


# --------------------------------------------------------------------------- #
# handler hygiene, liveness, background tasks
# --------------------------------------------------------------------------- #


def test_run_tool_handler_does_not_log_raw_kwargs(monkeypatch, tmp_path, capsys):
    config = make_config()
    tool_dir = make_tool_dir(tmp_path)
    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: {"tmpltool": (config, tool_dir)})
    monkeypatch.setattr(hub, "mcp", fake_mcp)

    async def fake_run_tool(config, tool_dir, arguments):
        return {"ok": True}

    monkeypatch.setattr(hub, "run_tool", fake_run_tool)

    hub.register_tools()
    handler = fake_mcp.handlers["tmpltool"]
    result = asyncio.run(handler(q="SUPER_SECRET_VALUE", __user_id="user-1"))

    captured = capsys.readouterr()
    assert result == {"ok": True}
    assert "RECEIVED KWARGS" not in captured.out
    assert "RECEIVED KWARGS" not in captured.err
    assert "SUPER_SECRET_VALUE" not in captured.out
    assert "SUPER_SECRET_VALUE" not in captured.err


def test_healthz_route_is_a_plain_liveness_probe():
    """Executable health lives on the runner's socket; the hub only proves it serves."""
    from httpx import ASGITransport, AsyncClient

    app = hub.mcp.http_app()

    async def _scenario():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://hub") as client:
            return await client.get("/healthz")

    response = asyncio.run(_scenario())

    assert response.status_code == 200
    assert response.json() == {"ok": True, "backend": "container"}


def test_hub_drain_background_tasks_waits_for_completion():
    completed = []

    async def work():
        await asyncio.sleep(0.01)
        completed.append(True)
        return "done"

    async def _scenario():
        task = hub._spawn_background(work(), "test-drain-complete")
        await hub._drain_background_tasks(timeout=5.0)
        return task

    task = asyncio.run(_scenario())

    assert completed == [True]
    assert task.done()
    assert not task.cancelled()
    assert task.result() == "done"
    assert task not in hub._background_tasks


def test_hub_drain_background_tasks_cancels_hung_task():
    started = asyncio.Event()

    async def work():
        started.set()
        await asyncio.sleep(60)

    async def _scenario():
        task = hub._spawn_background(work(), "test-drain-hang")
        await asyncio.wait_for(started.wait(), timeout=2)
        await hub._drain_background_tasks(timeout=0.05)
        await asyncio.gather(task, return_exceptions=True)
        return task

    task = asyncio.run(_scenario())

    assert task.cancelled()
    assert task not in hub._background_tasks


def test_lifespan_wrapper_drains_on_shutdown(monkeypatch):
    events = []

    async def fake_drain(timeout=5.0):
        events.append("drain")

    monkeypatch.setattr(hub, "_drain_background_tasks", fake_drain)

    inner_scopes = []

    class FakeInnerApp:
        async def __call__(self, scope, receive, send):
            inner_scopes.append(scope["type"])
            if scope["type"] != "lifespan":
                return
            while True:
                message = await receive()
                if message["type"] == "lifespan.shutdown":
                    events.append("inner_shutdown")
                    await send({"type": "lifespan.shutdown.complete"})
                    return
                await send({"type": "lifespan.startup.complete"})

    incoming = asyncio.Queue()

    async def fake_receive():
        return await incoming.get()

    sent = []

    async def fake_send(message):
        sent.append(message)

    wrapper = hub._LifespanDrainWrapper(FakeInnerApp())

    async def _scenario():
        await incoming.put({"type": "lifespan.startup"})
        await incoming.put({"type": "lifespan.shutdown"})
        await wrapper({"type": "lifespan"}, fake_receive, fake_send)
        await wrapper({"type": "http"}, fake_receive, fake_send)

    asyncio.run(_scenario())

    assert events == ["drain", "inner_shutdown"]
    assert inner_scopes == ["lifespan", "http"]
    assert sent == [{"type": "lifespan.startup.complete"}, {"type": "lifespan.shutdown.complete"}]
