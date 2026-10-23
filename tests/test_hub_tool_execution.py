# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for core.hub.run_tool (cycle-4 Phase 1).

Pins the contracts introduced by the Hub hardening plan:
- stamina re-invocation never mutates the caller's arguments, so `__user_id`
  (and therefore scoped secret injection / execution tokens) survives retries.
- subprocess execution honors `TOOL_EXECUTION_TIMEOUT` and per-tool
  `timeout_seconds`, kills the hung child, and is never retried.
- transient-stderr retries are gated by `retry_on_transient`.
- tool usage is recorded exactly once per invocation, not once per stamina
  retry attempt.
- the tool handler never logs raw kwargs (`RECEIVED KWARGS` is deleted).
- subprocess output is collected with bounded buffers (stdout/stderr caps plus a
  truncation marker) while still draining the pipes to EOF, and sandbox cleanup
  runs off the event loop.
- a timeout during output flooding returns promptly: the pipe transports are
  closed after the readers are cancelled so the child's exit waiter resolves.
- the non-JSON fallback is bounded too, so a multi-megabyte payload cannot flood
  the model context via `output` plus `warning`.
- the helper's benign sandbox warning is not logged as a tool failure.
"""

import asyncio
import json
import logging
import os
import sys
import threading
import time

import pytest

from core import hub
from core.models import ToolConfig


@pytest.fixture(autouse=True)
def _reset_registered_tools():
    """register_tools() reconciles against process-global state; reset it per test."""
    hub._registered_tools.clear()
    hub._unreadable_tool_names.clear()
    yield
    hub._registered_tools.clear()
    hub._unreadable_tool_names.clear()


ENTRYPOINT_SOURCE = "import json, sys\nprint(json.dumps({}))\n"


class FakeStream:
    """Duck-types the read side of a subprocess pipe."""

    def __init__(self, data=b"", hang=False, started=None, release=None):
        self._data = data
        self._offset = 0
        self._hang = hang
        self._started = started
        self._release = release
        self.read_calls = 0

    async def read(self, n=-1):
        self.read_calls += 1
        if self._started is not None and not self._started.is_set():
            self._started.set()
        if self._release is not None:
            await self._release.wait()
        if self._hang:
            await asyncio.sleep(60)
        if self._offset >= len(self._data):
            return b""
        size = len(self._data) if n is None or n < 0 else n
        chunk = self._data[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk


class FakeStdin:
    """Duck-types asyncio's subprocess StreamWriter."""

    def __init__(self, broken=False):
        self.writes = []
        self.closed = False
        self._broken = broken

    def write(self, data):
        if self._broken:
            raise BrokenPipeError()
        self.writes.append(data)

    async def drain(self):
        if self._broken:
            raise BrokenPipeError()

    def close(self):
        self.closed = True


class FakeProcess:
    """Duck-types the subset of asyncio.subprocess.Process that run_tool uses."""

    def __init__(self, returncode=0, stdout=b"", stderr=b"", hang=False, stdin_broken=False):
        # Like the real Process, the returncode is unknown until wait() reaps.
        self.returncode = None
        self._final_returncode = returncode
        self.stdout = FakeStream(stdout, hang=hang)
        self.stderr = FakeStream(stderr, hang=hang)
        self.stdin = FakeStdin(broken=stdin_broken)
        self.stdin_writes = self.stdin.writes
        self.kill_calls = 0
        self.wait_calls = 0

    def kill(self):
        self.kill_calls += 1
        self.returncode = -9

    async def wait(self):
        self.wait_calls += 1
        if self.returncode is None:
            self.returncode = self._final_returncode
        return self.returncode


class BlockingProcess(FakeProcess):
    """Pipes park until released, so task cancellation can be exercised."""

    def __init__(self):
        super().__init__()
        self.read_started = asyncio.Event()
        self.release = asyncio.Event()
        self.stdout = FakeStream(started=self.read_started, release=self.release)
        self.stderr = FakeStream(started=self.read_started, release=self.release)


class FakeIdentityManager:
    """Records identity lookups so retry attempts can be asserted on."""

    def __init__(self, resolved_config=None):
        self.resolved_config_calls = []
        self.execution_token_calls = []
        self.get_config_calls = []
        self.get_user_calls = []
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


def install_fake_subprocess(monkeypatch, processes):
    """Script asyncio.create_subprocess_exec with a sequence of FakeProcesses."""
    spawns = []
    remaining = list(processes)

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        spawns.append({"cmd": cmd, "kwargs": kwargs, "process": None})
        if not remaining:
            raise AssertionError("unexpected extra subprocess spawn")
        process = remaining.pop(0)
        spawns[-1]["process"] = process
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    return spawns


def install_fake_identity(monkeypatch, resolved_config=None):
    fake = FakeIdentityManager(resolved_config=resolved_config)
    for method in ("get_resolved_config", "generate_execution_token", "get_config", "get_user", "record_tool_usage"):
        monkeypatch.setattr(hub.identity_mgr, method, getattr(fake, method))
    return fake


def install_fake_health(monkeypatch):
    events = []

    def fake_record_event(entity_type, name, is_success, error_details=None):
        events.append({"entity_type": entity_type, "name": name, "is_success": is_success, "error_details": error_details})
        return {}

    monkeypatch.setattr(hub.health_monitor, "record_event", fake_record_event)
    return events


def install_sandbox(monkeypatch, backend="bwrap"):
    """Select a backend without probing; temp dirs still exercise real cleanup."""
    from core import sandbox

    sandbox.reset_for_tests()
    monkeypatch.setattr(
        sandbox, "select_backend", lambda force=None: sandbox.Backend(backend)
    )


async def _run_tool_scenario(config, tool_dir, arguments):
    """Await run_tool, then drain fire-and-forget background tasks deterministically."""
    result = await hub.run_tool(config, tool_dir, arguments)
    await asyncio.gather(*hub._background_tasks, return_exceptions=True)
    return result


def test_run_tool_preserves_user_id_across_retries(monkeypatch, tmp_path):
    install_sandbox(monkeypatch)
    monkeypatch.setenv("DEV_MODE", "false")
    fake_identity = install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    first = FakeProcess(returncode=1, stderr=b"connection refused")
    second = FakeProcess(returncode=0, stdout=b'{"ok": true}')
    spawns = install_fake_subprocess(monkeypatch, [first, second])

    result = asyncio.run(
        _run_tool_scenario(make_config(secrets=["API_KEY"]), make_tool_dir(tmp_path), {"__user_id": "user-1"})
    )

    assert result == {"ok": True}
    assert len(spawns) == 2
    resolved_user_ids = [call["identity"] for call in fake_identity.resolved_config_calls]
    assert resolved_user_ids.count("user-1") >= 2
    # v0.6 removed the FRAMEWORK_* injection: a tool never receives a
    # framework loopback credential, so no execution token is minted.
    assert fake_identity.execution_token_calls == []
    assert fake_identity.get_user_calls.count("user-1") >= 2
    assert ("user-1", "tmpltool") in fake_identity.record_tool_usage_calls


def test_run_tool_records_usage_once_across_retries(monkeypatch, tmp_path):
    install_sandbox(monkeypatch)
    monkeypatch.setenv("DEV_MODE", "false")
    fake_identity = install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    first = FakeProcess(returncode=1, stderr=b"connection refused")
    second = FakeProcess(returncode=0, stdout=b'{"ok": true}')
    spawns = install_fake_subprocess(monkeypatch, [first, second])

    result = asyncio.run(
        _run_tool_scenario(make_config(secrets=["API_KEY"]), make_tool_dir(tmp_path), {"__user_id": "user-1"})
    )

    assert result == {"ok": True}
    assert len(spawns) == 2
    assert fake_identity.record_tool_usage_calls == [("user-1", "tmpltool")]


def test_run_tool_does_not_mutate_caller_arguments(monkeypatch, tmp_path):
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    process = FakeProcess(returncode=0, stdout=b'{"ok": true}')
    install_fake_subprocess(monkeypatch, [process])

    arguments = {"__user_id": "user-1", "q": "x"}
    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), arguments))

    assert result == {"ok": True}
    assert arguments == {"__user_id": "user-1", "q": "x"}
    # The fake reports no returncode until reaped, so _communicate_bounded had
    # to take its exit-awaiter branch to classify the process correctly.
    assert process.wait_calls == 1
    assert process.returncode == 0


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


def test_run_tool_handler_reports_retry_exhaustion_and_records_usage_once(monkeypatch, tmp_path):
    config = make_config()
    tool_dir = make_tool_dir(tmp_path)
    install_sandbox(monkeypatch)
    fake_identity = install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: {"tmpltool": (config, tool_dir)})
    monkeypatch.setattr(hub, "mcp", fake_mcp)

    processes = [FakeProcess(returncode=1, stderr=b"connection refused") for _ in range(3)]
    spawns = install_fake_subprocess(monkeypatch, processes)

    hub.register_tools()
    handler = fake_mcp.handlers["tmpltool"]

    async def _scenario():
        result = await handler(q="x", __user_id="user-1")
        await asyncio.gather(*hub._background_tasks, return_exceptions=True)
        return result

    result = asyncio.run(_scenario())

    assert result["error"].startswith("Tool failed after retries:")
    assert len(spawns) == 3
    assert fake_identity.record_tool_usage_calls == [("user-1", "tmpltool")]


def test_run_tool_times_out_hung_subprocess(monkeypatch, tmp_path):
    install_sandbox(monkeypatch)
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "0.1")
    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)

    config = make_config()
    hung = FakeProcess(hang=True)
    spawns = install_fake_subprocess(monkeypatch, [hung])

    result = asyncio.run(_run_tool_scenario(config, make_tool_dir(tmp_path), {}))

    assert "timed out" in result["error"]
    assert hung.kill_calls == 1
    assert hung.wait_calls == 1
    failed_events = [event for event in health_events if event["is_success"] is False]
    assert len(failed_events) == 1
    assert failed_events[0]["entity_type"] == "tool"
    assert failed_events[0]["name"] == config.name
    assert "timed out" in failed_events[0]["error_details"]
    assert len(spawns) == 1


def test_run_tool_timeout_process_already_dead_is_handled(monkeypatch, tmp_path):
    install_sandbox(monkeypatch)
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "0.1")
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    class AlreadyDeadProcess(FakeProcess):
        def kill(self):
            self.kill_calls += 1
            raise ProcessLookupError()

    hung = AlreadyDeadProcess(hang=True)
    spawns = install_fake_subprocess(monkeypatch, [hung])

    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert "timed out" in result["error"]
    assert hung.kill_calls == 1
    assert hung.wait_calls == 1
    assert len(spawns) == 1


def test_run_tool_timeout_per_tool_override(monkeypatch, tmp_path):
    install_sandbox(monkeypatch)
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "30")
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    hung = FakeProcess(hang=True)
    spawns = install_fake_subprocess(monkeypatch, [hung])

    result = asyncio.run(_run_tool_scenario(make_config(timeout_seconds=1), make_tool_dir(tmp_path), {}))

    assert "timed out after 1s" in result["error"]
    assert hung.kill_calls == 1
    assert len(spawns) == 1


def test_run_tool_transient_stderr_still_retries(monkeypatch, tmp_path):
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    first = FakeProcess(returncode=1, stderr=b"connection refused")
    second = FakeProcess(returncode=0, stdout=b'{"ok": true}')
    spawns = install_fake_subprocess(monkeypatch, [first, second])

    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert result == {"ok": True}
    assert len(spawns) == 2


def test_run_tool_preserves_agent_name_across_retries(monkeypatch, tmp_path):
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    first = FakeProcess(returncode=1, stderr=b"connection refused")
    second = FakeProcess(returncode=0, stdout=b'{"ok": true}')
    spawns = install_fake_subprocess(monkeypatch, [first, second])

    result = asyncio.run(
        _run_tool_scenario(make_config(secrets=["API_KEY"]), make_tool_dir(tmp_path), {"__user_id": "svc_agent_triage"})
    )

    assert result == {"ok": True}
    assert len(spawns) == 2
    second_stdin = json.loads(spawns[1]["process"].stdin_writes[0].decode())
    # v0.6: agent identity travels in the verified token, never as a stdin field.
    assert "__agent_name" not in second_stdin


def test_run_tool_skips_retry_when_retry_on_transient_false(monkeypatch, tmp_path):
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)

    failed = FakeProcess(returncode=1, stderr=b"connection refused")
    spawns = install_fake_subprocess(monkeypatch, [failed])

    result = asyncio.run(_run_tool_scenario(make_config(retry_on_transient=False), make_tool_dir(tmp_path), {}))

    assert "connection refused" in result["error"]
    assert len(spawns) == 1
    assert any(event["is_success"] is False for event in health_events)


def test_run_tool_logs_truncation_warning(monkeypatch, tmp_path, caplog):
    """Oversized outputs are still truncated, and the warning now goes through
    the module logger (Phase 5, Task 5.2) rather than a bare print()."""
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    config = make_config()
    oversized = json.dumps({"data": "x" * 100000}).encode()
    install_fake_subprocess(monkeypatch, [FakeProcess(returncode=0, stdout=oversized)])

    with caplog.at_level(logging.WARNING, logger="core.hub"):
        result = asyncio.run(_run_tool_scenario(config, make_tool_dir(tmp_path), {}))

    assert "error" in result
    assert "safety" in result["error"].lower()
    assert "exceeded safety limit" in caplog.text
    assert config.name in caplog.text


def test_run_tool_stderr_log_bounded_but_result_full(monkeypatch, tmp_path, caplog):
    """The stderr warning is truncated for the log line, while the error dict
    returned to the caller preserves the full stderr payload."""
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    config = make_config()
    install_fake_subprocess(monkeypatch, [FakeProcess(returncode=1, stderr=b"x" * 5000)])

    with caplog.at_level(logging.WARNING, logger="core.hub"):
        result = asyncio.run(_run_tool_scenario(config, make_tool_dir(tmp_path), {}))

    assert result["stderr"] == "x" * 5000
    stderr_records = [record for record in caplog.records if "stderr" in record.getMessage()]
    assert len(stderr_records) == 1
    logged = stderr_records[0].getMessage()
    assert "[truncated]" in logged
    assert len(logged) <= 2100


def test_run_tool_cancellation_kills_subprocess(monkeypatch, tmp_path):
    """Cancelling the handler (MCP disconnect / shutdown) must kill the child and
    re-raise CancelledError without recording a health event."""
    from core import sandbox

    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)

    run_dirs = []
    real_prepare = sandbox.prepare_execution

    def _prepare(*args, **kwargs):
        plan = real_prepare(*args, **kwargs)
        run_dirs.append(plan.tmpdir)
        return plan

    monkeypatch.setattr(sandbox, "prepare_execution", _prepare)

    blocked = BlockingProcess()
    spawns = install_fake_subprocess(monkeypatch, [blocked])

    async def _scenario():
        task = asyncio.create_task(hub.run_tool(make_config(), make_tool_dir(tmp_path), {}))
        try:
            await asyncio.wait_for(blocked.read_started.wait(), timeout=2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            blocked.release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await asyncio.gather(*hub._background_tasks, return_exceptions=True)

    asyncio.run(_scenario())

    assert len(spawns) == 1
    assert blocked.kill_calls == 1
    assert blocked.wait_calls == 1
    assert health_events == []
    assert run_dirs and not run_dirs[0].exists()


def test_sandbox_classified_failure_is_not_retried(monkeypatch, tmp_path):
    """A denial is permanent: do not burn the transient-stderr retry budget."""
    from core import sandbox
    from core import sandbox_preflight

    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)

    spawns = install_fake_subprocess(
        monkeypatch,
        [FakeProcess(returncode=1, stderr=b"timeout: seccomp denied syscall")],
    )
    monkeypatch.setattr(
        sandbox,
        "classify_failure",
        lambda stderr, backend, returncode: sandbox_preflight.ProbeResult(
            backend="landlock",
            ok=False,
            code="helper_failed",
            detail=stderr,
            remediation="rebuild the image",
        ),
    )
    logged = []
    monkeypatch.setattr(sandbox, "log_failure_once", logged.append)

    result = asyncio.run(
        _run_tool_scenario(make_config(), make_tool_dir(tmp_path), {})
    )

    assert len(spawns) == 1
    assert result["sandbox"] == {
        "backend": "bwrap",
        "code": "helper_failed",
        "remediation": "rebuild the image",
    }
    assert result["error"].startswith("Tool failed inside the bwrap sandbox")
    assert len(logged) == 1
    assert any(event["is_success"] is False for event in health_events)


def test_sandbox_classified_failure_invalidates_the_cached_verdict(
    monkeypatch, tmp_path
):
    """A denial proves the cached verdict stale: re-probe on the next reader."""
    from core import sandbox, sandbox_preflight

    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    install_fake_subprocess(
        monkeypatch, [FakeProcess(returncode=65, stderr=b"trellis-sandbox: nope")]
    )
    monkeypatch.setattr(
        sandbox,
        "classify_failure",
        lambda *a, **k: sandbox_preflight.ProbeResult(
            backend="landlock",
            ok=False,
            code="landlock_unavailable",
            detail="nope",
            remediation="rebuild the image",
        ),
    )
    monkeypatch.setattr(sandbox, "log_failure_once", lambda result: None)
    invalidations = []
    monkeypatch.setattr(
        sandbox_preflight,
        "invalidate",
        lambda reason: invalidations.append(reason) or True,
    )

    result = asyncio.run(
        _run_tool_scenario(make_config(), make_tool_dir(tmp_path), {})
    )

    assert result["sandbox"]["code"] == "landlock_unavailable"
    assert invalidations == ["tool failure: landlock_unavailable"]


def test_net_policy_refusal_does_not_invalidate_the_cached_verdict(
    monkeypatch, tmp_path
):
    """A per-tool policy this kernel cannot express is not a host regression."""
    from core import sandbox, sandbox_preflight

    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    install_fake_subprocess(
        monkeypatch,
        [
            FakeProcess(
                returncode=65,
                stderr=(
                    b"trellis-sandbox: landlock net access control requires "
                    b"ABI 4 (have 3)"
                ),
            )
        ],
    )
    monkeypatch.setattr(
        sandbox,
        "classify_failure",
        lambda *a, **k: sandbox_preflight.ProbeResult(
            backend="landlock",
            ok=False,
            code="landlock_net_unsupported",
            detail="requires ABI 4",
            remediation=sandbox_preflight.REMEDIATIONS["landlock_net_unsupported"],
        ),
    )
    monkeypatch.setattr(sandbox, "log_failure_once", lambda result: None)
    invalidations = []
    monkeypatch.setattr(
        sandbox_preflight,
        "invalidate",
        lambda reason: invalidations.append(reason) or True,
    )

    result = asyncio.run(
        _run_tool_scenario(
            make_config(network="none"), make_tool_dir(tmp_path), {}
        )
    )

    assert result["sandbox"]["code"] == "landlock_net_unsupported"
    # Re-probing can only reach the same ABI conclusion, so the cached verdict
    # (and the selected backend) must survive.
    assert invalidations == []


@pytest.mark.parametrize(
    "returncode,stdout,stderr",
    [
        (1, b"", b"boom"),  # no sandbox provenance: ordinary tool failure
        (0, b'{"ok": true}', b""),  # successful run
    ],
)
def test_non_sandbox_outcomes_do_not_invalidate(
    monkeypatch, tmp_path, returncode, stdout, stderr
):
    from core import sandbox_preflight

    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    install_fake_subprocess(
        monkeypatch,
        [FakeProcess(returncode=returncode, stdout=stdout, stderr=stderr)],
    )
    invalidations = []
    monkeypatch.setattr(
        sandbox_preflight,
        "invalidate",
        lambda reason: invalidations.append(reason) or True,
    )

    asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert invalidations == []


def test_run_tool_network_none_reaches_the_sandbox_argv(monkeypatch, tmp_path):
    """The per-tool network policy must survive the config -> argv path."""
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    denied_spawns = install_fake_subprocess(
        monkeypatch, [FakeProcess(returncode=0, stdout=b'{"ok": true}')]
    )
    result = asyncio.run(
        _run_tool_scenario(
            make_config(network="none"), make_tool_dir(tmp_path), {}
        )
    )

    assert result == {"ok": True}
    assert "--unshare-net" in denied_spawns[0]["cmd"]

    allowed_spawns = install_fake_subprocess(
        monkeypatch, [FakeProcess(returncode=0, stdout=b'{"ok": true}')]
    )
    result = asyncio.run(
        _run_tool_scenario(make_config(), make_tool_dir(tmp_path), {})
    )

    assert result == {"ok": True}
    assert "--unshare-net" not in allowed_spawns[0]["cmd"]


def test_run_tool_net_default_applies_and_explicit_policy_overrides(
    monkeypatch, tmp_path
):
    """SANDBOX_NET_DEFAULT must reach tools that never set `network`."""
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    monkeypatch.setenv("SANDBOX_NET_DEFAULT", "none")

    implicit_spawns = install_fake_subprocess(
        monkeypatch, [FakeProcess(returncode=0, stdout=b'{"ok": true}')]
    )
    assert asyncio.run(
        _run_tool_scenario(make_config(), make_tool_dir(tmp_path), {})
    ) == {"ok": True}
    assert "--unshare-net" in implicit_spawns[0]["cmd"]

    explicit_spawns = install_fake_subprocess(
        monkeypatch, [FakeProcess(returncode=0, stdout=b'{"ok": true}')]
    )
    assert asyncio.run(
        _run_tool_scenario(
            make_config(network="allow"), make_tool_dir(tmp_path), {}
        )
    ) == {"ok": True}
    assert "--unshare-net" not in explicit_spawns[0]["cmd"]


def test_run_tool_net_config_dict_overrides_the_env_default(monkeypatch, tmp_path):
    """A config built from a dict must keep `network: allow` explicit.

    `model_fields_set` is the only signal that separates "the operator chose
    allow" from "pydantic's default", so the dict path must be pinned too:
    otherwise SANDBOX_NET_DEFAULT=none would silently win over the config.
    """
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    monkeypatch.setenv("SANDBOX_NET_DEFAULT", "none")

    config = ToolConfig.model_validate(
        {
            "name": "tmpltool",
            "description": "d",
            "runtime": "python",
            "entrypoint": "main.py",
            "network": "allow",
        }
    )
    assert "network" in config.model_fields_set
    # The implicit config has no explicit field, so it inherits the env default.
    assert "network" not in make_config().model_fields_set

    spawns = install_fake_subprocess(
        monkeypatch, [FakeProcess(returncode=0, stdout=b'{"ok": true}')]
    )
    assert asyncio.run(
        _run_tool_scenario(config, make_tool_dir(tmp_path), {})
    ) == {"ok": True}
    assert "--unshare-net" not in spawns[0]["cmd"]


def test_run_tool_reports_sandbox_unavailable(monkeypatch, tmp_path):
    from core import sandbox

    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)

    def _unavailable(*args, **kwargs):
        raise sandbox.SandboxUnavailable(
            "apparmor_mount_denied",
            "bwrap: Can't mount proc",
            "add apparmor=unconfined",
            backend="none",
        )

    monkeypatch.setattr(sandbox, "prepare_execution", _unavailable)

    result = asyncio.run(
        _run_tool_scenario(make_config(), make_tool_dir(tmp_path), {})
    )

    assert "Sandbox unavailable" in result["error"]
    assert result["sandbox"]["code"] == "apparmor_mount_denied"
    assert result["sandbox"]["remediation"] == "add apparmor=unconfined"
    assert any(event["is_success"] is False for event in health_events)


def test_run_tool_cleans_tmpdir_on_timeout(monkeypatch, tmp_path):
    from core import sandbox

    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "0.1")

    run_dir = tmp_path / "trellis-tmpltool-run"
    run_dir.mkdir()
    plan = sandbox.SandboxPlan(
        argv=["bwrap", "/bin/true"],
        env={},
        tmpdir=run_dir,
        backend=sandbox.Backend.BWRAP,
    )

    monkeypatch.setattr(sandbox, "prepare_execution", lambda *a, **k: plan)
    install_fake_subprocess(monkeypatch, [FakeProcess(hang=True)])

    result = asyncio.run(
        _run_tool_scenario(make_config(), make_tool_dir(tmp_path), {})
    )

    assert "timed out" in result["error"]
    assert not run_dir.exists()


def test_run_tool_truncates_stdout_flood(monkeypatch, tmp_path):
    """A tool flooding stdout is capped at MAX_STDOUT_BYTES instead of being
    buffered whole, and the hub keeps draining so the child never blocks."""
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "5")

    flood = b"x" * (hub.MAX_STDOUT_BYTES + 1024)
    # The flooding tool never reads stdin, so the hub's write hits a closed pipe.
    install_fake_subprocess(
        monkeypatch, [FakeProcess(returncode=0, stdout=flood, stdin_broken=True)]
    )

    async def _scenario():
        return await asyncio.wait_for(
            _run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}), timeout=10
        )

    result = asyncio.run(_scenario())

    # The flood is not valid JSON, so it surfaces through the JSONDecodeError
    # path, which previews 90k and reports the truncation flag.
    assert "output truncated by hub" in result["output"]
    assert result["truncated"] is True
    assert len(result["output"]) == 90000 + len(hub.TRUNCATION_MARKER.decode())
    assert result["warning"].startswith("Output was not valid JSON: ")
    assert len(result["warning"]) <= 2048 + len("Output was not valid JSON: ")


def test_oversized_valid_json_is_bounded(monkeypatch, tmp_path):
    """A valid JSON payload over the 8 MiB stdout cap must not reach the model
    twice over: the preview is 90k and the warning is capped."""
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "5")

    oversized = json.dumps({"data": "x" * 10_000_000}).encode()
    install_fake_subprocess(monkeypatch, [FakeProcess(returncode=0, stdout=oversized)])

    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert len(json.dumps(result)) < 100_000
    assert "not valid JSON" in result["warning"]
    assert result["truncated"] is True


def test_timeout_with_flooding_output_returns_promptly():
    """A tool flooding stdout must not hang the hub after the timeout fires.

    Cancelling a reader that asyncio paused on a full pipe leaves the transport
    open, so EOF is never seen and ``process.wait()`` can stay pending forever
    unless ``_communicate_bounded`` closes the pipes. Real subprocess on purpose.
    """
    script = (
        "import sys\n"
        "while True:\n"
        "    sys.stdout.write('x' * 65536)\n"
        "    sys.stdout.flush()\n"
    )

    async def _scenario():
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            script,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        started = time.monotonic()
        try:
            with pytest.raises(asyncio.TimeoutError):
                await hub._communicate_bounded(process, b"{}", 0.3)
            elapsed = time.monotonic() - started
        finally:
            hub._kill_process_tree(process)
            # The regression: this wait used to never resolve.
            await asyncio.wait_for(process.wait(), 2)

        assert process.returncode is not None
        return elapsed

    elapsed = asyncio.run(_scenario())

    assert elapsed < 2.0, f"timeout took {elapsed:.2f}s"


def test_sandbox_warning_only_stderr_is_not_logged(monkeypatch, tmp_path, caplog):
    """The helper's benign warning must not be logged as a tool failure."""
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    # The preflight warns when SANDBOX_UID differs from this process's uid. Pin both
    # to the current identity so this test is about the helper's stderr, not about
    # the uid of whoever runs it (GitHub runners are 1001, images are 1000).
    monkeypatch.setenv("SANDBOX_UID", str(os.geteuid()))
    monkeypatch.setenv("SANDBOX_GID", str(os.getegid()))

    warning = b"trellis-sandbox: warning: supplementary groups retained (needs CAP_SETGID)\n"
    install_fake_subprocess(
        monkeypatch, [FakeProcess(returncode=0, stdout=b'{"ok": true}', stderr=warning)]
    )

    with caplog.at_level(logging.WARNING, logger="core.hub"):
        result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert result == {"ok": True}
    assert caplog.records == []


def test_run_tool_truncates_stderr_flood(monkeypatch, tmp_path):
    """Stderr is capped too, and a truncated stderr still classifies normally."""
    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "5")

    flood = b"E" * (512 * 1024)
    install_fake_subprocess(monkeypatch, [FakeProcess(returncode=1, stderr=flood)])

    async def _scenario():
        return await asyncio.wait_for(
            _run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}), timeout=10
        )

    result = asyncio.run(_scenario())

    assert result["error"].startswith("Tool exited with code 1")
    assert "output truncated by hub" in result["stderr"]
    assert len(result["stderr"].encode()) <= (
        hub.MAX_STDERR_BYTES + len(hub.TRUNCATION_MARKER)
    )
    assert any(event["is_success"] is False for event in health_events)


def test_run_tool_prepare_execution_is_offloaded(monkeypatch, tmp_path):
    """Backend selection can re-probe; it must not run on the event loop."""
    from core import sandbox

    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    threads = []
    real_prepare = sandbox.prepare_execution

    def _prepare(*args, **kwargs):
        threads.append(threading.current_thread())
        return real_prepare(*args, **kwargs)

    monkeypatch.setattr(sandbox, "prepare_execution", _prepare)
    install_fake_subprocess(
        monkeypatch, [FakeProcess(returncode=0, stdout=b'{"ok": true}')]
    )

    assert asyncio.run(
        _run_tool_scenario(make_config(), make_tool_dir(tmp_path), {})
    ) == {"ok": True}

    assert len(threads) == 1
    assert threads[0] is not threading.main_thread()


def test_run_tool_cleanup_is_offloaded(monkeypatch, tmp_path):
    """Cleanup runs off the event loop but still happens on every exit path."""
    from core import sandbox

    install_sandbox(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "0.1")

    run_dirs = []
    real_prepare = sandbox.prepare_execution

    def _prepare(*args, **kwargs):
        plan = real_prepare(*args, **kwargs)
        run_dirs.append(plan.tmpdir)
        return plan

    monkeypatch.setattr(sandbox, "prepare_execution", _prepare)

    install_fake_subprocess(
        monkeypatch, [FakeProcess(returncode=0, stdout=b'{"ok": true}')]
    )
    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert result == {"ok": True}
    assert len(run_dirs) == 1
    assert not run_dirs[0].exists()

    install_fake_subprocess(monkeypatch, [FakeProcess(hang=True)])
    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert "timed out" in result["error"]
    assert len(run_dirs) == 2
    assert not run_dirs[1].exists()


@pytest.mark.parametrize(
    "ok,status_code",
    [(True, 200), (False, 503)],
)
def test_healthz_route_serves_cached_payload(monkeypatch, ok, status_code):
    """The route must expose the cached preflight verdict with no auth prompt."""
    from httpx import ASGITransport, AsyncClient

    from core import sandbox_preflight

    monkeypatch.setattr(
        sandbox_preflight,
        "cached_status",
        lambda: {
            "ok": ok,
            "backend": "bwrap" if ok else "none",
            "code": None if ok else "unknown",
            "remediation": "" if ok else "fix it",
        },
    )

    app = hub.mcp.http_app()

    async def _scenario():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://hub") as client:
            return await client.get("/healthz")

    response = asyncio.run(_scenario())

    assert response.status_code == status_code
    payload = response.json()
    assert payload["ok"] is ok
    assert payload["backend"] == ("bwrap" if ok else "none")


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
