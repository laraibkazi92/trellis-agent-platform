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
"""

import asyncio
import json
import logging

import pytest

from core import hub
from core.models import ToolConfig


ENTRYPOINT_SOURCE = "import json, sys\nprint(json.dumps({}))\n"


class FakeProcess:
    """Duck-types the subset of asyncio.subprocess.Process that run_tool uses."""

    def __init__(self, returncode=0, stdout=b"", stderr=b"", hang=False):
        self.returncode = returncode
        self.stdout_data = stdout
        self.stderr_data = stderr
        self.hang = hang
        self.communicate_calls = []
        self.kill_calls = 0
        self.wait_calls = 0

    async def communicate(self, input=None):
        self.communicate_calls.append(input)
        if self.hang:
            await asyncio.sleep(60)
        return self.stdout_data, self.stderr_data

    def kill(self):
        self.kill_calls += 1
        self.returncode = -9

    async def wait(self):
        self.wait_calls += 1
        return self.returncode


class BlockingProcess(FakeProcess):
    """communicate() parks until released, so task cancellation can be exercised."""

    def __init__(self):
        super().__init__()
        self.communicate_started = asyncio.Event()
        self.release = asyncio.Event()

    async def communicate(self, input=None):
        self.communicate_calls.append(input)
        self.communicate_started.set()
        await self.release.wait()
        return self.stdout_data, self.stderr_data


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


def install_bwrap(monkeypatch):
    monkeypatch.setattr(hub.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)


async def _run_tool_scenario(config, tool_dir, arguments):
    """Await run_tool, then drain fire-and-forget background tasks deterministically."""
    result = await hub.run_tool(config, tool_dir, arguments)
    await asyncio.gather(*hub._background_tasks, return_exceptions=True)
    return result


def test_run_tool_preserves_user_id_across_retries(monkeypatch, tmp_path):
    install_bwrap(monkeypatch)
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
    assert fake_identity.execution_token_calls.count("user-1") >= 2
    assert fake_identity.get_user_calls.count("user-1") >= 2
    assert ("user-1", "tmpltool") in fake_identity.record_tool_usage_calls


def test_run_tool_records_usage_once_across_retries(monkeypatch, tmp_path):
    install_bwrap(monkeypatch)
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
    install_bwrap(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)
    install_fake_subprocess(monkeypatch, [FakeProcess(returncode=0, stdout=b'{"ok": true}')])

    arguments = {"__user_id": "user-1", "q": "x"}
    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), arguments))

    assert result == {"ok": True}
    assert arguments == {"__user_id": "user-1", "q": "x"}


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
    install_bwrap(monkeypatch)
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
    install_bwrap(monkeypatch)
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
    install_bwrap(monkeypatch)
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
    install_bwrap(monkeypatch)
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
    install_bwrap(monkeypatch)
    install_fake_identity(monkeypatch)
    install_fake_health(monkeypatch)

    first = FakeProcess(returncode=1, stderr=b"connection refused")
    second = FakeProcess(returncode=0, stdout=b'{"ok": true}')
    spawns = install_fake_subprocess(monkeypatch, [first, second])

    result = asyncio.run(_run_tool_scenario(make_config(), make_tool_dir(tmp_path), {}))

    assert result == {"ok": True}
    assert len(spawns) == 2


def test_run_tool_preserves_agent_name_across_retries(monkeypatch, tmp_path):
    install_bwrap(monkeypatch)
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
    second_stdin = json.loads(spawns[1]["process"].communicate_calls[0].decode())
    assert second_stdin["__agent_name"] == "triage"


def test_run_tool_skips_retry_when_retry_on_transient_false(monkeypatch, tmp_path):
    install_bwrap(monkeypatch)
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
    install_bwrap(monkeypatch)
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
    install_bwrap(monkeypatch)
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
    install_bwrap(monkeypatch)
    install_fake_identity(monkeypatch)
    health_events = install_fake_health(monkeypatch)

    blocked = BlockingProcess()
    spawns = install_fake_subprocess(monkeypatch, [blocked])

    async def _scenario():
        task = asyncio.create_task(hub.run_tool(make_config(), make_tool_dir(tmp_path), {}))
        try:
            await asyncio.wait_for(blocked.communicate_started.wait(), timeout=2)
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
