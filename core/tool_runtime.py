# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Subprocess execution for tools, shared by the hub and the edge proxy.

This module is the execution core of ``core.hub`` with every hub-only concern
(etcd, FastMCP, identity-scoped env injection, health recording) removed. The
edge (``core.proxy``) must run tools with exactly the semantics the hub has --
same argv construction, same sandbox plan, same timeouts, same failure
classification -- but it cannot import ``core.hub``: that module builds an
``IdentityManager`` at import time and has no etcd to talk to.

The caller owns the environment: build it (secrets, PATH, framework tokens) and
pass it in. Health events are reported through ``on_health`` so the hub keeps
recording them while the edge, which has no health store, passes ``None``.
"""

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from core import sandbox
from core.models import ToolConfig

logger = logging.getLogger(__name__)

# Per-stream caps for buffered tool output. The 96k JSON safety net downstream
# still applies; these caps only stop a flooding tool from exhausting memory
# before it gets there.
MAX_STDOUT_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024

# Appended to captured output that hit a cap so truncation stays visible in the
# JSONDecodeError path and in the stderr handed back to the caller.
TRUNCATION_MARKER = b"\n...[output truncated by hub]"

_PIPE_CHUNK_BYTES = 64 * 1024

# Injected env names a tool must never be able to override: a secret stored under
# one of these would otherwise rewrite the interpreter's own search path.
RESTRICTED_ENV_VARS = {"PATH", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV", "HOSTALIASES"}

# Health callback: (is_success, error_message). Runs in a worker thread.
HealthCallback = Callable[[bool, Optional[str]], None]


class TransientToolError(Exception):
    """A failure worth retrying (stamina owns the retry budget)."""


def _kill_process_tree(process) -> None:
    """Kill the child's whole session, not just the direct child.

    bwrap tears its PID namespace down with the parent, but the Landlock backend
    runs the tool directly, so its own children are only killed by this signal.
    The container runs with ``init: true``: tini is PID 1 and reaps whatever
    survives, but reaping a live grandchild is not enough -- kill the session so
    it does not keep running after the timeout.
    """
    pid = getattr(process, "pid", None)
    if pid:
        try:
            os.killpg(pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass
    try:
        process.kill()
    except ProcessLookupError:
        pass


async def _collect_stream(stream, limit: int) -> tuple[bytes, bool]:
    """Read one subprocess pipe to EOF, keeping at most ``limit`` bytes.

    After the cap is reached the pipe is still drained and discarded: an unread
    pipe fills up and blocks the child forever, which would turn a chatty tool
    into a timeout instead of a truncated result.
    """
    chunks: list[bytes] = []
    captured = 0
    truncated = False
    while True:
        chunk = await stream.read(_PIPE_CHUNK_BYTES)
        if not chunk:
            break
        if captured >= limit:
            truncated = True
            continue
        room = limit - captured
        if len(chunk) > room:
            chunks.append(chunk[:room])
            captured = limit
            truncated = True
            continue
        chunks.append(chunk)
        captured += len(chunk)

    data = b"".join(chunks)
    if truncated:
        data += TRUNCATION_MARKER
    return data, truncated


async def _write_stdin(process, input_bytes: bytes) -> None:
    """Send the JSON arguments and close stdin (tolerating a tool that ignores it)."""
    stdin = process.stdin
    if stdin is None:
        return
    try:
        stdin.write(input_bytes)
        await stdin.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        try:
            stdin.close()
        except (BrokenPipeError, ConnectionResetError):
            pass


async def _wait_bounded(process, timeout: float = 5.0) -> None:
    """Await exit, but never let a wedged pipe pin the request.

    A killed child normally resolves in milliseconds; this is the backstop for
    the pathological case where even asyncio's exit waiter never fires.
    """
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("Tool process did not exit within %.0fs after kill", timeout)
    except ProcessLookupError:
        pass


async def _communicate_bounded(
    process, input_bytes: bytes, timeout: float
) -> tuple[bytes, bool, bytes, bool]:
    """``communicate()`` with bounded buffers and unchanged timeout semantics.

    Returns ``(stdout, stdout_truncated, stderr, stderr_truncated)``. Timeout
    semantics match ``asyncio.subprocess.Process.communicate()`` for the caller;
    the only addition is a bounded post-kill wait, so a pathological pipe state
    cannot pin a request indefinitely.
    """

    async def _run() -> tuple[bytes, bool, bytes, bool]:
        tasks = [
            asyncio.ensure_future(_write_stdin(process, input_bytes)),
            asyncio.ensure_future(_collect_stream(process.stdout, MAX_STDOUT_BYTES)),
            asyncio.ensure_future(_collect_stream(process.stderr, MAX_STDERR_BYTES)),
        ]
        try:
            results = await asyncio.gather(*tasks)
            stdout, stdout_truncated = results[1]
            stderr, stderr_truncated = results[2]
            # communicate() also awaited exit; without this the caller can race
            # returncode and classify a finished tool as "exited with code None".
            if process.returncode is None:
                await _wait_bounded(process)
            return stdout, stdout_truncated, stderr, stderr_truncated
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            # Cancelling a reader that asyncio paused on a full pipe leaves the
            # transport open: EOF is never observed, connection_lost() never
            # runs and the exit waiter a timeout handler awaits can stay pending
            # forever. Closing the pipes forces that callback. `_transport` is
            # private, but it is the only handle asyncio exposes on a
            # StreamReader's pipe.
            for stream in (process.stdout, process.stderr):
                transport = getattr(stream, "_transport", None)
                if transport is None:
                    continue
                try:
                    if not transport.is_closing():
                        transport.close()
                except Exception:
                    logger.debug("Failed to close tool pipe transport", exc_info=True)

    return await asyncio.wait_for(_run(), timeout=timeout)


async def execute_tool(
    config: ToolConfig,
    tool_dir: Path,
    arguments: Dict[str, Any],
    *,
    env: Dict[str, str],
    on_health: Optional[HealthCallback] = None,
) -> Dict[str, Any]:
    """Run one tool invocation and normalize its outcome into a result dict.

    ``env`` is the complete environment for the child (the caller has already
    applied secrets and PATH). ``on_health`` replaces the hub's
    ``health_monitor.record_event`` calls; it is invoked in a worker thread so a
    slow store cannot stall concurrent tool I/O.
    """

    async def record_health(is_success: bool, error_message: Optional[str] = None) -> None:
        if on_health is None:
            return
        await asyncio.to_thread(on_health, is_success, error_message)

    entrypoint_path = (tool_dir / config.entrypoint).resolve()
    if not str(entrypoint_path).startswith(str(tool_dir)):
        return {"error": f"Entrypoint resolves outside tool directory"}
    if not entrypoint_path.is_file():
        return {"error": f"Entrypoint does not exist or is not a file"}

    cmd = []
    if config.runtime == "python":
        cmd = [sys.executable, str(entrypoint_path)]
    elif config.runtime == "go":
        bin_path = tool_dir / ".bin" / config.name
        cmd = [str(bin_path)]
    elif config.runtime == "ts":
        cmd = ["npx", "tsx", str(entrypoint_path)]
    elif config.runtime == "bash":
        cmd = ["bash", str(entrypoint_path)]
    else:
        return {"error": f"Unsupported runtime: {config.runtime}"}

    try:
        input_json = json.dumps(arguments).encode()
        # Imported here, not at module scope: core.tunables pulls in core.auth
        # (and the etcd client), which the edge has no use for. Resolution is
        # still the hub's identical tunable lookup.
        from core.tunables import resolve as resolve_tunable

        default_timeout = resolve_tunable("tool_execution_timeout")
        timeout = config.timeout_seconds if getattr(config, "timeout_seconds", None) else default_timeout

        # Only an explicitly configured policy may override the deployment
        # default; pydantic's "allow" default would otherwise mask
        # SANDBOX_NET_DEFAULT=none for every tool that never set the field.
        explicit_net = (
            config.network
            if "network" in getattr(config, "model_fields_set", ())
            else None
        )
        # Backend selection can re-probe on a stale cache (up to the probe
        # budget); keep that off the event loop so concurrent tool I/O is not
        # stalled behind a sandbox probe. The plan is plain data.
        plan = await asyncio.to_thread(
            sandbox.prepare_execution,
            cmd,
            tool_dir,
            env=env,
            network=explicit_net,
        )
        try:
            process = await asyncio.create_subprocess_exec(
                *plan.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(tool_dir),
                env=plan.env,
                start_new_session=True,
            )

            try:
                stdout, stdout_truncated, stderr, _stderr_truncated = await _communicate_bounded(process, input_json, timeout)
            except asyncio.TimeoutError:
                _kill_process_tree(process)
                await _wait_bounded(process)
                error_msg = f"Tool execution timed out after {timeout:.0f}s."
                await record_health(False, error_msg)
                return {"error": error_msg}
            except asyncio.CancelledError:
                _kill_process_tree(process)
                await _wait_bounded(process)
                raise
        finally:
            # rmtree is blocking; keep it off the event loop so concurrent tool
            # calls are not serialized behind cleanup.
            await asyncio.to_thread(plan.cleanup)

        # The sandbox helper emits a benign "supplementary groups retained"
        # warning on successful runs. It is not tool output, so keep it out of
        # the log (raw stderr still feeds error classification below).
        stderr_text = stderr.decode("utf-8", errors="replace").strip()
        loggable_stderr = "\n".join(
            line
            for line in stderr_text.splitlines()
            if not line.startswith("trellis-sandbox: warning:")
        ).strip()
        if loggable_stderr:
            if len(loggable_stderr) > 2048:
                logger.warning(f"Tool {config.name} stderr ({len(loggable_stderr)} chars): {loggable_stderr[:2048]}... [truncated]")
            else:
                logger.warning(f"Tool {config.name} stderr: {loggable_stderr}")

        if process.returncode != 0:
            stderr_str = stderr.decode("utf-8", errors="replace").strip()
            failure = sandbox.classify_failure(
                stderr_str, plan.backend, process.returncode
            )
            if failure:
                sandbox.log_failure_once(failure)
                # The cached verdict no longer matches reality; let the next
                # selection and /healthz re-probe (cooldown-bounded). A
                # `landlock_net_unsupported` refusal is a per-tool policy this
                # kernel cannot express, not a host-sandbox regression: the
                # re-probe could only reach the same ABI conclusion, so do not
                # spend it.
                if failure.code != "landlock_net_unsupported":
                    sandbox.invalidate_after_failure(failure.code)
                error_msg = (
                    f"Tool failed inside the {plan.backend.value} sandbox "
                    f"({failure.code}): {failure.detail}"
                )
                await record_health(False, error_msg)
                # A sandbox denial can never succeed on retry: skip the
                # TransientToolError path even if stderr happens to contain a
                # transient keyword.
                return {
                    "error": error_msg,
                    "stderr": stderr_str,
                    "sandbox": {
                        "backend": plan.backend.value,
                        "code": failure.code,
                        "remediation": failure.remediation,
                    },
                }

            error_msg = f"Tool exited with code {process.returncode}: {stderr_str}"
            await record_health(False, error_msg)
            config_retry = getattr(config, "retry_on_transient", True)

            # Identify common transient network errors in stderr
            transient_keywords = ["timeout", "connection refused", "econnrefused", "eof", "network is unreachable", "temporary failure"]
            if config_retry and any(keyword in stderr_str.lower() for keyword in transient_keywords):
                raise TransientToolError(error_msg)

            return {
                "error": error_msg,
                "stderr": stderr_str
            }

        try:
            result = json.loads(stdout.decode("utf-8", errors="replace"))
            # Global Safety Net: Safely truncate tool outputs exceeding 24k tokens (96,000 characters)
            stringified = json.dumps(result)
            if len(stringified) > 96000:
                logger.warning(f"Warning: Tool {config.name} output size ({len(stringified)} chars) exceeded safety limit of 96000 chars. Truncating...")
                result = {
                    "error": f"Global Safety Net: The tool '{config.name}' output exceeded the 24k token limit (96,000 characters). Output was safely truncated to prevent model context crashes.",
                    "partial_data_preview": stringified[:90000] + "... [TRUNCATED DUE TO SAFETY LIMITS]"
                }
            # A valid JSON payload cannot hit the stdout cap: truncation appends
            # a marker and breaks the parse, so the flag is only meaningful on
            # the JSONDecodeError path below.
            # A valid JSON output with an 'error' key is considered a User-Scoped Failure,
            # which does NOT trip the global circuit breaker. We count it as a success for global health.
            await record_health(True)
            return result
        except json.JSONDecodeError:
            # stdout is capped at MAX_STDOUT_BYTES, which is far above the 96k
            # JSON safety net: returning it whole (plus the same text in the
            # warning) would flood the model context, so bound both.
            decoded = stdout.decode("utf-8", errors="replace").strip()
            preview = decoded[:90000]
            truncated = stdout_truncated
            if len(decoded) > len(preview):
                preview += TRUNCATION_MARKER.decode()
                truncated = True
            error_msg = f"Output was not valid JSON: {decoded[:2048]}"
            await record_health(False, error_msg)
            return {"output": preview, "warning": error_msg, "truncated": truncated}

    except sandbox.SandboxUnavailable as e:
        error_msg = f"Sandbox unavailable ({e.code}): {e.detail or e.remediation}"
        await record_health(False, error_msg)
        return {
            "error": error_msg,
            "sandbox": {
                "backend": e.backend,
                "code": e.code,
                "remediation": e.remediation,
            },
        }
    except TransientToolError:
        raise
    except Exception as e:
        error_msg = f"Failed to execute tool: {str(e)}"
        await record_health(False, error_msg)
        return {"error": error_msg}
