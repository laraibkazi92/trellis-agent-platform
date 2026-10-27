# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tool execution for the hub and the edge proxy — container per call.

This module is the execution core of ``core.hub`` with every hub-only concern
(etcd, FastMCP, identity-scoped env injection, health recording) removed. The
edge (``core.proxy``) must run tools with exactly the semantics the hub has --
same request shape, same timeouts, same result normalisation -- but it cannot
import ``core.hub``: that module builds an ``IdentityManager`` at import time
and has no etcd to talk to.

There is exactly one execution path: the call goes to the runner service
(``core.execution.client.RunnerClient``), which starts one container per call.
The caller owns the environment: build it (secrets, PATH, framework tokens) and
pass it in, and only keys the manifest declares cross the socket -- the runner
re-sanitizes the base environment and rejects anything undeclared. Health events
are reported through ``on_health`` so the hub keeps recording them while the
edge, which has no health store, passes ``None``.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

from core.models import ToolConfig

logger = logging.getLogger(__name__)

# JSON safety net: a result larger than this is summarised instead of handed to
# the model. Mirrored by the container stdio/exec paths.
MAX_RESULT_CHARS = 96_000
TRUNCATION_MARKER = b"\n...[output truncated by hub]"

# Injected env names a tool must never be able to override: a secret stored under
# one of these would otherwise rewrite the interpreter's own search path.
RESTRICTED_ENV_VARS = {"PATH", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV", "HOSTALIASES",
                       "AGENT_TOKEN_SECRET", "RUNNER_TOKEN", "RUNNER_SOCKET", "EDGE_PRIVATE_KEY_PATH"}

# Health callback: (is_success, error_message). Runs in a worker thread.
HealthCallback = Callable[[bool, Optional[str]], None]


class TransientToolError(Exception):
    """A failure worth retrying (stamina owns the retry budget)."""


async def _execute_in_container(
    config: ToolConfig,
    arguments: Dict[str, Any],
    *,
    env: Dict[str, str],
    timeout: float,
    agent_token: Optional[str] = None,
    identity: Optional[Mapping[str, Any]] = None,
    record_health,
) -> Dict[str, Any]:
    """Run the tool as its own container via the runner.

    Only declared env keys cross the socket; the runner re-sanitizes the base
    environment and rejects anything the manifest does not declare.

    Identity has two carriers, one per runner role, never both on one request:
    the **central** hub sends ``agent_token`` and the runner derives the caller's
    user id, email, groups, agent and run id from the verified claims, so the body
    carries none; the **edge** has no signing key, so the proxy forwards the relay-
    derived ``identity`` (the claims the relay verified on its side of the tunnel)
    and the edge runner takes it from this authenticated request instead.
    """
    from core.execution.client import RunnerCallError, RunnerClient, RunnerUnavailable
    from core.execution.contract import ExecRequest, RunIdentity
    from core.execution.spec import declared_env_keys, manifest_digest

    try:
        input_json = json.dumps(arguments)
        declared = declared_env_keys(config)
        request = ExecRequest(
            kind="tool",
            target=config.name,
            manifest_digest=manifest_digest(config),
            env={k: v for k, v in env.items() if k in declared},
            agent_token=agent_token,
            identity=RunIdentity.from_frame(identity),
            input=input_json,
            deadline_ms=max(1, int(timeout * 1000)),
        )
        async with RunnerClient() as client:
            result = await client.exec(request)
    except RunnerCallError as exc:
        if exc.retryable:
            raise TransientToolError(
                f"Tool '{config.name}' could not get a container slot: {exc.message}"
            ) from exc
        if exc.code == "timeout":
            error_msg = f"Tool execution timed out after {timeout:.0f}s."
            await record_health(False, error_msg)
            return {"error": error_msg}
        if exc.code in {"runner_path_mismatch", "runtime_missing", "image_missing"}:
            error_msg = f"Sandbox unavailable ({exc.code}): {exc.message}"
            await record_health(False, error_msg)
            return {
                "error": error_msg,
                "sandbox": {
                    "backend": "container",
                    "code": exc.code,
                    "remediation": "Run scripts/runner_preflight.py on the runner host.",
                },
            }
        error_msg = f"Tool '{config.name}' could not run ({exc.code}): {exc.message}"
        await record_health(False, error_msg)
        return {"error": error_msg}
    except RunnerUnavailable as exc:
        error_msg = f"Sandbox unavailable (runner_unavailable): {exc.message}"
        await record_health(False, error_msg)
        return {
            "error": error_msg,
            "sandbox": {
                "backend": "container",
                "code": "runner_unavailable",
                "remediation": "Check that the runner service is up and its socket is mounted.",
            },
        }

    return await _finalize_result(
        config,
        result.stdout.encode("utf-8"),
        result.stderr.encode("utf-8"),
        result.exit_code,
        result.stdout_truncated,
        record_health=record_health,
    )


async def _finalize_result(
    config: ToolConfig,
    stdout: bytes,
    stderr: bytes,
    returncode: int,
    stdout_truncated: bool,
    *,
    record_health,
) -> Dict[str, Any]:
    """Shared result normalisation for every container call."""
    stderr_text = stderr.decode("utf-8", errors="replace").strip()
    if stderr_text:
        if len(stderr_text) > 2048:
            logger.warning(f"Tool {config.name} stderr ({len(stderr_text)} chars): {stderr_text[:2048]}... [truncated]")
        else:
            logger.warning(f"Tool {config.name} stderr: {stderr_text}")

    if returncode != 0:
        stderr_str = stderr.decode("utf-8", errors="replace").strip()
        error_msg = f"Tool exited with code {returncode}: {stderr_str}"
        await record_health(False, error_msg)
        config_retry = getattr(config, "retry_on_transient", True)
        transient_keywords = ["timeout", "connection refused", "econnrefused", "eof", "network is unreachable", "temporary failure"]
        if config_retry and any(keyword in stderr_str.lower() for keyword in transient_keywords):
            raise TransientToolError(error_msg)
        return {"error": error_msg, "stderr": stderr_str}

    try:
        result = json.loads(stdout.decode("utf-8", errors="replace"))
        stringified = json.dumps(result)
        if len(stringified) > MAX_RESULT_CHARS:
            logger.warning(f"Warning: Tool {config.name} output size ({len(stringified)} chars) exceeded safety limit of {MAX_RESULT_CHARS} chars. Truncating...")
            result = {
                "error": f"Global Safety Net: The tool '{config.name}' output exceeded the 24k token limit (96,000 characters). Output was safely truncated to prevent model context crashes.",
                "partial_data_preview": stringified[:90000] + "... [TRUNCATED DUE TO SAFETY LIMITS]",
            }
        await record_health(True)
        return result
    except json.JSONDecodeError:
        decoded = stdout.decode("utf-8", errors="replace").strip()
        preview = decoded[:90000]
        truncated = stdout_truncated
        if len(decoded) > len(preview):
            preview += TRUNCATION_MARKER.decode()
            truncated = True
        error_msg = f"Output was not valid JSON: {decoded[:2048]}"
        await record_health(False, error_msg)
        return {"output": preview, "warning": error_msg, "truncated": truncated}


async def execute_tool(
    config: ToolConfig,
    tool_dir: Path,
    arguments: Dict[str, Any],
    *,
    env: Dict[str, str],
    on_health: Optional[HealthCallback] = None,
    agent_token: Optional[str] = None,
    identity: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Run one tool invocation and normalize its outcome into a result dict.

    ``env`` is the complete environment for the child (the caller has already
    applied secrets, PATH and the caller's ``TRELLIS_USER_*`` identity); only
    declared keys are forwarded. ``on_health`` replaces the hub's
    ``health_monitor.record_event`` calls; it is invoked in a worker thread so a
    slow store cannot stall concurrent tool I/O.

    ``agent_token`` is the hub's carrier (a central runner verifies it); ``identity``
    is the edge's, because the edge has no token to send and the relay already
    verified the caller. Exactly one of them is set by any given caller.

    Execution always happens in the runner's container for this call; the
    in-process sandbox backends are gone. ``tool_dir`` is validated here so a
    missing or escaping entrypoint fails without a runner round trip.
    """
    async def record_health(is_success: bool, error_message: Optional[str] = None) -> None:
        if on_health is None:
            return
        await asyncio.to_thread(on_health, is_success, error_message)

    tool_dir = Path(tool_dir).resolve()
    entrypoint_path = (tool_dir / config.entrypoint).resolve()
    # is_relative_to, not a string prefix: "tools/foo" must not accept "tools/foo-evil".
    if not entrypoint_path.is_relative_to(tool_dir):
        return {"error": "Entrypoint resolves outside tool directory"}
    if not entrypoint_path.is_file():
        return {"error": "Entrypoint does not exist or is not a file"}

    try:
        # Imported here, not at module scope: core.tunables pulls in core.auth
        # (and the etcd client), which the edge has no use for. Resolution is
        # still the hub's identical tunable lookup.
        from core.tunables import resolve as resolve_tunable

        default_timeout = resolve_tunable("tool_execution_timeout")
        timeout = config.timeout_seconds if getattr(config, "timeout_seconds", None) else default_timeout

        return await _execute_in_container(
            config,
            arguments,
            env=env,
            timeout=timeout,
            agent_token=agent_token,
            identity=identity,
            record_health=record_health,
        )
    except TransientToolError:
        raise
    except Exception as e:
        error_msg = f"Failed to execute tool: {str(e)}"
        await record_health(False, error_msg)
        return {"error": error_msg}
