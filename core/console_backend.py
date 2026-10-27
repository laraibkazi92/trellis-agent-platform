# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Console backends: framework code operating on an agent's own files.

`pydantic_ai_backends.LocalBackend` spawns shell children with no `env` argument, so
they inherit the host process's whole environment (SESSION_SECRET, ENCRYPTION_KEY, …).
`SanitizedLocalBackend` mirrors the library's `execute` / `async_execute` /
`_grep_ripgrep` bodies but passes `env=sanitized_env()`.

`RunnerConsoleBackend` also moves `execute` off the host: the command runs as a
throwaway runner container (``network none``, scratch ``/workspace``), so the agent's
shell cannot see the framework's filesystem. The other console tools stay in-process
with a ``reports/<agent>`` root.
"""

import asyncio
import contextlib
import contextvars
import logging
import subprocess
import sys
import threading
from pathlib import Path

from pydantic_ai_backends.backends.local import (
    DEFAULT_EXECUTE_TIMEOUT,
    GREP_TIMEOUT_SECONDS,
    LocalBackend,
    _execute_response,
    _kill_process_tree,
    _parse_grep_lines,
    shell_argv,
)
from pydantic_ai_backends.types import ExecuteResponse, GrepMatch

from core.env_sanitize import sanitized_env

logger = logging.getLogger(__name__)



class SanitizedLocalBackend(LocalBackend):
    """LocalBackend whose shell subprocesses get sanitized_env() instead of inheriting
    the host process's full environment (which holds SESSION_SECRET/ENCRYPTION_KEY/…)."""

    def execute(self, command: str, timeout: int | None = None) -> ExecuteResponse:
        denial = self._execute_denial(command)
        if denial is not None:
            return ExecuteResponse(output=f"Error: {denial}", exit_code=1, truncated=False)

        try:
            result = subprocess.run(
                shell_argv(command),
                cwd=self._root,
                capture_output=True,
                text=True,
                timeout=timeout if timeout is not None else DEFAULT_EXECUTE_TIMEOUT,
                env=sanitized_env(),
            )
        except subprocess.TimeoutExpired:
            return ExecuteResponse(
                output="Error: Command timed out", exit_code=124, truncated=False
            )
        except Exception as e:
            return ExecuteResponse(output=f"Error: {e}", exit_code=1, truncated=False)

        return _execute_response(result.stdout + result.stderr, result.returncode)

    async def async_execute(self, command: str, timeout: int | None = None) -> ExecuteResponse:
        denial = self._execute_denial(command)
        if denial is not None:
            return ExecuteResponse(output=f"Error: {denial}", exit_code=1, truncated=False)

        try:
            process = await asyncio.create_subprocess_exec(
                *shell_argv(command),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self._root,
                env=sanitized_env(),
                # New session so the whole group can be killed on Unix; on
                # Windows the `cmd /c` lifecycle already takes the tree down.
                start_new_session=(sys.platform != "win32"),
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout if timeout is not None else DEFAULT_EXECUTE_TIMEOUT,
                )
            except asyncio.CancelledError:
                _kill_process_tree(process)
                # Shielded so a second cancel cannot leave the pipes dangling.
                with contextlib.suppress(BaseException):
                    await asyncio.shield(asyncio.ensure_future(process.communicate()))
                raise
            except asyncio.TimeoutError:
                _kill_process_tree(process)
                with contextlib.suppress(BaseException):
                    await process.communicate()
                return ExecuteResponse(
                    output="Error: Command timed out", exit_code=124, truncated=False
                )

            output = stdout.decode("utf-8", errors="replace")
            output += stderr.decode("utf-8", errors="replace")
            return _execute_response(output, process.returncode)
        except Exception as e:
            return ExecuteResponse(output=f"Error: {e}", exit_code=1, truncated=False)

    def _grep_ripgrep(
        self, pattern: str, search_path: Path, glob: str | None, ignore_hidden: bool
    ) -> list[GrepMatch] | str:
        # Mirrors LocalBackend._grep_ripgrep, but the `rg` child must not inherit the
        # host process env (the library spawns it with no `env=`).
        argv = ["rg", "--line-number", "--no-heading", pattern]
        if glob:
            argv.extend(["--glob", glob])
        if not ignore_hidden:
            argv.append("--hidden")
        argv.append(".")

        try:
            result = subprocess.run(
                argv,
                cwd=search_path,
                capture_output=True,
                text=True,
                timeout=GREP_TIMEOUT_SECONDS,
                env=sanitized_env(),
            )
        except subprocess.TimeoutExpired:
            return "Error: Search timed out"
        except OSError as e:
            return f"Error: {e}"

        base_path = search_path.parent if search_path.is_file() else search_path
        matches: list[GrepMatch] = []
        for relative_path, line_number, line in _parse_grep_lines(result.stdout):
            full_path = (base_path / relative_path).resolve()
            try:
                self._resolve(str(full_path))
            except PermissionError:
                continue
            if self._hidden_from_grep(str(full_path)):
                continue
            matches.append(GrepMatch(path=str(full_path), line_number=line_number, line=line))
        return matches


class RunnerConsoleBackend(SanitizedLocalBackend):
    """`execute` runs in a runner container; file tools stay in-process.

    The framework's own shell is not a boundary: `bash -lc` inherits the host
    filesystem, network and (sanitized) environment. Sending the command to the
    runner gives it a throwaway tmpfs `/workspace`, `network none`, its own cgroup
    limits, and no path back to the hub's code, registries or credentials. Failures
    are returned as an `ExecuteResponse`, never raised: a runner outage must not
    abort the agent turn.
    """

    def __init__(
        self,
        root_dir: str | Path | None = None,
        enable_execute: bool = True,
        *,
        client_factory=None,
    ) -> None:
        super().__init__(root_dir=root_dir, enable_execute=enable_execute)
        # Seam for tests; ``RunnerClient`` is imported lazily otherwise so importing
        # the console backend stays cheap.
        self._client_factory = client_factory

    def execute(self, command: str, timeout: int | None = None) -> ExecuteResponse:
        denial = self._execute_denial(command)
        if denial is not None:
            return ExecuteResponse(output=f"Error: {denial}", exit_code=1, truncated=False)

        seconds = timeout if timeout is not None else DEFAULT_EXECUTE_TIMEOUT
        return _run_sync(self._run(command, seconds))

    async def async_execute(self, command: str, timeout: int | None = None) -> ExecuteResponse:
        denial = self._execute_denial(command)
        if denial is not None:
            return ExecuteResponse(output=f"Error: {denial}", exit_code=1, truncated=False)

        seconds = timeout if timeout is not None else DEFAULT_EXECUTE_TIMEOUT
        return await self._run(command, seconds)

    async def _run(self, command: str, timeout: float) -> ExecuteResponse:
        """Send one ``kind="console"`` exec and map it onto the local response shape."""
        from core.agent_token import refresh
        from core.auth import agent_token_var
        from core.execution.contract import ExecRequest
        from core.tool_gate import deny_reason

        # Pre-runner authorization: the runner only verifies the token, so the process
        # that owns the agent runtime decides whether this run may shell out at all.
        # A registry failure here fails CLOSED and still returns an ExecuteResponse:
        # an access-check outage must never raise out of the agent's shell tool.
        try:
            denial = await deny_reason("execute", surface="host")
        except Exception as exc:
            logger.exception("console: access check failed")
            return ExecuteResponse(
                output=f"Error: access check failed ({exc})", exit_code=1, truncated=False
            )
        if denial is not None:
            return ExecuteResponse(output=f"Error: {denial}", exit_code=1, truncated=False)


        # No identity in the body: the token carries the caller's user id, email and
        # run id, and the runner builds TRELLIS_USER_* from its verified claims.
        try:
            client = self._make_client()
            async with client as runner:
                result = await runner.exec(
                    ExecRequest(
                        kind="console",
                        target="console",
                        command=command,
                        env={},
                        agent_token=refresh(agent_token_var.get()),
                        deadline_ms=max(1, int(timeout * 1000)),
                    )
                )
        except Exception as exc:
            # Same shaped error as the local backend: the model sees a failed command.
            if getattr(exc, "code", None) == "timeout":
                return ExecuteResponse(output="Error: Command timed out", exit_code=124, truncated=False)
            return ExecuteResponse(
                output=f"Error: {_runner_message(exc)}", exit_code=1, truncated=False
            )

        return _execute_response(result.stdout + result.stderr, result.exit_code)

    def _make_client(self):
        if self._client_factory is not None:
            return self._client_factory()
        from core.execution.client import RunnerClient

        return RunnerClient()


def _runner_message(exc: BaseException) -> str:
    """A short, non-secret failure line for the model."""
    message = getattr(exc, "message", None) or str(exc) or type(exc).__name__
    return f"console command could not run ({message})"


class _OneShotThread(threading.Thread):
    """Runs one coroutine to completion on a private event loop.

    The caller's context is copied in: the run's agent token lives in a contextvar,
    and a bare thread starts with an empty context -- which would send a tokenless
    (and therefore refused) request to the runner.
    """

    def __init__(self, coro, context=None) -> None:
        super().__init__(daemon=True)
        self._coro = coro
        self._context = context
        self._result = None
        self._error: BaseException | None = None

    def run(self) -> None:
        try:
            if self._context is not None:
                self._result = self._context.run(asyncio.run, self._coro)
            else:
                self._result = asyncio.run(self._coro)
        except BaseException as exc:  # re-raised in the calling thread
            self._error = exc

    def result(self):
        self.join()
        if self._error is not None:
            raise self._error
        return self._result


def _run_sync(coro):
    """Run ``coro`` whether or not this thread already owns a running loop.

    ``execute`` is called by the library's sync tool path, which may be on the
    event-loop thread. Nesting ``asyncio.run`` there raises, so a running loop gets
    a one-shot thread with its own loop instead -- carrying this context with it, so
    the run's agent token reaches the request.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    thread = _OneShotThread(coro, contextvars.copy_context())
    thread.start()
    return thread.result()
