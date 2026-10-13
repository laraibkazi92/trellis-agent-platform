# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Console backend that strips framework secrets from spawned shell environments.

`pydantic_ai_backends.LocalBackend` spawns shell children with no `env` argument,
so they inherit the host process's whole environment (SESSION_SECRET,
ENCRYPTION_KEY, …). `SanitizedLocalBackend` mirrors the library's `execute` /
`async_execute` / `_grep_ripgrep` bodies but passes `env=sanitized_env()`.
"""

import asyncio
import contextlib
import subprocess
import sys
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
