# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""In-memory stand-in for ``core.execution.client.RunnerClient``.

Callers that hand work to the runner (the agent console, the ``background_script``
workflow path) are tested by pinning the request they build; the socket, the HTTP
layer and the container are the runner's business. A test constructs one of these
with the result it wants and monkeypatches the module's ``RunnerClient`` name to a
factory returning it.
"""

from typing import Optional

from core.execution.client import RunnerCallError, RunnerUnavailable
from core.execution.contract import ExecRequest, ExecResult


class FakeRunnerClient:
    """Records every ``ExecRequest``; answers with a canned result or raises."""

    def __init__(
        self,
        result: Optional[ExecResult] = None,
        error: Optional[BaseException] = None,
        *,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
    ) -> None:
        self.result = result or ExecResult(
            exit_code=exit_code, stdout=stdout, stderr=stderr
        )
        self.error = error
        self.requests: list[ExecRequest] = []
        self.closed = False

    async def __aenter__(self) -> "FakeRunnerClient":
        return self

    async def __aexit__(self, *exc_info) -> bool:
        self.closed = True
        return False

    async def exec(self, request: ExecRequest) -> ExecResult:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.result


def unreachable() -> RunnerUnavailable:
    """The socket/connection failure a stopped runner produces."""
    return RunnerUnavailable("runner is unreachable at /run/trellis/runner.sock")


def timeout_error() -> RunnerCallError:
    """The structured error the runner returns when a call outlives its deadline."""
    return RunnerCallError("timeout", "runner did not answer within 910s", 504)
