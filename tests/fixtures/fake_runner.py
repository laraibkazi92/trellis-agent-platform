# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""In-memory stand-in for ``core.execution.client.RunnerClient``.

Callers that hand work to the runner (the agent console, the ``background_script``
workflow path) are tested by pinning the request they build; the socket, the HTTP
layer and the container are the runner's business. A test constructs one of these
with the result it wants and monkeypatches the module's ``RunnerClient`` name to a
factory returning it.

The workflow lifecycle (v0.7.2 R3/R4) needs three more knobs: ``stop_run`` (what
``/v1/stop`` answers, or the error it raises) and ``capacity_until_call`` (the first N
exec attempts are refused with the runner's retryable 429).
"""

from typing import Optional

from core.execution.client import RunnerCallError, RunnerUnavailable
from core.execution.contract import ExecRequest, ExecResult, StopResult


class FakeRunnerClient:
    """Records every ``ExecRequest`` and stop; answers with a canned result or raises."""

    def __init__(
        self,
        result: Optional[ExecResult] = None,
        error: Optional[BaseException] = None,
        *,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        stop_result: Optional[StopResult] = None,
        stop_error: Optional[BaseException] = None,
        capacity_until_call: int = 0,
    ) -> None:
        self.result = result or ExecResult(
            exit_code=exit_code, stdout=stdout, stderr=stderr
        )
        self.error = error
        self.stop_result = stop_result
        self.stop_error = stop_error
        self.capacity_until_call = capacity_until_call
        self.requests: list[ExecRequest] = []
        self.stops: list[str] = []
        self.closed = False

    async def __aenter__(self) -> "FakeRunnerClient":
        return self

    async def __aexit__(self, *exc_info) -> bool:
        self.closed = True
        return False

    async def exec(self, request: ExecRequest) -> ExecResult:
        self.requests.append(request)
        if len(self.requests) <= self.capacity_until_call:
            raise capacity_exhausted()
        if self.error is not None:
            raise self.error
        return self.result

    async def stop_run(self, run_id: str) -> StopResult:
        self.stops.append(run_id)
        if self.stop_error is not None:
            raise self.stop_error
        # Default: the run's container was still there and is now gone. A test that
        # needs "already finished" passes StopResult(stopped=0).
        return self.stop_result or StopResult(run_id=run_id, stopped=1)


def unreachable() -> RunnerUnavailable:
    """The socket/connection failure a stopped runner produces."""
    return RunnerUnavailable("runner is unreachable at /run/trellis/runner.sock")


def timeout_error() -> RunnerCallError:
    """The structured error the runner returns when a call outlives its deadline."""
    return RunnerCallError("timeout", "runner did not answer within 910s", 504)


def capacity_exhausted(per_target: int = 1, global_limit: int = 2) -> RunnerCallError:
    """The 429 the runner answers when no container slot is free (retryable)."""
    return RunnerCallError(
        "capacity_exhausted",
        f"no free container slot for 'demo-inventory' (per-target limit "
        f"{per_target}, global limit {global_limit})",
        429,
    )
