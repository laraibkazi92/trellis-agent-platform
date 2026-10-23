#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Latency benchmark for the execution runner (``core.execution.runner``).

Measures the call a caller actually waits for: one blocking ``POST /v1/exec``
over the runner socket, from request to result. That spans container create,
start, the tool run and teardown, so its p50 is the "start-to-first-response"
number the v0.6 gate is about -- the client is blocking, so there is no earlier
byte to timestamp. ``ExecResult.duration_ms`` (container start to exit, without
create/remove) is reported alongside it as a breakdown.

Requires a running runner and a real tool in the workspace. Run it inside the
hub (or runner) image, where ``core/`` and ``/app/workspace`` are available:

    python scripts/runner_bench.py --tool text_stats \
        --input '{"text": "the quick brown fox"}' --runs 30 --concurrency 30

Add ``--agent NAME`` on an enforcing runner (``ENFORCE_AGENT_TOKENS=enforce``):
the bench mints a short-lived token for that agent so the call passes the same
check every production call passes. Without it an enforcing runner refuses with
``access_denied: agent token rejected (missing)``.

JSON goes to stdout and the human summary goes to stderr, so piping into
``jq`` stays clean. Exit codes: 0 every call succeeded, 1 at least one call
failed (the successful samples are still reported), 2 the tool or the runner
could not be used at all.
"""

import argparse
import asyncio
import json
import math
import os
import statistics
import sys
import time
import uuid
from typing import Any, Optional

from core import agent_token
from core.execution.client import (
    RunnerCallError,
    RunnerClient,
    RunnerUnavailable,
    socket_path,
)
from core.execution.contract import ExecRequest, ExecResult
from core.execution.spec import manifest_digest

DEFAULT_WORKSPACE_ROOT = "/app/workspace"
DEFAULT_RUNS = 30
DEFAULT_CONCURRENCY = 30
# Matches core.tool_runtime's default when the manifest does not override it.
DEFAULT_TOOL_TIMEOUT_S = 300


def _log(message: str) -> None:
    print(f"[runner-bench] {message}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# manifest resolution (same code the runner uses, so the digest matches)
# --------------------------------------------------------------------------- #


def _resolve_target(name: str) -> Optional[Any]:
    """Find the tool exactly as the runner does: on-disk manifest, no etcd.

    Imported lazily because ``core.execution.runner`` pulls the web stack in;
    a box that can reach the socket but not that import cannot compute the
    digest the runner will check, so it must fail loudly instead of guessing.
    """
    try:
        from core.execution.runner import resolve_target
    except ImportError as exc:
        raise RuntimeError(
            f"cannot import the runner's manifest resolver "
            f"({type(exc).__name__}: {exc}). Run this inside the hub or runner "
            "image, where core/ and the workspace are installed."
        ) from exc
    os.environ.setdefault("WORKSPACE_ROOT", DEFAULT_WORKSPACE_ROOT)
    return resolve_target(name)


def _deadline_ms(config: Any) -> int:
    seconds = getattr(config, "timeout_seconds", None)
    if not seconds:
        try:
            seconds = int(
                os.getenv("TOOL_EXECUTION_TIMEOUT", "") or DEFAULT_TOOL_TIMEOUT_S
            )
        except ValueError:
            seconds = DEFAULT_TOOL_TIMEOUT_S
    return max(1, int(float(seconds) * 1000))


# --------------------------------------------------------------------------- #
# measurement
# --------------------------------------------------------------------------- #


def _summary(samples: list[float]) -> dict[str, Any]:
    """p50/p95/mean/min/max over millisecond samples (nearest-rank p95)."""
    ordered = sorted(samples)

    def at(quantile: float) -> float:
        index = math.ceil(quantile * len(ordered)) - 1
        return ordered[max(0, min(len(ordered) - 1, index))]

    return {
        "count": len(ordered),
        "p50_ms": round(at(0.50), 1),
        "p95_ms": round(at(0.95), 1),
        "mean_ms": round(statistics.fmean(ordered), 1),
        "min_ms": round(ordered[0], 1),
        "max_ms": round(ordered[-1], 1),
    }


async def _one_call(socket: str, request: ExecRequest) -> tuple[float, ExecResult]:
    """One call as production makes it: a fresh client per call."""
    started = time.perf_counter()
    async with RunnerClient(socket=socket) as client:
        result = await client.exec(request)
    return (time.perf_counter() - started) * 1000.0, result


async def _phase(
    socket: str, request: ExecRequest, *, count: int, concurrency: int
) -> dict[str, Any]:
    """Run ``count`` calls with at most ``concurrency`` in flight at once."""
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one() -> tuple[float, ExecResult]:
        async with semaphore:
            return await _one_call(socket, request)

    started = time.perf_counter()
    outcomes = await asyncio.gather(
        *(one() for _ in range(count)), return_exceptions=True
    )
    wall_ms = (time.perf_counter() - started) * 1000.0

    latencies: list[float] = []
    server_ms: list[int] = []
    failures: list[dict[str, str]] = []
    for outcome in outcomes:
        # The runner going away mid-run invalidates the whole measurement.
        if isinstance(outcome, RunnerUnavailable):
            raise outcome
        if isinstance(outcome, RunnerCallError):
            failures.append({"code": outcome.code, "message": outcome.message})
            continue
        if isinstance(outcome, BaseException):
            failures.append(
                {"code": "internal", "message": f"{type(outcome).__name__}: {outcome}"}
            )
            continue
        elapsed, result = outcome
        if result.exit_code != 0:
            # The container ran, but a broken tool makes the timing useless as a
            # compatibility signal -- surface it instead of averaging it in.
            detail = (result.stderr or result.stdout or "").strip().splitlines()
            failures.append(
                {
                    "code": "tool_exit",
                    "message": f"exit {result.exit_code}: "
                    + (detail[-1][:300] if detail else "no output"),
                }
            )
            continue
        latencies.append(elapsed)
        server_ms.append(result.duration_ms)

    phase: dict[str, Any] = {
        "calls": count,
        "concurrency": concurrency,
        "wall_ms": round(wall_ms, 1),
        "failures": len(failures),
        "errors": failures[:10],
    }
    if latencies:
        phase.update(_summary(latencies))
        # Container-level time: start -> exit, excluding create/attach/remove.
        phase["runner"] = _summary([float(value) for value in server_ms])
    return phase


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/runner_bench.py",
        description=(
            "Benchmark POST /v1/exec through the runner socket against a real "
            "workspace tool. Requires a running runner and a built image."
        ),
    )
    parser.add_argument(
        "--tool",
        required=True,
        metavar="NAME",
        help=(
            "Registry tool name (a local tool with a manifest under WORKSPACE_ROOT)."
        ),
    )
    parser.add_argument(
        "--input",
        default="{}",
        metavar="JSON",
        help="Tool stdin as a JSON object (default: {}).",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        metavar="N",
        help=f"Calls per phase (default: {DEFAULT_RUNS}).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        metavar="N",
        help=(
            f"Maximum calls in flight in the concurrent phase (default: "
            f"{DEFAULT_CONCURRENCY}). Must not exceed RUNNER_MAX_CONTAINERS_PER_TOOL "
            "or RUNNER_MAX_CONTAINERS on the runner, or calls are refused with 429."
        ),
    )
    parser.add_argument(
        "--socket",
        default=socket_path(),
        metavar="PATH",
        help=(
            "Runner Unix socket (default: RUNNER_SOCKET, "
            "else /run/trellis/runner.sock)."
        ),
    )
    parser.add_argument(
        "--agent",
        metavar="NAME",
        help=(
            "Agent to call as. Required when the runner enforces agent tokens "
            "(ENFORCE_AGENT_TOKENS=enforce): the bench mints a short-lived token for "
            "this agent with AGENT_TOKEN_SECRET. The agent must have a manifest under "
            "WORKSPACE_ROOT/agents, because the runner resolves its allowlist."
        ),
    )
    return parser


def _human_line(report: dict[str, Any]) -> str:
    def fmt(phase: dict[str, Any]) -> str:
        if not phase.get("count"):
            return "no successful calls"
        return (
            f"p50={phase['p50_ms']:.0f}ms p95={phase['p95_ms']:.0f}ms "
            f"mean={phase['mean_ms']:.0f}ms max={phase['max_ms']:.0f}ms"
        )

    sequential = report["sequential"]
    concurrent = report["concurrent"]
    return (
        f"tool={report['tool']} runtime={report['runtime'] or '?'} | "
        f"sequential n={sequential['calls']}: {fmt(sequential)} "
        f"wall={sequential['wall_ms']:.0f}ms | "
        f"concurrent n={concurrent['calls']} x{concurrent['concurrency']}: "
        f"{fmt(concurrent)} wall={concurrent['wall_ms']:.0f}ms"
    )


async def _run(
    args: argparse.Namespace, target: Any, input_json: str
) -> dict[str, Any]:
    request = ExecRequest(
        kind="tool",
        target=target.config.name,
        manifest_digest=manifest_digest(target.config),
        agent=args.agent,
        agent_token=args.agent_token or None,
        run_id=f"bench-{uuid.uuid4().hex[:12]}",
        env={},
        input=input_json,
        deadline_ms=_deadline_ms(target.config),
    )

    async with RunnerClient(socket=args.socket) as client:
        health = await client.healthz()
    if not health.ok:
        _log(f"runner reports unhealthy: {health.detail}")

    _log(
        f"tool={target.config.name} suite={target.suite} "
        f"runtime={health.runtime or '?'} "
        f"sequential={args.runs} concurrent={args.concurrency}"
    )
    sequential = await _phase(args.socket, request, count=args.runs, concurrency=1)
    _log("sequential done: " + json.dumps(sequential))
    concurrent = await _phase(
        args.socket, request, count=args.runs, concurrency=args.concurrency
    )
    _log("concurrent done: " + json.dumps(concurrent))

    return {
        "tool": target.config.name,
        "suite": target.suite,
        "runtime": health.runtime,
        "container_runtime": getattr(target.config, "container_runtime", None),
        "image": health.image,
        "socket": args.socket,
        "input": input_json,
        "manifest_digest": request.manifest_digest,
        "runs": args.runs,
        "concurrency": args.concurrency,
        "sequential": sequential,
        "concurrent": concurrent,
        "ok": not (sequential["failures"] or concurrent["failures"]),
    }


def main(argv: Optional[list[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.runs < 1 or args.concurrency < 1:
        _log("--runs and --concurrency must be at least 1")
        return 2

    try:
        payload = json.loads(args.input)
    except ValueError as exc:
        _log(f"--input is not valid JSON: {exc}")
        return 2
    if not isinstance(payload, dict):
        _log("--input must be a JSON object (the tool's stdin protocol)")
        return 2
    input_json = json.dumps(payload)

    target: Optional[Any]
    try:
        target = _resolve_target(args.tool)
    except RuntimeError as exc:
        _log(f"cannot resolve {args.tool!r}: {exc}")
        return 2
    if target is None:
        root = os.getenv("WORKSPACE_ROOT") or DEFAULT_WORKSPACE_ROOT
        _log(
            f"unknown tool {args.tool!r}: no local tool with that name under "
            f"{root}/tools (a `remote` tool runs on its edge and is not served "
            "by this runner)"
        )
        return 2
    _log(f"resolved {target.config.name} from {target.path}")

    args.agent_token = ""
    if args.agent:
        try:
            args.agent_token = agent_token.mint(
                args.agent, user_id=os.getenv("TRELLIS_UID") or "bench"
            )
        except agent_token.AgentTokenError as exc:
            _log(
                f"cannot mint an agent token for {args.agent!r}: {exc.message}. "
                "Set AGENT_TOKEN_SECRET to the runner's value."
            )
            return 2

    try:
        report = asyncio.run(_run(args, target, input_json))
    except RunnerUnavailable as exc:
        _log(
            f"runner unreachable at {args.socket}: {exc.message}. Is the runner "
            "service up and is its socket mounted here?"
        )
        return 2
    except RunnerCallError as exc:
        hint = ""
        if exc.code == "capacity_exhausted":
            hint = (
                " Raise RUNNER_MAX_CONTAINERS_PER_TOOL / RUNNER_MAX_CONTAINERS on "
                "the runner, or lower --concurrency."
            )
        elif exc.code == "manifest_stale":
            hint = " Re-run the registry sync so etcd's manifest matches the files."
        _log(f"runner refused the call ({exc.code}): {exc.message}.{hint}")
        return 2

    if report["ok"]:
        _log(_human_line(report))
    else:
        errors = report["sequential"]["errors"] + report["concurrent"]["errors"]
        first = errors[0] if errors else {}
        _log(
            _human_line(report)
            + f" | FAILED calls: sequential={report['sequential']['failures']} "
            f"concurrent={report['concurrent']['failures']}"
            + (f" ({first.get('code')}: {first.get('message')})" if first else "")
        )

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
