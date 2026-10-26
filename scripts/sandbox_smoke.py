#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Smoke harness for the tool-execution path.

Runs **inside the hub container** (it needs ``/app/workspace`` and this edge's
runner socket). There is exactly one execution path -- the runner starts one
container per call -- so the harness has exactly one leg: it registers a
throwaway tool suite, executes it through ``core.execution.client.RunnerClient``
and asserts the container contract (JSON stdin round-trip, no egress under
``network: none``, writable tmpfs ``HOME``/``TMPDIR``). ``--tool`` additionally
runs registered hub tools through ``hub.run_tool``, i.e. the same path MCP
callers use.

Tools run without an identity, so prefer read-only tools in smoke runs.
Exit codes are 0 for a fully green run, 1 for any failed check, and 2 when the
environment itself is not usable (no ``/app/workspace``, no runner, or the
runner refused the probe).
"""

import argparse
import asyncio
import json
import shutil
import sys
import uuid
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

WORKSPACE = Path("/app/workspace")
TEST_TEXT = "the quick brown fox jumps over the lazy dog"

# --- container probes ------------------------------------------------------ #
# The runner only executes registered tools, so the probe is a throwaway suite:
# it runs inside a real tool container, reads its JSON on stdin and prints one
# report with all three contract facts.
CONTAINER_PROBE_TOOL = "trellis_smoke_probe"
CONTAINER_PROBE_INPUT = {"echo": "the quick brown fox", "n": 3}
CONTAINER_PROBE_ENTRY = {
    "name": CONTAINER_PROBE_TOOL,
    "version": "0.0.1",
    "description": (
        "Written by scripts/sandbox_smoke.py; removed after the run."
    ),
    "runtime": "python",
    "entrypoint": "probe.py",
    # Deny-by-default on purpose: the probe proves `none` really means no egress.
    "network": "none",
}

CONTAINER_PROBE_SOURCE = r'''
import json, os, socket, sys


def tcp(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "connected"
    except OSError as exc:
        return "blocked:" + type(exc).__name__


def dns(host, port):
    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return "unresolved:" + type(exc).__name__
    return "resolved"


def write_probe(directory):
    if not directory:
        return {"path": "", "writable": False}
    try:
        with open(os.path.join(directory, "trellis-smoke-probe"), "w") as handle:
            handle.write("ok")
    except OSError as exc:
        return {"path": directory, "writable": False, "error": type(exc).__name__}
    return {"path": directory, "writable": True}


def tmpfs_on(mountpoint):
    try:
        with open("/proc/mounts", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == mountpoint:
                    return fields[2] == "tmpfs"
    except OSError:
        pass
    return False


payload = json.load(sys.stdin)
print(json.dumps({
    "echo": payload,
    "home": write_probe(os.environ.get("HOME", "")),
    "tmpdir": write_probe(os.environ.get("TMPDIR", "")),
    "tmp_is_tmpfs": tmpfs_on("/tmp"),
    "network": {
        "1.1.1.1:443": tcp("1.1.1.1", 443),
        "169.254.169.254:80": tcp("169.254.169.254", 80),
        "example.com:443": dns("example.com", 443),
    },
}))
'''


def _log(message):
    print(f"[sandbox-smoke] {message}", file=sys.stderr, flush=True)


def _short(value, limit=400):
    text = (value or "").strip()
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def _observed(result):
    """Stdout plus stderr, for reports and failure messages."""
    stdout = (result.get("stdout") or "").strip()
    stderr = (result.get("stderr") or "").strip()
    if stdout and stderr:
        return f"{stdout} | stderr: {stderr}"
    return stdout or stderr


def check_tools(names):
    """Execute registered hub tools through ``hub.run_tool`` (same path as MCP)."""
    errors = []
    results = {}

    try:
        from core import hub
    except Exception as exc:  # noqa: BLE001 - report, do not traceback
        return {"ok": False, "results": {}}, [
            f"could not import core.hub: {type(exc).__name__}: {exc}"
        ]

    try:
        configs = hub.load_tool_configs()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "results": {}}, [
            f"could not load tool configs: {type(exc).__name__}: {exc}"
        ]
    if configs is None:
        return {"ok": False, "results": {}}, ["could not read the tool registry (etcd unavailable)"]

    for name in names:
        _log(f"tool: {name}")
        entry = configs.get(name)
        if entry is None:
            results[name] = {"ok": False, "error": "not registered in the tool registry"}
            errors.append(f"tool {name} is not registered")
            continue

        config, tool_dir = entry
        arguments = {"text": TEST_TEXT} if name == "text_stats" else {}
        try:
            result = asyncio.run(hub.run_tool(config, tool_dir, arguments))
        except Exception as exc:  # noqa: BLE001
            results[name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            errors.append(f"tool {name} raised {type(exc).__name__}: {exc}")
            continue

        ok = isinstance(result, dict) and "error" not in result
        results[name] = {
            "ok": ok,
            "result": _short(json.dumps(result, sort_keys=True, default=str), 1000),
        }
        if not ok:
            errors.append(f"tool {name} returned an error: {results[name]['result']}")

    return {"ok": not errors, "results": results}, errors


class ContainerProbeUnavailable(RuntimeError):
    """The container path cannot run: no runner, or the runner refused."""


def check_container(timeout):
    """The execution contract, from inside a real tool container.

    Three facts, all through ``RunnerClient`` (a blocking ``POST /v1/exec``):
    a JSON stdin/stdout round-trip, no egress under ``network: none``, and a
    writable tmpfs ``HOME``/``TMPDIR``. The probe is a throwaway tool suite
    under ``workspace/tools``: the runner executes registered manifests, so
    there is no other way to get code into its container.
    """
    try:
        from core.execution.client import (
            RunnerCallError,
            RunnerClient,
            RunnerUnavailable,
        )
        from core.execution.contract import ExecRequest
        from core.execution.spec import manifest_digest
        from core.models import ToolConfig
    except ImportError as exc:  # reported, not a traceback
        raise ContainerProbeUnavailable(
            f"core.execution is not importable ({type(exc).__name__}: {exc})"
        ) from exc

    suite = WORKSPACE / "tools" / f"trellis-smoke-probe-{uuid.uuid4().hex[:8]}"
    try:
        suite.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise ContainerProbeUnavailable(f"cannot create {suite}: {exc}") from exc
    try:
        (suite / "probe.py").write_text(CONTAINER_PROBE_SOURCE, encoding="utf-8")
        (suite / "tool.yaml").write_text(
            yaml.safe_dump([CONTAINER_PROBE_ENTRY], sort_keys=False), encoding="utf-8"
        )
        config = ToolConfig(**CONTAINER_PROBE_ENTRY)
        request = ExecRequest(
            kind="tool",
            target=config.name,
            manifest_digest=manifest_digest(config),
            input=json.dumps(CONTAINER_PROBE_INPUT),
            deadline_ms=max(1, int(timeout * 1000)),
        )

        async def _exec():
            async with RunnerClient() as client:
                return await client.healthz(), await client.exec(request)

        try:
            health, result = asyncio.run(_exec())
        except RunnerUnavailable as exc:
            raise ContainerProbeUnavailable(exc.message) from exc
        except RunnerCallError as exc:
            raise ContainerProbeUnavailable(f"{exc.code}: {exc.message}") from exc
    finally:
        shutil.rmtree(suite, ignore_errors=True)

    errors = []
    observed = {"stdout": result.stdout, "stderr": result.stderr}
    if not health.ok:
        errors.append(f"runner reports unhealthy: {health.detail}")
    info = None
    for line in (result.stdout or "").strip().splitlines()[::-1]:
        try:
            info = json.loads(line)
        except ValueError:
            continue
        if isinstance(info, dict):
            break
    if result.exit_code != 0 or not isinstance(info, dict):
        errors.append(f"container probe failed: {_short(_observed(observed))}")
        info = info if isinstance(info, dict) else {}

    if info.get("echo") != CONTAINER_PROBE_INPUT:
        errors.append(f"stdin JSON round-trip changed the payload: {info.get('echo')!r}")
    home = info.get("home") or {}
    tmpdir = info.get("tmpdir") or {}
    if not home.get("writable"):
        errors.append(f"HOME is not writable: {home}")
    if not tmpdir.get("writable"):
        errors.append(f"TMPDIR is not writable: {tmpdir}")
    if info.get("tmp_is_tmpfs") is not True:
        errors.append("the container's /tmp is not a tmpfs")
    network = info.get("network") or {}
    for target, verdict in network.items():
        if not str(verdict).startswith(("blocked:", "unresolved:")):
            errors.append(f"network: none still reached {target}: {verdict}")

    report = {
        "ok": not errors,
        "backend": "container",
        "runtime": health.runtime,
        "image": health.image,
        "tool": CONTAINER_PROBE_TOOL,
        "suite": suite.name,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "echo_roundtrip": info.get("echo"),
        "home_tmpdir": {
            "home": home,
            "tmpdir": tmpdir,
            "tmp_is_tmpfs": info.get("tmp_is_tmpfs"),
        },
        "network": network,
        "output": _short(_observed(observed)),
    }
    return report, errors


def _run_check(report, name, runner):
    _log(f"check: {name}")
    try:
        result, errors = runner()
    except Exception as exc:  # noqa: BLE001 - keep stdout a valid JSON report
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        errors = [f"{name} crashed: {type(exc).__name__}: {exc}"]
    report["checks"][name] = result
    report["errors"].extend(errors)


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Smoke harness for the Trellis tool-execution path (runner container "
            "per call). Run inside the hub container."
        )
    )
    parser.add_argument(
        "--backend",
        choices=("container",),
        default="container",
        help="Execution backend; 'container' (the runner) is the only one.",
    )
    parser.add_argument(
        "--tool",
        action="append",
        default=[],
        metavar="NAME",
        help="Run a registered hub tool through hub.run_tool (repeatable; prefer read-only tools).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        metavar="SECONDS",
        help="Per-command timeout in seconds (default: 120).",
    )
    return parser


def _print_report(report):
    print(json.dumps(report, indent=2, sort_keys=True))


def main(argv=None):
    args = build_parser().parse_args(argv)
    timeout = max(1.0, args.timeout)

    report = {
        "requested": args.backend,
        "backend": "container",
        "checks": {"container": None, "tools": None},
        "ok": False,
        "errors": [],
    }

    if not WORKSPACE.is_dir():
        report["errors"].append(
            f"{WORKSPACE} is missing; run this script inside the hub container"
        )
        _log(report["errors"][-1])
        _print_report(report)
        return 2

    _log("check: container (runner exec probes)")
    try:
        result, errors = check_container(timeout)
    except ContainerProbeUnavailable as exc:
        report["errors"].append(f"container probes unavailable: {exc}")
        _log(report["errors"][-1])
        _print_report(report)
        return 2
    except Exception as exc:  # noqa: BLE001 - keep stdout a valid JSON report
        report["errors"].append(
            f"container probes crashed: {type(exc).__name__}: {exc}"
        )
        _log(report["errors"][-1])
        _print_report(report)
        return 1

    report["checks"]["container"] = result
    report["errors"].extend(errors)
    if args.tool:
        _run_check(report, "tools", lambda: check_tools(args.tool))

    report["ok"] = not report["errors"]
    _print_report(report)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
