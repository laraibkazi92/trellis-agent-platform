#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Backend-parameterized smoke and parity harness for the tool-hub sandbox.

Runs **inside the hub container** (it needs ``/app/workspace`` and the sandbox
helper). Every command goes through ``core.sandbox.prepare_execution`` so the
harness exercises the same argv/env the hub uses for real tools, then reports
one JSON object on stdout for diffing between backends.

The default run (no check flags) is ``--runtime-matrix`` plus the security
checks (confinement, privilege, seccomp); ``--tool`` is only exercised when
named. Tools run without an identity, so prefer read-only tools in smoke runs.
Exit codes are 0 for a fully green run, 1 for any failed check, and 2 when the
environment itself is not usable (no backend, no ``/app/workspace``).
"""

import argparse
import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core import sandbox, sandbox_preflight
from core.env_sanitize import sanitized_env

WORKSPACE = Path("/app/workspace")
TEST_TEXT = "the quick brown fox jumps over the lazy dog"

GO_MAIN = """package main

import "fmt"

func main() {
    fmt.Println("go-ok")
}
"""

TS_SOURCE = "console.log('ts-ok')\n"

# Filled in per run; /proc/<pid>/environ must not be readable from the sandbox.
PRIVILEGE_SNIPPET = """
import json, os

info = {"euid": os.geteuid(), "capeff": None}
with open("/proc/self/status", encoding="utf-8") as handle:
    for line in handle:
        if line.startswith("CapEff:"):
            info["capeff"] = int(line.split()[1], 16)
            break

try:
    with open("/proc/__SIBLING_PID__/environ", "rb") as handle:
        handle.read(1)
except OSError as exc:
    info["environ_read"] = False
    info["environ_error"] = type(exc).__name__
else:
    info["environ_read"] = True

target = __WRITTEN__
with open(target, "w", encoding="utf-8") as handle:
    handle.write("ok")
info["written"] = os.path.exists(target)
print(json.dumps(info))
"""


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


def _command_entry(result):
    return {
        "returncode": result.get("returncode"),
        "output": _short(_observed(result)),
    }


def run_in_sandbox(cmd, backend, timeout):
    """Run ``cmd`` through the sandbox and return its exit status and output.

    The per-run tmpdir is always cleaned up. ``GOCACHE``/``npm_config_cache``
    are pointed at the plan's TMPDIR (the private tmpfs under bwrap, the
    per-run dir under Landlock) instead of the host's, so runtime caches never
    leak into a shared location.
    """
    plan = sandbox.prepare_execution(cmd, WORKSPACE, backend=backend, env=sanitized_env())
    try:
        run_env = dict(plan.env)
        tmpdir = run_env.get("TMPDIR") or str(plan.tmpdir)
        run_env["GOCACHE"] = f"{tmpdir}/gocache"
        run_env["npm_config_cache"] = f"{tmpdir}/npm-cache"
        # Keep parity output stable across backends (Landlock's fresh HOME/cache
        # triggers npm's update notice; bwrap's inherited cache does not).
        run_env["npm_config_update_notifier"] = "false"
        run_env["NO_UPDATE_NOTIFIER"] = "1"
        try:
            proc = subprocess.Popen(
                plan.argv,
                cwd=str(WORKSPACE),
                env=run_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                start_new_session=True,
            )
        except OSError as exc:
            return {
                "returncode": None,
                "stdout": "",
                "stderr": f"could not start {cmd[0]!r}: {exc}",
            }
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            stdout, stderr = proc.communicate()
            return {
                "returncode": None,
                "stdout": stdout or "",
                "stderr": f"timed out after {timeout:g}s",
            }
        return {
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }
    finally:
        plan.cleanup()


def _run_as_sandbox_uid(action):
    """Run ``action`` in a child dropped to the sandbox uid/gid.

    The hub is root but does not hold CAP_DAC_OVERRIDE (by design), so it cannot
    create or remove entries in an operator-owned (1000:1000 0755) workspace.
    Forking with CAP_SETUID is enough; the parent stays root.
    """
    uid, gid = sandbox_preflight.resolve_sandbox_identity()
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            action()
            os._exit(0)
        except BaseException as exc:
            try:
                sys.stderr.write(
                    f"[sandbox-smoke] sandbox-uid helper failed as {uid}:{gid}: "
                    f"{type(exc).__name__}: {exc}\n"
                )
                sys.stderr.flush()
            except Exception:
                pass
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def _workspace_scratch(prefix):
    path = WORKSPACE / f"{prefix}{uuid.uuid4().hex}"

    def _create():
        os.mkdir(path, 0o777)
        os.chmod(path, 0o777)

    if not _run_as_sandbox_uid(_create):
        uid, gid = sandbox_preflight.resolve_sandbox_identity()
        stat = WORKSPACE.stat()
        raise RuntimeError(
            f"could not create writable scratch dir {path} as sandbox uid {uid}:{gid}; "
            f"{WORKSPACE} is owned by {stat.st_uid}:{stat.st_gid} "
            f"mode {oct(stat.st_mode & 0o777)}"
        )
    return path


def _remove_scratch(path):
    def _remove():
        shutil.rmtree(path)

    if not _run_as_sandbox_uid(_remove):
        shutil.rmtree(path, ignore_errors=True)


def _runtime_entry(result, marker):
    return {
        "ok": result.get("returncode") == 0 and marker in (result.get("stdout") or ""),
        "returncode": result.get("returncode"),
        "output": _short(_observed(result)),
    }


def check_runtime_matrix(backend, timeout):
    """Start every runtime the image ships, inside the sandbox."""
    errors = []
    checks = {}
    scratch = _workspace_scratch("trellis-smoke-runtime-")
    try:
        fixed = {
            "python": (
                [sys.executable, "-c", "import asyncio, threading; print('python-ok')"],
                "python-ok",
            ),
            "bash": (["bash", "-c", "echo bash-ok"], "bash-ok"),
            "node": (["node", "-e", "console.log('node-ok')"], "node-ok"),
        }
        for name, (cmd, marker) in fixed.items():
            _log(f"runtime: {name}")
            entry = _runtime_entry(run_in_sandbox(cmd, backend, timeout), marker)
            checks[name] = entry
            if not entry["ok"]:
                errors.append(f"runtime {name} failed: {entry['output']}")

        _log("runtime: ts")
        entry = _runtime_entry(
            run_in_sandbox(
                ["npx", "tsx", "-e", "console.log('ts-ok')"], backend, timeout
            ),
            "ts-ok",
        )
        entry["method"] = "-e"
        if not entry["ok"]:
            # Some tsx versions do not support -e; fall back to a real file.
            ts_file = scratch / "smoke.ts"
            ts_file.write_text(TS_SOURCE, encoding="utf-8")
            entry = _runtime_entry(
                run_in_sandbox(["npx", "tsx", str(ts_file)], backend, timeout),
                "ts-ok",
            )
            entry["method"] = "file"
        checks["ts"] = entry
        if not entry["ok"]:
            errors.append(f"runtime ts failed: {entry['output']}")

        _log("runtime: go")
        go_file = scratch / "main.go"
        go_file.write_text(GO_MAIN, encoding="utf-8")
        entry = _runtime_entry(
            run_in_sandbox(["go", "run", str(go_file)], backend, timeout), "go-ok"
        )
        checks["go"] = entry
        if not entry["ok"]:
            errors.append(f"runtime go failed: {entry['output']}")
    finally:
        _remove_scratch(scratch)

    return {"ok": not errors, **checks}, errors


def check_confinement(backend, timeout):
    """Writes outside the grants must fail; TMPDIR writes must succeed."""
    errors = []
    root_escape = Path("/root/trellis-smoke-escape")
    host_tmp = Path(f"/tmp/trellis-smoke-{os.getpid()}")
    removed = []
    scratch = _workspace_scratch("trellis-smoke-conf-")
    locked = scratch / "locked"

    # A stale artefact from an earlier failed run would mask the real result.
    for path in (root_escape, host_tmp):
        if path.exists() or path.is_symlink():
            try:
                path.unlink()
                removed.append(str(path))
            except OSError:
                pass

    _log("confinement: TMPDIR write")
    tmpdir_result = run_in_sandbox(
        ["bash", "-c", 'echo ok > "$TMPDIR/ok"'], backend, timeout
    )

    _log("confinement: TMPDIR write then /root escape")
    combined_result = run_in_sandbox(
        ["bash", "-c", 'echo ok > "$TMPDIR/ok" && echo escape > /root/trellis-smoke-escape'],
        backend,
        timeout,
    )

    _log("confinement: /root escape only")
    root_result = run_in_sandbox(
        ["bash", "-c", "echo escape > /root/trellis-smoke-escape"], backend, timeout
    )

    _log(f"confinement: host /tmp write ({host_tmp})")
    host_result = run_in_sandbox(
        ["bash", "-c", f'echo escape > "{host_tmp}"'], backend, timeout
    )

    # The documented bwrap limitation: uid 0 without CAP_DAC_OVERRIDE cannot
    # write an operator-owned 0755 directory. Landlock runs as the owner and can.
    if not _run_as_sandbox_uid(lambda: os.mkdir(locked, 0o755)):
        errors.append(f"could not create {locked}")
    _log("confinement: operator-owned 0755 workspace dir")
    locked_result = run_in_sandbox(
        ["bash", "-c", f'echo ok > "{locked}/file"'], backend, timeout
    )
    locked_ok = locked_result["returncode"] == 0
    expected_locked_ok = backend is sandbox.Backend.LANDLOCK
    if locked_ok != expected_locked_ok:
        errors.append(
            f"0755 workspace write exit {locked_result['returncode']}, "
            f"expected {'success' if expected_locked_ok else 'denial'}: "
            f"{_short(_observed(locked_result))}"
        )

    root_visible = root_escape.exists()
    host_visible = host_tmp.exists()

    if tmpdir_result["returncode"] != 0:
        errors.append(f"TMPDIR write failed: {_short(_observed(tmpdir_result))}")
    if combined_result["returncode"] in (0, None):
        errors.append(
            "combined TMPDIR+/root write unexpectedly succeeded "
            f"(exit {combined_result['returncode']})"
        )
    if root_result["returncode"] in (0, None):
        errors.append(
            f"/root write was not denied (exit {root_result['returncode']})"
        )
    if root_visible:
        errors.append(f"{root_escape} exists on the hub filesystem")
    if host_visible:
        errors.append(f"{host_tmp} is visible on the hub filesystem")
    # bwrap mounts a private tmpfs on /tmp, so a successful write there is
    # expected and only host invisibility matters. Landlock must refuse it.
    if backend is sandbox.Backend.LANDLOCK and host_result["returncode"] == 0:
        errors.append("host /tmp write succeeded under the Landlock backend")

    result = {
        "ok": not errors,
        "tmpdir_write": _command_entry(tmpdir_result),
        "combined": _command_entry(combined_result),
        "root_write": _command_entry(root_result),
        "host_tmp_write": {
            **_command_entry(host_result),
            "expected_to_fail": backend is sandbox.Backend.LANDLOCK,
            "host_visible": host_visible,
        },
        "workspace_0755_write": {
            **_command_entry(locked_result),
            "expected_to_succeed": expected_locked_ok,
        },
        "root_escape_visible": root_visible,
        "host_tmp_visible": host_visible,
        "pre_existing_paths_removed": removed,
    }

    for path in (root_escape, host_tmp):
        try:
            path.unlink()
        except OSError:
            pass
    _remove_scratch(scratch)

    return result, errors


def check_privilege(backend, timeout):
    """Assert the tool's identity, capabilities, and /proc isolation."""
    errors = []
    sandbox_uid, _ = sandbox_preflight.resolve_sandbox_identity()
    # Documented asymmetry: bwrap keeps host uid 0 inside its namespaces,
    # Landlock drops to the workspace owner.
    expected_euid = 0 if backend is sandbox.Backend.BWRAP else sandbox_uid
    scratch = _workspace_scratch("trellis-smoke-priv-")
    written = scratch / "written.txt"

    sibling_kwargs = {}
    if os.geteuid() == 0:
        # Tool↔tool boundary: the sibling must have the same uid as the tool,
        # otherwise plain DAC (not Yama/Landlock) would deny the /proc read.
        sibling_kwargs = {
            "user": sandbox_uid,
            "group": sandbox_preflight.resolve_sandbox_identity()[1],
            "extra_groups": [],
        }
    sibling = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **sibling_kwargs,
    )
    try:
        time.sleep(0.2)
        snippet = (
            PRIVILEGE_SNIPPET.replace("__SIBLING_PID__", str(sibling.pid))
            .replace("__WRITTEN__", repr(str(written)))
        )
        _log(f"privilege: euid/ CapEff / /proc/{sibling.pid}/environ")
        result = run_in_sandbox([sys.executable, "-c", snippet], backend, timeout)

        info = None
        lines = (result.get("stdout") or "").strip().splitlines()
        if lines:
            try:
                info = json.loads(lines[-1])
            except ValueError:
                info = None

        if result["returncode"] != 0:
            errors.append(f"privilege probe failed: {_short(_observed(result))}")
        if not isinstance(info, dict):
            errors.append(f"privilege probe produced no JSON: {_short(_observed(result))}")
        else:
            if info.get("euid") != expected_euid:
                errors.append(
                    f"tool euid {info.get('euid')!r} != expected {expected_euid}"
                )
            if info.get("capeff") != 0:
                errors.append(f"tool CapEff {info.get('capeff')!r} != 0")
            if info.get("environ_read") is not False:
                errors.append("tool could read a sibling /proc/<pid>/environ")

        written_uid = written.stat().st_uid if written.exists() else None
        if written_uid is None:
            errors.append(f"tool did not create {written}")
        elif written_uid != expected_euid:
            errors.append(
                f"{written.name} is owned by uid {written_uid}, "
                f"expected {expected_euid}"
            )

        payload = {
            "ok": not errors,
            "backend": backend.value,
            "expected_euid": expected_euid,
            "expected_file_uid": expected_euid,
            "sibling_pid": sibling.pid,
            "sibling_uid": (
                sandbox_uid if os.geteuid() == 0 else os.geteuid()
            ),
            "euid": info.get("euid") if isinstance(info, dict) else None,
            "capeff": info.get("capeff") if isinstance(info, dict) else None,
            "environ_read": info.get("environ_read") if isinstance(info, dict) else None,
            "environ_error": info.get("environ_error") if isinstance(info, dict) else None,
            "written_uid": written_uid,
            "output": _short(_observed(result)),
        }
    finally:
        try:
            sibling.kill()
            sibling.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        _remove_scratch(scratch)

    return payload, errors


def check_seccomp(backend, timeout):
    """Prove the Landlock deny-list is actually installed."""
    if sandbox_preflight.seccomp_disabled():
        return {"ok": True, "skipped": "SANDBOX_SECCOMP=off"}, []

    snippet = """
import ctypes, json, os
info = {}
try:
    os.unshare(os.CLONE_NEWUSER)
    info["unshare"] = "ok"
except OSError as exc:
    info["unshare"] = exc.errno
libc = ctypes.CDLL(None, use_errno=True)
result = libc.syscall(425, 0, 0)
info["io_uring"] = ctypes.get_errno() if result == -1 else 0
print(json.dumps(info))
"""
    _log("seccomp: unshare / io_uring")
    result = run_in_sandbox([sys.executable, "-c", snippet], backend, timeout)
    info = None
    lines = (result.get("stdout") or "").strip().splitlines()
    if lines:
        try:
            info = json.loads(lines[-1])
        except ValueError:
            pass

    errors = []
    if result["returncode"] != 0 or not isinstance(info, dict):
        errors.append(f"seccomp probe failed: {_short(_observed(result))}")
    elif backend is sandbox.Backend.LANDLOCK:
        if info.get("unshare") != 1:  # EPERM
            errors.append(f"unshare(CLONE_NEWUSER) not denied: {info}")
        if info.get("io_uring") != 38:  # ENOSYS
            errors.append(f"io_uring_setup not ENOSYS: {info}")
    else:
        # bwrap keeps its userns; no seccomp filter is applied on this path.
        if info.get("unshare") != "ok":
            errors.append(f"bwrap unshare unexpectedly failed: {info}")

    return {"ok": not errors, "observed": info}, errors


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
            "Backend-parameterized smoke/parity harness for the Trellis tool-hub "
            "sandbox. Run inside the hub container."
        )
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "bwrap", "landlock"),
        default="auto",
        help="Sandbox backend to exercise (default: auto).",
    )
    parser.add_argument(
        "--tool",
        action="append",
        default=[],
        metavar="NAME",
        help="Run a registered hub tool through hub.run_tool (repeatable; prefer read-only tools).",
    )
    parser.add_argument(
        "--runtime-matrix",
        action="store_true",
        help="Start python/bash/node/ts/go inside the sandbox.",
    )
    parser.add_argument(
        "--check-confinement",
        action="store_true",
        help="Assert writes outside the grants fail and TMPDIR writes succeed.",
    )
    parser.add_argument(
        "--check-privilege",
        action="store_true",
        help="Assert euid, CapEff, sibling /proc isolation, and file ownership.",
    )
    parser.add_argument(
        "--check-seccomp",
        action="store_true",
        help="Assert the Landlock deny-list (unshare EPERM, io_uring ENOSYS).",
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

    os.environ["SANDBOX_BACKEND"] = args.backend
    sandbox.reset_for_tests()

    report = {
        "requested": args.backend,
        "backend": None,
        "checks": {
            "runtime_matrix": None,
            "confinement": None,
            "privilege": None,
            "seccomp": None,
            "tools": None,
        },
        "ok": False,
        "errors": [],
    }

    try:
        selected = sandbox.select_backend()
    except sandbox.SandboxUnavailable as exc:
        report["diagnosis"] = {
            "code": exc.code,
            "detail": exc.detail,
            "remediation": exc.remediation,
        }
        report["errors"].append(
            f"sandbox unavailable [{exc.code}]: {exc.detail or exc.remediation}"
        )
        _log(f"sandbox unavailable [{exc.code}]: {exc.detail or exc.remediation}")
        if exc.remediation:
            _log(f"remediation: {exc.remediation}")
        _print_report(report)
        return 2
    except Exception as exc:  # noqa: BLE001 - no traceback on a bare dev box
        report["errors"].append(
            f"sandbox selection crashed: {type(exc).__name__}: {exc}"
        )
        _log(report["errors"][-1])
        _print_report(report)
        return 2

    report["backend"] = selected.value
    _log(f"backend: {selected.value} (requested {args.backend})")

    if not WORKSPACE.is_dir():
        report["errors"].append(
            f"{WORKSPACE} is missing; run this script inside the hub container"
        )
        _log(report["errors"][-1])
        _print_report(report)
        return 2

    run_default = not (
        args.runtime_matrix
        or args.check_confinement
        or args.check_privilege
        or args.check_seccomp
        or args.tool
    )
    runners = {
        "runtime_matrix": lambda: check_runtime_matrix(selected, timeout),
        "confinement": lambda: check_confinement(selected, timeout),
        "privilege": lambda: check_privilege(selected, timeout),
        "seccomp": lambda: check_seccomp(selected, timeout),
    }
    if args.runtime_matrix or run_default:
        _run_check(report, "runtime_matrix", runners["runtime_matrix"])
    if args.check_confinement or run_default:
        _run_check(report, "confinement", runners["confinement"])
    if args.check_privilege or run_default:
        _run_check(report, "privilege", runners["privilege"])
    if args.check_seccomp or run_default:
        _run_check(report, "seccomp", runners["seccomp"])
    if args.tool:
        _run_check(report, "tools", lambda: check_tools(args.tool))

    report["ok"] = not report["errors"]
    _print_report(report)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
