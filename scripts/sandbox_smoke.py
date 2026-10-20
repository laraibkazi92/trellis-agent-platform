#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Backend-parameterized smoke and parity harness for the tool-hub sandbox.

Runs **inside the hub container** (it needs ``/app/workspace`` and the sandbox
helper). Every command goes through ``core.sandbox.prepare_execution`` so the
harness exercises the same argv/env the hub uses for real tools, then reports
one JSON object on stdout for diffing between backends.

The default run (no check flags) is ``--runtime-matrix`` plus the security
checks (confinement, privilege, seccomp); ``--check-net``, ``--check-egress``
and ``--tool`` are only exercised when named. Tools run without an identity, so
prefer read-only tools in smoke runs.
Exit codes are 0 for a fully green run, 1 for any failed check, and 2 when the
environment itself is not usable (no backend, no ``/app/workspace``, or
``--check-egress`` without the egress override active).
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
from urllib.parse import urlsplit

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

# Egress-mode probes, run inside the sandbox. They only use sockets, so they
# exercise the same path a tool would: the environment (HTTP_PROXY/NO_PROXY)
# plus the network reachable from the hub's namespace.
EGRESS_SNIPPET = r"""
import json, os, socket
from urllib.parse import urlsplit

LIVE_HOST = __LIVE_HOST__
ALLOWED = "api.egress-allowed.test"
DENIED = "api.egress-denied.test"


def proxy_url():
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return name, value
    return None, ""


def proxy_address(url):
    parts = urlsplit(url)
    return parts.hostname, parts.port or 3128


def status_line(url, target, port, timeout=8.0):
    try:
        with socket.create_connection(proxy_address(url), timeout=timeout) as sock:
            request = "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n".format(
                target, port, target, port
            )
            sock.sendall(request.encode())
            buffer = b""
            while b"\r\n" not in buffer:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                buffer += chunk
    except OSError as exc:
        return "error:" + type(exc).__name__
    return buffer.split(b"\r\n", 1)[0].decode("latin-1", "replace")


def direct(host, port, timeout=5.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "connected"
    except OSError as exc:
        return "blocked:" + type(exc).__name__


name, url = proxy_url()
if not url:
    print(json.dumps({"error": "no proxy variable in the sandbox environment"}))
else:
    # The IP literal is rejected by the proxy before resolution, so any address
    # proves the SSRF guard; prefer the mock's own IP when CI provides it.
    literal = (os.environ.get("EGRESS_TEST_IP") or "").strip()
    if not literal:
        try:
            literal = socket.gethostbyname(ALLOWED)
        except OSError:
            literal = "1.1.1.1"
    report = {
        "proxy_env": name,
        "proxy": url,
        "direct": direct(ALLOWED, 443),
        "allowed": status_line(url, ALLOWED, 443),
        "denied": status_line(url, DENIED, 443),
        "literal_target": literal,
        "literal": status_line(url, literal, 443),
        "no_proxy": os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "",
    }
    if LIVE_HOST:
        report["live_allowed"] = status_line(url, LIVE_HOST, 443)
        report["live_denied"] = status_line(url, "example.org", 443)
    print(json.dumps(report))
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


def run_in_sandbox(cmd, backend, timeout, network=None):
    """Run ``cmd`` through the sandbox and return its exit status and output.

    The per-run tmpdir is always cleaned up. ``GOCACHE``/``npm_config_cache``
    are pointed at the plan's TMPDIR (the private tmpfs under bwrap, the
    per-run dir under Landlock) instead of the host's, so runtime caches never
    leak into a shared location. The generated ``argv`` is returned too, so
    checks can assert the policy reached the command line.
    """
    plan = sandbox.prepare_execution(
        cmd, WORKSPACE, backend=backend, env=sanitized_env(), network=network
    )
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
                "argv": plan.argv,
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
                "argv": plan.argv,
            }
        return {
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "argv": plan.argv,
        }
    finally:
        plan.cleanup()


def _run_as_sandbox_uid(action):
    """Run ``action`` as the sandbox uid/gid.

    The hub normally runs as that uid already (compose sets ``user:`` to
    ``TRELLIS_UID``), so the action runs in-process. A root hub — the legacy
    posture, still supported — forks and drops with setgid/setuid instead, and
    the parent stays root.
    """
    uid, gid = sandbox_preflight.resolve_sandbox_identity()
    if os.geteuid() != 0:
        if os.geteuid() != uid:
            _log(
                f"sandbox uid {uid} differs from hub euid {os.geteuid()}: "
                "cannot switch identity without root"
            )
            return False
        try:
            action()
        except BaseException as exc:
            _log(
                f"sandbox-uid action failed as {uid}:{gid}: "
                f"{type(exc).__name__}: {exc}"
            )
            return False
        return True
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
    """Writes outside the grants must fail; TMPDIR writes must succeed.

    The checks here prove two different things and must not be conflated:

    * **Identity/DAC** (the ``identity_*`` keys): ``/etc/shadow`` is unreadable
      and ``/etc`` is unwritable because the tool is not root. Plain Unix
      permissions alone would produce that, so these say "not root", not
      "Landlock/bwrap confines writes". They still catch a regression to a
      root tool identity, so they stay.
    * **Confinement** (``tmpdir_write``/``host_tmp_write``/``var_tmp_write``):
      targets the tool's own DAC permissions allow, which only the sandbox can
      deny.
    """
    errors = []
    # Root-only fixtures cannot be created by a non-root hub, so the /etc
    # fixtures use paths that already exist with root-only permissions.
    shadow_path = Path("/etc/shadow")
    etc_escape = Path("/etc/trellis-smoke-escape")
    host_tmp = Path(f"/tmp/trellis-smoke-{os.getpid()}")
    # /var/tmp is 1777: DAC allows the tool's uid to create a file there, so a
    # denial is attributable to the sandbox alone (bwrap: `/` is a read-only
    # bind; Landlock: no grant). This is the check that actually discriminates.
    var_tmp = Path(f"/var/tmp/trellis-smoke-{os.getpid()}")
    removed = []
    scratch = _workspace_scratch("trellis-smoke-conf-")
    locked = scratch / "locked"

    # /tmp and /var/tmp are hub-uid writable, so a stale artefact from an
    # earlier aborted run can be cleaned up here. /etc/trellis-smoke-escape is
    # deliberately never unlinked: only a privileged (legacy root) hub could
    # have created it, so its presence is itself a finding an operator must
    # clear by hand.
    if etc_escape.exists() or etc_escape.is_symlink():
        etc_stale = True
        errors.append(
            f"{etc_escape} already exists; a non-root hub cannot remove it. "
            f"Remove it manually (rm -f {etc_escape}) and rerun."
        )
    else:
        etc_stale = False
    for path in (host_tmp, var_tmp):
        if path.exists() or path.is_symlink():
            try:
                path.unlink()
                removed.append(str(path))
            except OSError:
                pass

    # Positive control for the discriminating /var/tmp check: DAC must allow
    # the tool's uid to write there. On a read-only or unusually mounted
    # /var/tmp the in-sandbox denial would prove nothing, so say so explicitly
    # instead of reporting a false pass.
    var_tmp_control = _run_as_sandbox_uid(lambda: var_tmp.write_text("ok"))
    if var_tmp_control:
        try:
            var_tmp.unlink()
        except OSError:
            pass
    else:
        errors.append(
            f"cannot verify /var/tmp confinement: {var_tmp} is not writable "
            "outside the sandbox either (DAC, not the sandbox)"
        )

    _log("confinement: TMPDIR write")
    tmpdir_result = run_in_sandbox(
        ["bash", "-c", 'echo ok > "$TMPDIR/ok"'], backend, timeout
    )

    _log("confinement: TMPDIR write then root-only read")
    combined_result = run_in_sandbox(
        ["bash", "-c", f'echo ok > "$TMPDIR/ok" && cat "{shadow_path}"'],
        backend,
        timeout,
    )

    _log("confinement: root-only read only (identity/DAC, not sandbox)")
    shadow_result = run_in_sandbox(
        ["bash", "-c", f'cat "{shadow_path}"'], backend, timeout
    )

    _log("confinement: /etc write (identity/DAC, not sandbox)")
    etc_result = run_in_sandbox(
        ["bash", "-c", f'echo escape > "{etc_escape}"'], backend, timeout
    )

    _log(f"confinement: host /tmp write ({host_tmp})")
    host_result = run_in_sandbox(
        ["bash", "-c", f'echo escape > "{host_tmp}"'], backend, timeout
    )

    _log(f"confinement: world-writable /var/tmp write ({var_tmp})")
    var_tmp_result = run_in_sandbox(
        ["bash", "-c", f'echo escape > "{var_tmp}"'], backend, timeout
    )

    # Workspace-write contract: tools run as the workspace owner (the hub uid),
    # so an operator-owned 0755 directory is writable in both backends.
    if not _run_as_sandbox_uid(lambda: os.mkdir(locked, 0o755)):
        errors.append(f"could not create {locked}")
    _log("confinement: operator-owned 0755 workspace dir")
    locked_result = run_in_sandbox(
        ["bash", "-c", f'echo ok > "{locked}/file"'], backend, timeout
    )
    locked_ok = locked_result["returncode"] == 0
    if not locked_ok:
        errors.append(
            f"0755 workspace write exit {locked_result['returncode']}, expected "
            f"success: {_short(_observed(locked_result))}"
        )

    etc_visible = etc_escape.exists()
    host_visible = host_tmp.exists()
    var_tmp_visible = var_tmp.exists()

    if tmpdir_result["returncode"] != 0:
        errors.append(f"TMPDIR write failed: {_short(_observed(tmpdir_result))}")
    if combined_result["returncode"] in (0, None):
        errors.append(
            "combined TMPDIR+root-only-read unexpectedly succeeded "
            f"(exit {combined_result['returncode']})"
        )
    if shadow_result["returncode"] in (0, None):
        errors.append(
            f"{shadow_path} read was not denied (exit {shadow_result['returncode']}); "
            "the tool is not running as a non-root identity"
        )
    if etc_result["returncode"] in (0, None):
        errors.append(
            f"/etc write was not denied (exit {etc_result['returncode']}); "
            "the tool is not running as a non-root identity"
        )
    if etc_visible and not etc_stale:
        # A pre-existing /etc artefact is reported above with the manual removal
        # instruction; only a fresh escape is reported here.
        errors.append(f"{etc_escape} exists on the hub filesystem")
    if host_visible:
        errors.append(f"{host_tmp} is visible on the hub filesystem")
    # The discriminating check: DAC permits this write for the tool's uid, so a
    # success means the sandbox is not confining writes on *either* backend.
    if var_tmp_result["returncode"] in (0, None):
        errors.append(
            "world-writable /var/tmp write was not denied "
            f"(exit {var_tmp_result['returncode']}): DAC alone allows it, so the "
            f"sandbox is not confining writes: {_short(_observed(var_tmp_result))}"
        )
    if var_tmp_visible:
        errors.append(f"{var_tmp} is visible on the hub filesystem")
    # bwrap mounts a private tmpfs on /tmp, so a successful write there is
    # expected and only host invisibility matters. Landlock must refuse it.
    if backend is sandbox.Backend.LANDLOCK and host_result["returncode"] == 0:
        errors.append("host /tmp write succeeded under the Landlock backend")

    result = {
        "ok": not errors,
        "tmpdir_write": _command_entry(tmpdir_result),
        "combined": _command_entry(combined_result),
        # Identity/DAC evidence: fails for any non-root tool, sandbox or not.
        "identity_root_only_read": _command_entry(shadow_result),
        "identity_etc_write": _command_entry(etc_result),
        # Confinement evidence: DAC would allow these, the sandbox must not.
        "host_tmp_write": {
            **_command_entry(host_result),
            "expected_to_fail": backend is sandbox.Backend.LANDLOCK,
            "host_visible": host_visible,
        },
        "var_tmp_write": {
            **_command_entry(var_tmp_result),
            "expected_to_fail": True,
            "host_visible": var_tmp_visible,
            "positive_control_writable": var_tmp_control,
        },
        "workspace_0755_write": {
            **_command_entry(locked_result),
            "expected_to_succeed": True,
        },
        "etc_escape_visible": etc_visible,
        "host_tmp_visible": host_visible,
        "var_tmp_visible": var_tmp_visible,
        "pre_existing_paths_removed": removed,
    }

    for path in (host_tmp, var_tmp):
        try:
            path.unlink()
        except OSError:
            pass
    _remove_scratch(scratch)

    return result, errors


def check_privilege(backend, timeout):
    """Assert the tool's identity, capabilities, and /proc isolation."""
    errors = []
    hub_euid = os.geteuid()
    sandbox_uid, sandbox_gid = sandbox_preflight.resolve_sandbox_identity()
    # bwrap maps the hub's uid 1:1 inside its namespaces (the hub is no longer
    # root); Landlock runs the tool as SANDBOX_UID, which defaults to the hub
    # uid. On the default deployment both are the same operator uid.
    expected_euid = hub_euid if backend is sandbox.Backend.BWRAP else sandbox_uid
    _log(
        f"privilege: hub euid {hub_euid}, expected tool euid {expected_euid} "
        f"({backend.value})"
    )
    scratch = _workspace_scratch("trellis-smoke-priv-")
    written = scratch / "written.txt"

    sibling_kwargs = {}
    if hub_euid == 0:
        # Tool↔tool boundary: the sibling must have the same uid as the tool,
        # otherwise plain DAC (not Yama/Landlock) would deny the /proc read.
        sibling_kwargs = {
            "user": sandbox_uid,
            "group": sandbox_gid,
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
            "hub_euid": hub_euid,
            "expected_euid": expected_euid,
            "expected_file_uid": expected_euid,
            "sibling_pid": sibling.pid,
            "sibling_uid": sandbox_uid if hub_euid == 0 else hub_euid,
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


HUB_PORT = 8001


def _net_flag(backend):
    """The argv switch that enforces ``network: none`` on this backend."""
    if backend is sandbox.Backend.BWRAP:
        return "--unshare-net"
    return "--deny-net"


def check_net(backend, timeout, port=HUB_PORT):
    """Prove ``network: none`` changes reality, using ``allow`` as control.

    The hub's own ``/healthz`` listener is the target: tools share the hub's
    network namespace under ``allow``, so a loopback TCP connect must succeed
    there and fail under ``none`` (bwrap: private netns with no listener;
    Landlock: EACCES from the handled net rights).
    """
    errors = []
    cmd = ["bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{port}"]
    flag = _net_flag(backend)

    _log(f"net: allow -> 127.0.0.1:{port} (positive control)")
    allowed = run_in_sandbox(cmd, backend, timeout, network="allow")
    _log(f"net: none -> 127.0.0.1:{port}")
    denied = run_in_sandbox(cmd, backend, timeout, network="none")

    if flag not in denied.get("argv", []):
        errors.append(f"{flag} missing from the network: none argv: {denied.get('argv')}")
    if flag in allowed.get("argv", []):
        errors.append(f"{flag} present in the network: allow argv: {allowed.get('argv')}")

    if allowed["returncode"] != 0:
        errors.append(
            f"positive control failed: connect to 127.0.0.1:{port} must work "
            f"under network: allow (is the hub listening?): "
            f"{_short(_observed(allowed))}"
        )
    if denied["returncode"] in (0, None):
        errors.append(
            f"network: none did not block a connect to 127.0.0.1:{port} "
            f"(exit {denied['returncode']}): {_short(_observed(denied))}"
        )

    return {
        "ok": not errors,
        "backend": backend.value,
        "policy_flag": flag,
        "port": port,
        "allow": _command_entry(allowed),
        "none": _command_entry(denied),
    }, errors


NO_PROXY_REQUIRED = ("etcd", "redis", "host", "hub")


def _proxy_env():
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return name, value
    return None, None


def check_egress(backend, timeout, live_host=None):
    """Prove the egress override: no direct route, CONNECT allowlist, IP guard.

    Five facts, all from inside the sandbox:

    1. a direct TCP connection to the mock's name fails (topology, not env);
    2. ``CONNECT api.egress-allowed.test:443`` through the proxy returns 200;
    3. ``CONNECT api.egress-denied.test:443`` returns 403 -- same IP, different
       name, so the difference isolates the ACL from reachability;
    4. ``CONNECT <ip-literal>:443`` returns 403 (the SSRF guard);
    5. ``NO_PROXY`` covers etcd, redis, host, and hub, so framework traffic
       never goes to the proxy.
    """
    name, value = _proxy_env()
    if not value:
        error = (
            "egress mode is not enabled: HTTP_PROXY/HTTPS_PROXY is unset. "
            "Start the stack with COMPOSE_FILE=docker-compose.yml:"
            "docker-compose.egress.yml (see docs/deploy.md)."
        )
        return {"ok": False, "error": error}, [error]

    parts = urlsplit(value)
    display = f"{parts.scheme}://{parts.hostname or '?'}:{parts.port or 3128}"

    snippet = EGRESS_SNIPPET.replace("__LIVE_HOST__", json.dumps(live_host or ""))
    _log(f"egress: proxy {display} ({name}); direct + CONNECT probes")
    result = run_in_sandbox([sys.executable, "-c", snippet], backend, timeout)

    info = None
    lines = (result.get("stdout") or "").strip().splitlines()
    if lines:
        try:
            info = json.loads(lines[-1])
        except ValueError:
            info = None

    errors = []
    if result.get("returncode") != 0:
        errors.append(f"egress probe failed: {_short(_observed(result))}")
    if not isinstance(info, dict):
        errors.append(f"egress probe produced no JSON: {_short(_observed(result))}")
        return {"ok": False, "error": "no JSON from the egress probe"}, errors
    if info.get("error"):
        errors.append(f"egress probe: {info['error']}")
        return {"ok": False, "error": info["error"]}, errors

    direct = str(info.get("direct") or "")
    if direct == "connected":
        errors.append(
            "direct TCP to api.egress-allowed.test:443 succeeded inside the "
            "sandbox; the hub still has a route outside toolnet"
        )
    elif not direct.startswith("blocked:"):
        errors.append(f"unexpected direct-connect result: {direct!r}")

    def _status(field, code, description):
        observed = str(info.get(field) or "")
        if not observed.startswith(f"HTTP/1.1 {code}"):
            errors.append(
                f"{description}: expected HTTP/1.1 {code}, got {observed!r}"
            )

    _status("allowed", 200, "CONNECT to the allowlisted mock")
    _status("denied", 403, "CONNECT to the non-allowlisted alias")
    _status("literal", 403, "CONNECT to an IP literal")
    if live_host:
        _status("live_allowed", 200, f"CONNECT to the live host {live_host}")
        _status("live_denied", 403, "CONNECT to example.org")

    tokens = {
        token.strip().lower()
        for token in str(info.get("no_proxy") or "").split(",")
        if token.strip()
    }
    missing = [token for token in NO_PROXY_REQUIRED if token not in tokens]
    if missing:
        errors.append(
            "NO_PROXY does not cover " + ", ".join(missing) + f": {sorted(tokens)}"
        )

    return {
        "ok": not errors,
        "backend": backend.value,
        "proxy_env": info.get("proxy_env"),
        "proxy": display,
        "direct": direct,
        "allowed": info.get("allowed"),
        "denied": info.get("denied"),
        "literal_target": info.get("literal_target"),
        "literal": info.get("literal"),
        "no_proxy": info.get("no_proxy"),
        "live_host": live_host,
        "live_allowed": info.get("live_allowed"),
        "live_denied": info.get("live_denied"),
    }, errors


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
        help=(
            "Assert TMPDIR writes succeed and writes outside the grants fail, "
            "including a DAC-permitted /var/tmp write the sandbox must deny."
        ),
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
        "--check-net",
        action="store_true",
        help=(
            "Assert network: none blocks a loopback TCP connect while "
            "network: allow reaches the hub's /healthz listener."
        ),
    )
    parser.add_argument(
        "--check-egress",
        action="store_true",
        help=(
            "Assert egress mode: no direct route from the sandbox, proxy CONNECT "
            "allowed/denied/IP-literal verdicts, and NO_PROXY coverage."
        ),
    )
    parser.add_argument(
        "--egress-live",
        default=None,
        metavar="HOST",
        help=(
            "With --check-egress, additionally expect CONNECT to this real host "
            "to return 200 and example.org to return 403 (live deployment)."
        ),
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
    egress_enabled = args.check_egress or bool(args.egress_live)

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
            "net": None,
            "egress": None,
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

    if egress_enabled:
        proxy_name, proxy_value = _proxy_env()
        if not proxy_value:
            report["errors"].append(
                "egress mode is not enabled: neither HTTP_PROXY nor HTTPS_PROXY is "
                "set in the environment. Start the stack with "
                "COMPOSE_FILE=docker-compose.yml:docker-compose.egress.yml "
                "(see docs/deploy.md)."
            )
            _log(report["errors"][-1])
            _print_report(report)
            return 2

    run_default = not (
        args.runtime_matrix
        or args.check_confinement
        or args.check_privilege
        or args.check_seccomp
        or args.check_net
        or egress_enabled
        or args.tool
    )
    runners = {
        "runtime_matrix": lambda: check_runtime_matrix(selected, timeout),
        "confinement": lambda: check_confinement(selected, timeout),
        "privilege": lambda: check_privilege(selected, timeout),
        "seccomp": lambda: check_seccomp(selected, timeout),
        "net": lambda: check_net(selected, timeout),
        "egress": lambda: check_egress(selected, timeout, args.egress_live),
    }
    if args.runtime_matrix or run_default:
        _run_check(report, "runtime_matrix", runners["runtime_matrix"])
    if args.check_confinement or run_default:
        _run_check(report, "confinement", runners["confinement"])
    if args.check_privilege or run_default:
        _run_check(report, "privilege", runners["privilege"])
    if args.check_seccomp or run_default:
        _run_check(report, "seccomp", runners["seccomp"])
    if args.check_net:
        _run_check(report, "net", runners["net"])
    if egress_enabled:
        _run_check(report, "egress", runners["egress"])
    if args.tool:
        _run_check(report, "tools", lambda: check_tools(args.tool))

    report["ok"] = not report["errors"]
    _print_report(report)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
