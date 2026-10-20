# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Native integration tests for sandbox/trellis-sandbox.c.

Skipped unless the helper is built and TRELLIS_SANDBOX_INTEGRATION=1. Runs
unprivileged: the helper is given the caller's own uid/gid, so it early-returns
from the identity change while still applying Landlock confinement.
"""

import json
import os
import shlex
import subprocess
import sys

import pytest

from core import sandbox_preflight


HELPER = os.getenv("SANDBOX_HELPER", "/usr/local/bin/trellis-sandbox")
UID = os.getuid()
GID = os.getgid()

pytestmark = pytest.mark.skipif(
    os.getenv("TRELLIS_SANDBOX_INTEGRATION") != "1"
    or not os.access(HELPER, os.X_OK)
    or sandbox_preflight.landlock_abi_version() == 0,
    reason="set TRELLIS_SANDBOX_INTEGRATION=1, build the helper, and use a Landlock kernel",
)


def run_helper(args, input=None):
    return subprocess.run(
        [HELPER, *args],
        capture_output=True,
        text=True,
        input=input,
        timeout=120,
    )


def _granted_args(tmp_path):
    """Build the standard grant set using the caller's own identity."""
    ws = tmp_path / "ws"
    run = tmp_path / "run"
    ws.mkdir(exist_ok=True)
    run.mkdir(exist_ok=True)
    return [
        "--ro", "/",
        "--rw", str(ws),
        "--tmpdir", str(run),
        "--uid", str(UID),
        "--gid", str(GID),
    ]


def test_version():
    result = run_helper(["--version"])

    assert result.returncode == 0
    assert result.stdout.strip() == "trellis-sandbox 0.2.0"


def test_print_plan(tmp_path):
    result = run_helper(
        ["--print-plan", *_granted_args(tmp_path), "--", "/bin/true"]
    )

    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)

    abi = sandbox_preflight.landlock_abi_version()
    assert plan["abi"] == abi
    assert plan["uid"] == UID
    assert plan["gid"] == GID
    assert plan["scoped"] == (3 if abi >= 6 else 0)
    assert plan["seccomp"] is True

    no_seccomp = json.loads(
        run_helper(
            ["--print-plan", *_granted_args(tmp_path), "--no-seccomp", "--", "/bin/true"]
        ).stdout
    )
    assert no_seccomp["seccomp"] is False

    mask = int(plan["handled_access_fs"], 16)
    for bit in range(13):
        assert mask & (1 << bit), f"ABI-1 right 1<<{bit} missing from {mask:#x}"
    if abi >= 2:
        assert mask & (1 << 13), "REFER missing"
    if abi >= 3:
        assert mask & (1 << 14), "TRUNCATE missing"
    if abi >= 5:
        assert mask & (1 << 15), "IOCTL_DEV missing"


def test_confinement_and_identity(tmp_path):
    ws = tmp_path / "ws"
    escape = tmp_path / "escape"
    script = "\n".join(
        [
            "id -u",
            "grep '^CapEff:' /proc/self/status",
            'printf ok > "$TMPDIR/ok"; echo tmp=$?',
            f"printf ws > {shlex.quote(str(ws / 'file'))}; echo ws=$?",
            "cat /etc/hostname >/dev/null; echo etc=$?",
            f"printf bad > {shlex.quote(str(escape))}; echo escape=$?",
        ]
    )

    result = run_helper([*_granted_args(tmp_path), "--", "/bin/sh", "-c", script])

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0] == str(UID)
    assert "CapEff:\t0000000000000000" in result.stdout
    assert "tmp=0" in result.stdout
    assert "ws=0" in result.stdout
    assert "etc=0" in result.stdout

    escape_lines = [line for line in lines if line.startswith("escape=")]
    assert len(escape_lines) == 1
    assert int(escape_lines[0].split("=", 1)[1]) != 0
    assert "Permission denied" in result.stderr

    assert (ws / "file").stat().st_uid == UID


def test_exec_exit_code_passthrough(tmp_path):
    result = run_helper(
        [*_granted_args(tmp_path), "--", "/bin/sh", "-c", "exit 42"]
    )

    assert result.returncode == 42


def test_usage_errors(tmp_path):
    missing_separator = run_helper(
        ["--ro", "/", "--tmpdir", str(tmp_path), "/bin/true"]
    )
    assert missing_separator.returncode == 64

    missing_tmpdir = run_helper(
        [
            "--ro", "/",
            "--tmpdir", str(tmp_path / "does-not-exist"),
            "--", "/bin/true",
        ]
    )
    assert missing_tmpdir.returncode == 67


def test_sibling_proc_environ_denied(tmp_path):
    if sandbox_preflight.probe_yama()["ptrace_scope"] != 1:
        pytest.skip("Yama ptrace_scope is not 1; sibling /proc reads are not denied")
    if os.geteuid() == 0:
        pytest.skip("root bypasses Yama; run this suite unprivileged")

    sibling = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    try:
        result = run_helper(
            [
                *_granted_args(tmp_path),
                "--",
                "/bin/sh", "-c", f"cat /proc/{sibling.pid}/environ",
            ]
        )
    finally:
        sibling.kill()
        sibling.wait(timeout=10)

    assert result.returncode != 0
    assert "PATH=" not in result.stdout


def test_no_seccomp_flag_accepted(tmp_path):
    result = run_helper(
        [*_granted_args(tmp_path), "--no-seccomp", "--", "/bin/true"]
    )

    assert result.returncode == 0, result.stderr


def test_uid_zero_is_rejected(tmp_path):
    result = run_helper(
        [
            "--ro", "/",
            "--tmpdir", str(tmp_path),
            "--uid", "0", "--gid", "0",
            "--", "/bin/true",
        ]
    )

    assert result.returncode == 64
    assert "root" in result.stderr


@pytest.mark.skipif(
    os.geteuid() != 0, reason="requires root to exercise the real uid drop"
)
def test_root_drops_to_sandbox_uid(tmp_path):
    ws = tmp_path / "ws"
    run = tmp_path / "run"
    ws.mkdir()
    run.mkdir()
    # The target uid must be able to create the file after the drop.
    ws.chmod(0o777)

    result = run_helper(
        [
            "--ro", "/",
            "--rw", str(ws),
            "--tmpdir", str(run),
            "--uid", "1000",
            "--gid", "1000",
            "--",
            "/bin/sh", "-c",
            f"id -u; id -G; grep '^CapEff:' /proc/self/status; "
            f"echo x > {ws}/file",
        ]
    )

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0] == "1000"
    assert lines[1].strip() == "1000"
    assert "0000000000000000" in lines[2]
    assert (ws / "file").stat().st_uid == 1000
    assert run.stat().st_uid == 1000


def _run_python(tmp_path, code, extra=()):
    return run_helper(
        [*_granted_args(tmp_path), *extra, "--", sys.executable, "-c", code]
    )


def test_seccomp_denies_userns_creation(tmp_path):
    result = _run_python(
        tmp_path,
        "import os\n"
        "try:\n"
        "    os.unshare(os.CLONE_NEWUSER)\n"
        "    print('OK')\n"
        "except OSError as exc:\n"
        "    print(exc.errno)\n",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1"  # EPERM


IO_URING_CODE = (
    "import ctypes\n"
    "libc = ctypes.CDLL(None, use_errno=True)\n"
    "print(ctypes.get_errno() if libc.syscall(425, 0, 0) == -1 else 0)\n"
)

PTRACE_CODE = (
    "import ctypes\n"
    "libc = ctypes.CDLL(None, use_errno=True)\n"
    "print(ctypes.get_errno() if libc.ptrace(0, 0, 0, 0) == -1 else 0)\n"
)


def test_seccomp_denies_io_uring_with_enosys(tmp_path):
    baseline = _run_python(tmp_path, IO_URING_CODE, extra=["--no-seccomp"])
    if baseline.stdout.strip() == "38":
        pytest.skip("host already disables io_uring; filter not observable")

    result = _run_python(tmp_path, IO_URING_CODE)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "38"  # ENOSYS: libuv degrades cleanly


def test_seccomp_denies_ptrace(tmp_path):
    baseline = _run_python(tmp_path, PTRACE_CODE, extra=["--no-seccomp"])
    if baseline.stdout.strip() == "1":
        pytest.skip("process is already traced; filter not observable")

    result = _run_python(tmp_path, PTRACE_CODE)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1"  # EPERM


def test_seccomp_keeps_threads_working(tmp_path):
    result = _run_python(
        tmp_path,
        "import threading\n"
        "threads = [threading.Thread(target=lambda: None) for _ in range(12)]\n"
        "[t.start() for t in threads]\n"
        "[t.join() for t in threads]\n"
        "print('OK')\n",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "OK"


def test_no_seccomp_allows_userns_again(tmp_path):
    result = _run_python(
        tmp_path,
        "import os\n"
        "try:\n"
        "    os.unshare(os.CLONE_NEWUSER)\n"
        "    print('OK')\n"
        "except OSError as exc:\n"
        "    print(exc.errno)\n",
        extra=["--no-seccomp"],
    )

    if result.stdout.strip() != "OK":
        pytest.skip("host policy forbids unprivileged user namespaces")
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(
    os.uname().machine != "x86_64", reason="x32 ABI only exists on x86_64"
)
def test_x32_syscalls_do_not_bypass_the_filter(tmp_path):
    code = (
        "import ctypes\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "print(ctypes.get_errno() if libc.syscall(0x40000000 | 272, 0x10000000) == -1 else 0)\n"
    )
    baseline = _run_python(tmp_path, code, extra=["--no-seccomp"])
    if baseline.stdout.strip() == "38":
        pytest.skip("host disables the x32 ABI; bypass is not observable")

    result = _run_python(tmp_path, code)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "38"  # ENOSYS, not a successful unshare


def test_scope_signal_blocks_out_of_domain_signals(tmp_path):
    if sandbox_preflight.landlock_abi_version() < 6:
        pytest.skip("Landlock ABI < 6 has no signal scoping")
    sibling = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    try:
        code = (
            "import os, sys\n"
            f"try:\n"
            f"    os.kill({sibling.pid}, 0)\n"
            f"    print('OK')\n"
            f"except OSError as exc:\n"
            f"    print(exc.errno)\n"
        )
        result = _run_python(tmp_path, code)
    finally:
        sibling.kill()
        sibling.wait(timeout=10)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1"  # EPERM
