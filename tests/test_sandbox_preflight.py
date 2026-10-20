# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for core.sandbox_preflight — no network, root, or containers required."""

import errno
import logging
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from core import sandbox_preflight as preflight


@pytest.fixture(autouse=True)
def _reset_cache():
    preflight.reset_for_tests()
    yield
    preflight.reset_for_tests()


def _probe(ok: bool, code: str | None = None, detail: str = "") -> preflight.ProbeResult:
    return preflight.ProbeResult(
        backend="bwrap",
        ok=ok,
        code=code,
        detail=detail,
        remediation=preflight.REMEDIATIONS.get(code or "unknown", ""),
    )


@pytest.mark.parametrize(
    "stderr,evidence,expected",
    [
        (
            "bwrap: setting up uid map: Permission denied",
            {},
            "userns_restriction",
        ),
        (
            "bwrap: clone_newuser: Operation not permitted",
            {},
            "userns_restriction",
        ),
        (
            "bwrap: pivot_root: Operation not permitted",
            {},
            "seccomp_pivot_root",
        ),
        (
            "bwrap: Can't mount proc on /newroot/proc: Permission denied",
            {"apparmor": {"enabled": True, "profile": "docker-default (enforce)"}},
            "apparmor_mount_denied",
        ),
        (
            # A host-global AppArmor module is not enough: an unconfined
            # container profile must not be blamed for the denial.
            "bwrap: Can't mount proc on /newroot/proc: Permission denied",
            {"apparmor": {"enabled": True, "profile": "unconfined"}},
            "mount_denied_unknown_lsm",
        ),
        (
            "bwrap: Can't bind mount / to /: Permission denied",
            {"apparmor": {"enabled": False, "profile": "trellis-hub (enforce)"}},
            "apparmor_mount_denied",
        ),
        (
            "bwrap: Can't mount proc on /newroot/proc: Permission denied",
            {"selinux": True, "apparmor": {"enabled": True, "profile": ""}},
            "selinux_denied",
        ),
        (
            "bwrap: Can't mount proc on /newroot/proc: Permission denied",
            {"selinux": False, "apparmor": {"enabled": False, "profile": ""}},
            "mount_denied_unknown_lsm",
        ),
        (
            "bwrap: not found",
            {},
            "bwrap_missing",
        ),
        (
            # A missing bind source or interpreter is NOT "bwrap missing" --
            # telling the operator to install bwrap would be wrong.
            "bwrap: Can't find source path /app/workspace: No such file or directory",
            {},
            None,
        ),
        (
            "bwrap: execvp /bin/true: Exec format error",
            {},
            None,
        ),
        (
            "some unrelated failure: Permission denied",
            {},
            None,
        ),
    ],
)
def test_classify_bwrap_stderr(stderr, evidence, expected):
    assert preflight.classify_bwrap_stderr(stderr, evidence) == expected


def test_classify_bwrap_stderr_without_evidence():
    assert (
        preflight.classify_bwrap_stderr("bwrap: Can't mount proc: Permission denied")
        == "mount_denied_unknown_lsm"
    )


def test_classify_bwrap_stderr_netns_probe_marks_the_netns_refusal():
    """The same text means different things before and after the base run."""
    text = "bwrap: Creating new namespace failed: Operation not permitted"

    assert preflight.classify_bwrap_stderr(text) == "userns_restriction"
    assert preflight.classify_bwrap_stderr(text, netns=True) == "netns_denied"
    assert (
        preflight.classify_bwrap_stderr(
            "bwrap: setting up network namespace: Operation not permitted",
            netns=True,
        )
        == "netns_denied"
    )


def test_codes_and_remediations_are_complete():
    assert preflight.CODES
    for code in preflight.CODES:
        assert preflight.REMEDIATIONS.get(code), f"missing remediation for {code}"
    assert all(preflight.REMEDIATIONS[code].strip() for code in preflight.CODES)


def test_bwrap_base_args_match_hub_invocation():
    assert preflight.BWRAP_BASE_ARGS == (
        "bwrap",
        "--ro-bind", "/", "/",
        "--bind", "/app/workspace", "/app/workspace",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--cap-drop", "ALL",
    )


def test_read_lsm_evidence_tolerates_missing_files(monkeypatch):
    monkeypatch.setattr(preflight, "_read_text", lambda path: "")
    monkeypatch.setattr(preflight.os.path, "exists", lambda path: False)
    monkeypatch.setattr(preflight, "helper_path", lambda: "/nonexistent/trellis-sandbox")
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 0)

    evidence = preflight.read_lsm_evidence()

    assert evidence == {
        "apparmor": {"enabled": False, "profile": ""},
        "selinux": False,
        "landlock_abi": 0,
        "helper": {"present": False},
    }


def test_read_lsm_evidence_parses_apparmor_enabled_and_profile(monkeypatch):
    values = {
        "/sys/module/apparmor/parameters/enabled": "Y\n",
        "/proc/self/attr/current": "docker-default (enforce)\n",
    }
    monkeypatch.setattr(preflight, "_read_text", lambda path: values.get(path, ""))
    monkeypatch.setattr(preflight.os.path, "exists", lambda path: False)
    monkeypatch.setattr(preflight.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 3)

    evidence = preflight.read_lsm_evidence()

    assert evidence["apparmor"] == {
        "enabled": True,
        "profile": "docker-default (enforce)",
    }
    assert evidence["helper"]["present"] is True
    assert evidence["landlock_abi"] == 3


def test_landlock_abi_version_returns_kernel_value(monkeypatch):
    class _FakeLibc:
        def syscall(self, *args):
            assert args == (444, 0, 0, 1)
            return 7

    monkeypatch.setattr(preflight.ctypes, "CDLL", lambda *a, **k: _FakeLibc())

    assert preflight.landlock_abi_version() == 7


@pytest.mark.parametrize("raw", [-1, 0])
def test_landlock_abi_version_returns_zero_when_unsupported(monkeypatch, raw):
    """ctypes does not raise for a failing syscall; it returns -1."""

    class _FakeLibc:
        def syscall(self, *args):
            return raw

    monkeypatch.setattr(preflight.ctypes, "CDLL", lambda *a, **k: _FakeLibc())

    assert preflight.landlock_abi_version() == 0


def test_landlock_abi_version_returns_zero_on_enosys(monkeypatch):
    class _FakeLibc:
        def syscall(self, *args):
            raise OSError(errno.ENOSYS, "Function not implemented")

    monkeypatch.setattr(preflight.ctypes, "CDLL", lambda *a, **k: _FakeLibc())

    assert preflight.landlock_abi_version() == 0


def test_probe_bwrap_missing(monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)

    result = preflight.probe_bwrap()

    assert result.ok is False
    assert result.backend == "bwrap"
    assert result.code == "bwrap_missing"
    assert result.detail
    assert result.remediation == preflight.REMEDIATIONS["bwrap_missing"]


def test_probe_bwrap_success(monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda name: "/usr/bin/bwrap")
    monkeypatch.setattr(
        preflight.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""),
    )

    result = preflight.probe_bwrap()

    assert result.ok is True
    assert result.backend == "bwrap"
    assert result.code is None
    assert result.evidence["bwrap_netns"]["ok"] is True


def test_probe_bwrap_netns_denial_is_advisory(monkeypatch):
    """A host that refuses --unshare-net passes bwrap but breaks `network: none`."""
    monkeypatch.setattr(preflight.shutil, "which", lambda name: "/usr/bin/bwrap")
    calls = []

    def _run(argv, **kwargs):
        calls.append(argv)
        if "--unshare-net" in argv:
            return subprocess.CompletedProcess(
                argv,
                1,
                "",
                "bwrap: Creating new namespace failed: Operation not permitted",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(preflight.subprocess, "run", _run)

    result = preflight.probe_bwrap()

    assert len(calls) == 2
    assert result.ok is True
    assert result.code is None
    assert result.evidence["bwrap_netns"]["ok"] is False
    assert result.evidence["bwrap_netns"]["code"] == "netns_denied"


def test_probe_bwrap_netns_probe_skipped_when_the_base_run_fails(monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda name: "/usr/bin/bwrap")
    calls = []

    def _run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv, 1, "", "bwrap: pivot_root: Operation not permitted"
        )

    monkeypatch.setattr(preflight.subprocess, "run", _run)

    result = preflight.probe_bwrap()

    assert len(calls) == 1
    assert result.ok is False
    assert result.code == "seccomp_pivot_root"


def test_bwrap_netns_denial_does_not_fail_the_verdict(monkeypatch, caplog):
    monkeypatch.delenv("SANDBOX_BACKEND", raising=False)
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 5)
    monkeypatch.setattr(
        preflight,
        "_read_text",
        lambda path: "1\n" if path.endswith("ptrace_scope") else "",
    )
    monkeypatch.setattr(
        preflight,
        "probe_bwrap",
        lambda *a, **k: preflight.ProbeResult(
            backend="bwrap",
            ok=True,
            evidence={
                "bwrap_netns": {
                    "ok": False,
                    "code": "netns_denied",
                    "detail": "no netns here",
                }
            },
        ),
    )

    with caplog.at_level(logging.WARNING, logger=preflight.logger.name):
        payload = preflight.warmup()
        preflight.warmup()

    # `allow` tools never pass --unshare-net, so the verdict stays healthy.
    assert payload["ok"] is True
    assert payload["backend"] == "bwrap"
    assert payload["evidence"]["bwrap_netns"] == {
        "ok": False,
        "code": "netns_denied",
        "detail": "no netns here",
    }
    assert "netns_denied" in payload["warnings"]

    netns_warnings = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING
        and "network namespace" in record.getMessage()
    ]
    assert len(netns_warnings) == 1
    assert preflight.REMEDIATIONS["netns_denied"] in netns_warnings[0]


def test_probe_bwrap_classifies_apparmor_mount_denial(monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda name: "/usr/bin/bwrap")
    monkeypatch.setattr(
        preflight.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            [], 1, "", "bwrap: Can't mount proc on /newroot/proc: Permission denied"
        ),
    )
    monkeypatch.setattr(
        preflight,
        "read_lsm_evidence",
        lambda: {
            "apparmor": {"enabled": True, "profile": "docker-default"},
            "selinux": False,
            "landlock_abi": 0,
            "helper": {"present": False},
        },
    )

    result = preflight.probe_bwrap()

    assert result.ok is False
    assert result.code == "apparmor_mount_denied"
    assert result.remediation
    assert result.remediation == preflight.REMEDIATIONS["apparmor_mount_denied"]


def test_probe_bwrap_decodes_bytes_output(monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda name: "/usr/bin/bwrap")
    monkeypatch.setattr(
        preflight.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            [], 1, b"", b"bwrap: pivot_root: Operation not permitted"
        ),
    )

    result = preflight.probe_bwrap()

    assert result.code == "seccomp_pivot_root"


def test_probe_bwrap_timeout_is_unknown(monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda name: "/usr/bin/bwrap")

    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="bwrap", timeout=5.0)

    monkeypatch.setattr(preflight.subprocess, "run", _timeout)

    result = preflight.probe_bwrap()

    assert result.ok is False
    assert result.code == "unknown"
    assert result.remediation


@pytest.mark.parametrize(
    "raw,expected_scope,expected_warning",
    [
        ("2\n", 2, None),
        ("0\n", 0, "ptrace_scope_unrestricted"),
        # Missing Yama is as unsafe as scope 0 (same-uid sibling /proc reads).
        ("", None, "ptrace_scope_unrestricted"),
        ("not-a-number", None, "ptrace_scope_unrestricted"),
    ],
)
def test_probe_yama(monkeypatch, raw, expected_scope, expected_warning):
    monkeypatch.setattr(preflight, "_read_text", lambda path: raw)

    result = preflight.probe_yama()

    assert result == {
        "ptrace_scope": expected_scope,
        "warning_code": expected_warning,
    }


def test_healthz_payload_cold_cache_does_not_probe(monkeypatch):
    monkeypatch.delenv("SANDBOX_BACKEND", raising=False)
    monkeypatch.setattr(
        preflight,
        "probe_bwrap",
        lambda *a, **k: pytest.fail("healthz must not probe on the request path"),
    )
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 0)

    status, payload = preflight.build_healthz_payload()

    assert status == 503
    assert payload["ok"] is False
    assert payload["remediation"]


def test_healthz_payload_ok(monkeypatch):
    monkeypatch.delenv("SANDBOX_BACKEND", raising=False)
    monkeypatch.setattr(preflight, "probe_bwrap", lambda timeout=5.0: _probe(True))
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 5)
    monkeypatch.setattr(
        preflight,
        "_read_text",
        lambda path: "1\n" if path.endswith("ptrace_scope") else "",
    )

    preflight.warmup()
    status, payload = preflight.build_healthz_payload()

    assert status == 200
    assert payload["ok"] is True
    assert payload["backend"] == "bwrap"
    assert payload["requested"] == "auto"
    assert payload["landlock_abi"] == 5
    assert payload["sandbox_uid"] == 1000
    assert payload["ptrace_scope"] == 1
    assert payload["warnings"] == []
    assert payload["evidence"]["helper"]["present"] is False
    assert "checked_at" in payload
    assert preflight.cached_status()["backend"] == "bwrap"


def test_healthz_payload_failure_and_single_critical(monkeypatch, caplog):
    monkeypatch.setenv("SANDBOX_BACKEND", "bwrap")
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 0)
    monkeypatch.setattr(
        preflight,
        "probe_bwrap",
        lambda timeout=5.0: _probe(False, "seccomp_pivot_root", "x" * 900),
    )
    caplog.set_level(logging.CRITICAL)

    preflight.warmup()
    status, payload = preflight.build_healthz_payload()

    assert status == 503
    assert payload["ok"] is False
    assert payload["backend"] == "none"
    assert payload["code"] == "seccomp_pivot_root"
    assert payload["remediation"]
    assert len(payload["detail"]) <= 500

    criticals = [
        record
        for record in caplog.records
        if record.levelno == logging.CRITICAL
        and record.name == preflight.logger.name
    ]
    assert len(criticals) == 1
    assert "seccomp_pivot_root" in criticals[0].getMessage()
    assert preflight.REMEDIATIONS["seccomp_pivot_root"] in criticals[0].getMessage()


def test_healthz_cached_failure_logs_only_once(monkeypatch, caplog):
    monkeypatch.delenv("SANDBOX_BACKEND", raising=False)
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 0)
    monkeypatch.setattr(
        preflight, "probe_bwrap", lambda timeout=5.0: _probe(False, "bwrap_missing")
    )
    caplog.set_level(logging.CRITICAL)

    preflight.warmup()
    preflight.build_healthz_payload()

    assert len([r for r in caplog.records if r.levelno == logging.CRITICAL]) == 1


def test_invalid_sandbox_backend_behaves_as_auto(monkeypatch, caplog):
    monkeypatch.setenv("SANDBOX_BACKEND", "  bogus  ")
    monkeypatch.setattr(preflight, "probe_bwrap", lambda timeout=5.0: _probe(True))
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 0)

    payload = preflight.warmup()

    assert payload["requested"] == "auto"
    assert payload["ok"] is True
    assert payload["backend"] == "bwrap"
    assert any(
        record.levelno == logging.WARNING and "bogus" in record.getMessage()
        for record in caplog.records
    )


def test_probe_crash_never_crashes_warmup(monkeypatch):
    monkeypatch.setenv("SANDBOX_BACKEND", "bwrap")
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 0)

    def _boom(*args, **kwargs):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(preflight, "probe_bwrap", _boom)

    payload = preflight.warmup()

    assert payload["ok"] is False
    assert payload["code"] == "unknown"
    assert payload["remediation"]
    assert payload["detail"]


def test_landlock_backend_unavailable_without_kernel_support(monkeypatch):
    monkeypatch.setenv("SANDBOX_BACKEND", "landlock")
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 0)
    monkeypatch.setattr(
        preflight,
        "probe_bwrap",
        lambda *a, **k: pytest.fail("bwrap must not be selected for landlock"),
    )

    preflight.warmup()
    status, payload = preflight.build_healthz_payload()

    assert status == 503
    assert payload["backend"] == "none"
    assert payload["code"] == "landlock_unavailable"
    assert payload["remediation"]


def test_resolve_sandbox_identity_env_override(monkeypatch):
    monkeypatch.setenv("SANDBOX_UID", "4242")
    monkeypatch.setenv("SANDBOX_GID", "4343")

    assert preflight.resolve_sandbox_identity() == (4242, 4343)


def test_resolve_sandbox_identity_uses_trellis_user(monkeypatch):
    monkeypatch.delenv("SANDBOX_UID", raising=False)
    monkeypatch.delenv("SANDBOX_GID", raising=False)
    monkeypatch.setattr(
        preflight.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_uid=1234, pw_gid=2345),
    )

    assert preflight.resolve_sandbox_identity() == (1234, 2345)


def test_resolve_sandbox_identity_falls_back_to_1000(monkeypatch):
    monkeypatch.delenv("SANDBOX_UID", raising=False)
    monkeypatch.delenv("SANDBOX_GID", raising=False)

    def _missing(name):
        raise KeyError(name)

    monkeypatch.setattr(preflight.pwd, "getpwnam", _missing)

    assert preflight.resolve_sandbox_identity() == (1000, 1000)


def _install_helper_probe(monkeypatch, completed):
    """Make the helper look present and script its subprocess result."""
    monkeypatch.setattr(preflight, "_helper_probe_error", lambda backend, helper: None)
    monkeypatch.setattr(preflight, "resolve_sandbox_identity", lambda: (1000, 1000))
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 10)
    monkeypatch.setattr(
        preflight.subprocess, "run", lambda *a, **k: completed
    )


def test_probe_landlock_success_checks_identity(monkeypatch):
    _install_helper_probe(
        monkeypatch, subprocess.CompletedProcess([], 0, "1000\n", "")
    )

    result = preflight.probe_landlock(helper="/usr/local/bin/trellis-sandbox")

    assert result.ok is True
    assert result.backend == "landlock"


def test_probe_landlock_rejects_identity_mismatch(monkeypatch):
    _install_helper_probe(
        monkeypatch, subprocess.CompletedProcess([], 0, "0\n", "")
    )

    result = preflight.probe_landlock(helper="/usr/local/bin/trellis-sandbox")

    assert result.ok is False
    assert result.code == "landlock_setuid_denied"
    assert result.remediation == preflight.REMEDIATIONS["landlock_setuid_denied"]


def test_probe_landlock_missing_helper(monkeypatch):
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 10)
    monkeypatch.setattr(
        preflight,
        "_helper_probe_error",
        lambda backend, helper: preflight.ProbeResult(
            backend=backend,
            ok=False,
            code="helper_failed",
            detail="missing",
            remediation=preflight.REMEDIATIONS["helper_failed"],
        ),
    )

    result = preflight.probe_landlock()

    assert result.code == "helper_failed"


def test_probe_landlock_without_kernel_support(monkeypatch):
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 0)
    monkeypatch.setattr(
        preflight,
        "_helper_probe_error",
        lambda *a, **k: pytest.fail("kernel check runs before helper lookup"),
    )

    assert preflight.probe_landlock().code == "landlock_unavailable"


def _landlock_payload(monkeypatch, net_result, abi=6):
    monkeypatch.setenv("SANDBOX_BACKEND", "landlock")
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: abi)
    monkeypatch.setattr(
        preflight, "_read_text",
        lambda path: "1\n" if path.endswith("ptrace_scope") else "",
    )
    monkeypatch.setattr(preflight, "probe_landlock", lambda *a, **k: _probe(True))
    monkeypatch.setattr(
        preflight, "probe_privilege_drop", lambda *a, **k: _probe(True)
    )
    monkeypatch.setattr(
        preflight, "probe_landlock_net", lambda *a, **k: net_result
    )
    return preflight.warmup()


def test_healthz_reports_net_policy_support(monkeypatch):
    payload = _landlock_payload(
        monkeypatch, preflight.NetProbeResult(True, "--deny-net accepted", 6)
    )

    assert payload["ok"] is True
    assert payload["evidence"]["net"] == {
        "deny_supported": True,
        "detail": "--deny-net accepted",
        "abi": 6,
    }
    assert "landlock_net_unsupported" not in payload["warnings"]


def test_unsupported_net_abi_is_advisory_only(monkeypatch):
    payload = _landlock_payload(
        monkeypatch,
        preflight.NetProbeResult(False, "Landlock ABI 3 has no net control", 3),
        abi=3,
    )

    # The default policy is allow, so an unenforceable `none` must not fail
    # startup or block backend selection.
    assert payload["ok"] is True
    assert payload["backend"] == "landlock"
    assert payload["evidence"]["net"]["deny_supported"] is False
    assert payload["evidence"]["net"]["abi"] == 3
    assert "landlock_net_unsupported" in payload["warnings"]


def test_udp_permitted_at_abi4_skips_the_abi_warning(monkeypatch):
    """ABI 4+ can express the TCP policy; the UDP gap has its own cause."""
    payload = _landlock_payload(
        monkeypatch,
        preflight.NetProbeResult(
            False, "seccomp disabled: --deny-net denies TCP only", 6
        ),
        abi=6,
    )

    assert payload["ok"] is True
    assert payload["evidence"]["net"]["deny_supported"] is False
    assert "landlock_net_unsupported" not in payload["warnings"]


def test_bwrap_only_probe_omits_landlock_net_evidence(monkeypatch):
    monkeypatch.setenv("SANDBOX_BACKEND", "bwrap")
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 6)
    monkeypatch.setattr(
        preflight, "_read_text",
        lambda path: "1\n" if path.endswith("ptrace_scope") else "",
    )
    monkeypatch.setattr(preflight, "probe_bwrap", lambda *a, **k: _probe(True))
    monkeypatch.setattr(
        preflight,
        "probe_landlock_net",
        lambda *a, **k: pytest.fail("bwrap-only probe must not run the net probe"),
    )

    payload = preflight.warmup()

    assert payload["ok"] is True
    # bwrap supports --unshare-net unconditionally, so no Landlock verdict is
    # reported rather than a misleading one.
    assert "net" not in payload["evidence"]


def test_probe_landlock_net_gated_on_abi(monkeypatch):
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 3)
    monkeypatch.setattr(
        preflight.subprocess,
        "run",
        lambda *a, **k: pytest.fail("ABI gate must run before the helper"),
    )

    result = preflight.probe_landlock_net()

    assert result.supported is False
    assert result.abi == 3
    assert "ABI 3" in result.detail


def test_probe_landlock_net_argv_and_success(monkeypatch):
    seen = []

    def _run(argv, **kwargs):
        seen.append(argv)
        # A refused UDP socket: the property the probe is looking for. The
        # helper's benign warning line must not read as a helper refusal.
        return subprocess.CompletedProcess(
            argv,
            1,
            "",
            "trellis-sandbox: warning: supplementary groups retained "
            "(needs CAP_SETGID)\n"
            "PermissionError: [Errno 13] Permission denied",
        )

    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 6)
    monkeypatch.setattr(preflight, "_helper_probe_error", lambda *a, **k: None)
    monkeypatch.setattr(preflight, "resolve_sandbox_identity", lambda: (1000, 1000))
    monkeypatch.setattr(preflight.subprocess, "run", _run)

    result = preflight.probe_landlock_net(helper="/h")

    assert result.supported is True
    assert result.abi == 6
    argv = seen[0]
    assert argv[0] == "/h"
    assert argv[argv.index("--") - 1] == "--deny-net"
    assert argv[-2:] == ["-c", argv[-1]]
    assert "socket.socket(socket.AF_INET, socket.SOCK_DGRAM)" in argv[-1]
    assert "--no-seccomp" not in argv


def test_probe_landlock_net_rejects_an_accepting_run(monkeypatch):
    """Exit 0 means the UDP socket was created, so `none` is not enforceable."""
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 6)
    monkeypatch.setattr(preflight, "_helper_probe_error", lambda *a, **k: None)
    monkeypatch.setattr(preflight, "resolve_sandbox_identity", lambda: (1000, 1000))
    monkeypatch.delenv("SANDBOX_SECCOMP", raising=False)
    monkeypatch.setattr(
        preflight.subprocess,
        "run",
        lambda argv, **k: subprocess.CompletedProcess(argv, 0, "", ""),
    )

    result = preflight.probe_landlock_net(helper="/h")

    assert result.supported is False
    assert "UDP still permitted" in result.detail


def test_probe_landlock_net_names_seccomp_when_it_is_off(monkeypatch):
    seen = []

    def _run(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setenv("SANDBOX_SECCOMP", "off")
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 6)
    monkeypatch.setattr(preflight, "_helper_probe_error", lambda *a, **k: None)
    monkeypatch.setattr(preflight, "resolve_sandbox_identity", lambda: (1000, 1000))
    monkeypatch.setattr(preflight.subprocess, "run", _run)

    result = preflight.probe_landlock_net(helper="/h")

    # The probe runs the same argv the hub would (escape hatch included), so the
    # accepting run is explained by the filter that was skipped.
    assert "--no-seccomp" in seen[0]
    assert result.supported is False
    assert "seccomp disabled" in result.detail


def test_probe_landlock_net_reports_helper_failure(monkeypatch):
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 6)
    monkeypatch.setattr(preflight, "_helper_probe_error", lambda *a, **k: None)
    monkeypatch.setattr(preflight, "resolve_sandbox_identity", lambda: (1000, 1000))
    monkeypatch.setattr(
        preflight.subprocess,
        "run",
        lambda argv, **k: subprocess.CompletedProcess(
            argv,
            65,
            "",
            "trellis-sandbox: landlock net access control requires ABI 4 (have 3)",
        ),
    )

    result = preflight.probe_landlock_net(helper="/h")

    assert result.supported is False
    assert "ABI 4" in result.detail


@pytest.mark.parametrize("returncode", [1, 65])
def test_net_marker_is_classified_before_generic_landlock(monkeypatch, returncode):
    _install_helper_probe(
        monkeypatch,
        subprocess.CompletedProcess(
            [],
            returncode,
            "",
            "trellis-sandbox: landlock net access control requires ABI 4 (have 3)",
        ),
    )

    result = preflight.probe_landlock(helper="/usr/local/bin/trellis-sandbox")

    assert result.ok is False
    assert result.code == "landlock_net_unsupported"
    assert result.remediation == preflight.REMEDIATIONS["landlock_net_unsupported"]
    assert "bwrap" in result.remediation


@pytest.mark.parametrize(
    "returncode,stderr,expected",
    [
        (65, "landlock unavailable (ABI 0)", "landlock_unavailable"),
        (67, "path grant failed", "helper_failed"),
        (68, "chown(tmpdir): Operation not permitted", "landlock_setuid_denied"),
        (69, "setrlimit(RLIMIT_AS): Operation not permitted", "rlimit_denied"),
        (1, "setrlimit(RLIMIT_FSIZE): Invalid argument", "rlimit_denied"),
        (1, "setgroups: Operation not permitted", "landlock_setuid_denied"),
        (1, "something else", "unknown"),
    ],
)
def test_probe_landlock_classifies_helper_failures(
    monkeypatch, returncode, stderr, expected
):
    _install_helper_probe(
        monkeypatch, subprocess.CompletedProcess([], returncode, "", stderr)
    )

    result = preflight.probe_landlock(helper="/usr/local/bin/trellis-sandbox")

    assert result.ok is False
    assert result.code == expected


def test_probe_privilege_drop_uses_no_rw_grant(monkeypatch):
    seen = []

    def _run(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "1000\n", "")

    _install_helper_probe(monkeypatch, None)
    monkeypatch.setattr(preflight.subprocess, "run", _run)

    assert preflight.probe_privilege_drop(helper="/h").ok is True
    assert "--rw" not in seen[0]


def test_resolve_sandbox_identity_rejects_root_uid(monkeypatch, caplog):
    monkeypatch.setenv("SANDBOX_UID", "0")
    monkeypatch.setenv("SANDBOX_GID", "0")
    monkeypatch.setattr(
        preflight.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_uid=1000, pw_gid=1000),
    )

    assert preflight.resolve_sandbox_identity() == (1000, 1000)
    assert any("root" in record.getMessage() for record in caplog.records)


def _identity_messages(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING
        and "differs from the hub" in record.getMessage()
    ]


def test_resolve_sandbox_identity_warns_once_when_hub_cannot_switch(
    monkeypatch, caplog
):
    monkeypatch.setenv("SANDBOX_UID", "4242")
    monkeypatch.setenv("SANDBOX_GID", "4343")
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(preflight.os, "getegid", lambda: 1000)

    assert preflight.resolve_sandbox_identity() == (4242, 4343)
    assert preflight.resolve_sandbox_identity() == (4242, 4343)

    messages = _identity_messages(caplog)
    assert len(messages) == 1
    assert "4242" in messages[0] and "1000" in messages[0]
    assert "SANDBOX_UID" in messages[0]
    assert "SANDBOX_GID" in messages[0]
    assert "root" in messages[0]


def test_resolve_sandbox_identity_warns_on_gid_only_mismatch(monkeypatch, caplog):
    """A gid-only mismatch takes the chown branch too, so it must be reported."""
    monkeypatch.setenv("SANDBOX_UID", "1000")
    monkeypatch.setenv("SANDBOX_GID", "4343")
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(preflight.os, "getegid", lambda: 1000)

    assert preflight.resolve_sandbox_identity() == (1000, 4343)

    messages = _identity_messages(caplog)
    assert len(messages) == 1
    assert "SANDBOX_GID=4343" in messages[0]
    assert "differs from the hub uid" not in messages[0]


def test_resolve_sandbox_identity_silent_when_ids_match(monkeypatch, caplog):
    monkeypatch.setenv("SANDBOX_UID", "1000")
    monkeypatch.setenv("SANDBOX_GID", "1000")
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(preflight.os, "getegid", lambda: 1000)

    assert preflight.resolve_sandbox_identity() == (1000, 1000)
    assert _identity_messages(caplog) == []


def test_resolve_sandbox_identity_silent_for_root_hub(monkeypatch, caplog):
    monkeypatch.setenv("SANDBOX_UID", "4242")
    monkeypatch.setenv("SANDBOX_GID", "4343")
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 0)

    assert preflight.resolve_sandbox_identity() == (4242, 4343)
    assert _identity_messages(caplog) == []


def _install_stable_host(monkeypatch):
    """Make every non-monkeypatched probe deterministic and host-independent."""
    monkeypatch.delenv("SANDBOX_BACKEND", raising=False)
    monkeypatch.setattr(preflight, "landlock_abi_version", lambda: 5)
    monkeypatch.setattr(
        preflight,
        "_read_text",
        lambda path: "1\n" if path.endswith("ptrace_scope") else "",
    )
    monkeypatch.setattr(
        preflight,
        "probe_landlock_net",
        lambda *a, **k: preflight.NetProbeResult(False, "stubbed for tests", 5),
    )


def _install_ok_bwrap_probe(monkeypatch, calls):
    def _run(*args, **kwargs):
        calls.append(1)
        return _probe(True)

    monkeypatch.setattr(preflight, "probe_bwrap", _run)


def test_invalidate_clears_the_cached_verdict(monkeypatch, caplog):
    _install_stable_host(monkeypatch)
    monkeypatch.setattr(preflight, "probe_bwrap", lambda *a, **k: _probe(True))
    preflight.warmup()
    assert preflight.cached_status()["ok"] is True

    with caplog.at_level(logging.INFO, logger=preflight.logger.name):
        assert preflight.invalidate("tool failure: helper_failed") is True

    assert preflight.cached_status() == {}
    infos = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.INFO and "invalidated" in record.getMessage()
    ]
    assert len(infos) == 1
    assert "helper_failed" in infos[0]


def test_invalidate_is_cooldown_bounded(monkeypatch):
    _install_stable_host(monkeypatch)
    monkeypatch.setattr(preflight, "probe_bwrap", lambda *a, **k: _probe(True))
    clock = [1000.0]
    monkeypatch.setattr(preflight, "_monotonic", lambda: clock[0])

    assert preflight._REPROBE_COOLDOWN_S == 60.0
    assert preflight.invalidate("first") is True

    preflight.warmup()  # the re-probe that follows an invalidation
    assert preflight.invalidate("second") is False
    # Inside the cooldown the fresh verdict must survive untouched.
    assert preflight.cached_status()["ok"] is True

    clock[0] += preflight._REPROBE_COOLDOWN_S
    assert preflight.invalidate("third") is True
    assert preflight.cached_status() == {}


def test_invalidate_logs_once_per_window(monkeypatch, caplog):
    clock = [0.0]
    monkeypatch.setattr(preflight, "_monotonic", lambda: clock[0])

    with caplog.at_level(logging.INFO, logger=preflight.logger.name):
        assert preflight.invalidate("first") is True
        assert preflight.invalidate("suppressed") is False

    infos = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.INFO and "invalidated" in record.getMessage()
    ]
    assert len(infos) == 1
    assert "suppressed" not in infos[0]


def test_reset_for_tests_clears_the_cooldown(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(preflight, "_monotonic", lambda: clock[0])
    assert preflight.invalidate("first") is True
    assert preflight.invalidate("second") is False

    preflight.reset_for_tests()

    assert preflight.invalidate("after reset") is True


def test_invalidated_healthz_reprobes_and_serves_a_fresh_payload(monkeypatch):
    calls = []
    _install_stable_host(monkeypatch)
    _install_ok_bwrap_probe(monkeypatch, calls)

    preflight.warmup()
    assert len(calls) == 1

    assert preflight.invalidate("tool failure: apparmor_mount_denied") is True
    assert preflight.cached_status() == {}

    status, payload = preflight.build_healthz_payload()

    assert len(calls) == 2
    assert status == 200
    assert payload["ok"] is True
    assert payload["backend"] == "bwrap"
    # The re-probe re-caches, so the next request stays probe-free again.
    assert preflight.cached_status()["ok"] is True
    preflight.build_healthz_payload()
    assert len(calls) == 2


def test_invalidated_healthz_reports_a_newly_broken_backend(monkeypatch):
    """The point of the re-probe: /healthz must stop calling a broken host healthy."""
    _install_stable_host(monkeypatch)
    monkeypatch.setattr(preflight, "probe_bwrap", lambda *a, **k: _probe(True))
    preflight.warmup()
    assert preflight.build_healthz_payload()[0] == 200

    monkeypatch.setattr(
        preflight,
        "probe_bwrap",
        lambda *a, **k: _probe(False, "apparmor_mount_denied"),
    )
    monkeypatch.setattr(
        preflight,
        "probe_landlock",
        lambda *a, **k: _probe(False, "helper_failed"),
    )
    monkeypatch.setattr(
        preflight, "probe_privilege_drop", lambda *a, **k: _probe(True)
    )
    assert preflight.invalidate("tool failure: helper_failed") is True

    status, payload = preflight.build_healthz_payload()

    assert status == 503
    assert payload["ok"] is False
    assert payload["code"] == "helper_failed"


def test_stale_reprobe_is_single_flight(monkeypatch):
    """Concurrent /healthz requests must not each fork their own probe set."""
    calls = []
    started = threading.Event()
    release = threading.Event()

    _install_stable_host(monkeypatch)

    def _slow_probe(*args, **kwargs):
        calls.append(1)
        started.set()
        assert release.wait(5), "probe was never released"
        return _probe(True)

    monkeypatch.setattr(preflight, "probe_bwrap", _slow_probe)
    assert preflight.invalidate("tool failure: helper_failed") is True

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(preflight.build_healthz_payload)
        assert started.wait(5)
        second = pool.submit(preflight.build_healthz_payload)
        # Give the second caller time to reach the gate; without single-flight
        # it would start a probe of its own and bump `calls` to 2.
        deadline = time.monotonic() + 1.0
        while len(calls) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        release.set()
        results = [first.result(10), second.result(10)]

    assert len(calls) == 1
    assert [status for status, _ in results] == [200, 200]
    assert all(payload["ok"] is True for _, payload in results)


def test_stale_reprobe_waiter_reports_in_progress_instead_of_probing(monkeypatch):
    """A caller that cannot get the gate must not start a second probe set."""
    _install_stable_host(monkeypatch)
    monkeypatch.setattr(
        preflight,
        "probe_bwrap",
        lambda *a, **k: pytest.fail("a waiting caller must not probe"),
    )
    monkeypatch.setattr(preflight, "_REPROBE_WAIT_S", 0.01)
    assert preflight.invalidate("tool failure: helper_failed") is True

    # Hold the single-flight gate as the "probe in flight".
    assert preflight._STALE_REPROBE_LOCK.acquire(blocking=False) is True
    try:
        status, payload = preflight.build_healthz_payload()
    finally:
        preflight._STALE_REPROBE_LOCK.release()

    assert status == 503
    assert "re-probe is still running" in payload["detail"]
    assert payload["remediation"]


def test_warmup_discards_a_verdict_probed_across_an_invalidation(monkeypatch):
    """A probe that straddles invalidate() must not republish its older verdict."""
    calls = []
    started = threading.Event()
    release = threading.Event()

    _install_stable_host(monkeypatch)

    def _slow_probe(*args, **kwargs):
        calls.append(1)
        started.set()
        assert release.wait(5), "probe was never released"
        return _probe(True)

    monkeypatch.setattr(preflight, "probe_bwrap", _slow_probe)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(preflight.warmup)
        assert started.wait(5)
        assert preflight.invalidate("tool failure: helper_failed") is True
        release.set()
        stale_payload = future.result(10)

    # The caller still receives the verdict its probe produced...
    assert stale_payload["ok"] is True
    # ...but it is older than the invalidation, so it is not published.
    assert preflight.cached_status() == {}
    assert preflight._STATUS_STALE is True

    # The invalidation survives: the next reader re-probes and publishes.
    monkeypatch.setattr(preflight, "probe_bwrap", lambda *a, **k: _probe(True))
    status, payload = preflight.build_healthz_payload()

    assert status == 200
    assert payload["ok"] is True
    assert preflight.cached_status()["ok"] is True
    assert len(calls) == 1


def test_seccomp_off_warns_once_about_the_udp_gap(monkeypatch, caplog):
    _install_stable_host(monkeypatch)
    monkeypatch.setenv("SANDBOX_SECCOMP", "off")
    monkeypatch.setattr(preflight, "probe_bwrap", lambda *a, **k: _probe(True))

    with caplog.at_level(logging.WARNING, logger=preflight.logger.name):
        preflight.warmup()
        preflight.warmup()

    messages = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING and "UDP" in record.getMessage()
    ]
    assert len(messages) == 1
    assert "network: none" in messages[0]
    assert "bwrap" in messages[0]
