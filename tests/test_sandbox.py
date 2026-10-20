# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for core.sandbox.

Nothing here executes bwrap or the Landlock helper: every probe is
monkeypatched, so the suite runs on any host (no root, containers, or LSMs).
The argv builders and the per-run tmpdir lifecycle are pinned exactly.
"""

import logging
import stat
from pathlib import Path

import pytest

from core import sandbox, sandbox_preflight


HELPER = "/usr/local/bin/trellis-sandbox"
LSM_EVIDENCE = {
    "apparmor": {},
    "selinux": False,
    "landlock_abi": 10,
    "helper": {"present": True},
}


def _ok(backend):
    return sandbox_preflight.ProbeResult(backend=backend, ok=True)


def _fail(backend, code):
    return sandbox_preflight.ProbeResult(
        backend=backend,
        ok=False,
        code=code,
        detail="detail",
        remediation=sandbox_preflight.REMEDIATIONS[code],
    )


@pytest.fixture(autouse=True)
def _isolated_sandbox(monkeypatch):
    """Reset caches/env and make every real probe a hard test failure."""
    sandbox.reset_for_tests()
    for name in (
        "SANDBOX_BACKEND",
        "SANDBOX_SECCOMP",
        "SANDBOX_NET_DEFAULT",
        "SANDBOX_UID",
        "SANDBOX_GID",
        "SANDBOX_TMP_ROOT",
    ):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setattr(
        sandbox_preflight, "read_lsm_evidence", lambda landlock_abi=None: dict(LSM_EVIDENCE)
    )
    monkeypatch.setattr(sandbox_preflight, "landlock_abi_version", lambda: 10)
    monkeypatch.setattr(sandbox_preflight, "_read_text", lambda path: "")
    monkeypatch.setattr(sandbox_preflight, "helper_path", lambda: HELPER)

    def _forbidden(*args, **kwargs):
        pytest.fail("unit tests must monkeypatch the sandbox probes")

    for name in ("probe_bwrap", "probe_landlock", "probe_privilege_drop"):
        monkeypatch.setattr(sandbox_preflight, name, _forbidden)

    yield
    sandbox.reset_for_tests()


def test_bwrap_argv_is_pinned():
    argv = sandbox.build_cmd(
        sandbox.Backend.BWRAP,
        ["python", "/x/main.py"],
        Path("/app/workspace/tools/t"),
        Path("/tmp/run"),
        1000,
        1000,
    )

    assert argv == [
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
        "python", "/x/main.py",
    ]


def test_auto_prefers_bwrap(monkeypatch):
    landlock_calls = []
    monkeypatch.setattr(
        sandbox_preflight, "probe_bwrap", lambda *a, **k: _ok("bwrap")
    )
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_landlock",
        lambda *a, **k: landlock_calls.append(1) or _ok("landlock"),
    )
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_privilege_drop",
        lambda *a, **k: pytest.fail("privilege must not be probed when bwrap works"),
    )

    assert sandbox.select_backend() is sandbox.Backend.BWRAP
    assert landlock_calls == []


def test_auto_falls_back_to_landlock(monkeypatch):
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_bwrap",
        lambda *a, **k: _fail("bwrap", "apparmor_mount_denied"),
    )
    monkeypatch.setattr(
        sandbox_preflight, "probe_landlock", lambda *a, **k: _ok("landlock")
    )
    monkeypatch.setattr(
        sandbox_preflight, "probe_privilege_drop", lambda *a, **k: _ok("privilege")
    )

    assert sandbox.select_backend() is sandbox.Backend.LANDLOCK


def test_auto_reports_actionable_fallback_failure_when_both_fail(monkeypatch):
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_bwrap",
        lambda *a, **k: _fail("bwrap", "apparmor_mount_denied"),
    )
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_landlock",
        lambda *a, **k: _fail("landlock", "helper_failed"),
    )
    monkeypatch.setattr(
        sandbox_preflight, "probe_privilege_drop", lambda *a, **k: _ok("privilege")
    )

    with pytest.raises(sandbox.SandboxUnavailable) as excinfo:
        sandbox.select_backend()

    # The fallback's failure is the actionable one (a broken image/helper),
    # not the bwrap AppArmor denial the fallback was meant to route around.
    assert excinfo.value.code == "helper_failed"
    assert excinfo.value.remediation
    assert (
        excinfo.value.remediation
        == sandbox_preflight.REMEDIATIONS["helper_failed"]
    )


def test_forced_bwrap_failure_never_falls_back(monkeypatch):
    monkeypatch.setenv("SANDBOX_BACKEND", "bwrap")
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_bwrap",
        lambda *a, **k: _fail("bwrap", "apparmor_mount_denied"),
    )
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_landlock",
        lambda *a, **k: pytest.fail("forced bwrap must never probe landlock"),
    )
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_privilege_drop",
        lambda *a, **k: pytest.fail("forced bwrap must never probe privilege drop"),
    )

    with pytest.raises(sandbox.SandboxUnavailable) as excinfo:
        sandbox.select_backend()

    assert excinfo.value.code == "apparmor_mount_denied"


def test_forced_backend_overrides_auto(monkeypatch):
    monkeypatch.setattr(
        sandbox_preflight, "probe_bwrap", lambda *a, **k: _ok("bwrap")
    )
    assert sandbox.select_backend() is sandbox.Backend.BWRAP

    monkeypatch.setattr(
        sandbox_preflight, "probe_landlock", lambda *a, **k: _ok("landlock")
    )
    monkeypatch.setattr(
        sandbox_preflight, "probe_privilege_drop", lambda *a, **k: _ok("privilege")
    )
    assert sandbox.select_backend("landlock") is sandbox.Backend.LANDLOCK

    # An explicit force wins over a conflicting SANDBOX_BACKEND value.
    sandbox.reset_for_tests()
    monkeypatch.setenv("SANDBOX_BACKEND", "bwrap")
    assert sandbox.select_backend("landlock") is sandbox.Backend.LANDLOCK


def test_landlock_requires_privilege_drop(monkeypatch):
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_bwrap",
        lambda *a, **k: _fail("bwrap", "apparmor_mount_denied"),
    )
    monkeypatch.setattr(
        sandbox_preflight, "probe_landlock", lambda *a, **k: _ok("landlock")
    )
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_privilege_drop",
        lambda *a, **k: _fail("privilege", "landlock_setuid_denied"),
    )

    with pytest.raises(sandbox.SandboxUnavailable) as excinfo:
        sandbox.select_backend()

    assert excinfo.value.code == "landlock_setuid_denied"
    assert excinfo.value.remediation


def test_landlock_rejected_when_ptrace_scope_zero(monkeypatch):
    scope_path = "/proc/sys/kernel/yama/ptrace_scope"

    def _read_text(path):
        return "0\n" if path == scope_path else ""

    monkeypatch.setattr(sandbox_preflight, "_read_text", _read_text)
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_bwrap",
        lambda *a, **k: _fail("bwrap", "apparmor_mount_denied"),
    )
    monkeypatch.setattr(
        sandbox_preflight, "probe_landlock", lambda *a, **k: _ok("landlock")
    )
    monkeypatch.setattr(
        sandbox_preflight, "probe_privilege_drop", lambda *a, **k: _ok("privilege")
    )

    with pytest.raises(sandbox.SandboxUnavailable) as excinfo:
        sandbox.select_backend()

    assert excinfo.value.code == "ptrace_scope_unrestricted"


def test_invalid_backend_value_behaves_as_auto(monkeypatch):
    monkeypatch.setenv("SANDBOX_BACKEND", "bogus")
    monkeypatch.setattr(
        sandbox_preflight, "probe_bwrap", lambda *a, **k: _ok("bwrap")
    )

    assert sandbox.select_backend() is sandbox.Backend.BWRAP


def test_selection_is_memoized(monkeypatch):
    calls = []

    def _probe(*args, **kwargs):
        calls.append(1)
        return _ok("bwrap")

    monkeypatch.setattr(sandbox_preflight, "probe_bwrap", _probe)

    assert sandbox.select_backend() is sandbox.Backend.BWRAP
    assert sandbox.select_backend() is sandbox.Backend.BWRAP
    assert len(calls) == 1


def test_landlock_argv_shape():
    argv = sandbox.build_cmd(
        sandbox.Backend.LANDLOCK,
        ["bash", "x"],
        Path("/app/workspace/tools/t"),
        Path("/tmp/trellis-x"),
        1234,
        5678,
    )

    assert argv == [
        HELPER,
        "--ro", "/",
        "--rw", "/app/workspace",
        "--tmpdir", "/tmp/trellis-x",
        "--uid", "1234",
        "--gid", "5678",
        "--",
        "bash", "x",
    ]
    assert "--no-seccomp" not in argv


def test_landlock_argv_no_seccomp_flag(monkeypatch):
    monkeypatch.setenv("SANDBOX_SECCOMP", "off")

    argv = sandbox.build_cmd(
        sandbox.Backend.LANDLOCK,
        ["bash", "x"],
        Path("/app/workspace/tools/t"),
        Path("/tmp/trellis-x"),
        1234,
        5678,
    )

    assert argv.count("--no-seccomp") == 1
    assert argv[argv.index("--") - 1] == "--no-seccomp"
    assert argv[-2:] == ["bash", "x"]


POLICY_ARGS = {
    sandbox.Backend.BWRAP: "--unshare-net",
    sandbox.Backend.LANDLOCK: "--deny-net",
}


@pytest.mark.parametrize(
    "backend,network,expected",
    [
        (sandbox.Backend.BWRAP, None, False),
        (sandbox.Backend.BWRAP, "allow", False),
        (sandbox.Backend.BWRAP, "none", True),
        (sandbox.Backend.LANDLOCK, None, False),
        (sandbox.Backend.LANDLOCK, "allow", False),
        (sandbox.Backend.LANDLOCK, "none", True),
    ],
)
def test_network_policy_reaches_the_argv(backend, network, expected):
    argv = sandbox.build_cmd(
        backend,
        ["bash", "x"],
        Path("/app/workspace/tools/t"),
        Path("/tmp/trellis-x"),
        1234,
        5678,
        network=network,
    )
    flag = POLICY_ARGS[backend]

    assert (flag in argv) is expected
    assert argv[-2:] == ["bash", "x"]


def test_deny_net_flag_precedes_the_separator():
    argv = sandbox.build_cmd(
        sandbox.Backend.LANDLOCK,
        ["bash", "x"],
        Path("/app/workspace/tools/t"),
        Path("/tmp/trellis-x"),
        1234,
        5678,
        network="none",
    )

    assert argv[argv.index("--") - 1] == "--deny-net"


def test_net_default_env_none_makes_allow_the_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_NET_DEFAULT", "none")

    assert sandbox.net_policy_default() == "none"
    for backend in (sandbox.Backend.BWRAP, sandbox.Backend.LANDLOCK):
        default = sandbox.build_cmd(
            backend, ["true"], tmp_path, tmp_path, 1000, 1000
        )
        override = sandbox.build_cmd(
            backend, ["true"], tmp_path, tmp_path, 1000, 1000, network="allow"
        )
        assert POLICY_ARGS[backend] in default
        assert POLICY_ARGS[backend] not in override


@pytest.mark.parametrize("raw", ["bogus", "off", "deny"])
def test_invalid_net_default_warns_once_and_falls_back_to_allow(
    monkeypatch, caplog, raw
):
    monkeypatch.setenv("SANDBOX_NET_DEFAULT", raw)

    assert sandbox.net_policy_default() == "allow"
    assert sandbox.net_policy_default() == "allow"

    warnings = [
        record
        for record in caplog.records
        if record.levelno == logging.WARNING and "network policy" in record.getMessage()
    ]
    assert len(warnings) == 1


def test_plan_carries_the_network_policy(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_TMP_ROOT", str(tmp_path / "sroot"))

    denied = sandbox.prepare_execution(
        ["true"],
        tmp_path / "tools" / "t",
        backend=sandbox.Backend.BWRAP,
        env={},
        network="none",
    )
    allowed = sandbox.prepare_execution(
        ["true"],
        tmp_path / "tools" / "t",
        backend=sandbox.Backend.BWRAP,
        env={},
    )

    assert denied.network == "none"
    assert allowed.network == "allow"
    denied.cleanup()
    allowed.cleanup()


@pytest.mark.parametrize("backend", [sandbox.Backend.BWRAP, sandbox.Backend.LANDLOCK])
def test_prepare_execution_env_and_tmpdir(monkeypatch, tmp_path, backend):
    sroot = tmp_path / "sroot"
    monkeypatch.setenv("SANDBOX_TMP_ROOT", str(sroot))
    caller_env = {"KEEP": "1"}

    plan = sandbox.prepare_execution(
        ["python", "x"],
        tmp_path / "tools" / "mytool",
        backend=backend,
        env=caller_env,
    )

    assert plan.tmpdir.parent == sroot
    assert plan.tmpdir.name.startswith("trellis-mytool-")
    assert plan.tmpdir.is_dir()
    assert stat.S_IMODE(plan.tmpdir.stat().st_mode) == 0o700
    assert plan.env["KEEP"] == "1"

    if backend is sandbox.Backend.BWRAP:
        assert plan.env["TMPDIR"] == "/tmp"
        # /tmp is the private tmpfs: a writable HOME keeps tool caches working
        # and hides the hub's own home config.
        assert plan.env["HOME"] == "/tmp"
    else:
        assert plan.env["TMPDIR"] == plan.env["HOME"] == str(plan.tmpdir)

    # The caller's env dict is copied, never mutated.
    assert caller_env == {"KEEP": "1"}
    plan.cleanup()


def test_cleanup_removes_tmpdir_and_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_TMP_ROOT", str(tmp_path / "sroot"))
    plan = sandbox.prepare_execution(
        ["python", "x"],
        tmp_path / "tools" / "t",
        backend=sandbox.Backend.LANDLOCK,
        env={},
    )
    tmpdir = plan.tmpdir
    assert tmpdir.exists()

    plan.cleanup()
    assert not tmpdir.exists()
    plan.cleanup()
    assert not tmpdir.exists()

    # A hand-built plan pointing at /tmp must never remove it.
    shared = sandbox.SandboxPlan(
        argv=[], env={}, tmpdir=Path("/tmp"), backend=sandbox.Backend.BWRAP
    )
    shared.cleanup()
    assert Path("/tmp").is_dir()


def test_prepare_execution_uses_injected_uid_gid(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_UID", "4242")
    monkeypatch.setenv("SANDBOX_GID", "4343")
    monkeypatch.setenv("SANDBOX_TMP_ROOT", str(tmp_path / "sroot"))

    plan = sandbox.prepare_execution(
        ["true"],
        tmp_path / "tools" / "t",
        backend=sandbox.Backend.LANDLOCK,
        env={},
    )

    assert plan.argv[plan.argv.index("--uid") + 1] == "4242"
    assert plan.argv[plan.argv.index("--gid") + 1] == "4343"
    plan.cleanup()


def test_failed_selection_reuses_cached_preflight(monkeypatch):
    calls = []

    def _bwrap(*a, **k):
        calls.append(1)
        return _fail("bwrap", "apparmor_mount_denied")

    monkeypatch.setattr(sandbox_preflight, "probe_bwrap", _bwrap)
    monkeypatch.setattr(
        sandbox_preflight,
        "probe_landlock",
        lambda *a, **k: _fail("landlock", "helper_failed"),
    )
    monkeypatch.setattr(
        sandbox_preflight, "probe_privilege_drop", lambda *a, **k: _ok("privilege")
    )
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox.select_backend()
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox.select_backend()

    # Re-probing requires a restart / reset; a failed startup verdict is cached.
    assert calls == [1]
    sandbox.reset_for_tests()
    monkeypatch.setattr(
        sandbox_preflight, "probe_bwrap", lambda *a, **k: _ok("bwrap")
    )
    assert sandbox.select_backend() is sandbox.Backend.BWRAP


def test_sandbox_unavailable_from_tmpdir_failure(monkeypatch, tmp_path):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    monkeypatch.setenv("SANDBOX_TMP_ROOT", str(blocker))

    with pytest.raises(sandbox.SandboxUnavailable) as excinfo:
        sandbox.prepare_execution(
            ["true"],
            tmp_path / "tools" / "t",
            backend=sandbox.Backend.LANDLOCK,
            env={},
        )

    assert excinfo.value.code == "helper_failed"
    assert excinfo.value.remediation


def test_classify_failure_maps_bwrap_apparmor(monkeypatch):
    monkeypatch.setattr(
        sandbox_preflight,
        "read_lsm_evidence",
        lambda **kwargs: {
            "apparmor": {"enabled": True, "profile": "docker-default (enforce)"},
            "selinux": False,
        },
    )

    result = sandbox.classify_failure(
        "bwrap: Can't mount proc on /newroot/proc: Permission denied",
        sandbox.Backend.BWRAP,
        1,
    )

    assert result is not None
    assert result.code == "apparmor_mount_denied"


def test_classify_failure_ignores_tool_stderr(monkeypatch):
    assert (
        sandbox.classify_failure(
            "connection refused: upstream timeout", sandbox.Backend.LANDLOCK, 1
        )
        is None
    )
    assert (
        sandbox.classify_failure("bwrap: odd failure", sandbox.Backend.BWRAP, 1)
        is None
    )


@pytest.mark.parametrize(
    "returncode,stderr,expected",
    [
        (65, "trellis-sandbox: something failed", "landlock_unavailable"),
        (66, "trellis-sandbox: something failed", "helper_failed"),
        (67, "trellis-sandbox: something failed", "helper_failed"),
        (68, "trellis-sandbox: something failed", "landlock_setuid_denied"),
        (69, "trellis-sandbox: setrlimit(RLIMIT_AS): Invalid argument", "rlimit_denied"),
    ],
)
def test_classify_failure_maps_helper_exit_codes(returncode, stderr, expected):
    result = sandbox.classify_failure(stderr, sandbox.Backend.LANDLOCK, returncode)

    assert result is not None
    assert result.code == expected
    assert result.remediation


def test_classify_failure_maps_net_policy_refusal():
    result = sandbox.classify_failure(
        "trellis-sandbox: landlock net access control requires ABI 4 (have 3)",
        sandbox.Backend.LANDLOCK,
        65,
    )

    assert result is not None
    assert result.code == "landlock_net_unsupported"
    assert result.remediation


def test_classify_failure_exit_69_without_setrlimit_is_not_sandbox():
    """A tool that exits 69 itself must keep normal error handling."""
    assert (
        sandbox.classify_failure(
            "trellis-sandbox: warning: supplementary groups retained",
            sandbox.Backend.LANDLOCK,
            69,
        )
        is None
    )


def test_log_failure_once(caplog):
    result = sandbox_preflight.ProbeResult(
        backend="landlock",
        ok=False,
        code="helper_failed",
        detail="x",
        remediation="fix it",
    )

    with caplog.at_level("ERROR", logger="core.sandbox"):
        sandbox.log_failure_once(result)
        sandbox.log_failure_once(result)

    messages = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(messages) == 1
    assert "landlock" in messages[0].getMessage()


def _stub_preflight(monkeypatch, calls):
    """Make selection depend on a counted, cache-less warmup."""
    monkeypatch.setattr(sandbox_preflight, "cached_status", lambda: {})

    def _warmup(requested=None):
        calls.append(requested)
        return {"ok": True, "backend": "bwrap", "requested": requested or "auto"}

    monkeypatch.setattr(sandbox_preflight, "warmup", _warmup)


def test_reset_selection_forces_reselection(monkeypatch):
    calls = []
    _stub_preflight(monkeypatch, calls)

    assert sandbox.select_backend() is sandbox.Backend.BWRAP
    assert sandbox.select_backend() is sandbox.Backend.BWRAP
    assert len(calls) == 1

    sandbox.reset_selection()

    assert sandbox.select_backend() is sandbox.Backend.BWRAP
    assert len(calls) == 2


def test_reset_selection_keeps_failure_log_dedupe(caplog):
    result = sandbox_preflight.ProbeResult(
        backend="landlock",
        ok=False,
        code="helper_failed",
        detail="x",
        remediation="fix it",
    )

    with caplog.at_level("ERROR", logger="core.sandbox"):
        sandbox.log_failure_once(result)
        sandbox.reset_selection()
        sandbox.log_failure_once(result)

    assert len([r for r in caplog.records if r.levelname == "ERROR"]) == 1


def test_invalidate_after_failure_clears_the_selection(monkeypatch):
    calls = []
    _stub_preflight(monkeypatch, calls)
    reasons = []
    monkeypatch.setattr(
        sandbox_preflight,
        "invalidate",
        lambda reason: reasons.append(reason) or True,
    )

    assert sandbox.select_backend() is sandbox.Backend.BWRAP
    assert sandbox.invalidate_after_failure("apparmor_mount_denied") is True
    assert sandbox.select_backend() is sandbox.Backend.BWRAP

    assert len(calls) == 2
    assert reasons == ["tool failure: apparmor_mount_denied"]


def test_invalidate_after_failure_keeps_the_selection_within_cooldown(monkeypatch):
    calls = []
    _stub_preflight(monkeypatch, calls)
    monkeypatch.setattr(sandbox_preflight, "invalidate", lambda reason: False)

    assert sandbox.select_backend() is sandbox.Backend.BWRAP
    assert sandbox.invalidate_after_failure("helper_failed") is False
    assert sandbox.select_backend() is sandbox.Backend.BWRAP

    # Nothing new to select from: the memoized backend is still valid.
    assert len(calls) == 1
