# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Preflight probes for the tool-hub sandbox backends.

``warmup()`` probes the configured backend once at startup and caches a payload
shaped for ``/healthz``. Phase 2 probes both backends: bubblewrap, and the
Landlock helper (filesystem confinement plus the tool identity, probed separately
so a stripped capability is diagnosed as ``landlock_setuid_denied``). When the
Landlock backend is probed, a ``--deny-net`` run also reports whether this kernel
can enforce a tool's ``network: none`` policy (Landlock ABI 4+).

A classified tool failure calls ``invalidate()``: the cached verdict goes stale
so the next health check or backend selection re-probes a host whose LSM policy
may have changed under the running hub. Invalidation is cooldown-bounded, the
stale re-probe is single-flight (one probe set at a time), and a probe that
straddles an invalidation is discarded rather than published.
"""

import copy
import ctypes
import logging
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

CODES: frozenset[str] = frozenset({
    "bwrap_missing",
    "apparmor_mount_denied",
    "seccomp_pivot_root",
    "userns_restriction",
    "selinux_denied",
    "landlock_unavailable",
    "landlock_setuid_denied",
    "landlock_net_unsupported",
    "netns_denied",
    "rlimit_denied",
    "ptrace_scope_unrestricted",
    "mount_denied_unknown_lsm",
    "helper_failed",
    "unknown",
})

_warned_invalid_rw_path = False


def writable_root() -> Path:
    """The one path a sandboxed tool may write, overridable on a standalone install.

    Rejects ``/`` (which would remove write confinement) and non-absolute values, so a
    typo falls back to the framework default instead of silently widening the sandbox.
    """
    raw = (os.getenv("SANDBOX_RW_PATH") or "/app/workspace").strip()
    candidate = Path(raw)
    if not candidate.is_absolute() or candidate == Path("/"):
        global _warned_invalid_rw_path
        if raw != "/app/workspace" and not _warned_invalid_rw_path:
            # Called on every execution; one warning is enough to fix a typo.
            _warned_invalid_rw_path = True
            logger.warning(
                "Ignoring SANDBOX_RW_PATH=%r (must be an absolute path other than '/'); "
                "using /app/workspace",
                raw,
            )
        return Path("/app/workspace")
    return candidate


def bwrap_base_args() -> tuple[str, ...]:
    """The pinned bwrap argv with the configured writable root substituted in."""
    root = str(writable_root())
    if root == "/app/workspace":
        return BWRAP_BASE_ARGS
    return tuple(arg.replace("/app/workspace", root) for arg in BWRAP_BASE_ARGS)


BWRAP_BASE_ARGS: tuple[str, ...] = (
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
    # bwrap does not drop capabilities by default; Phase 2 pins the empty set.
    "--cap-drop", "ALL",
)

REMEDIATIONS: dict[str, str] = {
    "bwrap_missing": (
        "Install bubblewrap (e.g. `apt-get install bubblewrap`) in the tool hub "
        "image and rebuild the hub container."
    ),
    "apparmor_mount_denied": (
        "AppArmor is denying mounts. Run the container with "
        "`--security-opt apparmor=unconfined`, or install the narrower "
        "deploy/apparmor/trellis-hub profile and select it instead."
    ),
    "seccomp_pivot_root": (
        "The container seccomp profile blocks pivot_root. Permit pivot_root (or "
        "CAP_SYS_ADMIN) for the hub container's security profile."
    ),
    "userns_restriction": (
        "User namespaces are restricted on the host. Enable "
        "`kernel.unprivileged_userns_clone=1` (and a non-zero "
        "`user.max_user_namespaces`) before starting the hub."
    ),
    "selinux_denied": (
        "SELinux is denying container mounts. Inspect `ausearch -m avc` and give "
        "the hub the container_t context (or permissive mode) for sandbox mounts."
    ),
    "landlock_unavailable": (
        "Landlock is unavailable on this kernel (ABI 0) or blocked by the "
        "container's LSM/seccomp policy. Use a kernel 5.13+ with Landlock "
        "enabled, or fix bwrap instead (`SANDBOX_BACKEND=bwrap`)."
    ),
    "landlock_setuid_denied": (
        "The hub cannot chown the run dir or switch to the tool's uid. A "
        "non-root hub cannot switch identities at all: SANDBOX_UID/SANDBOX_GID "
        "must match the hub's own uid/gid (or run the hub as root, with "
        "CAP_SETUID, CAP_SETGID and CAP_CHOWN from the compose cap_add). "
        "Alternatively switch to `SANDBOX_BACKEND=bwrap`."
    ),
    "rlimit_denied": (
        "The sandbox helper's setrlimit call was refused after clamping to the "
        "inherited hard limit. Check the configured SANDBOX_RLIMIT_* values, "
        "then the container's ulimits (compose `ulimits:`/`--ulimit`, e.g. "
        "`as`, `cpu`, `fsize`), or lower the matching SANDBOX_RLIMIT_* setting."
    ),
    "landlock_net_unsupported": (
        "The kernel's Landlock ABI is below 4, so the Landlock backend cannot "
        "enforce a `network: none` tool policy and those tools fail closed. Use "
        "`SANDBOX_BACKEND=bwrap` (which supports `--unshare-net`) or upgrade to "
        "a kernel with Landlock ABI 4+ (Linux 6.7+). Policies left at the "
        "default `allow` are unaffected."
    ),
    "netns_denied": (
        "bwrap can build its namespaces but not a network namespace, so tools "
        "with `network: none` (`--unshare-net`) fail while `allow` tools keep "
        "working. Permit network namespace creation for the hub (check "
        "`unshare -n true` inside the container), or switch to "
        "`SANDBOX_BACKEND=landlock`, which denies TCP with Landlock instead of "
        "namespaces."
    ),
    "ptrace_scope_unrestricted": (
        "ptrace is unrestricted. Set `kernel.yama.ptrace_scope=1` (or higher) on "
        "the host to limit process tracing."
    ),
    "mount_denied_unknown_lsm": (
        "Mounts are denied by an unidentified LSM. Check `dmesg`/`auditd` and "
        "relax the container's mandatory access control policy."
    ),
    "helper_failed": (
        "The sandbox helper failed. Verify it is installed and executable, then "
        "check `docker compose logs hub` for the helper's stderr."
    ),
    "unknown": (
        "Sandbox probe failed for an unrecognized reason. Reproduce manually with "
        "`bwrap --ro-bind / / --unshare-user /bin/true` and inspect the output."
    ),
}


@dataclass(frozen=True)
class ProbeResult:
    backend: str
    ok: bool
    code: str | None = None
    detail: str = ""
    remediation: str = ""
    # Extra payload evidence a probe collected (e.g. the bwrap netns probe),
    # merged into the cached verdict's ``evidence`` map.
    evidence: dict | None = None


@dataclass(frozen=True)
class NetProbeResult:
    """Whether this kernel can enforce the ``network: none`` policy."""

    supported: bool
    detail: str = ""
    abi: int = 0


_VALID_BACKENDS = frozenset({"auto", "bwrap", "landlock"})
_SECCOMP_OFF = frozenset({"off", "0", "false", "no"})
_STATUS_CACHE: dict = {}
# Set by invalidate(): the cached verdict is stale, so the next reader re-probes.
_STATUS_STALE = False
_LAST_INVALIDATION: float | None = None
# A persistently failing sandbox would otherwise fork a probe per failed tool
# call; at most one invalidation (and therefore one re-probe) per window.
_REPROBE_COOLDOWN_S = 60.0
# Single-flight for the stale re-probe: a cold cache must not let every
# concurrent /healthz request fork its own probe set. A caller that loses the
# race waits this long for the in-flight verdict, then reports not-ready.
# Kept well under the hub healthcheck timeout (25 s) while the probing caller's
# own worst case (bwrap + landlock + privilege + net, 5 s each) is ~20 s.
_REPROBE_WAIT_S = 10.0
_STALE_REPROBE_LOCK = threading.Lock()
# Incremented by invalidate(); warmup() publishes only if it is unchanged, so a
# probe that straddled an invalidation cannot overwrite the newer verdict.
_GENERATION = 0
_WARNED_BACKEND = False
_WARNED_ROOT_UID = False
_WARNED_IDENTITY = False
_WARNED_SECCOMP_OFF = False
_WARNED_NETNS = False


def _monotonic() -> float:
    """Monotonic clock, isolated so tests can drive the invalidation cooldown."""
    return time.monotonic()


def _read_text(path: str) -> str:
    """Return a file's contents, or "" when it cannot be read."""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return ""


def _as_text(value) -> str:
    """Decode subprocess output defensively (monkeypatched runs may return bytes)."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def _truncate(text: str, limit: int = 500) -> str:
    return text if len(text) <= limit else text[:limit]


def helper_path() -> str:
    return os.getenv("SANDBOX_HELPER", "/usr/local/bin/trellis-sandbox")


def seccomp_disabled() -> bool:
    """True when ``SANDBOX_SECCOMP`` disables the Landlock helper's deny-list."""
    return (os.getenv("SANDBOX_SECCOMP") or "on").strip().lower() in _SECCOMP_OFF


def read_lsm_evidence(landlock_abi: int | None = None) -> dict:
    """Best-effort snapshot of the host's LSM configuration."""
    apparmor_enabled = _read_text(
        "/sys/module/apparmor/parameters/enabled"
    ).strip().lower() in {"y", "1", "yes", "true"}
    return {
        "apparmor": {
            "enabled": apparmor_enabled,
            "profile": _read_text("/proc/self/attr/current").strip(),
        },
        "selinux": os.path.exists("/sys/fs/selinux/enforce"),
        "landlock_abi": (
            landlock_abi if landlock_abi is not None else landlock_abi_version()
        ),
        "helper": {"present": os.path.isfile(helper_path())},
    }


def landlock_abi_version() -> int:
    """Return the kernel's Landlock ABI version, or 0 when unsupported."""
    try:
        libc = ctypes.CDLL(None)
        # 444 = landlock_create_ruleset; flags=1 selects the ABI version query.
        version = libc.syscall(444, 0, 0, 1)
    except Exception:
        return 0
    return version if isinstance(version, int) and version > 0 else 0


def classify_bwrap_stderr(
    stderr: str, evidence: dict | None = None, *, netns: bool = False
) -> str | None:
    """Map bwrap stderr to a stable sandbox failure code.

    ``netns`` marks a probe that already passed the base run and only added
    ``--unshare-net``: the same "Creating new namespace failed" text then means
    the network namespace (not the user namespace) was refused.
    """
    text = (stderr or "").lower()
    evidence = evidence or {}
    apparmor = evidence.get("apparmor") or {}
    profile = str(apparmor.get("profile") or "").lower()

    if netns and (
        "netns" in text
        or "network namespace" in text
        or "creating new namespace failed" in text
    ):
        return "netns_denied"

    if any(marker in text for marker in (
        "setting up uid map",
        "clone_newuser",
        "userns_create",
        "creating new namespace failed",
    )):
        return "userns_restriction"

    if "pivot_root" in text and "operation not permitted" in text:
        return "seccomp_pivot_root"

    mount_mentioned = (
        "can't bind mount" in text
        or "can't mount" in text
        or "cannot mount" in text
    )
    mount_denied = (
        ("permission denied" in text or "operation not permitted" in text)
        and (mount_mentioned or "mount" in text)
    )
    if mount_denied:
        if evidence.get("selinux") is True:
            return "selinux_denied"
        # A host-global AppArmor module is not evidence of confinement: the
        # container profile itself must be enforcing for AppArmor to be blamed.
        confined = bool(profile) and profile != "unconfined"
        if confined and any(
            name in profile for name in ("docker-default", "trellis-hub")
        ):
            return "apparmor_mount_denied"
        return "mount_denied_unknown_lsm"

    if "bwrap: not found" in text:
        return "bwrap_missing"

    return None


def probe_yama() -> dict:
    """Report Yama's ptrace_scope and warn when tracing is unrestricted."""
    raw = _read_text("/proc/sys/kernel/yama/ptrace_scope").strip()
    try:
        scope: int | None = int(raw)
    except ValueError:
        scope = None
    # Missing/unreadable Yama is as unsafe as scope 0: same uid + no Yama means
    # a tool can read a sibling's /proc/<pid>/environ.
    return {
        "ptrace_scope": scope,
        "warning_code": (
            "ptrace_scope_unrestricted" if scope is None or scope == 0 else None
        ),
    }


def _run_bwrap(extra_args: list[str], timeout: float):
    """Run the pinned bwrap argv plus ``extra_args`` around ``/bin/true``."""
    return subprocess.run(
        list(BWRAP_BASE_ARGS) + list(extra_args) + ["/bin/true"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _probe_bwrap_netns(timeout: float) -> dict:
    """Can this host create the netns a ``network: none`` bwrap tool needs?

    Advisory: ``allow`` tools never pass ``--unshare-net``, so a denied netns
    must not fail the overall bwrap verdict -- it only breaks the tools whose
    policy asks for no network.
    """
    try:
        proc = _run_bwrap(["--unshare-net"], timeout)
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "code": "netns_denied",
            "detail": _truncate(f"--unshare-net probe timed out after {timeout}s"),
        }
    except Exception as exc:
        return {
            "ok": False,
            "code": "netns_denied",
            "detail": _truncate(f"--unshare-net probe failed to start: {exc}"),
        }

    if proc.returncode == 0:
        return {"ok": True, "code": None, "detail": ""}

    detail = (
        _as_text(proc.stderr)
        or _as_text(proc.stdout)
        or f"bwrap --unshare-net exited with code {proc.returncode}"
    ).strip()
    code = (
        classify_bwrap_stderr(detail, read_lsm_evidence(), netns=True)
        or "netns_denied"
    )
    return {"ok": False, "code": code, "detail": _truncate(detail)}


def probe_bwrap(timeout: float = 5.0) -> ProbeResult:
    """Run a minimal bwrap invocation to verify the backend works."""
    if shutil.which("bwrap") is None:
        return ProbeResult(
            backend="bwrap",
            ok=False,
            code="bwrap_missing",
            detail="bwrap executable not found on PATH",
            remediation=REMEDIATIONS["bwrap_missing"],
        )

    try:
        proc = _run_bwrap([], timeout)
    except subprocess.TimeoutExpired as exc:
        return ProbeResult(
            backend="bwrap",
            ok=False,
            code="unknown",
            detail=_truncate(f"bwrap probe timed out after {timeout}s: {exc}"),
            remediation=REMEDIATIONS["unknown"],
        )
    except Exception as exc:
        return ProbeResult(
            backend="bwrap",
            ok=False,
            code="unknown",
            detail=_truncate(f"bwrap probe failed to start: {exc}"),
            remediation=REMEDIATIONS["unknown"],
        )

    stderr = _as_text(proc.stderr)
    stdout = _as_text(proc.stdout)
    if proc.returncode == 0:
        # The base run proves namespaces work; a host that still refuses a
        # network namespace would only fail `network: none` tools later, with a
        # misleading diagnosis, so probe that property here too.
        return ProbeResult(
            backend="bwrap",
            ok=True,
            evidence={"bwrap_netns": _probe_bwrap_netns(timeout)},
        )

    code = classify_bwrap_stderr(stderr, read_lsm_evidence()) or "unknown"
    detail = (stderr or stdout or f"bwrap exited with code {proc.returncode}").strip()
    return ProbeResult(
        backend="bwrap",
        ok=False,
        code=code,
        detail=_truncate(detail),
        remediation=REMEDIATIONS[code],
    )


def _helper_probe_error(backend: str, helper: str) -> ProbeResult | None:
    """Return a ``helper_failed`` result when the sandbox helper cannot run."""
    if os.path.isfile(helper) and os.access(helper, os.X_OK):
        return None
    return ProbeResult(
        backend=backend,
        ok=False,
        code="helper_failed",
        detail=f"Sandbox helper {helper!r} is missing or not executable",
        remediation=REMEDIATIONS["helper_failed"],
    )


def _probe_detail(proc) -> str:
    return (
        _as_text(proc.stderr)
        or _as_text(proc.stdout)
        or f"sandbox helper exited with code {proc.returncode}"
    ).strip()


def _helper_refused(text: str) -> bool:
    """True when the helper itself diagnosed a failure rather than the tool.

    The helper prefixes its fatal messages with ``trellis-sandbox:`` but also
    emits benign ``trellis-sandbox: warning: ...`` lines on successful runs, so
    only non-warning lines count as a refusal.
    """
    return any(
        line.startswith("trellis-sandbox:")
        and not line.startswith("trellis-sandbox: warning:")
        for line in (text or "").lower().splitlines()
    )


def _classify_helper_result(backend: str, proc) -> ProbeResult:
    """Map a helper exit status/stderr to a stable sandbox failure code."""
    if proc.returncode == 0:
        return ProbeResult(backend=backend, ok=True)

    detail = _probe_detail(proc)
    text = (detail or "").lower()

    # The net-policy refusal is exit 65 too, so its marker must win over the
    # generic Landlock-unavailable branch. It is also checked before the
    # setuid/chown markers so a warning line cannot swallow it.
    if "net access control requires abi" in text:
        return ProbeResult(
            backend=backend,
            ok=False,
            code="landlock_net_unsupported",
            detail=_truncate(detail),
            remediation=REMEDIATIONS["landlock_net_unsupported"],
        )

    if proc.returncode == 65:
        return ProbeResult(
            backend=backend,
            ok=False,
            code="landlock_unavailable",
            detail=_truncate(detail),
            remediation=REMEDIATIONS["landlock_unavailable"],
        )

    if proc.returncode == 68:
        return ProbeResult(
            backend=backend,
            ok=False,
            code="landlock_setuid_denied",
            detail=_truncate(detail),
            remediation=REMEDIATIONS["landlock_setuid_denied"],
        )

    if proc.returncode == 69:
        return ProbeResult(
            backend=backend,
            ok=False,
            code="rlimit_denied",
            detail=_truncate(detail),
            remediation=REMEDIATIONS["rlimit_denied"],
        )

    # A missing bind source is a deployment problem, not a Landlock refusal.
    # Phase 1 made the same call for bwrap; do not mislabel it ``bwrap_missing``.
    writable = str(writable_root())
    if (writable in text or "/app/workspace" in text) and any(
        marker in text
        for marker in ("no such file", "not found", "does not exist", "missing")
    ):
        return ProbeResult(
            backend=backend,
            ok=False,
            code="unknown",
            detail=_truncate(detail),
            remediation=REMEDIATIONS["unknown"],
        )

    # A failed rlimit is a host-hardening conflict, not an identity problem, so
    # it must be checked before the generic setuid/chown markers below.
    if "setrlimit" in text:
        return ProbeResult(
            backend=backend,
            ok=False,
            code="rlimit_denied",
            detail=_truncate(detail),
            remediation=REMEDIATIONS["rlimit_denied"],
        )

    # A failed chown/setuid means either the hub lacks CAP_SETUID/CAP_SETGID or
    # a non-root hub asked for an identity it cannot switch to.
    if any(
        marker in text
        for marker in ("setuid", "setgid", "setgroups", "chown", "epriv", "eperm")
    ):
        return ProbeResult(
            backend=backend,
            ok=False,
            code="landlock_setuid_denied",
            detail=_truncate(detail),
            remediation=REMEDIATIONS["landlock_setuid_denied"],
        )

    if proc.returncode == 67:
        return ProbeResult(
            backend=backend,
            ok=False,
            code="helper_failed",
            detail=_truncate(f"path grant failed: {detail}"),
            remediation=REMEDIATIONS["helper_failed"],
        )

    return ProbeResult(
        backend=backend,
        ok=False,
        code="unknown",
        detail=_truncate(detail),
        remediation=REMEDIATIONS["unknown"],
    )


def _helper_argv(
    helper: str,
    grants: list[str],
    tmpdir: str,
    extra_args: list[str] | None = None,
    command: list[str] | None = None,
) -> list[str]:
    """Assemble a helper invocation with the shared identity tail."""
    uid, gid = resolve_sandbox_identity()
    return [
        helper,
        *grants,
        "--tmpdir", tmpdir,
        "--uid", str(uid),
        "--gid", str(gid),
        # Probe the same argv the hub will run, including the escape hatch.
        *(["--no-seccomp"] if seccomp_disabled() else []),
        *(extra_args or []),
        "--",
        *(command or ["/bin/sh", "-c", "id -u"]),
    ]


def _run_helper(
    backend: str, helper: str, grants: list[str], timeout: float
) -> ProbeResult:
    """Run the helper with ``grants`` plus the shared identity tail."""
    uid, _ = resolve_sandbox_identity()
    try:
        tmpdir = tempfile.mkdtemp(prefix="trellis-probe-")
    except OSError as exc:
        return ProbeResult(
            backend=backend,
            ok=False,
            code="unknown",
            detail=_truncate(f"could not create probe tmpdir: {exc}"),
            remediation=REMEDIATIONS["unknown"],
        )

    # Assert the identity, not just exit 0: a helper that forgot to drop
    # must not make /healthz green.
    argv = _helper_argv(helper, grants, tmpdir)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/",
        )
    except subprocess.TimeoutExpired:
        return ProbeResult(
            backend=backend,
            ok=False,
            code="unknown",
            detail=_truncate(f"{backend} probe timed out after {timeout}s"),
            remediation=REMEDIATIONS["unknown"],
        )
    except Exception as exc:
        return ProbeResult(
            backend=backend,
            ok=False,
            code="unknown",
            detail=_truncate(f"{backend} probe failed to start: {exc}"),
            remediation=REMEDIATIONS["unknown"],
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    result = _classify_helper_result(backend, proc)
    if result.ok:
        reported_uid = _as_text(proc.stdout).strip()
        if reported_uid != str(uid):
            return ProbeResult(
                backend=backend,
                ok=False,
                code="landlock_setuid_denied",
                detail=_truncate(
                    f"helper reported uid {reported_uid or '?'} instead of {uid}"
                ),
                remediation=REMEDIATIONS["landlock_setuid_denied"],
            )
    return result


def probe_landlock(
    helper: str | None = None, timeout: float = 5.0
) -> ProbeResult:
    """Probe the Landlock backend end to end (filesystem grants + uid drop)."""
    helper = helper or helper_path()

    # Kernel support first: without it the helper cannot do anything useful,
    # and reporting a missing file would send the operator down a false path.
    if landlock_abi_version() == 0:
        return ProbeResult(
            backend="landlock",
            ok=False,
            code="landlock_unavailable",
            detail="Landlock is unavailable on this kernel (ABI version 0).",
            remediation=REMEDIATIONS["landlock_unavailable"],
        )

    missing = _helper_probe_error("landlock", helper)
    if missing is not None:
        return missing

    return _run_helper(
        "landlock", helper, ["--ro", "/", "--rw", str(writable_root())], timeout
    )


def probe_privilege_drop(
    helper: str | None = None, timeout: float = 5.0
) -> ProbeResult:
    """Probe only the tool identity (no ``--rw``), isolating ``SETUID``/``SETGID``."""
    helper = helper or helper_path()

    if landlock_abi_version() == 0:
        return ProbeResult(
            backend="privilege",
            ok=False,
            code="landlock_unavailable",
            detail="Landlock is unavailable on this kernel (ABI version 0).",
            remediation=REMEDIATIONS["landlock_unavailable"],
        )

    missing = _helper_probe_error("privilege", helper)
    if missing is not None:
        return missing

    return _run_helper("privilege", helper, ["--ro", "/"], timeout)


_NET_PROBE_CODE = (
    "import socket\n"
    "socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
)


def probe_landlock_net(
    helper: str | None = None, timeout: float = 5.0
) -> NetProbeResult:
    """Check whether the helper can deny UDP/raw as well as TCP under ``--deny-net``.

    Probes the property instead of accepting the flag: Landlock covers TCP only,
    so a ``--deny-net`` run must refuse a UDP socket with EACCES via the seccomp
    rule. Accepting the flag but creating the socket still means "deny" is not
    enforced (``SANDBOX_SECCOMP=off``, or a filter that was never installed).

    Advisory only: the default policy is ``allow``, so an unsupported kernel
    must not fail the preflight. Deliberately not routed through
    ``_classify_helper_result``: a failure here says nothing about whether the
    filesystem/identity sandbox works.
    """
    helper = helper or helper_path()
    abi = landlock_abi_version()
    if abi < 4:
        return NetProbeResult(
            supported=False,
            detail=(
                f"Landlock ABI {abi} has no network access control (needs 4+); "
                "tools with network: none fail closed under this backend."
            ),
            abi=abi,
        )

    missing = _helper_probe_error("landlock", helper)
    if missing is not None:
        return NetProbeResult(supported=False, detail=missing.detail, abi=abi)

    try:
        tmpdir = tempfile.mkdtemp(prefix="trellis-probe-net-")
    except OSError as exc:
        return NetProbeResult(
            supported=False,
            detail=_truncate(f"could not create probe tmpdir: {exc}"),
            abi=abi,
        )

    argv = _helper_argv(
        helper,
        ["--ro", "/"],
        tmpdir,
        extra_args=["--deny-net"],
        command=[sys.executable, "-c", _NET_PROBE_CODE],
    )
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/",
        )
    except subprocess.TimeoutExpired:
        return NetProbeResult(
            supported=False,
            detail=_truncate(f"net probe timed out after {timeout}s"),
            abi=abi,
        )
    except Exception as exc:
        return NetProbeResult(
            supported=False,
            detail=_truncate(f"net probe failed to start: {exc}"),
            abi=abi,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if proc.returncode == 0:
        if seccomp_disabled():
            cause = "seccomp disabled: --deny-net denies TCP only, UDP still permitted"
        else:
            cause = "--deny-net accepted but UDP still permitted"
        return NetProbeResult(supported=False, detail=cause, abi=abi)

    detail = _probe_detail(proc)
    if _helper_refused(detail):
        # The helper refused to start; that says nothing about the net policy.
        return NetProbeResult(supported=False, detail=_truncate(detail), abi=abi)
    return NetProbeResult(
        supported=True,
        detail=f"--deny-net refused the UDP socket (ABI {abi})",
        abi=abi,
    )


def _warn_if_identity_unreachable(uid: int, gid: int) -> None:
    """Warn once when a non-root hub cannot switch to the resolved identity."""
    global _WARNED_IDENTITY
    euid = os.geteuid()
    egid = os.getegid()
    if euid == 0 or (uid == euid and gid == egid) or _WARNED_IDENTITY:
        return
    mismatches = []
    if uid != euid:
        mismatches.append(f"SANDBOX_UID={uid} differs from the hub uid {euid}")
    if gid != egid:
        mismatches.append(f"SANDBOX_GID={gid} differs from the hub gid {egid}")
    logger.warning(
        "%s, and the hub is not root: the helper cannot switch identities "
        "without privilege, so every Landlock run will fail at chown/setgid. "
        "Set SANDBOX_UID/SANDBOX_GID to the hub uid/gid, or run the hub as root.",
        "; ".join(mismatches),
    )
    _WARNED_IDENTITY = True


def resolve_sandbox_identity() -> tuple[int, int]:
    """Resolve the uid/gid tools run as inside the sandbox.

    uid 0 is rejected: running tools as root would defeat privilege separation
    and leave the shared-/proc secret path open. Fall back to the image user.
    """
    global _WARNED_ROOT_UID
    uid = _env_int("SANDBOX_UID")
    gid = _env_int("SANDBOX_GID")

    if uid == 0 or gid == 0:
        if not _WARNED_ROOT_UID:
            logger.warning(
                "SANDBOX_UID/GID=0 would run tools as root; using the trellis "
                "user instead."
            )
            _WARNED_ROOT_UID = True
        uid = None if uid == 0 else uid
        gid = None if gid == 0 else gid

    try:
        entry = pwd.getpwnam("trellis")
        fallback_uid, fallback_gid = entry.pw_uid, entry.pw_gid
    except KeyError:
        fallback_uid, fallback_gid = 1000, 1000

    resolved_uid = uid if uid is not None else fallback_uid
    resolved_gid = gid if gid is not None else fallback_gid
    _warn_if_identity_unreachable(resolved_uid, resolved_gid)
    return resolved_uid, resolved_gid


def _env_int(name: str) -> int | None:
    raw = os.getenv(name)
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _normalize_requested(requested: str | None) -> str:
    """Normalize a requested backend, warning once for invalid values."""
    global _WARNED_BACKEND
    if requested is None:
        requested = os.getenv("SANDBOX_BACKEND") or "auto"
    value = str(requested).strip().lower()
    if value not in _VALID_BACKENDS:
        if not _WARNED_BACKEND:
            logger.warning(
                "Invalid SANDBOX_BACKEND=%r; falling back to 'auto'.", value
            )
            _WARNED_BACKEND = True
        return "auto"
    return value


def _requested_backend() -> str:
    return _normalize_requested(None)


def _base_payload(requested: str) -> dict:
    uid, _ = resolve_sandbox_identity()
    abi = landlock_abi_version()
    yama = probe_yama()
    warnings = [yama["warning_code"]] if yama["warning_code"] else []
    return {
        "requested": requested,
        "landlock_abi": abi,
        "sandbox_uid": uid,
        "ptrace_scope": yama["ptrace_scope"],
        "seccomp": "off" if seccomp_disabled() else "on",
        "warnings": warnings,
        "evidence": read_lsm_evidence(landlock_abi=abi),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _failure_payload(
    requested: str,
    code: str,
    detail: str,
    checks: dict | None = None,
    base: dict | None = None,
) -> dict:
    if base is None:
        try:
            base = _base_payload(requested)
        except Exception:
            base = {
                "requested": requested,
                "landlock_abi": 0,
                "sandbox_uid": 1000,
                "ptrace_scope": None,
                "evidence": {},
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
    return {
        **base,
        "ok": False,
        "backend": "none",
        "code": code,
        "detail": _truncate(detail),
        "remediation": REMEDIATIONS.get(code, REMEDIATIONS["unknown"]),
        "checks": checks if checks is not None else _empty_checks(),
    }


def _empty_checks() -> dict:
    return {"bwrap": None, "landlock": None, "privilege": None}


def _check(result: ProbeResult | None) -> dict | None:
    if result is None:
        return None
    return {"ok": result.ok, "code": result.code}


def _safe_probe(name: str, probe) -> ProbeResult:
    """Run a probe, converting any exception into an honest ``unknown``."""
    try:
        return probe()
    except Exception as exc:
        return ProbeResult(
            backend=name,
            ok=False,
            code="unknown",
            detail=_truncate(f"{name} crashed: {exc}"),
            remediation=REMEDIATIONS["unknown"],
        )


def _ptrace_failure(requested: str, checks: dict, base: dict | None = None) -> dict:
    return _failure_payload(
        requested,
        "ptrace_scope_unrestricted",
        "Landlock would be selected, but kernel.yama.ptrace_scope is 0; a tool "
        "could read a sibling process's /proc/<pid>/environ.",
        checks,
        base,
    )


def _attach_bwrap_evidence(base: dict, result: ProbeResult) -> None:
    """Merge a bwrap probe's extra evidence (the netns probe) into the payload."""
    global _WARNED_NETNS
    netns = (result.evidence or {}).get("bwrap_netns")
    if netns is None:
        return
    base.setdefault("evidence", {})["bwrap_netns"] = netns
    if not netns.get("ok"):
        base.setdefault("warnings", []).append("netns_denied")
        if not _WARNED_NETNS:
            _WARNED_NETNS = True
            logger.warning(
                "bwrap cannot create a network namespace, so tools with "
                "`network: none` will fail. %s",
                REMEDIATIONS["netns_denied"],
            )


def _attach_net_evidence(base: dict) -> None:
    """Add the network-policy probe to a payload, advisory only.

    Only called when the Landlock backend was probed: bwrap supports
    ``--unshare-net`` unconditionally, so on a bwrap-only run the evidence key
    is omitted rather than reporting a Landlock verdict that was never taken.
    """
    try:
        net = probe_landlock_net()
    except Exception as exc:  # advisory: never fail the payload
        net = NetProbeResult(False, _truncate(f"net probe crashed: {exc}"))
    base.setdefault("evidence", {})["net"] = {
        "deny_supported": net.supported,
        "detail": net.detail,
        "abi": net.abi,
    }
    # Only the ABI gate gets the remediation-bearing warning: with ABI 4+ the
    # TCP policy is enforceable, and an unenforced UDP path (seccomp off, or a
    # filter that did not install) is already reported in the detail above.
    if not net.supported and net.abi < 4:
        base.setdefault("warnings", []).append("landlock_net_unsupported")


def _run_probes(requested: str) -> dict:
    base = _base_payload(requested)
    scope = base["ptrace_scope"]
    checks = _empty_checks()

    if requested == "bwrap":
        result = _safe_probe("bwrap", probe_bwrap)
        checks["bwrap"] = _check(result)
        _attach_bwrap_evidence(base, result)
        if result.ok:
            return {**base, "ok": True, "backend": "bwrap", "checks": checks}
        return _failure_payload(
            requested, result.code or "unknown", result.detail, checks
        )

    if requested == "landlock":
        landlock = _safe_probe("landlock", probe_landlock)
        privilege = _safe_probe("privilege", probe_privilege_drop)
        checks["landlock"] = _check(landlock)
        checks["privilege"] = _check(privilege)
        _attach_net_evidence(base)
        if landlock.ok and privilege.ok:
            if scope == 0:
                return _ptrace_failure(requested, checks, base)
            return {**base, "ok": True, "backend": "landlock", "checks": checks}
        failed = landlock if not landlock.ok else privilege
        return _failure_payload(
            requested, failed.code or "unknown", failed.detail, checks, base
        )

    # auto: prefer bwrap (zero behavior change), fall back to Landlock.
    bwrap = _safe_probe("bwrap", probe_bwrap)
    checks["bwrap"] = _check(bwrap)
    _attach_bwrap_evidence(base, bwrap)
    if bwrap.ok:
        return {**base, "ok": True, "backend": "bwrap", "checks": checks}

    landlock = _safe_probe("landlock", probe_landlock)
    privilege = _safe_probe("privilege", probe_privilege_drop)
    checks["landlock"] = _check(landlock)
    checks["privilege"] = _check(privilege)
    _attach_net_evidence(base)
    if landlock.ok and privilege.ok:
        if scope == 0:
            return _ptrace_failure(requested, checks, base)
        return {**base, "ok": True, "backend": "landlock", "checks": checks}

    # Both backends failed: prefer the fallback's diagnosis because it is the
    # actionable one (e.g. ``landlock_setuid_denied`` when the operator stripped
    # SETUID/SETGID, or ``helper_failed`` when the image lacks the helper).
    if not landlock.ok:
        failed = landlock
    elif not privilege.ok:
        failed = privilege
    else:
        failed = bwrap
    return _failure_payload(
        requested, failed.code or "unknown", failed.detail, checks, base
    )


def _warn_if_seccomp_off() -> None:
    """Warn once that `network: none` loses its UDP/raw denial when seccomp is off."""
    global _WARNED_SECCOMP_OFF
    if _WARNED_SECCOMP_OFF or not seccomp_disabled():
        return
    _WARNED_SECCOMP_OFF = True
    logger.warning(
        "SANDBOX_SECCOMP=off: under the Landlock backend a `network: none` tool "
        "now has TCP connect/bind denied only -- UDP and raw IP sockets stay "
        "usable, so such a tool can still reach the network. Use "
        "SANDBOX_BACKEND=bwrap (`--unshare-net`) for tools that must have no "
        "network at all."
    )


def warmup(requested: str | None = None) -> dict:
    """Probe the configured backend once and cache the result.

    ``requested`` overrides ``SANDBOX_BACKEND`` when given. Never raises: a
    probe failure is reported in the payload so chat-only agents keep working.
    A verdict is published only if no ``invalidate()`` landed while it probed.
    """
    global _STATUS_CACHE, _STATUS_STALE
    selected = _normalize_requested(requested)
    generation = _GENERATION
    _warn_if_seccomp_off()
    try:
        payload = _run_probes(selected)
    except Exception as exc:
        payload = _failure_payload(
            selected, "unknown", f"Sandbox preflight crashed: {exc}"
        )

    if not payload["ok"]:
        logger.critical(
            "Sandbox preflight failed [%s]: %s",
            payload["code"],
            payload["remediation"],
        )
    else:
        logger.info(
            "Sandbox preflight: backend=%s requested=%s landlock_abi=%s",
            payload["backend"],
            payload["requested"],
            payload["landlock_abi"],
        )

    if generation == _GENERATION:
        _STATUS_CACHE = payload
        _STATUS_STALE = False
    else:
        # invalidate() ran while these probes were in flight: its verdict is
        # newer than anything this probe set could observe, so keep the cache
        # stale instead of overwriting it with an older observation.
        logger.info(
            "Discarding sandbox verdict probed across an invalidation; "
            "re-probing on next use."
        )
    return copy.deepcopy(payload)


def cached_status() -> dict:
    """Return a copy of the cached preflight payload (empty before warmup)."""
    return copy.deepcopy(_STATUS_CACHE)


def invalidate(reason: str) -> bool:
    """Drop the cached verdict so the next reader re-probes.

    Called after a sandbox-classified tool failure: the host configuration may
    have changed under the running hub (LSM policy reload, a broken bwrap), which
    would otherwise leave ``/healthz`` serving a stale "healthy" payload.

    Cooldown-bounded by ``_REPROBE_COOLDOWN_S``: a persistently failing sandbox
    re-probes at most once per window instead of forking a probe per failed tool
    call. Returns whether this call actually invalidated the cache.
    """
    global _STATUS_CACHE, _STATUS_STALE, _LAST_INVALIDATION, _GENERATION

    now = _monotonic()
    if (
        _LAST_INVALIDATION is not None
        and now - _LAST_INVALIDATION < _REPROBE_COOLDOWN_S
    ):
        return False

    _LAST_INVALIDATION = now
    _GENERATION += 1
    _STATUS_STALE = True
    _STATUS_CACHE = {}
    logger.info(
        "Sandbox preflight verdict invalidated (%s); re-probing on next use.",
        reason,
    )
    return True


def _reprobe_stale() -> dict:
    """Re-probe a stale verdict, one probe set at a time.

    Concurrent ``/healthz`` requests must not each fork their own probe set
    (up to four helper processes apiece, 5 s each). The first caller probes;
    the others wait briefly for that verdict and otherwise get ``{}`` so the
    caller reports not-ready rather than stacking probes.
    """
    if not _STALE_REPROBE_LOCK.acquire(blocking=False):
        # Another thread owns the probe in flight; its published verdict (if it
        # publishes one) is what these callers should serve.
        if _STALE_REPROBE_LOCK.acquire(timeout=_REPROBE_WAIT_S):
            _STALE_REPROBE_LOCK.release()
        return cached_status()

    try:
        # A probe may have published between the staleness check and here.
        payload = cached_status()
        if payload:
            return payload
        return warmup()
    finally:
        _STALE_REPROBE_LOCK.release()


def build_healthz_payload() -> tuple[int, dict]:
    """Return (200, payload) when ready, else (503, payload).

    Cheap in steady state: the probe result is cached by ``warmup()``. A cold
    process (startup, before warmup) reports not-ready instead of probing on the
    request path. An *invalidated* cache is different -- the verdict is known to
    be stale, so it is re-probed here (single-flight, and the invalidation
    cooldown bounds how often that can happen) rather than reporting a verdict
    nobody trusts.
    """
    payload = cached_status()
    if not payload and _STATUS_STALE:
        payload = _reprobe_stale()
        if not payload:
            # The probe set is still running in another request. Say so: a bare
            # timeout would leave the healthcheck with no diagnosis at all.
            payload = _failure_payload(
                _requested_backend(),
                "unknown",
                "Sandbox preflight re-probe is still running in another request; "
                f"the verdict was not ready within {_REPROBE_WAIT_S:.0f}s.",
            )
    if not payload:
        payload = _failure_payload(
            _requested_backend(), "unknown", "Sandbox preflight has not run."
        )
    return (200 if payload.get("ok") else 503), payload


def reset_for_tests() -> None:
    global _STATUS_CACHE, _STATUS_STALE, _LAST_INVALIDATION, _GENERATION
    global _WARNED_BACKEND, _WARNED_ROOT_UID, _WARNED_IDENTITY
    global _WARNED_SECCOMP_OFF, _WARNED_NETNS
    _STATUS_CACHE = {}
    _STATUS_STALE = False
    _LAST_INVALIDATION = None
    _GENERATION = 0
    _WARNED_BACKEND = False
    _WARNED_ROOT_UID = False
    _WARNED_IDENTITY = False
    _WARNED_SECCOMP_OFF = False
    _WARNED_NETNS = False
