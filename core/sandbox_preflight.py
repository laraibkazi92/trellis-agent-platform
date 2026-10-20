# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Preflight probes for the tool-hub sandbox backends.

``warmup()`` probes the configured backend once at startup and caches a payload
shaped for ``/healthz``. Phase 2 probes both backends: bubblewrap, and the
Landlock helper (filesystem confinement plus the uid drop, probed separately so
a stripped capability is diagnosed as ``landlock_setuid_denied``).
"""

import copy
import ctypes
import logging
import os
import pwd
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

CODES: frozenset[str] = frozenset({
    "bwrap_missing",
    "apparmor_mount_denied",
    "seccomp_pivot_root",
    "userns_restriction",
    "selinux_denied",
    "landlock_unavailable",
    "landlock_setuid_denied",
    "ptrace_scope_unrestricted",
    "mount_denied_unknown_lsm",
    "helper_failed",
    "unknown",
})

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
        "The hub cannot chown the run dir or drop the tool's uid. Start the hub "
        "with CAP_SETUID, CAP_SETGID and CAP_CHOWN (see the compose cap_add), or "
        "switch to `SANDBOX_BACKEND=bwrap`."
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


_VALID_BACKENDS = frozenset({"auto", "bwrap", "landlock"})
_SECCOMP_OFF = frozenset({"off", "0", "false", "no"})
_STATUS_CACHE: dict = {}
_WARNED_BACKEND = False
_WARNED_ROOT_UID = False


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


def classify_bwrap_stderr(stderr: str, evidence: dict | None = None) -> str | None:
    """Map bwrap stderr to a stable sandbox failure code."""
    text = (stderr or "").lower()
    evidence = evidence or {}
    apparmor = evidence.get("apparmor") or {}
    profile = str(apparmor.get("profile") or "").lower()

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
        proc = subprocess.run(
            list(BWRAP_BASE_ARGS) + ["/bin/true"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
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
        return ProbeResult(backend="bwrap", ok=True)

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


def _classify_helper_result(backend: str, proc) -> ProbeResult:
    """Map a helper exit status/stderr to a stable sandbox failure code."""
    if proc.returncode == 0:
        return ProbeResult(backend=backend, ok=True)

    detail = _probe_detail(proc)
    text = (detail or "").lower()

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

    # A missing bind source is a deployment problem, not a Landlock refusal.
    # Phase 1 made the same call for bwrap; do not mislabel it ``bwrap_missing``.
    if "/app/workspace" in text and any(
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

    # A failed chown/setuid means the hub is missing CAP_SETUID/CAP_SETGID.
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


def _run_helper(
    backend: str, helper: str, grants: list[str], timeout: float
) -> ProbeResult:
    """Run the helper with ``grants`` plus the shared uid-drop tail."""
    uid, gid = resolve_sandbox_identity()
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

    argv = [
        helper,
        *grants,
        "--tmpdir", tmpdir,
        "--uid", str(uid),
        "--gid", str(gid),
        # Probe the same argv the hub will run, including the escape hatch.
        *(["--no-seccomp"] if seccomp_disabled() else []),
        # Assert the identity, not just exit 0: a helper that forgot to drop
        # must not make /healthz green.
        "--", "/bin/sh", "-c", "id -u",
    ]
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
        "landlock", helper, ["--ro", "/", "--rw", "/app/workspace"], timeout
    )


def probe_privilege_drop(
    helper: str | None = None, timeout: float = 5.0
) -> ProbeResult:
    """Probe only the uid drop (no ``--rw``), isolating ``SETUID``/``SETGID``."""
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

    return (
        uid if uid is not None else fallback_uid,
        gid if gid is not None else fallback_gid,
    )


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
    requested: str, code: str, detail: str, checks: dict | None = None
) -> dict:
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


def _ptrace_failure(requested: str, checks: dict) -> dict:
    return _failure_payload(
        requested,
        "ptrace_scope_unrestricted",
        "Landlock would be selected, but kernel.yama.ptrace_scope is 0; a tool "
        "could read a sibling process's /proc/<pid>/environ.",
        checks,
    )


def _run_probes(requested: str) -> dict:
    base = _base_payload(requested)
    scope = base["ptrace_scope"]
    checks = _empty_checks()

    if requested == "bwrap":
        result = _safe_probe("bwrap", probe_bwrap)
        checks["bwrap"] = _check(result)
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
        if landlock.ok and privilege.ok:
            if scope == 0:
                return _ptrace_failure(requested, checks)
            return {**base, "ok": True, "backend": "landlock", "checks": checks}
        failed = landlock if not landlock.ok else privilege
        return _failure_payload(
            requested, failed.code or "unknown", failed.detail, checks
        )

    # auto: prefer bwrap (zero behavior change), fall back to Landlock.
    bwrap = _safe_probe("bwrap", probe_bwrap)
    checks["bwrap"] = _check(bwrap)
    if bwrap.ok:
        return {**base, "ok": True, "backend": "bwrap", "checks": checks}

    landlock = _safe_probe("landlock", probe_landlock)
    privilege = _safe_probe("privilege", probe_privilege_drop)
    checks["landlock"] = _check(landlock)
    checks["privilege"] = _check(privilege)
    if landlock.ok and privilege.ok:
        if scope == 0:
            return _ptrace_failure(requested, checks)
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
        requested, failed.code or "unknown", failed.detail, checks
    )


def warmup(requested: str | None = None) -> dict:
    """Probe the configured backend once and cache the result.

    ``requested`` overrides ``SANDBOX_BACKEND`` when given. Never raises: a
    probe failure is reported in the payload so chat-only agents keep working.
    """
    global _STATUS_CACHE
    selected = _normalize_requested(requested)
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

    _STATUS_CACHE = payload
    return copy.deepcopy(payload)


def cached_status() -> dict:
    """Return a copy of the cached preflight payload (empty before warmup)."""
    return copy.deepcopy(_STATUS_CACHE)


def build_healthz_payload() -> tuple[int, dict]:
    """Return (200, payload) when ready, else (503, payload).

    Pure and cheap: the probe result is cached by ``warmup()`` at startup, so a
    healthcheck request never forks a sandbox probe. Before warmup the route
    reports not-ready instead of probing on the event loop.
    """
    payload = cached_status()
    if not payload:
        payload = _failure_payload(
            _requested_backend(), "unknown", "Sandbox preflight has not run."
        )
    return (200 if payload.get("ok") else 503), payload


def reset_for_tests() -> None:
    global _STATUS_CACHE, _WARNED_BACKEND, _WARNED_ROOT_UID
    _STATUS_CACHE = {}
    _WARNED_BACKEND = False
    _WARNED_ROOT_UID = False
