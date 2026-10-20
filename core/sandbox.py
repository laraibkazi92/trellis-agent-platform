# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Sandbox backend selection and per-run execution plans for the tool hub.

Two backends share one interface:

- ``bwrap``: the historical bubblewrap invocation, plus ``--cap-drop ALL``.
- ``landlock``: the static helper, which applies filesystem confinement and
  drops the tool to the workspace owner uid/gid.

``select_backend()`` is memoized and delegates probing to
``core.sandbox_preflight`` so ``/healthz`` and per-call execution agree on one
verdict.
"""

import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from core import sandbox_preflight
from core.env_sanitize import sanitized_env

logger = logging.getLogger(__name__)

# Single source of truth shared with the preflight probe.
BWRAP_ARGS = sandbox_preflight.BWRAP_BASE_ARGS

_VALID_BACKENDS = frozenset({"auto", "bwrap", "landlock"})
_DEFAULT_TMP_ROOT = "/tmp/trellis"

_SELECTED: dict[str, "Backend"] = {}
_WARNED_INVALID: set[str] = set()
_LOGGED_SELECTION = False
_LOGGED_FAILURES: set[tuple[str, str]] = set()


class Backend(str, Enum):
    BWRAP = "bwrap"
    LANDLOCK = "landlock"


class SandboxUnavailable(RuntimeError):
    """No usable sandbox backend; carries the preflight diagnosis."""

    def __init__(
        self,
        code: str,
        detail: str = "",
        remediation: str = "",
        backend: str | None = None,
    ) -> None:
        self.code = code
        self.detail = detail
        self.remediation = remediation
        self.backend = backend
        super().__init__(f"Sandbox unavailable [{code}]: {detail or remediation}")


@dataclass
class SandboxPlan:
    argv: list[str]
    env: dict[str, str]
    tmpdir: Path
    backend: Backend
    _cleaned: bool = field(default=False, repr=False, compare=False)

    def cleanup(self) -> None:
        """Remove the per-run directory; safe to call more than once."""
        if self._cleaned:
            return
        self._cleaned = True
        # Never remove "/", "/tmp", or the shared tmp root itself.
        if not self.tmpdir.name.startswith("trellis-"):
            return
        try:
            if self.tmpdir.resolve() in {Path("/"), Path("/tmp")}:
                return
        except OSError:
            return
        shutil.rmtree(self.tmpdir, ignore_errors=True)


def _normalize(requested: str | None) -> str:
    raw = (os.getenv("SANDBOX_BACKEND") or "auto") if requested is None else requested
    value = str(raw).strip().lower()
    if value not in _VALID_BACKENDS:
        if value not in _WARNED_INVALID:
            logger.warning(
                "Invalid SANDBOX_BACKEND=%r; falling back to 'auto'.", raw
            )
            _WARNED_INVALID.add(value)
        return "auto"
    return value


def configured_backend() -> str:
    """Return the normalized ``SANDBOX_BACKEND`` value (default ``auto``)."""
    return _normalize(None)


def select_backend(force: str | None = None) -> Backend:
    """Select and memoize a working backend, or raise ``SandboxUnavailable``.

    A failed selection is not memoized: the cached preflight status is reused,
    so repeated calls stay cheap without forking probes.
    """
    global _LOGGED_SELECTION

    requested = _normalize(force)
    selected = _SELECTED.get(requested)
    if selected is not None:
        return selected

    status = sandbox_preflight.cached_status()
    if not status or status.get("requested") != requested:
        status = sandbox_preflight.warmup(requested=requested)

    if not status.get("ok"):
        raise SandboxUnavailable(
            status.get("code") or "unknown",
            status.get("detail") or "",
            status.get("remediation") or "",
            backend=status.get("backend"),
        )

    try:
        selected = Backend(status["backend"])
    except (KeyError, ValueError) as exc:
        raise SandboxUnavailable(
            "unknown",
            f"Preflight reported an unusable backend: {status.get('backend')!r}",
            sandbox_preflight.REMEDIATIONS["unknown"],
            backend=status.get("backend"),
        ) from exc

    _SELECTED[requested] = selected
    if not _LOGGED_SELECTION:
        logger.info("Sandbox backend: %s", selected.value)
        _LOGGED_SELECTION = True
    return selected


def classify_failure(
    stderr: str,
    backend: Backend | str,
    returncode: int | None = None,
) -> sandbox_preflight.ProbeResult | None:
    """Map a sandbox-caused non-zero exit to a stable diagnosis.

    The helper prefixes its own errors with ``trellis-sandbox:``, so tool stderr
    (including a coincidental exit 65) is not misclassified as a sandbox fault.
    """
    backend = Backend(backend)
    text = stderr or ""

    if backend is Backend.BWRAP:
        # bwrap prefixes its own diagnostics; without provenance a tool's
        # "permission denied" stderr would be mislabelled as a sandbox fault.
        if "bwrap:" not in text.lower():
            return None
        code = sandbox_preflight.classify_bwrap_stderr(
            text, sandbox_preflight.read_lsm_evidence()
        )
    else:
        if "trellis-sandbox:" not in text.lower():
            return None
        if returncode == 65:
            code = "landlock_unavailable"
        elif returncode == 68:
            code = "landlock_setuid_denied"
        elif returncode == 69:
            code = "rlimit_denied"
        elif returncode in (66, 67):
            code = "helper_failed"
        else:
            return None

    if not code:
        return None
    return sandbox_preflight.ProbeResult(
        backend=backend.value,
        ok=False,
        code=code,
        detail=text.strip()[:500],
        remediation=sandbox_preflight.REMEDIATIONS[code],
    )


def log_failure_once(result: sandbox_preflight.ProbeResult) -> None:
    """Log each (backend, code) diagnosis once per process."""
    key = (result.backend, result.code or "unknown")
    if key in _LOGGED_FAILURES:
        return
    _LOGGED_FAILURES.add(key)
    logger.error(
        "Tool failed inside the %s sandbox [%s]: %s",
        result.backend,
        result.code,
        result.remediation,
    )


def _seccomp_disabled() -> bool:
    return sandbox_preflight.seccomp_disabled()


def build_cmd(
    backend: Backend | str,
    cmd: list[str],
    tool_dir: Path,
    tmpdir: Path,
    uid: int,
    gid: int,
) -> list[str]:
    """Build the sandbox argv that wraps ``cmd``."""
    backend = Backend(backend)
    if backend is Backend.BWRAP:
        return list(BWRAP_ARGS) + list(cmd)

    argv = [
        sandbox_preflight.helper_path(),
        "--ro", "/",
        "--rw", "/app/workspace",
        "--tmpdir", str(tmpdir),
        "--uid", str(uid),
        "--gid", str(gid),
    ]
    if _seccomp_disabled():
        argv.append("--no-seccomp")
    return argv + ["--"] + list(cmd)


def _tmp_root() -> Path:
    return Path(os.getenv("SANDBOX_TMP_ROOT") or _DEFAULT_TMP_ROOT)


def _safe_tool_name(tool_dir: Path) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", tool_dir.name)[:40]
    return safe or "tool"


def prepare_execution(
    cmd: list[str],
    tool_dir: Path,
    backend: Backend | str | None = None,
    env: dict[str, str] | None = None,
) -> SandboxPlan:
    """Create the per-run tmpdir, env, and argv for one tool invocation."""
    tool_dir = Path(tool_dir)
    selected = Backend(backend) if backend is not None else select_backend()
    uid, gid = sandbox_preflight.resolve_sandbox_identity()

    root = _tmp_root()
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o711)
        # mkdir's mode is masked by umask and ignored when the dir exists; the
        # dropped-uid tool must be able to traverse it.
        try:
            os.chmod(root, 0o711)
        except OSError:
            pass
        tmpdir = Path(
            tempfile.mkdtemp(
                prefix=f"trellis-{_safe_tool_name(tool_dir)}-", dir=str(root)
            )
        )
    except OSError as exc:
        raise SandboxUnavailable(
            "helper_failed",
            f"Could not create sandbox tmpdir under {root}: {exc}",
            "Check that SANDBOX_TMP_ROOT is writable and has free space.",
            backend=selected.value,
        ) from exc

    plan_env = sanitized_env() if env is None else dict(env)
    if selected is Backend.BWRAP:
        # /tmp is a private tmpfs, so a writable HOME keeps npx/pip caches
        # working and stops tools from reading the hub's own home config.
        plan_env.update(
            {"TMPDIR": "/tmp", "TMP": "/tmp", "TEMP": "/tmp", "HOME": "/tmp"}
        )
    else:
        home = str(tmpdir)
        plan_env.update(
            {"TMPDIR": home, "TMP": home, "TEMP": home, "HOME": home}
        )

    return SandboxPlan(
        argv=build_cmd(selected, list(cmd), tool_dir, tmpdir, uid, gid),
        env=plan_env,
        tmpdir=tmpdir,
        backend=selected,
    )


def reset_for_tests() -> None:
    """Clear selection memoization and the preflight status cache."""
    global _LOGGED_SELECTION
    _SELECTED.clear()
    _WARNED_INVALID.clear()
    _LOGGED_FAILURES.clear()
    _LOGGED_SELECTION = False
    sandbox_preflight.reset_for_tests()
