# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge-local credential files: a shared store plus a per-user store.

Credentials stay on the edge VM. They never cross the tunnel and never touch etcd;
the edge trusts central's identity assertion (``user_email`` arrives over the
authenticated tunnel) and looks the caller up locally. Two stores, both dotenv:

* ``secrets_dir`` (default ``edge-secrets``) -- one ``<tool-or-mcp>.env`` per exported
  item, for service accounts that every caller shares.
* ``user_secrets_dir`` (default ``edge-user-secrets``) -- one
  ``<normalized-email>.env`` per user, written 0600.

``credential_mode`` decides the lookup chain per export:

* ``shared`` (default): shared file -> process env. Per-user files are never read, so
  a service account cannot be accidentally shadowed by one user's file.
* ``per_user``: user file -> shared file -> process env.
* ``per_user_required``: user file only; nothing found is a hard refusal
  (``missing_credentials``) -- the call must not run at all.

Only names the manifest declares (``core.edge_env.declared_keys_for``) are ever read or
returned; anything else in a file is ignored. Values are never logged -- only paths and
key names.

**Empty is unset.** A key whose value is empty or only whitespace is treated as absent
in every layer, so ``DEVOPS_PASSWORD=`` neither satisfies ``per_user_required`` nor
masks a real value further down the chain (the process env in ``shared``/``per_user``).
Blank values are the usual way an operator disables a key, not a credential.

Files are dotenv: ``KEY=VALUE`` per line, a leading ``export `` is accepted (the common
shell form), ``#`` is a comment, and one layer of matching quotes is stripped. The CLI
writes a leading ``# email: <address>`` header so ``user-secrets list`` can print the
address instead of the hashed filename stem; the reader ignores it.

Edge-only by design, like ``core.edge_env``: no etcd, no FastAPI, no ``core.discovery``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from core import edge_env

logger = logging.getLogger(__name__)

# The error code a refusal travels back to central under (plan §3.1/§7 Phase 5).
MISSING_CREDENTIALS = "missing_credentials"

CREDENTIAL_MODES: frozenset[str] = frozenset({"shared", "per_user", "per_user_required"})
DEFAULT_MODE = "shared"

# Both stores are meant to be 0600/0700: the shared one holds a service account, the
# per-user one holds a person's credentials. Write always uses this, regardless of umask.
SHARED_FILE_MODE = 0o600
USER_FILE_MODE = 0o600
DIR_MODE = 0o700

# Long local part + domain would otherwise produce a filename that busts PATH_MAX on
# top of a mounted directory; the hash suffix keeps it unique after the cap.
MAX_SANITIZED_EMAIL = 48

DEFAULT_SECRETS_DIR = Path("edge-secrets")
DEFAULT_USER_SECRETS_DIR = Path("edge-user-secrets")

_EMAIL_SLUG_RE = re.compile(r"[^a-z0-9]+")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# The ``# email:`` header ``user-secrets set`` writes; the value is informational only
# (resolution always uses the caller's address), so a hand-edited header cannot
# redirect a lookup.
_EMAIL_HEADER_RE = re.compile(r"^#\s*email\s*:\s*(\S.*?)\s*$", re.IGNORECASE)

# Credential filenames are derived from a tool/MCP name, which the loaders already
# validate; this second check is what keeps a hand-edited name from escaping the dir.
_SAFE_STEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_GROUP_OTHER_READABLE = 0o044

# One warning per file per process: a permissive shared file is worth saying once, not
# on every call. Tests clear this to re-assert the warning.
_WARNED_PERMISSIVE: set[str] = set()


class MissingCredentials(Exception):
    """No usable credentials for this caller; ``code`` becomes ``result.error.code``.

    Raised only by ``per_user_required``. The message is the exact string central
    surfaces to the agent, so it names the email and the site but never a value.
    """

    def __init__(self, message: str, *, code: str = MISSING_CREDENTIALS) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class CredentialFileError(Exception):
    """An existing credential file could not be read.

    Only writers raise it: a merge that treated an unreadable file as empty would
    rewrite it from ``{}`` and silently drop every key it still holds.
    """


def normalize_email(email: str) -> str:
    """A filesystem-safe, collision-resistant filename stem for one email.

    Lowercases, collapses every non-alphanumeric run to ``-``, trims, caps at
    ``MAX_SANITIZED_EMAIL`` and appends ``_<sha256(lowercased)[:8]>``. The hash is over
    the original (stripped, lowercased) address, so ``../``, ``/`` and unicode
    decoration cannot survive into a path, while two addresses that slugify to the same
    text (``a.b@x`` vs ``a-b@x``, ``ä@x`` vs ``a@x``) still get distinct files. Case
    variants of the *same* address map to one file by construction.
    """
    raw = str(email or "").strip().lower()
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]
    slug = _EMAIL_SLUG_RE.sub("-", raw).strip("-")[:MAX_SANITIZED_EMAIL].rstrip("-")
    return f"{slug}_{digest}"


def parse_env_text(text: str) -> Dict[str, str]:
    """Parse ``KEY=VALUE`` lines defensively: never interpolate, never evaluate.

    Blank lines and ``#`` comments are skipped, an optional leading ``export `` (the
    common shell/dotenv form) is accepted, a line without ``=`` or with a name that is
    not a plain env identifier is ignored (a malformed line must not cost the rest of
    the file), ``KEY=`` parses as an empty value (the resolver treats that as unset),
    and one layer of matching quotes is stripped. Later duplicates win, which is what
    "re-set the key" means.
    """
    values: Dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export ") or stripped.startswith("export\t"):
            stripped = stripped[len("export") :].strip()
            if not stripped:
                continue
        key, separator, value = stripped.partition("=")
        if not separator:
            continue
        key = key.strip()
        if not _ENV_KEY_RE.match(key):
            continue
        values[key] = _unquote(value.strip())
    return values


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_env_file(path: Path) -> Dict[str, str]:
    """Read one credential file; a missing or unreadable file is empty, not an error."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        logger.warning("credential file %s could not be read (%s); ignoring it", path, exc)
        return {}
    except UnicodeDecodeError:
        logger.warning("credential file %s is not valid UTF-8; ignoring it", path)
        return {}
    return parse_env_text(text)


def load_env_file(path: Path) -> Dict[str, str]:
    """``parse_env_file`` for a writer: missing is empty, unreadable raises.

    The CLI merges before it writes, so "unreadable" must never look like "empty" --
    rewriting from ``{}`` would drop every key the operator cannot currently read
    (a wrong owner, a mount, a half-copied file). Readers stay forgiving.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as exc:
        raise CredentialFileError(f"cannot read {path} ({exc})") from exc
    return parse_env_text(text)


def read_email_header(path: Path) -> Optional[str]:
    """The address from the leading ``# email:`` line, or ``None`` (legacy file).

    Display only: ``user-secrets list`` uses it to show an address instead of the
    hashed filename stem. Resolution never reads it, so a wrong header cannot send
    one user's credentials to another.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = _EMAIL_HEADER_RE.match(stripped)
        if match:
            return match.group(1)
        if not stripped.startswith("#"):
            break  # only the leading comment block can carry the header
    return None


def write_env_file(path: Path, values: Mapping[str, str], *, email: Optional[str] = None) -> None:
    """Write a credential file atomically, mode 0600.

    ``tmp + os.replace`` so a crash mid-write cannot leave a half file where the next
    call reads a truncated password. The parent directory is created 0700 here (and
    only here -- reads never create anything) and its mode is only *set* when this
    call created it: a directory the operator mounted 0750 is theirs, not ours.

    ``email`` writes a leading ``# email: <address>`` header (skipped by the parser),
    so ``user-secrets list`` can name the user instead of a filename stem.
    """
    path = Path(path)
    lines = []
    address = " ".join(str(email or "").split())
    if address:
        lines.append(f"# email: {address}\n")
    for key in sorted(values):
        name = str(key)
        if not _ENV_KEY_RE.match(name):
            raise ValueError(f"invalid credential key {name!r} (expected KEY=VALUE)")
        value = str(values[key])
        if "\n" in value or "\r" in value:
            raise ValueError(
                f"credential {name} contains a newline; write one KEY=VALUE per line"
            )
        lines.append(f"{name}={value}\n")

    created = False
    try:
        path.parent.mkdir(parents=True, mode=DIR_MODE)
        created = True
    except FileExistsError:
        pass
    if created:
        try:
            os.chmod(path.parent, DIR_MODE)
        except OSError:
            logger.debug("Could not chmod credential dir %s", path.parent, exc_info=True)

    handle_fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            handle.write("".join(lines))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, USER_FILE_MODE)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    try:
        # mkstemp already made it 0600; this covers a pre-existing file replaced over a
        # filesystem that kept the old mode, and documents the intent at the call site.
        os.chmod(path, USER_FILE_MODE)
    except OSError:
        logger.warning("could not set mode %04o on %s", USER_FILE_MODE, path)


def _warn_if_permissive(path: Path, kind: str) -> None:
    """Warn once when another user on the box can read this credential file."""
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return
    if not mode & _GROUP_OTHER_READABLE:
        return
    marker = f"{kind}:{path}"
    if marker in _WARNED_PERMISSIVE:
        return
    _WARNED_PERMISSIVE.add(marker)
    logger.warning(
        "%s credential file %s is readable by group/other (mode %04o); chmod %04o %s",
        kind,
        path,
        mode,
        SHARED_FILE_MODE,
        path,
    )


def _mode(mode: Any) -> str:
    normalized = str(mode or DEFAULT_MODE).strip().lower()
    if normalized not in CREDENTIAL_MODES:
        raise ValueError(
            f"credential_mode must be one of {', '.join(sorted(CREDENTIAL_MODES))} "
            f"(got {mode!r})"
        )
    return normalized


def _missing(email: Optional[str], site: Optional[str]) -> MissingCredentials:
    return MissingCredentials(
        f"no credentials for {email or 'anonymous'} on edge {site or 'unknown'}"
    )


def _nonempty(values: Mapping[str, str]) -> Dict[str, str]:
    """Drop empty/whitespace values: a blank value is an absent key, not a credential.

    Applied per layer, so ``KEY=`` in a user file neither satisfies
    ``per_user_required`` nor masks a real value in the next layer (the shared file or
    the process env). The value itself is passed through untouched otherwise.
    """
    return {key: value for key, value in values.items() if str(value).strip()}


def enforce_per_user_required(
    env: Dict[str, str], config: Any, resolved: Mapping[str, str], mode: Optional[str]
) -> None:
    """Under ``per_user_required``, drop every declared key the user file did not supply.

    ``env`` starts as a copy of the process environment (the whole sanitized copy under
    ``env_passthrough``), so a declared key the caller's file omits would otherwise
    arrive from the container and the mode would quietly degrade to "user -> process
    env" -- exactly what the mode forbids. In place, like the strip helpers; a no-op in
    the other modes.
    """
    if _mode(mode) != "per_user_required":
        return
    for key in edge_env.declared_keys_for(config):
        if key not in resolved:
            env.pop(key, None)


@dataclass(frozen=True)
class CredentialStore:
    """The two on-disk stores of one edge, plus the resolution chain over them."""

    secrets_dir: Path = DEFAULT_SECRETS_DIR
    user_secrets_dir: Path = DEFAULT_USER_SECRETS_DIR

    @classmethod
    def from_config(cls, config: Any) -> "CredentialStore":
        """Build from a ``core.proxy.ProxyConfig`` (or anything with the two attrs)."""
        secrets = getattr(config, "secrets_dir", None) if config is not None else None
        users = getattr(config, "user_secrets_dir", None) if config is not None else None
        return cls(
            secrets_dir=Path(secrets) if secrets else DEFAULT_SECRETS_DIR,
            user_secrets_dir=Path(users) if users else DEFAULT_USER_SECRETS_DIR,
        )

    def shared_file(self, name: str) -> Path:
        """``<secrets_dir>/<tool-or-mcp>.env``; a name that could escape is refused."""
        stem = str(name or "").strip()
        if not _SAFE_STEM_RE.match(stem):
            raise ValueError(
                f"invalid credential file name {name!r} (expected a plain tool/MCP name)"
            )
        return Path(self.secrets_dir) / f"{stem}.env"

    def user_file(self, email: str) -> Path:
        """``<user_secrets_dir>/<normalized-email>.env`` -- always one level deep."""
        return Path(self.user_secrets_dir) / f"{normalize_email(email)}.env"

    def resolve(
        self,
        config: Any,
        *,
        name: str,
        email: Optional[str],
        site: str,
        mode: str = DEFAULT_MODE,
    ) -> Dict[str, str]:
        """The credentials for one call, per ``mode`` (plan §7 Phase 5).

        Side-effect free and synchronous: no directory is created, and the only log
        lines name files and keys. Only ``edge_env.declared_keys_for(config)`` is ever
        read out of a file or the process env, so an extra key in someone's file cannot
        reach a child process.

        An empty or whitespace-only value counts as unset in every layer (see
        ``_nonempty``), so it cannot satisfy ``per_user_required`` or shadow a real
        value further down the chain.
        """
        declared = edge_env.declared_keys_for(config)
        resolved_mode = _mode(mode)

        if resolved_mode == "per_user_required":
            user = _nonempty(self._read_user(email))
            if not declared or not declared & set(user):
                raise _missing(email, site)
            return {key: value for key, value in user.items() if key in declared}

        layers = []
        if resolved_mode == "per_user" and email:
            layers.append(self._read_user(email))
        layers.append(self._read_shared(name))
        layers.append({key: os.environ[key] for key in declared if key in os.environ})

        resolved: Dict[str, str] = {}
        for layer in layers:
            for key, value in _nonempty(layer).items():
                if key in declared and key not in resolved:
                    resolved[key] = value
        return resolved

    def _read_user(self, email: Optional[str]) -> Dict[str, str]:
        if not email:
            return {}
        path = self.user_file(email)
        values = parse_env_file(path)
        if values:
            _warn_if_permissive(path, "per-user")
        return values

    def _read_shared(self, name: str) -> Dict[str, str]:
        try:
            path = self.shared_file(name)
        except ValueError as exc:
            logger.warning("%s; no shared credentials for it", exc)
            return {}
        values = parse_env_file(path)
        if values:
            _warn_if_permissive(path, "shared")
        return values
