# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge-local credential rules: the shared store plus the sealed per-user set.

Three sources exist, and only one of them is central:

* ``secrets_dir`` (default ``edge-secrets``) -- one ``<tool-or-mcp>.env`` per exported
  item, for a service account every caller shares. Dotenv, mode 0600.
* a **sealed blob** -- per-user credentials the browser encrypted to this edge's
  public key (``core.edge_crypto``). Central stores ciphertext; only this process
  can open it, and only for the ``(site, kind, name, identity)`` the AAD binds.
* the process environment -- the last fallback in ``shared`` mode only.

``credential_mode`` decides what happens when a sealed set exists:

* ``shared`` (default): the shared file -> process env.
* ``per_user``: the sealed set if the caller has one, else shared -> process env.
* ``per_user_required``: the sealed set **only**; nothing sealed for this caller is
  a hard refusal (``missing_credentials``) -- the call must not run at all.

The per-user set is all-or-nothing (plan §5 Phase 4 R8): once a blob is present, a
declared secret it omits stays missing and is never filled from the shared file or
the process env. ``variables`` (endpoints) are never per-user material: they come
from the shared file and the process env in every mode.

Only names the manifest declares are ever read or returned; anything else in a file
or a blob is ignored. Values are never logged -- only paths and key names.

Edge-only by design, like ``core.edge_env``: no etcd, no FastAPI, no
``core.discovery``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from core import edge_env

logger = logging.getLogger(__name__)

# The error code a refusal travels back to central under (plan §3.1/§5 Phase 4).
MISSING_CREDENTIALS = "missing_credentials"

CREDENTIAL_MODES: frozenset[str] = frozenset({"shared", "per_user", "per_user_required"})
DEFAULT_MODE = "shared"

SHARED_FILE_MODE = 0o600
DIR_MODE = 0o700

# Long local part + domain would otherwise produce a filename that busts PATH_MAX on
# top of a mounted directory; the hash suffix keeps it unique after the cap.
MAX_SANITIZED_EMAIL = 48

DEFAULT_SECRETS_DIR = Path("edge-secrets")
# The v0.5 plaintext per-user store. Nothing reads it any more; the path is kept only
# so the proxy can log one startup warning when a stale directory is still mounted.
LEGACY_USER_SECRETS_DIR = Path("edge-user-secrets")
LEGACY_USER_SECRETS_ENV = "TRELLIS_EDGE_USER_SECRETS_DIR"

_EMAIL_SLUG_RE = re.compile(r"[^a-z0-9]+")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Credential filenames are derived from a tool/MCP name, which the loaders already
# validate; this second check is what keeps a hand-edited name from escaping the dir.
_SAFE_STEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_GROUP_OTHER_READABLE = 0o044

# One warning per file per process: a permissive shared file is worth saying once, not
# on every call. Tests clear this to re-assert the warning.
_WARNED_PERMISSIVE: set[str] = set()
_LEGACY_WARNED = False


class MissingCredentials(Exception):
    """No usable credentials for this caller; ``code`` becomes ``result.error.code``.

    Raised by ``per_user_required`` when the caller has no sealed blob. The message is
    the exact string central surfaces to the agent, so it names the email and the site
    but never a value.
    """

    def __init__(self, message: str, *, code: str = MISSING_CREDENTIALS) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def normalize_email(email: str) -> str:
    """A filesystem-safe, collision-resistant stem for one email.

    Still used as the MCP session key (two spellings of one address must not become
    two sessions), so the normalization is part of the session contract even though
    there are no per-user files any more.
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


def warn_about_legacy_user_secrets() -> None:
    """Log once when a v0.5 ``edge-user-secrets/`` directory is still mounted.

    Nothing reads it: per-user credentials are browser-sealed now. The operator must
    re-enter them in the UI (compact JSON), and the directory can be deleted together
    with its compose mount (docs/upgrading.md).
    """
    global _LEGACY_WARNED
    if _LEGACY_WARNED:
        return
    _LEGACY_WARNED = True
    candidates = [Path(os.getenv(LEGACY_USER_SECRETS_ENV) or LEGACY_USER_SECRETS_DIR)]
    for directory in candidates:
        try:
            if not directory.is_dir():
                continue
        except OSError:
            continue
        logger.warning(
            "%s still exists but per-user plaintext credentials are no longer read "
            "(v0.6 seals them in the browser and decrypts on this edge). Re-enter "
            "those credentials in central under Configuration -> Edge credentials, "
            "then delete the directory and its compose mount.",
            directory,
        )
        return


def _warn_if_permissive(path: Path) -> None:
    """Warn once when another user on the box can read this credential file."""
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return
    if not mode & _GROUP_OTHER_READABLE:
        return
    marker = str(path)
    if marker in _WARNED_PERMISSIVE:
        return
    _WARNED_PERMISSIVE.add(marker)
    logger.warning(
        "shared credential file %s is readable by group/other (mode %04o); chmod %04o %s",
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
    """Drop empty/whitespace values: a blank file/env value is an absent key."""
    return {key: value for key, value in values.items() if str(value).strip()}


def _flatten(value: Any) -> set[str]:
    """One manifest declaration's names: a list is literal, a mapping spans buckets."""
    if isinstance(value, Mapping):
        names: set[str] = set()
        for bucket in ("general", "user", "background"):
            names.update(
                key for key in (value.get(bucket) or []) if isinstance(key, str) and key
            )
        return names
    if isinstance(value, (list, tuple)):
        return {key for key in value if isinstance(key, str) and key}
    return set()


def declared_variable_keys(config: Any) -> frozenset[str]:
    """The manifest's ``variables`` names -- endpoints, never per-user material."""
    if config is None:
        return frozenset()
    value = config.get("variables") if isinstance(config, Mapping) else getattr(
        config, "variables", None
    )
    return frozenset(_flatten(value))


def declared_secret_keys(config: Any) -> frozenset[str]:
    """The manifest's credential names: ``secrets``, ``optional_secrets``, groups.

    A name that also appears under ``variables`` is treated as a variable (the
    stricter reading, and the same rule the central write gate applies), so a sealed
    blob can never carry it.
    """
    if config is None:
        return frozenset()
    variables = declared_variable_keys(config)
    return frozenset(edge_env.declared_keys_for(config) - variables)


@dataclass(frozen=True)
class CredentialStore:
    """The edge's shared credential store plus the resolution rules over it."""

    secrets_dir: Path = DEFAULT_SECRETS_DIR

    @classmethod
    def from_config(cls, config: Any) -> "CredentialStore":
        """Build from a ``core.proxy.ProxyConfig`` (or anything with the attribute)."""
        secrets = getattr(config, "secrets_dir", None) if config is not None else None
        return cls(secrets_dir=Path(secrets) if secrets else DEFAULT_SECRETS_DIR)

    def shared_file(self, name: str) -> Path:
        """``<secrets_dir>/<tool-or-mcp>.env``; a name that could escape is refused."""
        stem = str(name or "").strip()
        if not _SAFE_STEM_RE.match(stem):
            raise ValueError(
                f"invalid credential file name {name!r} (expected a plain tool/MCP name)"
            )
        return Path(self.secrets_dir) / f"{stem}.env"

    def resolve(
        self,
        config: Any,
        *,
        name: str,
        email: Optional[str] = None,
        site: str = "",
        mode: str = DEFAULT_MODE,
        sealed: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, str]:
        """The credentials for one call, per ``mode`` and this caller's sealed set.

        ``sealed`` is the already-decrypted mapping from ``core.edge_crypto`` (``None``
        means the caller has no blob). Its presence switches the per-user branch on:

        * only declared **secret** names are taken, all-or-nothing -- a missing one is
          not filled from the shared file or the process env;
        * declared **variable** names still come from the shared file / process env,
          because an endpoint is edge configuration (plan §6 invariant 10).

        Without a blob, ``per_user_required`` fails closed and every other mode reads
        the shared file then the process env. Side-effect free and synchronous: no
        directory is created, and the only log lines name files and keys.
        """
        declared = edge_env.declared_keys_for(config)
        resolved_mode = _mode(mode)

        if sealed is not None:
            secrets = declared_secret_keys(config)
            # A blank field is treated as unset, consistently with files/env;
            # otherwise an all-empty submission would satisfy per_user_required
            # and run the tool with empty credentials.
            resolved = {
                key: str(value)
                for key, value in sealed.items()
                if key in secrets and isinstance(value, str) and value.strip()
            }
            if resolved_mode == "per_user_required" and not resolved:
                # A blob with no declared secret is as good as no blob: fail closed.
                raise _missing(email, site)
            variables = declared_variable_keys(config)
            for layer in (
                self._read_shared(name),
                {key: os.environ[key] for key in variables if key in os.environ},
            ):
                for key, value in _nonempty(layer).items():
                    if key in variables and key not in resolved:
                        resolved[key] = value
            return resolved

        if resolved_mode == "per_user_required":
            raise _missing(email, site)

        layers = [
            self._read_shared(name),
            {key: os.environ[key] for key in declared if key in os.environ},
        ]
        resolved: Dict[str, str] = {}
        for layer in layers:
            for key, value in _nonempty(layer).items():
                if key in declared and key not in resolved:
                    resolved[key] = value
        return resolved

    def _read_shared(self, name: str) -> Dict[str, str]:
        try:
            path = self.shared_file(name)
        except ValueError as exc:
            logger.warning("%s; no shared credentials for it", exc)
            return {}
        values = parse_env_file(path)
        if values:
            _warn_if_permissive(path)
        return values
