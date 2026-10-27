# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge-local credential rules: the shared store plus the sealed per-user set.

Two sources hold a **secret**, and only one of them is central:

* ``secrets_dir`` (default ``edge-secrets``) -- one ``<tool-or-mcp>.env`` per exported
  item, for a service account every caller shares. Dotenv, mode 0600. This is the only
  non-sealed source for a declared secret: the process environment is **not** a
  fallback for one (v0.7.1), because a value in the edge container's env reaches every
  tool and every operator container inspection.
* a **sealed blob** -- per-user credentials the browser encrypted to this edge's
  public key (``core.edge_crypto``). Central stores ciphertext; only this process
  can open it, and only for the ``(site, kind, name, identity)`` the AAD binds.

``variables`` (endpoints) are the edge's own configuration, not a credential: they
come from the shared file and then the process environment, in every mode.

``credential_mode`` decides what happens **when the caller has no sealed set**; a
present one wins in *every* mode, because it is the caller's explicit per-user
statement and the edge never second-guesses it:

* ``shared`` (default): the shared file for secrets, shared file -> process env for
  variables.
* ``per_user``: the sealed set if the caller has one, else the same as ``shared``.
* ``per_user_required``: the sealed set **only**; nothing sealed for this caller is
  a hard refusal (``missing_credentials``) -- the call must not run at all.

One refusal is about *identity*, not credentials: ``per_user_required`` for an
email-less caller with **no blob** is refused with ``identity_incomplete`` before the
shared file is even looked at, because re-sealing cannot fix an identity. A blob that
*did* arrive is never refused for that reason: it was sealed to the caller's email, or
to their user id when they have none, so it is provably theirs and still opens.

The per-user set is all-or-nothing (plan §5 Phase 4 R8): once a blob is present, a
declared secret it omits stays missing and is never filled from the shared file.

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

# Dependency-free by construction (stdlib + ``core.agent_token``): importing the
# refusal code and message from here keeps the edge, the hub and the gateway on one
# spelling instead of three copies of a wire contract.
from core.caller_identity import IDENTITY_INCOMPLETE, identity_incomplete_error

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

# A dropped key name reaches a log line; cap it so a pathological line cannot flood it.
MAX_LOGGED_KEY_CHARS = 64

DEFAULT_SECRETS_DIR = Path("edge-secrets")

_EMAIL_SLUG_RE = re.compile(r"[^a-z0-9]+")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Credential filenames are derived from a tool/MCP name, which the loaders already
# validate; this second check is what keeps a hand-edited name from escaping the dir.
_SAFE_STEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_GROUP_OTHER_READABLE = 0o044

# One warning per file per process: a permissive shared file is worth saying once, not
# on every call. Tests clear this to re-assert the warning.
_WARNED_PERMISSIVE: set[str] = set()


class MissingCredentials(Exception):
    """No usable credentials for this caller; ``code`` becomes ``result.error.code``.

    Raised for two different problems, and the code says which: ``missing_credentials``
    when ``per_user_required`` has no sealed set for this caller (sealing one fixes it),
    ``identity_incomplete`` when an email-less caller has no set at all, so there is
    nothing to seal to (nothing the caller seals fixes it). The message is
    the exact string central surfaces to the agent: it names the identity and the site
    or export, never a value.
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


def parse_env_text(text: str, *, source: str = "") -> Dict[str, str]:
    """Parse ``KEY=VALUE`` lines defensively: never interpolate, never evaluate.

    Blank lines and ``#`` comments are skipped, an optional leading ``export `` (the
    common shell/dotenv form) is accepted, a line without ``=`` or with a name that is
    not a plain env identifier is ignored (a malformed line must not cost the rest of
    the file), ``KEY=`` parses as an empty value (the resolver treats that as unset),
    and one layer of matching quotes is stripped. Later duplicates win, which is what
    "re-set the key" means.

    A dropped name is logged (key name only, never the value): a silently ignored
    ``my-key=...`` looks exactly like a missing credential at call time. ``source``
    names the file in that line; without it the message still names the key.
    """
    values: Dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
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
            logger.warning(
                "%sline %d: dropping credential key %r -- not a valid environment "
                "variable name (expected ^[A-Za-z_][A-Za-z0-9_]*$)",
                f"{source}: " if source else "",
                number,
                key[:MAX_LOGGED_KEY_CHARS],
            )
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
    return parse_env_text(text, source=str(path))


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


def _caller_email(email: Optional[str]) -> str:
    """The caller's email as a non-empty string, or ``""`` when the identity has none."""
    return str(email or "").strip()


def _identity_incomplete(name: str, site: Optional[str]) -> MissingCredentials:
    """The refusal for ``per_user_required`` with no set and no email (v0.7.2 R7.1).

    The code and the wording come from ``core.caller_identity`` so the code stays one
    wire contract, and the caller is sent to their identity provider rather than to the
    seal form (which cannot help).
    """
    return MissingCredentials(
        identity_incomplete_error(f"export '{name}'", site or "unknown")["error"],
        code=IDENTITY_INCOMPLETE,
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
        means the caller has no blob). Its presence switches the per-user branch on, in
        **every** mode:

        * only declared **secret** names are taken, all-or-nothing -- a missing one is
          not filled from the shared file;
        * declared **variable** names still come from the shared file / process env,
          because an endpoint is edge configuration (plan §6 invariant 10).

        Without a blob, ``per_user_required`` fails closed and every other mode reads
        the shared file for **secrets** and the shared file then the process env for
        **variables**. The process environment is deliberately not a secret source
        (v0.7.1): it is visible to every tool in the container and to any operator
        inspecting it, so a declared secret comes from ``secrets_dir`` or is absent.

        Either way ``per_user_required`` **without a blob** needs the caller's email:
        nothing is sealed for an identity that never had one, and a mixed-up caller is
        sent to their identity provider rather than to the seal form. That refusal comes
        first -- see :func:`_identity_incomplete`. A blob that *did* arrive is not gated
        on the email: it is bound to this caller's email *or* their user id
        (``edge_secrets_central.sealed_identity``), so it opens either way. Side-effect
        free and synchronous: no directory is created, and the only log lines name files
        and keys.
        """
        declared = edge_env.declared_keys_for(config)
        resolved_mode = _mode(mode)
        variables = declared_variable_keys(config)

        # Identity before credentials (v0.7.2 R7.1). ``per_user_required`` with no blob
        # can only be satisfied by a set sealed for this caller, and nothing is sealed
        # for an identity with no subject -- so that IS the refusal, answered before the
        # ``missing_credentials`` path below, which would send the operator to re-seal a
        # key that cannot fix a missing address.
        #
        # A blob that arrived is the opposite case: it was decrypted above, so it is
        # bound to this very caller -- their email, else their user id. Gating it on the
        # email would refuse the one path that is provably theirs (a webhook run's
        # identity is the literal user id ``webhook`` and has no address by design).
        if (
            resolved_mode == "per_user_required"
            and sealed is None
            and not _caller_email(email)
        ):
            raise _identity_incomplete(name, site)

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

        # Shared file first for both halves; the process env is a source for the
        # declared *variables* only.
        layers = (
            self._read_shared(name),
            {key: os.environ[key] for key in variables if key in os.environ},
        )
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
