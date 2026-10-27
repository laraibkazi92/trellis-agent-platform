# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Split a container's environment into *container config* and a *stdin preamble*.

``docker inspect`` shows a container's configured environment to anyone who can talk
to the daemon (and to anyone reading a support dump). Secrets therefore never go
into it: the runner starts every command through ``/usr/local/bin/trellis-exec``,
which reads ONE first stdin line ``{"env": {"NAME": "value", ...}}``, merges it into
the process environment and ``exec``s the real command. Everything after that
newline is the call's own stdin (tool JSON, MCP stdio frames) and reaches the child
byte for byte.

This module is the ONE place that decides which names a container's configuration
may carry. The rule is allowlist-only and deliberately tiny:

* the process needs a handful of fixed variables before it can start at all
  (``PATH`` to find the interpreter, ``HOME``/``TMPDIR`` for its scratch dirs,
  locale and zone), and
* the caller's identity (``TRELLIS_USER_*``) is not a secret and is part of the
  documented tool contract.

Everything else -- resolved secrets, declared ``variables``, sealed edge credentials,
the manifest's literal ``env:`` block, per-call values -- travels in the preamble.

A name that *looks* like a credential (``SECRET``/``TOKEN``/``KEY``/``PASSWORD``/...)
is refused by the allowlist even if someone adds it there by mistake: the split is
fail-closed in both directions, so an operator secret cannot become container
configuration through a typo in this file.
"""

import json
import logging
import re
from typing import Any, Mapping, Optional

logger = logging.getLogger(__name__)

# Absolute path of the shim inside the engine image (and every derived image).
# ``Dockerfile`` installs it there; see ``docker/trellis-exec``.
EXEC_SHIM = "/usr/local/bin/trellis-exec"

# The complete set of names a container's *configuration* may carry. Adding a name
# here means "this is public, fixed deployment information, and the process may need
# it before it has read a single byte of stdin".
CONTAINER_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Process basics: without PATH the shim cannot find a relative command.
        "HOME",
        "PATH",
        "TMPDIR",
        "TMP",
        "TEMP",
        # Locale / zone: fixed deployment values, not per-call state.
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TERM",
        # Interpreter behaviour (tools write JSON to stdout; buffering breaks them).
        "PYTHONUNBUFFERED",
        # CA bundles: file paths, never key material.
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        # Documented tool contract: the caller the verified token proves.
        "TRELLIS_USER_ID",
        "TRELLIS_USER_EMAIL",
        # Run-scoped container identity: the console spec emits it today, and the
        # workflow containers (v0.7.1 Phase 6) will emit it too. An opaque id, not
        # a credential.
        "TRELLIS_RUN_ID",
    }
)

# Substrings that make a name credential-shaped. Matched case-insensitively, so a
# name is refused regardless of how it is spelled.
_SECRETISH_MARKERS = (
    "SECRET",
    "TOKEN",
    "KEY",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE",
)

_SECRETISH = re.compile("|".join(_SECRETISH_MARKERS), re.IGNORECASE)

# What a process environment can actually carry (and what the shim accepts).
_VALID_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# ``trellis-exec`` refuses the whole preamble line (exit 78) on a name outside
# ``_VALID_ENV_NAME`` or a value containing NUL, which would take every *valid*
# credential of the call down with it. Manifests are validated where they are
# parsed (``core.models``) and again at the runner boundary (``core.execution.spec``);
# the drops below are the last-resort net for values that bypass both.
INVALID_ENV_NAME_HELP = "expected ^[A-Za-z_][A-Za-z0-9_]*$"


def is_valid_env_name(name: object) -> bool:
    """True when ``name`` can be a process environment variable name."""
    return bool(_VALID_ENV_NAME.match(str(name)))


def invalid_env_names(names) -> list[str]:
    """The names that cannot exist in a process environment, sorted and deduped."""
    return sorted({str(name) for name in names if not is_valid_env_name(name)})


def declared_names(value: Any) -> list[str]:
    """Flatten one declared ``secrets``/``variables`` field into env key names.

    ``secrets``/``variables`` accept a flat list *or* the documented
    ``{general: [...], user: [...], background: [...]}`` mapping (see
    ``core.discovery._resolve_requirements``). The env names are the leaves in
    both forms -- never the mapping keys.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        names: list[str] = []
        for nested in value.values():
            names.extend(declared_names(nested))
        return names
    try:
        return [str(name) for name in value]
    except TypeError:
        return []


def is_secretish(name: str) -> bool:
    """True when a variable name is credential-shaped and must stay out of the config."""
    return bool(_SECRETISH.search(str(name)))


def is_container_env(name: str) -> bool:
    """True when ``name`` may appear in a container's configured environment."""
    return str(name) in CONTAINER_ENV_ALLOWLIST and not is_secretish(name)


def container_env(env: Mapping[str, str]) -> dict[str, str]:
    """The non-secret, allowlisted part of ``env`` (what Docker may see).

    Values are returned unchanged; nothing is coerced, so a caller cannot smuggle a
    secret in by name alone.
    """
    return {
        str(key): str(value)
        for key, value in env.items()
        if value is not None and is_container_env(key)
    }


def preamble_env(env: Mapping[str, str]) -> dict[str, str]:
    """Everything the process must still receive, minus the container's own config.

    Secrets, declared variables, sealed credentials and per-call values land here.
    """
    return {
        str(key): str(value)
        for key, value in env.items()
        if value is not None and not is_container_env(key)
    }


def split_env(env: Mapping[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """``(container_env, preamble_env)`` -- sorted keys, so a payload is reproducible."""
    return (
        dict(sorted(container_env(env).items())),
        dict(sorted(preamble_env(env).items())),
    )


def preamble_line(values: Optional[Mapping[str, str]] = None) -> bytes:
    """The one stdin line the shim consumes: ``{"env": {...}}\\n``.

    ``json.dumps`` escapes newlines inside a value, so this is always exactly one
    line; keys are sorted for a deterministic payload. Values are never logged.
    An empty mapping still produces a line -- the shim always reads one.

    Two kinds of entry are dropped with a WARNING naming them, because the shim
    rejects the whole line (exit ``78``) otherwise and takes every *valid*
    credential of the tool down with it -- each is a manifest bug, and the names
    are all that is ever logged:

    * a name a process environment cannot carry (``my-secret``);
    * a value containing NUL, which no process environment can carry either.

    Both are validated earlier (``core.models`` at manifest load,
    ``core.execution.spec`` at the runner boundary); this is the net for anything
    that bypasses those paths.
    """
    variables = {
        str(key): str(value)
        for key, value in (values or {}).items()
        if value is not None
    }
    dropped = invalid_env_names(variables)
    if dropped:
        logger.warning(
            "dropping env name(s) a process environment cannot carry: %s (%s)",
            ", ".join(dropped),
            INVALID_ENV_NAME_HELP,
        )
        for name in dropped:
            variables.pop(name, None)
    unrepresentable = sorted(name for name, value in variables.items() if "\x00" in value)
    if unrepresentable:
        logger.warning(
            "dropping env value(s) containing a NUL byte, which no process "
            "environment can carry: %s",
            ", ".join(unrepresentable),
        )
        for name in unrepresentable:
            variables.pop(name, None)
    return json.dumps(
        {"env": dict(sorted(variables.items()))}, separators=(",", ":")
    ).encode("utf-8") + b"\n"


def with_preamble(values: Optional[Mapping[str, str]], payload: bytes) -> bytes:
    """Prefix ``payload`` with the preamble line: one write, then the call's own bytes."""
    return preamble_line(values) + payload
