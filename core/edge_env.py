# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge-only environment scoping for tools and MCP servers.

The hub builds a tool's env by *denylisting* the framework's own secrets out of
``os.environ`` -- it can afford to, because everything a tool needs is injected from
etcd afterwards. An edge has no store and no such authority, so the policy inverts:
a process sees a fixed base (process plumbing, locale, TLS trust, outbound proxy) plus
exactly the names its own ``tool.yaml``/``mcp.yaml`` declares. Whatever else an
operator left in the container env stays invisible.

Edge-only by design: nothing here imports ``services/`` and nothing touches etcd.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from core.env_sanitize import FRAMEWORK_SECRET_ENV, sanitized_env
from core.llm_providers import FRAMEWORK_PROVIDER_KEY_ENV

# The default enrollment-token variable. Named here (not in the proxy) so the
# stripping below is intrinsic: a caller that forgets to pass ``secret_env_names``
# still cannot hand the tunnel credential to a child process.
DEFAULT_TOKEN_ENV = "TRELLIS_EDGE_TOKEN"

# Framework-owned control-plane names that are never a legitimate tool input, in
# either mode. Provider API keys are deliberately excluded: an edge tool that calls
# an LLM declares one, and it must still arrive.
RESERVED_ENV_NAMES: frozenset[str] = FRAMEWORK_SECRET_ENV - FRAMEWORK_PROVIDER_KEY_ENV

# What any tool needs just to start. The caller prepends the tool's own ``bin/`` to
# PATH; the rest is process plumbing (HOME/TMPDIR for state, locale, CA bundle,
# outbound proxy).
BASE_ENV_KEYS: frozenset[str] = frozenset({
    "PATH",
    "HOME",
    "LANG",
    "TZ",
    "TMPDIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "path",
    "home",
    "lang",
    "tz",
    "tmpdir",
    "http_proxy",
    "https_proxy",
    "no_proxy",
})

# ``TRELLIS_*`` carries the framework's per-call context (caller identity, edge mode);
# ``LC_*`` is the POSIX way to override a single locale category.
BASE_ENV_PREFIXES: Tuple[str, ...] = ("LC_", "TRELLIS_")


def scoped_env(
    declared_keys: Iterable[str],
    *,
    passthrough: bool = False,
    secret_env_names: Iterable[str] = frozenset({DEFAULT_TOKEN_ENV}),
) -> Dict[str, str]:
    """The environment a tool or MCP server may see, as a fresh dict.

    ``passthrough`` restores the v0.4 denylist behaviour for an operator who cannot
    declare every key up front. ``secret_env_names`` and ``RESERVED_ENV_NAMES`` are
    stripped **last, in both modes**: ``TRELLIS_EDGE_TOKEN`` matches the ``TRELLIS_``
    prefix and would otherwise ride the allowlist into every child process.
    """
    if passthrough:
        env: Dict[str, str] = dict(sanitized_env())
    else:
        env = {
            key: value
            for key, value in os.environ.items()
            if key in BASE_ENV_KEYS or key.startswith(BASE_ENV_PREFIXES)
        }
        env.update({key: os.environ[key] for key in declared_keys if key in os.environ})

    for name in secret_env_names:
        env.pop(name, None)
    return strip_framework_names(env)


def strip_framework_names(
    env: Dict[str, str], *, token_env: Optional[str] = None
) -> Dict[str, str]:
    """Remove the tunnel credential and framework control-plane names, in place.

    ``scoped_env`` applies this to the process environment, but a credential file is
    a second source of names (``core.edge_user_secrets``) and a manifest may spell a
    literal ``env:`` value, so the same rule is re-applied after merging either. Both
    token names go: a mid-migration host can carry one under the default variable
    while ``token_env`` already points at another.
    """
    env.pop(DEFAULT_TOKEN_ENV, None)
    env.pop(token_env or DEFAULT_TOKEN_ENV, None)
    for name in RESERVED_ENV_NAMES:
        env.pop(name, None)
    # Porcelain case: an allowlisted key could still name a reserved variable.
    for key in list(env):
        if key.upper() in RESERVED_ENV_NAMES:
            env.pop(key, None)
    return env


def scoped_env_for(
    config: Any,
    *,
    passthrough: bool = False,
    token_env: Optional[str] = None,
) -> Dict[str, str]:
    """The scoped environment for one ``tool.yaml``/``mcp.yaml`` manifest.

    Single home for the rule ``core.proxy.build_env`` (tools) and the MCP session
    builder both need: the manifest's declared keys only, with **both** token names
    stripped -- a mid-migration host can carry a valid token under the default
    variable while ``token_env`` already points at another, so removing just the
    configured one would leak the other to every child process.
    """
    return scoped_env(
        declared_keys_for(config),
        passthrough=passthrough,
        secret_env_names={DEFAULT_TOKEN_ENV, token_env or DEFAULT_TOKEN_ENV},
    )


def declared_keys_for(config: Any) -> set[str]:
    """Every env name a ``tool.yaml``/``mcp.yaml`` declares it needs.

    The edge has no user/background distinction, so a dict-shaped declaration
    contributes every bucket: a key the hub would inject into either context is a key
    this manifest is allowed to read here. ``secret_groups`` are flattened to their
    underlying keys so an operator's chosen option is visible whatever it is called.

    The two helpers below mirror ``core/discovery`` (``_resolve_requirements`` and
    ``flatten_secret_group_keys``) instead of importing it: that module builds the
    etcd-backed ``IdentityManager`` at import time, which an edge process must never
    do -- the same reason this module duplicates rather than imports across the
    central/edge boundary.
    """
    if config is None:
        return set()

    def declared(attr: str) -> Any:
        if isinstance(config, Mapping):
            return config.get(attr)
        return getattr(config, attr, None)

    keys: set[str] = set()
    for attr in ("secrets", "optional_secrets", "variables"):
        value = declared(attr)
        if not value:
            continue
        keys.update(_declared(value))

    for group in declared("secret_groups") or []:
        for option in group.get("options", []):
            for field in option.get("fields", []):
                if isinstance(field, dict):
                    keys.add(field.get("key"))

    return {key for key in keys if isinstance(key, str) and key}


def _declared(requirement: Any) -> set[str]:
    """One declaration's key names: a list is literal, a dict spans every context."""
    if isinstance(requirement, list):
        return {key for key in requirement if isinstance(key, str)}
    if isinstance(requirement, dict):
        contexts = ("general", "user", "background")
        return {
            key
            for context in contexts
            for key in (requirement.get(context) or [])
            if isinstance(key, str)
        }
    return set()
