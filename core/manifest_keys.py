# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Name rules a tool/MCP manifest declares, shared by every reader of it.

Credential names first: central's write-time validator (which rejects a blob that
names an undeclared key, or a variable), the edge's environment allowlist (which
decides what a child process may see) and the sync's manifest check all read these.
They previously carried separate copies of the flattening rules; a drift between
them would mean central accepts a key the edge never exports, or the edge reads one
central would have refused.

It also holds the HTTP field-name rule for an MCP's literal ``env:`` block on a
non-stdio transport (``invalid_header_entries``), for the same reason: the sync
refuses such a manifest, and any downstream linter validating the same file must
refuse exactly the same ones.

Deliberately dependency-free: the edge imports this and must not pull the
etcd-backed modules into its process.
"""

from __future__ import annotations

import re
from typing import Any, List, Mapping, Tuple

# ``secrets:`` is either a flat list or a ``{general, user, background}`` mapping
# (plan G5). The edge has no user/background distinction, so every bucket counts
# as declared there; central applies the same flattening and then only separates
# variables, which are never per-user material.
_SECRET_BUCKETS = ("general", "user", "background")


def _get(config: Any, attr: str) -> Any:
    if isinstance(config, Mapping):
        return config.get(attr)
    return getattr(config, attr, None)


def _flatten(value: Any) -> List[str]:
    if isinstance(value, Mapping):
        keys: List[str] = []
        for bucket in _SECRET_BUCKETS:
            keys.extend(value.get(bucket) or [])
        return [key for key in keys if isinstance(key, str) and key]
    if isinstance(value, (list, tuple)):
        return [key for key in value if isinstance(key, str) and key]
    return []


def _group_keys(config: Any) -> List[str]:
    """Keys of every option in ``secret_groups`` (the /configuration selector)."""
    keys: List[str] = []
    for group in _get(config, "secret_groups") or []:
        if not isinstance(group, Mapping):
            continue
        for option in group.get("options") or []:
            if not isinstance(option, Mapping):
                continue
            for field in option.get("fields") or []:
                if isinstance(field, Mapping) and isinstance(field.get("key"), str):
                    keys.append(field["key"])
    return keys


def declared_keys(config: Any) -> Tuple[List[str], List[str]]:
    """``(secret_keys, variable_keys)`` from one manifest, sorted.

    Secret-group field keys count as secrets: they are credentials the user types,
    and the edge's manifest check intersects them like any other declared key. A
    name that appears in both lists is treated as a variable -- the stricter
    reading, because a variable is shared edge config and must never be filled
    from a per-user blob.
    """
    if config is None:
        return [], []

    secret_keys = (
        _flatten(_get(config, "secrets"))
        + _flatten(_get(config, "optional_secrets"))
        + _group_keys(config)
    )
    variable_keys = _flatten(_get(config, "variables"))
    variables = set(variable_keys)
    return sorted({key for key in secret_keys if key not in variables}), sorted(variables)


def all_declared(config: Any) -> set:
    """Every declared name, secrets and variables alike (the edge's view)."""
    secret_keys, variable_keys = declared_keys(config)
    return set(secret_keys) | set(variable_keys)


# An MCP's literal ``env:`` block is a *header map* on every transport but stdio
# (``core/agent_factory``, ``core/proxy_mcp._http_headers``, the sync's discovery
# probe), so its keys follow the HTTP field-name grammar, not the env-name one:
# ``mcp-version`` and ``X-Api-Key`` are perfectly good headers and perfectly bad
# environment variables. RFC 7230 token.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

# What a header value may never carry: a line break ends the field (request
# splitting), and NUL is not representable in an HTTP field value at all.
_HEADER_VALUE_FORBIDDEN = ("\r", "\n", "\x00")

# ``env:`` is a header map on these transports. ``remote`` is a registry pointer
# written by the edge relay, so it carries none -- validating it as headers only
# keeps a malformed one from being stored.
HEADER_TRANSPORTS = frozenset({"http", "streamable-http", "sse", "remote"})


def is_header_name(name: Any) -> bool:
    """True when ``name`` is a syntactically valid HTTP header field-name."""
    return bool(_HEADER_NAME_RE.match(str(name)))


def invalid_header_entries(mapping: Any) -> List[str]:
    """Header names from ``mapping`` that cannot be sent, sorted and deduped.

    A name outside the field-name grammar and a name whose value carries CR, LF or
    NUL are both refused: the first makes the request unbuildable, the second is a
    header-injection hole. A non-mapping is the caller's business (only the caller
    knows what an absent ``env:`` means).
    """
    if not isinstance(mapping, Mapping):
        return []
    bad = set()
    for key, value in mapping.items():
        if not is_header_name(key) or any(
            mark in str(value) for mark in _HEADER_VALUE_FORBIDDEN
        ):
            bad.add(str(key))
    return sorted(bad)
