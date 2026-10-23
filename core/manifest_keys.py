# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Credential names a tool/MCP manifest declares.

Shared by the two places that must agree on the same manifest: central's
write-time validator (which rejects a blob that names an undeclared key, or a
variable), and the edge's environment allowlist (which decides what a child
process may see). They previously carried separate copies of the flattening
rules; a drift between them would mean central accepts a key the edge never
exports, or the edge reads one central would have refused.

Deliberately dependency-free: the edge imports this and must not pull the
etcd-backed modules into its process.
"""

from __future__ import annotations

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
