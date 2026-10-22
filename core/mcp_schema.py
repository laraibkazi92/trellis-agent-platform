# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Provider-facing normalization of MCP tool input schemas.

Measured in the v0.5.0 spike (``__plan_docs/v0.5.0-edge-mcp-export.md`` §5): the Gemini
API drops a parameter schema whose root object has no ``properties`` but carries a
``oneOf``/``anyOf``. The tool is then advertised with **no arguments** and the model's
calls arrive as ``{}`` -- silent argument loss, not an error. ``anyOf`` behaves exactly
the same, and adding ``properties`` *next to* a root union does not help: the root union
keyword is what the API converter refuses.

So a root union is flattened before it reaches ``Tool.from_schema``: ``properties`` is the
first-wins union across the branches and ``required`` is the intersection of the branches'
required lists (a key is only required when every branch requires it -- never invented).
Nested unions are left alone; the converter only drops the *root* one.

**Normalization is provider-facing only.** The edge wire catalog, the registry config,
tool-search cards and the gateway's MCP catalog keep the schema verbatim (L6): those
consumers speak JSON Schema/MCP, not a model API, and losing the union there would
throw away the discrimination the tool actually enforces.
"""

from __future__ import annotations

import copy

UNION_PROVIDERS: frozenset[str] = frozenset({"google"})

# Root keywords that make a provider drop a parameter schema. Checked in this fixed order
# so a (pathological) schema carrying both stays deterministic.
_ROOT_UNION_KEYWORDS = ("oneOf", "anyOf")


def normalize_schema_for_provider(provider: str | None, schema: dict) -> dict:
    """Return ``schema`` in a form ``provider`` can carry.

    Every provider outside :data:`UNION_PROVIDERS` gets the input object back unchanged
    (same object, not a copy) -- schemas are only rewritten where a limitation was
    measured, so nothing else regresses.

    For :data:`UNION_PROVIDERS`, a root-level non-empty ``oneOf``/``anyOf`` list is
    flattened into ``properties`` + ``required`` and the root keyword is dropped; every
    other root key (``type``, ``description``, ``additionalProperties``, ``$defs``, ...)
    is preserved, and unions nested inside a property, ``$defs`` or ``items`` are
    preserved verbatim. A schema with no root union is returned untouched.

    The input is never mutated and the result shares no mutable structure with it: the
    flat schema is handed to a third-party SDK, while the original object is the
    verbatim catalog entry the registry and gateway still publish.
    """
    if provider is None or not isinstance(schema, dict):
        return schema
    if str(provider).strip().lower() not in UNION_PROVIDERS:
        return schema

    for keyword in _ROOT_UNION_KEYWORDS:
        branches = schema.get(keyword)
        if isinstance(branches, list) and branches:
            return _flatten_root_union(schema, keyword)
    return schema


def _flatten_root_union(schema: dict, keyword: str) -> dict:
    flattened = copy.deepcopy(schema)
    branches = flattened.pop(keyword)

    properties = flattened.get("properties")
    if not isinstance(properties, dict):
        # A non-dict `properties` cannot be merged into; drop it rather than carry junk.
        flattened.pop("properties", None)
        properties = {}

    # First wins: an earlier branch's spec is the one the provider sees, which keeps the
    # result stable regardless of how the server ordered its branches.
    for branch in branches:
        if not isinstance(branch, dict):
            continue
        branch_properties = branch.get("properties")
        if not isinstance(branch_properties, dict):
            continue
        for name, spec in branch_properties.items():
            properties.setdefault(name, spec)

    if not properties:
        # `$ref`/`allOf` branches contribute no inline properties. Flattening would drop
        # the union and leave the schema just as unusable, so hand the original back and
        # let the provider reject it loudly instead of us silently losing the branches.
        return schema

    flattened["properties"] = properties

    # A key is required only if every branch that declares `required` lists it, and only
    # if it is a property we actually publish: a `required` name with no spec is another
    # way the provider converter drops the whole schema. Root-level `required` survives
    # too -- a hybrid schema (shared discriminator at the root, payload in the union) must
    # not lose it. Dropping a required key is recoverable (the MCP server validates);
    # inventing one is not.
    root_required = [
        name
        for name in flattened.get("required") or []
        if isinstance(name, str) and name in properties
    ] if isinstance(flattened.get("required"), list) else []
    required_sets = [
        [name for name in branch["required"] if isinstance(name, str) and name in properties]
        for branch in branches
        if isinstance(branch, dict) and isinstance(branch.get("required"), list)
    ]
    required = list(dict.fromkeys(root_required))
    if required_sets:
        # Order comes from the root plus the first declaring branch, so the flattened
        # schema reads like the server authored it. Only the branch half is intersected:
        # the root's claim is not a union branch's claim.
        branch_required = list(dict.fromkeys(required_sets[0]))
        for names in required_sets[1:]:
            allowed = set(names)
            branch_required = [name for name in branch_required if name in allowed]
        required = list(dict.fromkeys(required + branch_required))
    if required:
        flattened["required"] = required
    else:
        flattened.pop("required", None)

    return flattened
