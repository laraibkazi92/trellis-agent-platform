# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Provider-facing root-union normalization for MCP tool input schemas (v0.5.0 Phase 6).

Pins the §5 spike finding: for a root object with no `properties` but a `oneOf`/`anyOf`,
the Gemini API **drops the parameter schema entirely** -- the tool is advertised with no
arguments, calls arrive as `{}`, and the action argument is silently lost. Nothing
raises, so these tests assert the schema itself (what `Tool.from_schema` receives), not
an error.

The catalog-side contract is the mirror image: wire catalogs, the registry and the
gateway keep the server's schema verbatim, so untouched schemas must come back
byte-identical and no input may ever be mutated.
"""

import copy
import json

import pytest

from core.mcp_schema import UNION_PROVIDERS, normalize_schema_for_provider


# --- fixtures ----------------------------------------------------------------


def meta_schema(keyword: str = "oneOf") -> dict:
    """The workload's meta-tool shape: one action branch per verb, plus `list_actions`."""
    return {
        "type": "object",
        keyword: [
            {
                "properties": {
                    "action": {"const": "get_value"},
                    "id": {"type": "integer"},
                },
                "required": ["action", "id"],
            },
            {
                "properties": {
                    "action": {"const": "set_value"},
                    "id": {"type": "integer"},
                    "value": {"type": "string"},
                },
                "required": ["action", "id", "value"],
            },
            {
                "properties": {"action": {"const": "list_actions"}},
                "required": ["action"],
            },
        ],
    }


def encoded(schema) -> str:
    return json.dumps(schema, sort_keys=True)


def flatten(schema: dict, provider: str = "google") -> dict:
    return normalize_schema_for_provider(provider, schema)


# --- 1. the measured failure: google + root union ---------------------------


def test_google_flattens_root_oneof_into_patchable_properties():
    flattened = flatten(meta_schema("oneOf"))

    assert "oneOf" not in flattened
    assert flattened["type"] == "object"
    assert set(flattened["properties"]) == {"action", "id", "value"}
    # Intersection of {"action","id"}, {"action","id","value"}, {"action"}.
    assert flattened["required"] == ["action"]
    # First branch wins: the earlier spec for a repeated key is the one that survives.
    assert flattened["properties"]["action"] == {"const": "get_value"}


def test_flattened_schema_is_consumable_as_a_plain_object():
    """A strict provider needs `properties` at the root and no root union keyword."""
    flattened = flatten(meta_schema())

    assert isinstance(flattened["properties"], dict)
    assert flattened["properties"]
    assert not ({"oneOf", "anyOf"} & set(flattened))
    # Never invent a required key: every required name must exist in `properties`.
    assert set(flattened.get("required", [])) <= set(flattened["properties"])


def test_anyof_behaves_exactly_like_oneof():
    assert flatten(meta_schema("anyOf")) == flatten(meta_schema("oneOf"))
    assert "anyOf" not in flatten(meta_schema("anyOf"))


def test_required_intersection_keeps_first_branch_order():
    schema = {
        "type": "object",
        "oneOf": [
            {"properties": {"b": {}, "a": {}, "c": {}}, "required": ["b", "a", "c"]},
            {"properties": {"c": {}, "a": {}, "b": {}}, "required": ["a", "c"]},
        ],
    }

    assert flatten(schema)["required"] == ["a", "c"]


def test_conflicting_required_names_drop_the_key_entirely():
    schema = {
        "type": "object",
        "oneOf": [
            {"properties": {"a": {}, "b": {}}, "required": ["a"]},
            {"properties": {"a": {}, "b": {}}, "required": ["b"]},
        ],
    }

    flattened = flatten(schema)

    assert "required" not in flattened
    assert set(flattened["properties"]) == {"a", "b"}


def test_other_root_keys_survive_flattening():
    schema = {
        "type": "object",
        "description": "Account tools.",
        "additionalProperties": False,
        "$defs": {"filter": {"type": "string"}},
        "properties": {"timeout": {"type": "integer"}},
        "oneOf": [
            {"properties": {"action": {"const": "a"}}, "required": ["action"]},
            {"properties": {"action": {"const": "b"}}, "required": ["action", "timeout"]},
        ],
    }

    flattened = flatten(schema)

    assert flattened["description"] == "Account tools."
    assert flattened["additionalProperties"] is False
    assert flattened["$defs"] == {"filter": {"type": "string"}}
    # Root-declared properties are kept, and branches only add to them.
    assert set(flattened["properties"]) == {"timeout", "action"}
    assert flattened["required"] == ["action"]


# --- 2. untouched providers and untouched schemas ---------------------------


@pytest.mark.parametrize("provider", ["openai", "anthropic", "ollama", "unknown", "", None])
def test_non_union_providers_get_the_schema_back_unchanged(provider):
    schema = meta_schema()
    before = encoded(schema)

    result = normalize_schema_for_provider(provider, schema)

    assert result is schema
    assert encoded(result) == before


def test_union_providers_is_google_only():
    assert UNION_PROVIDERS == frozenset({"google"})


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]},
        {"type": "object"},
        {},
        {"type": "object", "properties": {"nested": {"oneOf": [{"type": "string"}]}}},
    ],
)
def test_google_without_a_root_union_is_unchanged(schema):
    before = encoded(schema)

    result = flatten(schema)

    assert encoded(result) == before
    assert result is schema


# --- 3. nested unions are preserved verbatim --------------------------------


def test_google_preserves_nested_unions_inside_properties_and_defs():
    nested_property = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
    nested_defs = {"anyOf": [{"type": "string"}, {"type": "null"}]}
    schema = {
        "type": "object",
        "$defs": {"value": nested_defs},
        "oneOf": [
            {
                "properties": {"action": {"const": "set"}, "value": nested_property},
                "required": ["action"],
            },
            {
                "properties": {"action": {"const": "get"}, "value": nested_property},
                "required": ["action"],
            },
        ],
    }

    flattened = flatten(schema)

    assert "oneOf" not in flattened
    assert flattened["properties"]["value"] == nested_property
    assert flattened["$defs"] == {"value": nested_defs}


# --- 4. degenerate branches -------------------------------------------------


def test_branches_without_properties_contribute_nothing_but_their_required():
    schema = {
        "type": "object",
        "oneOf": [
            {"required": ["action"]},
            {"properties": {"action": {"const": "list_actions"}}, "required": ["action"]},
        ],
    }

    flattened = flatten(schema)

    assert flattened["properties"] == {"action": {"const": "list_actions"}}
    assert flattened["required"] == ["action"]


def test_non_dict_branches_are_ignored_without_raising():
    schema = {
        "type": "object",
        "oneOf": [
            "not-a-schema",
            7,
            None,
            {"properties": {"action": {"const": "go"}}, "required": ["action"]},
        ],
    }

    flattened = flatten(schema)

    assert flattened["properties"] == {"action": {"const": "go"}}
    assert flattened["required"] == ["action"]


def test_empty_union_list_is_returned_untouched():
    schema = {"type": "object", "oneOf": []}

    result = flatten(schema)

    assert result == schema
    assert result is schema


def test_a_union_without_any_properties_is_returned_unchanged():
    """`$ref`/empty branches: flattening would drop the union and gain nothing.

    The provider then rejects the schema loudly instead of us silently discarding
    every branch, and L6 stays trivially honest because nothing changed.
    """
    schema = {"type": "object", "oneOf": [{"required": ["action"]}]}

    assert flatten(schema) == schema


# --- 5. no mutation, ever ---------------------------------------------------


@pytest.mark.parametrize("provider", ["google", "openai", None])
@pytest.mark.parametrize("keyword", ["oneOf", "anyOf"])
def test_input_is_never_mutated(provider, keyword):
    schema = meta_schema(keyword)
    before = copy.deepcopy(schema)

    normalize_schema_for_provider(provider, schema)

    assert schema == before


def test_result_shares_no_mutable_structure_with_the_input():
    """The flattened copy goes to a third-party SDK; the original is still the verbatim
    catalog entry, so a provider-side rewrite must not reach the registry copy."""
    schema = meta_schema()

    flattened = flatten(schema)
    flattened["properties"]["action"]["const"] = "mutated"
    flattened["properties"]["injected"] = {}

    assert schema["oneOf"][0]["properties"]["action"] == {"const": "get_value"}
    assert "injected" not in schema["oneOf"][0]["properties"]


# --- 6. the workload-size schema -------------------------------------------


def test_large_root_union_flattens_without_losing_a_branch_property():
    branches = []
    for branch_index in range(26):
        branches.append(
            {
                "properties": {
                    "action": {"const": f"action_{branch_index}", "type": "string"},
                    **{
                        f"param_{branch_index}_{i}": {
                            "type": "string",
                            "description": f"branch {branch_index} parameter {i} description",
                        }
                        for i in range(15)
                    },
                },
                "required": ["action", f"param_{branch_index}_0"],
            }
        )
    schema = {"type": "object", "oneOf": branches}
    assert 20_000 < len(encoded(schema)) < 40_000  # ~26 KB, the workload's peak

    flattened = flatten(schema)

    assert "oneOf" not in flattened
    # 26 branches x 15 params, plus the shared discriminator (first-wins).
    assert len(flattened["properties"]) == 26 * 15 + 1
    assert flattened["required"] == ["action"]
    assert encoded(flattened).count('"type": "string"') == 26 * 15 + 1


# --- 7. silent-loss regressions ---------------------------------------------


def test_a_root_required_key_survives_flattening():
    """A shared discriminator required at the root must not be dropped."""
    schema = {
        "type": "object",
        "properties": {"tenant": {"type": "string"}},
        "required": ["tenant"],
        "oneOf": [
            {"properties": {"action": {"const": "a"}}, "required": ["action"]},
            {"properties": {"action": {"const": "b"}}, "required": ["action"]},
        ],
    }

    flattened = normalize_schema_for_provider("google", schema)

    assert flattened["required"] == ["tenant", "action"]
    assert flattened["properties"]["tenant"] == {"type": "string"}


def test_required_names_without_a_property_are_dropped():
    """A `required` name with no spec makes the provider converter drop everything."""
    schema = {
        "type": "object",
        "oneOf": [
            {"properties": {"action": {"const": "a"}}, "required": ["action", "ghost"]},
            {"properties": {"action": {"const": "b"}}, "required": ["action", "ghost"]},
        ],
    }

    flattened = normalize_schema_for_provider("google", schema)

    assert flattened["required"] == ["action"]
    assert "ghost" not in flattened["properties"]


def test_a_ref_only_union_is_left_verbatim():
    """`$ref` branches contribute no properties: keep the union instead of losing it."""
    schema = {
        "type": "object",
        "$defs": {"Get": {"type": "object", "properties": {"id": {"type": "integer"}}}},
        "oneOf": [{"$ref": "#/$defs/Get"}],
    }

    assert normalize_schema_for_provider("google", schema) == schema


@pytest.mark.parametrize("provider", ["Google", " GOOGLE ", "google"])
def test_the_provider_match_is_case_and_space_insensitive(provider):
    flattened = normalize_schema_for_provider(provider, meta_schema("oneOf"))

    assert "oneOf" not in flattened
