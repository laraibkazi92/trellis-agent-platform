# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The public edge-MCP reference forms (v0.5.0 Phase 7 / L7).

``core.models`` publishes the documented manifest regexes (``docs/mcp.md``):

- ``EDGE_TOOL_REF_RE`` / ``EDGE_MCP_REF_RE`` -- ``<site>__<name>``
- ``EDGE_MCP_WILDCARD_RE`` -- ``<site>__*`` (``allowed_mcps`` sugar)
- ``EDGE_MCP_TOOL_REF_RE`` -- ``mcp__<site>__<mcp>__<tool>`` (4 parts, edge)
- ``CENTRAL_MCP_TOOL_REF_RE`` -- ``mcp__<server>__<tool>`` (3 parts, central)

These tests pin the shapes *and* the ambiguity property that makes them safe: because
no site/MCP/tool name may contain ``__``, a 4-part ``mcp__`` name is edge and a 3-part
one is central. ``core.discovery.resolve_edge_mcp_target`` is still the runtime
authority (it is registry-backed, so a central MCP whose tool name contains ``__`` stays
central) -- the regexes must agree with it, not replace it.
"""

import asyncio
from types import SimpleNamespace

import pytest

from core import discovery
from core.models import (
    CENTRAL_MCP_TOOL_REF_RE,
    EDGE_MCP_REF_RE,
    EDGE_MCP_TOOL_REF_RE,
    EDGE_MCP_WILDCARD_RE,
    EDGE_TOOL_REF_RE,
)
from services.edge_relay import protocol

SITE = "dc1"
MCP = "devops-cli"
TOOL = "tenant_account_tools"

MCP_KEY = f"{SITE}__{MCP}"
WILDCARD = f"{SITE}__*"
EDGE_TOOL_NAME = f"mcp__{SITE}__{MCP}__{TOOL}"
CENTRAL_TOOL_NAME = f"mcp__{MCP}__action"
# The same tool name without the `mcp__` prefix: 3 segments, not a 2-part ref.
UNPREFIXED_TOOL_NAME = f"{SITE}__{MCP}__{TOOL}"


@pytest.mark.parametrize("entry", [MCP_KEY, "dc1__tenant_account_tools", "a__b", "A_1__b-2"])
def test_edge_pair_refs_accept_the_documented_samples(entry):
    assert EDGE_MCP_REF_RE.fullmatch(entry)
    assert EDGE_TOOL_REF_RE.fullmatch(entry)


@pytest.mark.parametrize(
    "entry",
    [
        "dc1__",  # no name half
        "__x",  # no site half
        "dc1",  # no separator
        UNPREFIXED_TOOL_NAME,  # 3 segments: a 4-part tool name needs the `mcp__` prefix
        WILDCARD,  # the wildcard is its own form, never a real ref
        "dc 1__x",
        "dc1__has space",
        "dc1__dot.name",
        "dc1__.hidden",
    ],
)
def test_edge_pair_refs_reject_ambiguous_or_illegal_names(entry):
    assert EDGE_MCP_REF_RE.fullmatch(entry) is None
    assert EDGE_TOOL_REF_RE.fullmatch(entry) is None


def test_a_two_part_ref_does_not_read_a_four_part_tool_name():
    """`dc1__a__b` would otherwise be site `dc1` + mcp `a__b` -- and would make the
    2-part and 4-part forms overlap. Names are banned from `__`, so it is not a ref."""
    assert EDGE_MCP_REF_RE.fullmatch("dc1__a__b") is None
    assert EDGE_TOOL_REF_RE.fullmatch("dc1__a__b") is None
    # Same string is a valid 2-part *site__name* only when the trailing segments are
    # joined by something other than the reserved separator, e.g. a dash.
    assert EDGE_MCP_REF_RE.fullmatch("dc1__a-b") is not None


def test_edge_wildcard_form():
    assert EDGE_MCP_WILDCARD_RE.fullmatch(WILDCARD)
    assert EDGE_MCP_WILDCARD_RE.fullmatch("dc-1__*")


@pytest.mark.parametrize("entry", ["*", "__*", "dc1*", "dc1__*__x", "dc1__", "dc1__**", "dc 1__*"])
def test_edge_wildcard_rejects_malformed_entries(entry):
    assert EDGE_MCP_WILDCARD_RE.fullmatch(entry) is None


def test_the_wildcard_is_not_a_mcp_ref():
    """A wildcard must be recognised by its own form: treating it as a server name
    would make `allowed_mcps` look for a server literally called `dc1__*`."""
    assert EDGE_MCP_REF_RE.fullmatch(WILDCARD) is None
    assert EDGE_MCP_WILDCARD_RE.fullmatch(MCP_KEY) is None


def test_edge_mcp_tool_ref_accepts_the_four_part_name():
    assert EDGE_MCP_TOOL_REF_RE.fullmatch(EDGE_TOOL_NAME)


@pytest.mark.parametrize(
    "entry",
    [
        CENTRAL_TOOL_NAME,  # 3 parts: central
        "mcp__a__b__c__d",  # 5 parts
        "mcp__dc1____x",  # empty segment
        "mcp__dc1__devops-cli__",  # empty tool half
        "mcp__dc1____",  # empty mcp + tool
        UNPREFIXED_TOOL_NAME,  # missing `mcp__`
    ],
)
def test_edge_mcp_tool_ref_rejects_non_four_part_names(entry):
    assert EDGE_MCP_TOOL_REF_RE.fullmatch(entry) is None


def test_central_mcp_tool_ref_accepts_three_parts():
    assert CENTRAL_MCP_TOOL_REF_RE.fullmatch(CENTRAL_TOOL_NAME)
    assert CENTRAL_MCP_TOOL_REF_RE.fullmatch("mcp__example-mcp__list")


def test_central_and_edge_forms_are_mutually_exclusive():
    """The ambiguity proof: a name is never both a 4-part edge tool and a 3-part
    central tool. Without the `__` ban in the segment, `mcp__dc1__devops-cli__tool`
    would also parse as central server `dc1__devops-cli`."""
    assert EDGE_MCP_TOOL_REF_RE.fullmatch(EDGE_TOOL_NAME)
    assert CENTRAL_MCP_TOOL_REF_RE.fullmatch(EDGE_TOOL_NAME) is None

    assert CENTRAL_MCP_TOOL_REF_RE.fullmatch(CENTRAL_TOOL_NAME)
    assert EDGE_MCP_TOOL_REF_RE.fullmatch(CENTRAL_TOOL_NAME) is None


def test_the_split_rule_gives_the_same_answer_as_the_regexes():
    """Both runtime and regexes split on `__`; a regex match therefore has exactly the
    segment count the runtime's `parts[1]` / `parts[2]` reads assume."""
    assert EDGE_MCP_TOOL_REF_RE.fullmatch(EDGE_TOOL_NAME)
    parts = EDGE_TOOL_NAME.split("__")
    assert parts[:3] == ["mcp", SITE, MCP]
    assert "__".join(parts[3:]) == TOOL

    assert CENTRAL_MCP_TOOL_REF_RE.fullmatch(CENTRAL_TOOL_NAME)
    parts = CENTRAL_TOOL_NAME.split("__")
    assert parts[1] == MCP
    assert parts[2] == "action"


def test_a_central_tool_name_containing_the_separator_matches_the_edge_shape():
    """Phase 4 gotcha: `mcp__srv__do__thing` is legal for a central server whose tool is
    called `do__thing`, and it is shape-identical to an edge site `srv` / mcp `do`.
    That is exactly why the runtime split is registry-backed and the regexes are
    documentation/classification -- never a grant on their own."""
    central = "mcp__srv__do__thing"

    assert CENTRAL_MCP_TOOL_REF_RE.fullmatch(central) is None
    assert EDGE_MCP_TOOL_REF_RE.fullmatch(central) is not None
    # No `srv__do` remote entry -> the runtime reads it as central.
    assert resolve(central, {"srv": {"name": "srv", "secrets": []}}) is None
    # With the edge entry registered it is the edge reading.
    assert resolve(central, {"srv__do": _edge_config("srv", "do")}) == ("srv", "do", "thing")


@pytest.mark.parametrize(
    "entry",
    [f"{'a' * 64}__b", f"a__{'b' * 64}", f"mcp__{'a' * 64}__b__{'c' * 64}"],
)
def test_length_edges_at_the_64_char_cap_are_accepted(entry):
    assert EDGE_MCP_REF_RE.fullmatch(entry) or EDGE_MCP_TOOL_REF_RE.fullmatch(entry)


@pytest.mark.parametrize(
    "entry",
    [f"{'a' * 65}__b", f"a__{'b' * 65}", f"mcp__{'a' * 65}__b__c", f"mcp__a__b__{'c' * 65}"],
)
def test_length_edges_past_the_64_char_cap_are_rejected(entry):
    assert EDGE_MCP_REF_RE.fullmatch(entry) is None
    assert EDGE_TOOL_REF_RE.fullmatch(entry) is None
    assert EDGE_MCP_TOOL_REF_RE.fullmatch(entry) is None
    assert CENTRAL_MCP_TOOL_REF_RE.fullmatch(entry) is None


def test_uppercase_is_legal_and_letters_are_case_folded_into_names_not_regions():
    assert EDGE_MCP_REF_RE.fullmatch("DC1__DevOps-CLI")
    assert EDGE_MCP_TOOL_REF_RE.fullmatch("mcp__DC1__DevOps-CLI__Tool")
    # The separator is exactly two lowercase underscores; a name merely looks like it.
    assert EDGE_MCP_REF_RE.fullmatch("dc1__x") is not None


def test_a_segment_can_never_contain_the_separator():
    """`a__b` is a legal *pair* (site `a`, name `b`), but `__` can never appear inside one
    segment: the wildcard's site half is a single segment, so it rejects the string."""
    assert EDGE_MCP_REF_RE.fullmatch("a__b")
    assert EDGE_MCP_WILDCARD_RE.fullmatch("a__b__*") is None
    assert EDGE_MCP_REF_RE.fullmatch("dc1__a__b") is None


def test_a_segment_may_not_end_with_an_underscore():
    """Intentionally stricter than `NAME_RE` (documented in docs/mcp.md).

    `_` is a legal name character and a trailing one is a legal *name*, but inside a
    reference it makes the `__` boundary ambiguous: `a___b` reads as site `a_` + name `b`
    or as site `a` + name `_b`, so the ambiguous string is rejected outright and a
    segment can never end in `_`.
    """
    assert protocol.NAME_RE.match("a_")  # legal as a standalone published name
    assert EDGE_MCP_REF_RE.fullmatch("dc1__a_") is None
    assert EDGE_TOOL_REF_RE.fullmatch("dc1__a_") is None
    assert EDGE_MCP_WILDCARD_RE.fullmatch("a___*") is None
    assert EDGE_MCP_TOOL_REF_RE.fullmatch("mcp__dc1__devops-cli__tool_") is None
    assert EDGE_MCP_REF_RE.fullmatch("a___b") is None
    # An inner `_` is fine; it only has to be followed by a letter, digit or `-`.
    assert EDGE_MCP_REF_RE.fullmatch("dc1__tenant_account_tools")
    assert EDGE_MCP_REF_RE.fullmatch("dc1__a_-b")


def test_the_segment_pattern_is_one_to_sixty_four_characters():
    """The cap is 64 *characters*, not 64 repetitions: the old `{0,63}_?` form admitted
    128. Behavioural proof only -- the pattern string is free to change."""
    assert EDGE_MCP_REF_RE.fullmatch(f"dc1__{'a' * 64}")
    assert EDGE_MCP_REF_RE.fullmatch(f"dc1__{'a' * 65}") is None
    # 64 chars built from the two-character `_x` unit, and one more (65).
    assert EDGE_MCP_REF_RE.fullmatch("dc1__a" + "x_" * 31 + "x") is not None
    assert EDGE_MCP_REF_RE.fullmatch("dc1__a" + "x_" * 32) is None


# --- consistency with the runtime split (registry-backed) -----------------------


def _edge_config(site=SITE, mcp=MCP):
    """The relay-written config shape: `<site>__<mcp>` plus a `remote` block."""
    return {
        "name": f"{site}__{mcp}",
        "transport": "remote",
        "remote": {"site": site, "mcp": mcp},
        "managed_by": "edge-relay",
        "tools": [],
    }


def resolve(tool_name, configs):
    mgr = SimpleNamespace(get_mcp_config=lambda key: configs.get(key))
    return asyncio.run(discovery.resolve_edge_mcp_target(tool_name, mgr))


def test_four_part_name_resolves_to_the_edge_when_the_registry_says_so():
    assert EDGE_MCP_TOOL_REF_RE.fullmatch(EDGE_TOOL_NAME)

    assert resolve(EDGE_TOOL_NAME, {MCP_KEY: _edge_config()}) == (SITE, MCP, TOOL)


def test_three_part_name_resolves_to_central_even_when_its_server_is_registered():
    assert CENTRAL_MCP_TOOL_REF_RE.fullmatch(CENTRAL_TOOL_NAME)
    # `mcp__devops-cli__action` has no `<site>__<mcp>` key to look up: central.
    assert resolve(CENTRAL_TOOL_NAME, {MCP_KEY: _edge_config()}) is None


def test_a_matching_regex_alone_never_grants_an_edge_target():
    """The regex is documentation/classification, not authorization: with no registry
    entry the 4-part name stays central (and unresolved)."""
    assert EDGE_MCP_TOOL_REF_RE.fullmatch(EDGE_TOOL_NAME)
    assert resolve(EDGE_TOOL_NAME, {}) is None


def test_a_registered_central_server_with_the_same_prefix_stays_central():
    """`<site>__<mcp>` must carry a `remote` block; a central server named `dc1` is not
    an edge, whatever the 4-part name looks like."""
    assert resolve(EDGE_TOOL_NAME, {SITE: {"name": SITE, "secrets": []}}) is None
