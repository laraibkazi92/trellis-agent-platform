# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The effective allowlist: reference forms, wildcards and classification.

Table-driven against the matrix in ``core/allowlist.py`` (and the plan's Phase 3
item 4), which is the server-side access-control decision the hub, the relay and the
runner all make. The last block pins that an ``AgentConfig.model_dump()`` (the way
the registry hands an agent to the hub) resolves identically to the raw dict.
"""

import pytest

from core.allowlist import CONSOLE_TOOLS, EMPTY, permits_mcp, permits_tool, resolve
from core.models import AgentConfig

EDGE_TOOL = "dc1__node_ssh"
CENTRAL_MCP_TOOL = "mcp__coralogix__t"
EDGE_MCP_TOOL = "mcp__dc1__devops-cli__t"


# --------------------------------------------------------------------------- #
# edge tool: exact `allowed_tools` entry only
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "allowed_tools,permitted",
    [
        ([EDGE_TOOL], True),
        ([EDGE_TOOL, "echo"], True),
        ([], False),
        (["node_ssh"], False),  # the bare name is not the site-qualified reference
        (["dc2__node_ssh"], False),  # another site
        (["dc1__node_ssh2"], False),
    ],
)
def test_edge_tool_is_granted_by_an_exact_allowed_tools_entry(allowed_tools, permitted):
    allowlist = resolve({"allowed_tools": allowed_tools})

    assert permits_tool(allowlist, EDGE_TOOL) is permitted


def test_edge_tool_is_never_implied_by_allowed_mcps():
    """`dc1__node_ssh` in `allowed_mcps` is an *MCP* grant, not a tool grant."""
    allowlist = resolve({"allowed_mcps": [EDGE_TOOL]})

    assert permits_tool(allowlist, EDGE_TOOL) is False
    # It is read as the (site, mcp) pair it is written like.
    assert permits_mcp(allowlist, "node_ssh", site="dc1") is True


# --------------------------------------------------------------------------- #
# central MCP tool: mcp__<server>__<tool>
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "config,permitted",
    [
        ({"allowed_tools": [CENTRAL_MCP_TOOL]}, True),
        ({"allowed_tools": ["t"]}, True),
        ({"allowed_mcps": ["coralogix"]}, True),
        ({"allowed_mcps": ["coralogix2"]}, False),
        ({"allowed_tools": ["mcp__coralogix2__t"]}, False),
        ({}, False),
    ],
)
def test_central_mcp_tool_grants(config, permitted):
    assert permits_tool(resolve(config), CENTRAL_MCP_TOOL) is permitted


# --------------------------------------------------------------------------- #
# edge MCP tool: mcp__<site>__<mcp>__<tool>
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "config,permitted",
    [
        ({"allowed_tools": [EDGE_MCP_TOOL]}, True),
        ({"allowed_tools": ["t"]}, True),
        ({"allowed_mcps": ["dc1__devops-cli"]}, True),
        ({"allowed_mcps": ["dc1__*"]}, True),
        ({"allowed_mcps": ["dc10__*"]}, False),  # prefix is not a prefix-match
        ({"allowed_mcps": ["devops-cli"]}, False),  # bare name is a central server
        ({"allowed_tools": ["mcp__dc10__devops-cli__t"]}, False),
        ({}, False),
    ],
)
def test_edge_mcp_tool_grants(config, permitted):
    assert permits_tool(resolve(config), EDGE_MCP_TOOL) is permitted


def test_wildcard_does_not_grant_another_tool_name_shape():
    allowlist = resolve({"allowed_mcps": ["dc1__*"]})

    assert permits_tool(allowlist, EDGE_MCP_TOOL) is True
    # A wildcard is not a tool-name wildcard: it only travels through the 4-part form.
    assert permits_tool(allowlist, EDGE_TOOL) is False
    assert permits_tool(allowlist, CENTRAL_MCP_TOOL) is False


# --------------------------------------------------------------------------- #
# console
# --------------------------------------------------------------------------- #


def test_console_names_are_classified_into_their_own_set():
    allowlist = resolve({"allowed_tools": ["echo", *sorted(CONSOLE_TOOLS)]})

    assert allowlist.console == CONSOLE_TOOLS
    assert "echo" in allowlist.tools
    for name in CONSOLE_TOOLS:
        assert permits_tool(allowlist, name) is True


def test_console_tool_requires_its_own_entry():
    allowlist = resolve({"allowed_tools": ["ls", "read_file"]})

    assert allowlist.console == frozenset({"ls", "read_file"})
    assert permits_tool(allowlist, "ls") is True
    assert permits_tool(allowlist, "execute") is False
    # A console name never doubles as an MCP server grant.
    assert permits_mcp(allowlist, "execute") is False


def test_execute_is_a_console_tool():
    allowlist = resolve({"allowed_tools": ["execute"]})

    assert allowlist.console == frozenset({"execute"})
    assert permits_tool(allowlist, "execute") is True


# --------------------------------------------------------------------------- #
# permits_mcp: central / edge / wildcard / site mismatch
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "config,mcp,site,permitted",
    [
        ({"allowed_mcps": ["coralogix"]}, "coralogix", None, True),
        ({"allowed_mcps": ["coralogix"]}, "coralogix2", None, False),
        ({"allowed_mcps": ["dc1__devops-cli"]}, "devops-cli", "dc1", True),
        ({"allowed_mcps": ["dc1__devops-cli"]}, "devops-cli", "dc2", False),
        ({"allowed_mcps": ["dc1__*"]}, "anything", "dc1", True),
        ({"allowed_mcps": ["dc1__*"]}, "anything", "dc2", False),
        ({"allowed_mcps": ["dc1__*"]}, "anything", None, False),
        # A bare central server name does not authorize the same name on a site.
        ({"allowed_mcps": ["devops-cli"]}, "devops-cli", "dc1", False),
        ({"allowed_mcps": ["devops-cli"]}, "devops-cli", None, True),
        # A bare tool grant does not imply its whole server.
        ({"allowed_tools": ["t"]}, "coralogix", None, False),
        ({"allowed_tools": [CENTRAL_MCP_TOOL]}, "coralogix", None, False),
        ({}, "coralogix", None, False),
    ],
)
def test_permits_mcp(config, mcp, site, permitted):
    assert permits_mcp(resolve(config), mcp, site=site) is permitted


# --------------------------------------------------------------------------- #
# empty / malformed input
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("config", [None, {}, {"allowed_tools": [], "allowed_mcps": []}])
def test_empty_config_resolves_to_an_empty_allowlist(config):
    allowlist = resolve(config)

    assert allowlist == EMPTY
    assert allowlist.empty() is True


@pytest.mark.parametrize("config", [["not", "a", "mapping"], "string", 7])
def test_non_mapping_agent_config_does_not_raise(config):
    assert resolve(config) == EMPTY


def test_malformed_list_types_are_read_not_rejected():
    # A single string is the one-element list an operator meant to write.
    assert resolve({"allowed_tools": "echo"}).tools == frozenset({"echo"})
    # A mapping is read by key (the YAML-dict mistake).
    assert resolve({"allowed_tools": {"echo": True, "ls": None}}).tools == frozenset(
        {"echo", "ls"}
    )
    # Non-iterable / mixed junk degrades to "no grant" instead of raising.
    assert resolve({"allowed_tools": 42, "allowed_mcps": 42}).empty() is True
    assert resolve({"allowed_mcps": [None]}).mcps == frozenset({"None"})
    assert resolve({"allowed_mcps": [""]}).mcps == frozenset()


def test_permits_tool_rejects_an_empty_reference():
    assert permits_tool(resolve({"allowed_tools": [""]}), "") is False


# --------------------------------------------------------------------------- #
# registry round trip
# --------------------------------------------------------------------------- #

RAW = {
    "allowed_tools": ["echo", "execute", "ls", CENTRAL_MCP_TOOL, "t", EDGE_MCP_TOOL],
    "allowed_mcps": ["coralogix", "dc1__devops-cli", "dc1__*"],
}

REFERENCES = [
    "echo",
    "execute",
    "ls",
    "grep",
    EDGE_TOOL,
    CENTRAL_MCP_TOOL,
    EDGE_MCP_TOOL,
    "mcp__coralogix__other",
    "mcp__dc1__other-mcp__t",
    "mcp__dc2__devops-cli__t",
]


def test_agent_config_model_dump_resolves_like_the_raw_dict():
    dumped = AgentConfig(name="agent-a", **RAW).model_dump()

    assert resolve(dumped) == resolve(RAW)
    for reference in REFERENCES:
        assert permits_tool(resolve(dumped), reference) is permits_tool(resolve(RAW), reference)
    for mcp, site in (("coralogix", None), ("devops-cli", "dc1"), ("devops-cli", "dc2")):
        assert permits_mcp(resolve(dumped), mcp, site=site) is permits_mcp(
            resolve(RAW), mcp, site=site
        )
