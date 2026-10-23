# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The agent's *effective* allowlist, resolved server-side at call time.

`allowed_tools` and `allowed_mcps` used to be a registration filter: the agent
runtime decided what to expose and nothing downstream re-checked. From v0.6 they
are an access-control decision: the hub (local tools), the relay (edge tools and
MCPs) and the runner (sessions/console) resolve them themselves from the agent
record they own.

Reference forms (same grammar as ``core.models``):

| Reference | Granted by |
|---|---|
| ``dc1__node_ssh`` (edge tool) | exact ``tools`` entry only |
| ``mcp__coralogix__t`` (central MCP tool) | the 3-part name or ``t`` in ``tools``, or ``coralogix`` in ``mcps`` |
| ``mcp__dc1__devops-cli__t`` (edge MCP tool) | the 4-part name or ``t`` in ``tools``, or ``dc1__devops-cli`` in ``mcps``, or ``dc1__*`` in ``wildcards`` |
| ``execute`` / console names | name in ``console`` |

Wildcards expand against the *live* registry, never a build-time snapshot: a
wildcard is stored unexpanded and checked per call.
"""

from dataclasses import dataclass
from typing import Any, Mapping, Optional

CONSOLE_TOOLS = frozenset({"ls", "read_file", "write_file", "edit_file", "glob", "grep", "execute"})


@dataclass(frozen=True)
class EffectiveAllowlist:
    tools: frozenset[str]
    mcps: frozenset[str]
    wildcards: frozenset[str]
    console: frozenset[str]

    def empty(self) -> bool:
        return not (self.tools or self.mcps or self.wildcards)


EMPTY = EffectiveAllowlist(frozenset(), frozenset(), frozenset(), frozenset())


def _names(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, Mapping):
        return [str(key).strip() for key in value if str(key).strip()]
    try:
        return [str(item).strip() for item in value if str(item).strip()]
    except TypeError:
        return []


def resolve(agent_config: Optional[Mapping[str, Any]]) -> EffectiveAllowlist:
    """Build the allowlist from an agent record (etcd dict or AgentConfig dump)."""
    config = agent_config or {}
    tools = set()
    console = set()
    for name in _names(config.get("allowed_tools") if isinstance(config, Mapping) else None):
        tools.add(name)
        if name in CONSOLE_TOOLS:
            console.add(name)
    mcps = set()
    wildcards = set()
    for name in _names(config.get("allowed_mcps") if isinstance(config, Mapping) else None):
        if name.endswith("__*"):
            wildcards.add(name)
        else:
            mcps.add(name)
    return EffectiveAllowlist(
        frozenset(tools), frozenset(mcps), frozenset(wildcards), frozenset(console)
    )


def _segments(reference: str) -> list[str]:
    return reference.split("__")


def permits_tool(allowlist: EffectiveAllowlist, reference: str) -> bool:
    """Does the agent's allowlist grant this tool reference?"""
    if not reference:
        return False
    if reference in allowlist.tools:
        return True
    if reference in allowlist.console:
        return True

    parts = _segments(reference)
    if parts[0] == "mcp" and len(parts) == 3:
        # mcp__<central-server>__<tool>
        server, tool = parts[1], parts[2]
        return server in allowlist.mcps or tool in allowlist.tools
    if parts[0] == "mcp" and len(parts) == 4:
        # mcp__<site>__<mcp>__<tool>
        site, mcp, tool = parts[1], parts[2], parts[3]
        edge_mcp = f"{site}__{mcp}"
        return (
            edge_mcp in allowlist.mcps
            or f"{site}__*" in allowlist.wildcards
            or tool in allowlist.tools
        )
    # A bare tool name in `allowed_tools` grants that tool everywhere it appears
    # (this is how a workspace tool name has always been written).
    if reference in allowlist.tools:
        return True
    return False


def permits_mcp_session(
    allowlist: EffectiveAllowlist, mcp: str, site: Optional[str] = None
) -> bool:
    """May the agent open a session for this MCP server?

    A session is the transport for every tool of that server, so either the server
    grant or *any* per-tool grant for it is enough. Requiring the server grant would
    silently break the documented ``allowed_tools: [mcp__server__tool]`` narrowing.
    """
    if permits_mcp(allowlist, mcp, site=site):
        return True
    name = f"{site}__{mcp}" if site else mcp
    prefix = f"mcp__{name}__"
    return any(entry.startswith(prefix) for entry in allowlist.tools)


def permits_mcp(
    allowlist: EffectiveAllowlist, mcp: str, site: Optional[str] = None
) -> bool:
    """Does the agent's allowlist grant this MCP server (edge or central)?"""
    name = f"{site}__{mcp}" if site else mcp
    if name in allowlist.mcps:
        return True
    if site and f"{site}__*" in allowlist.wildcards:
        return True
    # A tool granted by bare name does not imply its whole server.
    return False
