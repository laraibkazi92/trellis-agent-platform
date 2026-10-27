# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The in-process ("host") enforcement point: the running run asks the evaluator.

The runner only proves a token is genuine and unexpired; it has no registry and no
agent manifests, so it cannot decide whether an agent may open an MCP session or run
a console command. That decision belongs to the process that owns the agent runtime
(the host, the taskiq worker's agent runs) and happens here, *before* the runner is
asked for a container.

Identity and groups come from the run's agent token (claim ``"g"``) and nowhere else;
the allowlist comes from the agent record the token names. Denials are the stable
machine strings of :mod:`core.tool_access`, surfaced as the same ``SYSTEM: …`` /
``access_denied`` strings the tool seams already return to a model.
"""

import asyncio
import logging
from typing import Optional

from core import agent_token, allowlist, tool_access

logger = logging.getLogger(__name__)

# Reasons the token/allowlist rollout window (`ENFORCE_AGENT_TOKENS=log`) relaxes.
# The group-rule half always applies: it has its own switch (``TOOL_ACCESS_MODE``).
_ROLLOUT_REASONS = frozenset(
    {tool_access.REASON_NOT_IN_ALLOWLIST, tool_access.REASON_UNKNOWN_TARGET}
)


class ToolAccessDenied(PermissionError):
    """A pre-runner refusal: an authorization verdict, not a transient failure.

    Subclasses ``PermissionError`` so existing ``except`` clauses still catch it, but
    it is its own type so a caller cannot mistake it for a dead transport/session and
    answer "try again later" -- the verdict will be the same on the next call.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.reason = message


def current_claims() -> Optional[agent_token.Claims]:
    """The running run's verified claims, or ``None`` when it carries no valid token."""
    try:
        from core.auth import agent_token_var

        return agent_token.verify_or_none(agent_token_var.get())
    except Exception:
        logger.debug("agent token contextvar unavailable", exc_info=True)
        return None


async def session_exposure(server: str, identity_manager=None) -> bool:
    """Is this MCP *server* published whole, so a caller with no record may open it?

    Sessions never go through ``published_exposure`` (that resolves a tool name), so
    the server record's own ``public`` flag is the source -- the same flag
    ``search_tools`` publishes a whole MCP server's catalog from. A server that only
    lists ``public_tools`` keeps its session closed: an open session is the transport
    for every tool the server lists, so per-tool exposure must not widen into one.
    Fails closed (``False``) on anything unreadable.
    """
    reference = tool_access.session_reference(server)
    if reference is None:
        return False
    manager = identity_manager
    if manager is None:
        from core.auth import get_identity_manager

        manager = get_identity_manager()
    try:
        record = await asyncio.to_thread(manager.get_mcp_config, server)
    except Exception:
        logger.warning(
            "tool_gate: could not read MCP config %r; treating it as not public",
            server,
            exc_info=True,
        )
        return False
    if not record:
        # An edge server (`<site>__<mcp>`) is published through the relay's own
        # catalog and never opened centrally; only a central record can say "public".
        return False
    return record.get("public") is True


async def deny_reason(
    target: str, *, surface: str = "host", session: bool = False
) -> Optional[str]:
    """``None`` when this run may use ``target``, else the denial message to hand back.

    ``session=True`` authorizes opening an MCP session, where ``target`` is the server
    reference (``<server>`` for a central server, ``<site>__<mcp>`` for an edge one).
    A caller with no agent record (the gateway front door) is granted a session only
    by the server's own public exposure, exactly as it is granted a tool.

    The policy read and the shadow-ring write both happen off the event loop
    (``tool_access.*_async``), so one slow registry never stalls the turn.
    """
    mode = agent_token.mode()
    if mode == "off":
        return None
    claims = current_claims()
    if claims is None:
        if mode != "enforce":
            return None
        return f"access_denied [{surface}]: this run carries no verified agent token"

    from core.auth import get_identity_manager

    manager = get_identity_manager()
    record = await asyncio.to_thread(manager.get_agent_config, claims.agent)
    exposure = False
    if record is None and session:
        exposure = await session_exposure(target, manager)
    decision = await tool_access.enforce_async(
        await tool_access.authorize_claims_async(
            claims,
            target=target,
            allowed=allowlist.resolve(record) if record else None,
            public=exposure,
            surface=surface,
            session=session,
        ),
        agent=claims.agent,
        groups=claims.groups,
        target=target,
        surface=surface,
    )
    if decision.allowed:
        return None
    if mode == "log" and decision.reason in _ROLLOUT_REASONS:
        logger.warning(
            "%s: would deny agent=%s target=%s: %s",
            surface,
            claims.agent,
            target,
            decision.message,
        )
        return None
    return decision.message
