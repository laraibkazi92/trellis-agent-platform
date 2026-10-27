# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Central-side dispatch of calls to MCP servers exported by edge sites.

Sibling of ``core.hub::_run_remote`` for MCP tools: the edge owns the tunnel and
the per-user MCP sessions, so central only maps the relay's HTTP contract
(``POST /v1/sites/{site}/mcps/{mcp}/call``) onto the same result-dict shape a
local tool returns. Callers get ``{"content", "isError", "structuredContent"}``
on success and ``{"error": ...}`` otherwise; a completed HTTP exchange never
raises.

Deliberately does **not** import ``core.hub`` (it starts a FastMCP server and the
etcd-backed identity manager) nor ``services/`` (invariant 6), so the small
helpers below duplicate their hub/relay counterparts verbatim.

Arguments, results, and response bodies are never logged: they carry the
customer's internal data.
"""

import asyncio
import json
import logging
import os
from typing import Any, Dict, Optional

import httpx

from core import agent_token as agent_token_module
from core import edge_secrets_central
from core.auth import get_identity_manager
from core.caller_identity import identity_incomplete_error, lacks_credential_identity
from core.tool_runtime import MAX_RESULT_CHARS

logger = logging.getLogger(__name__)

identity_mgr = get_identity_manager()

RELAY_URL_ENV = "EDGE_RELAY_URL"
_DEFAULT_RELAY_URL = "http://edge-relay:8100"

# Mirrors services/edge_relay/protocol.MAX_DEADLINE_MS. Duplicated on purpose:
# core must never import services/ (the relay is a separate process tree, and the
# import would drag FastAPI/WS deps into central's module graph). The relay clamps
# the value again on its side, so this is only an upper bound on the wire.
_MAX_DEADLINE_MS = 3_600_000


def _relay_url() -> str:
    """Base URL of the in-cluster edge relay (compose service name by default)."""
    return os.getenv(RELAY_URL_ENV, _DEFAULT_RELAY_URL).rstrip("/")


def _remote_client(timeout_seconds: float) -> httpx.AsyncClient:
    """Client factory seam for remote MCP dispatch.

    One client per call: a call's edge round trip dwarfs the connection setup.
    Tests monkeypatch this seam to inject an ``httpx.MockTransport``, which keeps
    the request/response mapping under test without touching the network.
    """
    return httpx.AsyncClient(timeout=timeout_seconds)


def _edge_error_field(body: Dict[str, Any], field: str, default: str = "") -> str:
    """Reads ``error.<field>`` (or the string form of ``error``) from a call body."""
    error = body.get("error")
    if isinstance(error, dict):
        value = error.get(field)
        if isinstance(value, str) and value:
            return value
        return default
    if field == "message" and isinstance(error, str) and error:
        return error
    return default


def _cap_remote_result(label: str, result: Any) -> Any:
    """Apply the local 96k safety net to a remote MCP result.

    ``core.tool_runtime`` enforces this on the edge, but the edge is semi-trusted:
    a modified proxy can simply not truncate, and an oversized result would land
    in the model's context (and the provider bill). Central is the trust boundary.
    """
    try:
        stringified = json.dumps(result)
    except (TypeError, ValueError):
        return result
    if len(stringified) <= MAX_RESULT_CHARS:
        return result
    logger.warning(
        "Edge MCP tool %s returned %d chars; truncating to the %d-char safety limit",
        label,
        len(stringified),
        MAX_RESULT_CHARS,
    )
    return {
        "error": (
            f"Global Safety Net: The tool '{label}' output exceeded the 24k token limit "
            f"({MAX_RESULT_CHARS:,} characters). Output was safely truncated to prevent "
            "model context crashes."
        ),
        "partial_data_preview": stringified[:90_000] + "... [TRUNCATED DUE TO SAFETY LIMITS]",
    }


async def call_edge_mcp(
    site: str,
    mcp: str,
    tool: str,
    args: Dict[str, Any],
    user_id: Optional[str],
    *,
    timeout_seconds: Optional[float] = None,
    agent_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Calls one tool on an MCP server exported by edge ``site``.

    Returns the edge's MCP result payload (``content``/``isError``/
    ``structuredContent``) or ``{"error": <actionable message>}``. Never raises on
    transport or HTTP-status failures: the agent-facing wrappers turn the dict
    into one error string. Calls are never replayed — ``mcp_session_lost`` and
    ``edge_timeout`` are reported, not retried.

    ``user_id`` is ignored: identity (including whose sealed credential set to
    forward) comes only from the verified token's claims, so a caller argument can
    never select another user's credentials.
    """
    if timeout_seconds is None:
        # Imported here so a cold central start does not pull the tunables cache.
        from core.tunables import resolve as resolve_tunable

        timeout_seconds = resolve_tunable("tool_execution_timeout")

    if agent_token:
        from core.agent_token import refresh

        agent_token = refresh(agent_token)
    label = f"{site}__{mcp}__{tool}"
    # The HTTP read timeout leads deadline_ms by 5 s so the edge's structured
    # timeout (or the relay's 504) wins the race and the caller sees a reason,
    # not a bare client-side read timeout.
    deadline_ms = int(min((timeout_seconds + 30) * 1000, _MAX_DEADLINE_MS))

    # Identity travels only in the verified token: central never re-reads the
    # registry for it, and a call without one has no identity at all (the assertion
    # in the body cannot stand in for it).
    claims = agent_token_module.verify_or_none(agent_token) if agent_token else None

    # The caller's browser-sealed set for this (site, mcp, user). Central only ever
    # holds the ciphertext: it is forwarded verbatim and never logged. Sealing is
    # per verified identity, so a no-token call has nothing to look up and the edge's
    # credential_mode decides instead.
    sealed: Optional[Dict[str, Any]] = None
    if claims is not None and claims.user_id:
        try:
            sealed = await asyncio.to_thread(
                edge_secrets_central.get, identity_mgr, site, claims.user_id, "mcp", mcp
            )
        except Exception as exc:
            logger.warning(
                "Could not read sealed credentials for edge MCP tool %s (%s)",
                label,
                type(exc).__name__,
            )

    if lacks_credential_identity(claims, sealed=sealed is not None):
        # A sealed set with nothing to attribute it to: refuse with the real reason
        # (missing identity) rather than let the edge answer ``credential_rejected``.
        # An email-less caller's per-user *mode* is the edge's decision -- see
        # ``core.caller_identity.lacks_credential_identity`` (v0.7.2 R7.1).
        return identity_incomplete_error(f"MCP tool '{label}'", site)

    try:
        async with _remote_client(timeout_seconds + 35) as client:
            response = await client.post(
                f"{_relay_url()}/v1/sites/{site}/mcps/{mcp}/call",
                json={
                    "tool": tool,
                    "args": args,
                    "deadline_ms": deadline_ms,
                    # The relay verifies this token and builds the edge frame's
                    # identity from its claims; the body carries no identity.
                    "agent_token": agent_token,
                    "sealed": sealed,
                },
            )
    except httpx.TimeoutException as exc:
        return {
            "error": (
                f"MCP tool '{label}' did not respond on edge '{site}' before central's "
                f"own deadline ({type(exc).__name__}). The call may still have run on the edge."
            )
        }
    except httpx.ConnectError as exc:
        return {
            "error": (
                f"MCP tool '{label}' is unreachable (the edge relay hop to edge "
                f"'{site}' failed: {type(exc).__name__})."
            )
        }
    except (httpx.InvalidURL, httpx.UnsupportedProtocol) as exc:
        # A broken EDGE_RELAY_URL (bad protocol, bad port) is a central config error, not
        # a lost edge: nothing was sent, and the operator needs the actual cause.
        return {
            "error": (
                f"MCP tool '{label}' could not be dispatched: the edge relay URL "
                f"'{_relay_url()}' is unusable ({type(exc).__name__}: {exc}). "
                f"Check {RELAY_URL_ENV}."
            )
        }
    except httpx.TransportError as exc:
        return {
            "error": (
                f"MCP tool '{label}' lost its connection to edge '{site}' mid-call "
                f"({type(exc).__name__}). It may already have run on the edge."
            )
        }
    except httpx.HTTPError as exc:
        # Anything else httpx can raise on the way out (redirect loop, decoding, ...).
        # Never let it escape into the agent turn as a bare traceback.
        return {
            "error": (
                f"MCP tool '{label}' could not be dispatched to edge '{site}' "
                f"({type(exc).__name__}: {exc}). Check the relay at '{_relay_url()}'."
            )
        }

    try:
        body = response.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}

    status = response.status_code

    if status == 200:
        if "error" in body:
            message = _edge_error_field(body, "message", "the edge did not report a reason")
            return {"error": f"MCP tool '{label}' failed on edge '{site}': {message}"}
        result = body.get("result")
        # A well-formed MCP result is a JSON object; anything else is wrapped so
        # callers keep a dict contract.
        result = result if isinstance(result, dict) else {"result": result}
        return _cap_remote_result(label, result)

    if status == 400:
        # Schema rejection: permanent by construction, never retried.
        return {
            "error": (
                f"MCP tool '{label}' rejected the arguments: "
                f"{_edge_error_field(body, 'message', 'the relay rejected the call')}"
            )
        }

    if status == 404:
        # The relay distinguishes "this edge exports no MCPs at all" from "this server /
        # tool is not in the catalog"; keep that distinction instead of flattening it.
        detail = _edge_error_field(body, "message")
        return {
            "error": (
                f"Edge '{site}' does not export MCP tool '{label}'. Either the server or "
                "tool is no longer in the edge's catalog, or the edge does not export MCPs "
                f"at all (v0.4 edge).{f' Relay said: {detail}.' if detail else ''}"
            )
        }

    if status == 503:
        code = _edge_error_field(body, "code")
        if code == "edge_overloaded":
            return {"error": f"Edge '{site}' is busy and cannot accept MCP tool '{label}' right now."}
        if code in ("edge_offline", "edge_disconnected"):
            # Expected operational state, not a central bug: surface it, never raise.
            return {"error": f"MCP tool '{label}' is offline (edge '{site}' is not connected)."}

    if status == 429:
        return {"error": f"Edge '{site}' is rate-limiting tool calls; '{label}' was not sent."}

    if status == 504:
        return {"error": f"MCP tool '{label}' timed out on edge '{site}' (no result before the deadline)."}

    # Unknown status: include the code, and at most a short body preview.
    preview = (response.text or "")[:200]
    return {"error": f"MCP tool '{label}' failed on edge '{site}' (relay returned HTTP {status}: {preview})"}
