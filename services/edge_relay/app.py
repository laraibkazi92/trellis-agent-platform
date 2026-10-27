# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge relay: terminates the outbound-only tunnel an edge node dials into.

One live WebSocket per site, held in memory. The relay forwards a call only for
a tool that site published in its ``hello`` catalog, waits with the caller's
deadline, and never dials the edge itself -- the only path into a customer
network is a socket the edge opened.

Arguments and results are never logged: they can contain internal data. Only
site, tool, call id, duration and outcome are.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import threading
import time
import uuid
from typing import Annotated, Any, Dict, List, Optional

from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.websockets import WebSocketDisconnect

from core import agent_token as agent_token_module
from core import allowlist
from services.edge_relay import audit, protocol, registry
from services.edge_relay.ratelimit import SiteLimiter, normalise_rate
from services.edge_relay.protocol import (
    DEFAULT_DEADLINE_MS,
    HEARTBEAT_S,
    MAX_DEADLINE_MS,
    MAX_FRAME_BYTES,
    MAX_INFLIGHT,
    SUBPROTOCOL,
    EdgeMcp,
    EdgeTool,
    ProtocolError,
)
from services.edge_relay.tokens import hash_token, resolve_token

logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    """Make this module's INFO lines visible under uvicorn.

    uvicorn only configures the ``uvicorn*`` loggers, so without a root handler every
    connect/call line an operator greps for falls through to lastResort (WARNING).
    Under pytest a handler already exists, so this is a no-op there.
    """
    if logging.getLogger().handlers:
        return
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


_configure_logging()

RATE_LIMIT_PER_MIN = normalise_rate(os.getenv("EDGE_RATE_LIMIT_PER_MIN", "120"))
limiter = SiteLimiter(RATE_LIMIT_PER_MIN)

# A lazy-catalog detail read is a manifest lookup on an edge that is already connected:
# generous, but nowhere near a tool call's 330 s default, so a hung edge cannot pin the
# hub's schema lookup.
DETAIL_DEADLINE_MS = 20_000
# Detail reads are metadata only: a small, separate budget keeps a burst of schema
# lookups from consuming the call path's inflight slots.
DETAIL_MAX_INFLIGHT = 4


class EdgeOffline(Exception):
    """No live connection for the site."""


class EdgeUnknownTool(Exception):
    """The site never published this tool."""


class EdgeUnknownMcp(Exception):
    """The site never published this MCP server."""


class EdgeOverloaded(Exception):
    """The site already has MAX_INFLIGHT calls in flight."""


class EdgeTimeout(Exception):
    """The edge did not answer before the caller's deadline."""


class EdgeDisconnected(Exception):
    """The socket went away while the call was pending."""


class EdgeDetailError(Exception):
    """The edge answered a lazy-catalog detail request with an error result."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _consume_exception(future: "asyncio.Future[Any]") -> None:
    """Mark a failed future as retrieved so an abandoned call cannot warn."""
    if not future.cancelled():
        future.exception()


class EdgeConn:
    """One accepted edge socket: its catalog, its pending calls, its liveness."""

    def __init__(
        self,
        ws: Any,
        site: str,
        tools: Optional[Dict[str, EdgeTool]] = None,
        mcps: Optional[Dict[str, EdgeMcp]] = None,
        caps: Optional[List[str]] = None,
    ):
        self.ws = ws
        self.site = site
        self.tools: Dict[str, EdgeTool] = dict(tools or {})
        # Held in memory only: publishing MCP catalogs is the central consumer's
        # job (PR 4), this phase only accepts and accounts for them.
        self.mcps: Dict[str, EdgeMcp] = dict(mcps or {})
        self.caps: List[str] = ["tools"] if caps is None else list(caps)
        self.inflight: Dict[str, "asyncio.Future[Any]"] = {}
        self.detail_sem = asyncio.Semaphore(DETAIL_MAX_INFLIGHT)
        self.closed = False
        # What the edge claimed at handshake; echoed back in the site status.
        self.proto: Optional[int] = None
        # Per-site override from the edge config; None uses the deployment default.
        self.rate_limit_per_min: Optional[int] = None
        # Digest of the token presented at handshake; a rotation changes it.
        self.token_hash: str = ""
        # Catalog-relevant admin fields as last published (None = never published).
        self.published_signature: Optional[tuple] = None
        self.edge_version: str = ""

    async def send(self, frame: Dict[str, Any]) -> None:
        if self.closed:
            raise EdgeDisconnected(f"edge '{self.site}' is closed")
        try:
            await self.ws.send_text(protocol.encode(frame))
        except Exception as exc:
            self.closed = True
            raise EdgeDisconnected(f"edge '{self.site}' send failed: {exc}") from exc

    async def request(
        self,
        tool: str,
        args: Dict[str, Any],
        deadline_ms: int = DEFAULT_DEADLINE_MS,
        user: Optional[str] = None,
        user_email: Optional[str] = None,
        agent_token: Optional[str] = None,
        sealed: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Forward one tool call and await its validated result frame.

        ``user``/``user_email`` are the verified token's claims (``_claims_identity``),
        never a request body; the routes are the only production callers.
        """
        if self.closed:
            raise EdgeDisconnected(f"edge '{self.site}' is closed")
        if tool not in self.tools:
            raise EdgeUnknownTool(f"tool '{tool}' is not exported by edge '{self.site}'")
        return await self._forward(
            self._call_frame(tool, args, deadline_ms, user, user_email, agent_token, sealed),
            tool,
        )

    async def request_mcp(
        self,
        mcp: str,
        tool: str,
        args: Dict[str, Any],
        deadline_ms: int = DEFAULT_DEADLINE_MS,
        user: Optional[str] = None,
        user_email: Optional[str] = None,
        agent_token: Optional[str] = None,
        sealed: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Forward one MCP ``tools/call`` through the same tunnel.

        The tool name is *not* checked here: the edge owns that authority (it refuses
        a name it did not publish), and its refusal arrives as an ordinary error
        result rather than a relay-side 404.
        """
        if self.closed:
            raise EdgeDisconnected(f"edge '{self.site}' is closed")
        if mcp not in self.mcps:
            raise EdgeUnknownMcp(f"mcp '{mcp}' is not exported by edge '{self.site}'")
        frame = self._call_frame(tool, args, deadline_ms, user, user_email, agent_token, sealed)
        frame["kind"] = "mcp"
        frame["mcp"] = mcp
        return await self._forward(frame, tool, mcp=mcp)

    async def request_tool_detail(self, tool: str) -> Dict[str, Any]:
        """Ask the edge for one tool's full detail (lazy catalog).

        The tool must be in this connection's published catalog: an edge is never asked
        about a name it did not announce. A refusal arrives as an error result and
        becomes ``EdgeDetailError`` rather than a relay-side 404 -- the edge owns the
        authority over its own catalog, exactly as on an MCP call.
        """
        if self.closed:
            raise EdgeDisconnected(f"edge '{self.site}' is closed")
        if "lazy_catalog" not in self.caps:
            raise EdgeDetailError(
                "detail_unsupported",
                f"edge '{self.site}' does not support lazy catalogs",
            )
        if tool not in self.tools:
            raise EdgeUnknownTool(f"tool '{tool}' is not exported by edge '{self.site}'")
        frame = {"t": "tool_detail", "id": uuid.uuid4().hex, "tool": tool}
        detail = await self._request_detail(frame, tool)
        # The hello carried a summary: keep the live catalog in sync with the fetched
        # schema, or the very next call is rejected by args_for_tool for not knowing
        # the real arguments.
        try:
            self.tools[tool] = protocol.validate_tool_detail(detail)
        except ProtocolError as exc:
            raise EdgeDetailError("detail_invalid", str(exc)) from exc
        return detail

    async def request_mcp_tool_detail(self, mcp: str, tool: str) -> Dict[str, Any]:
        """Ask the edge for one MCP tool's full entry (schema included)."""
        if self.closed:
            raise EdgeDisconnected(f"edge '{self.site}' is closed")
        if "lazy_catalog" not in self.caps:
            raise EdgeDetailError(
                "detail_unsupported",
                f"edge '{self.site}' does not support lazy catalogs",
            )
        if mcp not in self.mcps:
            raise EdgeUnknownMcp(f"mcp '{mcp}' is not exported by edge '{self.site}'")
        frame = {
            "t": "mcp_tool_detail",
            "id": uuid.uuid4().hex,
            "mcp": mcp,
            "tool": tool,
        }
        return await self._request_detail(frame, tool, mcp=mcp)

    async def _request_detail(
        self, frame: Dict[str, Any], tool: str, mcp: Optional[str] = None
    ) -> Dict[str, Any]:
        """Send one detail frame and return its ``detail`` payload.

        It rides the ordinary result correlation (``inflight[id] -> Future``), so the
        receive loop needs no branch for it. The local deadline is deliberately much
        shorter than a call's: reading a manifest on a healthy edge is immediate, and a
        hung edge must not pin the hub's schema lookup for five minutes.
        """
        async with self.detail_sem:
            payload = await self._forward(
                frame, tool, mcp=mcp, deadline_ms=DETAIL_DEADLINE_MS
            )
        if not payload.get("ok"):
            error = payload.get("error") or {}
            raise EdgeDetailError(
                str(error.get("code") or "detail_failed"),
                str(error.get("message") or f"edge '{self.site}' refused the detail read"),
            )
        detail = payload.get("detail")
        if not isinstance(detail, dict):
            # Only reachable if the peer answers without the validated `detail` object
            # (an old edge that accepted an unknown frame type); refuse to cache it.
            raise EdgeDetailError(
                "detail_missing",
                f"edge '{self.site}' answered without a detail object",
            )
        return detail

    def _call_frame(
        self,
        tool: str,
        args: Dict[str, Any],
        deadline_ms: int,
        user: Optional[str],
        user_email: Optional[str],
        agent_token: Optional[str] = None,
        sealed: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build one ``call`` frame with the deadline clamped to the wire cap.

        ``user``/``user_email`` are the claims-derived identity: the edge uses them
        unchanged (MCP session key, sealed AAD, ``TRELLIS_USER_*``) and does not
        verify anything of its own.
        """
        frame: Dict[str, Any] = {
            "t": "call",
            "id": uuid.uuid4().hex,
            "tool": tool,
            "args": args,
            "deadline_ms": max(1_000, min(int(deadline_ms), MAX_DEADLINE_MS)),
            "user": user,
        }
        # Omitted when absent so a v0.4 edge sees the exact same bytes.
        if user_email is not None:
            frame["user_email"] = user_email
        # Forwarded verbatim for the edge's runner, which verifies signature/expiry
        # when it opens a container; the authorization decision was already made here.
        if agent_token is not None:
            frame["agent_token"] = agent_token
        # Opaque ciphertext: the relay cannot open it, so it forwards the bytes and
        # never stores, logs or audits them.
        if sealed is not None:
            frame["sealed"] = sealed
        return frame

    async def _forward(
        self,
        frame: Dict[str, Any],
        tool: str,
        mcp: Optional[str] = None,
        deadline_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Send a frame and await its result.

        The deadline is read back from the frame (``_call_frame`` already clamped it)
        so the local timer and the edge's cannot disagree. A caller that has no wire
        deadline (a detail read) passes its local bound instead.
        """
        if len(self.inflight) >= MAX_INFLIGHT:
            raise EdgeOverloaded(f"edge '{self.site}' is at {MAX_INFLIGHT} in-flight calls")

        timeout_ms = deadline_ms or frame.get("deadline_ms") or DEFAULT_DEADLINE_MS
        call_id = frame["id"]
        future: "asyncio.Future[Any]" = asyncio.get_running_loop().create_future()
        future.add_done_callback(_consume_exception)
        self.inflight[call_id] = future
        started = time.perf_counter()

        try:
            await self.send(frame)
            try:
                payload = await asyncio.wait_for(future, timeout_ms / 1000)
            except asyncio.TimeoutError:
                self._log(tool, call_id, started, "timeout", mcp=mcp)
                raise EdgeTimeout(
                    f"edge '{self.site}' did not answer '{tool}' within {timeout_ms}ms"
                ) from None
            except BaseException:
                self._log(tool, call_id, started, "error", mcp=mcp)
                raise
        finally:
            self.inflight.pop(call_id, None)

        self._log(tool, call_id, started, "ok" if payload.get("ok") else "tool_error", mcp=mcp)
        return payload

    def resolve(self, call_id: str, payload: Dict[str, Any]) -> bool:
        """Deliver a result frame to its waiter; unknown/expired ids are dropped."""
        future = self.inflight.pop(call_id, None)
        if future is None or future.done():
            return False
        future.set_result(payload)
        return True

    def fail_pending(self, message: str) -> None:
        """Fail every waiter so an HTTP caller never hangs on a dead socket."""
        for call_id in list(self.inflight):
            future = self.inflight.pop(call_id, None)
            if future is not None and not future.done():
                future.set_exception(EdgeDisconnected(message))

    async def close(self, code: int) -> None:
        self.closed = True
        with contextlib.suppress(Exception):
            await self.ws.close(code=code)

    def _log(
        self, tool: str, call_id: str, started: float, outcome: str, mcp: Optional[str] = None
    ) -> None:
        duration = int((time.perf_counter() - started) * 1000)
        if mcp is None:
            logger.info(
                "edge call site=%s tool=%s id=%s duration_ms=%d outcome=%s",
                self.site,
                tool,
                call_id,
                duration,
                outcome,
            )
            return
        logger.info(
            "edge call site=%s mcp=%s tool=%s id=%s duration_ms=%d outcome=%s",
            self.site,
            mcp,
            tool,
            call_id,
            duration,
            outcome,
        )


class Relay:
    """site -> live connection. One replica only (see design §10)."""

    def __init__(self) -> None:
        self.sites: Dict[str, EdgeConn] = {}

    async def register(self, site: str, conn: EdgeConn) -> None:
        """Install ``conn``, evicting the previous socket for the same site.

        A redeploy must never get stuck behind a zombie socket that the server
        has not noticed yet.
        """
        previous = self.sites.get(site)
        self.sites[site] = conn
        if previous is not None and previous is not conn:
            await previous.close(protocol.CLOSE_SUPERSEDED)
            previous.fail_pending(f"edge '{site}' was superseded by a newer connection")

    def unregister(self, site: str, conn: EdgeConn) -> None:
        if self.sites.get(site) is conn:
            del self.sites[site]

    def get(self, site: str) -> Optional[EdgeConn]:
        conn = self.sites.get(site)
        if conn is None or conn.closed:
            return None
        return conn

    def require(self, site: str) -> EdgeConn:
        conn = self.get(site)
        if conn is None:
            raise EdgeOffline(f"edge '{site}' is not connected")
        return conn


@contextlib.asynccontextmanager
async def _lifespan(_app: FastAPI):
    # Imported here so a cold start of the relay does not pull in the core
    # dev-mode helpers (and their FastAPI middleware imports) before serving.
    from core.devmode import enforce_dev_mode_safety

    enforce_dev_mode_safety("edge-relay")
    # Fail closed without a key outside DEV_MODE: the relay verifies agent tokens on
    # both call routes, so an unkeyed relay would silently permit every caller.
    from core.log_redaction import install as install_redaction

    install_redaction()
    agent_token_module.require_secret("edge-relay")
    audit.configure()
    # The site map is in-process: after a restart nothing is connected, so any
    # `connected: true` left in the registry is stale. Clear it before serving,
    # otherwise an edge that is offline across the restart looks usable forever.
    try:
        await asyncio.to_thread(_mark_all_disconnected, "relay restarted")
    except Exception as exc:  # registry unavailability must not block startup
        logger.warning("could not reset edge status at startup: %s", exc)
    yield

    # Best-effort drain: uvicorn may already have closed the sockets with 1012 by the
    # time this runs, in which case the send fails and the edge redials on its normal
    # 1 s floor anyway. Kept because a shutdown path that *does* reach here still saves
    # the edge a full backoff.
    for conn in list(relay.sites.values()):
        try:
            await conn.send({"t": "drain", "reconnect_after_s": 1})
            await conn.close(code=1001)
        except Exception:
            pass


async def _apply_admin_changes(conn: EdgeConn, config: Dict[str, Any]) -> None:
    """Republish when an admin edited exports/public/public_tools/rate limit.

    Those fields are read at handshake, so without this a removed tool stayed callable
    (and a new one invisible) until the edge happened to reconnect. The heartbeat
    already re-reads the record; acting on a change is one extra registry write.

    Both catalogs are republished: the site record is the authority for what the site
    publishes, and a refresh that touched only the tool half would leave the MCP status
    (and its prune) stale.
    """
    signature = _catalog_signature(config, conn.mcps)
    conn.rate_limit_per_min = config.get("rate_limit_per_min")
    if conn.published_signature is None or signature == conn.published_signature:
        return
    try:
        published, published_mcps = await asyncio.to_thread(
            _publish_catalogs,
            conn.site,
            list(conn.tools.values()),
            list(conn.mcps.values()),
            conn.edge_version,
            proto=conn.proto,
            caps=conn.caps,
            # An admin edit (exports/public/public_tools) is explicit intent for both
            # halves: without the MCP flag, removing the last server from export_mcps
            # would leave a stale registry entry the admin has no way to prune.
            allow_empty=True,
            allow_empty_mcps=True,
        )
    except Exception:
        logger.exception("could not refresh the catalog for site=%s", conn.site)
        return
    conn.published_signature = signature
    logger.info(
        "edge catalog refreshed from admin changes site=%s tools=%d mcps=%d",
        conn.site,
        len(published),
        len(published_mcps),
    )


def _publish_catalogs(
    site: str,
    tools: List[EdgeTool],
    mcps: List[EdgeMcp],
    edge_version: str,
    *,
    proto: Optional[int],
    caps: Optional[List[str]],
    allow_empty: bool = False,
    allow_empty_mcps: bool = False,
) -> tuple:
    """Publish both catalogs for one site; returns ``(tool_names, mcp_names)``.

    One function so the handshake and an admin-driven refresh cannot publish half a
    catalog. Tools go first: their write owns ``last_error``, and the MCP write keeps it.

    ``allow_empty`` and ``allow_empty_mcps`` are separate because their empties mean
    different things: an admin narrowing ``exports`` to nothing is intent for tools,
    while nothing on the site record filters MCPs -- an empty MCP catalog from a
    connected edge is always a suspected edge-side misconfiguration.

    ``lazy_catalog`` is derived once from the advertised caps and passed to both
    halves, so the tool and MCP records of one handshake always agree about whether
    their detail is complete.
    """
    mgr = _identity_manager()
    lazy_catalog = "lazy_catalog" in (caps or [])
    published = registry.publish_catalog(
        mgr,
        site,
        tools,
        edge_version,
        allow_empty=allow_empty,
        mcps=mcps,
        proto=proto,
        caps=caps,
        lazy_catalog=lazy_catalog,
    )
    published_mcps = registry.publish_mcp_catalog(
        mgr,
        site,
        mcps,
        edge_version,
        allow_empty=allow_empty_mcps,
        proto=proto,
        caps=caps,
        lazy_catalog=lazy_catalog,
    )
    return published, published_mcps


def _mark_all_disconnected(reason: str) -> None:
    mgr = _identity_manager()
    for site in mgr.list_edges():
        status = mgr.get_edge_status(site) or {}
        if status.get("connected"):
            registry.mark_disconnected(mgr, site, reason)


app = FastAPI(title="Trellis Edge Relay", lifespan=_lifespan)
relay = Relay()

_registry_identity_mgr: Optional[Any] = None


def _identity_manager() -> Any:
    """Registry accessor, resolved lazily and cached for the process lifetime.

    A function rather than a module-level object so the relay can start -- and tests can
    run -- without an etcd connection; tests replace this accessor wholesale.
    """
    global _registry_identity_mgr
    if _registry_identity_mgr is None:
        from core.auth import get_identity_manager

        _registry_identity_mgr = get_identity_manager()
    return _registry_identity_mgr


class CallBody(BaseModel):
    """One tool or MCP call, as the hub/host posts it.

    There is **no caller identity here**: ``user``/``user_email`` were removed in
    v0.7.1 (identity comes from the agent token's claims, see ``_claims_identity``).
    ``extra="allow"`` exists only so a pre-v0.7.1 caller is not 422'd mid-rollout --
    the fields it still posts are logged once and otherwise ignored.
    """

    model_config = ConfigDict(extra="allow")

    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)
    # Strict: pydantic would otherwise accept ``true`` as ``1``.
    deadline_ms: Annotated[int, Field(strict=True)] = DEFAULT_DEADLINE_MS
    # Minted by the agent runtime; verified here -- the relay is the only verifier on
    # this path -- and forwarded verbatim to the edge for the runner.
    agent_token: Optional[str] = None
    # Browser-sealed per-user credentials: opaque to the relay, forwarded verbatim and
    # never logged or audited (only ``has_sealed`` reaches the audit line). Typed as
    # ``Any`` so a non-object body is a 400 from ``validate_call``, not pydantic's 422.
    sealed: Optional[Any] = None


# Fields a pre-v0.7.1 caller may still post. Ignored (never read) and reported once so
# an operator can find the stale caller; a body can never assert an identity.
_BODY_IDENTITY_FIELDS = ("user", "user_email")
_BODY_IDENTITY_WARNED = False
# Two calls can arrive on two threads: check-and-set under a lock so one rollout window
# logs one line, not one per concurrent request.
_BODY_IDENTITY_LOCK = threading.Lock()


def _warn_body_identity(body: CallBody) -> None:
    """Log once if a request still carries body identity, then ignore it."""
    global _BODY_IDENTITY_WARNED
    extra = body.model_extra or {}
    present = [name for name in _BODY_IDENTITY_FIELDS if name in extra]
    if not present:
        return
    with _BODY_IDENTITY_LOCK:
        if _BODY_IDENTITY_WARNED:
            return
        _BODY_IDENTITY_WARNED = True
    logger.warning(
        "relay: ignoring %s in a call body; the caller identity comes from the agent "
        "token claims only (update the caller)",
        ", ".join(present),
    )


def _claims_identity(
    claims: Optional[agent_token_module.Claims],
) -> tuple[Optional[str], Optional[str]]:
    """The frame identity: ``(user, user_email)`` from the verified token's claims.

    ``(None, None)`` when there is no verified caller (mode ``off``, or a token the
    relay let through in ``log`` mode) -- the frame then carries no identity at all
    and the edge must not invent one. The edge uses these values unchanged for the
    MCP session key, the sealed-credential AAD identity and ``TRELLIS_USER_*``.
    """
    if claims is None:
        return None, None
    user = claims.user_id if isinstance(claims.user_id, str) and claims.user_id else None
    email = (
        claims.user_email
        if isinstance(claims.user_email, str) and claims.user_email
        else None
    )
    return user, email


async def _publicly_exposed(site: str, tool: str, mcp: Optional[str]) -> bool:
    """Is this edge export exposed to external clients?

    A caller with no agent record has no allowlist to resolve, so the export's own
    published exposure -- the same ``public``/``public_tools`` decision
    ``tool_search.is_tool_publicly_whitelisted`` applied before dispatching -- is the
    only grant that can apply. Read from the ``<site>__…`` records the relay itself
    published, so it reflects the site record an admin edited.
    """
    mgr = _identity_manager()
    if mcp is not None:
        record = await asyncio.to_thread(mgr.get_mcp_config, f"{site}__{mcp}") or {}
        if record.get("public") is True:
            return True
        names = record.get("public_tools")
        return isinstance(names, list) and tool in names
    record = await asyncio.to_thread(mgr.get_tool_config, f"{site}__{tool}")
    return bool(record) and record.get("public") is True


async def _authorize_agent(
    raw_token: Optional[str], *, site: str, tool: str, mcp: Optional[str] = None
) -> tuple[Optional[agent_token_module.Claims], Optional[tuple[str, str]]]:
    """Verify the agent token and the agent's effective allowlist for one edge call.

    Returns ``(claims, denial)``. ``denial`` is ``(code, message)`` for a 403, or
    ``None`` when the call may proceed. The allowlist is resolved from the registry
    here, at call time, so a caller cannot assert permissions it does not hold.

    This is the **only** token verification on the edge path: the identity in the
    forwarded frame is built from these claims (``_claims_identity``) and the edge
    trusts it over the authenticated tunnel.

    No caller is exempt. A token whose agent has no record (the gateway front door
    mints for the external client it serves) is left with the export's own public
    exposure as its only possible grant.

    In ``log`` mode a refusal is logged and the call still runs (one rollout window);
    ``off`` skips the check entirely.
    """
    mode = agent_token_module.mode()
    if mode == "off":
        return None, None

    try:
        claims = agent_token_module.verify(raw_token)
    except agent_token_module.AgentTokenError as exc:
        message = f"access_denied: agent token rejected ({exc.code})"
        if mode == "log":
            logger.warning(
                "relay: would deny site=%s tool=%r (%s)", site, tool, message
            )
            return None, None
        return None, ("access_denied", message)

    config = await asyncio.to_thread(
        _identity_manager().get_agent_config, claims.agent
    )
    permitted = False
    reference = f"{site}__{tool}"
    if not config:
        permitted = await _publicly_exposed(site, tool, mcp)
        message = f"access_denied: unknown agent '{claims.agent}'"
    else:
        allowed = allowlist.resolve(config)
        if mcp is None:
            permitted = allowlist.permits_tool(allowed, reference)
        else:
            # The composed reference already folds in the server grant, the
            # wildcard and a per-tool grant — the same rule that registers tools.
            reference = f"mcp__{site}__{mcp}__{tool}"
            permitted = allowlist.permits_tool(allowed, reference)
        message = agent_token_module.deny_message(claims.agent, reference)

    if permitted:
        return claims, None
    if mode == "log":
        logger.warning(
            "relay: would deny site=%s tool=%r agent=%s: %s",
            site,
            tool,
            claims.agent,
            message,
        )
        return claims, None
    return claims, ("access_denied", message)


class McpCallBody(CallBody):
    """Same shape as ``CallBody``; the MCP name rides the path, not the body."""


class ToolDetailBody(BaseModel):
    """A lazy-catalog read: which exported tool's full detail is wanted."""

    tool: str


class McpToolDetailBody(BaseModel):
    """The MCP half of the same read; the server name rides the body."""

    mcp: str
    tool: str


def _catalog_signature(config: Dict[str, Any], mcps: Any = ()) -> tuple:
    """The admin-editable fields that change what a site publishes or how fast.

    The MCP names are part of the signature as well: nothing on the site record
    filters MCP catalogs yet, so the published set is their half of it.
    """
    return (
        tuple(config.get("exports") or []),
        bool(config.get("public")),
        tuple(config.get("public_tools") or []),
        config.get("rate_limit_per_min"),
        tuple(sorted(mcps)),
    )


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


def _bearer(header: Optional[str]) -> str:
    if not header:
        return ""
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return value.strip()


async def _heartbeat(conn: EdgeConn) -> None:
    """Send the app-level keepalive and revalidate the enrollment.

    This is one-directional on purpose: the frame exists so a proxy in the path
    (nginx's ``proxy_read_timeout``) sees traffic. Answering an inbound ``ping``
    with another ``ping`` made two peers echo each other without bound.

    Revocation is checked here because the token is only validated at upgrade.
    Without this, a revoked (or deleted) site keeps forwarding calls for as long
    as its socket stays healthy -- and the heartbeat is what keeps it healthy.
    """
    while not conn.closed:
        await asyncio.sleep(HEARTBEAT_S)

        revoked = rotated = False
        config: Optional[Dict[str, Any]] = None
        try:
            config = await asyncio.to_thread(
                registry.effective_site_config, _identity_manager(), conn.site
            )
        except Exception as exc:
            # A registry hiccup is not a revocation: keep the tunnel alive.
            logger.warning("could not revalidate edge site=%s: %s", conn.site, exc)
        else:
            revoked = config is None or not config.get("enabled", True)
            rotated = (
                not revoked
                and bool(config.get("token_hash"))
                and bool(conn.token_hash)
                and config["token_hash"] != conn.token_hash
            )
            if revoked or rotated:
                # `enabled` stays true across a rotation, so the hash compare is what
                # makes "rotate" cut off a leaked tunnel instead of waiting for a drop.
                logger.info(
                    "edge %s while connected site=%s; closing tunnel",
                    "revoked" if revoked else "token rotated",
                    conn.site,
                )
                limiter.forget(conn.site)
                await conn.close(code=protocol.CLOSE_REVOKED)
                return

        try:
            await conn.send({"t": "ping"})
        except EdgeDisconnected:
            return

        # After the keepalive: a republish can re-index embeddings, and delaying the
        # ping risks an intermediary's read timeout mid-maintenance.
        if config is not None and not revoked and not rotated:
            await _apply_admin_changes(conn, config)


async def _receive_frame(ws: Any) -> Optional[Dict[str, Any]]:
    """Read one edge frame, or ``None`` once the peer disconnects.

    Both text and binary payloads are accepted (``protocol.decode`` normalises
    them). ``receive_text`` is not used here: a binary frame would land in the
    ASGI message without a ``text`` key and kill the handler with a ``KeyError``.
    """
    message = await ws.receive()
    if message["type"] == "websocket.disconnect":
        return None
    if message["type"] != "websocket.receive":
        raise ProtocolError(f"unexpected websocket message: {message['type']!r}")
    raw = message.get("text")
    if raw is None:
        raw = message.get("bytes")
    return protocol.decode(raw, protocol.EDGE_FRAMES)


@app.websocket("/edge/v1/connect")
async def edge_connect(ws: WebSocket) -> None:
    offered = [
        part.strip()
        for part in (ws.headers.get("sec-websocket-protocol") or "").split(",")
    ]
    if SUBPROTOCOL not in offered:
        # Reject the upgrade instead of accepting a socket that speaks an
        # unknown version of the tunnel.
        await ws.close(code=protocol.CLOSE_VERSION)
        return

    # Authenticate before accepting so an unauthenticated caller never gets a
    # socket. ``resolve_token`` is a single indexed get on ``/edge_tokens/<sha256>``
    # (never a scan of every site), which is what keeps this pre-upgrade check cheap
    # enough to run on an unauthenticated path.
    token = _bearer(ws.headers.get("authorization"))
    config = await asyncio.to_thread(resolve_token, token) if token else None
    if not config:
        if hasattr(ws, "send_denial_response"):
            try:
                await ws.send_denial_response(
                    JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
                )
                return
            except RuntimeError:
                # The server did not offer the denial-response extension.
                pass
        await ws.close(code=protocol.CLOSE_REVOKED)
        return

    try:
        site = protocol.validate_site_name(config.get("name"))
    except ProtocolError as exc:
        await ws.close(code=exc.close_code)
        return

    await ws.accept(subprotocol=SUBPROTOCOL)

    try:
        frame = await _receive_frame(ws)
        if frame is None:
            return
        if frame["t"] != "hello":
            await ws.close(code=protocol.CLOSE_MALFORMED)
            return
        hello = protocol.validate_hello(frame)
        proto, edge_version, tools, mcps, caps = hello
        credentials = hello.credentials
    except ProtocolError as exc:
        await ws.close(code=exc.close_code)
        return
    except (WebSocketDisconnect, RuntimeError):
        return

    # Entries the validator had to drop: log each (name + reason) and serve the rest.
    # One unusable manifest costs that export, never the tunnel.
    for skipped in hello.errors:
        logger.warning(
            "edge hello site=%s: not publishing %s", site, skipped.describe()
        )

    conn = EdgeConn(
        ws,
        site,
        {tool.name: tool for tool in tools},
        {mcp.name: mcp for mcp in mcps},
        caps,
    )
    conn.rate_limit_per_min = config.get("rate_limit_per_min")
    conn.proto = proto
    # Pinned at handshake so a rotation closes this socket on the next heartbeat:
    # `enabled` stays true across a rotation, so checking only that would leave a
    # leaked tunnel alive until it happened to drop.
    conn.token_hash = hash_token(token)

    # Welcome BEFORE the site becomes dispatchable. The edge is still blocked waiting
    # for this frame, so a call landing in the publish window (N etcd writes) would be
    # injected into the handshake and tear the tunnel down.
    await conn.send(
        {
            "t": "welcome",
            "site": site,
            "heartbeat_s": HEARTBEAT_S,
            "max_frame_bytes": MAX_FRAME_BYTES,
            "max_inflight": MAX_INFLIGHT,
        }
    )

    try:
        await asyncio.to_thread(
            _publish_catalogs,
            site,
            tools,
            mcps,
            edge_version,
            proto=proto,
            caps=caps,
        )
    except ValueError as exc:
        # The token was valid moments ago, but the site can be deleted or revoked
        # between the upgrade and this write; a tunnel whose catalog cannot be
        # registered must not keep running.
        logger.error("edge catalog publish refused site=%s: %s", site, exc)
        audit.record("connect", site=site, outcome="rejected")
        await conn.close(code=protocol.CLOSE_REVOKED)
        relay.unregister(site, conn)
        return
    except Exception:
        # A registry failure is not a revocation: close with an ordinary server-error
        # code so the edge redials on its normal backoff instead of the terminal one.
        logger.exception("edge catalog publish failed site=%s; closing the tunnel", site)
        audit.record("connect", site=site, outcome="error")
        await conn.close(code=1011)
        relay.unregister(site, conn)
        return

    conn.published_signature = _catalog_signature(config, conn.mcps)
    conn.edge_version = edge_version
    # The credential key/name material belongs to the site record, not to a tool
    # config: central's seal form reads it from there. A registry hiccup must not tear
    # down a working tunnel -- the edge would redial and publish the same catalog.
    try:
        await asyncio.to_thread(
            registry.publish_edge_credentials, _identity_manager(), site, credentials
        )
    except Exception as exc:
        logger.warning("could not record edge credential material site=%s: %s", site, exc)
    await relay.register(site, conn)
    logger.info(
        "edge connected site=%s version=%s tools=%d mcps=%d",
        site,
        edge_version,
        len(tools),
        len(mcps),
    )
    audit.record("connect", site=site, outcome="ok")

    heartbeat = asyncio.create_task(_heartbeat(conn))
    try:
        while True:
            try:
                frame = await _receive_frame(ws)
                if frame is None:
                    break
                if frame["t"] == "result":
                    # No health event on a successful result: per-call health for a
                    # remote tool is the hub's job. The relay records connectivity only.
                    payload = protocol.validate_result(frame)
                    conn.resolve(payload["id"], payload)
                elif frame["t"] == "ping":
                    # Keepalive only: never answered, or both ends echo forever.
                    continue
                else:  # a second hello
                    await conn.close(code=protocol.CLOSE_MALFORMED)
                    return
            except ProtocolError as exc:
                await conn.close(code=exc.close_code)
                return
    except (WebSocketDisconnect, RuntimeError, EdgeDisconnected):
        pass
    finally:
        heartbeat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat
        conn.closed = True
        relay.unregister(site, conn)
        conn.fail_pending(f"edge '{site}' disconnected")
        logger.info("edge disconnected site=%s", site)
        audit.record("disconnect", site=site, outcome="closed")
        # Record the connectivity transition, but only while this site has no other live
        # tunnel: a superseded socket's handler must not mark the site that replaced it
        # as disconnected (which would make its tools look unconfigured).
        if relay.get(site) is None:
            try:
                await asyncio.to_thread(
                    registry.mark_disconnected, _identity_manager(), site, "socket closed"
                )
            except Exception as exc:
                # A registry hiccup must never mask the disconnect (or the exception
                # that caused it) -- the socket is already gone either way.
                logger.warning("could not record edge disconnect site=%s: %s", site, exc)


@app.post("/v1/sites/{site}/call")
async def call_site_tool(site: str, body: CallBody) -> JSONResponse:
    """Internal-only: hub routes a remote tool here and waits for the edge."""
    started = time.monotonic()
    args_bytes = len(protocol.encode(body.args))
    call_id = uuid.uuid4().hex
    # Filled in after the token is verified; the frame identity (and the audit line)
    # come from the claims, never from the body.
    identity: Dict[str, Optional[str]] = {"user": None, "user_email": None}

    def audit_call(outcome: str, **extra: Any) -> None:
        audit.record(
            "call",
            site=site,
            tool=body.tool,
            call_id=call_id,
            user=identity["user"],
            outcome=outcome,
            ms=int((time.monotonic() - started) * 1000),
            args_bytes=args_bytes,
            # Presence only: the blob is opaque ciphertext and must never be stored.
            has_sealed=body.sealed is not None,
            **extra,
        )

    _warn_body_identity(body)

    try:
        conn = relay.require(site)
    except EdgeOffline as exc:
        audit_call("edge_offline")
        return _error(503, "edge_offline", str(exc))

    # One edge must not be able to pin the hub's call path (or turn a leaked token
    # into a firehose). Checked before any tool work, and audited either way.
    if not limiter.allow(site, conn.rate_limit_per_min):
        audit_call("rate_limited")
        return _error(
            429,
            "rate_limited",
            f"edge '{site}' exceeded its call rate; retry shortly",
        )

    # Authorization before export lookup: an unauthenticated caller must not be
    # able to enumerate a site's exports through 404 vs 403.
    claims, denial = await _authorize_agent(
        body.agent_token, site=site, tool=body.tool
    )
    if denial is not None:
        code, message = denial
        # The token verified even though the allowlist refused: keep the caller on the
        # audit line. No claims means no identity, and none is invented.
        identity["user"] = _claims_identity(claims)[0]
        audit_call("access_denied", agent=claims.agent if claims else None)
        return _error(403, code, message)
    try:
        identity["user"], identity["user_email"] = protocol.validate_identity(
            *_claims_identity(claims)
        )
    except ProtocolError as exc:
        audit_call("invalid_arguments")
        return _error(400, "invalid_arguments", str(exc))

    tool = conn.tools.get(body.tool)
    if tool is None:
        audit_call("unknown_tool")
        return _error(404, "unknown_tool", f"tool '{body.tool}' is not exported by edge '{site}'")

    try:
        protocol.validate_call(
            {
                "id": "http",
                "tool": body.tool,
                "args": body.args,
                "deadline_ms": body.deadline_ms,
                "agent_token": body.agent_token,
                "sealed": body.sealed,
            }
        )
    except ProtocolError as exc:
        audit_call("invalid_arguments")
        return _error(400, "invalid_arguments", str(exc))

    try:
        if "lazy_catalog" in conn.caps and not tool.inputs:
            # The published schema is a summary; the edge validates the real manifest
            # itself, so unknown-key rejection here would make the tool uncallable.
            args = body.args
        else:
            args = protocol.args_for_tool(tool, body.args)
    except ProtocolError as exc:
        audit_call("invalid_arguments")
        return _error(400, "invalid_arguments", str(exc))

    try:
        payload = await conn.request(
            body.tool,
            args,
            body.deadline_ms,
            identity["user"],
            identity["user_email"],
            agent_token=body.agent_token,
            sealed=body.sealed,
        )
    except EdgeOverloaded as exc:
        audit_call("edge_overloaded")
        return _error(503, "edge_overloaded", str(exc))
    except EdgeDisconnected as exc:
        audit_call("edge_disconnected")
        return _error(503, "edge_disconnected", str(exc))
    except EdgeTimeout as exc:
        audit_call("edge_timeout")
        return _error(504, "edge_timeout", str(exc))
    except Exception:
        logger.exception("relay error site=%s tool=%s", site, body.tool)
        audit_call("relay_error")
        return _error(500, "relay_error", "relay failed while forwarding the call")

    if not payload.get("ok"):
        # A tool-level failure is still a completed round trip, not a relay fault.
        audit_call("tool_error")
        return JSONResponse(
            status_code=200,
            content={"tool": body.tool, "error": payload.get("error")},
        )
    audit_call("ok", result_bytes=len(protocol.encode(payload.get("result"))))
    return JSONResponse(
        status_code=200,
        content={"tool": body.tool, "result": payload.get("result")},
    )


@app.post("/v1/sites/{site}/mcps/{mcp}/call")
async def call_site_mcp(site: str, mcp: str, body: McpCallBody) -> JSONResponse:
    """Internal-only: central routes an edge-exported MCP ``tools/call`` here.

    Same contract as the tool endpoint, one deliberate difference: arguments are
    checked as an object within the size cap and forwarded un-coerced. An MCP
    server's schemas are discriminated unions, so the *server* validates them; the
    edge refuses a tool name it did not publish, and that refusal arrives as a
    normal ``200`` with ``error``.
    """
    started = time.monotonic()
    args_bytes = len(protocol.encode(body.args))
    call_id = uuid.uuid4().hex
    identity: Dict[str, Optional[str]] = {"user": None, "user_email": None}

    def audit_call(outcome: str, **extra: Any) -> None:
        audit.record(
            "mcp_call",
            site=site,
            mcp=mcp,
            tool=body.tool,
            call_id=call_id,
            user=identity["user"],
            outcome=outcome,
            ms=int((time.monotonic() - started) * 1000),
            args_bytes=args_bytes,
            # Presence only: never the blob itself.
            has_sealed=body.sealed is not None,
            **extra,
        )

    _warn_body_identity(body)

    try:
        conn = relay.require(site)
    except EdgeOffline as exc:
        audit_call("edge_offline")
        return _error(503, "edge_offline", str(exc))

    # The same bucket as tool calls: one site has one budget, whatever it is asked to
    # run. Checked before the capability/catalog 404s (as on the tool endpoint) so a
    # probe for a non-existent MCP is accounted too.
    if not limiter.allow(site, conn.rate_limit_per_min):
        audit_call("rate_limited")
        return _error(
            429,
            "rate_limited",
            f"edge '{site}' exceeded its call rate; retry shortly",
        )

    # A v0.4 edge claims only "tools": it has no MCP router, so the request can never
    # be served, and saying so beats a timeout against a peer that cannot answer.
    if "mcp" not in conn.caps:
        audit_call("unknown_mcp")
        return _error(404, "unknown_mcp", f"edge '{site}' does not export MCPs")
    if mcp not in conn.mcps:
        audit_call("unknown_mcp")
        return _error(404, "unknown_mcp", f"mcp '{mcp}' is not exported by edge '{site}'")

    # Same gate as the tool route, plus the server grant: the MCP call requires both
    # `permits_mcp` and `permits_tool` for the fully-qualified tool reference.
    try:
        protocol.validate_call(
            {
                "id": "http",
                "kind": "mcp",
                "mcp": mcp,
                "tool": body.tool,
                "args": body.args,
                "deadline_ms": body.deadline_ms,
                "agent_token": body.agent_token,
                "sealed": body.sealed,
            }
        )
    except ProtocolError as exc:
        audit_call("invalid_arguments")
        return _error(400, "invalid_arguments", str(exc))

    claims, denial = await _authorize_agent(
        body.agent_token, site=site, tool=body.tool, mcp=mcp
    )
    if denial is not None:
        code, message = denial
        # As on the tool route: a verified caller stays on the audit line even when
        # the allowlist refuses the call.
        identity["user"] = _claims_identity(claims)[0]
        audit_call("access_denied", agent=claims.agent if claims else None)
        return _error(403, code, message)
    try:
        identity["user"], identity["user_email"] = protocol.validate_identity(
            *_claims_identity(claims)
        )
    except ProtocolError as exc:
        audit_call("invalid_arguments")
        return _error(400, "invalid_arguments", str(exc))

    try:
        payload = await conn.request_mcp(
            mcp,
            body.tool,
            body.args,
            body.deadline_ms,
            identity["user"],
            identity["user_email"],
            agent_token=body.agent_token,
            sealed=body.sealed,
        )
    except EdgeOverloaded as exc:
        audit_call("edge_overloaded")
        return _error(503, "edge_overloaded", str(exc))
    except EdgeDisconnected as exc:
        audit_call("edge_disconnected")
        return _error(503, "edge_disconnected", str(exc))
    except EdgeTimeout as exc:
        audit_call("edge_timeout")
        return _error(504, "edge_timeout", str(exc))
    except Exception:
        logger.exception("relay error site=%s mcp=%s tool=%s", site, mcp, body.tool)
        audit_call("relay_error")
        return _error(500, "relay_error", "relay failed while forwarding the call")

    if not payload.get("ok"):
        # Covers an edge-side refusal (unknown tool, mcp_session_lost, credentials):
        # a completed round trip that failed at the source, not a relay fault.
        audit_call("tool_error")
        return JSONResponse(
            status_code=200,
            content={"tool": body.tool, "error": payload.get("error")},
        )
    audit_call("ok", result_bytes=len(protocol.encode(payload.get("result"))))
    return JSONResponse(
        status_code=200,
        content={"tool": body.tool, "result": payload.get("result")},
    )


def _detail_outcome(exc: Exception) -> str:
    """The error code for one failed detail read (never the exception text)."""
    if isinstance(exc, EdgeOffline):
        return "edge_offline"
    if isinstance(exc, EdgeTimeout):
        return "edge_timeout"
    if isinstance(exc, EdgeDisconnected):
        return "edge_disconnected"
    if isinstance(exc, EdgeOverloaded):
        return "edge_overloaded"
    if isinstance(exc, EdgeUnknownTool):
        return "unknown_tool"
    if isinstance(exc, EdgeUnknownMcp):
        return "unknown_mcp"
    if isinstance(exc, EdgeDetailError):
        return exc.code or "detail_failed"
    return "edge_error"


async def _serve_detail(
    site: str, tool: str, *, mcp: Optional[str] = None
) -> JSONResponse:
    """Cache first, edge second: the body shared by both detail endpoints.

    A live edge is asked and the answer is cached in the tool's own registry record; a
    cached record is served without touching the edge, which is what keeps a schema read
    working while the edge is briefly offline. ``requester`` raising means the edge
    could not answer, and ``registry.fetch_tool_detail`` turns that into a payload --
    this route never propagates an edge failure as an exception.
    """
    started = time.monotonic()
    # Only the outcome of a failed read is recorded here; the payload (a schema) must
    # never reach an audit line.
    failure: Dict[str, str] = {}

    def audit_detail(outcome: str) -> None:
        audit.record(
            "detail",
            site=site,
            tool=tool,
            mcp=mcp,
            outcome=outcome,
            ms=int((time.monotonic() - started) * 1000),
        )

    try:
        # The names become registry key segments, so they get the same rules a hello
        # applies: a crafted site/tool/mcp must not read another record.
        protocol.validate_site_name(site)
        for label, value in (("tool", tool), ("mcp", mcp)):
            if value is None:
                continue
            if "__" in value or not protocol.NAME_RE.fullmatch(value):
                raise ProtocolError(f"invalid {label} name: {value!r}")
    except ProtocolError as exc:
        audit_detail("invalid_request")
        return _error(400, "invalid_request", str(exc))

    conn = relay.get(site)

    async def requester(mcp_name: Optional[str], tool_name: str) -> Dict[str, Any]:
        try:
            if conn is None:
                raise EdgeOffline(f"edge '{site}' is not connected")
            if mcp_name is None:
                return await conn.request_tool_detail(tool_name)
            return await conn.request_mcp_tool_detail(mcp_name, tool_name)
        except Exception as exc:
            failure["outcome"] = _detail_outcome(exc)
            raise

    result = await registry.fetch_tool_detail(
        _identity_manager(), site, tool, requester, mcp=mcp
    )
    if result.get("unavailable"):
        outcome = failure.get("outcome") or "unavailable"
        audit_detail(outcome)
        status = 404 if outcome in ("unknown_tool", "unknown_mcp") else 503
        return _error(
            status,
            outcome,
            str(result.get("reason") or "the edge could not provide this detail"),
        )

    audit_detail("ok")
    content: Dict[str, Any] = {
        "site": site,
        "tool": tool,
        "detail": result.get("detail") or {},
        "description": result.get("description") or "",
        "detail_state": result.get("detail_state") or "full",
        "cached": bool(result.get("cached")),
    }
    if mcp is not None:
        content["mcp"] = mcp
    if result.get("stale"):
        content["stale"] = True
    return JSONResponse(status_code=200, content=content)


@app.post("/v1/sites/{site}/tool_detail")
async def get_site_tool_detail(site: str, body: ToolDetailBody) -> JSONResponse:
    """Internal-only: the hub asks for one exported tool's full inputs.

    Not an agent-token route: the answer is metadata about a tool the caller already
    knows by name, and the caller is the hub/host on the internal network. It is wired
    exactly like ``/call`` -- reachable only from inside the deployment, never through
    the gateway.
    """
    return await _serve_detail(site, body.tool)


@app.post("/v1/sites/{site}/mcp_tool_detail")
async def get_site_mcp_tool_detail(site: str, body: McpToolDetailBody) -> JSONResponse:
    """Internal-only: the hub asks for one MCP tool's full entry (schema included)."""
    return await _serve_detail(site, body.tool, mcp=body.mcp)


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return {
        "status": "ok",
        "sites": {
            site: {
                "connected": True,
                "tools": len(conn.tools),
                "mcps": len(conn.mcps),
                "inflight": len(conn.inflight),
            }
            for site, conn in relay.sites.items()
            if relay.get(site) is conn and not conn.closed
        },
    }
