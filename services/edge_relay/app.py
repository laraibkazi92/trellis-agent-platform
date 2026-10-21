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
import time
import uuid
from typing import Annotated, Any, Dict, Optional

from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.websockets import WebSocketDisconnect

from services.edge_relay import audit, protocol, registry
from services.edge_relay.ratelimit import SiteLimiter, normalise_rate
from services.edge_relay.protocol import (
    DEFAULT_DEADLINE_MS,
    HEARTBEAT_S,
    MAX_DEADLINE_MS,
    MAX_FRAME_BYTES,
    MAX_INFLIGHT,
    SUBPROTOCOL,
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


class EdgeOffline(Exception):
    """No live connection for the site."""


class EdgeUnknownTool(Exception):
    """The site never published this tool."""


class EdgeOverloaded(Exception):
    """The site already has MAX_INFLIGHT calls in flight."""


class EdgeTimeout(Exception):
    """The edge did not answer before the caller's deadline."""


class EdgeDisconnected(Exception):
    """The socket went away while the call was pending."""


def _consume_exception(future: "asyncio.Future[Any]") -> None:
    """Mark a failed future as retrieved so an abandoned call cannot warn."""
    if not future.cancelled():
        future.exception()


class EdgeConn:
    """One accepted edge socket: its catalog, its pending calls, its liveness."""

    def __init__(self, ws: Any, site: str, tools: Optional[Dict[str, EdgeTool]] = None):
        self.ws = ws
        self.site = site
        self.tools: Dict[str, EdgeTool] = dict(tools or {})
        self.inflight: Dict[str, "asyncio.Future[Any]"] = {}
        self.closed = False
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
    ) -> Dict[str, Any]:
        """Forward one call and await its validated result frame.

        The deadline is clamped here as well as on the edge so the local timer
        and the frame's ``deadline_ms`` cannot disagree.
        """
        if self.closed:
            raise EdgeDisconnected(f"edge '{self.site}' is closed")
        if tool not in self.tools:
            raise EdgeUnknownTool(f"tool '{tool}' is not exported by edge '{self.site}'")
        if len(self.inflight) >= MAX_INFLIGHT:
            raise EdgeOverloaded(f"edge '{self.site}' is at {MAX_INFLIGHT} in-flight calls")

        timeout_ms = max(1_000, min(int(deadline_ms), MAX_DEADLINE_MS))
        call_id = uuid.uuid4().hex
        future: "asyncio.Future[Any]" = asyncio.get_running_loop().create_future()
        future.add_done_callback(_consume_exception)
        self.inflight[call_id] = future
        started = time.perf_counter()

        try:
            await self.send(
                {
                    "t": "call",
                    "id": call_id,
                    "tool": tool,
                    "args": args,
                    "deadline_ms": timeout_ms,
                    "user": user,
                }
            )
            try:
                payload = await asyncio.wait_for(future, timeout_ms / 1000)
            except asyncio.TimeoutError:
                self._log(tool, call_id, started, "timeout")
                raise EdgeTimeout(
                    f"edge '{self.site}' did not answer '{tool}' within {timeout_ms}ms"
                ) from None
            except BaseException:
                self._log(tool, call_id, started, "error")
                raise
        finally:
            self.inflight.pop(call_id, None)

        self._log(tool, call_id, started, "ok" if payload.get("ok") else "tool_error")
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

    def _log(self, tool: str, call_id: str, started: float, outcome: str) -> None:
        logger.info(
            "edge call site=%s tool=%s id=%s duration_ms=%d outcome=%s",
            self.site,
            tool,
            call_id,
            int((time.perf_counter() - started) * 1000),
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
    """
    signature = _catalog_signature(config)
    conn.rate_limit_per_min = config.get("rate_limit_per_min")
    if conn.published_signature is None or signature == conn.published_signature:
        return
    try:
        published = await asyncio.to_thread(
            registry.publish_catalog,
            _identity_manager(),
            conn.site,
            list(conn.tools.values()),
            conn.edge_version,
            allow_empty=True,
        )
    except Exception:
        logger.exception("could not refresh the catalog for site=%s", conn.site)
        return
    conn.published_signature = signature
    logger.info(
        "edge catalog refreshed from admin changes site=%s tools=%d",
        conn.site,
        len(published),
    )


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
    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)
    # Strict: pydantic would otherwise accept ``true`` as ``1``.
    deadline_ms: Annotated[int, Field(strict=True)] = DEFAULT_DEADLINE_MS
    user: Optional[str] = None


def _catalog_signature(config: Dict[str, Any]) -> tuple:
    """The admin-editable fields that change what a site publishes or how fast."""
    return (
        tuple(config.get("exports") or []),
        bool(config.get("public")),
        tuple(config.get("public_tools") or []),
        config.get("rate_limit_per_min"),
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
        _, edge_version, tools = protocol.validate_hello(frame)
    except ProtocolError as exc:
        await ws.close(code=exc.close_code)
        return
    except (WebSocketDisconnect, RuntimeError):
        return

    conn = EdgeConn(ws, site, {tool.name: tool for tool in tools})
    conn.rate_limit_per_min = config.get("rate_limit_per_min")
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
            registry.publish_catalog, _identity_manager(), site, tools, edge_version
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

    conn.published_signature = _catalog_signature(config)
    conn.edge_version = edge_version
    await relay.register(site, conn)
    logger.info("edge connected site=%s version=%s tools=%d", site, edge_version, len(tools))
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

    def audit_call(outcome: str, **extra: Any) -> None:
        audit.record(
            "call",
            site=site,
            tool=body.tool,
            call_id=call_id,
            user=body.user,
            outcome=outcome,
            ms=int((time.monotonic() - started) * 1000),
            args_bytes=args_bytes,
            **extra,
        )

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
            }
        )
    except ProtocolError as exc:
        audit_call("invalid_arguments")
        return _error(400, "invalid_arguments", str(exc))

    try:
        args = protocol.args_for_tool(tool, body.args)
    except ProtocolError as exc:
        audit_call("invalid_arguments")
        return _error(400, "invalid_arguments", str(exc))

    try:
        payload = await conn.request(body.tool, args, body.deadline_ms, body.user)
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


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return {
        "status": "ok",
        "sites": {
            site: {"connected": True, "tools": len(conn.tools), "inflight": len(conn.inflight)}
            for site, conn in relay.sites.items()
            if relay.get(site) is conn and not conn.closed
        },
    }
