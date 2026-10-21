# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for the edge relay: token resolution, connection lifecycle, dispatch.

Two failure modes matter most and are easy to get wrong: an HTTP caller must
never hang when a socket dies, and a second connection for a site must evict the
first rather than sit behind a zombie. Both are pinned with a fake WebSocket so
the timing is deterministic.
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketDenialResponse
from starlette.websockets import WebSocketDisconnect

from services.edge_relay import app as app_module
from services.edge_relay import protocol, tokens
from services.edge_relay.ratelimit import SiteLimiter
from services.edge_relay.app import (
    EdgeConn,
    EdgeDisconnected,
    EdgeOverloaded,
    EdgeTimeout,
    EdgeUnknownTool,
    Relay,
)


def _tool(name="echo", **inputs):
    return protocol.EdgeTool(
        name=name,
        inputs=inputs or {"q": {"type": "string", "required": True}},
    )


class _EmptyPrefixClient:
    """The only etcd call the app wiring's registry path makes directly."""

    @staticmethod
    def get_prefix(prefix):
        return []


class FakeEdgeRegistry:
    """Just enough registry for the connect/disconnect wiring (no etcd, no embedder)."""

    def __init__(self):
        self.client = _EmptyPrefixClient()
        self.tools = {}
        self.statuses = {}

    def get_edge_config(self, site):
        return {"name": site, "enabled": True, "exports": [], "public": False, "public_tools": []}

    def save_tool_config(self, name, config):
        self.tools[name] = dict(config)

    def save_edge_status(self, site, status):
        self.statuses[site] = dict(status)

    def get_edge_status(self, site):
        return self.statuses.get(site)


class _NoHealth:
    def __init__(self, identity_mgr):
        self.identity_mgr = identity_mgr

    @staticmethod
    def record_event(*args, **kwargs):
        pass


@pytest.fixture(autouse=True)
def edge_registry(monkeypatch):
    """Keep connect/disconnect off real etcd: they publish a catalog and write status.

    Embeddings are disabled here (`embed_text` -> None) exactly as they are in an
    install with no Google key; ``index_tool`` then writes no vector, which is not
    what these tests are about (``test_edge_registry`` covers the embedding path).
    """
    fake = FakeEdgeRegistry()
    monkeypatch.setattr(app_module, "_identity_manager", lambda: fake)
    monkeypatch.setattr(app_module.registry, "HealthMonitor", _NoHealth)
    monkeypatch.setattr("core.tool_index.embed_text", lambda *args, **kwargs: None)
    return fake


class FakeWebSocket:
    """Duck-types the two WebSocket methods the relay uses."""

    def __init__(self):
        self.sent = []
        self.closed_codes = []

    async def send_text(self, data):
        self.sent.append(protocol.decode(data, protocol.RELAY_FRAMES))

    async def close(self, code=1000, reason=None):
        self.closed_codes.append(code)


def _wait_until(predicate, message, timeout=5.0):
    """Poll a background transition (registration/unregistration runs off the client)."""
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, message
        time.sleep(0.01)


async def _wait_for_frames(ws, count=1, timeout=2.0):
    deadline = time.monotonic() + timeout
    while len(ws.sent) < count:
        if time.monotonic() > deadline:
            raise AssertionError(f"edge sent {len(ws.sent)} frames, expected {count}")
        await asyncio.sleep(0.005)


@pytest.fixture(autouse=True)
def _clean_relay():
    app_module.relay.sites.clear()
    yield
    app_module.relay.sites.clear()


def _install_conn(site="site-a", tools=None):
    conn = EdgeConn(FakeWebSocket(), site, tools or {"echo": _tool()})
    app_module.relay.sites[site] = conn
    return conn


# --- EdgeConn ---------------------------------------------------------------


def test_call_round_trip():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(ws, "site-a", {"echo": _tool()})
        task = asyncio.create_task(conn.request("echo", {"q": "hi"}, 5000, "user-1"))
        await _wait_for_frames(ws)

        frame = ws.sent[0]
        assert frame == {
            "t": "call",
            "id": frame["id"],
            "tool": "echo",
            "args": {"q": "hi"},
            "deadline_ms": 5000,
            "user": "user-1",
        }

        payload = {"id": frame["id"], "ok": True, "result": {"echoed": "hi"}}
        assert conn.resolve(frame["id"], payload) is True
        assert await task == payload
        assert conn.inflight == {}
        assert conn.resolve(frame["id"], payload) is False

    asyncio.run(_scenario())


def test_call_rejects_unknown_tool():
    conn = EdgeConn(FakeWebSocket(), "site-a", {"echo": _tool()})

    async def _scenario():
        with pytest.raises(EdgeUnknownTool):
            await conn.request("nope", {}, 5000)

    asyncio.run(_scenario())


def test_call_rejects_unknown_id_results():
    conn = EdgeConn(FakeWebSocket(), "site-a", {"echo": _tool()})
    assert conn.resolve("missing", {"ok": True}) is False


def test_call_times_out_and_forgets_the_id():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(ws, "site-a", {"echo": _tool()})
        started = time.monotonic()
        with pytest.raises(EdgeTimeout):
            await conn.request("echo", {"q": "hi"}, 1000)
        assert time.monotonic() - started >= 0.9
        # A late result for an expired id is dropped, not raised into a waiter.
        assert conn.inflight == {}
        assert conn.resolve(ws.sent[0]["id"], {"ok": True}) is False

    asyncio.run(_scenario())


def test_call_is_overloaded_at_max_inflight():
    async def _scenario():
        conn = EdgeConn(FakeWebSocket(), "site-a", {"echo": _tool()})
        loop = asyncio.get_running_loop()
        conn.inflight.update(
            {f"id-{i}": loop.create_future() for i in range(protocol.MAX_INFLIGHT)}
        )
        with pytest.raises(EdgeOverloaded):
            await conn.request("echo", {}, 5000)
        for future in conn.inflight.values():
            future.cancel()

    asyncio.run(_scenario())


def test_call_fails_fast_when_the_socket_drops():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(ws, "site-a", {"echo": _tool()})
        task = asyncio.create_task(conn.request("echo", {"q": "hi"}, 30_000))
        await _wait_for_frames(ws)

        conn.fail_pending("edge 'site-a' disconnected")
        with pytest.raises(EdgeDisconnected):
            await task
        assert conn.inflight == {}

    asyncio.run(_scenario())


def test_closed_connection_rejects_new_calls():
    conn = EdgeConn(FakeWebSocket(), "site-a", {"echo": _tool()})
    conn.closed = True

    async def _scenario():
        with pytest.raises(EdgeDisconnected):
            await conn.request("echo", {}, 5000)

    asyncio.run(_scenario())


def test_send_failure_is_surfaced_as_disconnected():
    class BrokenWebSocket(FakeWebSocket):
        async def send_text(self, data):
            raise OSError("socket closed")

    conn = EdgeConn(BrokenWebSocket(), "site-a", {"echo": _tool()})

    async def _scenario():
        with pytest.raises(EdgeDisconnected):
            await conn.request("echo", {}, 5000)
        assert conn.closed is True

    asyncio.run(_scenario())


def test_close_sends_the_given_code():
    ws = FakeWebSocket()
    conn = EdgeConn(ws, "site-a", {})

    asyncio.run(conn.close(protocol.CLOSE_SUPERSEDED))

    assert conn.closed is True
    assert ws.closed_codes == [protocol.CLOSE_SUPERSEDED]


# --- Relay ------------------------------------------------------------------


def test_new_connection_supersedes_the_previous_one():
    async def _scenario():
        relay = Relay()
        old = EdgeConn(FakeWebSocket(), "site-a", {"echo": _tool()})
        new = EdgeConn(FakeWebSocket(), "site-a", {"echo": _tool()})
        await relay.register("site-a", old)

        task = asyncio.create_task(old.request("echo", {"q": "hi"}, 30_000))
        await _wait_for_frames(old.ws)

        await relay.register("site-a", new)

        assert old.closed is True
        assert old.ws.closed_codes == [protocol.CLOSE_SUPERSEDED]
        with pytest.raises(EdgeDisconnected):
            await task
        assert relay.get("site-a") is new

        relay.unregister("site-a", old)
        assert relay.get("site-a") is new
        relay.unregister("site-a", new)
        assert relay.get("site-a") is None

    asyncio.run(_scenario())


def test_require_reports_offline_sites():
    relay = Relay()
    with pytest.raises(app_module.EdgeOffline):
        relay.require("ghost")


# --- HTTP routes ------------------------------------------------------------


def test_offline_site_returns_503():
    client = TestClient(app_module.app)

    response = client.post("/v1/sites/ghost/call", json={"tool": "echo", "args": {}})

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "edge_offline"


def test_unknown_tool_returns_404():
    _install_conn()
    client = TestClient(app_module.app)

    response = client.post("/v1/sites/site-a/call", json={"tool": "missing", "args": {}})

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "unknown_tool"


def test_invalid_arguments_return_400():
    _install_conn()
    client = TestClient(app_module.app)

    response = client.post("/v1/sites/site-a/call", json={"tool": "echo", "args": {"bogus": 1}})

    assert response.status_code == 400
    payload = response.json()["error"]
    assert payload["code"] == "invalid_arguments"
    assert "bogus" in payload["message"]


def test_oversize_args_are_rejected_before_forwarding():
    conn = _install_conn(tools={"echo": _tool("echo", q={"type": "string"})})
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/site-a/call",
        json={"tool": "echo", "args": {"q": "x" * (protocol.MAX_ARGS_BYTES + 1)}},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_arguments"
    assert conn.ws.sent == []


def test_boolean_deadline_is_rejected_by_the_schema():
    _install_conn()
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/site-a/call",
        json={"tool": "echo", "args": {"q": "x"}, "deadline_ms": True},
    )

    assert response.status_code == 422


def test_relay_error_does_not_leak_the_failure():
    conn = _install_conn()
    client = TestClient(app_module.app)

    async def _boom(*args, **kwargs):
        raise RuntimeError("internal detail")

    conn.request = _boom

    response = client.post("/v1/sites/site-a/call", json={"tool": "echo", "args": {"q": "x"}})

    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "relay_error",
        "message": "relay failed while forwarding the call",
    }


def test_healthz_reports_connected_sites():
    _install_conn()
    client = TestClient(app_module.app)

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "sites": {"site-a": {"connected": True, "tools": 1, "inflight": 0}},
    }


def test_healthz_hides_a_closed_connection():
    conn = _install_conn()
    conn.closed = True
    client = TestClient(app_module.app)

    response = client.get("/healthz")

    assert response.json()["sites"] == {}


# --- WebSocket handshake ----------------------------------------------------


def _hello(tools=None, **overrides):
    frame = {
        "t": "hello",
        "proto": protocol.PROTO,
        "edge_version": "0.3.0",
        "tools": tools
        if tools is not None
        else [{"name": "echo", "inputs": {"q": {"type": "string"}}}],
    }
    frame.update(overrides)
    return frame


def _connect(client):
    return client.websocket_connect(
        "/edge/v1/connect",
        subprotocols=[protocol.SUBPROTOCOL],
        headers={"authorization": "Bearer tok"},
    )


def test_handshake_accepts_subprotocol_and_sends_welcome(monkeypatch):
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with client.websocket_connect(
        "/edge/v1/connect",
        subprotocols=[protocol.SUBPROTOCOL],
        headers={"authorization": "Bearer tok"},
    ) as ws:
        assert ws.accepted_subprotocol == protocol.SUBPROTOCOL
        ws.send_json(_hello())
        assert ws.receive_json() == {
            "t": "welcome",
            "site": "site-a",
            "heartbeat_s": protocol.HEARTBEAT_S,
            "max_frame_bytes": protocol.MAX_FRAME_BYTES,
            "max_inflight": protocol.MAX_INFLIGHT,
        }
        # welcome precedes registration on purpose (a call must never be injected
        # into the handshake), so the site becomes dispatchable shortly after.
        _wait_until(
            lambda: app_module.relay.get("site-a") is not None,
            "the site was never registered",
        )

        # An unknown call id is dropped; the socket stays usable.
        ws.send_json({"t": "result", "id": "not-a-call", "ok": True, "result": {}})
        # A ping is never answered, so the next frame the client sees is the
        # close caused by the unknown frame type behind it.
        ws.send_json({"t": "ping"})
        ws.send_json({"t": "wat"})
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == protocol.CLOSE_UNKNOWN_TYPE

    _wait_until(
        lambda: app_module.relay.get("site-a") is None,
        "the relay never released the site",
    )


def test_connect_publishes_the_catalog_and_records_the_disconnect(monkeypatch, edge_registry):
    """The wiring under test: hello -> registry tool configs + status, drop -> disconnected."""
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with _connect(client) as ws:
        ws.send_json(_hello())
        assert ws.receive_json()["t"] == "welcome"
        # welcome is sent before the catalog write finishes (see the ordering note in
        # app.edge_connect), so wait for the publish instead of assuming it.
        _wait_until(
            lambda: "site-a__echo" in edge_registry.tools,
            "the catalog was never published",
        )
        assert edge_registry.tools["site-a__echo"]["runtime"] == "remote"
        assert edge_registry.statuses["site-a"]["connected"] is True
        # Close explicitly: relying on the context manager's teardown races the
        # server handler under a loaded portal, and the test then waits forever for a
        # disconnect that was never delivered.
        ws.close()

    # The handler records the disconnect just after the socket closes; the client's
    # context exit does not synchronise with it, and the registry write itself runs on
    # a worker thread. Poll the in-process map first (the reliable signal), then the
    # registry write, with a deadline that tolerates a loaded test runner.
    deadline = time.monotonic() + 5.0
    while app_module.relay.get("site-a") is not None:
        assert time.monotonic() < deadline, "the relay never released the site"
        time.sleep(0.01)

    deadline = time.monotonic() + 5.0
    while edge_registry.statuses["site-a"]["connected"] is not False:
        assert time.monotonic() < deadline, "disconnect was never recorded"
        time.sleep(0.01)
        time.sleep(0.01)
    assert app_module.relay.get("site-a") is None


@pytest.mark.parametrize(
    "error, code",
    [
        (ValueError("edge 'site-a' is not registered or is disabled"), protocol.CLOSE_REVOKED),
        (RuntimeError("etcd unavailable"), 1011),
    ],
    ids=["site-gone", "registry-error"],
)
def test_publish_failure_closes_the_tunnel(monkeypatch, error, code):
    """A site deleted or revoked mid-handshake must not keep a live socket.

    A registry failure is a different matter: it closes with a server-error code so the
    edge redials normally instead of backing off as if its token were dead.
    """
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})

    def _boom(*args, **kwargs):
        raise error

    monkeypatch.setattr(app_module.registry, "publish_catalog", _boom)
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client) as ws:
            ws.send_json(_hello())
            # welcome comes first now: the site is not dispatchable until the
            # catalog write completes, so no call can be injected mid-handshake.
            assert json.loads(ws.receive_text())["t"] == "welcome"
            ws.receive_text()

    assert exc.value.code == code
    assert app_module.relay.get("site-a") is None


@pytest.mark.parametrize(
    "headers",
    [{}, {"authorization": "Bearer wrong"}],
    ids=["no-token", "wrong-token"],
)
def test_unauthenticated_upgrade_is_rejected(monkeypatch, headers):
    monkeypatch.setattr(app_module, "resolve_token", lambda token: None)
    client = TestClient(app_module.app)

    with pytest.raises((WebSocketDisconnect, WebSocketDenialResponse)) as exc:
        with client.websocket_connect(
            "/edge/v1/connect",
            subprotocols=[protocol.SUBPROTOCOL],
            headers=headers,
        ):
            pass

    rejection = exc.value
    if isinstance(rejection, WebSocketDenialResponse):
        assert rejection.status_code == 401
        assert rejection.json()["error"]["code"] == "unauthorized"
    else:
        assert rejection.code == protocol.CLOSE_REVOKED


@pytest.mark.parametrize(
    "subprotocols",
    [None, ["other.edge.v1"]],
    ids=["none-offered", "wrong-offered"],
)
def test_missing_subprotocol_closes_with_4001(monkeypatch, subprotocols):
    def _resolver(token):
        raise AssertionError("auth must not run before the subprotocol check")

    monkeypatch.setattr(app_module, "resolve_token", _resolver)
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            "/edge/v1/connect",
            subprotocols=subprotocols,
            headers={"authorization": "Bearer tok"},
        ) as ws:
            ws.send_json(_hello())

    assert exc.value.code == protocol.CLOSE_VERSION


def test_invalid_site_name_closes_with_4000(monkeypatch):
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "bad__site"})
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client) as ws:
            ws.send_json(_hello())

    assert exc.value.code == protocol.CLOSE_MALFORMED


def test_binary_frames_are_not_a_handler_crash(monkeypatch):
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client) as ws:
            ws.send_json(_hello())
            assert ws.receive_json()["t"] == "welcome"

            # ``receive_text`` used to raise KeyError on a binary frame.
            ws.send_bytes(b'{"t":"result","id":"not-a-call","ok":true}')
            ws.send_bytes(b"not json")
            ws.receive_text()

    assert exc.value.code == protocol.CLOSE_MALFORMED


def test_unknown_frame_closes_with_4400(monkeypatch):
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client) as ws:
            ws.send_json(_hello())
            assert ws.receive_json()["t"] == "welcome"
            ws.send_json({"t": "wat"})
            ws.receive_text()

    assert exc.value.code == protocol.CLOSE_UNKNOWN_TYPE


def test_non_hello_first_frame_closes_with_4000(monkeypatch):
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client) as ws:
            ws.send_json({"t": "ping"})
            ws.receive_text()

    assert exc.value.code == protocol.CLOSE_MALFORMED


def test_version_mismatch_closes_with_4001(monkeypatch):
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client) as ws:
            ws.send_json(_hello(proto=protocol.PROTO + 1))
            ws.receive_text()

    assert exc.value.code == protocol.CLOSE_VERSION


def test_duplicate_tool_names_close_with_4000(monkeypatch):
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client) as ws:
            ws.send_json(_hello(tools=[{"name": "dup"}, {"name": "dup"}]))
            ws.receive_text()

    assert exc.value.code == protocol.CLOSE_MALFORMED


# --- Tokens -----------------------------------------------------------------


class FakeRegistry:
    """Mirrors the two methods `resolve_token` uses, including the enabled rule."""

    def __init__(self, tokens=None, configs=None, error=None):
        self.tokens = tokens or {}
        self.configs = configs if configs is not None else {}
        self.error = error
        self.calls = []

    def resolve_edge_token(self, token):
        self.calls.append(("resolve", token))
        if self.error is not None:
            raise self.error
        site = self.tokens.get(token)
        if not site:
            return None
        return site if (self.configs.get(site) or {}).get("enabled", True) else None

    def get_edge_config(self, site):
        if self.error is not None:
            raise self.error
        return self.configs.get(site)


def test_hash_token_is_sha256_hex():
    assert tokens.hash_token("abc") == hashlib.sha256(b"abc").hexdigest()


def test_resolve_token_resolves_through_the_hash_index():
    registry = FakeRegistry(
        tokens={"secret": "plant-floor"},
        configs={"plant-floor": {"token_hash": tokens.hash_token("secret"), "display_name": "Plant"}},
    )

    resolved = tokens.resolve_token("secret", identity_mgr=registry)

    assert resolved == {
        "token_hash": tokens.hash_token("secret"),
        "display_name": "Plant",
        "name": "plant-floor",
    }
    # One indexed lookup, never a scan of every site: this runs before accept().
    assert registry.calls == [("resolve", "secret")]


def test_resolve_token_rejects_unknown_and_disabled_sites():
    unknown = FakeRegistry()
    assert tokens.resolve_token("secret", identity_mgr=unknown) is None

    disabled = FakeRegistry(
        tokens={"secret": "site-a"}, configs={"site-a": {"enabled": False}}
    )
    assert tokens.resolve_token("secret", identity_mgr=disabled) is None


def test_resolve_token_swallows_registry_errors_without_logging_the_token(caplog):
    registry = FakeRegistry(error=RuntimeError("etcd unavailable"))

    with caplog.at_level(logging.WARNING, logger="services.edge_relay.tokens"):
        assert tokens.resolve_token("super-secret-token", identity_mgr=registry) is None

    assert "registry unavailable" in caplog.text
    assert "super-secret-token" not in caplog.text


def test_resolve_token_ignores_a_missing_config():
    """An index entry whose site record vanished must not authenticate anything."""
    registry = FakeRegistry(tokens={"secret": "plant-floor"})

    assert tokens.resolve_token("secret", identity_mgr=registry) is None


def test_dev_escape_hatch_requires_dev_mode(monkeypatch):
    monkeypatch.setenv("EDGE_DEV_TOKEN", "dev-token")
    monkeypatch.setenv("EDGE_DEV_SITE", "dev-site")
    monkeypatch.setenv("DEV_MODE", "true")
    assert tokens.resolve_token("dev-token") == {"name": "dev-site", "enabled": True}

    monkeypatch.setenv("DEV_MODE", "false")
    registry = FakeRegistry()
    assert tokens.resolve_token("dev-token", identity_mgr=registry) is None


# --- End to end -------------------------------------------------------------


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_server(port, timeout=10.0):
    import httpx

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(
                f"http://127.0.0.1:{port}/healthz", timeout=0.5, trust_env=False
            ).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    raise AssertionError("relay did not start")


@contextlib.contextmanager
def _live_relay(monkeypatch, resolver):
    """Run the relay on a real socket; yields ``(ws_url, http_url)``."""
    import uvicorn

    monkeypatch.setattr(app_module, "resolve_token", resolver)
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app_module.app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        _wait_for_server(port)
        yield f"ws://127.0.0.1:{port}/edge/v1/connect", f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        assert not thread.is_alive()


def test_end_to_end_tunnel_call(monkeypatch):
    """A real WebSocket client through a real server, then a real HTTP call."""
    import httpx
    from websockets.asyncio.client import connect

    def resolver(token):
        return {"name": "site-a"} if token == "tok" else None

    with _live_relay(monkeypatch, resolver) as (ws_url, http_url):
        async def _scenario():
            async with connect(
                ws_url,
                additional_headers={"Authorization": "Bearer tok"},
                subprotocols=[protocol.SUBPROTOCOL],
                proxy=None,
                max_size=protocol.MAX_FRAME_BYTES,
            ) as ws:
                await ws.send(
                    protocol.encode(
                        {
                            "t": "hello",
                            "proto": protocol.PROTO,
                            "edge_version": "test",
                            "tools": [
                                {
                                    "name": "echo",
                                    "inputs": {"q": {"type": "string", "required": True}},
                                }
                            ],
                        }
                    )
                )
                welcome = protocol.decode(await ws.recv(), protocol.RELAY_FRAMES)
                assert welcome["t"] == "welcome"
                assert welcome["site"] == "site-a"

                async def edge_loop():
                    while True:
                        frame = protocol.decode(await ws.recv(), protocol.RELAY_FRAMES)
                        if frame["t"] == "call":
                            await ws.send(
                                protocol.encode(
                                    {
                                        "t": "result",
                                        "id": frame["id"],
                                        "ok": True,
                                        "result": {"echoed": frame["args"]},
                                        "ms": 1,
                                    }
                                )
                            )

                responder = asyncio.create_task(edge_loop())
                try:
                    async with httpx.AsyncClient(
                        base_url=http_url, trust_env=False
                    ) as client:
                        response = await client.post(
                            "/v1/sites/site-a/call",
                            json={
                                "tool": "echo",
                                "args": {"q": "hi"},
                                "deadline_ms": 5000,
                                "user": "u1",
                            },
                        )
                        assert response.json() == {
                            "tool": "echo",
                            "result": {"echoed": {"q": "hi"}},
                        }

                        health = (await client.get("/healthz")).json()
                        assert health["sites"]["site-a"]["tools"] == 1
                finally:
                    responder.cancel()
                    await asyncio.gather(responder, return_exceptions=True)

        asyncio.run(_scenario())


def test_superseded_socket_does_not_mark_the_site_disconnected(monkeypatch, edge_registry):
    """A redeploy evicts the old socket; the site stays 'connected' for the new one."""
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed

    def resolver(token):
        return {"name": "site-a"} if token == "tok" else None

    with _live_relay(monkeypatch, resolver) as (ws_url, _http_url):
        async def _open():
            return await connect(
                ws_url,
                additional_headers={"Authorization": "Bearer tok"},
                subprotocols=[protocol.SUBPROTOCOL],
                proxy=None,
                max_size=protocol.MAX_FRAME_BYTES,
            ).__aenter__()

        async def _scenario():
            first = await _open()
            await first.send(protocol.encode(_hello()))
            assert protocol.decode(await first.recv(), protocol.RELAY_FRAMES)["t"] == "welcome"

            second = await _open()
            await second.send(protocol.encode(_hello()))
            assert protocol.decode(await second.recv(), protocol.RELAY_FRAMES)["t"] == "welcome"

            # The eviction closes the first socket; its handler's finally then runs.
            with pytest.raises(ConnectionClosed):
                await first.recv()
            for _ in range(200):
                if edge_registry.statuses.get("site-a", {}).get("connected") is True:
                    break
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.2)

            assert edge_registry.statuses["site-a"]["connected"] is True
            assert app_module.relay.get("site-a") is not None
            await second.close()

        asyncio.run(_scenario())


def test_inbound_ping_is_never_answered(monkeypatch):
    from websockets.asyncio.client import connect

    def resolver(token):
        return {"name": "site-a"} if token == "tok" else None

    with _live_relay(monkeypatch, resolver) as (ws_url, _http_url):
        async def _scenario():
            async with connect(
                ws_url,
                additional_headers={"Authorization": "Bearer tok"},
                subprotocols=[protocol.SUBPROTOCOL],
                proxy=None,
                max_size=protocol.MAX_FRAME_BYTES,
            ) as ws:
                await ws.send(protocol.encode(_hello()))
                assert protocol.decode(await ws.recv(), protocol.RELAY_FRAMES)["t"] == "welcome"

                await ws.send(protocol.encode({"t": "ping"}))
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(ws.recv(), timeout=0.5)

                # Ignoring the ping must not have broken the tunnel.
                await ws.send(
                    protocol.encode({"t": "result", "id": "not-a-call", "ok": True})
                )
                await ws.send(protocol.encode({"t": "ping"}))
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(ws.recv(), timeout=0.5)

        asyncio.run(_scenario())


# --- enrollment revalidation / startup status --------------------------------------
#
# The token is only validated during the upgrade, and the heartbeat is what keeps a
# tunnel alive. Without an explicit re-check, revoking a leaked token would leave the
# attacker's established socket forwarding calls indefinitely.


def test_revoked_site_closes_its_live_socket(monkeypatch):
    conn = _install_conn(site="plant-floor")

    class _Mgr:
        def get_edge_config(self, site):
            return {"name": site, "enabled": False}

    monkeypatch.setattr(app_module, "_identity_manager", lambda: _Mgr())
    monkeypatch.setattr(app_module, "HEARTBEAT_S", 0.01)

    async def run():
        await asyncio.wait_for(app_module._heartbeat(conn), timeout=2)

    asyncio.run(run())

    assert conn.ws.closed_codes == [protocol.CLOSE_REVOKED]


def test_deleted_site_closes_its_live_socket(monkeypatch):
    conn = _install_conn(site="plant-floor")

    class _Mgr:
        def get_edge_config(self, site):
            return None

    monkeypatch.setattr(app_module, "_identity_manager", lambda: _Mgr())
    monkeypatch.setattr(app_module, "HEARTBEAT_S", 0.01)

    asyncio.run(asyncio.wait_for(app_module._heartbeat(conn), timeout=2))

    assert conn.ws.closed_codes == [protocol.CLOSE_REVOKED]


def test_heartbeat_keeps_the_tunnel_when_revalidation_errors(monkeypatch):
    """An etcd blip is not a revocation: never kill a healthy tunnel over it."""
    conn = _install_conn(site="plant-floor")

    class _Mgr:
        def get_edge_config(self, site):
            raise RuntimeError("etcd unavailable")

    monkeypatch.setattr(app_module, "_identity_manager", lambda: _Mgr())
    monkeypatch.setattr(app_module, "HEARTBEAT_S", 0.01)

    async def run():
        task = asyncio.create_task(app_module._heartbeat(conn))
        await _wait_for_frames(conn.ws, count=1)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(run())

    assert conn.ws.closed_codes == []
    assert conn.ws.sent[0]["t"] == "ping"


def test_startup_clears_connected_status_for_every_site(monkeypatch):
    seen = []

    class _Mgr:
        def list_edges(self):
            return ["plant-floor", "warehouse"]

        def get_edge_status(self, site):
            return {"connected": site == "plant-floor"}

    monkeypatch.setattr(app_module, "_identity_manager", lambda: _Mgr())
    monkeypatch.setattr(
        app_module.registry,
        "mark_disconnected",
        lambda mgr, site, reason: seen.append((site, reason)),
    )

    app_module._mark_all_disconnected("relay restarted")

    # Only a site that still claims to be connected needs the correction.
    assert seen == [("plant-floor", "relay restarted")]


# --- per-site rate limit + audit ----------------------------------------------------


def test_rate_limit_returns_429_and_never_forwards(monkeypatch):
    conn = _install_conn()
    # Capacity of one: the first call consumes it, the second is refused.
    monkeypatch.setattr(app_module, "limiter", SiteLimiter(default_rate_per_min=1))
    app_module.limiter.allow("site-a")  # burn the only token
    client = TestClient(app_module.app)

    response = client.post("/v1/sites/site-a/call", json={"tool": "echo", "args": {}})

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"
    assert conn.ws.sent == []


def test_rate_limit_can_be_overridden_per_site(monkeypatch):
    _install_conn()
    monkeypatch.setattr(app_module, "limiter", SiteLimiter(default_rate_per_min=1))
    app_module.relay.sites["site-a"].rate_limit_per_min = 600
    client = TestClient(app_module.app)

    # An unknown tool keeps the call from being forwarded (which would wait out the
    # deadline against a fake socket); reaching 404 proves the limiter let it through.
    response = client.post("/v1/sites/site-a/call", json={"tool": "missing", "args": {}})

    assert response.status_code == 404


def test_every_call_outcome_is_audited_without_payloads(monkeypatch):
    calls = []
    monkeypatch.setattr(
        app_module.audit, "record", lambda event, **kw: calls.append({"event": event, **kw})
    )
    _install_conn()
    client = TestClient(app_module.app)

    client.post("/v1/sites/ghost/call", json={"tool": "echo", "args": {"q": "secret-value"}})
    client.post("/v1/sites/site-a/call", json={"tool": "missing", "args": {"q": "secret-value"}})
    monkeypatch.setattr(app_module, "limiter", SiteLimiter(default_rate_per_min=1))
    app_module.limiter.allow("site-a")
    client.post("/v1/sites/site-a/call", json={"tool": "missing", "args": {}})

    outcomes = [c["outcome"] for c in calls]
    assert outcomes == ["edge_offline", "unknown_tool", "rate_limited"]
    serialised = str(calls)
    assert "secret-value" not in serialised
    assert all("args" not in c for c in calls)


def test_site_is_not_dispatchable_while_its_catalog_is_publishing(monkeypatch):
    """A call injected into the handshake would make the edge die on 'expected welcome'."""
    seen = {}

    def _publish(*args, **kwargs):
        seen["during"] = app_module.relay.get("site-a")

    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    monkeypatch.setattr(app_module.registry, "publish_catalog", _publish)
    client = TestClient(app_module.app)

    with _connect(client) as ws:
        ws.send_json(_hello())
        assert json.loads(ws.receive_text())["t"] == "welcome"

    assert seen["during"] is None


def test_rotating_the_token_closes_the_live_tunnel(monkeypatch):
    """`enabled` stays true across a rotation, so the hash is what proves freshness."""
    conn = _install_conn(site="plant-floor")
    conn.token_hash = "digest-of-the-old-token"

    class _Mgr:
        def get_edge_config(self, site):
            return {"name": site, "enabled": True, "token_hash": "digest-of-the-new-token"}

    monkeypatch.setattr(app_module, "_identity_manager", lambda: _Mgr())
    monkeypatch.setattr(app_module, "HEARTBEAT_S", 0.01)

    asyncio.run(asyncio.wait_for(app_module._heartbeat(conn), timeout=2))

    assert conn.ws.closed_codes == [protocol.CLOSE_REVOKED]


def test_unchanged_token_hash_keeps_the_tunnel(monkeypatch):
    conn = _install_conn(site="plant-floor")
    conn.token_hash = "same-digest"

    class _Mgr:
        def get_edge_config(self, site):
            return {"name": site, "enabled": True, "token_hash": "same-digest"}

    monkeypatch.setattr(app_module, "_identity_manager", lambda: _Mgr())
    monkeypatch.setattr(app_module, "HEARTBEAT_S", 0.01)

    async def run():
        task = asyncio.create_task(app_module._heartbeat(conn))
        await _wait_for_frames(conn.ws, count=1)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(run())

    assert conn.ws.closed_codes == []


def test_heartbeat_republishes_after_an_admin_changes_the_exports(monkeypatch):
    """An un-exported tool must stop being callable without waiting for a reconnect."""
    conn = _install_conn(site="plant-floor")
    conn.published_signature = (("echo",), False, (), None)
    conn.edge_version = "0.3.0"
    published = []

    class _Mgr:
        def get_edge_config(self, site):
            return {
                "name": site,
                "enabled": True,
                "exports": ["echo", "new_tool"],
                "public": True,
                "public_tools": [],
                "rate_limit_per_min": 30,
            }

    monkeypatch.setattr(app_module, "_identity_manager", lambda: _Mgr())
    monkeypatch.setattr(
        app_module.registry,
        "publish_catalog",
        lambda mgr, site, tools, version, **kwargs: published.append(
            (site, len(tools), version)
        ) or [],
    )
    monkeypatch.setattr(app_module, "HEARTBEAT_S", 0.01)

    async def run():
        task = asyncio.create_task(app_module._heartbeat(conn))
        # The keepalive is sent first; the republish follows it on the same beat.
        await _wait_for_frames(conn.ws, count=1)
        for _ in range(200):
            if published:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(run())

    assert published == [("plant-floor", 1, "0.3.0")]
    assert conn.rate_limit_per_min == 30
    assert conn.published_signature == (("echo", "new_tool"), True, (), 30)


def test_heartbeat_does_not_republish_without_an_admin_change(monkeypatch):
    conn = _install_conn(site="plant-floor")
    conn.published_signature = ((), False, (), None)
    published = []

    class _Mgr:
        def get_edge_config(self, site):
            return {"name": site, "enabled": True, "exports": [], "public": False,
                    "public_tools": [], "rate_limit_per_min": None}

    monkeypatch.setattr(app_module, "_identity_manager", lambda: _Mgr())
    monkeypatch.setattr(
        app_module.registry, "publish_catalog", lambda *args, **kwargs: published.append(args)
    )
    monkeypatch.setattr(app_module, "HEARTBEAT_S", 0.01)

    async def run():
        task = asyncio.create_task(app_module._heartbeat(conn))
        await _wait_for_frames(conn.ws, count=1)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(run())

    assert published == []


def test_an_admin_export_change_is_allowed_to_empty_the_catalog(monkeypatch):
    """An explicit admin narrowing is intent, unlike a handshake that sent nothing."""
    conn = _install_conn(site="plant-floor")
    conn.published_signature = (("echo",), False, (), None)
    seen = {}

    class _Mgr:
        def get_edge_config(self, site):
            return {"name": site, "enabled": True, "exports": [], "public": False,
                    "public_tools": [], "rate_limit_per_min": None}

    monkeypatch.setattr(app_module, "_identity_manager", lambda: _Mgr())
    monkeypatch.setattr(
        app_module.registry,
        "publish_catalog",
        lambda *args, **kwargs: seen.update(kwargs) or [],
    )
    monkeypatch.setattr(app_module, "HEARTBEAT_S", 0.01)

    async def run():
        task = asyncio.create_task(app_module._heartbeat(conn))
        await _wait_for_frames(conn.ws, count=1)
        for _ in range(200):
            if seen:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(run())

    assert seen.get("allow_empty") is True
