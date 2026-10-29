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
from core import agent_token as agent_token_module

AGENT_SECRET = "test-agent-token-secret-0123456789abcdef"


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
        self.mcps = {}
        self.statuses = {}
        # Site records: the relay merges the hello credential material into these.
        self.edge_configs = {}
        # Agent records the enforcement path resolves (name -> config dict).
        self.agents = {}

    def get_edge_config(self, site):
        return self.edge_configs.get(site) or {
            "name": site,
            "enabled": True,
            "exports": [],
            "public": False,
            "public_tools": [],
        }

    def save_edge_config(self, site, config):
        self.edge_configs[site] = dict(config)

    def get_agent_config(self, name):
        return self.agents.get(name)

    def get_tool_config(self, name):
        return self.tools.get(name)

    def get_mcp_config(self, name):
        return self.mcps.get(name)

    def save_tool_config(self, name, config):
        self.tools[name] = dict(config)

    def save_mcp_config(self, name, config):
        self.mcps[name] = dict(config)

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


@pytest.fixture(autouse=True)
def _agent_token_env(monkeypatch):
    """Startup refuses to run without a key, so every test gets one.

    ``ENFORCE_AGENT_TOKENS=log`` here: the enforcement tests set ``enforce``
    explicitly, and the rest of the suite keeps its pre-token behaviour (a call with
    no token is logged and forwarded).
    """
    monkeypatch.setenv("AGENT_TOKEN_SECRET", AGENT_SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")


@pytest.fixture(autouse=True)
def _hermetic_tool_access(monkeypatch):
    """The relay asks :mod:`core.tool_access`; keep it off etcd.

    An absent policy document means "no group rules", so the agent allowlist alone
    decides -- the pre-v0.7.1 behaviour these tests were written against.
    """
    from core import tool_access

    class _NoPolicy:
        def put(self, key, value):
            raise AssertionError(f"no write expected: {key}")

        def get(self, key, **_kwargs):
            return None, None

    monkeypatch.setattr(tool_access, "_client", lambda: _NoPolicy())
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()
    yield
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()


@pytest.fixture(autouse=True)
def _body_identity_warning_armed():
    """The one-shot body-identity warning is process-global: re-arm it per test."""
    app_module._BODY_IDENTITY_WARNED = False
    yield
    app_module._BODY_IDENTITY_WARNED = False


def _install_conn(site="site-a", tools=None, mcps=None, caps=None):
    if caps is None and mcps:
        caps = ["tools", "mcp"]
    conn = EdgeConn(
        FakeWebSocket(),
        site,
        tools or {"echo": _tool()},
        mcps or {},
        caps,
    )
    app_module.relay.sites[site] = conn
    return conn


def _mcp(name="devops-cli", transport="stdio", tools=None):
    return protocol.EdgeMcp(
        name=name,
        transport=transport,
        tools=tools
        or [
            protocol.EdgeMcpTool(
                name="tenant_account_tools",
                description="manage tenants",
                input_schema={
                    "type": "object",
                    "oneOf": [{"properties": {"action": {"const": "list_actions"}}}],
                },
            )
        ],
    )


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


def test_call_frame_carries_the_caller_email():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(ws, "site-a", {"echo": _tool()})
        task = asyncio.create_task(
            conn.request("echo", {"q": "hi"}, 5000, "u1", "ann@example.com")
        )
        await _wait_for_frames(ws)

        frame = ws.sent[0]
        assert frame["user"] == "u1"
        assert frame["user_email"] == "ann@example.com"

        assert conn.resolve(frame["id"], {"id": frame["id"], "ok": True, "result": {}}) is True
        await task

    asyncio.run(_scenario())


def test_call_frame_omits_user_email_when_not_given():
    """A call with no email must stay byte-identical to v0.4 (no null key)."""

    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(ws, "site-a", {"echo": _tool()})
        task = asyncio.create_task(conn.request("echo", {"q": "hi"}, 5000, "u1"))
        await _wait_for_frames(ws)

        frame = ws.sent[0]
        assert "user_email" not in frame
        assert frame["user"] == "u1"

        conn.resolve(frame["id"], {"id": frame["id"], "ok": True, "result": {}})
        await task

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


def test_call_body_has_no_identity_fields():
    """v0.7.1 removed them: identity comes from the token claims, not the body."""
    assert "user" not in app_module.CallBody.model_fields
    assert "user_email" not in app_module.CallBody.model_fields
    assert set(app_module.CallBody.model_fields) == {
        "tool",
        "args",
        "deadline_ms",
        "agent_token",
        "sealed",
    }


def test_the_frame_identity_comes_from_the_claims_only(enforcing):
    """A body identity is inert: only the verified token's claims reach the edge."""
    conn = _install_conn()
    seen = {}

    async def _record(
        tool,
        args,
        deadline_ms,
        user=None,
        user_email=None,
        agent=None,
        groups=None,
        run_id=None,
        parent_run_id=None,
        sealed=None,
    ):
        seen.update(
            tool=tool,
            user=user,
            user_email=user_email,
            agent=agent,
            groups=groups,
            run_id=run_id,
            parent_run_id=parent_run_id,
            sealed=sealed,
        )
        return {"id": "x", "ok": True, "result": {"echoed": args}}

    conn.request = _record
    token = _mint(user_id="claim-user", user_email="claims@example.com")
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/site-a/call",
        json={
            "tool": "echo",
            "args": {"q": "x"},
            # Both are ignored: they are not fields of the body any more.
            "user": "body-user",
            "user_email": "body@example.com",
            "agent_token": token,
        },
    )

    assert response.status_code == 200
    # The run id is minted fresh per token, so compare it to the claims itself.
    claims = agent_token_module.verify(token)
    assert seen == {
        "tool": "echo",
        "user": "claim-user",
        "user_email": "claims@example.com",
        # Run attribution comes from the same claims, never the body.
        "agent": "agent-a",
        "groups": None,
        "run_id": claims.run_id,
        "parent_run_id": None,
        "sealed": None,
    }


def test_a_body_identity_is_logged_once_and_ignored(caplog):
    """The stale-caller aid: one warning naming the fields, then silence."""
    conn = _install_conn()
    client = TestClient(app_module.app)

    # The warning is emitted before dispatch; answer the call so the test does not
    # wait out the real deadline.
    async def _answer(*args, **kwargs):
        return {"id": "x", "ok": True, "result": {}}

    conn.request = _answer

    body = {"tool": "echo", "args": {"q": "x"}, "user": "body-user"}
    assert client.post("/v1/sites/site-a/call", json=body).status_code == 200
    assert client.post("/v1/sites/site-a/call", json=body).status_code == 200

    lines = [r for r in caplog.records if "ignoring" in r.getMessage()]
    assert len(lines) == 1
    assert "user" in lines[0].getMessage()


def test_a_call_without_a_token_has_no_identity(in_log_mode):
    """No verified token: no identity travels, and none is invented."""
    conn = _install_conn()
    seen = {}

    async def _record(*args, **kwargs):
        seen.update(
            user=kwargs.get("user"),
            user_email=kwargs.get("user_email"),
            agent=kwargs.get("agent"),
            groups=kwargs.get("groups"),
            run_id=kwargs.get("run_id"),
            parent_run_id=kwargs.get("parent_run_id"),
        )
        return {"id": "x", "ok": True, "result": {}}

    conn.request = _record

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call", json={"tool": "echo", "args": {"q": "x"}}
    )

    assert response.status_code == 200
    assert seen == {
        "user": None,
        "user_email": None,
        "agent": None,
        "groups": None,
        "run_id": None,
        "parent_run_id": None,
    }


def test_a_malformed_claims_email_is_rejected_before_forwarding(enforcing):
    """The edge closes the tunnel on a bad call frame, so the relay must pre-filter."""
    conn = _install_conn()
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/site-a/call",
        json={
            "tool": "echo",
            "args": {"q": "x"},
            "agent_token": _mint(user_email="ann@example.com\n"),
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_arguments"
    assert conn.ws.sent == []


def test_a_malformed_claims_group_is_rejected_before_forwarding(enforcing):
    """Same rule for the run identity: a claim the edge would refuse never leaves here.

    A bad value on arrival closes the tunnel, so the relay validates with the edge's own
    rules first (R1: this is the only place a malformed claim can be caught).
    """
    conn = _install_conn()
    conn.request = pytest.fail

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={
            "tool": "echo",
            "args": {"q": "x"},
            "agent_token": _mint(groups=("ops\nprod",)),
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_arguments"
    assert conn.ws.sent == []


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


# --- MCP routing ------------------------------------------------------------


def test_mcp_call_round_trip_carries_kind_and_mcp():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(
            ws, "site-a", {"echo": _tool()}, {"devops-cli": _mcp()}, ["tools", "mcp"]
        )
        task = asyncio.create_task(
            conn.request_mcp(
                "devops-cli", "tenant_account_tools", {"action": "list_actions"}, 5000, "u1"
            )
        )
        await _wait_for_frames(ws)

        frame = ws.sent[0]
        assert frame == {
            "t": "call",
            "id": frame["id"],
            "kind": "mcp",
            "mcp": "devops-cli",
            "tool": "tenant_account_tools",
            "args": {"action": "list_actions"},
            "deadline_ms": 5000,
            "user": "u1",
        }
        # Same rule as a tool call: an absent email stays absent (v0.4-sized frame).
        assert "user_email" not in frame

        payload = {
            "id": frame["id"],
            "ok": True,
            "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
        }
        assert conn.resolve(frame["id"], payload) is True
        assert await task == payload
        assert conn.inflight == {}

    asyncio.run(_scenario())


def test_mcp_call_frame_carries_the_caller_email():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(ws, "site-a", {}, {"devops-cli": _mcp()}, ["tools", "mcp"])
        task = asyncio.create_task(
            conn.request_mcp(
                "devops-cli", "tenant_account_tools", {}, 5000, "u1", "ann@example.com"
            )
        )
        await _wait_for_frames(ws)

        frame = ws.sent[0]
        assert frame["user_email"] == "ann@example.com"
        assert frame["user"] == "u1"

        conn.resolve(frame["id"], {"id": frame["id"], "ok": True, "result": {}})
        await task

    asyncio.run(_scenario())


def test_mcp_call_rejects_an_mcp_the_site_never_published():
    conn = EdgeConn(FakeWebSocket(), "site-a", {}, {"devops-cli": _mcp()}, ["tools", "mcp"])

    async def _scenario():
        with pytest.raises(app_module.EdgeUnknownMcp):
            await conn.request_mcp("other", "tenant_account_tools", {}, 5000)

    asyncio.run(_scenario())


def test_a_closed_connection_refuses_an_mcp_call():
    conn = EdgeConn(FakeWebSocket(), "site-a", {}, {"devops-cli": _mcp()}, ["tools", "mcp"])
    conn.closed = True

    async def _scenario():
        with pytest.raises(EdgeDisconnected):
            await conn.request_mcp("devops-cli", "tenant_account_tools", {}, 5000)

    asyncio.run(_scenario())


def test_mcp_calls_share_the_inflight_cap():
    async def _scenario():
        conn = EdgeConn(FakeWebSocket(), "site-a", {}, {"devops-cli": _mcp()}, ["tools", "mcp"])
        loop = asyncio.get_running_loop()
        conn.inflight.update(
            {f"id-{i}": loop.create_future() for i in range(protocol.MAX_INFLIGHT)}
        )
        with pytest.raises(EdgeOverloaded):
            await conn.request_mcp("devops-cli", "tenant_account_tools", {}, 5000)
        for future in conn.inflight.values():
            future.cancel()

    asyncio.run(_scenario())


def test_mcp_endpoint_routes_to_the_edge_connection(enforcing):
    enforcing.agents["agent-a"] = _agent(mcps=["site-a__devops-cli"])
    conn = _install_conn(mcps={"devops-cli": _mcp()})
    seen = {}
    result = {"content": [{"type": "text", "text": "ok"}], "isError": False}

    async def _record(
        mcp,
        tool,
        args,
        deadline_ms,
        user=None,
        user_email=None,
        agent=None,
        groups=None,
        run_id=None,
        parent_run_id=None,
        sealed=None,
    ):
        seen.update(
            mcp=mcp, tool=tool, args=args, deadline_ms=deadline_ms, user=user,
            user_email=user_email, agent=agent, groups=groups, run_id=run_id,
            parent_run_id=parent_run_id, sealed=sealed,
        )
        return {"id": "x", "ok": True, "result": result}

    conn.request_mcp = _record
    token = _mint(user_id="claim-user", user_email="claims@example.com")
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={
            "tool": "tenant_account_tools",
            "args": {"action": "list_actions"},
            # Body identity is inert; the claims are what the edge sees.
            "user": "body-user",
            "user_email": "body@example.com",
            "agent_token": token,
        },
    )

    assert response.status_code == 200
    assert response.json() == {"tool": "tenant_account_tools", "result": result}
    claims = agent_token_module.verify(token)
    assert seen == {
        "mcp": "devops-cli",
        "tool": "tenant_account_tools",
        # Forwarded un-coerced: the MCP server owns argument validation.
        "args": {"action": "list_actions"},
        "deadline_ms": protocol.DEFAULT_DEADLINE_MS,
        "user": "claim-user",
        "user_email": "claims@example.com",
        # The token itself never crosses (R1): the MCP route forwards identity too.
        "agent": "agent-a",
        "groups": None,
        "run_id": claims.run_id,
        "parent_run_id": None,
        "sealed": None,
    }


def test_mcp_endpoint_404s_on_a_v04_edge():
    """A tools-only edge has no MCP router: saying so beats a 504 after the deadline."""
    _install_conn()
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={"tool": "tenant_account_tools", "args": {}},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "unknown_mcp"
    assert "does not export MCPs" in response.json()["error"]["message"]


def test_mcp_endpoint_404s_on_an_unknown_mcp():
    _install_conn(mcps={"devops-cli": _mcp()})
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/site-a/mcps/other/call",
        json={"tool": "tenant_account_tools", "args": {}},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "unknown_mcp"


def test_mcp_endpoint_503s_when_the_site_is_offline():
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/ghost/mcps/devops-cli/call",
        json={"tool": "tenant_account_tools", "args": {}},
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "edge_offline"


def test_an_edge_side_refusal_is_a_completed_call():
    """Unknown tool, mcp_session_lost, missing credentials: 200 with `error`."""
    conn = _install_conn(mcps={"devops-cli": _mcp()})
    error = {"code": "unknown_tool", "message": "tool not published by this mcp"}

    async def _record(*args, **kwargs):
        return {"id": "x", "ok": False, "error": error}

    conn.request_mcp = _record
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={"tool": "tenant_account_tools", "args": {}},
    )

    assert response.status_code == 200
    assert response.json() == {"tool": "tenant_account_tools", "error": error}


def test_invalid_mcp_arguments_are_rejected_before_forwarding():
    conn = _install_conn(mcps={"devops-cli": _mcp()})
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={"tool": "tenant_account_tools", "args": {"blob": "x" * (protocol.MAX_ARGS_BYTES + 1)}},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_arguments"
    assert conn.ws.sent == []


def test_an_mcp_call_consumes_the_site_tool_budget(monkeypatch):
    """One bucket per site: whatever the edge is asked to run, it is one budget."""
    conn = _install_conn(mcps={"devops-cli": _mcp()})
    monkeypatch.setattr(app_module, "limiter", SiteLimiter(default_rate_per_min=1))

    async def _record(*args, **kwargs):
        return {"id": "x", "ok": True, "result": {}}

    conn.request_mcp = _record
    client = TestClient(app_module.app)

    # The MCP call spends the site's only token...
    first = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={"tool": "tenant_account_tools", "args": {}},
    )
    assert first.status_code == 200

    # ...so the tool endpoint is refused, from the same bucket.
    second = client.post("/v1/sites/site-a/call", json={"tool": "missing", "args": {}})
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "rate_limited"


def test_the_mcp_endpoint_is_rate_limited_by_a_tool_call(monkeypatch):
    conn = _install_conn(mcps={"devops-cli": _mcp()})
    monkeypatch.setattr(app_module, "limiter", SiteLimiter(default_rate_per_min=1))
    client = TestClient(app_module.app)

    assert client.post("/v1/sites/site-a/call", json={"tool": "missing", "args": {}}).status_code == 404
    response = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={"tool": "tenant_account_tools", "args": {}},
    )

    assert response.status_code == 429
    assert conn.ws.sent == []


def test_mcp_calls_are_audited_without_payloads(monkeypatch):
    events = []
    monkeypatch.setattr(
        app_module.audit, "record", lambda event, **kw: events.append({"event": event, **kw})
    )
    conn = _install_conn(mcps={"devops-cli": _mcp()})

    async def _refuse(*args, **kwargs):
        return {"id": "x", "ok": False, "error": {"code": "unknown_tool", "message": "nope"}}

    conn.request_mcp = _refuse
    client = TestClient(app_module.app)

    client.post(
        "/v1/sites/ghost/mcps/devops-cli/call",
        json={"tool": "tenant_account_tools", "args": {"secret": "secret-value"}},
    )
    client.post(
        "/v1/sites/site-a/mcps/other/call",
        json={"tool": "tenant_account_tools", "args": {"secret": "secret-value"}},
    )
    response = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={"tool": "tenant_account_tools", "args": {"secret": "secret-value"}},
    )

    assert response.status_code == 200
    assert [e["event"] for e in events] == ["mcp_call", "mcp_call", "mcp_call"]
    assert [e["outcome"] for e in events] == ["edge_offline", "unknown_mcp", "tool_error"]
    last = events[-1]
    assert last["site"] == "site-a"
    assert last["mcp"] == "devops-cli"
    assert last["tool"] == "tenant_account_tools"
    assert last["call_id"]
    # No verified caller here, so no identity on the line -- and never one from a body.
    # (The real audit.record drops a None field; this interception sees it.)
    assert last["user"] is None
    assert last["args_bytes"] > 0
    # The audit trail records shape, never payload.
    assert "secret-value" not in str(events)
    assert all("args" not in event for event in events)
    assert all("result" not in event for event in events)


def test_healthz_reports_connected_sites():
    _install_conn()
    client = TestClient(app_module.app)

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "sites": {
            "site-a": {"connected": True, "tools": 1, "mcps": 0, "inflight": 0}
        },
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

    deadline = time.monotonic() + 5.0
    while app_module.relay.get("site-a") is not None:
        assert time.monotonic() < deadline, "the relay never released the site"
        time.sleep(0.01)

    # Bound the number of *reads*, not the wall clock: this read blocks on the
    # registry lock the worker thread holds while it writes the disconnect, so a
    # deadline measured before it can expire while the read simply waits.
    for _ in range(500):
        if edge_registry.statuses["site-a"]["connected"] is False:
            break
        time.sleep(0.01)
    else:
        raise AssertionError("disconnect was never recorded")
    assert app_module.relay.get("site-a") is None


def test_connect_publishes_the_edge_key_and_declared_credential_names(
    monkeypatch, edge_registry, tmp_path
):
    """The seal form reads the key/name material from the site record, not a tool config."""
    from core import edge_keypair

    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
    key = edge_keypair.generate(tmp_path / "etc-trellis" / "edge-key")
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    credential_keys = {
        "echo": {"secret_keys": ["DEVOPS_PASSWORD"], "variable_keys": ["DEVOPS_URL"]}
    }
    client = TestClient(app_module.app)

    with _connect(client) as ws:
        ws.send_json(
            _hello(
                edge_pubkey=key.spki_b64,
                edge_key_fp=key.fingerprint,
                prev_edge_key_fp=None,
                credential_keys=credential_keys,
            )
        )
        assert ws.receive_json()["t"] == "welcome"
        _wait_until(
            lambda: "site-a" in edge_registry.edge_configs,
            "the credential material was never written to the site record",
        )
        record = edge_registry.edge_configs["site-a"]
        assert record["edge_pubkey"] == key.spki_b64
        assert record["edge_key_fp"] == key.fingerprint
        assert record["edge_key_id"] == key.key_id
        assert record["edge_key_fps"] == []
        assert record["credential_keys"] == credential_keys
        ws.close()


def test_a_hello_with_a_bad_key_fingerprint_is_refused(monkeypatch, tmp_path):
    """Bad key material must close the connection, never be pinned in the registry."""
    from core import edge_keypair

    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
    key = edge_keypair.generate(tmp_path / "etc-trellis" / "edge-key")
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client) as ws:
            ws.send_json(
                _hello(
                    edge_pubkey=key.spki_b64,
                    edge_key_fp="SHA256:" + "A" * 43,
                )
            )
            ws.receive_json()

    assert exc.value.code == protocol.CLOSE_MALFORMED


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


def test_duplicate_tool_names_skip_one_entry_not_the_hello(monkeypatch, caplog):
    """One unusable entry costs that export; the tunnel and the rest stay up."""
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with _connect(client) as ws:
        ws.send_json(
            _hello(tools=[{"name": "dup"}, {"name": "dup"}, {"name": "healthy"}])
        )
        assert ws.receive_json()["t"] == "welcome"
        # The welcome is answered before the site is registered for dispatch.
        _wait_until(
            lambda: app_module.relay.get("site-a") is not None,
            "the site was never registered",
        )
        conn = app_module.relay.get("site-a")
        assert sorted(conn.tools) == ["dup", "healthy"]

    assert any("duplicate" in record.getMessage() for record in caplog.records)


def test_an_invalid_credential_key_target_keeps_the_tunnel_up(monkeypatch, caplog):
    """A hyphenated declared key costs that seal form, not every export (v0.7.1)."""
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with _connect(client) as ws:
        ws.send_json(
            _hello(
                tools=[{"name": "echo"}],
                credential_keys={
                    "echo": {"secret_keys": ["ECHO_TOKEN"]},
                    "node_ssh": {"secret_keys": ["my-api-key"]},
                },
            )
        )
        assert ws.receive_json()["t"] == "welcome"
        _wait_until(
            lambda: app_module.relay.get("site-a") is not None,
            "the site was never registered",
        )
        conn = app_module.relay.get("site-a")
        assert sorted(conn.tools) == ["echo"]

    assert any("my-api-key" in record.getMessage() for record in caplog.records)


def test_an_invalid_mcp_entry_keeps_the_other_servers_online(monkeypatch, caplog):
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with _connect(client) as ws:
        ws.send_json(
            _hello(
                tools=[{"name": "echo"}],
                caps=["tools", "mcp"],
                mcps=[
                    {"name": "devops-cli", "tools": [{"name": "list_actions"}]},
                    {"name": "broken", "transport": "carrier-pigeon"},
                ],
            )
        )
        assert ws.receive_json()["t"] == "welcome"
        _wait_until(
            lambda: app_module.relay.get("site-a") is not None,
            "the site was never registered",
        )
        conn = app_module.relay.get("site-a")
        assert sorted(conn.mcps) == ["devops-cli"]

    assert any("carrier-pigeon" in record.getMessage() for record in caplog.records)


def _mcp_catalog():
    return [
        {
            "name": "devops-cli",
            "transport": "stdio",
            "tools": [
                {
                    "name": "tenant_account_tools",
                    "description": "meta",
                    "inputSchema": {
                        "type": "object",
                        "oneOf": [
                            {
                                "type": "object",
                                "properties": {"action": {"const": "list_actions"}},
                            }
                        ],
                    },
                }
            ],
        }
    ]


def test_proto2_hello_registers_mcps_and_caps(monkeypatch):
    """A proto-2 edge's catalogs land on the live connection, not in the registry."""
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
                        _hello(caps=["tools", "mcp"], mcps=_mcp_catalog())
                    )
                )
                welcome = protocol.decode(await ws.recv(), protocol.RELAY_FRAMES)
                assert welcome["t"] == "welcome"

                _wait_until(
                    lambda: app_module.relay.get("site-a") is not None,
                    "the site was never registered",
                )
                conn = app_module.relay.get("site-a")
                assert conn.caps == ["tools", "mcp"]
                assert list(conn.mcps) == ["devops-cli"]
                assert conn.mcps["devops-cli"].transport == "stdio"
                tool = conn.mcps["devops-cli"].tools[0]
                assert tool.name == "tenant_account_tools"
                assert tool.input_schema["oneOf"][0]["properties"]["action"]["const"] == (
                    "list_actions"
                )

                async with httpx.AsyncClient(
                    base_url=http_url, trust_env=False
                ) as client:
                    health = (await client.get("/healthz")).json()

                assert health["sites"]["site-a"]["mcps"] == 1
                assert health["sites"]["site-a"]["tools"] == 1

        asyncio.run(_scenario())


@pytest.mark.parametrize("proto", [1, 2])
def test_an_older_proto_hello_is_refused_with_4001(monkeypatch, proto):
    """v0.7.2 refuses proto <3: those edges' runners still expect an agent token.

    Such an edge would stay connected and then fail *every* call with a 403, so the
    handshake is where it must be told to upgrade (the edge logs a version mismatch
    and backs off to its maximum interval instead of reconnect-storming).
    """
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client) as ws:
            ws.send_json(_hello(proto=proto))
            ws.receive_text()

    assert exc.value.code == protocol.CLOSE_VERSION
    assert app_module.relay.get("site-a") is None


def test_a_proto4_hello_is_refused_with_4001(monkeypatch):
    """A newer edge than this relay speaks a version it cannot parse."""
    monkeypatch.setattr(app_module, "resolve_token", lambda token: {"name": "site-a"})
    client = TestClient(app_module.app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _connect(client) as ws:
            ws.send_json(_hello(proto=4))
            ws.receive_text()

    assert exc.value.code == protocol.CLOSE_VERSION


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


def test_end_to_end_wire_frame_carries_the_claims_email(monkeypatch):
    """The claims email crosses the real tunnel; without one the frame has no key."""
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
                await ws.send(protocol.encode(_hello()))
                assert protocol.decode(await ws.recv(), protocol.RELAY_FRAMES)["t"] == "welcome"

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
                                        "result": frame,
                                    }
                                )
                            )

                responder = asyncio.create_task(edge_loop())
                try:
                    async with httpx.AsyncClient(
                        base_url=http_url, trust_env=False
                    ) as client:
                        with_email = await client.post(
                            "/v1/sites/site-a/call",
                            json={
                                "tool": "echo",
                                "args": {"q": "hi"},
                                "agent_token": _mint(
                                    user_id="claim-user",
                                    user_email="ann@example.com",
                                ),
                            },
                        )
                        echoed = with_email.json()["result"]
                        assert echoed["user_email"] == "ann@example.com"
                        assert echoed["user"] == "claim-user"

                        # A token with no email claim carries no such key at all.
                        without_email = await client.post(
                            "/v1/sites/site-a/call",
                            json={
                                "tool": "echo",
                                "args": {"q": "hi"},
                                "agent_token": _mint(user_id="claim-user"),
                            },
                        )
                        assert "user_email" not in without_email.json()["result"]
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
    conn.published_signature = (("echo",), False, (), None, ())
    conn.edge_version = "0.3.0"
    published = []
    published_mcps = []

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
    monkeypatch.setattr(
        app_module.registry,
        "publish_mcp_catalog",
        lambda mgr, site, mcps, version, **kwargs: published_mcps.append(
            (site, len(mcps), version)
        ) or [],
    )
    monkeypatch.setattr(app_module, "HEARTBEAT_S", 0.01)

    async def run():
        task = asyncio.create_task(app_module._heartbeat(conn))
        # The keepalive is sent first; the republish follows it on the same beat.
        await _wait_for_frames(conn.ws, count=1)
        for _ in range(200):
            if published and published_mcps:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(run())

    assert published == [("plant-floor", 1, "0.3.0")]
    # A tool-side change republishes the MCP half too: one site record, two catalogs.
    assert published_mcps == [("plant-floor", 0, "0.3.0")]
    assert conn.rate_limit_per_min == 30
    assert conn.published_signature == (("echo", "new_tool"), True, (), 30, ())


def test_heartbeat_does_not_republish_without_an_admin_change(monkeypatch):
    conn = _install_conn(site="plant-floor")
    conn.published_signature = ((), False, (), None, ())
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
    conn.published_signature = (("echo",), False, (), None, ())
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
    monkeypatch.setattr(
        app_module.registry, "publish_mcp_catalog", lambda *args, **kwargs: []
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


def test_a_probe_for_an_unknown_mcp_consumes_the_site_budget(monkeypatch):
    """404 probes are accounted for, exactly like the tool endpoint's unknown_tool.

    Moving the limiter ahead of the capability/catalog checks is what keeps a leaked
    token from being turned into an unmetered scanner for MCP names.
    """
    _install_conn(mcps={"devops-cli": _mcp()})
    monkeypatch.setattr(app_module, "limiter", SiteLimiter(default_rate_per_min=1))
    client = TestClient(app_module.app)

    first = client.post(
        "/v1/sites/site-a/mcps/not-exported/call",
        json={"tool": "tenant_account_tools", "args": {}},
    )
    second = client.post(
        "/v1/sites/site-a/mcps/not-exported/call",
        json={"tool": "tenant_account_tools", "args": {}},
    )

    assert first.status_code == 404
    assert first.json()["error"]["code"] == "unknown_mcp"
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "rate_limited"


def test_an_admin_visibility_edit_republishes_the_mcp_config(monkeypatch):
    """`public`/`public_tools` are admin-owned, so an edit must reach the MCP half too.

    `_catalog_signature` covers both fields; this pins the republish end to end (the
    signature check alone would pass with a stale MCP config).
    """
    config = {
        "name": "site-a",
        "enabled": True,
        "exports": [],
        "public": False,
        "public_tools": ["mcp__site-a__devops-cli__tenant_account_tools"],
        "rate_limit_per_min": None,
    }
    fake = app_module._identity_manager()
    fake.get_edge_config = lambda site: dict(config)
    conn = _install_conn(site="site-a", mcps={"devops-cli": _mcp()})
    conn.published_signature = ((), False, (), None, ("devops-cli",))
    conn.edge_version = "0.5.0"

    asyncio.run(app_module._apply_admin_changes(conn, config))

    published = fake.mcps["site-a__devops-cli"]
    assert published["public"] is False
    assert published["public_tools"] == ["tenant_account_tools"]


def test_an_admin_edit_is_allowed_to_empty_the_mcp_catalog(monkeypatch):
    """Removing every server from export_mcps is explicit intent: without
    `allow_empty_mcps`, the registry entry would be unprunable from the admin UI."""
    conn = _install_conn(site="site-a", mcps={})
    conn.published_signature = ((), False, (), None, ("devops-cli",))
    conn.edge_version = "0.5.0"
    seen = {}

    monkeypatch.setattr(app_module.registry, "publish_catalog", lambda *a, **k: [])
    monkeypatch.setattr(
        app_module.registry,
        "publish_mcp_catalog",
        lambda *args, **kwargs: seen.update(kwargs) or [],
    )

    asyncio.run(
        app_module._apply_admin_changes(
            conn,
            {"name": "site-a", "enabled": True, "exports": [], "public": False,
             "public_tools": [], "rate_limit_per_min": None},
        )
    )

    # The MCP publish must also be told an empty catalog is intent, not a bad edge.
    assert seen.get("allow_empty") is True


# --- agent-token enforcement (phase 3) --------------------------------------
#
# The relay is the authority for edge calls: it verifies the token, resolves the
# agent's effective allowlist from the registry itself, and only then forwards a
# frame. These tests pin the denial paths (none of which may reach the edge) and
# what crosses instead of the token: the claims-derived identity (R1 -- the edge
# holds no signing key, so a token on the wire would be the only thing it could
# verify, and whoever holds one can mint a run).


def _agent(tools=None, mcps=None):
    return {"name": "agent-a", "allowed_tools": tools or [], "allowed_mcps": mcps or []}


@pytest.fixture
def in_log_mode(monkeypatch):
    """Explicit log mode: a missing token is tolerated (and no identity is invented)."""
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    return None


@pytest.fixture
def enforcing(monkeypatch, edge_registry):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    edge_registry.agents["agent-a"] = _agent(tools=["site-a__echo"])
    return edge_registry


def _mint(agent="agent-a", **kwargs):
    return agent_token_module.mint(agent, **kwargs)


def _capture(seen):
    """Record the identity arguments the relay hands to the edge connection.

    R1: what crosses is a resolved identity, never the agent token -- so there is no
    ``agent_token`` kwarg left to capture.
    """

    async def _record(*args, **kwargs):
        seen.update(
            agent=kwargs.get("agent"),
            groups=kwargs.get("groups"),
            run_id=kwargs.get("run_id"),
            parent_run_id=kwargs.get("parent_run_id"),
            call=args,
        )
        return {"id": "x", "ok": True, "result": {}}

    return _record


def test_a_permitted_call_forwards_the_claims_identity(enforcing):
    conn = _install_conn()
    seen = {}
    conn.request = _capture(seen)

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={
            "tool": "echo",
            "args": {"q": "x"},
            "agent_token": _mint(run_id="run-1", groups=("ops",)),
        },
    )

    assert response.status_code == 200
    assert seen["agent"] == "agent-a"
    assert seen["groups"] == ["ops"]
    assert seen["run_id"] == "run-1"
    assert seen["parent_run_id"] is None


def test_the_forwarded_frame_carries_the_claims_identity_and_no_token():
    """R1: the wire frame carries the resolved identity, never the agent token."""

    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(ws, "site-a", {"echo": _tool()})
        task = asyncio.create_task(
            conn.request(
                "echo",
                {"q": "hi"},
                5000,
                "u1",
                agent="agent-a",
                groups=["ops"],
                run_id="run-1",
                parent_run_id="run-0",
            )
        )
        await _wait_for_frames(ws)

        frame = ws.sent[0]
        assert frame["agent"] == "agent-a"
        assert frame["groups"] == ["ops"]
        assert frame["run_id"] == "run-1"
        assert frame["parent_run_id"] == "run-0"
        # The signing material stops at the relay: whoever holds it can mint a run.
        assert "agent_token" not in frame

        conn.resolve(frame["id"], {"id": frame["id"], "ok": True, "result": {}})
        await task

    asyncio.run(_scenario())


def test_a_frame_without_a_verified_caller_carries_no_run_identity():
    """No token, no identity: the keys are absent, not present-and-null."""
    conn = EdgeConn(FakeWebSocket(), "site-a", {"echo": _tool()})

    frame = conn._call_frame("echo", {"q": "hi"}, 5000, None, None)

    assert frame == {
        "t": "call",
        "id": frame["id"],
        "tool": "echo",
        "args": {"q": "hi"},
        "deadline_ms": 5000,
        "user": None,
    }


def test_validate_call_returns_the_run_identity_and_tolerates_an_old_token():
    """The edge-side half of R1: new keys are validated and returned, the token is not.

    An older relay still sends ``agent_token``; the frame must parse (wire tolerance),
    even though nothing on the edge consumes it any more.
    """
    parsed = protocol.validate_call(
        {
            "id": "c1",
            "tool": "echo",
            "agent": "agent-a",
            "groups": ["ops"],
            "run_id": "run-1",
            "agent_token": "t1.payload.sig",
        }
    )

    assert parsed["agent"] == "agent-a"
    assert parsed["groups"] == ["ops"]
    assert parsed["run_id"] == "run-1"
    # Absent, not null: a root run and a token-less caller add no keys.
    assert "parent_run_id" not in parsed
    assert parsed["agent_token"] == "t1.payload.sig"

    # An older edge's own shape checks still apply to what crosses the tunnel.
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_call({"id": "c1", "tool": "echo", "groups": "ops"})


@pytest.mark.parametrize(
    "token",
    [None, "t1.forged.signature", ""],
    ids=["missing", "bad_sig", "empty"],
)
def test_a_call_without_a_valid_token_is_refused(enforcing, token):
    conn = _install_conn()
    conn.request = pytest.fail
    body = {"tool": "echo", "args": {"q": "x"}}
    if token is not None:
        body["agent_token"] = token

    response = TestClient(app_module.app).post("/v1/sites/site-a/call", json=body)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "access_denied"
    assert conn.ws.sent == []


def test_an_expired_token_is_refused(enforcing):
    conn = _install_conn()
    conn.request = pytest.fail
    token = _mint(now=time.time() - 10_000, ttl_s=60)

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={"tool": "echo", "args": {"q": "x"}, "agent_token": token},
    )

    assert response.status_code == 403
    assert "expired" in response.json()["error"]["message"]


def test_a_tool_outside_the_allowlist_is_refused(enforcing):
    conn = _install_conn()
    conn.request = pytest.fail
    enforcing.agents["agent-a"] = _agent(tools=["site-a__other"])

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={"tool": "echo", "args": {"q": "x"}, "agent_token": _mint()},
    )

    assert response.status_code == 403
    body = response.json()["error"]
    assert body["code"] == "access_denied"
    assert "site-a__echo" in body["message"]
    assert conn.ws.sent == []


def test_an_unknown_agent_is_refused(enforcing):
    conn = _install_conn()
    conn.request = pytest.fail

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={"tool": "echo", "args": {"q": "x"}, "agent_token": _mint("ghost")},
    )

    assert response.status_code == 403
    assert "agent 'ghost'" in response.json()["error"]["message"]


def test_the_front_door_gets_no_exemption(enforcing):
    """The gateway has no agent record, so it has no allowlist either.

    v0.7.1 Phase 3/4: there is no elevated principal any more (the `k` claim and the
    `principal=` kwarg are gone). The `gateway` agent name grants nothing; its only
    possible grant on the edge is the export's own public exposure.
    """
    conn = _install_conn()
    conn.request = pytest.fail

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={
            "tool": "echo",
            "args": {"q": "x"},
            "agent_token": _mint("gateway"),
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "access_denied"
    assert "agent 'gateway'" in response.json()["error"]["message"]
    assert conn.ws.sent == []


def test_the_forwarded_frame_carries_the_token_identity_not_a_record_read(enforcing):
    """The relay takes user id, email and groups from the claims only.

    Nothing on this path may go back to the registry for the caller's identity: a
    second read could disagree with the claim the hub already trusted.
    """
    conn = _install_conn()
    seen = {}
    conn.request = _capture(seen)
    reads = []

    def fake_get_user(user_id):
        reads.append(user_id)
        return {"groups": ["other"], "email": "stale@example.test"}

    enforcing.get_user = fake_get_user
    token = _mint(user_id="u-1", user_email="u@example.test", groups=("ops",))

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={"tool": "echo", "args": {"q": "x"}, "agent_token": token},
    )

    assert response.status_code == 200
    assert reads == []
    # The frame's positional identity arguments came from the verified claims.
    assert seen["call"][3] == "u-1"
    assert seen["call"][4] == "u@example.test"
    # ...and so did the run attribution the edge sees instead of the token.
    assert seen["agent"] == "agent-a"
    assert seen["groups"] == ["ops"]


def test_a_public_export_is_the_front_doors_grant(enforcing):
    """A public export needs no agent record: that is the grant the front door uses."""
    conn = _install_conn()
    seen = {}
    conn.request = _capture(seen)
    enforcing.save_edge_config(
        "site-a", {"name": "site-a", "enabled": True, "public": True, "public_tools": []}
    )

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={"tool": "echo", "args": {"q": "x"}, "agent_token": _mint("gateway")},
    )

    assert response.status_code == 200
    assert seen["call"][0] == "echo"


def test_a_public_export_does_not_widen_an_agents_allowlist(enforcing):
    """`public` substitutes for a MISSING allowlist, never for a non-matching one."""
    conn = _install_conn()
    conn.request = pytest.fail
    enforcing.agents["agent-a"] = _agent(tools=[])
    enforcing.save_edge_config(
        "site-a", {"name": "site-a", "enabled": True, "public": True, "public_tools": []}
    )

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={"tool": "echo", "args": {"q": "x"}, "agent_token": _mint()},
    )

    assert response.status_code == 403
    assert "site-a__echo" in response.json()["error"]["message"]
    assert conn.ws.sent == []


def test_a_public_mcp_tool_list_is_the_front_doors_grant(enforcing):
    """The MCP route applies the same rule: the server's public/public_tools decides."""
    conn = _install_conn(mcps={"devops-cli": _mcp()})
    seen = {}
    conn.request_mcp = _capture(seen)
    client = TestClient(app_module.app)
    body = {
        "tool": "tenant_account_tools",
        "args": {"action": "list_actions"},
        "agent_token": _mint("gateway"),
    }

    denied = client.post("/v1/sites/site-a/mcps/devops-cli/call", json=body)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "access_denied"

    enforcing.save_edge_config(
        "site-a",
        {
            "name": "site-a",
            "enabled": True,
            "public": False,
            # A site record names an MCP tool by its documented reference form.
            "public_tools": ["mcp__site-a__devops-cli__tenant_account_tools"],
        },
    )
    allowed = client.post("/v1/sites/site-a/mcps/devops-cli/call", json=body)
    assert allowed.status_code == 200
    assert seen["call"][0] == "devops-cli"


def test_an_mcp_call_accepts_a_server_grant_or_a_per_tool_grant(enforcing):
    seen = {}
    conn = _install_conn(mcps={"devops-cli": _mcp()})
    conn.request_mcp = _capture(seen)
    client = TestClient(app_module.app)
    body = {"tool": "tenant_account_tools", "args": {"action": "list_actions"}}

    # Granted as an edge MCP: permits_mcp and permits_tool both hold.
    enforcing.agents["agent-a"] = _agent(mcps=["site-a__devops-cli"])
    permitted = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={**body, "agent_token": _mint()},
    )
    assert permitted.status_code == 200
    assert seen["agent"] == "agent-a"

    # Documented narrowing: the tool's full `mcp__...` reference grants just that tool,
    # which is enough to open the session it needs.
    enforcing.agents["agent-a"] = _agent(tools=["mcp__site-a__devops-cli__tenant_account_tools"])
    narrowed = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={**body, "agent_token": _mint()},
    )
    assert narrowed.status_code == 200

    # v0.7.1: the bare tool name is NOT that grant -- it belongs to the framework tool
    # of that name (permits_tool / permits_mcp_session / build-time registration).
    enforcing.agents["agent-a"] = _agent(tools=["tenant_account_tools"])
    collision = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={**body, "agent_token": _mint()},
    )
    assert collision.status_code == 403
    assert collision.json()["error"]["code"] == "access_denied"

    # Nothing granted: denied.
    enforcing.agents["agent-a"] = _agent(tools=[], mcps=[])
    denied = client.post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={**body, "agent_token": _mint()},
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "access_denied"


def test_log_mode_permits_but_warns(caplog):
    conn = _install_conn()
    seen = {}
    conn.request = _capture(seen)

    with caplog.at_level(logging.WARNING, logger="services.edge_relay.app"):
        response = TestClient(app_module.app).post(
            "/v1/sites/site-a/call",
            json={"tool": "echo", "args": {"q": "x"}, "agent_token": "t1.forged.signature"},
        )

    assert response.status_code == 200
    assert seen["call"][0] == "echo"
    assert "would deny" in caplog.text


def test_an_access_denial_is_audited_with_the_agent_and_no_args(monkeypatch, enforcing):
    events = []
    monkeypatch.setattr(
        app_module.audit, "record", lambda event, **kw: events.append({"event": event, **kw})
    )
    conn = _install_conn()
    conn.request = pytest.fail
    enforcing.agents["agent-a"] = _agent(tools=[])

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={
            "tool": "echo",
            "args": {"q": "do-not-log-me"},
            "agent_token": _mint(user_id="u-alice"),
        },
    )

    assert response.status_code == 403
    assert [event["outcome"] for event in events] == ["access_denied"]
    entry = events[0]
    assert entry["site"] == "site-a"
    assert entry["tool"] == "echo"
    assert entry["agent"] == "agent-a"
    # The token verified; only the allowlist refused. The caller stays on the line.
    assert entry["user"] == "u-alice"
    assert "args" not in entry
    assert "do-not-log-me" not in str(events)


def test_an_mcp_access_denial_keeps_the_caller_on_the_audit_line(monkeypatch, enforcing):
    """Same rule on the MCP route: a verified caller is never dropped from the line."""
    events = []
    monkeypatch.setattr(
        app_module.audit, "record", lambda event, **kw: events.append({"event": event, **kw})
    )
    conn = _install_conn(mcps={"devops-cli": _mcp()})
    conn.request_mcp = pytest.fail
    enforcing.agents["agent-a"] = _agent(tools=[], mcps=[])

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/mcps/devops-cli/call",
        json={
            "tool": "tenant_account_tools",
            "args": {"action": "list_actions"},
            "agent_token": _mint(user_id="u-alice"),
        },
    )

    assert response.status_code == 403
    [entry] = events
    assert entry["outcome"] == "access_denied"
    assert entry["user"] == "u-alice"


def test_a_malformed_token_shape_is_a_400_in_log_mode():
    """Shape checks stay a `invalid_arguments` 400, not a token verdict."""
    conn = _install_conn()
    conn.request = pytest.fail

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={"tool": "echo", "args": {"q": "x"}, "agent_token": "a" * 5000},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_arguments"


def test_a_token_with_control_characters_is_a_400():
    conn = _install_conn()

    response = TestClient(app_module.app).post(
        "/v1/sites/site-a/call",
        json={"tool": "echo", "args": {"q": "x"}, "agent_token": "t1.a\nb.c"},
    )

    assert response.status_code == 400
    assert conn.ws.sent == []


# --- lazy catalog detail cache (P6) -----------------------------------------


@pytest.fixture()
def detail_registry(monkeypatch):
    """Point the relay's registry at a fake that serves stored records (no etcd)."""
    fake = FakeEdgeRegistry()
    monkeypatch.setattr(app_module, "_identity_manager", lambda: fake)
    return fake


def _remote_tool_record(*, detail="full", inputs=None):
    """A ``<site>__<tool>`` record shaped like the relay's own publish."""
    config = {
        "name": "site-a__echo",
        "description": "Echoes the input.",
        "runtime": "remote",
        "inputs": (
            {"q": {"type": "string", "required": True}} if inputs is None else inputs
        ),
        "remote": {"site": "site-a", "tool": "echo"},
        "managed_by": "edge-relay",
        "public": False,
    }
    if detail is not None:
        config["detail"] = detail
    return config


def _stored_tool(mgr, *, detail="full", inputs=None):
    config = _remote_tool_record(detail=detail, inputs=inputs)
    mgr.tools["site-a__echo"] = config
    return config


def _lazy_mcp_record(mgr):
    """One lazy server: two summary entries, neither carrying a schema."""
    config = {
        "name": "site-a__devops-cli",
        "description": "",
        "transport": "remote",
        "remote": {"site": "site-a", "mcp": "devops-cli"},
        "managed_by": "edge-relay",
        "public": False,
        "public_tools": [],
        "detail": "lazy",
        "tools": [
            {"name": "tenant_account_tools", "description": "manage tenants"},
            {"name": "sibling_tool", "description": "never fetched"},
        ],
    }
    mgr.mcps["site-a__devops-cli"] = config
    return config


def test_a_lazy_publish_writes_a_summary_record():
    mgr = FakeEdgeRegistry()

    published = app_module.registry.publish_catalog(
        mgr,
        "site-a",
        [protocol.EdgeTool(name="echo", description="Echoes the input.")],
        "0.6.2",
        lazy_catalog=True,
    )

    assert published == ["site-a__echo"]
    config = mgr.tools["site-a__echo"]
    assert config["detail"] == "lazy"
    assert config["inputs"] == {}
    assert config["remote"] == {"site": "site-a", "tool": "echo"}
    assert config["managed_by"] == "edge-relay"


def test_a_full_publish_keeps_the_pre_lazy_record_shape():
    """No cap: the record has no ``detail`` key at all (absent reads as "full")."""
    mgr = FakeEdgeRegistry()

    app_module.registry.publish_catalog(
        mgr,
        "site-a",
        [protocol.EdgeTool(name="echo", inputs={"q": {"type": "string"}})],
        "0.6.2",
    )

    assert "detail" not in mgr.tools["site-a__echo"]
    assert mgr.tools["site-a__echo"]["inputs"] == {"q": {"type": "string"}}


def test_a_lazy_publish_that_still_carries_inputs_is_a_full_record():
    mgr = FakeEdgeRegistry()

    app_module.registry.publish_catalog(
        mgr,
        "site-a",
        [protocol.EdgeTool(name="echo", inputs={"q": {"type": "string"}})],
        "0.6.2",
        lazy_catalog=True,
    )

    config = mgr.tools["site-a__echo"]
    assert config["detail"] == "full"
    assert config["inputs"] == {"q": {"type": "string"}}


def test_a_lazy_mcp_publish_marks_the_server_when_a_schema_is_missing():
    mgr = FakeEdgeRegistry()
    mcp = protocol.EdgeMcp(
        name="devops-cli",
        tools=[
            protocol.EdgeMcpTool(name="summary_only"),
            protocol.EdgeMcpTool(name="with_schema", input_schema={"type": "object"}),
        ],
    )

    app_module.registry.publish_mcp_catalog(
        mgr, "site-a", [mcp], "0.6.2", lazy_catalog=True
    )

    config = mgr.mcps["site-a__devops-cli"]
    assert config["detail"] == "lazy"
    assert [tool["name"] for tool in config["tools"]] == ["summary_only", "with_schema"]


def test_fetch_tool_detail_serves_a_cached_full_record_without_the_edge():
    mgr = FakeEdgeRegistry()
    _stored_tool(mgr)
    calls = []

    async def requester(mcp, tool):
        calls.append((mcp, tool))
        raise AssertionError("a cached full detail must not reach the edge")

    result = asyncio.run(
        app_module.registry.fetch_tool_detail(mgr, "site-a", "echo", requester)
    )

    assert result["cached"] is True
    assert result["detail_state"] == "full"
    assert result["detail"] == {"q": {"type": "string", "required": True}}
    assert result["description"] == "Echoes the input."
    assert "stale" not in result
    assert calls == []


def test_fetch_tool_detail_fetches_validates_and_caches_a_lazy_record():
    mgr = FakeEdgeRegistry()
    _stored_tool(mgr, detail="lazy", inputs={})
    calls = []

    async def requester(mcp, tool):
        calls.append((mcp, tool))
        return {
            "name": tool,
            "description": "Echoes the input, fully.",
            "inputs": {"q": {"type": "string", "required": True}},
        }

    result = asyncio.run(
        app_module.registry.fetch_tool_detail(mgr, "site-a", "echo", requester)
    )

    assert calls == [(None, "echo")]
    assert result["cached"] is False
    assert result["detail"] == {"q": {"type": "string", "required": True}}
    stored = mgr.tools["site-a__echo"]
    assert stored["detail"] == "full"
    assert stored["description"] == "Echoes the input, fully."
    assert stored["inputs"] == {"q": {"type": "string", "required": True}}
    # The merge is additive: routing fields from the summary survive.
    assert stored["remote"] == {"site": "site-a", "tool": "echo"}
    assert stored["managed_by"] == "edge-relay"

    # The next read is a cache hit, with no second round trip.
    again = asyncio.run(
        app_module.registry.fetch_tool_detail(mgr, "site-a", "echo", requester)
    )
    assert again["cached"] is True
    assert calls == [(None, "echo")]


def test_fetch_tool_detail_rejects_an_invalid_detail_and_degrades():
    mgr = FakeEdgeRegistry()
    _stored_tool(mgr, detail="lazy", inputs={})

    async def requester(mcp, tool):
        return {"name": tool, "description": "d", "inputs": ["not", "an", "object"]}

    result = asyncio.run(
        app_module.registry.fetch_tool_detail(mgr, "site-a", "echo", requester)
    )

    assert result["unavailable"] is True
    assert "ProtocolError" in result["reason"]
    # Nothing invalid is cached: the record is still the lazy summary.
    assert mgr.tools["site-a__echo"]["detail"] == "lazy"


class _RacyDetailRegistry(FakeEdgeRegistry):
    """First read misses, later reads see a full record (a concurrent publish)."""

    def __init__(self):
        super().__init__()
        self.reads = 0

    def get_tool_config(self, name):
        self.reads += 1
        config = super().get_tool_config(name)
        if config is None or self.reads > 1:
            return config
        return {**config, "detail": "lazy"}


def test_fetch_tool_detail_falls_back_to_a_stale_copy_when_the_edge_fails():
    mgr = _RacyDetailRegistry()
    _stored_tool(mgr)

    async def requester(mcp, tool):
        raise RuntimeError("tunnel dropped")

    result = asyncio.run(
        app_module.registry.fetch_tool_detail(mgr, "site-a", "echo", requester)
    )

    assert result.get("stale") is True
    assert result["cached"] is True
    assert result["detail"] == {"q": {"type": "string", "required": True}}
    assert mgr.reads == 2


def test_fetch_tool_detail_degrades_to_unavailable_without_a_cache():
    mgr = FakeEdgeRegistry()

    async def requester(mcp, tool):
        raise RuntimeError("tunnel dropped")

    result = asyncio.run(
        app_module.registry.fetch_tool_detail(mgr, "site-a", "echo", requester)
    )

    assert result["unavailable"] is True
    assert result["detail"] is None
    assert result["detail_state"] == "unavailable"
    assert "RuntimeError" in result["reason"]
    assert "tunnel dropped" in result["reason"]


def test_fetch_mcp_tool_detail_round_trips_the_schema():
    """The MCP payload's ``detail`` is the ``inputSchema`` itself, not the entry."""
    mgr = FakeEdgeRegistry()
    _lazy_mcp_record(mgr)
    schema = {"type": "object", "properties": {"action": {"type": "string"}}}
    calls = []

    async def requester(mcp, tool):
        calls.append((mcp, tool))
        return {
            "name": "tenant_account_tools",
            "description": "manage tenants",
            "inputSchema": schema,
        }

    first = asyncio.run(
        app_module.registry.fetch_tool_detail(
            mgr, "site-a", "tenant_account_tools", requester, mcp="devops-cli"
        )
    )

    assert calls == [("devops-cli", "tenant_account_tools")]
    assert first["cached"] is False
    assert first["detail"] == schema
    assert first["description"] == "manage tenants"

    second = asyncio.run(
        app_module.registry.fetch_tool_detail(
            mgr, "site-a", "tenant_account_tools", requester, mcp="devops-cli"
        )
    )

    assert second["cached"] is True
    assert second["detail"] == schema
    assert calls == [("devops-cli", "tenant_account_tools")]


def test_storing_one_mcp_detail_completes_only_that_entry():
    mgr = FakeEdgeRegistry()
    _lazy_mcp_record(mgr)
    schema = {"type": "object", "properties": {"action": {"type": "string"}}}

    config = app_module.registry.store_mcp_tool_detail(
        mgr,
        "site-a",
        "devops-cli",
        {
            "name": "tenant_account_tools",
            "description": "manage tenants",
            "inputSchema": schema,
        },
    )

    # The server flag flips to "full"; `detail_tools` is what proves which entries did.
    assert config["detail"] == "full"
    assert config["detail_tools"] == ["tenant_account_tools"]
    fetched = next(t for t in config["tools"] if t["name"] == "tenant_account_tools")
    assert fetched["inputSchema"] == schema
    sibling = next(t for t in config["tools"] if t["name"] == "sibling_tool")
    assert not sibling.get("inputSchema")

    assert (
        app_module.registry.get_mcp_tool_detail(
            mgr, "site-a", "devops-cli", "tenant_account_tools"
        )["inputSchema"]
        == schema
    )
    # Never fetched, so still a summary: unavailable rather than an empty schema.
    assert (
        app_module.registry.get_mcp_tool_detail(
            mgr, "site-a", "devops-cli", "sibling_tool"
        )
        is None
    )


def test_request_tool_detail_correlates_on_the_sent_id():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(ws, "site-a", {"echo": _tool()}, caps=["tools", "lazy_catalog"])
        task = asyncio.create_task(conn.request_tool_detail("echo"))
        await _wait_for_frames(ws)

        frame = ws.sent[0]
        assert frame == {"t": "tool_detail", "id": frame["id"], "tool": "echo"}

        detail = {
            "name": "echo",
            "description": "Echoes.",
            "inputs": {"q": {"type": "string", "required": True}},
        }
        payload = {"id": frame["id"], "ok": True, "detail": detail}
        assert conn.resolve(frame["id"], payload) is True
        assert await task == detail
        assert conn.inflight == {}

    asyncio.run(_scenario())


def test_request_mcp_tool_detail_correlates_on_the_sent_id():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(
            ws, "site-a", mcps={"devops-cli": _mcp()},
            caps=["tools", "mcp", "lazy_catalog"],
        )
        task = asyncio.create_task(
            conn.request_mcp_tool_detail("devops-cli", "tenant_account_tools")
        )
        await _wait_for_frames(ws)

        frame = ws.sent[0]
        assert frame == {
            "t": "mcp_tool_detail",
            "id": frame["id"],
            "mcp": "devops-cli",
            "tool": "tenant_account_tools",
        }

        detail = {
            "name": "tenant_account_tools",
            "description": "manage tenants",
            "inputSchema": {"type": "object"},
        }
        assert conn.resolve(frame["id"], {"id": frame["id"], "ok": True, "detail": detail})
        assert await task == detail

    asyncio.run(_scenario())


def test_a_detail_refusal_raises_edge_detail_error_with_the_code():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(ws, "site-a", {"echo": _tool()}, caps=["tools", "lazy_catalog"])
        task = asyncio.create_task(conn.request_tool_detail("echo"))
        await _wait_for_frames(ws)

        frame = ws.sent[0]
        conn.resolve(
            frame["id"],
            {
                "id": frame["id"],
                "ok": False,
                "error": {"code": "unknown_tool", "message": "tool not published"},
            },
        )

        with pytest.raises(app_module.EdgeDetailError) as exc:
            await task
        assert exc.value.code == "unknown_tool"
        assert exc.value.message == "tool not published"
        assert conn.inflight == {}

    asyncio.run(_scenario())


def test_a_detail_reply_without_a_detail_object_is_refused():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(ws, "site-a", {"echo": _tool()}, caps=["tools", "lazy_catalog"])
        task = asyncio.create_task(conn.request_tool_detail("echo"))
        await _wait_for_frames(ws)

        frame = ws.sent[0]
        conn.resolve(frame["id"], {"id": frame["id"], "ok": True, "result": {}})

        with pytest.raises(app_module.EdgeDetailError) as exc:
            await task
        assert exc.value.code == "detail_missing"

    asyncio.run(_scenario())


def test_an_unknown_tool_or_mcp_is_never_asked_for_detail():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(
            ws, "site-a", {"echo": _tool()}, {"devops-cli": _mcp()},
            caps=["tools", "mcp", "lazy_catalog"],
        )

        with pytest.raises(EdgeUnknownTool):
            await conn.request_tool_detail("nope")
        with pytest.raises(app_module.EdgeUnknownMcp):
            await conn.request_mcp_tool_detail("nope", "tenant_account_tools")

        # Refused before anything was written to the tunnel.
        assert ws.sent == []
        assert conn.inflight == {}

    asyncio.run(_scenario())


def test_tool_detail_endpoint_serves_the_edge_and_caches_the_answer(detail_registry):
    conn = _install_conn()
    entry = {
        "name": "echo",
        "description": "Echoes the input.",
        "inputs": {"q": {"type": "string", "required": True}},
    }
    calls = []

    async def _detail(tool):
        calls.append(tool)
        return entry

    conn.request_tool_detail = _detail
    client = TestClient(app_module.app)

    first = client.post("/v1/sites/site-a/tool_detail", json={"tool": "echo"})

    assert first.status_code == 200
    assert first.json() == {
        "site": "site-a",
        "tool": "echo",
        "detail": entry["inputs"],
        "description": "Echoes the input.",
        "detail_state": "full",
        "cached": False,
    }

    second = client.post("/v1/sites/site-a/tool_detail", json={"tool": "echo"})

    assert second.status_code == 200
    assert second.json()["cached"] is True
    assert second.json()["detail"] == entry["inputs"]
    assert calls == ["echo"]


def test_tool_detail_endpoint_503s_for_an_offline_site_without_a_cache(
    monkeypatch, detail_registry
):
    events = []
    monkeypatch.setattr(
        app_module.audit, "record", lambda event, **kw: events.append({"event": event, **kw})
    )
    client = TestClient(app_module.app)

    response = client.post("/v1/sites/ghost/tool_detail", json={"tool": "echo"})

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "edge_offline"
    assert [event["event"] for event in events] == ["detail"]
    assert events[0]["outcome"] == "edge_offline"
    assert events[0]["site"] == "ghost"
    assert events[0]["tool"] == "echo"


def test_tool_detail_audit_line_records_shape_not_schema(monkeypatch, detail_registry):
    events = []
    monkeypatch.setattr(
        app_module.audit, "record", lambda event, **kw: events.append({"event": event, **kw})
    )
    marker = "SCHEMA-CONTENT-MARKER"
    conn = _install_conn()

    async def _detail(tool):
        return {
            "name": "echo",
            "description": "Echoes the input.",
            "inputs": {"q": {"type": "string", "description": marker}},
        }

    conn.request_tool_detail = _detail
    client = TestClient(app_module.app)

    response = client.post("/v1/sites/site-a/tool_detail", json={"tool": "echo"})

    assert response.status_code == 200
    assert len(events) == 1
    event = events[0]
    assert event["event"] == "detail"
    assert event["outcome"] == "ok"
    assert event["site"] == "site-a"
    assert event["tool"] == "echo"
    assert isinstance(event["ms"], int)
    # ``audit.record`` drops a None field; the intercepted call still carries it.
    assert event.get("mcp") is None
    # Same rule as a call: names, outcome and timing only.
    assert "detail" not in event
    assert "description" not in event
    assert marker not in json.dumps(events)


def test_an_offline_site_still_serves_a_cached_detail(monkeypatch, detail_registry):
    """The cache is the point: a schema read keeps working while the edge is away."""
    _stored_tool(detail_registry)
    client = TestClient(app_module.app)

    response = client.post("/v1/sites/site-a/tool_detail", json={"tool": "echo"})

    assert response.status_code == 200
    assert response.json()["cached"] is True
    assert response.json()["detail"] == {"q": {"type": "string", "required": True}}


# --- Lazy-catalog execution path --------------------------------------------


def test_a_lazy_published_tool_is_still_callable_with_arguments(monkeypatch):
    # The hello carried only a summary, so the relay's in-memory EdgeTool has no
    # inputs. Strict unknown-key validation would make every argument 400 before the
    # edge (which validates its real manifest) ever sees it.
    summary = protocol.EdgeTool(name="boiler_status", description="status", inputs={})
    conn = _install_conn(tools={"boiler_status": summary}, caps=["tools", "lazy_catalog"])
    sent = {}

    async def fake_request(tool, args, *a, **k):
        sent["tool"] = tool
        sent["args"] = args
        return {"id": "x", "ok": True, "result": {"ok": True}}

    conn.request = fake_request
    client = TestClient(app_module.app)

    response = client.post(
        "/v1/sites/site-a/call",
        json={"tool": "boiler_status", "args": {"room": "kitchen"}},
    )

    assert response.status_code == 200
    assert sent == {"tool": "boiler_status", "args": {"room": "kitchen"}}


def test_fetching_a_detail_refreshes_the_connection_catalog():
    async def _scenario():
        ws = FakeWebSocket()
        conn = EdgeConn(
            ws, "site-a", {"echo": protocol.EdgeTool(name="echo", description="e", inputs={})},
            caps=["tools", "lazy_catalog"],
        )
        task = asyncio.create_task(conn.request_tool_detail("echo"))
        await _wait_for_frames(ws)
        frame = ws.sent[0]
        detail = {
            "name": "echo",
            "description": "Echoes.",
            "inputs": {"q": {"type": "string", "required": True}},
        }
        conn.resolve(frame["id"], {"id": frame["id"], "ok": True, "detail": detail})
        assert await task == detail

        # The next call validates against the real schema, not the summary.
        assert conn.tools["echo"].inputs == detail["inputs"]
        args = protocol.args_for_tool(conn.tools["echo"], {"q": "hi"})
        assert args == {"q": "hi"}

    asyncio.run(_scenario())


def test_a_prelazy_schemaless_mcp_tool_is_a_cache_hit():
    # A record from before lazy publishing has no `detail` key; an empty inputSchema is
    # legal for a schema-less tool, so asking the edge would send a detail frame to a
    # peer that cannot decode it (and closes the tunnel on an unknown frame type).
    class Mgr:
        def get_mcp_config(self, name):
            return {
                "managed_by": app_module.registry.MANAGED_BY,
                "name": name,
                "tools": [{"name": "ping", "description": "ping", "inputSchema": {}}],
            }

    entry = app_module.registry.get_mcp_tool_detail(
        Mgr(), "site-a", "devops-cli", "ping"
    )
    assert entry is not None
    assert entry["name"] == "ping"
