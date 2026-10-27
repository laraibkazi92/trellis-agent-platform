# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge MCP export tests: catalog building, session isolation, refusal, reload.

Sessions are runner containers now, so there is no child process and no session
directory to assert on. ``proxy_mcp._runner_transport`` is the seam: the fake here
returns an in-memory ``ClientTransport`` backed by a real FastMCP server, so the
client/server session lifecycle (state, timeouts, env) is still exercised for real
while everything stays inside the test process.
"""

import asyncio
import contextlib
import json
import logging
import secrets
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from fastmcp.client.transports.base import ClientTransport

from core import edge_user_secrets, proxy, proxy_mcp
from core.models import MCPConfig
from services.edge_relay import protocol

REPO_ROOT = Path(__file__).parent.parent

# A session key is the *normalized* email (``proxy_mcp._identity_key``), not the raw
# address: case/whitespace variants of one person must share one session.
SESSION_KEY = edge_user_secrets.normalize_email("a@x")

SERVER_TOOLS = [
    {"name": "set_value", "description": "store a value", "inputSchema": {"type": "object"}},
    {"name": "get_value", "description": "read a value", "inputSchema": {"type": "object"}},
    {"name": "get_home", "description": "the session HOME", "inputSchema": {"type": "object"}},
]
ENV_DUMP_TOOL = {"name": "env_dump", "description": "env", "inputSchema": {"type": "object"}}
SLOW_TOOL = {"name": "slow", "description": "sleep", "inputSchema": {"type": "object"}}
DEADLINE_MS = 60_000


# ---------------------------------------------------------------- helpers


@pytest.fixture(autouse=True)
def edge_env(tmp_path, monkeypatch):
    """A private workspace root and a clean identity/token environment."""
    rw = tmp_path / "rw"
    monkeypatch.setenv("WORKSPACE_ROOT", str(rw))
    for var in (
        "TRELLIS_USER_ID",
        "TRELLIS_USER_EMAIL",
        "TRELLIS_EDGE_TOKEN",
        "TRELLIS_EDGE_CONFIG",
        "TRELLIS_EDGE_MCPS_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    return rw


def _fake_server(state, env):
    """A real FastMCP server whose state lives in ``state`` (per session)."""
    from fastmcp import FastMCP

    server = FastMCP("stateful")

    @server.tool
    def set_value(key: str, value: object) -> str:
        """Store a raw JSON value under key."""
        state["data"][key] = value
        return "ok"

    @server.tool
    def get_value(key: str) -> object:
        """Read key back from this session's state."""
        return state["data"].get(key)

    @server.tool
    def get_home() -> str:
        """An opaque per-session home id (the container tmpfs, in production)."""
        return state["home"]

    @server.tool
    def env_dump() -> dict:
        """The environment this session received."""
        return dict(env)

    @server.tool
    async def slow(seconds: float = 5.0) -> str:
        """Sleep, counting the invocation first: a timeout must not replay it."""
        state["slow_calls"] += 1
        await asyncio.sleep(seconds)
        return "done"

    return server


class FakeRunnerTransport(ClientTransport):
    """Stands in for ``RunnerStdioTransport``: in-memory, one state per instance."""

    _counter = 0

    def __init__(self, entry_name, env, **kwargs):
        from fastmcp.client.transports.memory import FastMCPTransport

        type(self)._counter += 1
        self.target = entry_name
        self.env = dict(env)
        self.kwargs = kwargs
        self.closed = False
        self.state = {
            "data": {},
            "home": f"session-{self._counter}",
            "slow_calls": 0,
        }
        self._inner = FastMCPTransport(_fake_server(self.state, self.env))

    @contextlib.asynccontextmanager
    async def connect_session(self, *, transport_options=None, **session_kwargs):
        async with self._inner.connect_session(
            transport_options=transport_options, **session_kwargs
        ) as session:
            try:
                yield session
            finally:
                self.closed = True


@pytest.fixture
def fake_sessions(monkeypatch):
    """Fake the runner transport seam; returns every transport the manager built."""
    created = []

    def factory(entry, env, **kwargs):
        kwargs.setdefault("session_key", secrets.token_hex(16))
        transport = FakeRunnerTransport(entry.name, env, **kwargs)
        created.append(transport)
        return transport

    monkeypatch.setattr(proxy_mcp, "_runner_transport", factory)
    return created


def write_mcp(root, name="stateful", **overrides):
    directory = Path(root) / name
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "name": name,
        "transport": "stdio",
        "command": "stateful-mcp",
        "args": ["--serve"],
        "tools": SERVER_TOOLS,
    }
    payload.update(overrides)
    (directory / "mcp.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")
    return directory


def load_one(root, **export):
    entry = {"name": "stateful"}
    entry.update(export)
    entries = proxy_mcp.load_mcps(root, [entry])
    assert set(entries) == {"stateful"}, entries
    return entries


async def catalogs_for(entries):
    return {name: await proxy_mcp.build_catalog(entry) for name, entry in entries.items()}


def text(result):
    """The concatenated text blocks of a mapped MCP result."""
    return " ".join(block.get("text", "") for block in result["content"])


def structured(result):
    """A tool's structured result: the structuredContent block, else parsed text."""
    if result.get("structuredContent") is not None:
        return result["structuredContent"]
    return json.loads(text(result))


class FakeClient:
    """A client stand-in: records calls, spawns nothing."""

    def __init__(self, name=""):
        self.name = name
        self.calls = 0
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.closed = True
        return False

    async def call_tool(self, tool, args, **kwargs):
        self.calls += 1
        return SimpleNamespace(
            content=[{"type": "text", "text": "ok"}],
            is_error=False,
            structured_content=None,
        )




class FakeWebSocket:
    """Just enough of the relay socket to drive ``_serve`` twice in one loop."""

    def __init__(self, frames, grace=0.4):
        self._frames = [protocol.encode(frame) for frame in frames]
        self.sent = []
        self._grace = grace
        self._drained = False

    async def recv(self):
        if not self._frames:
            raise AssertionError("no frame available")
        return self._frames.pop(0)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._frames:
            return self._frames.pop(0)
        if not self._drained:
            self._drained = True
            await asyncio.sleep(self._grace)
        raise StopAsyncIteration

    async def send(self, data):
        self.sent.append(json.loads(data))

    async def close(self, code=1000, reason=""):
        return None


def call_frame(tool, args, *, call_id="1", mcp="stateful", identity=None, deadline_ms=DEADLINE_MS):
    frame = {
        "t": "call",
        "id": call_id,
        "kind": "mcp",
        "mcp": mcp,
        "tool": tool,
        "args": args,
        "deadline_ms": deadline_ms,
    }
    frame.update(identity or {})
    return frame


# ---------------------------------------------------------------- sessions


def test_same_user_sees_its_own_state_across_calls(tmp_path, fake_sessions):
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            await manager.call(
                "stateful", "set_value", {"key": "k", "value": "v1"}, {"user_email": "a@x"}, DEADLINE_MS
            )
            return await manager.call(
                "stateful", "get_value", {"key": "k"}, {"user_email": "a@x"}, DEADLINE_MS
            )
        finally:
            await manager.kill_all()

    result = asyncio.run(scenario())

    assert text(result) == "v1"
    assert len(fake_sessions) == 1


def test_two_users_never_share_state_or_a_transport(tmp_path, fake_sessions, edge_env):
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            for user, value in (("a@x", "alpha"), ("b@x", "beta")):
                await manager.call(
                    "stateful", "set_value", {"key": "k", "value": value}, {"user_email": user}, DEADLINE_MS
                )
            first = await manager.call(
                "stateful", "get_value", {"key": "k"}, {"user_email": "a@x"}, DEADLINE_MS
            )
            second = await manager.call(
                "stateful", "get_value", {"key": "k"}, {"user_email": "b@x"}, DEADLINE_MS
            )
            homes = {}
            for user in ("a@x", "b@x"):
                homes[user] = await manager.call(
                    "stateful", "get_home", {}, {"user_email": user}, DEADLINE_MS
                )
            return first, second, homes
        finally:
            await manager.kill_all()

    first, second, homes = asyncio.run(scenario())

    assert text(first) == "alpha"
    assert text(second) == "beta"
    assert text(homes["a@x"]) != text(homes["b@x"])
    # One container-backed transport per identity, with independent state.
    assert len(fake_sessions) == 2
    assert fake_sessions[0].state is not fake_sessions[1].state
    assert all(len(t.kwargs["session_key"]) == 32 for t in fake_sessions)
    # Session state lives in the container, never under the writable root.
    assert not (edge_env / "mcp-sessions").exists()


def test_sessions_survive_a_tunnel_reconnect(tmp_path, fake_sessions):
    """The manager owns sessions: a dropped socket must not reset a user's state."""
    root = tmp_path / "mcps"
    write_mcp(root)
    config = proxy.ProxyConfig(
        site="plant-floor",
        server_url="ws://relay.local/edge/v1/connect",
        mcps_dir=root,
        export_mcps=["stateful"],
    )

    async def scenario():
        session = proxy._Session(config)
        session.reload()
        await session.refresh_mcps()
        try:
            first = FakeWebSocket(
                [
                    {"t": "welcome", "site": "plant-floor"},
                    call_frame("set_value", {"key": "k", "value": "kept"}, call_id="1"),
                ],
                grace=1.0,
            )
            await proxy._serve(session, first)
            second = FakeWebSocket(
                [
                    {"t": "welcome", "site": "plant-floor"},
                    call_frame("get_value", {"key": "k"}, call_id="2"),
                ],
                grace=1.0,
            )
            await proxy._serve(session, second)
            return first, second
        finally:
            await session.mcp.kill_all()

    first, second = asyncio.run(scenario())

    assert first.sent[0]["caps"] == ["tools", "mcp"]
    assert second.sent[0]["mcps"][0]["name"] == "stateful"
    assert second.sent[1]["ok"] is True
    assert text(second.sent[1]["result"]) == "kept"
    assert len(fake_sessions) == 1


def test_eviction_reports_once_then_starts_a_fresh_session(tmp_path, fake_sessions):
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps", max_sessions=1)
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            await manager.call(
                "stateful", "set_value", {"key": "k", "value": "a"}, {"user_email": "a@x"}, DEADLINE_MS
            )
            # B needs the only slot, so A's idle session is evicted.
            await manager.call(
                "stateful", "set_value", {"key": "k", "value": "b"}, {"user_email": "b@x"}, DEADLINE_MS
            )
            with pytest.raises(proxy_mcp.McpCallError) as lost:
                await manager.call(
                    "stateful", "get_value", {"key": "k"}, {"user_email": "a@x"}, DEADLINE_MS
                )
            await manager.call(
                "stateful", "set_value", {"key": "k", "value": "a2"}, {"user_email": "a@x"}, DEADLINE_MS
            )
            result = await manager.call(
                "stateful", "get_value", {"key": "k"}, {"user_email": "a@x"}, DEADLINE_MS
            )
            return result, lost.value, [t.closed for t in fake_sessions]
        finally:
            await manager.kill_all()

    result, error, closed = asyncio.run(scenario())

    assert error.code == "mcp_session_lost"
    assert "eviction" in error.message
    assert text(result) == "a2"
    # Each identity's session was evicted once: A by B, then B by A's respawn.
    assert closed == [True, True, False]


# --- no retired session may leak its container --------------------------------------


def test_an_evicted_session_closes_its_transport(tmp_path, fake_sessions):
    """A session that is detached without closing its client leaks a runner container."""
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps", max_sessions=1)
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            await manager.call(
                "stateful", "set_value", {"key": "k", "value": "a"}, {"user_email": "a@x"}, DEADLINE_MS
            )
            assert len(fake_sessions) == 1
            # B needs the only slot, so A's idle session is evicted and reaped.
            await manager.call(
                "stateful", "set_value", {"key": "k", "value": "b"}, {"user_email": "b@x"}, DEADLINE_MS
            )
            return fake_sessions[0].closed
        finally:
            await manager.kill_all()

    assert asyncio.run(scenario()) is True


def test_kill_all_closes_every_transport(tmp_path, fake_sessions):
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        manager.set_entries(entries, await catalogs_for(entries))
        for user in ("a@x", "b@x"):
            await manager.call(
                "stateful", "set_value", {"key": "k", "value": user}, {"user_email": user}, DEADLINE_MS
            )
        assert len(fake_sessions) == 2
        assert not any(t.closed for t in fake_sessions)
        await manager.kill_all()
        return dict(manager._sessions), [t.closed for t in fake_sessions]

    sessions, closed = asyncio.run(scenario())

    assert sessions == {}
    assert closed == [True, True]


def test_a_lost_runner_session_maps_to_mcp_session_lost_and_respawns(
    tmp_path, monkeypatch
):
    """A deleted runner container is reported for that call and retried on the next."""
    from core.execution.client import RunnerCallError

    created = []

    class LostClient(FakeClient):
        def __init__(self, name=""):
            super().__init__(name)
            created.append(self)

        async def call_tool(self, tool, args, **kwargs):
            if len(created) == 1:
                # What the transport surfaces when the runner no longer knows the id.
                raise RunnerCallError("session_not_found", "no such session")
            return await super().call_tool(tool, args, **kwargs)

    monkeypatch.setattr(proxy_mcp, "_transport", lambda *a, **k: LostClient())
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            with pytest.raises(proxy_mcp.McpCallError) as lost:
                await manager.call("stateful", "get_value", {}, {"user_email": "a@x"}, DEADLINE_MS)
            retried = await manager.call(
                "stateful", "get_value", {}, {"user_email": "a@x"}, DEADLINE_MS
            )
            return lost.value, retried, len(created)
        finally:
            await manager.kill_all()

    error, retried, sessions = asyncio.run(scenario())

    assert error.code == "mcp_session_lost"
    assert text(retried) == "ok"
    assert sessions == 2


def test_a_changed_server_reload_closes_the_old_session(tmp_path, fake_sessions):
    """SIGHUP-for-changed-servers must tear the container down, not just its entry."""
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            catalogs = await catalogs_for(entries)
            manager.set_entries(entries, catalogs)
            await manager.call(
                "stateful", "set_value", {"key": "k", "value": "v"}, {"user_email": "a@x"}, DEADLINE_MS
            )
            assert len(fake_sessions) == 1
            changed = dict(entries)
            changed["stateful"] = replace(
                entries["stateful"],
                config=entries["stateful"].config.model_copy(update={"args": ["--changed"]}),
            )
            manager.set_entries(changed, catalogs)
            await manager.reap()
            return fake_sessions[0].closed
        finally:
            await manager.kill_all()

    assert asyncio.run(scenario()) is True


def test_concurrent_first_calls_spawn_exactly_one_server(tmp_path, monkeypatch):
    """Two first calls for one key must share one spawn, one session, one lock."""
    created = []

    class SlowClient(FakeClient):
        def __init__(self, name=""):
            super().__init__(name)
            created.append(self)

        async def __aenter__(self):
            # A yield point inside creation: without the manager's lock the second
            # caller enters here too and spawns a second, untracked server.
            await asyncio.sleep(0.05)
            return self

    monkeypatch.setattr(proxy_mcp, "_transport", lambda *a, **k: SlowClient())
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            results = await asyncio.gather(
                manager.call("stateful", "get_value", {}, {"user_email": "a@x"}, DEADLINE_MS),
                manager.call("stateful", "get_value", {}, {"user_email": "a@x"}, DEADLINE_MS),
            )
            return results, list(manager._sessions), [client.calls for client in created]
        finally:
            await manager.kill_all()

    results, sessions, calls = asyncio.run(scenario())

    assert [text(result) for result in results] == ["ok", "ok"]
    assert sessions == [("stateful", SESSION_KEY)]
    assert len(created) == 1, f"{len(created)} servers spawned for one session"
    # Both calls went through the one session's client (hence the one session lock).
    assert calls == [2]


def test_the_session_env_is_scoped_and_carries_the_caller_identity(
    tmp_path, fake_sessions, monkeypatch
):
    """Only declared keys + identity reach the runner; the host env never does."""
    monkeypatch.setenv("TRELLIS_EDGE_TOKEN", "edge_plant-floor_supersecret")
    monkeypatch.setenv("UNDECLARED_PROCESS_VAR", "should-not-leak")
    # A declared secret is no longer read from the process env (v0.7.1): it must come
    # from the edge's shared file.
    monkeypatch.setenv("DEVOPS_PASSWORD", "process-env-must-not-win")
    write_mcp(
        tmp_path / "mcps",
        secrets=["DEVOPS_PASSWORD"],
        tools=SERVER_TOOLS + [ENV_DUMP_TOOL],
    )
    store = credentials_at(tmp_path)
    store.secrets_dir.mkdir(parents=True, exist_ok=True)
    (store.secrets_dir / "stateful.env").write_text(
        "DEVOPS_PASSWORD=hunter2\n", encoding="utf-8"
    )
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager(credentials=store)

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            return await manager.call(
                "stateful",
                "env_dump",
                {},
                {"user": "user-1", "user_email": "user-1@corp.example"},
                DEADLINE_MS,
            )
        finally:
            await manager.kill_all()

    seen = structured(asyncio.run(scenario()))

    assert "TRELLIS_EDGE_TOKEN" not in seen
    assert "UNDECLARED_PROCESS_VAR" not in seen
    assert seen["DEVOPS_PASSWORD"] == "hunter2"
    assert seen["TRELLIS_USER_ID"] == "user-1"
    assert seen["TRELLIS_USER_EMAIL"] == "user-1@corp.example"
    # The container's tmpfs owns HOME/TMPDIR: the edge must not set them.
    for name in ("HOME", "TMPDIR", "TMP", "TEMP"):
        assert name not in fake_sessions[0].env
    # Exactly what the runner will accept: declared keys + the identity pair.
    assert set(seen) == {
        "DEVOPS_PASSWORD",
        "TRELLIS_USER_ID",
        "TRELLIS_USER_EMAIL",
    }


def test_a_call_past_its_deadline_is_reported_and_never_replayed(tmp_path, fake_sessions):
    """No MCP call is retried: a timed-out action may change state twice."""
    write_mcp(
        tmp_path / "mcps",
        tools=SERVER_TOOLS + [SLOW_TOOL],
    )
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            started = time.monotonic()
            with pytest.raises(proxy_mcp.McpCallError) as timeout:
                await manager.call(
                    "stateful", "slow", {"seconds": 30}, {"user_email": "a@x"}, deadline_ms=1_000
                )
            elapsed = time.monotonic() - started
            # The server counts the invocation before it sleeps: give a replay a
            # generous chance to show up, then read the counter.
            await asyncio.sleep(1.0)
            return timeout.value, elapsed
        finally:
            await manager.kill_all()

    error, elapsed = asyncio.run(scenario())

    assert error.code == "edge_timeout"
    assert elapsed < 5.0
    assert fake_sessions[0].state["slow_calls"] == 1


def test_run_kills_the_sessions_and_the_sweeper_in_its_finally(tmp_path, monkeypatch):
    """``run()`` owns the sessions: any exit path must stop every server process."""
    calls = []

    class SpyManager:
        def __init__(self, **kwargs):
            calls.append("init")

        def set_entries(self, entries, catalogs):
            pass

        def installed_entry(self, name):
            return None

        async def sweep(self):
            calls.append("sweep")

        async def reap(self):
            pass

        async def kill_all(self):
            calls.append("kill_all")

        def retire_all(self):
            calls.append("retire_all")

    class FakeConnect:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return SimpleNamespace(close_code=1011, send=None, close=None)

        async def __aexit__(self, *exc):
            return False

    async def exploding_serve(session, ws):
        raise RuntimeError("socket exploded")

    def _fake_connect(url, additional_headers=None, **kwargs):
        return FakeConnect()

    monkeypatch.setattr(proxy_mcp, "McpSessionManager", SpyManager)
    monkeypatch.setattr(proxy, "_SECRET_ENV_NAMES", set())
    monkeypatch.setattr(proxy, "_serve", exploding_serve)
    monkeypatch.setattr(proxy, "_connect_factory", lambda: _fake_connect)
    monkeypatch.setenv("TRELLIS_EDGE_TOKEN", "edge_plant-floor_secret")

    config = proxy.ProxyConfig(
        site="plant-floor",
        server_url="ws://relay.local/edge/v1/connect",
        mcps_dir=tmp_path / "mcps",
        export_mcps=[],
    )

    async def scenario():
        with pytest.raises(RuntimeError, match="socket exploded"):
            await proxy.run(config, once=True)
        current = asyncio.current_task()
        return [task for task in asyncio.all_tasks() if task is not current and not task.done()]

    leftover = asyncio.run(scenario())

    assert calls[0] == "init"
    assert calls[-1] == "kill_all"
    assert "sweep" not in calls  # the sweeper must not fire before its first interval
    assert leftover == [], f"tasks outlived run(): {leftover}"


def test_ttl_sweep_reports_once_then_starts_a_fresh_session(tmp_path, fake_sessions):
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps", session_ttl_minutes=1)
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            await manager.call(
                "stateful", "set_value", {"key": "k", "value": "v"}, {"user_email": "a@x"}, DEADLINE_MS
            )
            # The TTL is configured in whole minutes; age the session instead of
            # sleeping a minute (the sweep itself is what is under test).
            manager._sessions[("stateful", SESSION_KEY)].last_used -= 120
            with pytest.raises(proxy_mcp.McpCallError) as lost:
                await manager.call(
                    "stateful", "get_value", {"key": "k"}, {"user_email": "a@x"}, DEADLINE_MS
                )
            await manager.call(
                "stateful", "set_value", {"key": "k", "value": "fresh"}, {"user_email": "a@x"}, DEADLINE_MS
            )
            return await manager.call(
                "stateful", "get_value", {"key": "k"}, {"user_email": "a@x"}, DEADLINE_MS
            ), lost.value
        finally:
            await manager.kill_all()

    result, error = asyncio.run(scenario())

    assert error.code == "mcp_session_lost"
    assert "idle timeout" in error.message
    assert text(result) == "fresh"


def test_reload_retires_only_the_sessions_of_changed_servers(tmp_path, monkeypatch):
    closed = []

    class FakeClient:
        def __init__(self, name):
            self.name = name

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            closed.append(self.name)
            return False

        async def call_tool(self, tool, args, **kwargs):
            return SimpleNamespace(content=[], is_error=False, structured_content=None)

    monkeypatch.setattr(proxy_mcp, "_transport", lambda entry, *a, **k: FakeClient(entry.name))
    root = tmp_path / "mcps"
    write_mcp(root, name="alpha")
    write_mcp(root, name="beta")
    entries = proxy_mcp.load_mcps(root, ["alpha", "beta"])

    async def scenario():
        manager = proxy_mcp.McpSessionManager()
        try:
            catalogs = await catalogs_for(entries)
            manager.set_entries(entries, catalogs)
            await manager.call("alpha", "get_value", {}, {"user_email": "a@x"}, DEADLINE_MS)
            await manager.call("beta", "get_value", {}, {"user_email": "a@x"}, DEADLINE_MS)
            changed = dict(entries)
            changed["beta"] = replace(
                entries["beta"],
                config=entries["beta"].config.model_copy(update={"args": ["--changed"]}),
            )
            manager.set_entries(changed, catalogs)
            await manager.reap()
            return list(manager._sessions), set(manager._tombs)
        finally:
            await manager.kill_all()

    remaining, tombs = asyncio.run(scenario())

    assert remaining == [("alpha", SESSION_KEY)]
    assert ("beta", SESSION_KEY) in tombs
    assert closed[0] == "beta"


# --- reload windows -----------------------------------------------------------------


def _static_session(tmp_path, monkeypatch):
    """A session over one statically-catalogued server and a fake client (no spawn)."""
    root = tmp_path / "mcps"
    write_mcp(root)
    config_path = tmp_path / "proxy.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "site": "plant-floor",
                "server_url": "ws://relay.local/edge/v1/connect",
                "mcps_dir": str(root),
                "export_mcps": ["stateful"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(proxy_mcp, "_transport", lambda *a, **k: FakeClient())
    session = proxy._Session(proxy.load_config(config_path), config_path)
    session.reload()
    return session


def test_a_reload_keeps_answering_calls_while_the_catalogs_rebuild(tmp_path, monkeypatch):
    """The old catalog must stay installed until the new one exists: no unknown_tool window."""
    session = _static_session(tmp_path, monkeypatch)
    started = asyncio.Event()
    release = asyncio.Event()
    real_build = proxy_mcp.build_catalog

    async def gated_build(*args, **kwargs):
        started.set()
        await release.wait()
        return await real_build(*args, **kwargs)

    async def scenario():
        try:
            await session.refresh_mcps()
            assert set(session.mcp_catalogs) == {"stateful"}

            session.reload()  # SIGHUP reloads the files...
            monkeypatch.setattr(proxy_mcp, "build_catalog", gated_build)
            refresh = asyncio.create_task(session.refresh_mcps())  # ...then rebuilds
            await asyncio.wait_for(started.wait(), timeout=5)

            # Mid-rebuild a call still runs against the installed catalog.
            during = await session.mcp.call(
                "stateful", "get_value", {}, {"user_email": "a@x"}, DEADLINE_MS
            )
            release.set()
            await asyncio.wait_for(refresh, timeout=5)
            after = await session.mcp.call(
                "stateful", "get_value", {}, {"user_email": "a@x"}, DEADLINE_MS
            )
            return during, after, set(session.mcp_catalogs)
        finally:
            await session.mcp.kill_all()

    during, after, catalogs = asyncio.run(scenario())

    assert text(during) == "ok"
    assert text(after) == "ok"
    assert catalogs == {"stateful"}


def test_a_failed_rebuild_keeps_the_previous_catalog_usable(tmp_path, monkeypatch, caplog):
    session = _static_session(tmp_path, monkeypatch)

    async def failing_build(*args, **kwargs):
        raise proxy_mcp.McpCallError("mcp_unavailable", "did not answer tools/list")

    async def scenario():
        try:
            await session.refresh_mcps()
            monkeypatch.setattr(proxy_mcp, "build_catalog", failing_build)
            session.reload()
            with caplog.at_level(logging.ERROR, logger="core.proxy"):
                await session.refresh_mcps()
            return await session.mcp.call(
                "stateful", "get_value", {}, {"user_email": "a@x"}, DEADLINE_MS
            )
        finally:
            await session.mcp.kill_all()

    result = asyncio.run(scenario())

    assert text(result) == "ok"
    assert "keeping the previously published catalog" in caplog.text


def test_a_changed_server_whose_discovery_fails_is_dropped(tmp_path, monkeypatch, caplog):
    """A stale catalog for a *changed* server would advertise tools it no longer has."""
    session = _static_session(tmp_path, monkeypatch)

    async def failing_build(*args, **kwargs):
        raise proxy_mcp.McpCallError("mcp_unavailable", "did not answer tools/list")

    async def scenario():
        try:
            await session.refresh_mcps()
            monkeypatch.setattr(proxy_mcp, "build_catalog", failing_build)
            session.mcps = {
                "stateful": replace(
                    session.mcps["stateful"],
                    config=session.mcps["stateful"].config.model_copy(
                        update={"args": ["--changed"]}
                    ),
                )
            }
            with caplog.at_level(logging.ERROR, logger="core.proxy"):
                await session.refresh_mcps()
            return set(session.mcp_catalogs)
        finally:
            await session.mcp.kill_all()

    assert asyncio.run(scenario()) == set()
    assert "not exporting it" in caplog.text


def test_a_superseded_rebuild_does_not_install_its_stale_catalog(tmp_path, monkeypatch, caplog):
    """Two SIGHUPs inside the discovery window: the older result must be discarded."""
    session = _static_session(tmp_path, monkeypatch)
    real_build = proxy_mcp.build_catalog
    gates = {"first": asyncio.Event(), "release_first": asyncio.Event()}
    calls = {"n": 0}

    async def gated_build(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            gates["first"].set()
            await gates["release_first"].wait()
        return await real_build(*args, **kwargs)

    async def scenario():
        try:
            monkeypatch.setattr(proxy_mcp, "build_catalog", gated_build)
            older = asyncio.create_task(session.refresh_mcps())
            await asyncio.wait_for(gates["first"].wait(), timeout=5)

            # A second SIGHUP lands while the first rebuild is still discovering.
            session.reload()
            newer = asyncio.create_task(session.refresh_mcps())
            await asyncio.wait_for(newer, timeout=5)

            with caplog.at_level(logging.INFO, logger="core.proxy"):
                gates["release_first"].set()
                await asyncio.wait_for(older, timeout=5)
            return set(session.mcp_catalogs)
        finally:
            await session.mcp.kill_all()

    assert asyncio.run(scenario()) == {"stateful"}
    assert "superseded by a newer reload" in caplog.text


# ---------------------------------------------------------------- catalogs


def _large_one_of_schema():
    branches = []
    for index in range(40):
        branches.append(
            {
                "type": "object",
                "properties": {
                    "action": {"const": f"action_{index}"},
                    "target": {"type": "string", "description": "t" * 600},
                    "params": {
                        "type": "object",
                        "properties": {
                            "force": {"type": "boolean"},
                            "ids": {"type": "array", "items": {"type": "integer"}},
                            "note": {"type": "string", "description": "n" * 200},
                        },
                        "required": ["ids"],
                    },
                },
                "required": ["action", "target"],
            }
        )
    return {"type": "object", "oneOf": branches}


def test_a_large_root_one_of_schema_round_trips_verbatim(tmp_path):
    schema = _large_one_of_schema()
    assert len(json.dumps(schema)) > 30_000, "fixture schema is too small to be a real test"

    root = tmp_path / "mcps"
    write_mcp(root, tools=[{"name": "meta_tool", "description": "meta", "inputSchema": schema}])

    catalog = asyncio.run(proxy_mcp.build_catalog(load_one(root)["stateful"]))
    published = catalog.tools[0].input_schema
    assert json.dumps(published, sort_keys=True) == json.dumps(schema, sort_keys=True)

    frame = proxy.hello_frame({}, {"stateful": catalog})
    _, _, _, mcps, _ = protocol.validate_hello(frame)
    assert json.dumps(mcps[0].tools[0].input_schema, sort_keys=True) == json.dumps(
        schema, sort_keys=True
    )


def test_a_server_without_a_static_catalog_is_discovered_live(tmp_path, fake_sessions):
    proxy_mcp.clear_discovery_cache()
    write_mcp(tmp_path / "mcps", tools=[])
    entries = load_one(tmp_path / "mcps")

    try:
        catalog = asyncio.run(proxy_mcp.build_catalog(entries["stateful"]))
        # Cached in memory: a second build must not open another discovery session.
        again = asyncio.run(proxy_mcp.build_catalog(entries["stateful"]))
    finally:
        proxy_mcp.clear_discovery_cache()

    assert [tool.name for tool in catalog.tools] == [
        "set_value",
        "get_value",
        "get_home",
        "env_dump",
        "slow",
    ]
    assert catalog.tools[0].input_schema["type"] == "object"
    assert [tool.name for tool in again.tools] == [tool.name for tool in catalog.tools]
    # A throwaway discovery container, not a warm mcp_session.
    assert len(fake_sessions) == 1
    assert fake_sessions[0].kwargs["kind"] == "discovery"
    assert fake_sessions[0].kwargs["deadline_ms"] == proxy_mcp.DISCOVERY_DEADLINE_MS
    assert fake_sessions[0].closed is True


def test_include_tools_narrows_the_published_catalog(tmp_path):
    root = tmp_path / "mcps"
    write_mcp(root)

    entries = load_one(root, include_tools=["get_value"])
    catalog = asyncio.run(proxy_mcp.build_catalog(entries["stateful"]))

    assert [tool.name for tool in catalog.tools] == ["get_value"]


def test_excluded_and_unknown_names_are_refused_on_the_edge(tmp_path):
    root = tmp_path / "mcps"
    write_mcp(
        root,
        tools=SERVER_TOOLS + [{"name": "secret_tool", "description": "no", "inputSchema": {}}],
    )
    entries = load_one(root, exclude_tools=["secret_tool"])

    async def scenario():
        manager = proxy_mcp.McpSessionManager()
        catalog = await proxy_mcp.build_catalog(entries["stateful"])
        # A relay that ignored the catalog and asked anyway: the edge is the name
        # authority, so the excluded tool has to be refused here.
        forced = {
            "stateful": protocol.EdgeMcp(
                name="stateful",
                transport="stdio",
                tools=list(catalog.tools) + [protocol.EdgeMcpTool(name="secret_tool")],
            )
        }
        manager.set_entries(entries, forced)
        codes = []
        for mcp, tool in (
            ("stateful", "secret_tool"),
            ("stateful", "not_a_tool"),
            ("ghost", "get_value"),
        ):
            with pytest.raises(proxy_mcp.McpCallError) as exc:
                await manager.call(mcp, tool, {}, {}, DEADLINE_MS)
            codes.append(exc.value.code)

        # ``include_tools`` is re-checked by the same helper: a forced catalog that
        # names a non-included tool is refused too.
        narrow = load_one(root, include_tools=["get_value"])
        manager.set_entries(narrow, forced)
        with pytest.raises(proxy_mcp.McpCallError) as exc:
            await manager.call("stateful", "set_value", {}, {}, DEADLINE_MS)
        return codes, exc.value.code, [tool.name for tool in catalog.tools]

    codes, not_included, published = asyncio.run(scenario())

    assert codes == ["unknown_tool", "unknown_tool", "unknown_mcp"]
    assert not_included == "unknown_tool"
    assert "secret_tool" not in published


def test_hello_frame_advertises_the_mcp_capability(tmp_path):
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    catalog = asyncio.run(proxy_mcp.build_catalog(entries["stateful"]))

    frame = proxy.hello_frame({}, {"stateful": catalog})

    assert frame["caps"] == ["tools", "mcp"]
    assert [mcp["name"] for mcp in frame["mcps"]] == ["stateful"]
    proto, _version, tools, mcps, caps = protocol.validate_hello(frame)
    assert proto == protocol.PROTO == 3
    assert tools == []
    assert caps == ["tools", "mcp"]
    assert [tool.name for tool in mcps[0].tools] == ["set_value", "get_value", "get_home"]


def test_hello_frame_without_mcps_is_tools_only():
    frame = proxy.hello_frame({})

    assert frame["caps"] == ["tools"]
    assert frame["mcps"] == []
    _, _, _, mcps, caps = protocol.validate_hello(frame)
    assert mcps == [] and caps == ["tools"]


# ---------------------------------------------------------------- arguments


def test_the_edge_passes_arguments_through_untouched(tmp_path, monkeypatch):
    seen = []

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def call_tool(self, tool, args, **kwargs):
            seen.append((tool, args))
            return SimpleNamespace(content=[], is_error=False, structured_content=None)

    monkeypatch.setattr(proxy_mcp, "_transport", lambda *a, **k: FakeClient())
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            args = {"key": "k", "value": "5"}
            await manager.call("stateful", "set_value", args, {}, DEADLINE_MS)
            return args
        finally:
            await manager.kill_all()

    args = asyncio.run(scenario())

    assert seen == [("set_value", args)]
    assert seen[0][1] is args
    assert type(seen[0][1]["value"]) is str


def test_a_string_argument_reaches_the_server_as_a_string(tmp_path, fake_sessions):
    """No ``coerce_arg`` on the MCP path: the server, not the edge, validates args."""
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            await manager.call(
                "stateful",
                "set_value",
                {"key": "n", "value": "5"},
                {"user_email": "a@x"},
                DEADLINE_MS,
            )
            return await manager.call(
                "stateful", "get_value", {"key": "n"}, {"user_email": "a@x"}, DEADLINE_MS
            )
        finally:
            await manager.kill_all()

    result = asyncio.run(scenario())

    assert text(result) == "5"
    assert isinstance(fake_sessions[0].state["data"]["n"], str)


# ---------------------------------------------------------------- loading


def test_load_mcps_exports_nothing_by_default(tmp_path, caplog):
    write_mcp(tmp_path / "mcps")

    with caplog.at_level(logging.WARNING, logger="core.proxy_mcp"):
        assert proxy_mcp.load_mcps(tmp_path / "mcps", []) == {}

    assert "export_mcps is empty" in caplog.text


def test_load_mcps_parses_the_mapping_form(tmp_path):
    write_mcp(tmp_path / "mcps")

    entry = proxy_mcp.load_mcps(
        tmp_path / "mcps",
        [
            {
                "name": "stateful",
                "include_tools": ["get_value"],
                "exclude_tools": ["set_value"],
                "credential_mode": "per_user_required",
                "session_ttl_minutes": 5,
                "max_sessions": 2,
            }
        ],
    )["stateful"]

    assert entry.include_tools == ("get_value",)
    assert entry.exclude_tools == ("set_value",)
    assert entry.credential_mode == "per_user_required"
    assert entry.session_ttl_minutes == 5
    assert entry.max_sessions == 2
    assert entry.directory == (tmp_path / "mcps" / "stateful").resolve()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"transport": "carrier-pigeon"}, "transport"),
        (
            {
                "tools": [
                    {"name": "wide", "description": "w", "inputSchema": {"description": "x" * 200_000}}
                ]
            },
            "exceeds",
        ),
    ],
)
def test_load_mcps_skips_an_unpublishable_server_with_a_warning(tmp_path, caplog, overrides, message):
    write_mcp(tmp_path / "mcps", **overrides)

    with caplog.at_level(logging.WARNING, logger="core.proxy_mcp"):
        entries = proxy_mcp.load_mcps(tmp_path / "mcps", ["stateful"])

    assert entries == {}
    assert message in caplog.text


def test_load_mcps_skips_a_yaml_entry_with_an_unpublishable_name(tmp_path, caplog):
    """A second entry in one mcp.yaml with a name the relay would refuse."""
    directory = tmp_path / "mcps" / "stateful"
    directory.mkdir(parents=True)
    payload = [
        {"name": "stateful", "transport": "stdio", "command": sys.executable, "tools": SERVER_TOOLS},
        {"name": "bad__name", "transport": "stdio", "command": sys.executable},
    ]
    (directory / "mcp.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="core.proxy_mcp"):
        entries = proxy_mcp.load_mcps(tmp_path / "mcps", ["stateful"])

    assert set(entries) == {"stateful"}
    assert "not publishable" in caplog.text


def test_load_mcps_warns_about_a_missing_server(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="core.proxy_mcp"):
        entries = proxy_mcp.load_mcps(tmp_path / "mcps", ["ghost"])

    assert entries == {}
    assert "ghost" in caplog.text


def test_load_mcps_drops_servers_beyond_the_aggregate_cap(tmp_path, caplog):
    """MAX_MCPS is an aggregate hello limit: one over the cap fails the whole frame."""
    root = tmp_path / "mcps"
    names = [f"mcp-{index:02d}" for index in range(protocol.MAX_MCPS + 3)]
    for name in names:
        write_mcp(root, name=name)

    with caplog.at_level(logging.WARNING, logger="core.proxy_mcp"):
        entries = proxy_mcp.load_mcps(root, names)

    assert len(entries) == protocol.MAX_MCPS
    # Deterministic subset: the same servers survive every reload.
    assert set(entries) == set(sorted(names)[: protocol.MAX_MCPS])
    assert f"maximum of {protocol.MAX_MCPS}" in caplog.text


def test_an_export_whose_catalog_blows_the_frame_budget_is_dropped(monkeypatch, caplog):
    """Oversized catalogs must be dropped, not looped on with CLOSE_MALFORMED."""
    monkeypatch.setattr(protocol, "MAX_FRAME_BYTES", 4_000)
    big = protocol.validate_mcps(
        [
            {
                "name": "big",
                "transport": "stdio",
                "tools": [
                    {"name": "wide", "description": "d" * 8_000, "inputSchema": {}}
                ],
            }
        ]
    )[0]
    small = protocol.validate_mcps(
        [
            {
                "name": "small",
                "transport": "stdio",
                "tools": [{"name": "narrow", "description": "s", "inputSchema": {}}],
            }
        ]
    )[0]

    with caplog.at_level(logging.ERROR, logger="core.proxy"):
        remaining = proxy._fit_hello_budget({}, {"big": big, "small": small})

    assert set(remaining) == {"small"}
    assert len(protocol.encode(proxy.hello_frame({}, remaining)).encode("utf-8")) <= 4_000
    assert "MAX_FRAME_BYTES" in caplog.text
    assert "big" in caplog.text


def test_a_credential_mode_is_honoured_without_a_warning(tmp_path, caplog):
    """The mode is enforced now (Phase 5): loading it is silent, not a deprecation."""
    write_mcp(tmp_path / "mcps")

    with caplog.at_level(logging.WARNING, logger="core.proxy_mcp"):
        entries = proxy_mcp.load_mcps(
            tmp_path / "mcps", [{"name": "stateful", "credential_mode": "per_user_required"}]
        )

    assert entries["stateful"].credential_mode == "per_user_required"
    # No "not enforced" deprecation: the mode is enforced at session creation now.
    assert "credential_mode" not in caplog.text


def test_no_warning_for_the_default_credential_mode(tmp_path, caplog):
    write_mcp(tmp_path / "mcps")

    with caplog.at_level(logging.WARNING, logger="core.proxy_mcp"):
        entries = proxy_mcp.load_mcps(tmp_path / "mcps", ["stateful"])

    assert "credential_mode" not in caplog.text
    # Silence is not the property under test: the default must actually be ``shared``.
    assert entries["stateful"].credential_mode == "shared"


def test_load_config_reads_mcps_dir_and_export_mcps(tmp_path):
    config_path = tmp_path / "proxy.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "site": "plant-floor",
                "server_url": "ws://relay.local/edge/v1/connect",
                "mcps_dir": "./edge-mcps",
                "export_mcps": ["alpha", {"name": "beta", "include_tools": ["t"]}],
            }
        ),
        encoding="utf-8",
    )

    config = proxy.load_config(config_path)

    assert config.mcps_dir == Path("edge-mcps")
    assert config.export_mcps == ["alpha", {"name": "beta", "include_tools": ["t"]}]


def test_mcps_dir_can_be_overridden_from_the_environment(tmp_path, monkeypatch):
    config_path = tmp_path / "proxy.yaml"
    config_path.write_text(
        yaml.safe_dump({"site": "plant-floor", "server_url": "ws://relay.local/edge/v1/connect"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("TRELLIS_EDGE_MCPS_DIR", str(tmp_path / "mounted"))

    assert proxy.load_config(config_path).mcps_dir == tmp_path / "mounted"


@pytest.mark.parametrize("entry", [5, ["alpha"], {"name": "bad__name"}, {"include_tools": ["t"]}])
def test_load_config_rejects_a_malformed_export_mcps_entry(tmp_path, entry):
    config_path = tmp_path / "proxy.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "site": "plant-floor",
                "server_url": "ws://relay.local/edge/v1/connect",
                "export_mcps": [entry],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="export_mcps"):
        proxy.load_config(config_path)


def test_reload_applies_a_changed_export_mcps_allowlist(tmp_path):
    root = tmp_path / "mcps"
    write_mcp(root, name="alpha")
    write_mcp(root, name="beta")
    config_path = tmp_path / "proxy.yaml"

    def write(exports):
        config_path.write_text(
            yaml.safe_dump(
                {
                    "site": "plant-floor",
                    "server_url": "ws://relay.local/edge/v1/connect",
                    "mcps_dir": str(root),
                    "export_mcps": exports,
                }
            ),
            encoding="utf-8",
        )

    write(["alpha"])
    session = proxy._Session(proxy.load_config(config_path), config_path)
    session.reload()
    assert set(session.mcps) == {"alpha"}

    write(["alpha", "beta"])
    session.reload()

    assert set(session.mcps) == {"alpha", "beta"}


def test_signature_changes_when_the_server_or_its_policy_changes(tmp_path):
    write_mcp(tmp_path / "mcps")
    entry = load_one(tmp_path / "mcps")

    same = replace(entry["stateful"])
    assert same.signature() == entry["stateful"].signature()

    for change in (
        {"session_ttl_minutes": 5},  # policy only: sessions keep running
        {"max_sessions": 4},
    ):
        assert replace(entry["stateful"], **change).signature() == entry["stateful"].signature()

    for change in (
        {"include_tools": ("get_value",)},
        {"exclude_tools": ("set_value",)},
        {"credential_mode": "per_user"},
    ):
        assert replace(entry["stateful"], **change).signature() != entry["stateful"].signature()


def test_truncation_marks_an_oversized_result():
    payload = {
        "content": [{"type": "text", "text": "x" * 200_000}],
        "isError": False,
    }

    truncated = proxy_mcp._truncate(payload)

    assert len(proxy_mcp._encode(truncated)) <= proxy_mcp.MAX_RESULT_CHARS
    assert "truncated by edge: original" in truncated["content"][0]["text"]
    assert truncated["isError"] is False


def test_small_results_are_untouched():
    payload = {"content": [{"type": "text", "text": "ok"}], "isError": False}

    assert proxy_mcp._truncate(payload) is payload


def test_the_session_identity_and_key_come_from_the_frame_never_the_token(
    tmp_path, fake_sessions
):
    """v0.7.1/v0.7.2: no token-derived identity on the edge. The frame is the only source."""
    write_mcp(tmp_path / "mcps", tools=SERVER_TOOLS + [ENV_DUMP_TOOL])
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()
    identity = {"user": "frame-user", "user_email": "frame@example.com"}

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            # R1: the call takes no token at all -- the frame's identity is the whole
            # of what the session and the runner see.
            result = await manager.call(
                "stateful",
                "env_dump",
                {},
                identity,
                DEADLINE_MS,
            )
            return result, list(manager._sessions)
        finally:
            await manager.kill_all()

    result, sessions = asyncio.run(scenario())
    seen = structured(result)

    assert seen["TRELLIS_USER_ID"] == "frame-user"
    assert seen["TRELLIS_USER_EMAIL"] == "frame@example.com"
    # One session, keyed by the frame identity (normalized email), not by the token.
    assert sessions == [
        ("stateful", edge_user_secrets.normalize_email("frame@example.com"))
    ]


def test_identity_key_prefers_the_email():
    assert proxy_mcp._identity_key({"user_email": "a@x", "user": "u1"}) == SESSION_KEY
    # Two spellings of one address are one person: one session, one server process.
    assert proxy_mcp._identity_key({"user_email": "  A@X "}) == SESSION_KEY
    assert proxy_mcp._identity_key({"user": "u1"}) == "u1"
    assert proxy_mcp._identity_key({}) == "anonymous"
    assert proxy_mcp._identity_key({"user_email": "", "user": None}) == "anonymous"


# ---------------------------------------------------------------- hygiene


def test_tombstones_are_bounded_and_still_fire_once():
    """A long-lived edge must not grow the one-shot tombstone map without bound."""
    manager = proxy_mcp.McpSessionManager()
    for index in range(proxy_mcp.MAX_SESSION_TOMBS + 10):
        manager._add_tomb(("stateful", f"user-{index}"))

    assert len(manager._tombs) == proxy_mcp.MAX_SESSION_TOMBS
    assert ("stateful", "user-0") not in manager._tombs
    assert ("stateful", f"user-{proxy_mcp.MAX_SESSION_TOMBS + 9}") in manager._tombs


def test_a_cancelled_reap_never_drops_a_session(tmp_path):
    """Cancellation mid-reap must not leak the sessions it had not closed yet."""
    gate = asyncio.Event()
    closed = []

    class GatedClient(FakeClient):
        async def __aexit__(self, *exc):
            closed.append(self.name)
            if self.name == "first":
                await gate.wait()
            return False

    async def scenario():
        manager = proxy_mcp.McpSessionManager()
        for name in ("first", "second"):
            manager._sessions[(name, SESSION_KEY)] = proxy_mcp._ServerSession(
                name, GatedClient(name)
            )
        for key in list(manager._sessions):
            manager._retire(key, tombstone=False)

        task = asyncio.create_task(manager.reap())
        await asyncio.sleep(0.05)  # let it block inside the first __aexit__
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        retained = [session.mcp for session in manager._retired]

        gate.set()
        await manager.reap()
        return retained, manager._retired, closed

    retained, after, closed = asyncio.run(scenario())

    assert retained == ["first", "second"]
    assert after == []
    assert set(closed) == {"first", "second"}


def test_the_idle_sweeper_sweeps_on_its_interval_until_cancelled():
    """spec D2: idle sessions are retired by a periodic task, not only by a call."""
    calls = []

    class FakeManager:
        async def sweep(self):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("one bad sweep must not kill the sweeper")

    session = SimpleNamespace(mcp=FakeManager())

    async def scenario():
        task = asyncio.create_task(proxy._sweep_mcp_sessions(session, 0.01))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())

    assert len(calls) >= 2


def test_a_failed_session_never_logs_the_endpoint(tmp_path, monkeypatch, caplog):
    """An http/sse failure message can echo the URL: log the type, not the text."""
    write_mcp(tmp_path / "mcps", transport="http", command="https://secret.internal/x", args=[])
    entries = load_one(tmp_path / "mcps")

    def exploding_transport(*args, **kwargs):
        raise RuntimeError("GET https://secret.internal/x failed: 502")

    monkeypatch.setattr(proxy_mcp, "_transport", exploding_transport)
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        manager.set_entries(entries, await catalogs_for(entries))
        with pytest.raises(proxy_mcp.McpCallError) as exc:
            await manager.call("stateful", "get_value", {}, {}, DEADLINE_MS)
        return exc.value

    with caplog.at_level(logging.ERROR, logger="core.proxy_mcp"):
        error = asyncio.run(scenario())

    assert error.code == "mcp_session_lost"
    assert "RuntimeError" in caplog.text
    assert "secret.internal" not in caplog.text


def test_a_stdio_session_is_a_runner_transport_with_declared_env_and_digest(
    tmp_path, monkeypatch
):
    """stdio is a runner session: target, random key, declared env, digest, no cwd."""
    import core.execution.stdio_transport as stdio_transport
    from core.execution.spec import manifest_digest

    captured = {}

    class FakeRunnerTransport:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    class FakeClient:
        def __init__(self, transport):
            self.transport = transport

    monkeypatch.setattr(stdio_transport, "RunnerStdioTransport", FakeRunnerTransport)
    monkeypatch.setattr(
        proxy_mcp, "_fastmcp", lambda: (FakeClient, None, None)
    )
    entry = proxy_mcp.McpExport(
        name="devops-cli",
        config=MCPConfig(
            name="devops-cli",
            command="node",
            args=["server.js"],
            secrets=["DEVOPS_PASSWORD"],
        ),
        directory=tmp_path,
    )

    proxy_mcp._transport(
        entry,
        {"DEVOPS_PASSWORD": "s3cret", "TRELLIS_USER_ID": "u1"},
    )

    assert captured["target"] == "devops-cli"
    assert len(captured["session_key"]) == 32
    assert captured["env"] == {"DEVOPS_PASSWORD": "s3cret", "TRELLIS_USER_ID": "u1"}
    assert captured["manifest_digest"] == manifest_digest(entry.config)
    # No identity on the transport (v0.7.1 Phase 2): the runner reads it from the token.
    assert "agent" not in captured
    assert "user_id" not in captured
    assert "user_email" not in captured
    assert captured["kind"] == "mcp_session"
    assert captured["deadline_ms"] == proxy_mcp.DEFAULT_SESSION_DEADLINE_MS


def test_a_stdio_session_never_creates_the_legacy_session_root(
    tmp_path, fake_sessions, edge_env
):
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            await manager.call(
                "stateful", "get_value", {"key": "k"}, {"user_email": "a@x"}, DEADLINE_MS
            )
        finally:
            await manager.kill_all()

    asyncio.run(scenario())

    # Nothing was ever written under the writable root; it need not even exist.
    assert not (edge_env / "mcp-sessions").exists()


def test_a_legacy_mcp_sessions_directory_is_reported_once(edge_env, caplog):
    """v0.5 session HOMEs are dead state: warn once per process, never read them."""
    legacy = edge_env / "mcp-sessions"
    legacy.mkdir(parents=True)
    proxy_mcp._DEAD_SESSION_STATE_WARNED = False

    with caplog.at_level(logging.WARNING, logger="core.proxy_mcp"):
        proxy_mcp.McpSessionManager()
        proxy_mcp.McpSessionManager()

    assert caplog.text.count("dead state from v0.5") == 1
    assert str(legacy) in caplog.text


def test_truncation_budgets_the_encoded_size_not_the_character_count():
    """Quotes and newlines double under JSON escaping: a char slice can still overflow."""
    nasty = ('say "hi"\\' + "\n") * 60_000

    payload = {"content": [{"type": "text", "text": nasty}], "isError": False}
    truncated = proxy_mcp._truncate(payload)

    assert len(proxy_mcp._encode(truncated)) <= proxy_mcp.MAX_RESULT_CHARS
    assert "truncated by edge: original" in truncated["content"][0]["text"]
    assert len(truncated["content"][0]["text"]) < len(nasty)


def test_importing_the_edge_entrypoint_stays_light():
    """The edge must never drag the central stack (FastAPI, etcd, the MCP client) in."""
    code = (
        "import sys\n"
        "import core.proxy\n"
        "print(sorted(m for m in ('fastmcp', 'fastapi', 'core.auth') if m in sys.modules))\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]", result.stdout + result.stderr


# ---------------------------------------------------------------- credentials


def credentials_at(tmp_path):
    return edge_user_secrets.CredentialStore(secrets_dir=tmp_path / "edge-secrets")


def test_per_user_required_with_passthrough_never_falls_back_to_the_process_env(
    tmp_path, fake_sessions, monkeypatch
):
    """The blocking property: ``passthrough`` must not fill a sealed set's gaps.

    ``scoped_env(passthrough=True)`` copies the sanitized container env, so a declared
    key the caller's sealed set omits would otherwise arrive from the container and the
    "sealed only" mode would silently degrade. Everything not declared is dropped
    before the request: the runner rejects it, and it is not the server's business.
    """
    monkeypatch.setenv("DEVOPS_PASSWORD", "leaked-from-the-container")
    monkeypatch.setenv("CORALOGIX_DOMAIN", "corp.example")
    write_mcp(
        tmp_path / "mcps",
        secrets=["DEVOPS_PASSWORD", "DEVOPS_URL"],
        tools=SERVER_TOOLS + [ENV_DUMP_TOOL],
    )
    entries = load_one(tmp_path / "mcps", credential_mode="per_user_required")
    manager = proxy_mcp.McpSessionManager(
        passthrough=True, credentials=credentials_at(tmp_path), site="plant-floor"
    )

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            return structured(
                await manager.call(
                    "stateful",
                    "env_dump",
                    {},
                    {"user_email": "ops@example.com"},
                    DEADLINE_MS,
                    sealed={"DEVOPS_URL": "https://ops.internal"},
                )
            )
        finally:
            await manager.kill_all()

    env = asyncio.run(scenario())

    assert env["DEVOPS_URL"] == "https://ops.internal"
    # Declared, absent from the sealed set: the container's value must NOT stand in.
    assert "DEVOPS_PASSWORD" not in env
    # Passthrough is not a licence to send undeclared names to the runner.
    assert "CORALOGIX_DOMAIN" not in env
    assert set(env) <= proxy_mcp.declared_env_keys(entries["stateful"].config)


def test_a_literal_mcp_env_never_overrides_a_resolved_credential(tmp_path):
    """```env: {DEVOPS_PASSWORD: old}`` in mcp.yaml must not defeat the sealed set."""
    entry = proxy_mcp.McpExport(
        name="stateful",
        config=MCPConfig(
            name="stateful",
            transport="stdio",
            command="stateful-mcp",
            env={
                "DEVOPS_PASSWORD": "stale-literal",
                "DEVOPS_URL": "https://stale.internal",
                "EXTRA_HEADER": "kept",
            },
            secrets=["DEVOPS_PASSWORD", "DEVOPS_URL"],
        ),
        directory=tmp_path,
        credential_mode="per_user_required",
    )
    env = proxy_mcp._server_env(
        entry,
        {"user_email": "ops@example.com"},
        passthrough=False,
        token_env=None,
        credentials=credentials_at(tmp_path),
        site="plant-floor",
        sealed={"DEVOPS_PASSWORD": "fresh-from-the-browser"},
    )

    assert env["DEVOPS_PASSWORD"] == "fresh-from-the-browser"  # sealed set wins
    # Declared but absent from the set: the literal must not fill it either.
    assert "DEVOPS_URL" not in env
    # A literal for a key the manifest does not declare never reaches the runner...
    assert "EXTRA_HEADER" not in env
    # ...but a remote transport still gets it as a header (headers are not env).
    headers = proxy_mcp._http_headers(entry, env)
    assert headers["DEVOPS_PASSWORD"] == "fresh-from-the-browser"
    assert "DEVOPS_URL" not in headers
    assert headers["EXTRA_HEADER"] == "kept"


def test_case_variants_of_one_email_share_one_session(tmp_path, monkeypatch):
    """A normalized key: two spellings must not become two sessions (or two containers)."""
    monkeypatch.setattr(proxy_mcp, "_transport", lambda *a, **k: FakeClient())
    write_mcp(tmp_path / "mcps")
    entries = load_one(tmp_path / "mcps")
    manager = proxy_mcp.McpSessionManager()

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries))
            first = text(
                await manager.call(
                    "stateful", "get_home", {}, {"user_email": "Ops@Example.com"}, DEADLINE_MS
                )
            )
            second = text(
                await manager.call(
                    "stateful", "get_home", {}, {"user_email": "  ops@example.com  "}, DEADLINE_MS
                )
            )
            return first, second, list(manager._sessions)
        finally:
            await manager.kill_all()

    first, second, sessions = asyncio.run(scenario())

    assert first == second
    assert sessions == [("stateful", edge_user_secrets.normalize_email("ops@example.com"))]


def test_sighup_retires_live_sessions_so_a_new_credential_applies(tmp_path, fake_sessions):
    """``refresh_mcps`` is the operator's escape hatch: new value, new container, no tombstone."""
    root = tmp_path / "mcps"
    write_mcp(root, secrets=["DEVOPS_PASSWORD"], tools=SERVER_TOOLS + [ENV_DUMP_TOOL])
    store = credentials_at(tmp_path)
    config_path = tmp_path / "proxy.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "site": "plant-floor",
                "server_url": "ws://relay.local/edge/v1/connect",
                "mcps_dir": str(root),
                "secrets_dir": str(store.secrets_dir),
                "export_mcps": [
                    {"name": "stateful", "credential_mode": "per_user_required"}
                ],
            }
        ),
        encoding="utf-8",
    )
    session = proxy._Session(proxy.load_config(config_path), config_path)
    session.reload()
    identity = {"user_email": "ops@example.com"}

    async def scenario():
        try:
            await session.refresh_mcps()  # what run() does before the first connect
            before = structured(
                await session.mcp.call(
                    "stateful", "env_dump", {}, identity, DEADLINE_MS,
                    sealed={"DEVOPS_PASSWORD": "before"},
                )
            )
            assert len(fake_sessions) == 1

            # The SIGHUP path: reload the files, rebuild the catalogs, install them.
            session.reload()
            await session.refresh_mcps()

            after = structured(
                await session.mcp.call(
                    "stateful", "env_dump", {}, identity, DEADLINE_MS,
                    sealed={"DEVOPS_PASSWORD": "after"},
                )
            )
            return before, after, [t.closed for t in fake_sessions], list(session.mcp._tombs)
        finally:
            await session.mcp.kill_all()

    before, after, closed, tombs = asyncio.run(scenario())

    assert before["DEVOPS_PASSWORD"] == "before"
    assert after["DEVOPS_PASSWORD"] == "after"
    # A new session container, and the old one was torn down.
    assert len(closed) == 2 and closed == [True, False]
    # A SIGHUP is a requested reopen, not a lost session: nothing one-shot is armed.
    assert tombs == []
