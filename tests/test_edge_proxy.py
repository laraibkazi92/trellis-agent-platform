# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the edge entrypoint (core.proxy) — config, catalog, call handling.

No relay is started here: the transport is exercised by the edge-relay tests.
These pin the parts that must be right independently of the network: the export
allowlist is enforced locally, arguments are re-validated against the published
schema, and one failing tool never takes the receive loop down.
"""

import asyncio
import os
import json
import logging
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from core import agent_token, proxy
from core.models import MCPConfig, ToolConfig
from services.edge_relay import protocol


ENV_VARS = (
    "TRELLIS_EDGE_CONFIG",
    "TRELLIS_EDGE_SITE",
    "TRELLIS_SERVER_URL",
    "TRELLIS_EDGE_TOOLS_DIR",
    "TRELLIS_EDGE_TOKEN",
    "TRELLIS_USER_ID",
    "TRELLIS_USER_EMAIL",
)


@pytest.fixture(autouse=True)
def _clean_edge_env(monkeypatch):
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def make_config(name="demo", **kw):
    return ToolConfig(
        name=name,
        description=f"{name} tool",
        runtime="python",
        entrypoint="main.py",
        **kw,
    )


def write_proxy_yaml(path, **overrides):
    data = {
        "site": "plant-floor",
        "server_url": "wss://trellis.example.com/edge/v1/connect",
        "token_env": "EDGE_TOKEN",
        "tools_dir": "./workspace/tools",
        "exports": ["boiler_status"],
        "sandbox": "auto",
    }
    data.update(overrides)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def write_tool_yaml(root, dir_name, payload):
    tool_dir = root / dir_name
    tool_dir.mkdir(parents=True)
    (tool_dir / "tool.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")
    return tool_dir


# ---------------------------------------------------------------- load_config


def test_load_config_parses_yaml(tmp_path):
    config_path = write_proxy_yaml(tmp_path / "proxy.yaml")

    config = proxy.load_config(config_path)

    assert config.site == "plant-floor"
    assert config.server_url == "wss://trellis.example.com/edge/v1/connect"
    assert config.token_env == "EDGE_TOKEN"
    assert config.tools_dir == Path("workspace/tools")
    assert config.exports == ["boiler_status"]
    assert config.sandbox == "auto"


def test_load_config_defaults_to_cwd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    write_proxy_yaml(tmp_path / "proxy.yaml")

    assert proxy.load_config().site == "plant-floor"


def test_load_config_reads_path_from_env(monkeypatch, tmp_path):
    config_path = write_proxy_yaml(tmp_path / "custom.yaml")
    monkeypatch.setenv("TRELLIS_EDGE_CONFIG", str(config_path))

    assert proxy.load_config().site == "plant-floor"


def test_load_config_env_overrides_win(monkeypatch, tmp_path):
    write_proxy_yaml(tmp_path / "proxy.yaml")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TRELLIS_EDGE_SITE", "remote-site")
    monkeypatch.setenv("TRELLIS_SERVER_URL", "ws://localhost:8100/edge/v1/connect")
    monkeypatch.setenv("TRELLIS_EDGE_TOOLS_DIR", str(tmp_path / "tools"))

    config = proxy.load_config()

    assert config.site == "remote-site"
    assert config.server_url == "ws://localhost:8100/edge/v1/connect"
    assert config.tools_dir == tmp_path / "tools"


def test_load_config_requires_site(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    write_proxy_yaml(tmp_path / "proxy.yaml", site=None)

    with pytest.raises(ValueError, match="site"):
        proxy.load_config()


def test_load_config_requires_server_url(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    write_proxy_yaml(tmp_path / "proxy.yaml", server_url=None)

    with pytest.raises(ValueError, match="server_url"):
        proxy.load_config()


@pytest.mark.parametrize("site", ["mcp", "bad site", "-leading", "a" * 65, "a__b", "plant__floor"])
def test_load_config_rejects_invalid_site_names(tmp_path, site):
    config_path = write_proxy_yaml(tmp_path / "proxy.yaml", site=site)

    with pytest.raises(ValueError, match="invalid site name"):
        proxy.load_config(config_path)


@pytest.mark.parametrize("url", ["https://example.com/edge", "example.com", "tcp://x"])
def test_load_config_requires_ws_scheme(tmp_path, url):
    config_path = write_proxy_yaml(tmp_path / "proxy.yaml", server_url=url)

    with pytest.raises(ValueError, match="ws://"):
        proxy.load_config(config_path)


def test_load_config_rejects_missing_explicit_file(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        proxy.load_config(tmp_path / "absent.yaml")


def test_run_requires_a_token(tmp_path):
    config = proxy.ProxyConfig(site="plant-floor", server_url="ws://relay.local/edge/v1/connect")

    with pytest.raises(ValueError, match="TRELLIS_EDGE_TOKEN"):
        asyncio.run(proxy.run(config, once=True))


# ---------------------------------------------------------------- load_tools


def test_load_tools_single_dict(tmp_path):
    tools_dir = tmp_path / "tools"
    write_tool_yaml(
        tools_dir,
        "boiler",
        {
            "name": "boiler_status",
            "description": "read the boiler",
            "runtime": "python",
            "entrypoint": "main.py",
            "inputs": {"unit": {"type": "string"}},
        },
    )

    configs = proxy.load_tools(tools_dir, ["boiler_status"])

    assert set(configs) == {"boiler_status"}
    config, tool_dir = configs["boiler_status"]
    assert config.runtime == "python"
    assert tool_dir == (tools_dir / "boiler").resolve()


def test_load_tools_list_and_implicit_name(tmp_path):
    tools_dir = tmp_path / "tools"
    write_tool_yaml(
        tools_dir,
        "multi",
        [
            {"name": "first", "description": "a", "runtime": "bash", "entrypoint": "run.sh"},
            {"description": "b", "runtime": "python", "entrypoint": "main.py"},
        ],
    )

    configs = proxy.load_tools(tools_dir, ["first", "multi"])

    assert set(configs) == {"first", "multi"}
    assert configs["multi"][0].runtime == "python"


def test_load_tools_exports_allowlist_excludes_unlisted(tmp_path):
    tools_dir = tmp_path / "tools"
    write_tool_yaml(
        tools_dir, "exported", {"name": "exported", "description": "a", "runtime": "python", "entrypoint": "main.py"}
    )
    write_tool_yaml(
        tools_dir, "private", {"name": "private", "description": "b", "runtime": "python", "entrypoint": "main.py"}
    )

    configs = proxy.load_tools(tools_dir, ["exported"])

    assert set(configs) == {"exported"}


def test_load_tools_empty_exports_publishes_nothing(tmp_path, caplog):
    tools_dir = tmp_path / "tools"
    write_tool_yaml(
        tools_dir, "exported", {"name": "exported", "description": "a", "runtime": "python", "entrypoint": "main.py"}
    )

    with caplog.at_level(logging.WARNING, logger="core.proxy"):
        configs = proxy.load_tools(tools_dir, [])

    assert configs == {}
    assert "exports is empty" in caplog.text


def test_load_tools_rejects_remote_runtime(tmp_path, caplog):
    tools_dir = tmp_path / "tools"
    write_tool_yaml(
        tools_dir,
        "remote",
        {"name": "remote", "description": "a", "runtime": "remote", "entrypoint": "main.py"},
    )

    with caplog.at_level(logging.WARNING, logger="core.proxy"):
        configs = proxy.load_tools(tools_dir, ["remote"])

    assert configs == {}
    assert "remote" in caplog.text


def test_load_tools_skips_go_tools(tmp_path, caplog):
    """The hub precompiles go tools; an edge has no compiler and a read-only workspace."""
    tools_dir = tmp_path / "tools"
    write_tool_yaml(
        tools_dir,
        "gopher",
        {"name": "gopher", "description": "a", "runtime": "go", "entrypoint": "main.go"},
    )

    with caplog.at_level(logging.WARNING, logger="core.proxy"):
        configs = proxy.load_tools(tools_dir, ["gopher"])

    assert configs == {}
    assert "go tools must be pre-built and cannot run on an edge yet" in caplog.text
    assert "gopher" in caplog.text


def test_load_tools_warns_about_unknown_exports(tmp_path, caplog):
    tools_dir = tmp_path / "tools"
    write_tool_yaml(
        tools_dir, "known", {"name": "known", "description": "a", "runtime": "python", "entrypoint": "main.py"}
    )

    with caplog.at_level(logging.WARNING, logger="core.proxy"):
        configs = proxy.load_tools(tools_dir, ["known", "typo"])

    assert set(configs) == {"known"}
    assert "typo" in caplog.text


def test_load_tools_skips_an_invalid_catalog_entry(tmp_path, caplog):
    tools_dir = tmp_path / "tools"
    write_tool_yaml(
        tools_dir,
        "bad",
        {
            "name": "bad",
            "description": "a",
            "runtime": "python",
            "entrypoint": "main.py",
            "inputs": {"n": {"type": "unsupported-type"}},
        },
    )

    with caplog.at_level(logging.WARNING, logger="core.proxy"):
        configs = proxy.load_tools(tools_dir, ["bad"])

    assert configs == {}
    assert "unsupported type" in caplog.text


# ---------------------------------------------------------------- handle_call


def call_frame(tool="demo", args=None, call_id="call-1", **extra):
    frame = {"t": "call", "id": call_id, "tool": tool, "args": args or {}}
    frame.update(extra)
    return frame


class FakeWebSocket:
    """Duck-types the websockets connection: async iteration plus send/recv."""

    def __init__(self, frames, drain_grace=0.4):
        self._frames = list(frames)
        self._drained = False
        self._grace = drain_grace
        self.sent = []
        self.closed = None

    async def recv(self):
        return self._take()

    def _take(self):
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
            # A real socket blocks here instead; give the handlers spawned from
            # the frames above time to finish before reporting EOF.
            await asyncio.sleep(self._grace)
        raise StopAsyncIteration

    async def send(self, data):
        self.sent.append(json.loads(data))

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)


def serve(config_map, frames, *, ws_class=FakeWebSocket, ws_kwargs=None, drain_grace=0.4):
    session = proxy._Session(proxy.ProxyConfig(site="plant-floor", server_url="ws://relay.local/edge/v1/connect"))
    session.tools = config_map
    ws = ws_class(
        [protocol.encode(frame) for frame in frames],
        drain_grace=drain_grace,
        **(ws_kwargs or {}),
    )
    asyncio.run(proxy._serve(session, ws))
    return ws


def test_serve_publishes_then_answers_calls(tmp_path, monkeypatch):
    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None):
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    config_map = {"demo": (make_config(), tmp_path)}

    ws = serve(
        config_map,
        [
            {"t": "welcome", "site": "plant-floor"},
            call_frame(),
        ],
    )

    assert [frame["t"] for frame in ws.sent] == ["hello", "result"]
    assert ws.sent[0]["proto"] == protocol.PROTO
    assert ws.sent[1]["ok"] is True


def test_serve_ignores_inbound_pings():
    """Answering an app-level ping turned the edge and the relay into an echo loop."""
    ws = serve({}, [{"t": "welcome", "site": "plant-floor"}, {"t": "ping"}])

    assert [frame["t"] for frame in ws.sent] == ["hello"]


def test_serve_warns_when_the_token_resolves_to_another_site(caplog):
    with caplog.at_level(logging.WARNING, logger="core.proxy"):
        serve({}, [{"t": "welcome", "site": "warehouse"}, {"t": "ping"}])

    assert "declares" in caplog.text
    assert "warehouse" in caplog.text
    assert "plant-floor" in caplog.text


def test_serve_accepts_a_matching_site_without_a_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="core.proxy"):
        serve({}, [{"t": "welcome", "site": "plant-floor"}, {"t": "ping"}])

    assert "declares" not in caplog.text


def test_drain_closes_immediately_and_defers_the_pause():
    """The pause belongs to the reconnect wait: sleeping in the receive loop blocks results."""
    session = proxy._Session(
        proxy.ProxyConfig(site="plant-floor", server_url="ws://relay.local/edge/v1/connect")
    )
    ws = FakeWebSocket(
        [
            protocol.encode({"t": "welcome", "site": "plant-floor"}),
            protocol.encode({"t": "drain", "reconnect_after_s": 30}),
        ]
    )

    started = time.monotonic()
    asyncio.run(proxy._serve(session, ws))
    elapsed = time.monotonic() - started

    assert elapsed < 1.0, f"drain slept inside the receive loop ({elapsed:.1f}s)"
    assert session.reconnect_delay == 30.0
    assert session.reconnect.is_set()
    assert ws.closed == (1000, "drain")


def test_connect_kwargs_raise_the_inbound_frame_cap():
    """A legal call frame is larger than the websockets 1 MiB client default."""
    config = proxy.ProxyConfig(site="plant-floor", server_url="ws://relay.local/edge/v1/connect")

    kwargs = proxy._connect_kwargs(config, "tok")

    assert kwargs["max_size"] == protocol.MAX_FRAME_BYTES
    assert protocol.MAX_FRAME_BYTES > protocol.MAX_ARGS_BYTES
    assert kwargs["subprotocols"] == [protocol.SUBPROTOCOL]
    headers = kwargs.get("additional_headers") or kwargs.get("extra_headers")
    assert headers == {"Authorization": "Bearer tok"}


@pytest.mark.parametrize(
    "code",
    [protocol.CLOSE_REVOKED, protocol.CLOSE_SUPERSEDED, protocol.CLOSE_VERSION],
)
def test_next_backoff_never_retries_a_terminal_close_fast(code):
    assert proxy._next_backoff(proxy._BACKOFF_MIN_S, 1.0, code) == proxy._BACKOFF_MAX_S
    # A revoked token stays revoked, however healthy the session had been.
    assert (
        proxy._next_backoff(proxy._BACKOFF_MIN_S, proxy._BACKOFF_STABLE_S * 2, code)
        == proxy._BACKOFF_MAX_S
    )


def test_a_version_mismatch_is_diagnosed_as_central_being_old():
    """4001 is terminal: a v0.5 edge cannot fix an un-upgraded relay by retrying, and a
    generic "disconnected" line would hide the one action that helps (upgrade central)."""
    assert protocol.CLOSE_VERSION in proxy._TERMINAL_CLOSE_CODES

    message = proxy._terminal_close_message(protocol.CLOSE_VERSION, "plant-floor")

    assert "version mismatch" in message
    assert "upgrade central" in message
    assert "older tunnel protocol" in message
    assert "4001" in message
    # The other terminal codes keep their own diagnosis.
    assert "revoked" in proxy._terminal_close_message(protocol.CLOSE_REVOKED, "site")
    assert "superseded" in proxy._terminal_close_message(protocol.CLOSE_SUPERSEDED, "site")


def test_next_backoff_grows_after_a_short_session():
    assert proxy._next_backoff(proxy._BACKOFF_MIN_S, 0.5, 1006) == 2 * proxy._BACKOFF_MIN_S
    assert proxy._next_backoff(8.0, 0.5, None) == 16.0


def test_next_backoff_is_capped():
    assert proxy._next_backoff(proxy._BACKOFF_MAX_S, 0.0, 1006) == proxy._BACKOFF_MAX_S
    assert proxy._next_backoff(proxy._BACKOFF_MAX_S * 10, 0.0, None) == proxy._BACKOFF_MAX_S


def test_next_backoff_resets_only_after_a_stable_session():
    assert proxy._next_backoff(32.0, proxy._BACKOFF_STABLE_S, 1006) == proxy._BACKOFF_MIN_S
    assert proxy._next_backoff(8.0, proxy._BACKOFF_STABLE_S - 0.1, 1006) == 16.0


def test_serve_rejects_calls_beyond_max_inflight(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy, "MAX_INFLIGHT", 1)

    async def slow_execute(config, tool_dir, arguments, *, env, on_health=None):
        await asyncio.sleep(0.2)
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", slow_execute)
    config_map = {"demo": (make_config(), tmp_path)}

    ws = serve(
        config_map,
        [
            {"t": "welcome", "site": "plant-floor"},
            call_frame(call_id="1"),
            call_frame(call_id="2"),
        ],
    )

    results = [frame for frame in ws.sent if frame["t"] == "result"]
    assert results[0]["id"] == "2"
    assert results[0]["ok"] is False
    assert results[0]["error"]["code"] == "edge_overloaded"
    assert results[1]["id"] == "1" and results[1]["ok"] is True


def test_call_is_cancelled_at_the_caller_deadline(tmp_path, monkeypatch):
    """An abandoned call must not hold an inflight slot for the tool's full timeout."""
    monkeypatch.setattr(proxy, "MAX_INFLIGHT", 1)

    async def fake_handle(
        config_map, frame, *, proxy_config=None, credential_modes=None, **_kwargs
    ):
        if frame.get("tool") == "slow":
            await asyncio.sleep(30)
        return proxy._result_frame(frame["id"], 0, result={"tool": frame["tool"]})

    monkeypatch.setattr(proxy, "handle_call", fake_handle)
    config_map = {
        "slow": (make_config("slow"), tmp_path),
        "fast": (make_config("fast"), tmp_path),
    }

    class GatedWebSocket(FakeWebSocket):
        """Pauses before selected frames so one result can precede the next call."""

        def __init__(self, frames, wait_before=(), **kwargs):
            super().__init__(frames, **kwargs)
            self._wait_before = set(wait_before)
            self._index = 0

        async def __anext__(self):
            index, self._index = self._index, self._index + 1
            if index in self._wait_before:
                for _ in range(500):
                    if any(frame.get("t") == "result" for frame in self.sent):
                        break
                    await asyncio.sleep(0.01)
            return await super().__anext__()

    ws = serve(
        config_map,
        [
            {"t": "welcome", "site": "plant-floor"},
            call_frame(tool="slow", call_id="slow-1", deadline_ms=1000),
            call_frame(tool="fast", call_id="fast-1", deadline_ms=1000),
        ],
        ws_class=GatedWebSocket,
        ws_kwargs={"wait_before": {1}},
    )

    results = [frame for frame in ws.sent if frame["t"] == "result"]
    assert results[0]["id"] == "slow-1"
    assert results[0]["ok"] is False
    assert results[0]["error"]["code"] == "edge_timeout"
    assert results[0]["error"]["message"] == "edge cancelled the call at its deadline"
    # The cancelled call released its slot: MAX_INFLIGHT is 1, so the second
    # call could only run (instead of edge_overloaded) after that release.
    assert results[1]["id"] == "fast-1"
    assert results[1]["ok"] is True


def test_handle_call_returns_result(tmp_path, monkeypatch):

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None):
        assert config.name == "demo"
        assert arguments == {"q": "1"}  # string inputs are coerced like the hub
        assert "PATH" in env
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    config_map = {"demo": (make_config(inputs={"q": {"type": "string"}}), tmp_path)}

    frame = asyncio.run(proxy.handle_call(config_map, call_frame(args={"q": 1})))

    assert frame["t"] == "result"
    assert frame["id"] == "call-1"
    assert frame["ok"] is True
    assert frame["result"] == {"ok": True}
    assert isinstance(frame["ms"], int)


def test_handle_call_exports_the_caller_identity_to_the_tool(tmp_path, monkeypatch):
    seen = {}

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None):
        seen.update(env)
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    config_map = {"demo": (make_config(), tmp_path)}

    frame = asyncio.run(
        proxy.handle_call(
            config_map,
            call_frame(user="user-1", user_email="user-1@corp.example"),
        )
    )

    assert frame["ok"] is True
    assert seen["TRELLIS_USER_ID"] == "user-1"
    assert seen["TRELLIS_USER_EMAIL"] == "user-1@corp.example"


def test_handle_call_without_identity_exports_no_identity_vars(tmp_path, monkeypatch):
    seen = {}

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None):
        seen.update(env)
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    config_map = {"demo": (make_config(), tmp_path)}

    asyncio.run(proxy.handle_call(config_map, call_frame()))

    # Absent, not empty: a tool branches on presence.
    assert "TRELLIS_USER_ID" not in seen
    assert "TRELLIS_USER_EMAIL" not in seen


def test_handle_call_unknown_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", pytest.fail)

    frame = asyncio.run(proxy.handle_call({}, call_frame(tool="nope")))

    assert frame["ok"] is False
    assert frame["error"]["code"] == "unknown_tool"


def test_handle_call_rejects_unknown_arguments(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", pytest.fail)
    config_map = {"demo": (make_config(inputs={"q": {"type": "string"}}), tmp_path)}

    frame = asyncio.run(proxy.handle_call(config_map, call_frame(args={"surprise": "x"})))

    assert frame["ok"] is False
    assert frame["error"]["code"] == "invalid_arguments"
    assert "surprise" in frame["error"]["message"]


def test_handle_call_rejects_a_malformed_frame(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", pytest.fail)

    frame = asyncio.run(proxy.handle_call({}, {"t": "call", "id": "", "tool": "demo"}))

    assert frame["ok"] is False
    assert frame["error"]["code"] == "invalid_arguments"


def test_handle_call_reports_tool_exceptions(tmp_path, monkeypatch):
    async def exploding(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", exploding)
    config_map = {"demo": (make_config(), tmp_path)}

    frame = asyncio.run(proxy.handle_call(config_map, call_frame()))

    assert frame["ok"] is False
    assert frame["error"] == {"code": "tool_error", "message": "boom"}


def test_slow_call_does_not_block_a_second_call(tmp_path, monkeypatch):
    finished = []

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None):
        if config.name == "slow":
            await asyncio.sleep(0.2)
        finished.append(config.name)
        return {"tool": config.name}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    config_map = {
        "slow": (make_config("slow"), tmp_path),
        "fast": (make_config("fast"), tmp_path),
    }

    async def scenario():
        started = time.monotonic()
        await asyncio.gather(
            proxy.handle_call(config_map, call_frame(tool="slow", call_id="1")),
            proxy.handle_call(config_map, call_frame(tool="fast", call_id="2")),
        )
        return time.monotonic() - started

    elapsed = asyncio.run(scenario())

    assert finished == ["fast", "slow"]
    assert elapsed < 0.35, f"calls serialized ({elapsed:.2f}s)"


# ---------------------------------------------------------------- frames


def test_hello_frame_publishes_the_catalog(tmp_path):
    config_map = {
        "alpha": (make_config("alpha", inputs={"q": {"type": "string"}}), tmp_path),
        "beta": (make_config("beta"), tmp_path),
    }

    frame = proxy.hello_frame(config_map, None)

    assert frame["t"] == "hello"
    assert frame["proto"] == protocol.PROTO
    assert frame["edge_version"]
    assert [tool["name"] for tool in frame["tools"]] == ["alpha", "beta"]
    assert frame["tools"][0]["inputs"] == {"q": {"type": "string", "required": False}}

    # The relay validates the catalog on arrival; make sure it accepts ours.
    _, _, tools, mcps, caps = protocol.validate_hello(frame)
    assert [tool.name for tool in tools] == ["alpha", "beta"]
    assert mcps == [] and caps == ["tools"]


def test_hello_frame_with_mcp_catalogs_passes_the_relay_validator(tmp_path):
    """A proto-2 hello must satisfy the relay's caps/mcps contract."""
    schema = {
        "type": "object",
        "oneOf": [
            {"properties": {"action": {"const": "list_actions"}}, "required": ["action"]},
            {"properties": {"action": {"const": "get_tenant"}, "id": {"type": "string"}}},
        ],
    }
    catalog = protocol.validate_mcps(
        [
            {
                "name": "devops-cli",
                "transport": "stdio",
                "tools": [
                    {"name": "tenant_tools", "description": "meta", "inputSchema": schema}
                ],
            }
        ]
    )[0]

    frame = proxy.hello_frame({}, {"devops-cli": catalog})

    assert frame["caps"] == ["tools", "mcp"]
    assert [mcp["name"] for mcp in frame["mcps"]] == ["devops-cli"]

    proto, _version, tools, mcps, caps = protocol.validate_hello(frame)
    assert proto == protocol.PROTO == 2
    assert tools == []
    assert caps == ["tools", "mcp"]
    assert mcps[0].tools[0].input_schema == schema


def test_build_env_prepends_the_tool_bin_dir(tmp_path):
    env = proxy.build_env(tmp_path)

    assert env["PATH"].split(":")[0] == str((tmp_path / "bin").resolve())


def test_build_env_exports_the_caller_identity(tmp_path):
    env = proxy.build_env(
        tmp_path, identity={"user": "u1", "user_email": "u1@corp.example"}
    )

    assert env["TRELLIS_USER_ID"] == "u1"
    assert env["TRELLIS_USER_EMAIL"] == "u1@corp.example"


def test_build_env_sets_only_the_identity_it_was_given(tmp_path):
    env = proxy.build_env(tmp_path, identity={"user": "u1"})

    assert env["TRELLIS_USER_ID"] == "u1"
    assert "TRELLIS_USER_EMAIL" not in env


def test_build_env_never_exports_an_empty_identity(tmp_path):
    """A tool tests presence, so "None"/"" must never reach the environment."""
    env = proxy.build_env(tmp_path, identity={"user": "", "user_email": None})

    assert "TRELLIS_USER_ID" not in env
    assert "TRELLIS_USER_EMAIL" not in env


def test_edge_version_is_never_empty():
    assert isinstance(proxy.EDGE_VERSION, str)
    assert proxy.EDGE_VERSION


def test_edge_version_falls_back_without_package_metadata(monkeypatch):
    import importlib.metadata

    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)

    assert proxy._installed_version() == "0.0.0"



# --- mutual TLS ---------------------------------------------------------------------


def _fake_connect(additional_headers=None, **kwargs):
    """Signature shape the header-kwarg probe looks for; never called."""


def test_connect_kwargs_present_a_client_certificate(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(proxy, "_build_ssl_context", lambda config: sentinel)
    config = proxy.ProxyConfig(
        site="plant-floor",
        server_url="wss://relay.local/edge/v1/connect",
        tls_cert_file="/etc/trellis/tls/edge.pem",
        tls_key_file="/etc/trellis/tls/edge-key.pem",
    )

    kwargs = proxy._connect_kwargs(config, "tok", connect=_fake_connect)

    assert kwargs["ssl"] is sentinel


def test_connect_kwargs_omit_ssl_without_tls_files():
    config = proxy.ProxyConfig(site="plant-floor", server_url="wss://relay.local/edge/v1/connect")

    kwargs = proxy._connect_kwargs(config, "tok", connect=_fake_connect)

    assert "ssl" not in kwargs


def test_a_client_certificate_without_its_key_is_rejected(tmp_path):
    (tmp_path / "proxy.yaml").write_text(
        "site: plant-floor\n"
        "server_url: wss://relay.local/edge/v1/connect\n"
        "tls_cert_file: /tmp/edge.pem\n"
    )

    with pytest.raises(ValueError, match="must be set together"):
        proxy.load_config(tmp_path / "proxy.yaml")


def test_missing_header_kwarg_is_an_error_not_a_silent_unauthorized(monkeypatch):
    def legacy_connect(**kwargs):  # no header parameter at all
        pass

    config = proxy.ProxyConfig(site="plant-floor", server_url="ws://relay.local/edge/v1/connect")

    with pytest.raises(ValueError, match="websockets"):
        proxy._connect_kwargs(config, "tok", connect=legacy_connect)


# --- SIGHUP reload ---------------------------------------------------------------


def _write_tool(root, name):
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "tool.yaml").write_text(
        f"name: {name}\ndescription: {name}\nruntime: python\nentrypoint: {name}.py\n"
    )


def _write_config(path, tools_dir, exports, site="plant-floor", url="ws://relay.local/edge/v1/connect"):
    path.write_text(
        f"site: {site}\nserver_url: {url}\ntools_dir: {tools_dir}\n"
        f"exports: [{', '.join(exports)}]\n"
    )


def test_reload_applies_a_changed_exports_allowlist(tmp_path):
    """SIGHUP after editing proxy.yaml must publish a newly allowed tool."""
    tools = tmp_path / "tools"
    _write_tool(tools, "alpha")
    _write_tool(tools, "beta")
    config_path = tmp_path / "proxy.yaml"
    _write_config(config_path, tools, ["alpha"])

    session = proxy._Session(proxy.load_config(config_path), config_path)
    session.reload()
    assert set(session.tools) == {"alpha"}

    _write_config(config_path, tools, ["alpha", "beta"])
    session.reload()

    assert set(session.tools) == {"alpha", "beta"}


def test_reload_refuses_to_move_a_live_tunnel_to_another_site(tmp_path):
    tools = tmp_path / "tools"
    _write_tool(tools, "alpha")
    config_path = tmp_path / "proxy.yaml"
    _write_config(config_path, tools, ["alpha"])

    session = proxy._Session(proxy.load_config(config_path), config_path)
    session.reload()

    _write_config(config_path, tools, ["alpha"], site="other-site")
    session.reload()

    assert session.config.site == "plant-floor"
    assert set(session.tools) == {"alpha"}


def test_edge_mode_stops_the_tunable_etcd_refresh(monkeypatch):
    """An edge has no etcd; the shared tunables cache must not keep probing for one."""
    from core import tunables

    monkeypatch.setenv("TRELLIS_EDGE_MODE", "1")
    monkeypatch.setattr(tunables, "_overrides_checked_at", 0.0)
    monkeypatch.setattr(tunables, "_refresh_in_flight", False)
    calls = []
    monkeypatch.setattr(tunables, "_refresh_overrides_sync", lambda: calls.append(1))

    assert tunables.resolve("tool_execution_timeout") == 300.0
    assert calls == []


@pytest.fixture
def _clean_secret_env_names():
    import core.proxy as proxy_module

    before = set(proxy_module._SECRET_ENV_NAMES)
    yield
    proxy_module._SECRET_ENV_NAMES.clear()
    proxy_module._SECRET_ENV_NAMES.update(before)


def test_the_enrollment_token_is_removed_before_tools_run(monkeypatch, tmp_path, _clean_secret_env_names):
    """The tunnel credential must not be inherited by tool subprocesses."""
    monkeypatch.setenv("TRELLIS_EDGE_TOKEN", "edge_site_supersecret")
    config = proxy.ProxyConfig(site="plant-floor", server_url="ws://relay.local/edge/v1/connect")

    token = proxy._resolve_and_forget_token(config)

    assert token == "edge_site_supersecret"
    assert "TRELLIS_EDGE_TOKEN" not in os.environ
    assert "TRELLIS_EDGE_TOKEN" not in proxy.build_env(tmp_path)


def test_build_env_drops_a_reintroduced_token(monkeypatch, tmp_path, _clean_secret_env_names):
    monkeypatch.setenv("TRELLIS_EDGE_TOKEN", "edge_site_supersecret")
    proxy._SECRET_ENV_NAMES.add("TRELLIS_EDGE_TOKEN")

    env = proxy.build_env(tmp_path)

    assert "TRELLIS_EDGE_TOKEN" not in env


def test_reload_keeps_the_old_state_when_the_new_config_is_invalid(tmp_path):
    tools = tmp_path / "tools"
    _write_tool(tools, "alpha")
    config_path = tmp_path / "proxy.yaml"
    _write_config(config_path, tools, ["alpha"])

    session = proxy._Session(proxy.load_config(config_path), config_path)
    session.reload()
    before = (session.config, dict(session.tools))

    config_path.write_text("site: [unclosed\n")

    # An unreadable/invalid config is logged and ignored: the previous allowlist keeps
    # serving rather than dropping every tool because of a typo.
    session.reload()

    assert session.config == before[0]
    assert session.tools == before[1]


# --- token file ---------------------------------------------------------------------


def _token_config(tmp_path, token_file):
    return proxy.ProxyConfig(
        site="plant-floor",
        server_url="ws://relay.local/edge/v1/connect",
        token_file=str(token_file) if token_file is not None else None,
    )


def test_the_token_is_read_from_a_file_and_the_file_is_removed(monkeypatch, tmp_path):
    monkeypatch.delenv("TRELLIS_EDGE_TOKEN_FILE", raising=False)
    token_path = tmp_path / "edge-token"
    token_path.write_text("edge_plant-floor_secret\n")

    token = proxy._resolve_token(_token_config(tmp_path, token_path))

    assert token == "edge_plant-floor_secret"
    # No copy left on disk for a tool running as the same uid to read.
    assert not token_path.exists()


def test_the_token_file_wins_over_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("TRELLIS_EDGE_TOKEN", "edge_from_env")
    monkeypatch.delenv("TRELLIS_EDGE_TOKEN_FILE", raising=False)
    token_path = tmp_path / "edge-token"
    token_path.write_text("edge_from_file")

    assert proxy._resolve_token(_token_config(tmp_path, token_path)) == "edge_from_file"


def test_a_missing_token_file_fails_with_an_actionable_message(tmp_path):
    with pytest.raises(ValueError, match="cannot read token_file"):
        proxy._resolve_token(_token_config(tmp_path, tmp_path / "nope"))


def test_an_empty_token_file_is_rejected(tmp_path):
    token_path = tmp_path / "edge-token"
    token_path.write_text("   \n")

    with pytest.raises(ValueError, match="is empty"):
        proxy._resolve_token(_token_config(tmp_path, token_path))


def test_token_file_is_loaded_from_proxy_yaml(tmp_path):
    tools = tmp_path / "tools"
    _write_tool(tools, "alpha")
    config_path = tmp_path / "proxy.yaml"
    _write_config(config_path, tools, ["alpha"])
    config_path.write_text(
        config_path.read_text() + f"token_file: {tmp_path / 'edge-token'}\n"
    )

    config = proxy.load_config(config_path)

    assert config.token_file == str(tmp_path / "edge-token")


def test_once_fails_when_the_relay_hangs_up_before_welcome(monkeypatch):
    """A clean close before the catalog is accepted must not look like success."""
    _install_fake_connect(monkeypatch, close_code=1011)

    with pytest.raises(RuntimeError, match="before the relay accepted") as excinfo:
        asyncio.run(proxy.run(_once_config(), once=True))

    assert "1011" in str(excinfo.value)


def test_once_surfaces_a_version_mismatch_close_code(monkeypatch):
    """`--once` is the diagnostic path: it must name 4001, not just fail."""
    _install_fake_connect(monkeypatch, close_code=protocol.CLOSE_VERSION)

    with pytest.raises(RuntimeError, match="before the relay accepted") as excinfo:
        asyncio.run(proxy.run(_once_config(), once=True))

    assert str(protocol.CLOSE_VERSION) in str(excinfo.value)


def _once_config():
    return proxy.ProxyConfig(site="plant-floor", server_url="ws://relay.local/edge/v1/connect")


def _install_fake_connect(monkeypatch, close_code):
    """``_serve`` is a no-op and the socket closes with ``close_code``: the session never
    reaches `accepted`, which is exactly the handshake-refusal shape."""
    from types import SimpleNamespace

    monkeypatch.setenv("TRELLIS_EDGE_TOKEN", "edge_plant-floor_secret")
    monkeypatch.setattr(proxy, "_SECRET_ENV_NAMES", set())

    async def _noop_serve(session, ws):
        return None

    async def _noop(*args, **kwargs):
        return None

    class _FakeConnect:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return SimpleNamespace(close_code=close_code, send=_noop, close=_noop)

        async def __aexit__(self, *exc):
            return False

    def _fake_connect(url, additional_headers=None, **kwargs):
        return _FakeConnect()

    monkeypatch.setattr(proxy, "_serve", _noop_serve)
    monkeypatch.setattr(proxy, "_connect_factory", lambda: _fake_connect)


# ---------------------------------------------------------------- agent tokens
#
# The edge verifies signature and expiry only: it has no agent registry, so the
# allowlist decision belongs to the relay (staffed with etcd). The token must still
# ride through to the tool call and to the MCP session container, where the runner
# verifies it again -- that is the part these tests pin.

TOKEN_SECRET = "test-agent-token-secret-0123456789abcdef"


@pytest.fixture
def enforcing_tokens(monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN_SECRET", TOKEN_SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")


def test_handle_call_refuses_an_invalid_token_when_enforcing(
    tmp_path, monkeypatch, enforcing_tokens
):
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", pytest.fail)

    frame = asyncio.run(
        proxy.handle_call(
            {"demo": (make_config(), tmp_path)},
            call_frame(agent_token="t1.forged.signature"),
        )
    )

    assert frame["ok"] is False
    assert frame["error"]["code"] == "access_denied"
    assert "bad_sig" in frame["error"]["message"]


def test_handle_call_refuses_a_missing_token_when_enforcing(
    tmp_path, monkeypatch, enforcing_tokens
):
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", pytest.fail)

    frame = asyncio.run(proxy.handle_call({"demo": (make_config(), tmp_path)}, call_frame()))

    assert frame["ok"] is False
    assert frame["error"]["code"] == "access_denied"
    assert "missing" in frame["error"]["message"]


def test_handle_call_refuses_an_expired_token_when_enforcing(
    tmp_path, monkeypatch, enforcing_tokens
):
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", pytest.fail)
    token = agent_token.mint("demo", now=time.time() - 10_000, ttl_s=60)

    frame = asyncio.run(
        proxy.handle_call(
            {"demo": (make_config(), tmp_path)}, call_frame(agent_token=token)
        )
    )

    assert frame["ok"] is False
    assert "expired" in frame["error"]["message"]


def test_handle_call_passes_the_agent_token_to_the_tool(
    tmp_path, monkeypatch, enforcing_tokens
):
    seen = {}

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None, agent_token=None):
        seen["agent_token"] = agent_token
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    token = agent_token.mint("demo")

    frame = asyncio.run(
        proxy.handle_call(
            {"demo": (make_config(), tmp_path)}, call_frame(agent_token=token)
        )
    )

    assert frame["ok"] is True
    assert seen["agent_token"] == token


def test_a_bad_token_only_warns_in_log_mode(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("AGENT_TOKEN_SECRET", TOKEN_SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None, agent_token=None):
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)

    with caplog.at_level(logging.WARNING, logger="core.proxy"):
        frame = asyncio.run(
            proxy.handle_call(
                {"demo": (make_config(), tmp_path)},
                call_frame(agent_token="t1.forged.signature"),
            )
        )

    assert frame["ok"] is True
    assert "access_denied" in caplog.text


def test_handle_mcp_call_refuses_an_invalid_token_when_enforcing(
    monkeypatch, enforcing_tokens
):
    class Manager:
        async def call(self, *args, **kwargs):
            pytest.fail("an unauthenticated MCP call must not reach the manager")

    frame = asyncio.run(
        proxy.handle_mcp_call(
            Manager(),
            {
                "t": "call",
                "id": "m1",
                "kind": "mcp",
                "mcp": "devops-cli",
                "tool": "stateful",
                "args": {},
                "agent_token": "t1.forged.signature",
            },
        )
    )

    assert frame["ok"] is False
    assert frame["error"]["code"] == "access_denied"


def test_handle_mcp_call_passes_the_agent_token_to_the_manager(
    monkeypatch, enforcing_tokens
):
    seen = {}

    class Manager:
        site = "plant-floor"

        async def call(
            self, mcp, tool, args, identity, deadline_ms, *, agent_token=None, sealed=None
        ):
            seen["agent_token"] = agent_token
            seen["sealed"] = sealed
            return {"content": [], "isError": False}

    token = agent_token.mint("demo")
    frame = asyncio.run(
        proxy.handle_mcp_call(
            Manager(),
            {
                "t": "call",
                "id": "m1",
                "kind": "mcp",
                "mcp": "devops-cli",
                "tool": "stateful",
                "args": {},
                "agent_token": token,
            },
        )
    )

    assert frame["ok"] is True
    assert seen["agent_token"] == token
    assert seen["sealed"] is None


def test_the_session_manager_opens_the_transport_with_the_token(tmp_path, monkeypatch):
    """The token is used at open time only: a warm session keeps what it has."""
    from core import proxy_mcp

    seen = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def call_tool(self, tool, args, **kwargs):
            return SimpleNamespace(content=[], is_error=False)

    def fake_transport(
        entry,
        env,
        token_env=None,
        *,
        kind="mcp_session",
        deadline_ms=0,
        identity=None,
        agent_token=None,
    ):
        seen["agent_token"] = agent_token
        return FakeClient()

    monkeypatch.setattr(proxy_mcp, "_transport", fake_transport)
    entry = proxy_mcp.McpExport(
        name="devops-cli",
        config=MCPConfig(name="devops-cli", command="node", args=["server.js"]),
        directory=tmp_path,
    )
    manager = proxy_mcp.McpSessionManager()
    manager.set_entries(
        {"devops-cli": entry},
        {
            "devops-cli": protocol.EdgeMcp(
                name="devops-cli",
                tools=[protocol.EdgeMcpTool(name="stateful")],
            )
        },
    )

    result = asyncio.run(
        manager.call(
            "devops-cli",
            "stateful",
            {},
            {"user_email": "ops@example.com"},
            5000,
            agent_token="t1.payload.signature",
        )
    )

    assert result["isError"] is False
    assert seen["agent_token"] == "t1.payload.signature"


def test_the_runner_stdio_transport_receives_the_agent_token(tmp_path, monkeypatch):
    from core import proxy_mcp
    from core.execution import stdio_transport

    seen = {}

    class FakeRunnerTransport:
        def __init__(self, **kwargs):
            seen.update(kwargs)

    monkeypatch.setattr(stdio_transport, "RunnerStdioTransport", FakeRunnerTransport)
    entry = proxy_mcp.McpExport(
        name="devops-cli",
        config=MCPConfig(name="devops-cli", command="node", args=["server.js"]),
        directory=tmp_path,
    )

    proxy_mcp._runner_transport(entry, {}, agent_token="t1.payload.signature")

    assert seen["agent_token"] == "t1.payload.signature"
