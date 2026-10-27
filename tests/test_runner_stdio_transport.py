# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""``RunnerStdioTransport``: JSON-RPC framing over the runner session endpoints.

The runner client is faked in memory (no socket, no MCP server, no FastMCP client),
so these tests pin exactly what the transport owes the MCP session: newline-delimited
JSON-RPC in and out, tolerance for split frames, parse errors surfaced as values, and
a container that is always deleted on exit.
"""

import asyncio
import json
import struct

import mcp_types as types
import pytest
from fastmcp.client.transports.base import TransportOptions
from mcp.shared.message import SessionMessage

from core.execution.contract import SessionCreateRequest, SessionInfo
from core.execution.stdio_transport import RunnerStdioTransport, parse_frames

SESSION_KEY = "c" * 32
DIGEST = "d" * 64


def _frame(tag: int, payload: bytes) -> bytes:
    return struct.pack(">BI", tag, len(payload)) + payload


class FakeRunnerClient:
    """Implements the runner session methods the transport calls, in memory."""

    def __init__(self, chunks=()) -> None:
        self.chunks = list(chunks)
        self.requests: list[SessionCreateRequest] = []
        self.stdin: list[bytes] = []
        self.closed_stdin: list[str] = []
        self.deleted: list[str] = []
        self.closed = False

    async def open_session(self, request: SessionCreateRequest) -> SessionInfo:
        self.requests.append(request)
        return SessionInfo(
            session_id="sess-1", container_id="cont-1", created_at=1.0, state="running"
        )

    async def session_stdin(self, session_id: str, data: bytes) -> None:
        self.stdin.append(bytes(data))

    async def session_stdout(self, session_id: str):
        for chunk in self.chunks:
            yield chunk

    async def close_session_stdin(self, session_id: str) -> None:
        self.closed_stdin.append(session_id)

    async def delete_session(self, session_id: str) -> None:
        self.deleted.append(session_id)

    async def close(self) -> None:
        self.closed = True


class FakeSession:
    """Stands in for ``mcp.ClientSession``: just the two streams."""

    def __init__(self, read_stream, write_stream, **kwargs) -> None:
        self.read_stream = read_stream
        self.write_stream = write_stream
        self.kwargs = kwargs

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, *exc_info) -> bool:
        return False


def _request(request_id: int, method: str, params=None) -> SessionMessage:
    return SessionMessage(
        types.JSONRPCRequest(
            jsonrpc="2.0", id=request_id, method=method, params=params or {}
        )
    )


def _response(request_id: int, result: dict) -> bytes:
    return (
        json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n"
    ).encode("utf-8")


def _transport(client: FakeRunnerClient, **overrides) -> RunnerStdioTransport:
    kwargs = dict(
        target="stateful",
        session_key=SESSION_KEY,
        env={"MCP_TOKEN": "s3cret"},
        manifest_digest=DIGEST,
        client_factory=lambda: client,
    )
    kwargs.update(overrides)
    return RunnerStdioTransport(**kwargs)


def test_initialize_round_trip_with_a_split_frame_header():
    result = {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "serverInfo": {"name": "fake", "version": "1"},
    }
    raw = _frame(1, _response(1, result))
    # A 2-byte, then 5-byte, then the rest: no read boundary may be assumed.
    client = FakeRunnerClient([raw[:2], raw[2:7], raw[7:]])

    async def scenario():
        transport = _transport(client)
        async with transport.connect_session(
            transport_options=TransportOptions(session_class=FakeSession)
        ) as session:
            await session.write_stream.send(
                _request(1, "initialize", {"protocolVersion": "2025-06-18"})
            )
            message = await session.read_stream.receive()
            return transport, message

    transport, message = asyncio.run(scenario())

    assert isinstance(message, SessionMessage)
    assert isinstance(message.message, types.JSONRPCResponse)
    assert message.message.result == result

    request = client.requests[0]
    assert request.kind == "mcp_session"
    assert request.target == "stateful"
    assert request.session_key == SESSION_KEY
    assert request.manifest_digest == DIGEST
    assert request.env == {"MCP_TOKEN": "s3cret"}
    assert request.deadline_ms == 3_600_000
    # No identity in the body (v0.7.1 Phase 2): the runner derives the agent, user,
    # email and groups from the token's claims.
    assert set(request.model_dump()) == {
        "kind",
        "target",
        "manifest_digest",
        "session_key",
        "env",
        "deadline_ms",
        "agent_token",
    }

    # Newline-delimited JSON-RPC, exactly as a local stdio server would see it.
    assert len(client.stdin) == 1
    assert client.stdin[0].endswith(b"\n")
    sent = json.loads(client.stdin[0])
    assert sent["method"] == "initialize"
    assert sent["id"] == 1

    # Teardown: half-close, delete, and no session id left on the transport.
    assert client.closed_stdin == ["sess-1"]
    assert client.deleted == ["sess-1"]
    assert client.closed is True
    assert transport.get_session_id() is None


def test_two_messages_are_coalesced_into_one_post_and_stderr_is_ignored():
    first = _response(1, {"tools": []})
    second = _response(2, {"ok": True})
    client = FakeRunnerClient(
        [
            _frame(2, b"server started on stdin\n"),
            _frame(1, first),
            _frame(1, second),
        ]
    )

    async def scenario():
        transport = _transport(client, kind="discovery")
        async with transport.connect_session(
            transport_options=TransportOptions(session_class=FakeSession)
        ) as session:
            await session.write_stream.send(_request(1, "tools/list"))
            await session.write_stream.send(_request(2, "tools/call", {"name": "x"}))
            one = await session.read_stream.receive()
            two = await session.read_stream.receive()
            return one, two

    one, two = asyncio.run(scenario())

    assert one.message.id == 1
    assert two.message.id == 2
    assert client.requests[0].kind == "discovery"

    assert len(client.stdin) == 1
    lines = client.stdin[0].split(b"\n")
    assert lines[-1] == b""
    assert [json.loads(line)["method"] for line in lines[:-1]] == [
        "tools/list",
        "tools/call",
    ]


def test_a_parse_error_is_surfaced_as_a_value():
    client = FakeRunnerClient(
        [_frame(1, b"this is not json\n"), _frame(1, _response(7, {"ok": True}))]
    )

    async def scenario():
        transport = _transport(client)
        async with transport.connect_session(
            transport_options=TransportOptions(session_class=FakeSession)
        ) as session:
            bad = await session.read_stream.receive()
            good = await session.read_stream.receive()
            return bad, good

    bad, good = asyncio.run(scenario())

    assert isinstance(bad, ValueError)
    assert isinstance(good, SessionMessage)
    assert good.message.id == 7


def test_eof_on_the_runner_stream_deletes_the_session():
    client = FakeRunnerClient([])

    async def scenario():
        transport = _transport(client)
        async with transport.connect_session(
            transport_options=TransportOptions(session_class=FakeSession)
        ) as session:
            # The outbound stream closes with no response: the transport must not
            # hang on teardown, and must still remove the container.
            await session.write_stream.aclose()
        await transport.close()

    asyncio.run(scenario())

    assert client.closed_stdin == ["sess-1"]
    assert client.deleted == ["sess-1"]
    assert client.closed is True


def test_stderr_frames_never_reach_the_session():
    client = FakeRunnerClient(
        [_frame(2, b"warning: deprecated\n"), _frame(1, _response(3, {"ok": True}))]
    )

    async def scenario():
        transport = _transport(client)
        async with transport.connect_session(
            transport_options=TransportOptions(session_class=FakeSession)
        ) as session:
            return await session.read_stream.receive()

    message = asyncio.run(scenario())

    assert isinstance(message, SessionMessage)
    assert message.message.id == 3


def test_identity_keywords_are_gone_not_merely_ignored():
    """v0.7.1 Phase 2 took them out of the signature: identity is token-only."""
    with pytest.raises(TypeError):
        RunnerStdioTransport(
            target="stateful",
            session_key=SESSION_KEY,
            env={},
            user_id="user-1",
        )


def test_the_env_travels_on_the_open_request_and_never_in_a_frame():
    """The preamble is written once at session open; frames are pure JSON-RPC after it.

    The transport's half of the Phase 5 contract: the environment rides on
    ``SessionCreateRequest`` (which the runner turns into ONE stdin line before any
    frame), and every byte the transport posts for a message is JSON-RPC on its own
    -- no env line glued onto a frame. The runner's half (that line really is the
    session's first stdin bytes, in order) is pinned in
    ``tests/test_runner_sessions.py``.
    """
    client = FakeRunnerClient([_frame(1, _response(1, {"ok": True}))])

    async def scenario():
        transport = _transport(client)
        async with transport.connect_session(
            transport_options=TransportOptions(session_class=FakeSession)
        ) as session:
            await session.write_stream.send(_request(1, "initialize"))
            await session.read_stream.receive()

    asyncio.run(scenario())

    assert client.requests[0].env == {"MCP_TOKEN": "s3cret"}
    assert client.stdin
    for chunk in client.stdin:
        assert chunk.startswith(b'{"jsonrpc"')
        assert chunk.endswith(b"\n")
        assert b'"env"' not in chunk


def test_parse_frames_tolerates_partial_headers_and_payloads():
    payload = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
    raw = _frame(1, payload)

    frames, leftover = parse_frames(raw[:3])
    assert frames == [] and leftover == raw[:3]

    frames, leftover = parse_frames(raw[:7])
    assert frames == [] and leftover == raw[:7]

    frames, leftover = parse_frames(raw)
    assert frames == [(1, payload)] and leftover == b""

    combined = _frame(1, b"a") + _frame(2, b"bb") + raw[:4]
    frames, leftover = parse_frames(combined)
    assert frames == [(1, b"a"), (2, b"bb")]
    assert leftover == raw[:4]
