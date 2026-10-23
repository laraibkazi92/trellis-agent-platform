# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""FastMCP transport that drives a stdio MCP server running in a runner container.

The MCP server is no longer a child of the hub/proxy process: the runner creates a
container from the registered manifest, and this transport speaks JSON-RPC to it
over ``/v1/sessions/{id}`` (raw stdin bytes in, ``tag + length + payload`` frames
out). Two tasks bridge those endpoints to the in-memory streams a
``ClientSession`` expects -- the same shape as ``mcp.client.stdio.stdio_client``,
so the MCP client is untouched and sees an ordinary stdio peer.

Framing tolerances are deliberate: the runner's stdout stream is HTTP chunked, so
a frame header or a JSON line can be split across reads; both buffers below are
incremental and never assume a read boundary.
"""

import contextlib
import logging
import struct
from typing import Any, AsyncIterator, Optional

import anyio
import mcp_types as types
from fastmcp.client.transports.base import (
    ClientTransport,
    SessionKwargs,
    TransportOptions,
)
from mcp.shared.message import SessionMessage
from typing_extensions import Unpack

from core.execution.client import RunnerClient
from core.execution.contract import SessionCreateRequest, SessionInfo

logger = logging.getLogger(__name__)

# Runner wire framing: 1 stream tag (1=stdout, 2=stderr) + 4-byte big-endian length.
FRAME_HEADER = struct.Struct(">BI")

# Coalesce tiny JSON-RPC messages into one POST: a tools/list response is one
# write, but a multi-message burst (initialize + notification) should not become
# one HTTP round trip per message.
MAX_BATCH_BYTES = 64 * 1024
COALESCE_S = 0.005
# Time allowed for the last accepted messages to reach the server at teardown.
WRITER_FLUSH_TIMEOUT_S = 0.5

STDERR_LOG_LIMIT = 500


def parse_frames(buffer: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    """Split complete runner frames out of ``buffer`` (``(frames, leftover)``)."""
    frames: list[tuple[int, bytes]] = []
    offset = 0
    while len(buffer) - offset >= FRAME_HEADER.size:
        tag, length = FRAME_HEADER.unpack_from(buffer, offset)
        end = offset + FRAME_HEADER.size + length
        if end > len(buffer):
            break
        frames.append((tag, buffer[offset + FRAME_HEADER.size : end]))
        offset = end
    return frames, buffer[offset:]


def _parse_line(line: str) -> SessionMessage | Exception:
    """Parse one stdout line, returning parse errors as values for the session."""
    try:
        message = types.jsonrpc_message_adapter.validate_json(line, by_name=False)
    except ValueError as exc:
        logger.exception("Failed to parse JSONRPC message from the MCP server")
        return exc
    return SessionMessage(message)


def _encode(message: SessionMessage) -> bytes:
    return (
        message.message.model_dump_json(by_alias=True, exclude_none=True) + "\n"
    ).encode("utf-8")


async def _close_client(client: Any) -> None:
    close = getattr(client, "close", None)
    if close is None:
        return
    with contextlib.suppress(Exception):
        await close()


class RunnerStdioTransport(ClientTransport):
    """MCP over a runner session container instead of a local subprocess."""

    def __init__(
        self,
        target: str,
        session_key: str,
        env: Optional[dict[str, str]] = None,
        manifest_digest: str = "",
        agent: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        agent_token: Optional[str] = None,
        token_resolver: Any = None,
        deadline_ms: int = 3_600_000,
        kind: str = "mcp_session",
        client_factory: Any = RunnerClient,
    ) -> None:
        self.target = target
        self.session_key = session_key
        self.env = dict(env or {})
        self.manifest_digest = manifest_digest
        self.agent = agent
        self.user_id = user_id
        self.user_email = user_email
        self.agent_token = agent_token
        # Central clients live in a process-wide cache, so a token captured at
        # construction belongs to whichever run created the cache entry. Resolve
        # per session-open instead (the contextvar is per run); an explicit token
        # (the edge frame) wins.
        self._token_resolver = token_resolver
        self.deadline_ms = deadline_ms
        self.kind = kind
        self._client_factory = client_factory
        self._session_id: Optional[str] = None

    def get_session_id(self) -> Optional[str]:
        return self._session_id

    def _current_token(self) -> Optional[str]:
        from core.agent_token import refresh

        if self.agent_token:
            return refresh(self.agent_token)
        if self._token_resolver is not None:
            return refresh(self._token_resolver())
        try:
            from core.auth import agent_token_var

            return refresh(agent_token_var.get())
        except Exception:
            return None

    def _request(self) -> SessionCreateRequest:
        return SessionCreateRequest(
            kind=self.kind,  # type: ignore[arg-type]
            target=self.target,
            manifest_digest=self.manifest_digest,
            agent=self.agent,
            user_id=self.user_id,
            user_email=self.user_email,
            session_key=self.session_key,
            env=self.env,
            agent_token=self._current_token(),
            deadline_ms=self.deadline_ms,
        )

    @contextlib.asynccontextmanager
    async def connect_session(
        self,
        *,
        transport_options: Optional[TransportOptions] = None,
        **session_kwargs: Unpack[SessionKwargs],
    ) -> AsyncIterator[Any]:
        options = transport_options or TransportOptions()
        client = self._client_factory()
        info: Optional[SessionInfo] = None
        try:
            info = await client.open_session(self._request())
            self._session_id = info.session_id
            async with anyio.create_task_group() as tg:
                read_writer, read_stream = anyio.create_memory_object_stream[
                    SessionMessage | Exception
                ](0)
                write_stream, write_reader = anyio.create_memory_object_stream[
                    SessionMessage
                ](0)
                writer_done = anyio.Event()
                tg.start_soon(
                    self._pump_stdout, client, info.session_id, read_writer
                )
                tg.start_soon(
                    self._pump_stdin,
                    client,
                    info.session_id,
                    write_reader,
                    read_writer,
                    writer_done,
                )
                try:
                    async with options.session_class(
                        read_stream, write_stream, **session_kwargs
                    ) as session:
                        yield session
                finally:
                    # Let the writer flush its last batch (a `cancelled`
                    # notification matters), then cancel both pumps and tear the
                    # container down under a shield: a cancelled caller must still
                    # never leak one.
                    with anyio.CancelScope(shield=True):
                        with anyio.move_on_after(WRITER_FLUSH_TIMEOUT_S):
                            await write_stream.aclose()
                            await writer_done.wait()
                    tg.cancel_scope.cancel()
                    with anyio.CancelScope(shield=True):
                        await self._teardown(client, info.session_id)
        finally:
            await _close_client(client)

    async def close(self) -> None:
        """Delete a session that outlived its ``connect_session`` scope."""
        session_id, self._session_id = self._session_id, None
        if not session_id:
            return
        client = self._client_factory()
        try:
            await client.delete_session(session_id)
        except Exception as exc:
            logger.warning(
                "runner session %s could not be deleted: %s", session_id, exc
            )
        finally:
            await _close_client(client)

    # --- plumbing -----------------------------------------------------------

    async def _teardown(self, client: Any, session_id: str) -> None:
        """Half-close then delete; every step attempted even if an earlier failed."""
        if self._session_id == session_id:
            self._session_id = None
        with contextlib.suppress(Exception):
            await client.close_session_stdin(session_id)
        try:
            await client.delete_session(session_id)
        except Exception as exc:
            # Not fatal: the runner's reaper collects orphaned session containers.
            logger.warning(
                "runner session %s could not be deleted: %s", session_id, exc
            )

    async def _pump_stdout(
        self,
        client: Any,
        session_id: str,
        read_writer: Any,
    ) -> None:
        """Runner stdout frames -> newline-delimited JSON-RPC -> ``read_stream``."""
        frame_buffer = b""
        line_buffer = ""
        async with read_writer:
            try:
                async for chunk in client.session_stdout(session_id):
                    if not chunk:
                        continue
                    frames, frame_buffer = parse_frames(frame_buffer + chunk)
                    for tag, payload in frames:
                        if tag == 2:
                            logger.info(
                                "mcp session %s stderr: %s",
                                session_id,
                                payload.decode("utf-8", "replace")
                                .rstrip()[:STDERR_LOG_LIMIT],
                            )
                            continue
                        line_buffer += payload.decode("utf-8", "replace")
                        while "\n" in line_buffer:
                            line, line_buffer = line_buffer.split("\n", 1)
                            if line.strip():
                                await read_writer.send(_parse_line(line))
            except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                return
            except Exception:
                logger.exception(
                    "reading the runner stdout stream for %s failed", session_id
                )

    async def _pump_stdin(
        self,
        client: Any,
        session_id: str,
        write_reader: Any,
        read_writer: Any,
        writer_done: anyio.Event,
    ) -> None:
        """``write_stream`` -> coalesced POSTs to ``/v1/sessions/{id}/stdin``."""
        pending = b""
        deadline: Optional[float] = None
        try:
            async with write_reader:
                while True:
                    if deadline is None:
                        try:
                            message = await write_reader.receive()
                        except (anyio.EndOfStream, anyio.ClosedResourceError):
                            break
                        pending = _encode(message)
                        deadline = anyio.current_time() + COALESCE_S

                    if len(pending) >= MAX_BATCH_BYTES:
                        await client.session_stdin(session_id, pending)
                        pending, deadline = b"", None
                        continue

                    remaining = deadline - anyio.current_time()
                    if remaining <= 0:
                        await client.session_stdin(session_id, pending)
                        pending, deadline = b"", None
                        continue

                    try:
                        with anyio.move_on_after(remaining) as scope:
                            message = await write_reader.receive()
                    except (anyio.EndOfStream, anyio.ClosedResourceError):
                        break
                    if scope.cancelled_caught:
                        await client.session_stdin(session_id, pending)
                        pending, deadline = b"", None
                        continue

                    encoded = _encode(message)
                    if len(pending) + len(encoded) > MAX_BATCH_BYTES:
                        await client.session_stdin(session_id, pending)
                        pending = encoded
                        deadline = anyio.current_time() + COALESCE_S
                    else:
                        pending += encoded

                if pending:
                    await client.session_stdin(session_id, pending)
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            return
        except Exception:
            logger.exception(
                "writing to runner session %s failed; ending the stream", session_id
            )
            # The server may still be alive: close the read side so the session
            # sees the connection end instead of hanging on a request forever.
            with contextlib.suppress(Exception):
                await read_writer.aclose()
        finally:
            writer_done.set()


def reset_for_tests() -> None:
    """No module state is kept; present so the standard test hook exists."""
    return None
