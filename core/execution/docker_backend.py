# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Docker Engine API backend for one-shot containers.

The daemon is reached over its Unix socket: ``httpx`` for the ordinary API calls
and a raw HTTP/1.1 upgrade for ``attach``. ``aiodocker`` is deliberately not a
dependency — it wraps exactly these two protocols, and the attach path below is
~40 lines of the same code with no version drift to track.

Attach must happen *before* ``start`` (Docker only buffers output for a client
that is already attached), and the attachment is no longer HTTP once the daemon
answers ``101 UPGRADED``: every byte after the headers is the multiplexed stream
``[stream_type, 0, 0, 0, len_be32] + payload`` (1=stdout, 2=stderr, 0=stdin).
``Tty`` is therefore always false; with a TTY the framing disappears.

Half-closing the socket's write side (``write_eof``) is how a container gets
stdin EOF. ``AutoRemove`` is false so a wedged container stays inspectable; every
run removes its own container in ``finally``.
"""

import asyncio
import json
import logging
import os
import struct
import time
from collections import deque
from contextlib import suppress
from typing import Any, Mapping, Optional
from urllib.parse import quote

import httpx

from core.execution.backend import (
    AttachHandle,
    BackendError,
    ContainerBackend,
    ExecRaw,
)
from core.execution.spec import (
    DEFAULT_NETWORK_MODE,
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    ContainerSpec,
)

logger = logging.getLogger(__name__)

DEFAULT_SOCKET = "/var/run/docker.sock"
ATTACH_TIMEOUT_S = 30.0
READ_CHUNK = 64 * 1024

# Frame header: stream type byte + three padding bytes + big-endian payload length.
_FRAME_HEADER = struct.Struct(">B3xI")


def _api_error(code: str, message: str, status: int = 0) -> BackendError:
    """BackendError carrying the HTTP status, so cleanup can ignore 404/409."""
    error = BackendError(code, message)
    error.status = status  # type: ignore[attr-defined]
    return error


def _error_message(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:300] or response.reason_phrase
    if isinstance(body, dict) and body.get("message"):
        return str(body["message"])
    return response.text[:300] or response.reason_phrase


def _create_payload(spec: ContainerSpec) -> dict:
    """The create body, built key by key from the spec.

    This is the only place Docker hardening flags are emitted. Nothing is copied
    from the caller, so no field can add capabilities, devices, extra mounts,
    host namespaces, or a writable rootfs.

    Network: there is no profile machinery and no resolv.conf bind. A container
    that may use the network gets Docker's default (the default bridge), so no
    NetworkMode is emitted at all; only ``network: none`` names a network, to
    take it away.
    """
    binds = [
        f"{mount.source}:{mount.target}:{'ro' if mount.read_only else 'rw'}"
        for mount in spec.mounts
    ]
    host_config = {
        "Binds": binds,
        "Tmpfs": {path: f"size={mb}m" for path, mb in spec.tmpfs.items()},
        "Memory": spec.memory_mb * 1024 * 1024,
        "NanoCpus": int(spec.cpus * 1_000_000_000),
        "PidsLimit": spec.pids,
        "Runtime": spec.runtime,
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true"],
        "ReadonlyRootfs": True,
        "AutoRemove": False,
        "Init": True,
        # The daemon's json-file log copies every container's stdout/stderr to
        # host disk, unrotated. Tool output must not outlive the call (and must
        # not reach /var/lib/docker); the attach stream is the only sink.
        "LogConfig": {"Type": "none"},
        # No swap: a memory limit that can swap is not a memory limit.
        "MemorySwap": spec.memory_mb * 1024 * 1024,
    }
    if spec.network_mode != DEFAULT_NETWORK_MODE:
        host_config["NetworkMode"] = spec.network_mode
    payload: dict = {
        "Image": spec.image,
        "Cmd": list(spec.cmd),
        "Env": [f"{key}={value}" for key, value in sorted(spec.env.items())],
        "WorkingDir": spec.working_dir,
        "Labels": dict(spec.labels),
        "Tty": False,
        "OpenStdin": True,
        # A tool gets one stdin write then EOF; a session keeps stdin open for
        # the next MCP message.
        "StdinOnce": spec.kind not in {"mcp_session", "discovery"},
        "HostConfig": host_config,
    }
    if spec.user:
        payload["User"] = spec.user
    return payload


def parse_frames(buffer: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    """Split complete multiplexed frames out of ``buffer``.

    Returns ``(frames, leftover)``. ``leftover`` is the start of a frame whose
    payload has not fully arrived yet and must be prepended to the next read.
    """
    frames: list[tuple[int, bytes]] = []
    offset = 0
    while len(buffer) - offset >= _FRAME_HEADER.size:
        stream, length = _FRAME_HEADER.unpack_from(buffer, offset)
        end = offset + _FRAME_HEADER.size + length
        if end > len(buffer):
            break
        frames.append((stream, buffer[offset + _FRAME_HEADER.size : end]))
        offset = end
    return frames, buffer[offset:]


class _DockerAttach:
    """A hijacked attach socket exposing frames instead of HTTP bytes."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer
        self._buffer = b""
        self._frames: deque[tuple[int, bytes]] = deque()
        self._eof = False
        self._stdin_closed = False
        self._closed = False

    async def write(self, data: bytes) -> None:
        if self._closed or not data:
            return
        self._writer.write(data)
        await self._writer.drain()

    async def close_stdin(self) -> None:
        if self._stdin_closed or self._closed:
            return
        self._stdin_closed = True
        with suppress(OSError, RuntimeError):
            self._writer.write_eof()
            await self._writer.drain()

    async def read_frame(self) -> Optional[tuple[int, bytes]]:
        while not self._frames:
            frames, self._buffer = parse_frames(self._buffer)
            self._frames.extend(frames)
            if self._frames:
                break
            if self._eof or self._closed:
                break
            try:
                chunk = await self._reader.read(READ_CHUNK)
            except OSError:
                chunk = b""
            if not chunk:
                # A reset is the daemon closing a dead container; the exit code
                # comes from inspect, so treat it as EOF.
                self._eof = True
            else:
                self._buffer += chunk
        if self._frames:
            return self._frames.popleft()
        return None

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._writer.close()
        with suppress(OSError, RuntimeError):
            await self._writer.wait_closed()


async def _collect(handle: AttachHandle) -> tuple[bytes, bytes, bool, bool]:
    """Drain the attach stream, capping each buffer but never stopping reads.

    Stopping the read would block the container on a full pipe and turn an
    oversized-output tool into a timeout instead of a truncation.
    """
    stdout = bytearray()
    stderr = bytearray()
    stdout_truncated = False
    stderr_truncated = False
    while True:
        frame = await handle.read_frame()
        if frame is None:
            break
        stream, payload = frame
        if not payload:
            continue
        if stream == 2:
            truncated = _take(stderr, payload, MAX_STDERR_BYTES)
            stderr_truncated = stderr_truncated or truncated
        elif stream == 1:
            truncated = _take(stdout, payload, MAX_STDOUT_BYTES)
            stdout_truncated = stdout_truncated or truncated
    return bytes(stdout), bytes(stderr), stdout_truncated, stderr_truncated


def _take(buffer: bytearray, payload: bytes, cap: int) -> bool:
    room = cap - len(buffer)
    if room <= 0:
        return True
    buffer.extend(payload[:room])
    return len(payload) > room


class DockerBackend(ContainerBackend):
    def __init__(
        self,
        *,
        socket: Optional[str] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        timeout: float = 120.0,
    ) -> None:
        self._socket = socket or os.getenv("DOCKER_SOCKET") or DEFAULT_SOCKET
        self._transport = transport
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    def _make_client(self) -> httpx.AsyncClient:
        transport = self._transport or httpx.AsyncHTTPTransport(uds=self._socket)
        return httpx.AsyncClient(
            transport=transport, base_url="http://docker", timeout=self._timeout
        )

    async def _client_or_make(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = self._make_client()
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict] = None,
        body: Optional[dict] = None,
    ) -> httpx.Response:
        client = await self._client_or_make()
        try:
            response = await client.request(method, path, params=params, json=body)
        except httpx.HTTPError as exc:
            raise BackendError(
                "daemon_unavailable",
                f"docker daemon unreachable at {self._socket} "
                f"({type(exc).__name__}: {exc})",
            ) from exc
        if response.status_code >= 400:
            raise _api_error(
                "internal",
                f"{method} {path} -> {response.status_code}: "
                f"{_error_message(response)}",
                response.status_code,
            )
        return response

    # --- ContainerBackend ---------------------------------------------------

    async def create(self, spec: ContainerSpec) -> str:
        try:
            response = await self._request(
                "POST", "/containers/create", body=_create_payload(spec)
            )
        except BackendError as exc:
            if (
                getattr(exc, "status", 0) == 404
                and "no such image" in exc.message.lower()
            ):
                raise BackendError(
                    "image_missing",
                    f"image {spec.image!r} is not present locally; "
                    "the runner never pulls",
                ) from None
            raise
        payload = response.json()
        container_id = payload.get("Id") if isinstance(payload, dict) else None
        if not container_id:
            raise BackendError("internal", "docker create returned no container id")
        return str(container_id)

    async def attach(
        self, container_id: str, *, stdin: bool = True
    ) -> AttachHandle:
        try:
            reader, writer = await asyncio.open_unix_connection(self._socket)
        except OSError as exc:
            raise BackendError(
                "daemon_unavailable",
                f"docker daemon unreachable at {self._socket} ({exc})",
            ) from exc
        handle = _DockerAttach(reader, writer)
        query = "stream=1&stdout=1&stderr=1"
        if stdin:
            query = "stream=1&stdin=1&stdout=1&stderr=1"
        request = (
            f"POST /containers/{container_id}/attach?{query} HTTP/1.1\r\n"
            "Host: docker\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: tcp\r\n"
            "Content-Type: application/vnd.docker.raw-stream\r\n\r\n"
        )
        try:
            writer.write(request.encode("ascii"))
            await writer.drain()
            header = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), ATTACH_TIMEOUT_S
            )
        except (
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            asyncio.TimeoutError,
            OSError,
        ) as exc:
            await handle.close()
            raise BackendError(
                "internal",
                f"docker attach to {container_id} failed "
                f"({type(exc).__name__}: {exc})",
            ) from exc
        status_line = header.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or parts[1] != "101":
            await handle.close()
            raise BackendError(
                "internal",
                f"docker attach to {container_id} was refused: {status_line}",
            )
        return handle

    async def start(self, container_id: str) -> None:
        await self._request("POST", f"/containers/{container_id}/start")

    async def kill(self, container_id: str) -> None:
        await self._request(
            "POST",
            f"/containers/{container_id}/kill",
            params={"signal": "SIGKILL"},
        )

    async def remove(self, container_id: str) -> None:
        try:
            await self._request(
                "DELETE",
                f"/containers/{container_id}",
                params={"force": 1, "v": 1},
            )
        except BackendError as exc:
            if getattr(exc, "status", 0) == 404:
                return
            raise

    async def inspect(self, container_id: str) -> Mapping[str, Any]:
        response = await self._request("GET", f"/containers/{container_id}/json")
        payload = response.json()
        if not isinstance(payload, dict):
            raise BackendError("internal", "docker inspect returned a non-object")
        return payload

    async def list_containers(
        self, labels: Mapping[str, str]
    ) -> list[Mapping[str, Any]]:
        params: dict = {"all": 1}
        if labels:
            params["filters"] = json.dumps(
                {"label": [f"{key}={value}" for key, value in labels.items()]},
                sort_keys=True,
            )
        response = await self._request("GET", "/containers/json", params=params)
        payload = response.json()
        return payload if isinstance(payload, list) else []

    async def has_runtime(self, name: str) -> bool:
        response = await self._request("GET", "/info")
        payload = response.json()
        runtimes = payload.get("Runtimes") if isinstance(payload, dict) else None
        return isinstance(runtimes, dict) and name in runtimes

    async def has_image(self, image: str) -> bool:
        try:
            await self._request(
                "GET", f"/images/{quote(image, safe='/:@')}/json"
            )
        except BackendError as exc:
            if getattr(exc, "status", 0) == 404:
                return False
            raise
        return True

    # --- one-shot execution -------------------------------------------------

    async def run(
        self, spec: ContainerSpec, stdin: bytes, timeout_s: float
    ) -> ExecRaw:
        started = time.monotonic()
        deadline = started + max(0.5, float(timeout_s))

        def remaining() -> float:
            return max(0.1, deadline - time.monotonic())

        async def bounded(awaitable):
            try:
                return await asyncio.wait_for(awaitable, remaining())
            except TimeoutError:
                raise BackendError(
                    "timeout",
                    f"container did not become ready within {timeout_s:.1f}s",
                ) from None

        container_id = await bounded(self.create(spec))
        handle: Optional[AttachHandle] = None
        try:
            handle = await bounded(self.attach(container_id))
            await bounded(self.start(container_id))

            async def feed() -> None:
                if stdin:
                    try:
                        await handle.write(stdin)
                    except OSError as exc:
                        # The process exited before reading its input; the exit
                        # code and output still describe the run better than an
                        # EPIPE traceback does.
                        logger.debug(
                            "container %s closed stdin early: %s", container_id, exc
                        )
                await handle.close_stdin()

            # Feed and collect concurrently: a tool that writes more than a pipe
            # buffer before reading stdin would otherwise deadlock every slot.
            try:
                _, (stdout, stderr, out_trunc, err_trunc) = await asyncio.wait_for(
                    asyncio.gather(feed(), _collect(handle)), remaining()
                )
            except TimeoutError:
                raise BackendError(
                    "timeout",
                    f"container {container_id} did not finish within {timeout_s:.1f}s",
                ) from None
            exit_code = await self._exit_code(container_id)
            return ExecRaw(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=out_trunc,
                stderr_truncated=err_trunc,
                duration_ms=int((time.monotonic() - started) * 1000),
                container_id=container_id,
            )
        finally:
            if handle is not None:
                with suppress(Exception):
                    await handle.close()
            await self._discard(container_id)

    async def _exit_code(self, container_id: str) -> int:
        # The attach stream closes just before the daemon commits the final
        # state, so give inspect a short window instead of reporting 0.
        deadline = time.monotonic() + 2.0
        while True:
            state = (await self.inspect(container_id)).get("State") or {}
            running = bool(state.get("Running"))
            if not running:
                return int(state.get("ExitCode") or 0)
            if time.monotonic() >= deadline:
                # A process that closed stdout but keeps running is NOT a
                # success; the caller SIGKILLs it in cleanup.
                raise BackendError(
                    "timeout",
                    f"container {container_id} closed its output but is still running",
                )
            await asyncio.sleep(0.05)

    async def _discard(self, container_id: str) -> None:
        """Best-effort kill + remove; never masks the run's real outcome."""
        try:
            await self.kill(container_id)
        except BackendError as exc:
            if getattr(exc, "status", 0) not in (404, 409):
                logger.debug("container %s kill failed: %s", container_id, exc)
        try:
            await self.remove(container_id)
        except BackendError as exc:
            logger.debug("container %s remove failed: %s", container_id, exc)
