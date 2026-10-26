# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Pure tests for the Docker Engine backend.

No Docker daemon: the ordinary API calls run against ``httpx.MockTransport`` and
the attach hijack against a local Unix socket that speaks the 101 upgrade. What
is pinned here is the security shape of the create body, the multiplexed frame
parser, and the error-code mapping the runner turns into HTTP statuses.
"""

import asyncio
from contextlib import suppress

import httpx
import pytest

from core.execution import docker_backend
from core.execution.backend import BackendError
from core.execution.docker_backend import DockerBackend, _create_payload, parse_frames
from core.execution.spec import DEFAULT_NETWORK_MODE, ContainerSpec, Mount


def _spec(**overrides) -> ContainerSpec:
    values = dict(
        image="trellis-agent-platform:test",
        runtime="runsc",
        cmd=["python3", "/app/workspace/tools/demo/demo.py"],
        working_dir="/app/workspace/tools/demo",
        env={"B": "2", "A": "1"},
        mounts=[
            Mount("/host/ws/tools/demo", "/app/workspace/tools/demo", True),
            Mount("/host/ws/shared", "/app/workspace/shared", True),
            Mount("/host/ws/reports/agent", "/app/workspace/reports/agent", False),
        ],
        tmpfs={"/tmp": 128},
        memory_mb=512,
        cpus=1.5,
        pids=256,
        network_mode=DEFAULT_NETWORK_MODE,
        labels={"trellis.install": "default", "trellis.kind": "tool"},
        user="1000:1000",
        kind="tool",
    )
    values.update(overrides)
    return ContainerSpec(**values)


def _frame(stream: int, payload: bytes) -> bytes:
    return bytes([stream, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload


# --- create body ---------------------------------------------------------


def test_create_payload_sets_every_hardening_flag():
    payload = _create_payload(_spec())

    assert set(payload) == {
        "Image",
        "Cmd",
        "Env",
        "WorkingDir",
        "Labels",
        "Tty",
        "OpenStdin",
        "StdinOnce",
        "HostConfig",
        "User",
    }
    assert payload["Tty"] is False
    assert payload["OpenStdin"] is True
    assert payload["StdinOnce"] is True
    assert payload["User"] == "1000:1000"
    assert payload["Env"] == ["A=1", "B=2"]
    assert payload["Cmd"] == ["python3", "/app/workspace/tools/demo/demo.py"]

    host = payload["HostConfig"]
    assert set(host) == {
        "Binds",
        "Tmpfs",
        "Memory",
        "NanoCpus",
        "PidsLimit",
        "Runtime",
        "CapDrop",
        "SecurityOpt",
        "ReadonlyRootfs",
        "AutoRemove",
        "Init",
        "LogConfig",
        "MemorySwap",
    }
    assert host["CapDrop"] == ["ALL"]
    assert host["SecurityOpt"] == ["no-new-privileges:true"]
    assert host["ReadonlyRootfs"] is True
    assert host["AutoRemove"] is False
    assert host["Init"] is True
    # A caller must not be able to reach these at all.
    for forbidden in (
        "Privileged",
        "CapAdd",
        "Devices",
        "PidMode",
        "IpcMode",
        "UsernsMode",
    ):
        assert forbidden not in payload
        assert forbidden not in host


def test_create_payload_binds_tmpfs_and_limits():
    host = _create_payload(_spec())["HostConfig"]

    assert host["Binds"] == [
        "/host/ws/tools/demo:/app/workspace/tools/demo:ro",
        "/host/ws/shared:/app/workspace/shared:ro",
        "/host/ws/reports/agent:/app/workspace/reports/agent:rw",
    ]
    assert host["Tmpfs"] == {"/tmp": "size=128m"}
    assert host["Memory"] == 512 * 1024 * 1024
    assert host["NanoCpus"] == 1_500_000_000
    assert host["PidsLimit"] == 256
    # Egress is Docker's own default bridge, so the payload names no network at all.
    assert "NetworkMode" not in host
    assert host["Runtime"] == "runsc"


def test_create_payload_network_none_is_the_only_network_override():
    host = _create_payload(_spec(network_mode="none"))["HostConfig"]

    assert host["NetworkMode"] == "none"


@pytest.mark.parametrize("network_mode", [DEFAULT_NETWORK_MODE, "none"])
def test_create_payload_never_mounts_a_resolv_conf(network_mode):
    """Docker supplies /etc/resolv.conf; the generated-file machinery is gone."""
    payload = _create_payload(_spec(network_mode=network_mode))

    assert all("resolv.conf" not in bind for bind in payload["HostConfig"]["Binds"])
    assert all("resolv" not in key for key in payload["HostConfig"]["Tmpfs"])


def test_console_payload_has_no_network(monkeypatch):
    monkeypatch.setenv("TRELLIS_UID", "1000")
    monkeypatch.setenv("TRELLIS_GID", "1000")
    from core.execution.spec import build_console_spec

    payload = _create_payload(build_console_spec("id", env={}))

    assert payload["HostConfig"]["NetworkMode"] == "none"
    assert payload["HostConfig"]["Binds"] == []


def test_legacy_internal_manifest_runs_on_the_default_bridge(tmp_path, monkeypatch, caplog):
    """Acceptance gate: `network: internal` loads, runs with egress, one warning."""
    from core.execution.spec import build_spec
    from core.models import ToolConfig, reset_network_policy_warnings

    root = tmp_path / "workspace"
    suite = root / "tools" / "legacy"
    suite.mkdir(parents=True)
    (suite / "tool.py").write_text("print('{}')\n", encoding="utf-8")
    monkeypatch.setenv("TRELLIS_UID", "1000")
    monkeypatch.setenv("TRELLIS_GID", "1000")
    monkeypatch.setenv("RUNNER_IMAGE", "trellis-agent-platform:test")
    reset_network_policy_warnings()

    with caplog.at_level("WARNING", logger="core.models"):
        config = ToolConfig(
            name="legacy",
            description="d",
            runtime="python",
            entrypoint="tool.py",
            network="internal",
        )
        spec = build_spec(
            config,
            kind="tool",
            suite_rel="tools/legacy",
            target="legacy",
            env={},
            host_workspace=str(root),
        )
    payload = _create_payload(spec)

    assert config.network == "egress"
    assert spec.network_mode == DEFAULT_NETWORK_MODE
    assert "NetworkMode" not in payload["HostConfig"]
    assert len([r for r in caplog.records if r.levelno == 30]) == 1


def test_create_payload_session_keeps_stdin_open_and_omits_default_user():
    payload = _create_payload(_spec(kind="mcp_session", user=None))

    assert payload["StdinOnce"] is False
    assert "User" not in payload


def test_create_payload_discovery_keeps_stdin_open():
    # Discovery drives the MCP handshake, so stdin must outlive the first write.
    assert _create_payload(_spec(kind="discovery"))["StdinOnce"] is False


# --- frame parsing -------------------------------------------------------


def test_parse_frames_multiple_and_zero_length():
    buffer = _frame(1, b"hello") + _frame(2, b"err") + _frame(0, b"")
    frames, leftover = parse_frames(buffer)

    assert frames == [(1, b"hello"), (2, b"err"), (0, b"")]
    assert leftover == b""


def test_parse_frames_keeps_partial_header_as_leftover():
    whole = _frame(1, b"hello")
    partial = whole[:5]

    frames, leftover = parse_frames(partial)
    assert frames == []
    assert leftover == partial

    frames, leftover = parse_frames(leftover + whole[5:])
    assert frames == [(1, b"hello")]
    assert leftover == b""


def test_parse_frames_keeps_partial_payload_as_leftover():
    whole = _frame(1, b"hello")
    head, tail = whole[:11], whole[11:]

    frames, leftover = parse_frames(head + tail[:-2])
    assert frames == []
    assert leftover == head + tail[:-2]

    frames, leftover = parse_frames(leftover + tail[-2:])
    assert frames == [(1, b"hello")]
    assert leftover == b""


def test_parse_frames_reads_big_endian_length():
    payload = b"x" * 300

    frames, leftover = parse_frames(_frame(1, payload))

    assert frames == [(1, payload)]
    assert leftover == b""


def test_parse_frames_empty_buffer():
    assert parse_frames(b"") == ([], b"")


# --- daemon error mapping ------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


def test_create_missing_image_maps_to_image_missing():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/containers/create"
        assert request.method == "POST"
        return httpx.Response(404, json={"message": "No such image: nope:latest"})

    async def scenario() -> None:
        backend = DockerBackend(transport=httpx.MockTransport(handler))
        try:
            with pytest.raises(BackendError) as excinfo:
                await backend.create(_spec(image="nope:latest"))
            assert excinfo.value.code == "image_missing"
        finally:
            await backend.close()

    _run(scenario())


def test_unreachable_daemon_maps_to_runtime_missing():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("socket refused", request=request)

    async def scenario() -> None:
        backend = DockerBackend(transport=httpx.MockTransport(handler))
        try:
            with pytest.raises(BackendError) as excinfo:
                await backend.has_runtime("runsc")
            assert excinfo.value.code == "daemon_unavailable"
        finally:
            await backend.close()

    _run(scenario())


def test_has_runtime_reads_docker_info():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/info"
        return httpx.Response(200, json={"Runtimes": {"runc": {}, "runsc": {}}})

    async def scenario() -> None:
        backend = DockerBackend(transport=httpx.MockTransport(handler))
        try:
            assert await backend.has_runtime("runsc") is True
            assert await backend.has_runtime("kata") is False
        finally:
            await backend.close()

    _run(scenario())


def test_has_image_false_only_for_404():
    def missing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "No such image: nope"})

    def present(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"Id": "sha256:abc"})

    async def scenario() -> None:
        backend = DockerBackend(transport=httpx.MockTransport(missing))
        try:
            assert await backend.has_image("nope:latest") is False
        finally:
            await backend.close()
        backend = DockerBackend(transport=httpx.MockTransport(present))
        try:
            assert await backend.has_image("present:latest") is True
        finally:
            await backend.close()

    _run(scenario())


def test_remove_ignores_already_gone_container():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        return httpx.Response(404, json={"message": "No such container: gone"})

    async def scenario() -> None:
        backend = DockerBackend(transport=httpx.MockTransport(handler))
        try:
            await backend.remove("gone")
        finally:
            await backend.close()

    _run(scenario())


def test_inspect_surfaces_daemon_errors():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"message": "daemon exploded"})

    async def scenario() -> None:
        backend = DockerBackend(transport=httpx.MockTransport(handler))
        try:
            with pytest.raises(BackendError) as excinfo:
                await backend.inspect("c1")
            assert excinfo.value.code == "internal"
            assert "daemon exploded" in excinfo.value.message
        finally:
            await backend.close()

    _run(scenario())


def test_list_containers_sends_label_filters():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["params"] = request.url.params
        return httpx.Response(200, json=[{"Id": "c1"}])

    async def scenario() -> None:
        backend = DockerBackend(transport=httpx.MockTransport(handler))
        try:
            containers = await backend.list_containers(
                {"trellis.install": "default", "trellis.kind": "tool"}
            )
            assert containers == [{"Id": "c1"}]
        finally:
            await backend.close()

    _run(scenario())
    assert seen["params"]["all"] == "1"
    assert seen["params"]["filters"] == (
        '{"label": ["trellis.install=default", "trellis.kind=tool"]}'
    )


# --- attach + run over a real Unix socket --------------------------------


class _FakeDaemon:
    """Fake engine: httpx transport for the API plus a 101-upgrading UDS."""

    def __init__(self, sock_path, attach_bytes: bytes, *, hang: bool = False):
        self.sock_path = str(sock_path)
        self.attach_bytes = attach_bytes
        self.hang = hang
        self.stdin = b""
        self.attach_request = b""
        self.calls: list[tuple[str, str]] = []
        self._server = None
        self._release = asyncio.Event()

    async def start(self) -> None:
        self._server = await asyncio.start_unix_server(
            self._handle, path=self.sock_path
        )

    async def stop(self) -> None:
        self._release.set()
        if self._server is not None:
            self._server.close()
            with suppress(Exception):
                await self._server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        try:
            self.calls.append(("POST", "/containers/abc123/attach"))
            self.attach_request = await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 101 UPGRADED\r\n\r\n")
            await writer.drain()
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                self.stdin += chunk
            if self.attach_bytes:
                writer.write(self.attach_bytes)
                await writer.drain()
            if self.hang:
                # Hold the stream open until the test stops the fake daemon, so
                # the client's deadline is what ends the run.
                await self._release.wait()
        except Exception:
            pass
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            self.calls.append((request.method, path))
            if path == "/containers/create":
                return httpx.Response(201, json={"Id": "abc123"})
            if path == "/containers/abc123/json":
                return httpx.Response(
                    200, json={"State": {"Running": False, "ExitCode": 7}}
                )
            if path.endswith("/kill"):
                # The process already exited: Docker answers 409.
                return httpx.Response(409, json={"message": "not running"})
            return httpx.Response(204)

        return httpx.MockTransport(handler)


def test_run_reports_frames_truncation_and_exit_code(tmp_path, monkeypatch):
    monkeypatch.setattr(docker_backend, "MAX_STDOUT_BYTES", 4)

    async def scenario() -> None:
        daemon = _FakeDaemon(
            tmp_path / "docker.sock",
            _frame(1, b"hello") + _frame(2, b"stderr-output") + _frame(1, b"!!"),
        )
        await daemon.start()
        backend = DockerBackend(
            socket=daemon.sock_path, transport=daemon.transport()
        )
        try:
            result = await backend.run(_spec(), b'{"x": 1}', 5.0)
        finally:
            await backend.close()
            await daemon.stop()

        assert result.exit_code == 7
        assert result.stdout == b"hell"
        assert result.stdout_truncated is True
        assert result.stderr == b"stderr-output"
        assert result.stderr_truncated is False
        assert result.container_id == "abc123"
        assert result.duration_ms >= 0
        # stdin reached the container, and the write half was closed (EOF).
        assert daemon.stdin == b'{"x": 1}'
        assert daemon.attach_request.startswith(
            b"POST /containers/abc123/attach"
            b"?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1"
        )
        assert b"Upgrade: tcp" in daemon.attach_request
        # Attach must happen BEFORE start: attaching after start loses the first
        # bytes of output (the highest-risk ordering in the plan).
        order = [
            index
            for index, call in enumerate(daemon.calls)
            if call in {
                ("POST", "/containers/create"),
                ("POST", "/containers/abc123/attach"),
                ("POST", "/containers/abc123/start"),
            }
        ]
        assert [daemon.calls[index] for index in order] == [
            ("POST", "/containers/create"),
            ("POST", "/containers/abc123/attach"),
            ("POST", "/containers/abc123/start"),
        ]
        # Cleanup ran even though kill answered 409.
        assert ("POST", "/containers/abc123/kill") in daemon.calls
        assert ("DELETE", "/containers/abc123") in daemon.calls

    _run(scenario())


def test_run_timeout_kills_and_removes(tmp_path):
    async def scenario() -> None:
        daemon = _FakeDaemon(tmp_path / "docker.sock", b"", hang=True)
        await daemon.start()
        backend = DockerBackend(
            socket=daemon.sock_path, transport=daemon.transport()
        )
        try:
            with pytest.raises(BackendError) as excinfo:
                await backend.run(_spec(), b"", 0.05)
            assert excinfo.value.code == "timeout"
        finally:
            await backend.close()
            await daemon.stop()

        assert ("POST", "/containers/abc123/kill") in daemon.calls
        assert ("DELETE", "/containers/abc123") in daemon.calls

    _run(scenario())
