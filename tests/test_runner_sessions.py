# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Runner session API: spec derivation, stdin/stdout plumbing, reaping, capacity.

All against ``FakeBackend`` -- no Docker daemon, no runsc. Each test runs inside a
single ``asyncio.run`` because the session registry and its semaphores are bound to
one event loop (which is also true of the real single-worker runner).
"""

import asyncio
import struct
from types import SimpleNamespace

import httpx
import pytest
import yaml

from core import agent_token
from core.execution import backend as backend_module
from core.execution import canary as canary_module
from core.execution import runner as runner_module
from core.execution.spec import ContainerSpec, manifest_digest
from core.models import MCPConfig
from fixtures.fake_backend import FakeBackend, RawExec

AUTH = {"authorization": "Bearer test-token"}
SECRET = "runner-sessions-unit-secret-0123456789abcdef"


def _token(agent="demo-assistant", user_id="u-1", email="u@example.test"):
    """The run's token: the runner's ONLY identity source (no identity in the body)."""
    return agent_token.mint(agent, user_id=user_id, user_email=email)
FRAME = struct.Struct(">BI")
SESSION_KEY = "a" * 32

MCP_YAML = """\
- name: stateful
  transport: stdio
  command: python3
  args: ["server.py"]
  secrets:
    - MCP_TOKEN
  network: none
"""

OTHER_YAML = """\
- name: billing
  transport: stdio
  command: node
  args: ["server.js"]
"""

HTTP_YAML = """\
- name: docs-http
  transport: sse
  command: python3
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    suite = root / "mcps" / "stateful"
    suite.mkdir(parents=True)
    (suite / "server.py").write_text("print('ready')\n", encoding="utf-8")
    (suite / "mcp.yaml").write_text(MCP_YAML, encoding="utf-8")
    other = root / "mcps" / "billing"
    other.mkdir()
    (other / "server.js").write_text("// billing\n", encoding="utf-8")
    (other / "mcp.yaml").write_text(OTHER_YAML, encoding="utf-8")
    http = root / "mcps" / "docs"
    http.mkdir()
    (http / "mcp.yaml").write_text(HTTP_YAML, encoding="utf-8")
    (root / "shared").mkdir()

    monkeypatch.setenv("WORKSPACE_ROOT", str(root))
    # Deliberately different from the runner's view: host paths resolve in Docker.
    monkeypatch.setenv("TRELLIS_HOST_WORKSPACE", f"/host{root}")
    monkeypatch.setenv("RUNNER_TOKEN", "test-token")
    monkeypatch.setenv("RUNNER_IMAGE", "trellis-agent-platform:test")
    monkeypatch.setenv("CONTAINER_DEFAULT_RUNTIME", "runsc")
    monkeypatch.setenv("RUNNER_MAX_CONTAINERS", "32")
    monkeypatch.setenv("RUNNER_MAX_CONTAINERS_PER_TOOL", "8")
    monkeypatch.setenv("TRELLIS_INSTALL_ID", "test-install")
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.delenv("ENFORCE_AGENT_TOKENS", raising=False)
    monkeypatch.setenv("TRELLIS_UID", "1000")
    monkeypatch.setenv("TRELLIS_GID", "1000")

    backend = FakeBackend()
    backend_module.set_backend(backend)
    runner_module.reset_for_tests()
    canary_module.reset_for_tests()
    try:
        yield SimpleNamespace(root=root, suite=suite, backend=backend)
    finally:
        backend_module.set_backend(None)
        runner_module.reset_for_tests()
        canary_module.reset_for_tests()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _digest(root, suite: str = "stateful") -> str:
    raw = yaml.safe_load((root / "mcps" / suite / "mcp.yaml").read_text())
    return manifest_digest(MCPConfig(**raw[0]))


def _body(root, **overrides) -> dict:
    body = {
        "kind": "mcp_session",
        "target": "stateful",
        "manifest_digest": _digest(root),
        "session_key": SESSION_KEY,
        "agent_token": _token(),
        "env": {"MCP_TOKEN": "s3cret"},
        "deadline_ms": 60_000,
    }
    body.update(overrides)
    return body


def _client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=runner_module.app)
    return httpx.AsyncClient(transport=transport, base_url="http://runner")


async def _open(client, root, **overrides) -> dict:
    response = await client.post(
        "/v1/sessions", json=_body(root, **overrides), headers=AUTH
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _delete(client, session_id: str) -> None:
    await client.delete(f"/v1/sessions/{session_id}", headers=AUTH)


# --------------------------------------------------------------------------- #
# open: spec derivation
# --------------------------------------------------------------------------- #


def test_open_session_derives_a_read_only_session_spec(env):
    async def scenario():
        async with _client() as client:
            info = await _open(client, env.root)
            await _delete(client, info["session_id"])
            return info

    info = asyncio.run(scenario())

    assert info["session_id"]
    assert info["container_id"] == "fake-1"
    assert info["state"] == "running"
    assert info["exit_code"] is None

    container_spec = env.backend.specs[0]
    assert [mount.target for mount in container_spec.mounts] == [
        "/app/workspace/mcps/stateful",
        "/app/workspace/shared",
    ]
    # A session gets no output dir: there is no rw mount at all.
    assert [mount.read_only for mount in container_spec.mounts] == [True, True]
    assert container_spec.mounts[0].source == f"/host{env.suite}"
    assert container_spec.mounts[1].source == f"/host{env.root}/shared"

    assert container_spec.working_dir == "/app/workspace/mcps/stateful"
    assert container_spec.cmd == ["python3", "server.py"]
    assert container_spec.kind == "mcp_session"
    assert container_spec.network_mode == "none"
    assert container_spec.image == "trellis-agent-platform:test"
    assert container_spec.runtime == "runsc"
    assert container_spec.tmpfs == {"/tmp": 512}
    assert container_spec.labels["trellis.install"] == "test-install"
    assert container_spec.labels["trellis.kind"] == "mcp_session"
    assert container_spec.labels["trellis.target"] == "stateful"
    assert container_spec.labels["trellis.session"] == SESSION_KEY
    assert container_spec.labels["trellis.run"] == ""
    assert container_spec.env["MCP_TOKEN"] == "s3cret"
    assert container_spec.env["HOME"] == "/tmp"
    assert "RUNNER_TOKEN" not in container_spec.env


def test_discovery_kind_uses_the_same_container_with_its_own_label(env):
    async def scenario():
        async with _client() as client:
            info = await _open(client, env.root, kind="discovery")
            await _delete(client, info["session_id"])

    asyncio.run(scenario())

    assert env.backend.specs[0].kind == "discovery"
    assert env.backend.specs[0].labels["trellis.kind"] == "discovery"


def test_two_sessions_get_disjoint_containers_and_mounts(env):
    async def scenario():
        async with _client() as client:
            first = await _open(client, env.root)
            second = await _open(client, env.root, session_key="b" * 32)
            await _delete(client, first["session_id"])
            await _delete(client, second["session_id"])
            return first, second

    first, second = asyncio.run(scenario())

    assert first["container_id"] != second["container_id"]
    first_spec, second_spec = env.backend.specs
    assert first_spec.labels["trellis.session"] != second_spec.labels["trellis.session"]
    # Neither session can see the other suite, and neither has a writable mount.
    for container_spec in (first_spec, second_spec):
        targets = {mount.target for mount in container_spec.mounts}
        assert "/app/workspace/mcps/billing" not in targets
        assert all(mount.read_only for mount in container_spec.mounts)
        assert container_spec.env["HOME"] == "/tmp"


# --------------------------------------------------------------------------- #
# stdin / stdout / close
# --------------------------------------------------------------------------- #


def test_stdin_reaches_the_attach_and_close_half_closes_it(env):
    async def scenario():
        async with _client() as client:
            info = await _open(client, env.root)
            cid = info["container_id"]
            first = await client.post(
                f"/v1/sessions/{info['session_id']}/stdin",
                content=b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n',
                headers={**AUTH, "content-type": "application/octet-stream"},
            )
            closed = await client.post(
                f"/v1/sessions/{info['session_id']}/close", headers=AUTH
            )
            attach = env.backend.attaches[cid]
            await _delete(client, info["session_id"])
            return first, closed, attach

    first, closed, attach = asyncio.run(scenario())

    assert first.status_code == 204
    assert closed.status_code == 204
    assert bytes(attach.written) == (
        b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'
    )
    assert attach.stdin_closed.is_set()


def test_stdout_is_reframed_and_eof_ends_the_stream(env):
    async def scenario():
        async with _client() as client:
            info = await _open(client, env.root)
            cid = info["container_id"]
            env.backend.push(cid, 1, b'{"jsonrpc":"2.0","id":1,"result":{}}\n')
            env.backend.push(cid, 2, b"server warning\n")
            env.backend.finish(cid, exit_code=3)

            chunks = []
            async with client.stream(
                "GET", f"/v1/sessions/{info['session_id']}/stdout", headers=AUTH
            ) as response:
                assert response.status_code == 200
                assert response.headers["content-type"] == "application/octet-stream"
                async for chunk in response.aiter_raw():
                    chunks.append(chunk)

            status = await client.get(
                f"/v1/sessions/{info['session_id']}", headers=AUTH
            )
            await _delete(client, info["session_id"])
            return b"".join(chunks), status.json()

    raw, status = asyncio.run(scenario())

    stdout = b'{"jsonrpc":"2.0","id":1,"result":{}}\n'
    assert raw == (
        FRAME.pack(1, len(stdout))
        + stdout
        + FRAME.pack(2, len(b"server warning\n"))
        + b"server warning\n"
    )
    assert status["state"] == "exited"
    assert status["exit_code"] == 3
    assert status["bytes_out"] == len(stdout) + len(b"server warning\n")


def test_stream_ends_after_eof_and_a_second_consumer_is_refused(env):
    async def scenario():
        async with _client() as client:
            info = await _open(client, env.root)
            cid = info["container_id"]
            sid = info["session_id"]
            env.backend.push(cid, 1, b"one\n")

            async def consume():
                async with client.stream(
                    "GET", f"/v1/sessions/{sid}/stdout", headers=AUTH
                ) as response:
                    return b"".join([chunk async for chunk in response.aiter_raw()])

            # ASGI transport buffers the body, so the first consumer stays blocked
            # on the sentinel we push below while its request is already in flight.
            task = asyncio.create_task(consume())
            for _ in range(50):
                if runner_module._sessions[sid].streaming:
                    break
                await asyncio.sleep(0)
            assert runner_module._sessions[sid].streaming is True

            second = await client.get(f"/v1/sessions/{sid}/stdout", headers=AUTH)
            env.backend.finish(cid)
            body = await task
            await _delete(client, sid)
            return second, body

    second, body = asyncio.run(scenario())

    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "session_streaming"
    assert body == FRAME.pack(1, 4) + b"one\n"


def test_backpressure_stops_reading_until_the_consumer_drains(env):
    async def scenario():
        async with _client() as client:
            info = await _open(client, env.root)
            cid = info["container_id"]
            sid = info["session_id"]
            big = b"x" * (runner_module.SESSION_BUFFER_BYTES + 1)
            env.backend.push(cid, 1, big)
            env.backend.push(cid, 1, b"tail\n")
            env.backend.finish(cid)
            for _ in range(5):
                await asyncio.sleep(0)

            session = runner_module._sessions[sid]
            stalled = session.queued_bytes
            counted = session.bytes_out

            async with client.stream(
                "GET", f"/v1/sessions/{sid}/stdout", headers=AUTH
            ) as response:
                body = b"".join([chunk async for chunk in response.aiter_raw()])

            await _delete(client, sid)
            return stalled, counted, body

    stalled, counted, body = asyncio.run(scenario())

    # The oversized first frame fills the buffer; the tail stays unread (and is
    # not counted) until the consumer drains, which is the intended throttle.
    assert stalled == runner_module.SESSION_BUFFER_BYTES + 1
    assert counted == runner_module.SESSION_BUFFER_BYTES + 1
    assert body.startswith(FRAME.pack(1, runner_module.SESSION_BUFFER_BYTES + 1))


# --------------------------------------------------------------------------- #
# lookup / teardown
# --------------------------------------------------------------------------- #


def test_delete_removes_the_container_and_the_session(env):
    async def scenario():
        async with _client() as client:
            info = await _open(client, env.root)
            health_before = (await client.get("/v1/healthz", headers=AUTH)).json()
            deleted = await client.delete(
                f"/v1/sessions/{info['session_id']}", headers=AUTH
            )
            missing = await client.get(
                f"/v1/sessions/{info['session_id']}", headers=AUTH
            )
            health_after = (await client.get("/v1/healthz", headers=AUTH)).json()
            return info, health_before, deleted, missing, health_after

    info, health_before, deleted, missing, health_after = asyncio.run(scenario())

    assert deleted.status_code == 204
    assert info["container_id"] in env.backend.removed
    assert info["container_id"] not in env.backend.containers
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "session_not_found"
    assert health_before["active_sessions"] == 1
    assert health_after["active_sessions"] == 0


def test_unknown_session_routes_return_session_not_found(env):
    async def scenario():
        async with _client() as client:
            stdin = await client.post(
                "/v1/sessions/nope/stdin", content=b"x", headers=AUTH
            )
            close = await client.post("/v1/sessions/nope/close", headers=AUTH)
            stdout = await client.get("/v1/sessions/nope/stdout", headers=AUTH)
            return stdin, close, stdout

    stdin, close, stdout = asyncio.run(scenario())

    for response in (stdin, close, stdout):
        assert response.status_code == 404
        assert response.json()["detail"]["code"] == "session_not_found"


# --------------------------------------------------------------------------- #
# rejection paths
# --------------------------------------------------------------------------- #


def test_unknown_mcp_target_returns_404(env):
    response = asyncio.run(
        _post_open(env.root, target="nope")
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "unknown_target"


def test_non_stdio_mcp_is_not_a_container_target(env):
    response = asyncio.run(_post_open(env.root, target="docs-http"))

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "unknown_target"


@pytest.mark.parametrize("digest", ["deadbeef", ""])
def test_session_digest_mismatch_returns_409(env, digest):
    response = asyncio.run(_post_open(env.root, manifest_digest=digest))

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "manifest_stale"


def test_undeclared_session_env_key_returns_400(env):
    response = asyncio.run(_post_open(env.root, env={"NOT_DECLARED": "x"}))

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["code"] == "invalid_request"
    assert "NOT_DECLARED" in detail["message"]


def test_capacity_is_held_for_the_session_lifetime(env, monkeypatch):
    monkeypatch.setenv("RUNNER_MAX_CONTAINERS_PER_TOOL", "1")

    async def scenario():
        async with _client() as client:
            first = await _open(client, env.root)
            second = await client.post(
                "/v1/sessions", json=_body(env.root), headers=AUTH
            )
            await _delete(client, first["session_id"])
            third = await client.post(
                "/v1/sessions", json=_body(env.root), headers=AUTH
            )
            if third.status_code == 200:
                await _delete(client, third.json()["session_id"])
            return second, third

    second, third = asyncio.run(scenario())

    assert second.status_code == 429
    assert second.json()["detail"]["code"] == "capacity_exhausted"
    # Deleting the holder gave the slot back.
    assert third.status_code == 200


async def _post_open(root, **overrides) -> httpx.Response:
    async with _client() as client:
        return await client.post(
            "/v1/sessions", json=_body(root, **overrides), headers=AUTH
        )


# --------------------------------------------------------------------------- #
# reaping
# --------------------------------------------------------------------------- #


def _leftover(kind: str, install: str = "test-install") -> ContainerSpec:
    return ContainerSpec(
        image="trellis-agent-platform:test",
        runtime="runsc",
        cmd=["python3", "server.py"],
        working_dir="/app/workspace/mcps/stateful",
        env={},
        labels={
            "trellis.install": install,
            "trellis.kind": kind,
            "trellis.target": "stateful",
            "trellis.session": SESSION_KEY,
            "trellis.run": "",
        },
        kind=kind,
    )


def test_startup_reaps_session_and_one_shot_containers(env):
    async def seed():
        session = await env.backend.create(_leftover("mcp_session"))
        discovery = await env.backend.create(_leftover("discovery"))
        tool = await env.backend.create(_leftover("tool"))
        foreign = await env.backend.create(_leftover("mcp_session", install="other"))
        return session, discovery, tool, foreign

    session, discovery, tool, foreign = asyncio.run(seed())

    removed = asyncio.run(runner_module.reap_one_shot(env.backend))

    # Two session kinds + one one-shot kind of this install; the foreign install
    # is not listed by the label filter at all.
    assert removed == 3
    assert {session, discovery, tool} <= set(env.backend.removed)
    assert foreign not in env.backend.removed
    assert foreign in env.backend.containers


def test_expired_session_is_reaped_and_its_container_removed(env):
    async def scenario():
        async with _client() as client:
            info = await _open(client, env.root, deadline_ms=1)
            await asyncio.sleep(0.01)
            removed = await runner_module.reap_sessions(env.backend, grace_s=0)
            missing = await client.get(
                f"/v1/sessions/{info['session_id']}", headers=AUTH
            )
            return info, removed, missing

    info, removed, missing = asyncio.run(scenario())

    assert removed >= 1
    assert info["container_id"] in env.backend.removed
    assert missing.status_code == 404


def test_stray_session_container_is_reaped_even_if_the_registry_is_empty(env):
    async def seed():
        stuck = await env.backend.create(_leftover("discovery"))
        healthy_tool = await env.backend.create(_leftover("tool"))
        return stuck, healthy_tool

    stuck, healthy_tool = asyncio.run(seed())

    removed = asyncio.run(runner_module.reap_sessions(env.backend, grace_s=0))

    assert removed == 1
    assert env.backend.removed == [stuck]
    assert healthy_tool in env.backend.containers


# --------------------------------------------------------------------------- #
# /v1/exec gains kind="console"
# --------------------------------------------------------------------------- #


def _console_body(**overrides) -> dict:
    body = {
        "kind": "console",
        "target": "console",
        "command": "echo hi",
        "env": {},
        "deadline_ms": 5000,
        "agent_token": _token(),
    }
    body.update(overrides)
    return body


def test_console_exec_runs_in_a_scratch_container(env):
    env.backend.queue(RawExec(exit_code=0, stdout=b"hi\n"))

    async def scenario():
        async with _client() as client:
            return await client.post(
                "/v1/exec", json=_console_body(), headers=AUTH
            )

    response = asyncio.run(scenario())

    assert response.status_code == 200
    assert response.json()["stdout"] == "hi\n"

    container_spec = env.backend.specs[-1]
    assert container_spec.kind == "console"
    assert container_spec.network_mode == "none"
    assert container_spec.mounts == []
    assert container_spec.cmd == ["bash", "-lc", "echo hi"]
    assert container_spec.env["TRELLIS_USER_ID"] == "u-1"
    assert container_spec.env["TRELLIS_USER_EMAIL"] == "u@example.test"


def test_console_exec_without_a_command_is_invalid(env):
    async def scenario():
        async with _client() as client:
            return await client.post(
                "/v1/exec", json=_console_body(command="  "), headers=AUTH
            )

    response = asyncio.run(scenario())

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_request"


def test_exec_rejects_session_kinds(env):
    async def scenario():
        async with _client() as client:
            return await client.post(
                "/v1/exec",
                json={"kind": "mcp_session", "target": "stateful"},
                headers=AUTH,
            )

    response = asyncio.run(scenario())

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_request"
