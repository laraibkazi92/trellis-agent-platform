# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Runner HTTP surface: auth, target resolution, digest, capacity, canary, errors.

Everything runs against ``FakeBackend`` (no Docker daemon, no runsc). The assertions
that matter are the ``ContainerSpec`` the runner derives from the on-disk manifest and
the HTTP codes the hub branches on.
"""

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest
import yaml

from core import agent_token
from core.execution import backend as backend_module
from core.execution import canary as canary_module
from core.execution import runner as runner_module
from core.execution.backend import BackendError
from core.execution.spec import DEFAULT_NETWORK_MODE, manifest_digest
from core.models import ToolConfig
from fixtures.fake_backend import FakeBackend, RawExec

AUTH = {"authorization": "Bearer test-token"}
SECRET = "runner-api-unit-secret-0123456789abcdef"


def _token(agent="demo-assistant", run_id="run-1", user_id="u-1"):
    """The run's token: the runner's ONLY identity source."""
    return agent_token.mint(
        agent, user_id=user_id, user_email="u@example.test", run_id=run_id
    )

TOOL_YAML = """\
- name: echo
  description: Echo a block of text back.
  runtime: python
  entrypoint: echo.py
  secrets:
    - ECHO_TOKEN
  output_dirs:
    - reports
  network: none
"""

REMOTE_YAML = """\
- name: dc1__node_ssh
  description: Edge-hosted SSH tool.
  runtime: remote
  remote:
    site: dc1
    tool: node_ssh
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    suite = root / "tools" / "echo"
    suite.mkdir(parents=True)
    (suite / "echo.py").write_text("print('hi')\n", encoding="utf-8")
    (suite / "tool.yaml").write_text(TOOL_YAML, encoding="utf-8")
    (root / "shared").mkdir()

    monkeypatch.setenv("WORKSPACE_ROOT", str(root))
    # Deliberately different from the runner's view: conflating the two is the
    # exact bug the canary exists to catch.
    monkeypatch.setenv("TRELLIS_HOST_WORKSPACE", f"/host{root}")
    monkeypatch.setenv("RUNNER_TOKEN", "test-token")
    monkeypatch.setenv("RUNNER_IMAGE", "trellis-agent-platform:test")
    monkeypatch.setenv("CONTAINER_DEFAULT_RUNTIME", "runsc")
    monkeypatch.setenv("RUNNER_MAX_CONTAINERS_PER_TOOL", "8")
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


def _digest(root) -> str:
    raw = yaml.safe_load((root / "tools" / "echo" / "tool.yaml").read_text())
    return manifest_digest(ToolConfig(**raw[0]))


def _body(root, **overrides) -> dict:
    # No identity in the body: agent/run/user/email come from the token's claims.
    body = {
        "kind": "tool",
        "target": "echo",
        "manifest_digest": _digest(root),
        "agent_token": _token(),
        "env": {"ECHO_TOKEN": "s3cret"},
        "input": '{"text":"hi"}',
        "deadline_ms": 5000,
    }
    body.update(overrides)
    return body


async def _call(method: str, path: str, *, json_body=None, headers=None):
    transport = httpx.ASGITransport(app=runner_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://runner") as client:
        return await client.request(
            method, path, json=json_body, headers=AUTH if headers is None else headers
        )


def test_tool_call_returns_result_and_derives_spec(env):
    env.backend.queue(RawExec(exit_code=0, stdout=b'{"ok": true}\n'))

    response = asyncio.run(_call("POST", "/v1/exec", json_body=_body(env.root)))

    assert response.status_code == 200
    payload = response.json()
    assert payload["exit_code"] == 0
    assert payload["stdout"] == '{"ok": true}\n'
    assert payload["stderr"] == ""

    container_spec = env.backend.specs[0]
    assert [mount.target for mount in container_spec.mounts] == [
        "/app/workspace/tools/echo",
        "/app/workspace/shared",
        "/app/workspace/reports/demo-assistant",
    ]
    assert [mount.read_only for mount in container_spec.mounts] == [True, True, False]
    assert container_spec.mounts[0].source == f"/host{env.suite}"
    assert container_spec.mounts[2].source == f"/host{env.root}/reports/demo-assistant"
    assert (env.root / "reports" / "demo-assistant").is_dir()

    assert container_spec.working_dir == "/app/workspace/tools/echo"
    assert container_spec.runtime == "runsc"
    assert container_spec.image == "trellis-agent-platform:test"
    assert container_spec.network_mode == "none"
    assert container_spec.kind == "tool"
    assert container_spec.labels["trellis.kind"] == "tool"
    assert container_spec.labels["trellis.target"] == "echo"
    assert container_spec.labels["trellis.run"] == "run-1"
    assert container_spec.env["HOME"] == "/tmp"
    # The declared token is a secret: it is NOT container configuration, it is on
    # stdin (the trellis-exec preamble), and the trailing payload follows it.
    assert "ECHO_TOKEN" not in container_spec.env
    assert container_spec.preamble_env["ECHO_TOKEN"] == "s3cret"
    stdin = env.backend.stdin[0][1]
    first, _, payload = stdin.partition(b"\n")
    assert json.loads(first)["env"]["ECHO_TOKEN"] == "s3cret"
    assert payload == b'{"text":"hi"}'


def test_unknown_target_returns_404(env):
    response = asyncio.run(
        _call("POST", "/v1/exec", json_body=_body(env.root, target="nope"))
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "unknown_target"


def test_remote_tool_is_not_a_local_target(env):
    edge = env.root / "tools" / "edge"
    edge.mkdir()
    (edge / "tool.yaml").write_text(REMOTE_YAML, encoding="utf-8")

    response = asyncio.run(
        _call("POST", "/v1/exec", json_body=_body(env.root, target="dc1__node_ssh"))
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "unknown_target"


@pytest.mark.parametrize("digest", ["deadbeef", ""])
def test_digest_mismatch_returns_409(env, digest):
    response = asyncio.run(
        _call("POST", "/v1/exec", json_body=_body(env.root, manifest_digest=digest))
    )

    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "manifest_stale"
    assert detail["retryable"] is False


def test_undeclared_env_key_returns_400(env):
    response = asyncio.run(
        _call("POST", "/v1/exec", json_body=_body(env.root, env={"NOT_DECLARED": "x"}))
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["code"] == "invalid_request"
    assert "NOT_DECLARED" in detail["message"]


def test_missing_bearer_returns_401(env):
    response = asyncio.run(
        _call("POST", "/v1/exec", json_body=_body(env.root), headers={})
    )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "unauthorized"


def test_capacity_exhausted_is_retryable_429(env, monkeypatch):
    monkeypatch.setenv("RUNNER_MAX_CONTAINERS_PER_TOOL", "1")

    async def scenario():
        transport = httpx.ASGITransport(app=runner_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://runner") as client:
            semaphore = runner_module._target_semaphore("echo")
            await semaphore.acquire()
            try:
                return await client.post(
                    "/v1/exec", json=_body(env.root), headers=AUTH
                )
            finally:
                semaphore.release()

    response = asyncio.run(scenario())

    assert response.status_code == 429
    detail = response.json()["detail"]
    assert detail["code"] == "capacity_exhausted"
    assert detail["retryable"] is True


def test_preflight_fails_closed_without_the_configured_runtime(env):
    env.backend.runtimes = {"runc"}

    checks = asyncio.run(runner_module.run_preflight(env.backend))
    runtime_check = next(check for check in checks if check.name == "runtime")

    assert runtime_check.ok is False
    assert "runsc" in runtime_check.message
    assert "CONTAINER_DEFAULT_RUNTIME" in runtime_check.message
    assert runner_module.startup_ready(checks) is False

    with pytest.raises(SystemExit):
        asyncio.run(runner_module.startup(env.backend))


def test_runc_is_a_legitimate_runtime(env, monkeypatch):
    """A dev machine (or a per-tool choice) may run on runc -- it is not an error."""
    monkeypatch.setenv("CONTAINER_DEFAULT_RUNTIME", "runc")
    env.backend.runtimes = {"runc"}

    checks = asyncio.run(runner_module.run_preflight(env.backend))
    runtime_check = next(check for check in checks if check.name == "runtime")

    assert runtime_check.ok is True
    assert "runc" in runtime_check.message
    assert "syscall isolation" in runtime_check.message


def test_preflight_checks_exactly_the_startup_gates(env):
    """runtime, image, tool identity and manifest runtimes -- nothing network-bound."""
    checks = asyncio.run(runner_module.run_preflight(env.backend))

    assert [check.name for check in checks] == [
        "runtime",
        "image",
        "tool_identity",
        "manifest_runtimes",
    ]
    assert runner_module.startup_ready(checks) is True


def test_preflight_fails_closed_on_an_unregistered_manifest_runtime(env):
    """A tool pinning ``container_runtime: runc`` cannot start on a runsc-only host."""
    (env.root / "tools" / "echo" / "tool.yaml").write_text(
        TOOL_YAML.replace("network: none", "network: none\n  container_runtime: runc"),
        encoding="utf-8",
    )
    env.backend.runtimes = {"runsc"}

    checks = asyncio.run(runner_module.run_preflight(env.backend))
    manifest_check = next(check for check in checks if check.name == "manifest_runtimes")

    assert manifest_check.ok is False
    assert "runc" in manifest_check.message
    assert "echo" in manifest_check.message
    assert runner_module.startup_ready(checks) is False


def test_failed_canary_refuses_exec(env):
    env.backend.queue(RawExec(exit_code=0, stdout=b"wrong-bytes"))

    result = asyncio.run(runner_module.recheck_canary(env.backend))

    assert result.ok is False
    assert "TRELLIS_HOST_WORKSPACE" in result.detail

    response = asyncio.run(_call("POST", "/v1/exec", json_body=_body(env.root)))

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["code"] == "runner_path_mismatch"
    assert detail["retryable"] is False
    # The refusal happened before a tool container was even asked for.
    assert all(container.kind == "canary" for container in env.backend.specs)


def test_canary_round_trip_cleans_up(env, monkeypatch):
    monkeypatch.setattr(canary_module.secrets, "token_bytes", lambda _n: b"canary-payload")
    env.backend.queue(RawExec(exit_code=0, stdout=b"canary-payload"))

    result = asyncio.run(runner_module.recheck_canary(env.backend))

    assert result.ok is True
    canary_spec = env.backend.specs[0]
    assert canary_spec.kind == "canary"
    assert canary_spec.network_mode == "none"
    assert canary_spec.mounts[0].target == "/canary"
    assert canary_spec.mounts[0].source == f"/host{env.root}"
    assert not list(env.root.glob(".runner-canary-*"))


def test_backend_timeout_maps_to_504(env):
    env.backend.fail_run = BackendError("timeout", "container exceeded its deadline")

    response = asyncio.run(_call("POST", "/v1/exec", json_body=_body(env.root)))

    assert response.status_code == 504
    detail = response.json()["detail"]
    assert detail["code"] == "timeout"
    assert detail["retryable"] is False


# --- authorization: the token, and nothing else ------------------------------
#
# v0.7.1 Phase 4: the runner verifies signature and expiry and then runs. It has no
# registry and no agent manifests, so it cannot resolve an allowlist, and every
# decision is made before the request arrives: the hub authorizes tool calls, and the
# process that owns the agent runtime authorizes console/MCP sessions
# (`core.tool_gate`, checked in tests/test_enforcement_matrix.py). The one agent-free
# kind remains a throwaway discovery read, gated by the control socket's bearer token.


def _console_body(token):
    return {
        "kind": "console",
        "target": "console",
        "command": "echo hi",
        "agent_token": token,
    }


@pytest.mark.parametrize("agent", ["gateway", "supervisor", "agent-a", "ghost"])
@pytest.mark.parametrize("kind", ["console", "tool"])
def test_the_runner_does_not_rederive_an_allowlist(env, monkeypatch, agent, kind):
    """A valid token is the whole gate, whatever the agent and whatever the target.

    The old runner check re-read a workspace manifest and denied every caller whose
    manifest was not on disk (the gateway has none, the supervisor's ships in the
    image). That decision now belongs to the caller (``core.tool_gate``), so the
    runner must not refuse a call it cannot judge.
    """
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    env.backend.queue(RawExec(exit_code=0, stdout=b'{"ok": true}\n'))
    token = agent_token.mint(agent, user_id="u-1")
    body = (
        _console_body(token)
        if kind == "console"
        else _body(env.root, agent_token=token)
    )

    response = asyncio.run(_call("POST", "/v1/exec", json_body=body))

    assert response.status_code == 200, response.json()
    assert len(env.backend.specs) == 1


def test_runner_authorization_no_longer_reads_a_knob(monkeypatch):
    """`RUNNER_AUTHORIZATION` is gone: the runner has one behaviour."""
    from core.execution import runner as runner_module

    assert not hasattr(runner_module, "_agent_manifest")
    assert not hasattr(runner_module, "_RUNNER_OWNED_KINDS")


def test_a_session_with_a_valid_token_is_authorized(env, monkeypatch):
    """The session's authorization happened in the caller; the runner only verifies.

    The target does not exist in this fixture, so the request stops at the manifest
    lookup -- past authorization, which is what this pins.
    """
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    body = {
        "kind": "mcp_session",
        "target": "coralogix",
        "session_key": "a" * 32,
        "agent_token": agent_token.mint("supervisor", user_id="u-1"),
    }

    response = asyncio.run(_call("POST", "/v1/sessions", json_body=body))

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "unknown_target"


def test_a_session_without_a_token_is_refused(env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    body = {"kind": "mcp_session", "target": "coralogix", "session_key": "a" * 32}

    response = asyncio.run(_call("POST", "/v1/sessions", json_body=body))

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "access_denied"


def test_a_leftover_workflow_container_is_reaped_like_any_one_shot(env):
    """A SIGKILLed runner leaves one-shot containers behind: workflows included."""
    from core.execution.spec import ContainerSpec

    def leftover(kind: str, install: str = "default") -> ContainerSpec:
        return ContainerSpec(
            image="trellis-agent-platform:test",
            runtime="runsc",
            cmd=["python3", "/app/workspace/workflows/demo-inventory/pipeline.py"],
            working_dir="/app/workspace/workflows/demo-inventory",
            env={},
            labels={"trellis.install": install, "trellis.kind": kind},
            kind=kind,
        )

    async def seed():
        workflow = await env.backend.create(leftover("workflow"))
        tool = await env.backend.create(leftover("tool"))
        foreign = await env.backend.create(leftover("workflow", install="other"))
        return workflow, tool, foreign

    workflow, tool, foreign = asyncio.run(seed())

    removed = asyncio.run(runner_module.reap_one_shot(env.backend))

    assert removed == 2
    assert {workflow, tool} <= set(env.backend.removed)
    assert foreign not in env.backend.removed


def test_a_workflow_run_is_a_first_class_exec_kind(env):
    """``kind='workflow'`` runs one pipeline container (matrix: test_workflow_container)."""
    workflow = env.root / "workflows" / "demo-inventory"
    workflow.mkdir(parents=True)
    (workflow / "pipeline.py").write_text("print('{}')\n", encoding="utf-8")
    env.backend.queue(RawExec(exit_code=0, stdout=b"done\n"))

    body = {
        "kind": "workflow",
        "target": "demo-inventory",
        "entrypoint": "pipeline.py",
        "input": "inventory",
        "deadline_ms": 5000,
        "agent_token": _token("demo-inventory"),
    }
    response = asyncio.run(_call("POST", "/v1/exec", json_body=body))

    assert response.status_code == 200, response.json()
    assert response.json()["stdout"] == "done\n"
    container_spec = env.backend.specs[0]
    assert container_spec.kind == "workflow"
    assert container_spec.working_dir == "/app/workspace/workflows/demo-inventory"
    assert container_spec.mounts[0].source == f"/host{workflow}"
    # Egress unless the workflow asks for `none` -- Docker's own default.
    assert container_spec.network_mode == DEFAULT_NETWORK_MODE
    assert container_spec.env["TRELLIS_RUN_ID"] == "run-1"
    first, _, payload = env.backend.stdin[0][1].partition(b"\n")
    assert json.loads(first)["env"] == {}
    assert payload == b"inventory"


def test_the_wire_contract_refuses_an_unrecognized_exec_kind(env, monkeypatch):
    """``ExecKind`` is a closed Literal, so an unknown kind cannot reach the runner at
    all; if one ever does (a future kind added to the contract), ``_authorize`` denies
    it -- see ``tests/test_enforcement_matrix.py``. ``workflow`` is a *known* kind
    since v0.7.1 Phase 6 (``tests/test_workflow_container.py``)."""
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")

    response = asyncio.run(
        _call(
            "POST",
            "/v1/exec",
            json_body=_body(env.root, kind="batch", agent_token=_token("supervisor")),
        )
    )

    assert response.status_code == 422
    assert env.backend.specs == []


def test_a_discovery_read_is_gated_by_the_socket_token_alone(env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    body = {"kind": "discovery", "target": "catalog", "session_key": "a" * 32}

    # Past authorization (no agent record involved); the target does not exist here.
    authorized = asyncio.run(_call("POST", "/v1/sessions", json_body=body))
    assert authorized.status_code == 404
    assert authorized.json()["detail"]["code"] == "unknown_target"

    # The socket bearer token is the gate on that path.
    unauthenticated = asyncio.run(
        _call("POST", "/v1/sessions", json_body=body, headers={})
    )
    assert unauthenticated.status_code == 401


def test_preflight_endpoint_reports_ok_health(env, monkeypatch):

    monkeypatch.setattr(canary_module.secrets, "token_bytes", lambda _n: b"canary-payload")
    env.backend.queue(RawExec(exit_code=0, stdout=b"canary-payload"))

    response = asyncio.run(_call("POST", "/v1/preflight"))
    assert response.status_code == 200
    assert response.json()["ok"] is True

    health = asyncio.run(_call("GET", "/v1/healthz"))
    assert health.status_code == 200
    payload = health.json()
    assert payload["ok"] is True
    assert payload["runtime"] == "runsc"
    assert payload["image"] == "trellis-agent-platform:test"


def test_socket_permissions_land_on_the_rebound_socket(monkeypatch, tmp_path):
    """After a restart the socket volume still holds the old process's file.

    ``_serve`` must wait for uvicorn to rebind (``server.started``) before it
    chmod/chowns, or the permissions land on the stale inode and the new socket
    stays root-owned: every app-uid caller gets EACCES while the in-container
    healthcheck (root) keeps reporting healthy.
    """
    import os
    from pathlib import Path

    path = tmp_path / "runner.sock"
    path.write_text("")  # stale socket left by the previous process
    stale_inode = path.stat().st_ino
    fixed: list[int] = []
    release = asyncio.Event()

    class FakeConfig:
        def __init__(self, **kwargs):
            self.uds = kwargs["uds"]

    class FakeServer:
        def __init__(self, config):
            self.config = config
            self.started = False

        async def serve(self):
            # uvicorn unlinks and rebinds: the inode changes.
            if os.path.exists(self.config.uds):
                os.unlink(self.config.uds)
            Path(self.config.uds).write_text("")
            self.started = True
            await release.wait()

    monkeypatch.setattr(runner_module, "socket_path", lambda: str(path))
    monkeypatch.setattr(runner_module.uvicorn, "Config", FakeConfig)
    monkeypatch.setattr(runner_module.uvicorn, "Server", FakeServer)
    def fake_fix(target):
        fixed.append(Path(target).stat().st_ino)
        release.set()

    monkeypatch.setattr(runner_module, "_fix_socket_permissions", fake_fix)

    asyncio.run(runner_module._serve())

    assert fixed == [path.stat().st_ino]
    assert fixed[0] != stale_inode
