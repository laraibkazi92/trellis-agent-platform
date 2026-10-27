# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""``background_script`` workflows as ONE sandboxed runner container.

A workflow used to be an ordinary subprocess in the taskiq worker: whole workspace
mounted, engine network reachable, no isolation at all. It is now one container per
run, and the only enforcement it has is its filesystem -- an undeclared tool is not
mounted, and nothing outside the workflow's own tree, ``shared/``, ``output/``,
``reports/`` and ``/tmp`` exists. These tests pin that mount matrix, the working
directory, the network mapping, the environment split and the lifecycle.

No Docker daemon and no runsc: the spec is plain data, the one-shot path is driven
through ``FakeBackend``, and the create body is the Docker payload builder itself.
"""

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest
import yaml

from core import agent_token
from core.execution import backend as backend_module
from core.execution import runner as runner_module
from core.execution.backend import BackendError
from core.execution.docker_backend import DockerBackend, _create_payload
from core.execution.env import CONTAINER_ENV_ALLOWLIST, EXEC_SHIM
from core.execution.spec import (
    CONTAINER_TMP,
    CONTAINER_WORKSPACE,
    DEFAULT_NETWORK_MODE,
    InvalidRequest,
    build_workflow_spec,
    workflow_network_mode,
)
from core.models import (
    ContainerLimits,
    ToolConfig,
    reset_network_policy_warnings,
    workflow_limits,
)
from fixtures.fake_backend import FakeBackend, RawExec

AUTH = {"authorization": "Bearer test-token"}
SECRET = "workflow-container-unit-secret-0123456789"
WORKFLOW = "demo-inventory"

REPORT_TOOL = """\
- name: make_report
  description: Write a report into reports/<agent>/.
  runtime: python
  entrypoint: make_report.py
  output_dirs:
    - reports
"""

OTHER_TOOL = """\
- name: side_effect
  description: A tool this workflow never declared.
  runtime: python
  entrypoint: side_effect.py
"""


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A workspace shaped like the real one: one workflow, two tool suites."""
    root = tmp_path / "workspace"
    wf = root / "workflows" / WORKFLOW
    wf.mkdir(parents=True)
    (wf / "pipeline.py").write_text("print('{}')\n", encoding="utf-8")
    (root / "shared").mkdir()

    for suite, tool, manifest in (
        ("reporting", "make_report", REPORT_TOOL),
        ("other", "side_effect", OTHER_TOOL),
    ):
        suite_dir = root / "tools" / suite
        suite_dir.mkdir(parents=True)
        (suite_dir / f"{tool}.py").write_text("print('{}')\n", encoding="utf-8")
        (suite_dir / "tool.yaml").write_text(manifest, encoding="utf-8")

    monkeypatch.setenv("WORKSPACE_ROOT", str(root))
    # Deliberately different from the runner's view: conflating the two is what the
    # host-path canary exists to catch, and a workflow mount must use the host path.
    monkeypatch.setenv("TRELLIS_HOST_WORKSPACE", f"/host{root}")
    monkeypatch.setenv("RUNNER_TOKEN", "test-token")
    monkeypatch.setenv("RUNNER_IMAGE", "trellis-agent-platform:test")
    monkeypatch.setenv("CONTAINER_DEFAULT_RUNTIME", "runsc")
    monkeypatch.setenv("TRELLIS_INSTALL_ID", "test-install")
    monkeypatch.setenv("TRELLIS_UID", "1000")
    monkeypatch.setenv("TRELLIS_GID", "1000")
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.delenv("ENFORCE_AGENT_TOKENS", raising=False)
    reset_network_policy_warnings()
    return SimpleNamespace(root=root, workflow=wf)


def build(workspace, **overrides):
    kwargs = dict(
        name=WORKFLOW,
        entrypoint="pipeline.py",
        env={},
        host_workspace=str(workspace.root),
        workspace_root=str(workspace.root),
        run_id="run-1",
        user_id="svc_agent_demo-inventory",
    )
    kwargs.update(overrides)
    return build_workflow_spec(**kwargs)


# --------------------------------------------------------------------------- #
# the mount matrix -- this IS the workflow's enforcement
# --------------------------------------------------------------------------- #


def test_only_read_paths_are_mounted_and_the_matrix_matches_the_old_layout(workspace):
    spec = build(workspace, tool_suites=["reporting"])

    assert [(mount.target, mount.read_only) for mount in spec.mounts] == [
        (f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}", True),
        (f"{CONTAINER_WORKSPACE}/shared", True),
        (f"{CONTAINER_WORKSPACE}/tools/reporting", True),
        (f"{CONTAINER_WORKSPACE}/reports/{WORKFLOW}", False),
        (f"{CONTAINER_WORKSPACE}/output/{WORKFLOW}", False),
    ]
    # Spec-level tests model a runner whose host view and own view are the same
    # path; the runner's real split is pinned through /v1/exec below.
    assert [mount.source for mount in spec.mounts] == [
        f"{workspace.root}/workflows/{WORKFLOW}",
        f"{workspace.root}/shared",
        f"{workspace.root}/tools/reporting",
        f"{workspace.root}/reports/{WORKFLOW}",
        f"{workspace.root}/output/{WORKFLOW}",
    ]


def test_a_tool_suite_the_workflow_did_not_declare_is_not_on_the_filesystem(workspace):
    spec = build(workspace, tool_suites=["reporting"])

    targets = " ".join(mount.target for mount in spec.mounts)
    sources = " ".join(mount.source for mount in spec.mounts)
    assert "tools/other" not in targets
    assert "tools/other" not in sources
    assert "make_report" not in targets
    # Nothing else either: no other workflow, no tool registry, no env file.
    for forbidden in ("agents", "mcps", "policies", "routing_rules", ".env", "data"):
        assert forbidden not in targets
        assert forbidden not in sources


def test_no_tool_suites_means_no_tool_mounts_at_all(workspace):
    spec = build(workspace)

    assert [mount.target for mount in spec.mounts] == [
        f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}",
        f"{CONTAINER_WORKSPACE}/shared",
        f"{CONTAINER_WORKSPACE}/reports/{WORKFLOW}",
        f"{CONTAINER_WORKSPACE}/output/{WORKFLOW}",
    ]


def test_a_repeated_suite_is_mounted_once(workspace):
    spec = build(workspace, tool_suites=["reporting", "reporting"])

    targets = [mount.target for mount in spec.mounts]
    assert targets.count(f"{CONTAINER_WORKSPACE}/tools/reporting") == 1


def test_output_and_reports_are_created_for_the_workflow(workspace):
    build(workspace)

    assert (workspace.root / "reports" / WORKFLOW).is_dir()
    assert (workspace.root / "output" / WORKFLOW).is_dir()


def test_shared_is_skipped_when_it_does_not_exist(workspace):
    (workspace.root / "shared").rmdir()

    spec = build(workspace)

    assert all("shared" not in mount.target for mount in spec.mounts)


def test_tmp_is_the_only_scratch_space(workspace):
    spec = build(workspace)

    assert list(spec.tmpfs) == [CONTAINER_TMP]
    # tmpfs is charged to the cgroup, so it must stay under the memory limit.
    assert spec.tmpfs[CONTAINER_TMP] * 2 <= spec.memory_mb


def test_the_workflow_directory_is_the_working_directory(workspace):
    """Existing pipelines use relative paths -- cwd must be their own tree."""
    spec = build(workspace)

    assert spec.working_dir == f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}"
    assert spec.working_dir == spec.mounts[0].target


# --------------------------------------------------------------------------- #
# what runs
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "runtime,prefix",
    [("python", ["python3"]), ("node", ["node"]), ("bash", ["bash"]), ("exec", [])],
)
def test_the_entrypoint_runs_under_its_declared_runtime(workspace, runtime, prefix):
    spec = build(workspace, runtime=runtime)

    assert spec.cmd == [
        *prefix,
        f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}/pipeline.py",
    ]


def test_python_is_the_default_runtime_and_args_are_appended(workspace):
    spec = build(workspace, args=["--mode", "daily"])

    assert spec.cmd == [
        "python3",
        f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}/pipeline.py",
        "--mode",
        "daily",
    ]


def test_the_container_is_a_workflow_one_shot(workspace):
    spec = build(workspace)

    assert spec.kind == "workflow"
    assert spec.labels["trellis.kind"] == "workflow"
    assert spec.labels["trellis.target"] == WORKFLOW
    assert spec.labels["trellis.run"] == "run-1"
    assert spec.labels["trellis.install"] == "test-install"


def test_a_missing_entrypoint_is_refused_before_a_container_exists(workspace):
    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, entrypoint="nope.py")

    assert "nope.py" in excinfo.value.message


@pytest.mark.parametrize("entrypoint", ["/etc/passwd", "../shared/x.py", "a/../../x.py"])
def test_the_entrypoint_must_stay_inside_the_workflow_directory(workspace, entrypoint):
    with pytest.raises(InvalidRequest):
        build(workspace, entrypoint=entrypoint)


def test_the_workflow_name_cannot_escape_the_workspace(workspace):
    with pytest.raises(InvalidRequest):
        build(workspace, name="../../etc")


def test_a_symlinked_workflow_directory_is_refused(workspace, tmp_path):
    """A plain relative path is not enough: the bind source must really be inside.

    ``workspace/workflows/<name> -> /etc`` passes the string check and would hand the
    container a directory the workspace never contained (Docker follows the source).
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "pipeline.py").write_text("print('{}')\n", encoding="utf-8")
    linked = workspace.root / "workflows" / "linked"
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, name="linked")

    assert "outside the workspace" in excinfo.value.message


def test_a_symlinked_tool_suite_is_refused(workspace, tmp_path):
    outside = tmp_path / "outside-suite"
    outside.mkdir()
    (workspace.root / "tools" / "linked-suite").symlink_to(
        outside, target_is_directory=True
    )

    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, tool_suites=["linked-suite"])

    assert "outside the workspace" in excinfo.value.message


def test_a_symlinked_shared_directory_is_refused(workspace, tmp_path):
    """``shared/`` bypasses the generic mount helper for nothing: same rule."""
    (workspace.root / "shared").rmdir()
    outside = tmp_path / "outside-shared"
    outside.mkdir()
    (workspace.root / "shared").symlink_to(outside, target_is_directory=True)

    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace)

    assert "outside the workspace" in excinfo.value.message


def test_a_symlink_inside_a_mounted_tree_is_not_a_mount_source(workspace, tmp_path):
    """Only the mount SOURCE is checked; a symlink beneath it stays a container concern.

    ``workflows/<name>/data -> /etc`` is a path the pipeline can already reach with or
    without the guard, and refusing it here would break legitimate pipelines.
    """
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (workspace.workflow / "data").symlink_to(outside, target_is_directory=True)

    spec = build(workspace, tool_suites=["reporting"])

    assert spec.mounts[0].source == str(workspace.root / "workflows" / WORKFLOW)
    assert f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}" in {
        mount.target for mount in spec.mounts
    }


def test_an_unknown_runtime_is_refused(workspace):
    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, runtime="ruby")

    assert "ruby" in excinfo.value.message


# --------------------------------------------------------------------------- #
# network
# --------------------------------------------------------------------------- #


def test_network_defaults_to_egress(workspace):
    """v0.7.1 flipped tools/MCP/workflows from ``none`` to ordinary egress."""
    spec = build(workspace)

    assert spec.network_mode == DEFAULT_NETWORK_MODE
    assert workflow_network_mode(None) == DEFAULT_NETWORK_MODE
    assert workflow_network_mode("egress") == DEFAULT_NETWORK_MODE


def test_network_none_is_honoured(workspace):
    spec = build(workspace, network="none")

    assert spec.network_mode == "none"


# --------------------------------------------------------------------------- #
# environment: declared values never reach the create body
# --------------------------------------------------------------------------- #


def test_a_declared_secret_rides_the_preamble_and_identity_stays_in_config(workspace):
    spec = build(workspace, env={"REPORTS_TOKEN": "s3cret", "REPORT_REGION": "eu"})

    assert spec.env["TRELLIS_RUN_ID"] == "run-1"
    assert spec.env["TRELLIS_USER_ID"] == "svc_agent_demo-inventory"
    assert spec.env["HOME"] == CONTAINER_TMP
    assert "REPORTS_TOKEN" not in spec.env
    assert "REPORT_REGION" not in spec.env
    assert spec.preamble_env["REPORTS_TOKEN"] == "s3cret"
    assert spec.preamble_env["REPORT_REGION"] == "eu"
    # Everything in the container configuration is on the allowlist by construction.
    assert set(spec.env) <= CONTAINER_ENV_ALLOWLIST


def test_an_empty_email_is_not_invented(workspace):
    """A workflow is a service identity: minted without an email, so no env var."""
    spec = build(workspace)

    assert "TRELLIS_USER_EMAIL" not in spec.env
    assert "TRELLIS_USER_EMAIL" not in spec.preamble_env


def test_the_pipeline_is_told_where_it_may_write(workspace):
    """v0.7.2 R2: both rw mounts, by their in-container path, in the config env.

    A pipeline must not have to hard-code ``reports/<name>``: the runner created the
    mounts, so it is the only party that knows the path.
    """
    spec = build(workspace)

    assert spec.env["TRELLIS_REPORTS_DIR"] == f"{CONTAINER_WORKSPACE}/reports/{WORKFLOW}"
    assert spec.env["TRELLIS_OUTPUT_DIR"] == f"{CONTAINER_WORKSPACE}/output/{WORKFLOW}"
    rw_targets = {mount.target for mount in spec.mounts if not mount.read_only}
    assert {
        spec.env["TRELLIS_REPORTS_DIR"],
        spec.env["TRELLIS_OUTPUT_DIR"],
    } == rw_targets
    # Not on stdin: the create body carries them, so the pipeline sees them before
    # it reads anything (subprocesses inherit them too).
    payload = _create_payload(spec)
    for name in ("TRELLIS_REPORTS_DIR", "TRELLIS_OUTPUT_DIR"):
        assert f"{name}={spec.env[name]}" in payload["Env"]
        assert name not in spec.preamble_env


def test_a_caller_cannot_redirect_the_workflow_output_dirs(workspace):
    """The dirs are set after the caller's values, so they cannot be replaced."""
    spec = build(
        workspace, env={"TRELLIS_REPORTS_DIR": "/etc", "TRELLIS_OUTPUT_DIR": "/etc"}
    )

    assert spec.env["TRELLIS_REPORTS_DIR"] == f"{CONTAINER_WORKSPACE}/reports/{WORKFLOW}"
    assert spec.env["TRELLIS_OUTPUT_DIR"] == f"{CONTAINER_WORKSPACE}/output/{WORKFLOW}"


def test_the_workflow_name_is_derived_not_taken_from_the_caller(workspace):
    """``TRELLIS_AGENT_NAME`` is the validated pipeline directory, not caller input.

    ``core.tasks`` sends the same value today, but the ground truth is the workflow
    name ``build_workflow_spec`` already validated: a caller that sends nothing (or
    something else) must not be able to rename the pipeline's run context.
    """
    spec = build(workspace, env={"TRELLIS_AGENT_NAME": "someone-else"})

    assert spec.env["TRELLIS_AGENT_NAME"] == WORKFLOW
    # Even with no caller value at all.
    assert build(workspace).env["TRELLIS_AGENT_NAME"] == WORKFLOW
    # The unmounted-dirs case does not exist for a workflow: both dirs are always
    # created, so both variables are always present.
    assert spec.env["TRELLIS_REPORTS_DIR"] == f"{CONTAINER_WORKSPACE}/reports/{WORKFLOW}"


def test_a_reserved_control_plane_name_is_refused(workspace):
    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, env={"RUNNER_TOKEN": "x"})

    assert "RUNNER_TOKEN" in excinfo.value.message


def test_a_name_no_environment_can_carry_is_refused(workspace):
    with pytest.raises(InvalidRequest):
        build(workspace, env={"report-token": "x"})


# --------------------------------------------------------------------------- #
# limits
# --------------------------------------------------------------------------- #


def test_default_limits_are_larger_than_a_single_tool(workspace):
    spec = build(workspace)
    tool = ContainerLimits()

    assert (spec.memory_mb, spec.cpus, spec.pids) == (4096, 2.0, 1024)
    assert spec.memory_mb > tool.memory_mb
    assert spec.pids > tool.pids
    assert spec.tmpfs[CONTAINER_TMP] > 128
    # The documented defaults and the ones a workflow container gets agree.
    defaults = workflow_limits()
    assert spec.memory_mb == defaults.memory_mb
    assert spec.pids == defaults.pids
    assert spec.tmpfs[CONTAINER_TMP] == defaults.tmpfs_mb


def test_a_partial_override_keeps_the_other_workflow_defaults(workspace):
    spec = build(workspace, limits={"memory_mb": 8192})

    assert spec.memory_mb == 8192
    assert spec.cpus == 2.0
    assert spec.pids == 1024
    assert spec.tmpfs[CONTAINER_TMP] == 1024


def test_an_impossible_override_is_refused(workspace):
    with pytest.raises(InvalidRequest):
        build(workspace, limits={"memory_mb": 512})


# --------------------------------------------------------------------------- #
# the create body a workflow container actually gets
# --------------------------------------------------------------------------- #


def test_the_create_body_has_no_secret_and_runs_through_the_shim(workspace):
    spec = build(workspace, env={"REPORTS_TOKEN": "s3cret"}, tool_suites=["reporting"])

    payload = _create_payload(spec)

    assert payload["Entrypoint"] == [EXEC_SHIM]
    assert payload["Cmd"] == [
        "python3",
        f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}/pipeline.py",
    ]
    assert payload["WorkingDir"] == f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}"
    assert payload["StdinOnce"] is True
    assert payload["HostConfig"]["Binds"] == [
        f"{workspace.root}/workflows/{WORKFLOW}:"
        f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}:ro",
        f"{workspace.root}/shared:{CONTAINER_WORKSPACE}/shared:ro",
        f"{workspace.root}/tools/reporting:"
        f"{CONTAINER_WORKSPACE}/tools/reporting:ro",
        f"{workspace.root}/reports/{WORKFLOW}:"
        f"{CONTAINER_WORKSPACE}/reports/{WORKFLOW}:rw",
        f"{workspace.root}/output/{WORKFLOW}:"
        f"{CONTAINER_WORKSPACE}/output/{WORKFLOW}:rw",
    ]
    assert payload["HostConfig"]["Tmpfs"] == {CONTAINER_TMP: "size=1024m"}
    assert payload["HostConfig"]["Memory"] == 4096 * 1024 * 1024
    assert payload["HostConfig"]["PidsLimit"] == 1024
    # Egress is Docker's own default: no NetworkMode in the payload at all.
    assert "NetworkMode" not in payload["HostConfig"]
    # docker inspect shows this list: no secret may be in it.
    assert not any(entry.startswith("REPORTS_TOKEN=") for entry in payload["Env"])
    assert "TRELLIS_RUN_ID=run-1" in payload["Env"]


def test_a_none_network_workflow_names_the_network_in_the_payload(workspace):
    payload = _create_payload(build(workspace, network="none"))

    assert payload["HostConfig"]["NetworkMode"] == "none"


def test_a_workflow_container_is_removed_when_the_run_ends(workspace, tmp_path):
    """Same one-shot lifecycle as a tool: the run kills and deletes its container.

    The attach step fails here (no daemon on that socket), which is exactly what
    proves the cleanup is in a ``finally`` rather than on the happy path.
    """
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/containers/create":
            return httpx.Response(201, json={"Id": "wf1"})
        if request.url.path.endswith("/kill"):
            return httpx.Response(409, json={"message": "not running"})
        return httpx.Response(204)

    async def scenario():
        backend = DockerBackend(
            socket=str(tmp_path / "no-daemon.sock"),
            transport=httpx.MockTransport(handler),
        )
        try:
            await backend.run(build(workspace), b'{"env":{}}\nprompt', 5.0)
        finally:
            await backend.close()

    with pytest.raises(BackendError):
        asyncio.run(scenario())

    assert ("POST", "/containers/create") in calls
    assert calls[-1] == ("DELETE", "/containers/wf1")


# --------------------------------------------------------------------------- #
# the runner's /v1/exec path
# --------------------------------------------------------------------------- #


@pytest.fixture
def runner_env(workspace, monkeypatch):
    backend = FakeBackend()
    backend_module.set_backend(backend)
    runner_module.reset_for_tests()
    monkeypatch.setenv("RUNNER_MAX_CONTAINERS_PER_TOOL", "8")
    try:
        yield SimpleNamespace(workspace=workspace, backend=backend)
    finally:
        backend_module.set_backend(None)
        runner_module.reset_for_tests()


def _token(agent=WORKFLOW, run_id="run-1"):
    return agent_token.mint(agent, user_id=f"svc_agent_{agent}", run_id=run_id)


def _body(**overrides) -> dict:
    body = {
        "kind": "workflow",
        "target": WORKFLOW,
        "entrypoint": "pipeline.py",
        "tools": ["make_report"],
        "env": {"REPORTS_TOKEN": "s3cret"},
        "input": "inventory for today",
        "deadline_ms": 60_000,
        "agent_token": _token(),
    }
    body.update(overrides)
    return body


async def _call(method: str, path: str, *, json_body=None, headers=None):
    transport = httpx.ASGITransport(app=runner_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://runner") as client:
        return await client.request(
            method, path, json=json_body, headers=AUTH if headers is None else headers
        )


def test_the_runner_runs_a_workflow_in_one_container(runner_env):
    runner_env.backend.queue(RawExec(exit_code=0, stdout=b"report written\n"))
    workspace = runner_env.workspace

    response = asyncio.run(_call("POST", "/v1/exec", json_body=_body()))

    assert response.status_code == 200, response.json()
    assert response.json()["stdout"] == "report written\n"

    spec = runner_env.backend.specs[0]
    assert spec.kind == "workflow"
    assert spec.working_dir == f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}"
    assert [mount.target for mount in spec.mounts] == [
        f"{CONTAINER_WORKSPACE}/workflows/{WORKFLOW}",
        f"{CONTAINER_WORKSPACE}/shared",
        f"{CONTAINER_WORKSPACE}/tools/reporting",
        f"{CONTAINER_WORKSPACE}/reports/{WORKFLOW}",
        f"{CONTAINER_WORKSPACE}/output/{WORKFLOW}",
    ]
    # The declared tool's suite is mounted; the undeclared one is not.
    assert not any("tools/other" in mount.target for mount in spec.mounts)
    assert spec.mounts[0].source == f"/host{workspace.root}/workflows/{WORKFLOW}"
    assert (workspace.root / "reports" / WORKFLOW).is_dir()
    assert spec.labels["trellis.kind"] == "workflow"
    assert spec.labels["trellis.run"] == "run-1"
    assert spec.env["TRELLIS_RUN_ID"] == "run-1"

    # The runner writes ONE preamble line (the declared secret) and the prompt is
    # the pipeline's stdin, byte for byte.
    stdin = runner_env.backend.stdin[0][1]
    first, _, payload = stdin.partition(b"\n")
    assert json.loads(first)["env"] == {"REPORTS_TOKEN": "s3cret"}
    assert payload == b"inventory for today"

    # A workflow never takes the create/start path, so nothing is left behind that
    # would need its own cleanup.
    assert runner_env.backend.containers == {}
    assert runner_env.backend.started == []


def test_a_workflow_may_declare_a_tool_that_has_no_files_here(runner_env):
    """An edge tool / MCP tool has no local suite: declared is legal, mounted is not."""
    runner_env.backend.queue(RawExec(exit_code=0, stdout=b"ok"))

    response = asyncio.run(
        _call(
            "POST",
            "/v1/exec",
            json_body=_body(
                tools=["make_report", "dc1__node_ssh", "mcp__coralogix__query"]
            ),
        )
    )

    assert response.status_code == 200, response.json()
    spec = runner_env.backend.specs[0]
    assert [mount.target for mount in spec.mounts if "tools/" in mount.target] == [
        f"{CONTAINER_WORKSPACE}/tools/reporting"
    ]


def test_an_undeclared_tool_is_absent_from_the_filesystem(runner_env):
    runner_env.backend.queue(RawExec(exit_code=0, stdout=b"ok"))

    response = asyncio.run(_call("POST", "/v1/exec", json_body=_body(tools=[])))

    assert response.status_code == 200, response.json()
    spec = runner_env.backend.specs[0]
    assert not any("tools/" in mount.target for mount in spec.mounts)
    assert not any("tools/" in mount.source for mount in spec.mounts)


def test_an_unknown_workflow_is_a_400_naming_the_path(runner_env):
    response = asyncio.run(
        _call("POST", "/v1/exec", json_body=_body(target="no-such-workflow"))
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["code"] == "invalid_request"
    assert "no-such-workflow" in detail["message"]
    assert runner_env.backend.specs == []


def test_a_workflow_run_needs_a_token(runner_env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")

    response = asyncio.run(
        _call("POST", "/v1/exec", json_body=_body(agent_token=None))
    )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "access_denied"
    assert runner_env.backend.specs == []


def test_a_workflow_request_without_an_entrypoint_is_refused_on_the_wire(runner_env):
    response = asyncio.run(
        _call("POST", "/v1/exec", json_body=_body(entrypoint=None))
    )

    assert response.status_code == 422
    assert runner_env.backend.specs == []


def test_workflow_fields_on_a_tool_call_are_refused_on_the_wire(runner_env):
    response = asyncio.run(
        _call("POST", "/v1/exec", json_body={"kind": "tool", "target": "make_report",
                                             "entrypoint": "pipeline.py",
                                             "agent_token": _token()})
    )

    assert response.status_code == 422
    assert runner_env.backend.specs == []


def test_workflow_is_a_one_shot_kind_not_a_session_kind():
    assert "workflow" in runner_module.ONE_SHOT_KINDS
    assert "workflow" not in runner_module.SESSION_KINDS


def test_the_tool_yaml_of_a_mounted_suite_is_still_a_local_target(workspace):
    """The suite list comes from the same scan a tool call uses (no drift)."""
    assert runner_module.workflow_tool_suites(["make_report"]) == ["reporting"]
    assert runner_module.workflow_tool_suites(["side_effect"]) == ["other"]
    assert runner_module.workflow_tool_suites(["make_report", "side_effect"]) == [
        "other",
        "reporting",
    ]
    # Unknown registry names (edge tools, MCP tools, typos) mount nothing.
    assert runner_module.workflow_tool_suites(["dc1__node_ssh", "nope"]) == []


def test_a_tool_manifest_is_still_parsed_as_a_tool_config(workspace):
    """Guard against the suite fixtures drifting from the real manifest schema."""
    raw = yaml.safe_load((workspace.root / "tools" / "reporting" / "tool.yaml").read_text())
    assert ToolConfig(**raw[0]).name == "make_report"


def test_stopping_the_task_id_removes_the_workflow_container(runner_env):
    """R3, end to end: the ``trellis.run`` label IS the run id the worker knows.

    The worker never learns the container id (it never sees one: the runner owns the
    container), so ``/v1/stop`` has to find it by the label the spec derived from the
    verified token's claims -- for a workflow, the taskiq task id.
    """
    runner_env.backend.queue(RawExec(exit_code=0, stdout=b"ok"))
    asyncio.run(_call("POST", "/v1/exec", json_body=_body()))
    spec = runner_env.backend.specs[0]
    assert spec.labels["trellis.run"] == "run-1"

    async def seed() -> str:
        container_id = await runner_env.backend.create(spec)
        await runner_env.backend.start(container_id)
        return container_id

    container_id = asyncio.run(seed())

    response = asyncio.run(_call("POST", "/v1/stop", json_body={"run_id": "run-1"}))

    assert response.status_code == 200, response.json()
    assert response.json()["stopped"] == 1
    assert container_id not in runner_env.backend.containers
    # The poller can race the run's own exit: a second stop is harmless.
    again = asyncio.run(_call("POST", "/v1/stop", json_body={"run_id": "run-1"}))
    assert again.status_code == 200
    assert again.json()["stopped"] == 0
