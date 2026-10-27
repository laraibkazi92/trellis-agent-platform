# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Manifest -> ContainerSpec derivation (``core.execution.spec``).

The spec builder is the only place a container's mounts, environment, limits,
network profile and runtime are chosen, so these assertions are the isolation
contract in unit form: a caller can name a target and stdin, nothing else. No
Docker daemon, no runsc -- the spec is plain data.
"""

import json
import logging
import os
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from core.execution.env import preamble_line
from core.execution.spec import (
    CONTAINER_WORKSPACE,
    DEFAULT_NETWORK_MODE,
    InvalidRequest,
    build_console_spec,
    build_spec,
    declared_env_keys,
    manifest_digest,
    runtime_for,
    workflow_network_mode,
)
from core.models import (
    ContainerLimits,
    MCPConfig,
    ToolConfig,
    reset_network_policy_warnings,
)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    suite = root / "tools" / "echo"
    suite.mkdir(parents=True)
    (suite / "echo.py").write_text("print('{}')\n", encoding="utf-8")
    (root / "shared").mkdir()

    monkeypatch.setenv("RUNNER_IMAGE", "trellis-agent-platform:test")
    monkeypatch.setenv("TRELLIS_INSTALL_ID", "test-install")
    monkeypatch.setenv("CONTAINER_DEFAULT_RUNTIME", "runsc")
    # A tool container is never allowed to fall back to the image's default user.
    monkeypatch.setenv("TRELLIS_UID", "1000")
    monkeypatch.setenv("TRELLIS_GID", "1000")
    reset_network_policy_warnings()
    return SimpleNamespace(root=root, suite=suite)


def make_config(**overrides):
    data = dict(name="echo", description="d", runtime="python", entrypoint="echo.py")
    data.update(overrides)
    return ToolConfig(**data)


def build(workspace, config, **overrides):
    kwargs = dict(
        kind="tool",
        suite_rel="tools/echo",
        target=config.name,
        env={},
        host_workspace=str(workspace.root),
    )
    kwargs.update(overrides)
    return build_spec(config, **kwargs)


# --------------------------------------------------------------------------- #
# mounts
# --------------------------------------------------------------------------- #


def test_mounts_are_suite_shared_and_declared_outputs_only(workspace):
    config = make_config(output_dirs=["reports", "output"])

    spec = build(workspace, config, agent="demo-assistant")

    assert [(mount.target, mount.read_only) for mount in spec.mounts] == [
        (f"{CONTAINER_WORKSPACE}/tools/echo", True),
        (f"{CONTAINER_WORKSPACE}/shared", True),
        (f"{CONTAINER_WORKSPACE}/reports/demo-assistant", False),
        (f"{CONTAINER_WORKSPACE}/output/demo-assistant", False),
    ]
    assert spec.mounts[0].source == str(workspace.suite)
    assert spec.mounts[1].source == str(workspace.root / "shared")
    assert spec.mounts[2].source == str(workspace.root / "reports" / "demo-assistant")
    assert spec.mounts[3].source == str(workspace.root / "output" / "demo-assistant")

    # Nothing else exists in the container: no other suite, no agent/workflow
    # manifests, no MCP dir, no .env.
    targets = " ".join(mount.target for mount in spec.mounts)
    sources = " ".join(mount.source for mount in spec.mounts)
    for forbidden in ("agents", "workflows", "mcps", ".env", "mcp-sessions"):
        assert forbidden not in targets
        assert forbidden not in sources

    for mount in spec.mounts:
        assert mount.target.startswith(f"{CONTAINER_WORKSPACE}/")
        assert os.path.normpath(mount.target) == mount.target


def test_no_output_mounts_when_nothing_is_declared(workspace):
    config = make_config()

    spec = build(workspace, config, agent="demo-assistant")

    assert [mount.target for mount in spec.mounts] == [
        f"{CONTAINER_WORKSPACE}/tools/echo",
        f"{CONTAINER_WORKSPACE}/shared",
    ]
    assert all(mount.read_only for mount in spec.mounts)


def test_only_the_declared_output_dir_is_mounted(workspace):
    config = make_config(output_dirs=["output"])

    spec = build(workspace, config, agent="a1")

    assert [mount.target for mount in spec.mounts] == [
        f"{CONTAINER_WORKSPACE}/tools/echo",
        f"{CONTAINER_WORKSPACE}/shared",
        f"{CONTAINER_WORKSPACE}/output/a1",
    ]


def test_output_mounts_require_an_agent(workspace):
    """Phase-1 decision D6: no agent identity -> no rw mount (e.g. the edge)."""
    config = make_config(output_dirs=["reports", "output"])

    spec = build(workspace, config, agent=None)

    assert [mount.target for mount in spec.mounts] == [
        f"{CONTAINER_WORKSPACE}/tools/echo",
        f"{CONTAINER_WORKSPACE}/shared",
    ]


@pytest.mark.parametrize(
    "overrides",
    [
        {"agent": "../../etc"},
        {"agent": "/etc"},
        {"agent": "a/../../b"},
        {"suite_rel": "/etc"},
        {"suite_rel": "tools/../../etc"},
        {"suite_rel": "tools/../agents/demo-assistant"},
    ],
)
def test_mount_paths_cannot_escape_the_workspace(workspace, overrides):
    config = make_config(output_dirs=["reports"])

    with pytest.raises(InvalidRequest):
        build(workspace, config, **overrides)


def test_a_symlinked_suite_directory_is_refused(workspace, tmp_path):
    """A relative path can still resolve outside: the bind source must be inside.

    ``tools/<suite> -> /etc`` has no ``..`` in it, so the string check passes while the
    container would get a directory the workspace never contained (Docker follows the
    mount source).
    """
    outside = tmp_path / "outside-suite"
    outside.mkdir()
    (workspace.root / "tools" / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, make_config(), suite_rel="tools/linked")

    assert "outside the workspace" in excinfo.value.message


def test_a_symlinked_shared_directory_is_refused(workspace, tmp_path):
    (workspace.root / "shared").rmdir()
    outside = tmp_path / "outside-shared"
    outside.mkdir()
    (workspace.root / "shared").symlink_to(outside, target_is_directory=True)

    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, make_config())

    assert "outside the workspace" in excinfo.value.message


def test_a_symlink_inside_a_suite_is_not_a_mount_source(workspace, tmp_path):
    """Only the source is checked; a symlink beneath it is a container concern."""
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (workspace.suite / "data").symlink_to(outside, target_is_directory=True)

    spec = build(workspace, make_config())

    assert spec.mounts[0].source == str(workspace.suite)


# --------------------------------------------------------------------------- #
# environment
# --------------------------------------------------------------------------- #


def test_declared_env_keys_cover_the_documented_group_form():
    """``secrets``/``variables`` as {general,user,background} name keys in the leaves."""
    config = make_config(
        secrets={"general": ["SHARED_TOKEN"], "user": ["USER_TOKEN"], "background": ["BG_TOKEN"]},
        optional_secrets=["OPTIONAL_TOKEN"],
        variables={"user": ["SERVICE_URL"]},
    )

    assert declared_env_keys(config) == {
        "SHARED_TOKEN",
        "USER_TOKEN",
        "BG_TOKEN",
        "OPTIONAL_TOKEN",
        "SERVICE_URL",
        "TRELLIS_USER_ID",
        "TRELLIS_USER_EMAIL",
    }


def test_declared_env_passes_through(workspace):
    config = make_config(
        secrets={"general": ["API_KEY"], "user": ["USER_TOKEN"]},
        variables=["SERVICE_URL"],
    )

    spec = build(
        workspace,
        config,
        env={
            "API_KEY": "a",
            "USER_TOKEN": "u",
            "SERVICE_URL": "https://example.test",
            "TRELLIS_USER_ID": "user-1",
            "TRELLIS_USER_EMAIL": "u@example.com",
        },
    )

    # Identity is part of the documented contract and stays in the container
    # configuration; credentials/variables reach the process on stdin only.
    assert spec.env["TRELLIS_USER_ID"] == "user-1"
    assert spec.env["TRELLIS_USER_EMAIL"] == "u@example.com"
    assert spec.preamble_env["API_KEY"] == "a"
    assert spec.preamble_env["USER_TOKEN"] == "u"
    assert spec.preamble_env["SERVICE_URL"] == "https://example.test"
    assert "API_KEY" not in spec.env
    assert "USER_TOKEN" not in spec.env
    assert "SERVICE_URL" not in spec.env


def test_undeclared_env_key_is_rejected(workspace):
    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, make_config(), env={"SMUGGLED_SECRET": "x"})

    assert "SMUGGLED_SECRET" in excinfo.value.message


def test_an_env_name_no_process_can_carry_is_a_bad_request(workspace):
    """``my-api-key`` reaches the boundary through an MCP's literal ``env:`` block.

    Declared ``secrets``/``variables`` are rejected at manifest load
    (``core.models``), but the literal block is free-form, so the runner boundary
    must refuse it too: dropping the entry would silently lose a credential.
    """
    config = MCPConfig(name="demo", command="srv", env={"my-api-key": "x"})

    with pytest.raises(InvalidRequest) as excinfo:
        build_spec(
            config,
            kind="mcp_session",
            suite_rel="tools/echo",
            target="demo",
            env={},
            host_workspace=str(workspace.root),
        )

    assert "my-api-key" in excinfo.value.message
    assert "not valid environment names" in excinfo.value.message


def test_console_spec_refuses_an_env_name_no_process_can_carry(workspace):
    with pytest.raises(InvalidRequest) as excinfo:
        build_console_spec("echo hi", env={"my-key": "x"})

    assert "my-key" in excinfo.value.message


def test_preamble_line_is_only_the_net_for_values_that_bypass_validation(caplog):
    """The drops that used to be silent are now belt-and-braces.

    Both exit-78 triggers (an unusable name, a NUL in a value) are rejected earlier;
    if something still reaches ``preamble_line`` it is dropped with a warning naming
    the key, never the value, so one bad entry cannot take the whole tool down.
    """
    caplog.set_level(logging.WARNING, logger="core.execution.env")
    line = preamble_line({"GOOD_KEY": "kept", "my-api-key": "dropped-1", "NUL_KEY": "a\x00b"})

    assert json.loads(line) == {"env": {"GOOD_KEY": "kept"}}

    warnings = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING and record.name == "core.execution.env"
    ]
    assert any("my-api-key" in message for message in warnings)
    assert any("NUL_KEY" in message for message in warnings)
    for message in warnings:
        assert "dropped-1" not in message
        assert "kept" not in message


@pytest.mark.parametrize(
    "name",
    ["PATH", "LD_PRELOAD", "AGENT_TOKEN_SECRET", "RUNNER_TOKEN", "PYTHONPATH"],
)
def test_reserved_env_keys_are_rejected_even_when_declared(workspace, name):
    config = make_config(secrets=[name])

    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, config, env={name: "x"})

    assert "reserved" in excinfo.value.message
    assert name in excinfo.value.message


def test_control_plane_names_never_survive_in_the_env(workspace):
    """A restricted name present in the base environment is dropped, not inherited."""
    config = make_config()

    spec = build(workspace, config, env={})

    for name in ("RUNNER_TOKEN", "AGENT_TOKEN_SECRET", "LD_PRELOAD"):
        assert name not in spec.env


def test_home_and_tmp_point_at_the_container_tmpfs(workspace):
    spec = build(workspace, make_config())

    assert spec.env["HOME"] == "/tmp"
    assert spec.env["TMPDIR"] == "/tmp"
    assert spec.env["TMP"] == "/tmp"
    assert spec.tmpfs == {"/tmp": 128}


def test_path_starts_with_the_suite_bin_directory(workspace):
    spec = build(workspace, make_config())

    assert spec.env["PATH"].startswith(f"{CONTAINER_WORKSPACE}/tools/echo/bin:")


# --------------------------------------------------------------------------- #
# run context (v0.7.2 R2): the agent, the run and the writable dirs
# --------------------------------------------------------------------------- #
#
# Every one of these is derived runner-side (from the identity the runner resolved
# and the mounts it just created) and lives in the container's configuration, so a
# tool -- or a subprocess it spawns -- sees them before it reads its stdin.


def test_a_tool_call_knows_its_agent_run_and_report_dir(workspace):
    config = make_config(output_dirs=["reports"])

    spec = build(workspace, config, agent="demo-assistant", run_id="run-1")

    assert spec.env["TRELLIS_AGENT_NAME"] == "demo-assistant"
    assert spec.env["TRELLIS_RUN_ID"] == "run-1"
    # The variable names the mount that was actually created, at its container path.
    assert spec.env["TRELLIS_REPORTS_DIR"] == f"{CONTAINER_WORKSPACE}/reports/demo-assistant"
    assert f"{CONTAINER_WORKSPACE}/reports/demo-assistant" in {
        mount.target for mount in spec.mounts
    }
    # Only mounted dirs are announced: `output` was not declared, so writing there
    # is not an option the tool should be told about.
    assert "TRELLIS_OUTPUT_DIR" not in spec.env
    assert "TRELLIS_OUTPUT_DIR" not in spec.preamble_env


def test_both_declared_output_dirs_are_announced(workspace):
    spec = build(
        workspace,
        make_config(output_dirs=["reports", "output"]),
        agent="a1",
        run_id="run-1",
    )

    assert spec.env["TRELLIS_REPORTS_DIR"] == f"{CONTAINER_WORKSPACE}/reports/a1"
    assert spec.env["TRELLIS_OUTPUT_DIR"] == f"{CONTAINER_WORKSPACE}/output/a1"


def test_no_mounted_dir_means_no_dir_variable(workspace):
    """A tool that declared nothing writable is told nothing about writing."""
    spec = build(workspace, make_config(), agent="demo-assistant", run_id="run-1")

    for name in ("TRELLIS_REPORTS_DIR", "TRELLIS_OUTPUT_DIR"):
        assert name not in spec.env
        assert name not in spec.preamble_env


def test_without_an_agent_there_is_no_name_and_no_dir(workspace):
    """Same rule as the mounts: no identity -> no rw mount, no dir variable."""
    spec = build(
        workspace, make_config(output_dirs=["reports"]), agent=None, run_id="run-1"
    )

    assert "TRELLIS_AGENT_NAME" not in spec.env
    assert "TRELLIS_REPORTS_DIR" not in spec.env
    assert spec.env["TRELLIS_RUN_ID"] == "run-1"


def test_no_run_id_means_no_run_variable(workspace):
    spec = build(workspace, make_config(), agent="demo-assistant")

    assert "TRELLIS_RUN_ID" not in spec.env
    assert spec.env["TRELLIS_AGENT_NAME"] == "demo-assistant"


def test_a_gateway_call_runs_under_the_reserved_gateway_identity(workspace):
    """``gateway`` is a reserved agent name: the runner passes it like any other."""
    spec = build(workspace, make_config(), agent="gateway", run_id="run-gw")

    assert spec.env["TRELLIS_AGENT_NAME"] == "gateway"
    assert spec.env["TRELLIS_RUN_ID"] == "run-gw"


def test_a_caller_cannot_assert_the_run_context(workspace):
    """The vars are applied after the merge, so even a manifest that declares one
    cannot let a caller redirect it (and ``_merge_env`` still refuses undeclared
    keys, so ``declared_env_keys`` stays as it was)."""
    config = make_config(output_dirs=["reports"], variables=["TRELLIS_REPORTS_DIR"])

    spec = build(
        workspace,
        config,
        agent="demo-assistant",
        run_id="run-1",
        env={"TRELLIS_REPORTS_DIR": "/etc"},
    )

    assert spec.env["TRELLIS_REPORTS_DIR"] == f"{CONTAINER_WORKSPACE}/reports/demo-assistant"
    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, config, agent="demo-assistant", env={"TRELLIS_AGENT_NAME": "x"})
    assert "TRELLIS_AGENT_NAME" in excinfo.value.message


def test_an_unattributed_call_gets_no_run_context_even_if_the_caller_sends_one(workspace):
    """No identity, no announced dirs -- a declared name must not survive the merge.

    The pop-then-set rule: without it, a manifest that declares one of these names
    would let an anonymous caller announce ``TRELLIS_REPORTS_DIR=/etc`` in a
    container that has no writable mount at all.
    """
    config = make_config(
        output_dirs=["reports"], variables=["TRELLIS_REPORTS_DIR", "TRELLIS_RUN_ID"]
    )

    spec = build(
        workspace,
        config,
        agent=None,
        env={"TRELLIS_REPORTS_DIR": "/etc", "TRELLIS_RUN_ID": "forged"},
    )

    for name in ("TRELLIS_AGENT_NAME", "TRELLIS_RUN_ID", "TRELLIS_REPORTS_DIR"):
        assert name not in spec.env, name
        assert name not in spec.preamble_env, name
    assert all(mount.read_only for mount in spec.mounts)


def test_a_console_gets_no_run_context_from_its_env(workspace):
    """A console mounts no workspace tree, so a dir/agent variable would be a lie."""
    spec = build_console_spec(
        "echo hi",
        env={
            "TRELLIS_REPORTS_DIR": "/etc",
            "TRELLIS_AGENT_NAME": "someone",
            "TRELLIS_RUN_ID": "forged",
        },
        user_id="u-1",
        run_id="run-1",
    )

    for name in ("TRELLIS_AGENT_NAME", "TRELLIS_REPORTS_DIR", "TRELLIS_OUTPUT_DIR"):
        assert name not in spec.env, name
        assert name not in spec.preamble_env, name
    # The runner's own run id is still announced; that one it knows.
    assert spec.env["TRELLIS_RUN_ID"] == "run-1"


# --------------------------------------------------------------------------- #
# limits
# --------------------------------------------------------------------------- #


def test_limits_map_onto_the_spec(workspace):
    config = make_config(limits=ContainerLimits(memory_mb=1024, cpus=2.5, pids=512, tmpfs_mb=256))

    spec = build(workspace, config)

    assert spec.memory_mb == 1024
    assert spec.cpus == 2.5
    assert spec.pids == 512
    assert spec.tmpfs == {"/tmp": 256}


def test_tmpfs_bounded_by_memory(workspace):
    """The spec rejects it too, for a config that bypassed model validation."""
    config = SimpleNamespace(
        name="echo",
        runtime="python",
        entrypoint="echo.py",
        limits=SimpleNamespace(memory_mb=100, cpus=1.0, pids=64, tmpfs_mb=60),
    )

    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, config)

    assert "half" in excinfo.value.message


def test_the_same_limit_is_rejected_at_manifest_load():
    with pytest.raises(ValidationError) as excinfo:
        ToolConfig(
            name="echo",
            description="d",
            runtime="python",
            entrypoint="echo.py",
            limits={"memory_mb": 100, "tmpfs_mb": 60},
        )

    assert "half" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# network
# --------------------------------------------------------------------------- #


def test_undeclared_network_is_egress(workspace):
    """v0.7.1 flips the default: a tool gets ordinary Docker egress."""
    spec = build(workspace, make_config())

    assert spec.network_mode == DEFAULT_NETWORK_MODE
    assert DEFAULT_NETWORK_MODE == "bridge"


def test_network_none_is_the_only_override(workspace):
    spec = build(workspace, make_config(network="none"))

    assert spec.network_mode == "none"


@pytest.mark.parametrize("declared", ["allow", "internet", "internal"])
def test_legacy_network_values_become_egress(workspace, declared):
    """Every v0.6 profile meant "may use the network" -- that is exactly egress."""
    spec = build(workspace, make_config(network=declared))

    assert spec.network_mode == DEFAULT_NETWORK_MODE


@pytest.mark.parametrize("declared", ["deny", "off"])
def test_legacy_deny_values_become_none(workspace, declared):
    spec = build(workspace, make_config(network=declared))

    assert spec.network_mode == "none"


def test_unknown_network_value_falls_back_to_none(workspace):
    """A typo must not drop the tool, and the fallback is the restrictive one."""
    spec = build(workspace, make_config(network="nonsense"))

    assert spec.network_mode == "none"


@pytest.mark.parametrize("declared", ["egress", "internal"])
def test_egress_containers_get_no_resolv_conf_mount(workspace, declared):
    """Docker supplies the resolver; the generated-file machinery is gone."""
    spec = build(workspace, make_config(network=declared))

    assert all(mount.target != "/etc/resolv.conf" for mount in spec.mounts)
    assert not (workspace.root / ".runner-dns").exists()


@pytest.mark.parametrize(
    "declared", [None, "", "egress", "allow", "internet", "internal", "none", "deny", "junk"]
)
def test_a_workflow_network_maps_exactly_like_a_tool_manifest(workspace, declared):
    """One vocabulary, one mapping: workflow containers cannot drift from tools.

    A workflow config is a raw registry document (no manifest model normalizes it),
    so the same helper has to produce the same ``NetworkMode`` for both.
    """
    tool = build(workspace, make_config(network=declared)) if declared is not None else build(
        workspace, make_config()
    )

    assert workflow_network_mode(declared) == tool.network_mode


# --------------------------------------------------------------------------- #
# labels, runtime, digest
# --------------------------------------------------------------------------- #


def test_labels_carry_install_kind_target_session_and_run(workspace):
    spec = build(
        workspace, make_config(), session_key="session-1", run_id="run-1"
    )

    assert spec.labels == {
        "trellis.install": "test-install",
        "trellis.kind": "tool",
        "trellis.target": "echo",
        "trellis.session": "session-1",
        "trellis.run": "run-1",
    }


def test_labels_are_empty_without_a_session_or_run(workspace):
    spec = build(workspace, make_config())

    assert spec.labels["trellis.session"] == ""
    assert spec.labels["trellis.run"] == ""


def test_default_runtime_is_runsc(workspace, monkeypatch):
    monkeypatch.delenv("CONTAINER_DEFAULT_RUNTIME", raising=False)

    assert build(workspace, make_config()).runtime == "runsc"


def test_container_default_runtime_is_honored(workspace, monkeypatch):
    monkeypatch.setenv("CONTAINER_DEFAULT_RUNTIME", "runc")

    assert build(workspace, make_config()).runtime == "runc"


def test_manifest_runtime_override_is_honored(workspace, monkeypatch):
    monkeypatch.setenv("CONTAINER_DEFAULT_RUNTIME", "runsc")

    assert build(workspace, make_config(container_runtime="runc")).runtime == "runc"


@pytest.mark.parametrize("runtime", ["bogus", "gvisor"])
def test_unknown_runtime_fails_closed(workspace, monkeypatch, runtime):
    monkeypatch.delenv("CONTAINER_DEFAULT_RUNTIME", raising=False)

    with pytest.raises(InvalidRequest):
        build(workspace, make_config(), default_runtime=runtime)


def test_unknown_runtime_in_an_unvalidated_config_fails_closed():
    """MCPConfig has no runtime validator, so the spec has to be the gate."""
    with pytest.raises(InvalidRequest):
        runtime_for(SimpleNamespace(container_runtime="gvisor"), None)


def test_manifest_runtime_field_is_validated_at_load():
    with pytest.raises(ValidationError):
        ToolConfig(
            name="echo",
            description="d",
            runtime="python",
            entrypoint="echo.py",
            container_runtime="gvisor",
        )


def test_digest_is_stable_across_key_order():
    first = ToolConfig(
        **{
            "name": "echo",
            "description": "d",
            "runtime": "python",
            "entrypoint": "echo.py",
            "secrets": {"general": ["A"], "user": ["B"]},
            "output_dirs": ["reports"],
        }
    )
    second = ToolConfig(
        **{
            "output_dirs": ["reports"],
            "secrets": {"user": ["B"], "general": ["A"]},
            "entrypoint": "echo.py",
            "runtime": "python",
            "description": "d",
            "name": "echo",
        }
    )

    assert manifest_digest(first) == manifest_digest(second)


def test_digest_changes_when_a_field_changes():
    base = make_config()

    assert manifest_digest(base) != manifest_digest(make_config(network="none"))
    assert manifest_digest(base) != manifest_digest(
        make_config(limits=ContainerLimits(memory_mb=1024, tmpfs_mb=256))
    )


def test_digest_survives_a_parse_round_trip():
    """The hub parses etcd JSON, the runner parses YAML: both must agree."""
    config = make_config(
        secrets={"general": ["A"]},
        output_dirs=["reports"],
        limits=ContainerLimits(memory_mb=1024, tmpfs_mb=256),
    )

    rebuilt = ToolConfig.model_validate(config.model_dump(mode="json"))

    assert manifest_digest(rebuilt) == manifest_digest(config)


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("entrypoint", ["../x.py", "/etc/passwd", "tools/../../etc/passwd"])
def test_entrypoint_traversal_is_rejected(workspace, entrypoint):
    with pytest.raises(InvalidRequest):
        build(workspace, make_config(entrypoint=entrypoint))


# --------------------------------------------------------------------------- #
# console
# --------------------------------------------------------------------------- #


def test_console_spec_is_a_scratch_workspace(monkeypatch):
    monkeypatch.delenv("CONTAINER_DEFAULT_RUNTIME", raising=False)
    monkeypatch.setenv("TRELLIS_UID", "1000")
    monkeypatch.setenv("TRELLIS_GID", "1000")

    spec = build_console_spec(
        "echo hi", env={"FOO": "bar"}, user_id="user-1", user_email="u@example.com", run_id="run-1"
    )

    assert spec.cmd == ["bash", "-lc", "echo hi"]
    assert spec.working_dir == "/workspace"
    assert spec.mounts == []
    assert spec.tmpfs == {"/workspace": 256, "/tmp": 256}
    assert spec.network_mode == "none"
    assert spec.runtime == "runsc"
    assert spec.kind == "console"
    assert spec.labels["trellis.kind"] == "console"
    assert spec.labels["trellis.target"] == "console"
    assert spec.labels["trellis.run"] == "run-1"
    # A console container's configuration is the fixed non-secret set only.
    assert "FOO" not in spec.env
    assert spec.preamble_env["FOO"] == "bar"
    assert spec.env["TRELLIS_USER_ID"] == "user-1"
    assert spec.env["TRELLIS_USER_EMAIL"] == "u@example.com"
    assert spec.env["TRELLIS_RUN_ID"] == "run-1"
    assert spec.env["HOME"] == spec.env["TMPDIR"] == spec.env["TMP"] == "/tmp"


def test_console_spec_never_forwards_control_plane_env(monkeypatch):
    monkeypatch.setenv("TRELLIS_UID", "1000")
    monkeypatch.setenv("TRELLIS_GID", "1000")
    spec = build_console_spec(
        "env",
        env={
            "RUNNER_TOKEN": "runner",
            "AGENT_TOKEN_SECRET": "agent",
            "LD_PRELOAD": "/tmp/x.so",
            "PATH": "/tmp/evil",
        },
    )

    assert "RUNNER_TOKEN" not in spec.env
    assert "AGENT_TOKEN_SECRET" not in spec.env
    assert "LD_PRELOAD" not in spec.env
    assert spec.env["PATH"] != "/tmp/evil"
    assert spec.network_mode == "none"


def test_console_spec_rejects_an_empty_command():
    with pytest.raises(InvalidRequest):
        build_console_spec("   ", env={})


def test_runner_view_and_host_path_are_not_conflated(workspace, tmp_path):
    """The runner stats its own mount, but binds the HOST path."""
    host_workspace = "/srv/host-only/workspace"
    spec = build(workspace, make_config(), host_workspace=host_workspace,
                 workspace_root=str(workspace.root))
    assert spec.mounts[0].source == f"{host_workspace}/tools/echo"
    assert spec.mounts[1].source == f"{host_workspace}/shared"


def test_a_host_path_the_runner_cannot_read_still_fails_closed(workspace):
    with pytest.raises(InvalidRequest):
        build(workspace, make_config(), workspace_root="/nonexistent-runner-view")


def test_missing_tool_identity_refuses_to_build(workspace, monkeypatch):
    monkeypatch.delenv("TRELLIS_UID", raising=False)
    monkeypatch.delenv("TRELLIS_GID", raising=False)
    with pytest.raises(InvalidRequest):
        build(workspace, make_config())


@pytest.mark.parametrize(
    ("variable", "value"),
    [("TRELLIS_UID", "0"), ("TRELLIS_GID", "0"), ("TRELLIS_UID", "00"), ("TRELLIS_GID", "00")],
)
def test_a_root_tool_identity_refuses_to_build(workspace, monkeypatch, variable, value):
    """The last gate before a container exists: 0 must not reach Docker as ``0:0``.

    The runner's startup preflight reads the environment once, so a ``TRELLIS_UID``
    changed after startup would otherwise slip through to the spec builder.
    """
    monkeypatch.setenv(variable, value)

    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, make_config())

    assert "non-root" in str(excinfo.value)


def test_a_root_tool_identity_refuses_a_console_spec(monkeypatch):
    monkeypatch.setenv("TRELLIS_UID", "0")
    monkeypatch.setenv("TRELLIS_GID", "1000")

    with pytest.raises(InvalidRequest):
        build_console_spec("echo hi", env={})
