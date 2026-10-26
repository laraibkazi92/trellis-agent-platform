# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Manifest -> ContainerSpec derivation (``core.execution.spec``).

The spec builder is the only place a container's mounts, environment, limits,
network profile and runtime are chosen, so these assertions are the isolation
contract in unit form: a caller can name a target and stdin, nothing else. No
Docker daemon, no runsc -- the spec is plain data.
"""

import os
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from core.execution.spec import (
    CONTAINER_WORKSPACE,
    DEFAULT_NETWORK_MODE,
    InvalidRequest,
    build_console_spec,
    build_spec,
    declared_env_keys,
    manifest_digest,
    runtime_for,
)
from core.models import ContainerLimits, ToolConfig, reset_network_policy_warnings


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

    assert spec.env["API_KEY"] == "a"
    assert spec.env["USER_TOKEN"] == "u"
    assert spec.env["SERVICE_URL"] == "https://example.test"
    assert spec.env["TRELLIS_USER_ID"] == "user-1"
    assert spec.env["TRELLIS_USER_EMAIL"] == "u@example.com"


def test_undeclared_env_key_is_rejected(workspace):
    with pytest.raises(InvalidRequest) as excinfo:
        build(workspace, make_config(), env={"SMUGGLED_SECRET": "x"})

    assert "SMUGGLED_SECRET" in excinfo.value.message


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
    assert spec.env["FOO"] == "bar"
    assert spec.env["TRELLIS_USER_ID"] == "user-1"
    assert spec.env["TRELLIS_USER_EMAIL"] == "u@example.com"
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
