# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Derive a hardened :class:`ContainerSpec` from a registered manifest.

This is the only place a container's image, mounts, environment, limits, user,
runtime and network are chosen. Callers (hub, edge proxy, console, MCP sessions)
supply a *target* and stdin; anything they send that the manifest does not
declare is rejected here rather than trusted.

Container paths are identical to the pre-container layout
(``/app/workspace/tools/<suite>``, ``/app/workspace/shared``, ...) so tool
wrappers and the stdin/stdout protocol are unchanged.

Network: there are no network profiles. A manifest either denies the network
(``network: none``) or gets ordinary Docker egress on the **default bridge**,
which is Docker's own default NetworkMode -- so an egress container carries no
network override in its create payload at all.

Workflows (``background_script``) are one container per run:
:func:`build_workflow_spec` freezes the old taskiq-worker layout into mounts, with
the pipeline's own directory as the working directory so relative paths keep
working.
"""

import hashlib
import json
import os
import shlex
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from pydantic import ValidationError

from core.execution.contract import WORKFLOW_RUNTIMES as WORKFLOW_RUNTIME_NAMES
from core.execution.env import (
    INVALID_ENV_NAME_HELP,
    declared_names,
    invalid_env_names,
    split_env,
)
from core.models import (
    MCPConfig,
    ContainerLimits,
    ToolConfig,
    normalize_network_policy,
    workflow_limits,
)

CONTAINER_WORKSPACE = "/app/workspace"
CONTAINER_TMP = "/tmp"

# Fixed base environment. Everything else in the runner's own environment stays
# in the runner: a container must never inherit its control-plane credentials.
SAFE_BASE_ENV = (
    "PATH",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TERM",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
)

# Names a caller may never set, even when a manifest happens to declare one.
RESTRICTED_ENV_VARS = frozenset(
    {
        "PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "BASH_ENV",
        "ENV",
        "HOSTALIASES",
        "RUNNER_TOKEN",
        "AGENT_TOKEN_SECRET",
        "ENCRYPTION_KEY",
        "SESSION_SECRET",
        "EDGE_PRIVATE_KEY_PATH",
    }
)

OUTPUT_DIRS = ("reports", "output")
# The container env variable each agent/workflow-owned writable dir is announced as
# (v0.7.2 R2). One map, so the mount matrix and the variables cannot drift apart.
OUTPUT_DIR_VARS = {"reports": "TRELLIS_REPORTS_DIR", "output": "TRELLIS_OUTPUT_DIR"}
KNOWN_RUNTIMES = ("runsc", "runsc-variant", "runc")

# Workflows live one directory per workflow, exactly like a tool suite or an MCP
# server: ``workspace/workflows/<name>/`` is the pipeline's tree and, inside the
# container, its working directory.
WORKFLOW_DIR = "workflows"
# runtime -> argv prefix. The vocabulary itself lives in ``core.execution.contract``
# (the wire Literal); this map is built from it, so a runtime the contract accepts but
# this map forgot fails at import instead of in a container that exits 127.
_WORKFLOW_INTERPRETERS = {
    # ``exec`` has none: the entrypoint itself is the command (a shebang script or a
    # binary), which was the v0.7 worker's fallback.
    "python": ["python3"],
    "node": ["node"],
    "bash": ["bash"],
    "exec": [],
}
WORKFLOW_RUNTIMES: dict[str, list[str]] = {
    name: _WORKFLOW_INTERPRETERS[name] for name in WORKFLOW_RUNTIME_NAMES
}
DEFAULT_WORKFLOW_RUNTIME = "python"

# Manifest network policies. ``none`` means no network at all; ``egress`` means
# normal Docker egress. Docker's default bridge is the only network whose DNS
# works under gVisor (the embedded resolver on a user-defined network is
# unreachable), and it is also Docker's default -- hence the mapping below.
POLICY_NONE = "none"
DEFAULT_NETWORK_MODE = "bridge"

# Per-stream caps for one-shot runs. Sessions cap separately in the runner.
MAX_STDOUT_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024


class InvalidRequest(ValueError):
    """The caller asked for something the manifest does not allow."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class ManifestStale(RuntimeError):
    """The caller's manifest digest does not match the file on disk."""


@dataclass(frozen=True)
class Mount:
    source: str
    target: str
    read_only: bool = True


@dataclass
class ContainerSpec:
    image: str
    runtime: str
    cmd: list[str]
    working_dir: str
    # Container *configuration*: the non-secret allowlist only (``core.execution.env``).
    env: dict[str, str]
    # Everything else the process needs (secrets, declared variables, sealed
    # credentials). The runner writes it as one stdin line ahead of the payload;
    # it must never reach the container's create body.
    preamble_env: dict[str, str] = field(default_factory=dict)
    mounts: list[Mount] = field(default_factory=list)
    # container path -> size in MB (tmpfs)
    tmpfs: dict[str, int] = field(default_factory=dict)
    memory_mb: int = 512
    cpus: float = 1.0
    pids: int = 256
    network_mode: str = DEFAULT_NETWORK_MODE
    labels: dict[str, str] = field(default_factory=dict)
    user: Optional[str] = None
    init: bool = True
    kind: str = "tool"


def declared_env_keys(config: Any) -> set[str]:
    """Every env name a manifest declares, plus the identity pair."""
    keys: set[str] = set()
    for attr in ("secrets", "optional_secrets", "variables", "env"):
        # MCPConfig has a literal `env:` block: those names are part of the
        # manifest's declared environment (not caller-supplied credentials).
        keys |= {str(name) for name in declared_names(getattr(config, attr, None))}
    for group in getattr(config, "secret_groups", None) or []:
        if not isinstance(group, Mapping):
            continue
        for option in group.get("options") or []:
            if not isinstance(option, Mapping):
                continue
            for field_def in option.get("fields") or []:
                if isinstance(field_def, Mapping) and field_def.get("key"):
                    keys.add(str(field_def["key"]))
    keys |= {"TRELLIS_USER_ID", "TRELLIS_USER_EMAIL"}
    return keys


def manifest_digest(config: Any) -> str:
    """Stable digest of a parsed manifest (canonical JSON, sorted keys)."""
    payload = config.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def network_mode_for(config: Any) -> str:
    """Docker ``NetworkMode`` for a manifest: ``none`` or the default bridge.

    ``DEFAULT_NETWORK_MODE`` is what Docker already does when no NetworkMode is
    sent, so the create payload only ever names a network to take it away.
    """
    policy = normalize_network_policy(getattr(config, "network", None), "manifest")
    return POLICY_NONE if policy == POLICY_NONE else DEFAULT_NETWORK_MODE


def workflow_network_mode(network: Optional[str] = None) -> str:
    """Docker ``NetworkMode`` for a workflow run: ``none`` or the default bridge.

    Same vocabulary and same default as a tool/MCP manifest (``egress``), applied
    again here so a runner handed a raw registry value cannot drift from
    ``network_mode_for``. ``normalize_network_policy`` is idempotent, so a value the
    caller already normalized warns once, not twice.
    """
    policy = normalize_network_policy(network, "workflow")
    return POLICY_NONE if policy == POLICY_NONE else DEFAULT_NETWORK_MODE


def runtime_for(config: Any, default: Optional[str] = None) -> str:
    """OCI runtime for a container: per-manifest, else the deployment default.

    ``runsc`` is the documented default (``CONTAINER_DEFAULT_RUNTIME`` overrides
    it for the whole deployment, e.g. ``runc`` on a dev machine); a manifest may
    also pin one with ``container_runtime:``.
    """
    runtime = str(
        getattr(config, "container_runtime", None)
        or default
        or os.getenv("CONTAINER_DEFAULT_RUNTIME")
        or "runsc"
    ).strip()
    if runtime not in KNOWN_RUNTIMES:
        # Fail closed: an unknown runtime is a manifest bug, not a reason to run
        # with less isolation than declared.
        raise InvalidRequest(f"unknown container_runtime {runtime!r}")
    return runtime


def _image(default: Optional[str] = None) -> str:
    return (
        default
        or os.getenv("RUNNER_IMAGE")
        or os.getenv("TRELLIS_IMAGE")
        or "trellis-agent-platform:local"
    )


def _base_env() -> dict[str, str]:
    from core.env_sanitize import sanitized_env

    clean = sanitized_env()
    base = {k: clean[k] for k in SAFE_BASE_ENV if k in clean}
    # No TRELLIS_* names here on purpose: the documented run context
    # (TRELLIS_USER_*/AGENT_NAME/RUN_ID/REPORTS_DIR/OUTPUT_DIR) is applied by the
    # builder from the identity and the mounts it created. Copying the runner's own
    # TRELLIS_* would leak topology (engine subnets, install id, host paths) to
    # untrusted code.
    return base


def _require_carriable_env_names(env: Mapping[str, str]) -> None:
    """Refuse a name no process environment can carry (``my-api-key``).

    The last boundary before the preamble is written: the shim would otherwise
    reject the whole line and take every valid credential down with it, and
    ``core.execution.env`` would silently drop the entry -- which for a declared
    secret means the tool runs without the credential it asked for.
    """
    unrepresentable = invalid_env_names(env)
    if unrepresentable:
        raise InvalidRequest(
            f"env keys are not valid environment names "
            f"({INVALID_ENV_NAME_HELP}): {', '.join(unrepresentable)}"
        )


def _merge_env(config: Any, requested: Mapping[str, str]) -> dict[str, str]:
    declared = declared_env_keys(config)
    unknown = sorted(set(requested) - declared)
    if unknown:
        raise InvalidRequest(
            f"env keys not declared by the manifest: {', '.join(unknown)}"
        )
    blocked = sorted(set(requested) & RESTRICTED_ENV_VARS)
    if blocked:
        raise InvalidRequest(f"env keys are reserved: {', '.join(blocked)}")

    env = _base_env()
    # The manifest's literal `env:` block is server configuration, applied in the
    # runner so it does not depend on a caller remembering to forward it.
    for key, value in (getattr(config, "env", None) or {}).items():
        if isinstance(key, str) and value is not None:
            env[key] = str(value)
    # Resolved credentials/identity override a stale literal value.
    for key, value in requested.items():
        if value is None:
            continue
        env[str(key)] = str(value)
    # A caller-supplied control-plane name must not survive even if a manifest
    # declared it by accident.
    for name in RESTRICTED_ENV_VARS:
        if name != "PATH":
            env.pop(name, None)
    # Last boundary before the preamble: a name no process environment can carry
    # (`my-api-key`) is a manifest bug, and dropping it here would lose a declared
    # credential silently -- the caller gets a 400 instead.
    _require_carriable_env_names(env)
    return env


def _tool_cmd(config: ToolConfig, suite_dir: str) -> list[str]:
    entrypoint = config.entrypoint or ""
    parts = entrypoint.split("/")
    if not entrypoint or entrypoint.startswith("/") or ".." in parts:
        raise InvalidRequest("entrypoint must be a plain relative path")
    path = f"{suite_dir}/{entrypoint}"
    if config.runtime == "python":
        return ["python3", path]
    if config.runtime == "go":
        # Compiled by the hub at registration; the binary lives in the suite.
        return [f"{suite_dir}/.bin/{config.name}"]
    if config.runtime == "ts":
        return ["npx", "tsx", path]
    if config.runtime == "bash":
        return ["bash", path]
    raise InvalidRequest(f"unsupported runtime {config.runtime!r}")


def _mcp_cmd(config: MCPConfig) -> list[str]:
    if not config.command:
        raise InvalidRequest(f"MCP {config.name!r} has no command")
    argv = shlex.split(config.command) if isinstance(config.command, str) else []
    argv.extend(str(a) for a in (config.args or []))
    if not argv:
        raise InvalidRequest(f"MCP {config.name!r} has an empty command")
    return argv


def is_plain_relative(value: str) -> bool:
    """True when ``value`` is a plain relative path: no absolute, no ``..``/empty parts.

    The rule the runner applies to every manifest/caller-supplied path, exposed so the
    registry sync can reject a workflow's ``entrypoint`` with the same test instead of
    discovering it when the run starts.
    """
    text = str(value or "")
    return bool(text) and not text.startswith("/") and not any(
        part in ("", ".", "..") for part in text.split("/")
    )


def _relative_path(value: str, what: str) -> str:
    """Reject anything but a plain relative path (no absolute, no ``..``/empty parts).

    Mount sources and targets are built from manifest/caller-controlled names
    (suite dir, agent). Without this a crafted agent name (``../../etc``) would
    both create a directory outside the workspace and produce a container target
    that resolves outside ``/app/workspace``.
    """
    text = str(value or "")
    if not is_plain_relative(text):
        raise InvalidRequest(f"{what} must be a plain relative path: {text!r}")
    return text


def _append_mount(
    mounts: list[Mount],
    workspace_root: str,
    host_workspace: str,
    rel: str,
    target_suffix: str,
    read_only: bool,
    *,
    mkdir: bool = False,
) -> Mount:
    """Add one bind mount.

    ``workspace_root`` is the runner's OWN view of the workspace (what it can
    stat/mkdir), ``host_workspace`` is the HOST path Docker resolves the bind
    against. They differ by construction (the runner sees the workspace at
    /app/workspace) and must never be conflated: using the host path for IO makes
    every mount fail inside the runner, and using the runner path as the bind
    source makes Docker create empty directories on the host.
    """
    rel = _relative_path(rel, "mount source")
    target = _relative_path(target_suffix, "mount target")
    local_path = os.path.join(workspace_root, rel)
    host_path = os.path.join(host_workspace, rel)
    # Before anything is created: a plain relative path is not enough, because a
    # symlink (``workspace/workflows/x -> /etc``) resolves outside the workspace and
    # Docker follows the bind source. The check is on the mount SOURCE only -- a
    # symlink *inside* a mounted tree is not a mount source and stays a container
    # problem, not this one.
    _require_inside_workspace(workspace_root, local_path, rel)
    if mkdir:
        try:
            os.makedirs(local_path, exist_ok=True)
            # The runner is root (it needs the container socket); the tool runs as
            # TRELLIS_UID. Without this hand-off a freshly created report dir is
            # root:root and read-only for the tool it was created for.
            uid, gid = _uid_gid()
            if os.geteuid() == 0 and uid is not None and gid is not None:
                os.chown(local_path, uid, gid)
        except OSError as exc:
            raise InvalidRequest(f"cannot create output dir {rel}: {exc}") from exc
    elif not os.path.exists(local_path):
        raise InvalidRequest(
            f"manifest path does not exist in the runner's workspace view: {rel} "
            f"(looked at {local_path})"
        )
    mount = Mount(host_path, f"{CONTAINER_WORKSPACE}/{target}", read_only)
    mounts.append(mount)
    return mount


def _require_inside_workspace(
    workspace_root: str, local_path: str, what: str
) -> str:
    """Refuse a path whose *real* location is outside the workspace.

    :func:`_relative_path` only proves the string has no ``..``/absolute parts. A
    symlink under the workspace (``workflows/<name>`` -> ``/``, ``tools/<suite>`` ->
    ``/etc``) still passes that test while the bind mount would hand the container a
    directory the workspace never contained. ``realpath`` resolves the existing part
    of the path (the leaf may not exist yet for an output dir), so this catches a
    symlinked ancestor as well.
    """
    real_root = os.path.realpath(workspace_root)
    real_path = os.path.realpath(local_path)
    try:
        contained = os.path.commonpath([real_root, real_path]) == real_root
    except ValueError:  # different drives / mixed absolute-relative: treat as escape
        contained = False
    if not contained:
        raise InvalidRequest(
            f"{what} resolves outside the workspace: {real_path} is not under {real_root}"
        )
    return local_path


def _append_shared_mount(
    mounts: list[Mount], workspace_root: str, host_workspace: str
) -> None:
    """Mount ``workspace/shared`` read-only, when it exists (tools and workflows).

    Same rule as any other source, so it goes through the containment check instead
    of appending a :class:`Mount` directly.
    """
    if not os.path.isdir(os.path.join(workspace_root, "shared")):
        return
    _append_mount(
        mounts, workspace_root, host_workspace, "shared", "shared", read_only=True
    )


def _uid_gid() -> tuple[Optional[int], Optional[int]]:
    raw_uid = os.getenv("TRELLIS_UID")
    raw_gid = os.getenv("TRELLIS_GID")
    try:
        uid = int(raw_uid) if raw_uid else None
    except ValueError:
        uid = None
    try:
        gid = int(raw_gid) if raw_gid else None
    except ValueError:
        gid = None
    return uid, gid


def _require_user() -> str:
    """Fail closed: a container never runs without an explicit non-root uid."""
    uid, gid = _uid_gid()
    if uid is None or gid is None:
        raise InvalidRequest(
            "TRELLIS_UID and TRELLIS_GID must be set; refusing to start a container "
            "with the image's default user (which may be root)"
        )
    return f"{uid}:{gid}"


def _labels(kind: str, target: str, *, session: Optional[str] = None,
            run: Optional[str] = None) -> dict[str, str]:
    return {
        "trellis.install": os.getenv("TRELLIS_INSTALL_ID", "default"),
        "trellis.kind": kind,
        "trellis.target": target,
        "trellis.session": session or "",
        "trellis.run": run or "",
    }


def _limits(config: Any) -> tuple[int, float, int, int]:
    limits = getattr(config, "limits", None)
    memory = int(getattr(limits, "memory_mb", 512))
    cpus = float(getattr(limits, "cpus", 1.0))
    pids = int(getattr(limits, "pids", 256))
    tmpfs = int(getattr(limits, "tmpfs_mb", 128))
    if tmpfs * 2 > memory:
        # tmpfs is charged to the container's cgroup: at/over the memory limit
        # the first temp file OOM-kills the tool.
        raise InvalidRequest("limits.tmpfs_mb must be at most half of memory_mb")
    return memory, cpus, pids, tmpfs


def build_spec(
    config: ToolConfig | MCPConfig,
    *,
    kind: str,
    suite_rel: str,
    target: str,
    env: Mapping[str, str],
    host_workspace: str,
    workspace_root: Optional[str] = None,
    agent: Optional[str] = None,
    session_key: Optional[str] = None,
    run_id: Optional[str] = None,
    image: Optional[str] = None,
    default_runtime: Optional[str] = None,
) -> ContainerSpec:
    """Spec for a tool run or an MCP session container."""
    # Default to one root only for unit tests that model a runner with an
    # identically-pathed workspace; the runner always passes both.
    workspace_root = workspace_root or host_workspace
    container_suite = f"{CONTAINER_WORKSPACE}/{suite_rel}"
    mounts: list[Mount] = []
    _append_mount(
        mounts, workspace_root, host_workspace, suite_rel, suite_rel, read_only=True
    )
    _append_shared_mount(mounts, workspace_root, host_workspace)

    output_dirs = set(getattr(config, "output_dirs", None) or [])
    # Which writable dirs this container actually got, so the variables below can
    # only ever name a mount that exists (an undeclared dir is not mounted and must
    # not be announced -- a tool that writes there would fail with a confusing ENOENT
    # instead of falling back).
    mounted_output_dirs: list[str] = []
    if kind == "tool" and agent:
        for name in OUTPUT_DIRS:
            if name not in output_dirs:
                continue
            rel = f"{name}/{agent}"
            _append_mount(
                mounts, workspace_root, host_workspace, rel, rel,
                read_only=False, mkdir=True,
            )
            mounted_output_dirs.append(name)

    merged = _merge_env(config, env)
    merged.update(
        {
            "HOME": CONTAINER_TMP,
            "TMPDIR": CONTAINER_TMP,
            "TMP": CONTAINER_TMP,
            "TEMP": CONTAINER_TMP,
            "PATH": f"{container_suite}/bin:{merged.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
        }
    )
    # v0.7.2 R2: the run context, applied here and not from the caller's ``env``.
    # Two reasons: ``_merge_env`` accepts manifest-declared names only (widening that
    # set would let a caller assert an agent name, a run id or another agent's
    # directory), and these values are derived -- the name and run id from the
    # verified identity the runner resolved (a gateway call arrives as the reserved
    # ``gateway``), the dirs from the mounts just created. They are not secrets, so
    # they stay in the container configuration: a tool needs them before it reads its
    # stdin, and subprocesses it spawns inherit them without any plumbing.
    #
    # Popped first, then set: an *unattributed* call (central ``off``/``log`` with no
    # claims, or a container kind that gets no agent) must see no run context at all,
    # even when a manifest declared one of these names and the caller supplied a
    # value for it. Without the pop, a declared name would survive the merge and the
    # container would announce a writable dir it was never given.
    for _name in ("TRELLIS_AGENT_NAME", "TRELLIS_RUN_ID", *OUTPUT_DIR_VARS.values()):
        merged.pop(_name, None)
    if agent:
        merged["TRELLIS_AGENT_NAME"] = str(agent)
    if run_id:
        merged["TRELLIS_RUN_ID"] = str(run_id)
    for name in mounted_output_dirs:
        merged[OUTPUT_DIR_VARS[name]] = f"{CONTAINER_WORKSPACE}/{name}/{agent}"

    memory, cpus, pids, tmpfs_mb = _limits(config)
    user = _require_user()

    if kind in ("mcp_session", "discovery"):
        cmd = _mcp_cmd(config)  # type: ignore[arg-type]
    else:
        cmd = _tool_cmd(config, container_suite)  # type: ignore[arg-type]

    # One split at the end: whatever is not public, fixed deployment information
    # (a secret, a declared variable, a sealed credential) is handed to the process
    # on stdin instead of living in the container's configuration.
    config_env, preamble = split_env(merged)

    return ContainerSpec(
        image=_image(image),
        runtime=runtime_for(config, default_runtime),
        cmd=cmd,
        working_dir=container_suite,
        env=config_env,
        preamble_env=preamble,
        mounts=mounts,
        tmpfs={CONTAINER_TMP: tmpfs_mb},
        memory_mb=memory,
        cpus=cpus,
        pids=pids,
        network_mode=network_mode_for(config),
        labels=_labels(kind, target, session=session_key, run=run_id),
        user=user,
        kind=kind,
    )


def build_console_spec(
    command: str,
    *,
    env: Mapping[str, str],
    user_id: Optional[str] = None,
    user_email: Optional[str] = None,
    run_id: Optional[str] = None,
    image: Optional[str] = None,
    default_runtime: Optional[str] = None,
) -> ContainerSpec:
    """``bash -lc <command>`` on a throwaway tmpfs workspace, network ``none``."""
    if not isinstance(command, str) or not command.strip():
        raise InvalidRequest("console command is empty")
    merged = _base_env()
    merged.update({k: v for k, v in env.items() if k not in RESTRICTED_ENV_VARS})
    # Applied last: the scratch paths are not caller-configurable, and neither is the
    # run context (v0.7.2 R2). A console container mounts no workspace tree at all,
    # so any TRELLIS_AGENT_NAME/RUN_ID/dir variable in a caller's env would be a
    # claim about a mount that does not exist -- drop it, then set the parts the
    # runner actually resolved.
    for name in ("TRELLIS_AGENT_NAME", "TRELLIS_RUN_ID", *OUTPUT_DIR_VARS.values()):
        merged.pop(name, None)
    merged.update(
        {
            "HOME": CONTAINER_TMP,
            "TMPDIR": CONTAINER_TMP,
            "TMP": CONTAINER_TMP,
            "TEMP": CONTAINER_TMP,
        }
    )
    if user_id:
        merged["TRELLIS_USER_ID"] = str(user_id)
    if user_email:
        merged["TRELLIS_USER_EMAIL"] = str(user_email)
    if run_id:
        merged["TRELLIS_RUN_ID"] = str(run_id)
    _require_carriable_env_names(merged)
    config_env, preamble = split_env(merged)
    return ContainerSpec(
        image=_image(image),
        runtime=runtime_for(None, default_runtime),
        cmd=["bash", "-lc", command],
        working_dir="/workspace",
        env=config_env,
        preamble_env=preamble,
        mounts=[],
        tmpfs={"/workspace": 256, CONTAINER_TMP: 256},
        memory_mb=1024,
        cpus=1.0,
        pids=256,
        network_mode=POLICY_NONE,
        labels=_labels("console", "console", run=run_id),
        user=_require_user(),
        kind="console",
    )


def _workflow_limits(
    overrides: Optional[Mapping[str, Any]] = None,
) -> tuple[int, float, int, int]:
    """``(memory_mb, cpus, pids, tmpfs_mb)`` with workflow-sized defaults.

    A workflow config names only the knobs it cares about; everything else keeps
    :func:`core.models.workflow_limits` (4 GiB / 2 CPUs / 1024 pids / 1 GiB tmpfs),
    so a partial block can never silently drop the pipeline to a single tool's
    512 MiB. ``ContainerLimits`` re-checks the tmpfs-vs-memory ratio: tmpfs pages are
    charged to the container's cgroup, so a tmpfs at the memory limit turns the
    pipeline's first temp file into an OOM kill.
    """
    merged = workflow_limits().model_dump()
    for key, value in (overrides or {}).items():
        if value is None:
            continue
        merged[str(key)] = value
    try:
        limits = ContainerLimits(**merged)
    except ValidationError as exc:
        raise InvalidRequest(f"workflow limits are invalid: {exc}") from None
    return limits.memory_mb, limits.cpus, limits.pids, limits.tmpfs_mb


def _workflow_env(
    requested: Mapping[str, str],
    *,
    name: str,
    run_id: Optional[str],
    user_id: Optional[str],
    user_email: Optional[str],
) -> dict[str, str]:
    """The pipeline's environment, before the container/preamble split.

    ``requested`` is the workflow's own resolved credentials and variables --
    declared keys only, resolved by the caller from the registry. The runner cannot
    intersect with a manifest here (a workflow has none on disk), so it enforces the
    two rules it does own: a reserved control-plane name is refused outright, and a
    name no process environment can carry fails instead of being handed to a shim
    that would reject the whole preamble line.
    """
    env = _base_env()
    blocked = sorted(set(requested) & RESTRICTED_ENV_VARS)
    if blocked:
        raise InvalidRequest(f"env keys are reserved: {', '.join(blocked)}")
    for key, value in requested.items():
        if value is None:
            continue
        env[str(key)] = str(value)
    env.update(
        {
            "HOME": CONTAINER_TMP,
            "TMPDIR": CONTAINER_TMP,
            "TMP": CONTAINER_TMP,
            "TEMP": CONTAINER_TMP,
        }
    )
    # Identity, not secrets: these stay in the container configuration so the
    # pipeline and every tool it shells out to can attribute what they do.
    if user_id:
        env["TRELLIS_USER_ID"] = str(user_id)
    if user_email:
        env["TRELLIS_USER_EMAIL"] = str(user_email)
    if run_id:
        env["TRELLIS_RUN_ID"] = str(run_id)
    # v0.7.2 R2: the workflow's own writable dirs, at the paths build_workflow_spec
    # mounts rw for every run, plus the workflow's name -- the ground truth is the
    # validated ``name`` here, not whatever the caller put in ``requested`` (the
    # worker does send TRELLIS_AGENT_NAME; a different caller may send nothing, or
    # something else). Applied after ``requested`` so neither can be redirected.
    env["TRELLIS_AGENT_NAME"] = name
    for output in OUTPUT_DIRS:
        env[OUTPUT_DIR_VARS[output]] = f"{CONTAINER_WORKSPACE}/{output}/{name}"
    _require_carriable_env_names(env)
    return env


def _workflow_cmd(
    container_workflow: str,
    entrypoint: str,
    runtime: Optional[str],
    args: Sequence[str],
) -> list[str]:
    """``[interpreter, <workflow dir>/<entrypoint>, *args]`` inside the container."""
    runtime = runtime or DEFAULT_WORKFLOW_RUNTIME
    prefix = WORKFLOW_RUNTIMES.get(str(runtime).strip().lower())
    if prefix is None:
        raise InvalidRequest(
            f"unsupported workflow runtime {runtime!r} "
            f"(expected {', '.join(sorted(WORKFLOW_RUNTIMES))})"
        )
    return [*prefix, f"{container_workflow}/{entrypoint}", *(str(a) for a in args)]


def build_workflow_spec(
    *,
    name: str,
    entrypoint: str,
    env: Mapping[str, str],
    host_workspace: str,
    workspace_root: Optional[str] = None,
    runtime: Optional[str] = None,
    args: Sequence[str] = (),
    tool_suites: Sequence[str] = (),
    run_id: Optional[str] = None,
    user_id: Optional[str] = None,
    user_email: Optional[str] = None,
    network: Optional[str] = None,
    limits: Optional[Mapping[str, Any]] = None,
    image: Optional[str] = None,
    default_runtime: Optional[str] = None,
) -> ContainerSpec:
    """Spec for one ``background_script`` run: a whole pipeline in one container.

    The mounts are the v0.7 taskiq-worker layout, frozen so the pipeline sees the
    same paths it always did and reads only what it declared:

    * ``workspace/workflows/<name>`` -- read-only. Also the container's working
      directory, so a pipeline that uses relative paths keeps working.
    * ``workspace/shared`` -- read-only, when it exists (same rule as a tool).
    * ``workspace/tools/<suite>`` -- read-only, one per suite that contains a tool
      the workflow declared in ``allowed_tools``. A tool that is *not* declared is
      simply not on the filesystem, which is the whole enforcement for workflows:
      no token, no hub round trip. Only local suites can be mounted -- an edge tool
      or a central/edge MCP tool is a registry/network reference with no directory
      here, so it mounts nothing (a workflow may still declare it for its token's
      allowlist; it just will not find files for it).
    * ``workspace/output/<name>`` and ``workspace/reports/<name>`` -- read-write,
      created if missing, so a report tool writing ``reports/<name>/`` works. Each is
      announced to the pipeline as ``TRELLIS_REPORTS_DIR``/``TRELLIS_OUTPUT_DIR`` at
      exactly that path, so a pipeline never has to hard-code it.
    * ``/tmp`` -- tmpfs, the only writable scratch space (rootfs is read-only).

    ``tool_suites`` are plain suite directory names (``demo``), resolved by the
    runner from the same manifest scan it uses for tool calls; this function never
    reads a manifest.

    Environment: the caller's declared credentials and variables go through the
    Phase 5 split, so a secret is never in the create body. Network: ``none`` or
    ``egress`` (default) from the workflow config. Limits: workflow defaults, with
    whatever the config overrides.
    """
    name = _relative_path(name, "workflow name")
    entrypoint = _relative_path(entrypoint, "workflow entrypoint")
    workspace_root = workspace_root or host_workspace
    workflow_rel = f"{WORKFLOW_DIR}/{name}"
    container_workflow = f"{CONTAINER_WORKSPACE}/{workflow_rel}"

    mounts: list[Mount] = []
    _append_mount(
        mounts, workspace_root, host_workspace, workflow_rel, workflow_rel,
        read_only=True,
    )
    # Fail before a container exists: a typo in the entrypoint must be a 400 with
    # the path the runner looked at, not an empty container that exits 2.
    if not os.path.isfile(os.path.join(workspace_root, workflow_rel, entrypoint)):
        raise InvalidRequest(
            f"workflow {name!r} has no entrypoint {entrypoint!r} "
            f"(looked at {workflow_rel}/{entrypoint})"
        )

    _append_shared_mount(mounts, workspace_root, host_workspace)

    suite_rels = {
        f"tools/{_relative_path(suite, 'tool suite')}" for suite in tool_suites
    }
    for rel in sorted(suite_rels):
        _append_mount(mounts, workspace_root, host_workspace, rel, rel, read_only=True)

    for output in OUTPUT_DIRS:
        rel = f"{output}/{name}"
        _append_mount(
            mounts, workspace_root, host_workspace, rel, rel, read_only=False, mkdir=True
        )

    memory, cpus, pids, tmpfs_mb = _workflow_limits(limits)
    merged = _workflow_env(
        env, name=name, run_id=run_id, user_id=user_id, user_email=user_email
    )
    # One split at the end: declared credentials/variables ride the stdin preamble,
    # never the container's configuration.
    config_env, preamble = split_env(merged)

    return ContainerSpec(
        image=_image(image),
        # A workflow has no manifest to pin a runtime; the deployment default
        # (CONTAINER_DEFAULT_RUNTIME) applies, like a console container.
        runtime=runtime_for(None, default_runtime),
        cmd=_workflow_cmd(container_workflow, entrypoint, runtime, args),
        working_dir=container_workflow,
        env=config_env,
        preamble_env=preamble,
        mounts=mounts,
        tmpfs={CONTAINER_TMP: tmpfs_mb},
        memory_mb=memory,
        cpus=cpus,
        pids=pids,
        network_mode=workflow_network_mode(network),
        labels=_labels("workflow", name, run=run_id),
        user=_require_user(),
        kind="workflow",
    )
