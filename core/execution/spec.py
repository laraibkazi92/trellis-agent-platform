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
"""

import hashlib
import ipaddress
import json
import logging
import os
import shlex
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from core.execution import netprofiles
from core.models import MCPConfig, ToolConfig, normalize_network_policy

logger = logging.getLogger(__name__)

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
KNOWN_RUNTIMES = ("runsc", "runsc-variant", "runc")

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
    env: dict[str, str]
    mounts: list[Mount] = field(default_factory=list)
    # container path -> size in MB (tmpfs)
    tmpfs: dict[str, int] = field(default_factory=dict)
    memory_mb: int = 512
    cpus: float = 1.0
    pids: int = 256
    network_mode: str = "none"
    labels: dict[str, str] = field(default_factory=dict)
    user: Optional[str] = None
    init: bool = True
    kind: str = "tool"


def _env_names(value: Any) -> list[str]:
    """Flatten one declared-names field into env key names.

    ``secrets``/``variables`` accept a flat list *or* the documented
    ``{general: [...], user: [...], background: [...]}`` mapping (see
    ``core.discovery._resolve_requirements``). The env names are the leaves in
    both forms -- never the mapping keys.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        names: list[str] = []
        for nested in value.values():
            names.extend(_env_names(nested))
        return names
    try:
        return [str(name) for name in value]
    except TypeError:
        return []


def declared_env_keys(config: Any) -> set[str]:
    """Every env name a manifest declares, plus the identity pair."""
    keys: set[str] = set()
    for attr in ("secrets", "optional_secrets", "variables", "env"):
        # MCPConfig has a literal `env:` block: those names are part of the
        # manifest's declared environment (not caller-supplied credentials).
        keys |= {str(name) for name in _env_names(getattr(config, attr, None))}
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


def network_profile_for(config: Any, *, force_none: bool = False) -> str:
    """Manifest network, mapped onto a profile. ``allow`` -> ``internet``."""
    if force_none:
        return netprofiles.PROFILE_NONE
    declared = getattr(config, "network", None)
    return normalize_network_policy(declared, "manifest")


def runtime_for(config: Any, default: Optional[str] = None) -> str:
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
    # No TRELLIS_* names here on purpose: the only ones a tool may see are
    # TRELLIS_USER_ID/TRELLIS_USER_EMAIL, and those arrive through the declared
    # env set. Copying the runner's own TRELLIS_* would leak topology
    # (engine subnets, install id, host paths) to untrusted code.
    return base


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


def _relative_path(value: str, what: str) -> str:
    """Reject anything but a plain relative path (no absolute, no ``..``/empty parts).

    Mount sources and targets are built from manifest/caller-controlled names
    (suite dir, agent). Without this a crafted agent name (``../../etc``) would
    both create a directory outside the workspace and produce a container target
    that resolves outside ``/app/workspace``.
    """
    text = str(value or "")
    if (
        not text
        or text.startswith("/")
        or any(part in ("", ".", "..") for part in text.split("/"))
    ):
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


# --------------------------------------------------------------------------- #
# name resolution for network profiles
# --------------------------------------------------------------------------- #

DNS_ENV = {
    netprofiles.PROFILE_INTERNAL: "TOOLS_INTERNAL_DNS",
    netprofiles.PROFILE_INTERNET: "TOOLS_INTERNET_DNS",
}
# gVisor cannot use Docker's embedded resolver (127.0.0.11) on a user-defined
# network, so a container that needs DNS gets a mounted resolv.conf instead. The
# internet profile defaults to public resolvers because its whole purpose is
# public egress; an internal resolver has to be named explicitly (and its CIDR
# allowlisted in TRELLIS_INTERNAL_CIDRS, or the profile's blanket deny drops it).
DEFAULT_DNS = {
    netprofiles.PROFILE_INTERNAL: (),
    netprofiles.PROFILE_INTERNET: ("1.1.1.1", "8.8.8.8"),
}
RESOLV_DIR = ".runner-dns"
RESOLV_TARGET = "/etc/resolv.conf"


def dns_servers(profile: str) -> tuple[str, ...]:
    """Nameservers for a network profile (``()`` = leave Docker's file alone)."""
    profile = netprofiles.normalize_profile(profile)
    name = DNS_ENV.get(profile)
    if name is None:
        return ()
    raw = os.getenv(name)
    if raw is None:
        return DEFAULT_DNS[profile]
    servers: list[str] = []
    for part in raw.replace(",", " ").split():
        try:
            servers.append(str(ipaddress.ip_address(part)))
        except ValueError:
            logger.warning("ignoring invalid nameserver %r in %s", part, name)
    return tuple(servers)


def _mount_resolv_conf(
    mounts: list[Mount],
    profile: str,
    workspace_root: str,
    host_workspace: str,
) -> None:
    """Bind a generated resolv.conf over the container's, when DNS is configured.

    Docker writes 127.0.0.11 (its embedded resolver) into every container on a
    user-defined network, and gVisor's netstack cannot reach it: name resolution
    fails in every profile that has a network. The file is written once per
    profile under the workspace -- which is mounted read-write into the runner
    and is the only path Docker can use as a bind source -- and mounted
    read-only. It holds resolver addresses only, never anything secret.
    """
    servers = dns_servers(profile)
    if not servers:
        return
    rel = os.path.join(RESOLV_DIR, f"{profile}.conf")
    local = os.path.join(workspace_root, rel)
    os.makedirs(os.path.dirname(local), exist_ok=True)
    body = "".join(f"nameserver {server}\n" for server in servers)
    tmp = f"{local}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(tmp, 0o644)
    os.replace(tmp, local)
    mounts.append(Mount(os.path.join(host_workspace, rel), RESOLV_TARGET, True))


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
    if os.path.isdir(os.path.join(workspace_root, "shared")):
        mounts.append(
            Mount(
                os.path.join(host_workspace, "shared"),
                f"{CONTAINER_WORKSPACE}/shared",
                True,
            )
        )

    output_dirs = set(getattr(config, "output_dirs", None) or [])
    if kind == "tool" and agent:
        for name in OUTPUT_DIRS:
            if name not in output_dirs:
                continue
            rel = f"{name}/{agent}"
            _append_mount(
                mounts, workspace_root, host_workspace, rel, rel,
                read_only=False, mkdir=True,
            )

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

    memory, cpus, pids, tmpfs_mb = _limits(config)
    profile = network_profile_for(config)
    _mount_resolv_conf(mounts, profile, workspace_root, host_workspace)
    user = _require_user()

    if kind in ("mcp_session", "discovery"):
        cmd = _mcp_cmd(config)  # type: ignore[arg-type]
    else:
        cmd = _tool_cmd(config, container_suite)  # type: ignore[arg-type]

    return ContainerSpec(
        image=_image(image),
        runtime=runtime_for(config, default_runtime),
        cmd=cmd,
        working_dir=container_suite,
        env=merged,
        mounts=mounts,
        tmpfs={CONTAINER_TMP: tmpfs_mb},
        memory_mb=memory,
        cpus=cpus,
        pids=pids,
        network_mode=netprofiles.network_mode(profile),
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
    # Applied last: the scratch paths are not caller-configurable.
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
    return ContainerSpec(
        image=_image(image),
        runtime=runtime_for(None, default_runtime),
        cmd=["bash", "-lc", command],
        working_dir="/workspace",
        env=merged,
        mounts=[],
        tmpfs={"/workspace": 256, CONTAINER_TMP: 256},
        memory_mb=1024,
        cpus=1.0,
        pids=256,
        network_mode="none",
        labels=_labels("console", "console", run=run_id),
        user=_require_user(),
        kind="console",
    )
