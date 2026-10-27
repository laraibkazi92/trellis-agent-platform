# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The runner service: the only component allowed to talk to the container daemon.

Callers name a registered target and hand over stdin bytes; the runner resolves the
manifest on disk, checks the caller's digest, derives a hardened container spec
(``core.execution.spec``) and runs it through ``ContainerBackend``. It serves a
Unix-socket HTTP API (no TCP listener, no network namespace of its own) so the
control plane cannot be reached from a tool container, and it fails closed: a
missing runtime, a missing image or a broken host-path mount stop it at startup
instead of degrading to a weaker sandbox.

Capacity is enforced without blocking: two semaphores (global + per target) guard
container slots, and a caller that finds none gets ``429 capacity_exhausted`` so the
hub can retry elsewhere instead of piling up open requests.

A session (a long-lived stdio MCP server, or a throwaway discovery run) holds its
capacity slot for its whole lifetime and is driven over ``/v1/sessions/{id}``: stdin
is raw bytes, stdout is re-framed as ``tag(1) + length(4, big-endian) + payload``
so one stream carries both stdout and stderr. The registry is in-process on purpose
-- a restart kills every session, which is cheaper and safer than trying to
re-adopt containers whose stdin socket the old process owned.
"""

import argparse
import asyncio
import json
import hmac
import logging
import os
import signal
import struct
import sys
import time
import uuid
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional, Sequence

import uvicorn
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from core import agent_token as agent_token_module
from core import allowlist
from core.execution import canary, spec
from core.execution.backend import (
    AttachHandle,
    BackendError,
    ContainerBackend,
    get_backend,
)
from core.execution.client import RunnerClient, socket_path
from core.execution.contract import (
    ExecRequest,
    ExecResult,
    HealthInfo,
    SessionCreateRequest,
    SessionInfo,
)
from core.models import MCPConfig, ToolConfig

logger = logging.getLogger(__name__)

DEFAULT_WORKSPACE_ROOT = "/app/workspace"
DEFAULT_RUNTIME = "runsc"
DEFAULT_MAX_CONTAINERS = 32
DEFAULT_MAX_CONTAINERS_PER_TOOL = 8
DEFAULT_REAP_INTERVAL_S = 300
SOCKET_READY_TIMEOUT_S = 10.0

# Containers no client may re-adopt after a runner restart.
SESSION_KINDS = frozenset({"mcp_session", "discovery"})
ONE_SHOT_KINDS = frozenset({"tool", "console", "canary"})

# Total bytes buffered per session before the reader stops draining the attach
# socket. The container then blocks on its pipe -- that IS the backpressure.
SESSION_BUFFER_BYTES = 1024 * 1024
MAX_SESSION_STDIN_BYTES = 8 * 1024 * 1024
# A session whose stdout consumer is gone cannot be used again (the transport
# reads that stream for its whole life), so free its container and slot promptly
# instead of waiting for the hard deadline.
SESSION_ABANDON_GRACE_S = 60.0
# JSON-RPC methods a discovery session may issue.
_DISCOVERY_METHODS = frozenset({
    "initialize",
    "ping",
    "tools/list",
    "notifications/initialized",
    "notifications/cancelled",
})
# Slack on top of a session's own deadline before the reaper kills it.
SESSION_DEADLINE_GRACE_S = 5.0

# Wire framing for the stdout stream: 1 stream tag + 4-byte big-endian length.
SESSION_FRAME = struct.Struct(">BI")

# Backend failures the caller can act on; anything else is an internal error.
_BACKEND_STATUS = {
    "timeout": 504,
    "runtime_missing": 503,
    "image_missing": 503,
    "daemon_unavailable": 503,
    "capacity_exhausted": 429,
}
_BACKEND_RETRYABLE = frozenset({"capacity_exhausted", "daemon_unavailable"})


# --------------------------------------------------------------------------- #
# settings
# --------------------------------------------------------------------------- #


def _dev_mode() -> bool:
    return os.getenv("DEV_MODE", "false").lower() == "true"


def _env_positive(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, "") or default)
    except ValueError:
        return default
    return value if value > 0 else default


def _workspace_root() -> str:
    """The runner's own view of the workspace (where manifests are read from)."""
    return (os.getenv("WORKSPACE_ROOT") or DEFAULT_WORKSPACE_ROOT).rstrip("/") or "/"


def _host_workspace() -> str:
    """The HOST path of the same directory; Docker resolves bind mounts against it."""
    value = os.getenv("TRELLIS_HOST_WORKSPACE", "").strip()
    if not value:
        raise RuntimeError("TRELLIS_HOST_WORKSPACE is not set")
    return value


def _default_runtime() -> str:
    return (os.getenv("CONTAINER_DEFAULT_RUNTIME") or DEFAULT_RUNTIME).strip()


def _runner_image() -> str:
    return (os.getenv("RUNNER_IMAGE") or os.getenv("TRELLIS_IMAGE") or "").strip()


# --------------------------------------------------------------------------- #
# startup configuration gate
# --------------------------------------------------------------------------- #


def _require_configuration() -> None:
    """Refuse a configuration the runner cannot be correct with (loud, no default)."""
    try:
        _host_workspace()
    except RuntimeError:
        raise SystemExit(
            "runner: TRELLIS_HOST_WORKSPACE is not set. It must be the HOST path of the "
            "workspace directory (the same files the runner sees under "
            f"{_workspace_root()!r}), not a path inside the runner container. "
            "Without it every container mount would point at the wrong files."
        ) from None

    if os.getenv("RUNNER_TOKEN", ""):
        return
    if _dev_mode():
        logger.warning(
            "\n%s\n  WARNING: runner is running in DEV_MODE with no RUNNER_TOKEN -- "
            "the control API accepts unauthenticated requests on its socket.\n%s",
            "=" * 74,
            "=" * 74,
        )
        return
    raise SystemExit(
        "runner: RUNNER_TOKEN is not set. Refusing to start an unauthenticated control "
        "API (the socket is the only thing that can create containers). Set RUNNER_TOKEN, "
        "or DEV_MODE=true for a local development instance."
    )


# --------------------------------------------------------------------------- #
# manifest cache / target resolution
# --------------------------------------------------------------------------- #

_MANIFESTS = (
    ("tool", "tools", "tool.yaml", ToolConfig),
    ("mcp", "mcps", "mcp.yaml", MCPConfig),
)

# path -> ((mtime_ns, size), parsed configs). A per-call stat is enough to notice a
# manifest edit; parsing only happens when the file actually changed.
_manifest_cache: dict[str, tuple[tuple[int, int], list[Any]]] = {}


@dataclass(frozen=True)
class Target:
    """A local, executable tool manifest and the suite directory it lives in."""

    config: ToolConfig
    suite: str
    path: str


def _manifest_paths(base: str, filename: str) -> list[str]:
    try:
        suites = sorted(os.listdir(base))
    except OSError:
        return []
    paths = []
    for suite in suites:
        path = os.path.join(base, suite, filename)
        if os.path.isfile(path):
            paths.append(path)
    return paths


def _parse_manifest(path: str, model: type) -> list[Any]:
    """Parse one manifest file; a bad entry is logged and skipped, never guessed at."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        logger.error("runner: cannot read manifest %s: %s", path, exc)
        return []
    entries = raw if isinstance(raw, list) else [raw]
    configs = []
    for entry in entries:
        if not isinstance(entry, dict):
            logger.error("runner: ignoring a non-mapping entry in %s", path)
            continue
        try:
            configs.append(model(**entry))
        except Exception as exc:  # pydantic ValidationError / model validators
            logger.error("runner: invalid manifest entry in %s: %s", path, exc)
    return configs


def _cached_configs(path: str, model: type) -> list[Any]:
    try:
        stat = os.stat(path)
    except OSError:
        _manifest_cache.pop(path, None)
        return []
    stamp = (stat.st_mtime_ns, stat.st_size)
    cached = _manifest_cache.get(path)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    configs = _parse_manifest(path, model)
    _manifest_cache[path] = (stamp, configs)
    return configs


def _iter_manifests() -> Iterator[tuple[str, Any]]:
    root = _workspace_root()
    for kind, subdir, filename, model in _MANIFESTS:
        for path in _manifest_paths(os.path.join(root, subdir), filename):
            for config in _cached_configs(path, model):
                yield kind, config


def resolve_target(name: str) -> Optional[Target]:
    """Find a local tool by registry name; a ``remote`` manifest is not local."""
    root = _workspace_root()
    for path in _manifest_paths(os.path.join(root, "tools"), "tool.yaml"):
        suite = os.path.basename(os.path.dirname(path))
        for config in _cached_configs(path, ToolConfig):
            if config.name == name and config.remote is None:
                return Target(config=config, suite=suite, path=path)
    return None


@dataclass(frozen=True)
class McpTarget:
    """A local stdio MCP manifest and the suite directory it lives in."""

    config: MCPConfig
    suite: str
    path: str


def resolve_mcp_target(name: str) -> Optional[McpTarget]:
    """Find a locally spawnable MCP by name.

    Only ``stdio`` manifests without a ``remote`` spec can become a container:
    http/sse servers are reached over the network by the client, and an edge
    server's process lives on the edge.
    """
    root = _workspace_root()
    for path in _manifest_paths(os.path.join(root, "mcps"), "mcp.yaml"):
        suite = os.path.basename(os.path.dirname(path))
        for config in _cached_configs(path, MCPConfig):
            if (
                config.name == name
                and config.transport == "stdio"
                and config.remote is None
            ):
                return McpTarget(config=config, suite=suite, path=path)
    return None


# --------------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Check:
    """One startup gate, reported by the API and by ``scripts/runner_preflight.py``."""

    name: str
    ok: bool
    message: str
    skipped: bool = False


def startup_ready(checks: Sequence[Check]) -> bool:
    """True only when every gate passed; the entrypoint exits non-zero otherwise."""
    return bool(checks) and all(check.ok for check in checks)


async def _check_runtime(backend: ContainerBackend) -> Check:
    """The configured runtime must be registered with the daemon -- no more.

    ``runsc`` is the default; ``runc`` is a legitimate choice here (a dev
    machine, or a per-tool ``container_runtime``) and only costs kernel-syscall
    isolation.
    """
    runtime = _default_runtime()
    if not await backend.has_runtime(runtime):
        return Check(
            "runtime",
            False,
            f"container runtime {runtime!r} is not registered with the container daemon. "
            "Register it in /etc/docker/daemon.json and restart Docker, or set "
            "CONTAINER_DEFAULT_RUNTIME to a runtime that is registered "
            "(runsc for syscall isolation, runc on a dev machine).",
        )
    if runtime == "runc":
        return Check(
            "runtime",
            True,
            "container runtime 'runc' is registered (no kernel-syscall isolation; "
            "intended for dev machines or a deliberate per-tool choice)",
        )
    return Check("runtime", True, f"container runtime {runtime!r} is registered")


async def _check_image(backend: ContainerBackend) -> Check:
    image = _runner_image()
    if not image:
        return Check(
            "image",
            False,
            "RUNNER_IMAGE (or TRELLIS_IMAGE) is not set; every container starts from "
            "that image and the runner never pulls one.",
        )
    if await backend.has_image(image):
        return Check("image", True, f"image {image!r} is present locally")
    return Check(
        "image",
        False,
        f"image {image!r} is not present locally. Build or load it, or point "
        "RUNNER_IMAGE at an image that exists; the runner never pulls one.",
    )


async def _check_tool_identity() -> Check:
    """A container must never inherit the image's default (possibly root) user."""
    uid = (os.getenv("TRELLIS_UID") or "").strip()
    gid = (os.getenv("TRELLIS_GID") or "").strip()
    if uid.isdigit() and gid.isdigit():
        return Check(
            "tool_identity", True, f"tool containers run as {uid}:{gid} (non-root)"
        )
    return Check(
        "tool_identity",
        False,
        "TRELLIS_UID and TRELLIS_GID must be set to the workspace owner's numeric "
        "uid/gid. Without them a tool container would run as the image default, "
        "which is root.",
    )


async def _check_manifest_runtimes(backend: ContainerBackend) -> Check:
    declared: dict[str, str] = {}
    for kind, config in _iter_manifests():
        try:
            runtime = spec.runtime_for(config)
        except spec.InvalidRequest as exc:
            return Check(
                "manifest_runtimes",
                False,
                f"{kind} {getattr(config, 'name', '?')!r} declares an unusable runtime: "
                f"{exc.message}",
            )
        declared.setdefault(runtime, f"{kind}:{getattr(config, 'name', '?')}")

    missing = [name for name in sorted(declared) if not await backend.has_runtime(name)]
    if missing:
        detail = ", ".join(f"{name} (declared by {declared[name]})" for name in missing)
        return Check(
            "manifest_runtimes",
            False,
            f"runtime(s) declared by manifests are not registered: {detail}",
        )
    if not declared:
        return Check(
            "manifest_runtimes",
            True,
            "skipped: no tool or MCP manifest declares a container runtime",
            skipped=True,
        )
    return Check(
        "manifest_runtimes",
        True,
        "manifest runtimes registered: " + ", ".join(sorted(declared)),
    )


async def run_preflight(backend: Optional[ContainerBackend] = None) -> list[Check]:
    """The startup gates, in order. The host-path canary runs afterwards."""
    backend = backend or get_backend()
    return [
        await _check_runtime(backend),
        await _check_image(backend),
        await _check_tool_identity(),
        await _check_manifest_runtimes(backend),
    ]


# --------------------------------------------------------------------------- #
# health state
# --------------------------------------------------------------------------- #


@dataclass
class _State:
    preflight_ok: bool = False
    preflight_detail: str = "startup preflight has not run"
    # Optimistic until a canary actually fails: tests and --healthcheck probes do
    # not run startup, and only a *failed* canary may close the exec path.
    canary_ok: bool = True
    canary_detail: str = ""


_state = _State()


def health_info() -> HealthInfo:
    detail = "; ".join(
        part for part in (_state.preflight_detail, _state.canary_detail) if part
    )
    return HealthInfo(
        ok=_state.preflight_ok and _state.canary_ok,
        runtime=_default_runtime(),
        image=_runner_image(),
        install_id=os.getenv("TRELLIS_INSTALL_ID", "default"),
        active_sessions=len(_sessions),
        detail=detail or "ok",
    )


def _apply_preflight(checks: Sequence[Check]) -> None:
    failed = [check for check in checks if not check.ok]
    _state.preflight_ok = bool(checks) and not failed
    _state.preflight_detail = (
        "" if not failed else "; ".join(f"{c.name}: {c.message}" for c in failed)
    )


def _apply_canary(result: canary.CanaryResult) -> None:
    _state.canary_ok = result.ok
    _state.canary_detail = "" if result.ok else result.detail


async def _run_canary(backend: ContainerBackend) -> canary.CanaryResult:
    return await canary.run(
        backend,
        host_workspace=_host_workspace(),
        workspace_root=_workspace_root(),
        image=_runner_image(),
        runtime=_default_runtime(),
    )


async def recheck_canary(
    backend: Optional[ContainerBackend] = None,
) -> canary.CanaryResult:
    """Re-run the host-path canary (SIGHUP, periodic, endpoint tests)."""
    result = await _run_canary(backend or get_backend())
    _apply_canary(result)
    if not result.ok:
        logger.error("runner: host-path canary re-check failed -- %s", result.detail)
    return result


async def full_preflight(
    backend: Optional[ContainerBackend] = None,
) -> list[Check]:
    """Every gate including the canary -- what ``POST /v1/preflight`` reports.

    The canary is skipped when an earlier gate failed: with no image or runtime the
    container cannot start, and the failure is already in the report.
    """
    backend = backend or get_backend()
    checks = list(await run_preflight(backend))
    _apply_preflight(checks)
    if not startup_ready(checks):
        checks.append(
            Check("canary", False, "skipped: an earlier check failed", skipped=True)
        )
        return checks
    result = await _run_canary(backend)
    _apply_canary(result)
    checks.append(
        Check(
            "canary",
            result.ok,
            result.detail or "container read the canary file back through the host path",
        )
    )
    return checks


async def reap_one_shot(backend: Optional[ContainerBackend] = None) -> int:
    """Remove this install's owned containers left by a previous process.

    A SIGKILLed runner leaves ``AutoRemove=false`` containers behind forever, and
    a session can never survive a restart: its stdin socket died with the old
    process. So both the one-shot kinds and the session kinds are dead state
    here, and clients simply respawn lazily.
    """
    backend = backend or get_backend()
    install = os.getenv("TRELLIS_INSTALL_ID", "default")
    removed = 0
    try:
        containers = await backend.list_containers({"trellis.install": install})
    except Exception as exc:
        logger.warning("runner: cannot list containers for the startup sweep: %s", exc)
        return 0
    for container in containers:
        labels = (container.get("Config") or {}).get("Labels") or container.get("Labels") or {}
        kind = labels.get("trellis.kind")
        if kind not in ONE_SHOT_KINDS and kind not in SESSION_KINDS:
            continue
        container_id = container.get("Id") or ""
        if not container_id:
            continue
        try:
            await backend.remove(container_id)
            removed += 1
        except Exception:
            logger.debug("runner: could not remove leftover %s", container_id, exc_info=True)
    if removed:
        logger.info("runner: reaped %d leftover container(s)", removed)
    return removed


async def startup(backend: Optional[ContainerBackend] = None) -> list[Check]:
    """Fail closed: log every failed gate, then refuse to serve."""
    agent_token_module.require_secret("runner")
    checks = await full_preflight(backend)
    failed = [check for check in checks if not check.ok]
    for check in failed:
        logger.error("runner startup check FAILED: %s -- %s", check.name, check.message)
    if failed:
        raise SystemExit(1)
    logger.info("runner startup checks passed")
    await reap_one_shot(backend)
    return checks


# --------------------------------------------------------------------------- #
# authorization
# --------------------------------------------------------------------------- #

# The runner has no etcd client (deliberate: tool execution must not depend on
# the registry). Agent allowlists are read from the workspace manifests instead,
# with a short mtime cache so an operator edit lands without a restart.
_AGENT_MANIFESTS = (("agents", "agent"), ("workflows", "workflow"))
_agent_cache: dict[str, tuple[tuple[int, int], Optional[dict]]] = {}


def _agent_manifest(agent: str) -> Optional[dict]:
    if not agent or "/" in agent or agent in {".", ".."}:
        return None
    root = _workspace_root()
    for subdir, _kind in _AGENT_MANIFESTS:
        path = os.path.join(root, subdir, agent, "config.yaml")
        try:
            stat = os.stat(path)
        except OSError:
            continue
        stamp = (stat.st_mtime_ns, stat.st_size)
        cached = _agent_cache.get(path)
        if cached is not None and cached[0] == stamp:
            return cached[1]
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = yaml.safe_load(handle)
        except (OSError, yaml.YAMLError):
            logger.error("runner: cannot read agent manifest %s", path)
            return None
        data = payload if isinstance(payload, dict) else None
        _agent_cache[path] = (stamp, data)
        return data
    return None


def _verified_claims(payload: Any) -> Optional[agent_token_module.Claims]:
    """The caller's verified claims, or ``None`` when the request carries no verified token.

    Identity in the runner comes from here and nowhere else -- the wire bodies have no
    identity fields. ``None`` is the rollout/dev posture (``ENFORCE_AGENT_TOKENS=off``,
    or ``log`` without a minting secret): the container then runs with no identity
    attribution rather than an asserted one.
    """
    if agent_token_module.mode() == "off":
        return None
    try:
        return agent_token_module.verify(getattr(payload, "agent_token", None))
    except agent_token_module.AgentTokenError:
        return None


# The resource kinds the runner itself owns: a session container and a console
# container are created and kept alive here, so the runner is the party that has to
# check the allowlist. Everything else is somebody else's decision (see _authorize).
_RUNNER_OWNED_KINDS = {"console", "mcp_session"}


def _authorize(payload: Any) -> Optional[JSONResponse]:
    """Verify the agent token and, where it owns the resource, the allowlist.

    ``tool`` callers are authorized by the hub, which read the same registry the tool
    was registered from and dispatched the call; the runner only proves the token is
    valid. Requiring an on-disk manifest here would refuse every front-door/gateway
    call -- neither has an agent record -- and the supervisor, whose manifest ships
    inside the image (``core/assets/supervisor``) and is never materialised under
    ``workspace/``.

    A session/console container *is* owned by the runner, so the agent's on-disk
    manifest is checked here, and an unrecognized kind is refused rather than trusted.

    No caller is exempt: whoever minted the token, a resource the runner owns is
    checked against that token agent's own allowlist. The one non-agent path is a
    ``kind: "discovery"`` catalog read, which carries no agent run at all and is
    gated by the runner bearer token on the control socket.
    """
    mode = agent_token_module.mode()
    if mode == "off":
        return None
    if payload.kind == "discovery" and not getattr(payload, "agent_token", None):
        # A throwaway catalog read has no agent/run behind it. The socket already
        # requires the runner bearer token; a supplied agent token must still verify.
        return None
    try:
        claims = agent_token_module.verify(getattr(payload, "agent_token", None))
    except agent_token_module.AgentTokenError as exc:
        if mode == "log" and exc.code in {"missing", "missing_secret"}:
            # Rollout mode with no key/token: nothing to enforce yet, and warning
            # on every call would drown the log.
            return None
        message = f"access_denied: agent token rejected ({exc.code})"
        if mode == "log":
            logger.warning("runner: would deny %r: %s", payload.kind, message)
            return None
        return _error(403, "access_denied", message)

    if payload.kind == "discovery":
        # Throwaway catalog read: no agent owns it, and the socket already
        # requires the runner bearer token.
        return None

    claimed_agent = claims.agent

    # The edge runner has no agent manifests and no registry: the relay already
    # made the allowlist decision on the same call. Signature/expiry only there.
    if (os.getenv("RUNNER_AUTHORIZATION") or "allowlist").strip().lower() == "signature":
        return None

    if payload.kind == "tool":
        # The hub authorized this call before dispatch (local and edge tools alike),
        # against the same registry the target was resolved from. Re-deriving an
        # allowlist from a workspace manifest here cannot work: the gateway has no
        # agent record at all and the supervisor's manifest is an image asset.
        return None

    if payload.kind not in _RUNNER_OWNED_KINDS:
        message = f"access_denied: unrecognized exec kind '{payload.kind}'"
        if mode == "log":
            logger.warning("runner: would deny %r: %s", payload.kind, message)
            return None
        return _error(403, "access_denied", message)

    manifest = _agent_manifest(claimed_agent)
    if manifest is None:
        message = f"access_denied: unknown agent '{claimed_agent}'"
        if mode == "log":
            logger.warning("runner: would deny %r: %s", payload.kind, message)
            return None
        return _error(403, "access_denied", message)

    allowed = allowlist.resolve(manifest)
    if payload.kind == "mcp_session":
        permitted = allowlist.permits_mcp_session(allowed, payload.target)
    else:  # console: the runtime's own console tools
        permitted = "execute" in allowed.console
    if not permitted:
        message = agent_token_module.deny_message(claimed_agent, payload.target)
        if mode == "log":
            logger.warning("runner: would deny %r: %s", payload.kind, message)
            return None
        return _error(403, "access_denied", message)
    return None


# --------------------------------------------------------------------------- #
# capacity
# --------------------------------------------------------------------------- #


@dataclass
class _Capacity:
    loop: asyncio.AbstractEventLoop
    global_sem: asyncio.Semaphore
    global_limit: int
    per_target: dict[str, asyncio.Semaphore]
    per_target_limit: int


_capacity: Optional[_Capacity] = None


def _capacity_for_loop() -> _Capacity:
    """Semaphores are loop-bound; rebuild them when the serving loop changes."""
    global _capacity
    loop = asyncio.get_running_loop()
    if _capacity is None or _capacity.loop is not loop:
        global_limit = _env_positive("RUNNER_MAX_CONTAINERS", DEFAULT_MAX_CONTAINERS)
        _capacity = _Capacity(
            loop=loop,
            global_sem=asyncio.Semaphore(global_limit),
            global_limit=global_limit,
            per_target={},
            per_target_limit=_env_positive(
                "RUNNER_MAX_CONTAINERS_PER_TOOL", DEFAULT_MAX_CONTAINERS_PER_TOOL
            ),
        )
    return _capacity


def _target_semaphore(target: str) -> asyncio.Semaphore:
    """Per-target slot pool (tests hold one to pin the 429 path)."""
    capacity = _capacity_for_loop()
    semaphore = capacity.per_target.get(target)
    if semaphore is None:
        semaphore = asyncio.Semaphore(capacity.per_target_limit)
        capacity.per_target[target] = semaphore
    return semaphore


async def _acquire_slots(target: str) -> Optional[tuple[_Capacity, asyncio.Semaphore]]:
    """Take a global and a per-target slot, or ``None`` -- never waits."""
    capacity = _capacity_for_loop()
    target_sem = _target_semaphore(target)
    if capacity.global_sem.locked() or target_sem.locked():
        return None
    # No suspension between the checks and the acquires: an unlocked
    # Semaphore.acquire() completes instantly, so another task cannot take the slot.
    await target_sem.acquire()
    await capacity.global_sem.acquire()
    return capacity, target_sem


# --------------------------------------------------------------------------- #
# session registry
# --------------------------------------------------------------------------- #


@dataclass
class _Session:
    """One live session container and the caller-facing state of its stream."""

    session_id: str
    container_id: str
    target: str
    kind: str
    session_key: str
    created_at: float
    deadline_ms: int
    attach: AttachHandle
    capacity: _Capacity
    target_sem: asyncio.Semaphore
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    drained: asyncio.Event = field(default_factory=asyncio.Event)
    reader: Optional[asyncio.Task] = None
    state: str = "running"
    exit_code: Optional[int] = None
    bytes_out: int = 0
    queued_bytes: int = 0
    last_activity: float = field(default_factory=time.time)
    streaming: bool = False
    unconsumed_since: Optional[float] = None


# In-process by design: a second worker would double-count capacity and reap a
# colleague's containers, and a session cannot outlive the socket that owns it.
_sessions: dict[str, _Session] = {}
# Container ids between create and registry insertion: the reaper must not treat
# a half-open session as a stray and remove it under the opening request.
_opening: set[str] = set()


def _session_info(session: _Session) -> SessionInfo:
    return SessionInfo(
        session_id=session.session_id,
        container_id=session.container_id,
        created_at=session.created_at,
        state=session.state,
        exit_code=session.exit_code,
        bytes_out=session.bytes_out,
        idle_s=max(0.0, time.time() - session.last_activity),
    )


async def _exit_code(backend: ContainerBackend, container_id: str) -> Optional[int]:
    """Best-effort exit code: a container already removed reports nothing."""
    try:
        state = (await backend.inspect(container_id)).get("State") or {}
        return int(state.get("ExitCode") or 0)
    except Exception:
        logger.debug(
            "runner: cannot inspect %s for its exit code", container_id, exc_info=True
        )
        return None


async def _pump_session(session: _Session) -> None:
    """Drain the attach socket into the caller's buffer, one frame at a time.

    Reading is paused while the buffer is full, which blocks the container on a
    full pipe: a server that logs too much is throttled instead of having its
    output silently dropped or buffered in the runner without bound.
    """
    eof = False
    try:
        while True:
            try:
                frame = await session.attach.read_frame()
            except Exception:
                logger.debug(
                    "runner: session %s attach read failed",
                    session.session_id,
                    exc_info=True,
                )
                frame = None
            if frame is None:
                eof = True
                break
            tag, payload = frame
            if not payload:
                continue
            while (
                session.queued_bytes > 0
                and session.queued_bytes + len(payload) > SESSION_BUFFER_BYTES
            ):
                session.drained.clear()
                await session.drained.wait()
            session.queued_bytes += len(payload)
            session.bytes_out += len(payload)
            session.last_activity = time.time()
            session.queue.put_nowait((tag, payload))
    except Exception:
        logger.exception("runner: session %s reader crashed", session.session_id)
        eof = True
    finally:
        # Cancelled (DELETE/expiry) means the caller is gone: no sentinel, no inspect.
        # A `CancelledError` is a BaseException, so it reaches this block with
        # `eof` still False.
        if eof:
            session.state = "exited"
            session.exit_code = await _exit_code(get_backend(), session.container_id)
            session.queue.put_nowait(None)


def _release_slots(session: _Session) -> None:
    """Give the session's capacity slot back exactly once (DELETE or expiry)."""
    session.target_sem.release()
    session.capacity.global_sem.release()


async def _destroy_session(session: _Session) -> None:
    """Tear a session down for good: stop the reader, kill, remove, free the slot."""
    _sessions.pop(session.session_id, None)
    reader, session.reader = session.reader, None
    if reader is not None:
        reader.cancel()
        with suppress(BaseException):
            await reader
    with suppress(Exception):
        await session.attach.close()
    backend = get_backend()
    with suppress(Exception):
        await backend.kill(session.container_id)
    with suppress(Exception):
        await backend.remove(session.container_id)
    _release_slots(session)
    session.state = "closed"
    logger.info("runner: session %s closed", session.session_id)


async def reap_sessions(
    backend: Optional[ContainerBackend] = None,
    *,
    now: Optional[float] = None,
    grace_s: Optional[float] = None,
) -> int:
    """Kill expired sessions, then remove session containers no registry owns.

    The second half is what makes a crash survivable: a container created by a
    previous process (or one whose create/attach failed halfway) has no owner and
    would otherwise sit there holding memory forever.
    """
    backend = backend or get_backend()
    now = time.time() if now is None else now
    grace = SESSION_DEADLINE_GRACE_S if grace_s is None else grace_s
    removed = 0

    for session in list(_sessions.values()):
        expired = now - session.created_at > session.deadline_ms / 1000.0 + grace
        abandoned = (
            not session.streaming
            and now - (session.unconsumed_since or session.created_at)
            > SESSION_ABANDON_GRACE_S
        )
        if not expired and not abandoned:
            continue
        try:
            await _destroy_session(session)
            removed += 1
        except Exception:
            logger.exception("runner: could not reap session %s", session.session_id)

    live = {session.container_id for session in _sessions.values()} | _opening
    try:
        containers = await backend.list_containers(
            {"trellis.install": os.getenv("TRELLIS_INSTALL_ID", "default")}
        )
    except Exception as exc:
        logger.warning("runner: cannot list containers for the session sweep: %s", exc)
        return removed
    for container in containers:
        labels = (container.get("Config") or {}).get("Labels") or container.get("Labels") or {}
        if labels.get("trellis.kind") not in SESSION_KINDS:
            continue
        container_id = container.get("Id") or ""
        if not container_id or container_id in live:
            continue
        try:
            await backend.remove(container_id)
            removed += 1
        except Exception:
            logger.debug(
                "runner: could not remove stray session container %s",
                container_id, exc_info=True,
            )
    if removed:
        logger.info("runner: reaped %d session container(s)", removed)
    return removed


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #


def _error(
    status: int,
    code: str,
    message: str,
    *,
    retryable: bool = False,
    headers: Optional[dict[str, str]] = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"detail": {"code": code, "message": message, "retryable": retryable}},
        headers=headers,
    )


def _authenticate(request: Request) -> Optional[JSONResponse]:
    """Constant-time bearer check. An empty token is only legal in DEV_MODE."""
    expected = os.getenv("RUNNER_TOKEN", "")
    header = request.headers.get("authorization", "")
    supplied = header[7:] if header[:7].lower() == "bearer " else ""
    if not expected:
        if _dev_mode():
            return None
        return _error(
            401,
            "unauthorized",
            "RUNNER_TOKEN is not configured on the runner",
            headers={"www-authenticate": "Bearer"},
        )
    if supplied and hmac.compare_digest(supplied.encode(), expected.encode()):
        return None
    return _error(
        401,
        "unauthorized",
        "missing or invalid runner bearer token",
        headers={"www-authenticate": "Bearer"},
    )


def _backend_error(exc: BackendError) -> JSONResponse:
    status = _BACKEND_STATUS.get(exc.code)
    if status is None:
        logger.error("runner: unclassified backend error %r: %s", exc.code, exc.message)
        return _error(500, "internal", exc.message or "container backend failure")
    return _error(
        status,
        exc.code,
        exc.message or exc.code.replace("_", " "),
        retryable=exc.code in _BACKEND_RETRYABLE,
    )


def _result(raw: Any) -> ExecResult:
    # duration/container id are optional on the backend contract, so a minimal
    # backend still produces a valid result.
    return ExecResult(
        exit_code=int(raw.exit_code),
        stdout=raw.stdout.decode("utf-8", errors="replace"),
        stderr=raw.stderr.decode("utf-8", errors="replace"),
        stdout_truncated=bool(getattr(raw, "stdout_truncated", False)),
        stderr_truncated=bool(getattr(raw, "stderr_truncated", False)),
        duration_ms=int(getattr(raw, "duration_ms", 0) or 0),
        container_id=str(getattr(raw, "container_id", "") or ""),
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Background canary + session reaper; single worker, so this is the schedule."""
    loop = asyncio.get_running_loop()
    _install_sighup(loop)
    interval = _env_positive("RUNNER_REAP_INTERVAL_S", DEFAULT_REAP_INTERVAL_S)
    tasks = [
        asyncio.create_task(_canary_loop(interval), name="runner-canary"),
        asyncio.create_task(_reap_loop(interval), name="runner-reaper"),
    ]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(
    title="Trellis execution runner",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.get("/v1/healthz")
async def healthz(request: Request):
    denied = _authenticate(request)
    if denied is not None:
        return denied
    return health_info()


@app.post("/v1/preflight")
async def preflight(request: Request):
    """Full diagnostic (four gates + canary); ``ok`` in the body is the verdict."""
    denied = _authenticate(request)
    if denied is not None:
        return denied
    await full_preflight()
    return health_info()


@app.post("/v1/exec")
async def exec_tool(request: Request, payload: ExecRequest):
    denied = _authenticate(request)
    if denied is not None:
        return denied

    if not _state.canary_ok:
        return _error(
            503,
            "runner_path_mismatch",
            "the host-path canary failed; refusing new calls until it passes: "
            + (_state.canary_detail or "see /v1/healthz"),
        )

    denial = _authorize(payload)
    if denial is not None:
        return denial

    # Identity for the container: the verified claims, and nothing else. A request
    # with no verified token (off/log rollout) runs unattributed.
    claims = _verified_claims(payload)

    if payload.kind == "console":
        return await _execute_one_shot(
            "console",
            payload,
            lambda: spec.build_console_spec(
                payload.command or "",
                env=payload.env,
                user_id=claims.user_id if claims else None,
                user_email=claims.user_email if claims else None,
                run_id=claims.run_id if claims else None,
            ),
        )

    if payload.kind != "tool":
        return _error(
            400,
            "invalid_request",
            f"/v1/exec accepts kind='tool' or kind='console' (got {payload.kind!r}); "
            "sessions use /v1/sessions",
        )

    target = resolve_target(payload.target)
    if target is None:
        return _error(
            404,
            "unknown_target",
            f"no local tool named {payload.target!r} under {_workspace_root()}/tools",
        )

    expected = spec.manifest_digest(target.config)
    if not payload.manifest_digest or payload.manifest_digest != expected:
        return _error(
            409,
            "manifest_stale",
            f"manifest digest mismatch for {payload.target!r}: caller sent "
            f"{payload.manifest_digest or '<empty>'}, disk is {expected}. "
            "Re-run the registry sync so the registry matches the files.",
        )

    return await _execute_one_shot(
        payload.target,
        payload,
        lambda: spec.build_spec(
            target.config,
            kind="tool",
            suite_rel=f"tools/{target.suite}",
            target=target.config.name,
            env=payload.env,
            host_workspace=_host_workspace(),
            workspace_root=_workspace_root(),
            # Output-directory ownership follows the token's agent, so a tool can
            # only be handed `output|reports|data/<its own agent>`.
            agent=claims.agent if claims else None,
            run_id=claims.run_id if claims else None,
        ),
    )


async def _execute_one_shot(target_name: str, payload: ExecRequest, build):
    """Take a slot, derive the spec, run, and always give the slot back."""
    slots = await _acquire_slots(target_name)
    if slots is None:
        capacity = _capacity_for_loop()
        return _error(
            429,
            "capacity_exhausted",
            f"no free container slot for {target_name!r} (per-target limit "
            f"{capacity.per_target_limit}, global limit {capacity.global_limit})",
            retryable=True,
        )

    capacity, target_sem = slots
    try:
        try:
            container_spec = build()
        except spec.InvalidRequest as exc:
            return _error(400, "invalid_request", exc.message)
        except spec.ManifestStale as exc:
            return _error(409, "manifest_stale", str(exc))
        except RuntimeError as exc:
            return _error(500, "internal", f"runner configuration error: {exc}")

        backend = get_backend()
        deadline_s = max(payload.deadline_ms, 1) / 1000.0
        try:
            raw = await backend.run(
                container_spec, payload.input.encode("utf-8"), deadline_s
            )
        except spec.InvalidRequest as exc:
            return _error(400, "invalid_request", exc.message)
        except BackendError as exc:
            return _backend_error(exc)
        except Exception:
            logger.exception("runner: container backend raised for %r", target_name)
            return _error(500, "internal", "container backend failure")
    finally:
        target_sem.release()
        capacity.global_sem.release()

    return _result(raw)


# --------------------------------------------------------------------------- #
# sessions
# --------------------------------------------------------------------------- #


def _session_or_error(session_id: str):
    """Look up a live session; returns ``(session, error_response)``."""
    session = _sessions.get(session_id)
    if session is None:
        return None, _error(
            404,
            "session_not_found",
            f"no live session {session_id!r}; it exited, was reaped, or the runner "
            "restarted",
        )
    return session, None


@app.post("/v1/sessions")
async def open_session(request: Request, payload: SessionCreateRequest):
    denied = _authenticate(request)
    if denied is not None:
        return denied

    if not _state.canary_ok:
        return _error(
            503,
            "runner_path_mismatch",
            "the host-path canary failed; refusing new sessions until it passes: "
            + (_state.canary_detail or "see /v1/healthz"),
        )

    # Authorization before target/digest lookups: an unauthenticated caller must
    # not be able to enumerate targets or probe manifest digests.
    denial = _authorize(payload)
    if denial is not None:
        return denial

    target = resolve_mcp_target(payload.target)
    if target is None:
        return _error(
            404,
            "unknown_target",
            f"no local stdio MCP named {payload.target!r} under "
            f"{_workspace_root()}/mcps",
        )

    expected = spec.manifest_digest(target.config)
    if not payload.manifest_digest or payload.manifest_digest != expected:
        return _error(
            409,
            "manifest_stale",
            f"manifest digest mismatch for {payload.target!r}: caller sent "
            f"{payload.manifest_digest or '<empty>'}, disk is {expected}. "
            "Re-run the registry sync so the registry matches the files.",
        )

    slots = await _acquire_slots(payload.target)
    if slots is None:
        capacity = _capacity_for_loop()
        return _error(
            429,
            "capacity_exhausted",
            f"no free container slot for session target {payload.target!r} "
            f"(per-target limit {capacity.per_target_limit}, global limit "
            f"{capacity.global_limit})",
            retryable=True,
        )
    capacity, target_sem = slots

    backend = get_backend()
    container_id = ""
    attach: Optional[AttachHandle] = None
    opened = False
    try:
        try:
            container_spec = spec.build_spec(
                target.config,
                kind=payload.kind,
                suite_rel=f"mcps/{target.suite}",
                target=payload.target,
                env=payload.env,
                host_workspace=_host_workspace(),
                workspace_root=_workspace_root(),
                # A session mounts no agent-owned output directory, so there is no
                # agent name to pass into the spec.
                agent=None,
                session_key=payload.session_key,
                run_id=None,
            )
        except spec.InvalidRequest as exc:
            return _error(400, "invalid_request", exc.message)
        except spec.ManifestStale as exc:
            return _error(409, "manifest_stale", str(exc))
        except RuntimeError as exc:
            return _error(500, "internal", f"runner configuration error: {exc}")

        container_id = await backend.create(container_spec)
        _opening.add(container_id)
        attach = await backend.attach(container_id)
        await backend.start(container_id)
        opened = True
    except BackendError as exc:
        await _discard_session_container(backend, container_id, attach)
        return _backend_error(exc)
    except Exception:
        logger.exception("runner: cannot start session %r", payload.target)
        await _discard_session_container(backend, container_id, attach)
        return _error(500, "internal", "container backend failure")
    except BaseException:
        # A cancellation during create/attach/start must still not leak the
        # container, so the rollback itself is shielded from it.
        with suppress(BaseException):
            await asyncio.shield(
                _discard_session_container(backend, container_id, attach)
            )
        raise
    finally:
        _opening.discard(container_id)
        if not opened:
            target_sem.release()
            capacity.global_sem.release()

    session = _Session(
        session_id=uuid.uuid4().hex,
        container_id=container_id,
        target=payload.target,
        kind=payload.kind,
        session_key=payload.session_key,
        created_at=time.time(),
        deadline_ms=payload.deadline_ms,
        attach=attach,
        capacity=capacity,
        target_sem=target_sem,
    )
    _sessions[session.session_id] = session
    session.reader = asyncio.create_task(
        _pump_session(session), name=f"runner-session-{session.session_id}"
    )
    logger.info(
        "runner: session %s opened for %r (%s)",
        session.session_id,
        payload.target,
        payload.kind,
    )
    return _session_info(session)


async def _discard_session_container(
    backend: ContainerBackend, container_id: str, attach: Optional[AttachHandle]
) -> None:
    """Best-effort rollback of a half-opened session (no leak on a failed open)."""
    if attach is not None:
        with suppress(Exception):
            await attach.close()
    if container_id:
        with suppress(Exception):
            await backend.kill(container_id)
        with suppress(Exception):
            await backend.remove(container_id)


@app.post("/v1/sessions/{session_id}/stdin")
async def session_stdin(session_id: str, request: Request):
    denied = _authenticate(request)
    if denied is not None:
        return denied
    session, error = _session_or_error(session_id)
    if error is not None:
        return error
    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > MAX_SESSION_STDIN_BYTES:
        return _error(
            400,
            "invalid_request",
            f"session stdin body exceeds {MAX_SESSION_STDIN_BYTES} bytes",
        )
    data = await request.body()
    if len(data) > MAX_SESSION_STDIN_BYTES:
        return _error(
            400,
            "invalid_request",
            f"session stdin body exceeds {MAX_SESSION_STDIN_BYTES} bytes",
        )
    if session.kind == "discovery":
        # A discovery run is a catalog read, not a drivable server: anything past
        # initialize/tools-list/notifications would let a caller use it as a
        # general MCP session with the edge/central credentials.
        for line in data.splitlines():
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except ValueError:
                return _error(400, "invalid_request", "discovery stdin must be JSON-RPC")
            method = message.get("method") if isinstance(message, dict) else None
            if method and method not in _DISCOVERY_METHODS:
                return _error(
                    403,
                    "access_denied",
                    f"discovery sessions may not call {method!r}",
                )
    if data:
        try:
            await session.attach.write(data)
        except Exception as exc:
            logger.debug("runner: session %s stdin write failed: %s", session_id, exc)
            return _error(
                409,
                "mcp_session_lost",
                f"session {session_id!r} is no longer accepting input",
            )
        session.last_activity = time.time()
    return Response(status_code=204)


@app.post("/v1/sessions/{session_id}/close")
async def close_session_stdin(session_id: str, request: Request):
    """Half-close the container's stdin: the MCP server sees EOF after the flush."""
    denied = _authenticate(request)
    if denied is not None:
        return denied
    session, error = _session_or_error(session_id)
    if error is not None:
        return error
    with suppress(Exception):
        await session.attach.close_stdin()
    session.last_activity = time.time()
    return Response(status_code=204)


@app.get("/v1/sessions/{session_id}/stdout")
async def session_stdout(session_id: str, request: Request):
    denied = _authenticate(request)
    if denied is not None:
        return denied
    session, error = _session_or_error(session_id)
    if error is not None:
        return error
    if session.streaming:
        # Two consumers would interleave and each lose frames; a session has one
        # stdout reader for its whole life.
        return _error(
            409,
            "session_streaming",
            f"session {session_id!r} already has a stdout consumer",
        )
    session.streaming = True
    session.unconsumed_since = None
    return StreamingResponse(
        _session_frames(session), media_type="application/octet-stream"
    )


async def _session_frames(session: _Session):
    """Re-frame buffered attach frames onto the wire until EOF."""
    try:
        while True:
            item = await session.queue.get()
            if item is None:
                return
            tag, payload = item
            session.queued_bytes = max(0, session.queued_bytes - len(payload))
            session.drained.set()
            session.last_activity = time.time()
            yield SESSION_FRAME.pack(tag, len(payload)) + payload
    finally:
        # Also runs on client disconnect: the abandonment reaper sees the session
        # has no consumer and frees its container/slot after a short grace.
        session.streaming = False
        session.unconsumed_since = time.time()


@app.get("/v1/sessions/{session_id}")
async def get_session(session_id: str, request: Request):
    denied = _authenticate(request)
    if denied is not None:
        return denied
    session, error = _session_or_error(session_id)
    if error is not None:
        return error
    return _session_info(session)


@app.delete("/v1/sessions/{session_id}")
async def delete_session(session_id: str, request: Request):
    """Kill + remove. Idempotent: teardown races must not look like failures."""
    denied = _authenticate(request)
    if denied is not None:
        return denied
    session = _sessions.get(session_id)
    if session is not None:
        await _destroy_session(session)
    return Response(status_code=204)


# --------------------------------------------------------------------------- #
# background canary
# --------------------------------------------------------------------------- #


async def _canary_loop(interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            await recheck_canary()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("runner: periodic canary re-check crashed")


async def _reap_loop(interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            await reap_sessions()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("runner: periodic session reap crashed")


def _install_sighup(loop: asyncio.AbstractEventLoop) -> None:
    """SIGHUP re-runs the canary without restarting (sandbox hosts reload signals)."""

    def _on_hup(*_args) -> None:
        loop.call_soon_threadsafe(lambda: asyncio.ensure_future(recheck_canary()))

    try:
        signal.signal(signal.SIGHUP, _on_hup)
    except (AttributeError, ValueError, OSError) as exc:
        logger.warning("runner: cannot install the SIGHUP handler: %s", exc)


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #


def _fix_socket_permissions(path: str) -> None:
    """0660 so the app group -- not the world -- may drive the runner."""
    os.chmod(path, 0o660)
    gid = os.getenv("TRELLIS_GID", "").strip()
    if os.geteuid() == 0 and gid.isdigit():
        os.chown(path, -1, int(gid))


async def _await_socket(
    path: str, server_task: asyncio.Task, server: Any
) -> None:
    """Wait until uvicorn has bound the socket and finished startup.

    Waiting for the *file* to exist is not enough. The socket lives on a
    persistent volume, so after a restart the previous process's file is still
    there: the check passes before uvicorn has replaced it, and the chmod/chown
    that follows lands on the stale inode. The replacement socket is then
    root-owned and every app-uid caller (host, hub, gateway, taskiq) gets EACCES
    while the runner's own healthcheck -- which runs as root inside this
    container -- keeps reporting healthy.
    """
    deadline = time.monotonic() + SOCKET_READY_TIMEOUT_S
    while not getattr(server, "started", False):
        if server_task.done():
            return
        if time.monotonic() > deadline:
            raise SystemExit(
                f"runner: socket {path!r} did not become ready within "
                f"{SOCKET_READY_TIMEOUT_S:.0f}s"
            )
        await asyncio.sleep(0.05)


async def _serve() -> None:
    path = socket_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # A socket left behind by a previous process would be replaced by
        # uvicorn *after* we set permissions (see _await_socket). This process is
        # the only runner on the install's control volume, so clear it first.
        with suppress(FileNotFoundError):
            os.unlink(path)
    except OSError as exc:
        raise SystemExit(f"runner: cannot create {os.path.dirname(path)!r}: {exc}")

    # One worker, always: container slots and (from phase 2) the session registry
    # live in this process. A second worker would double-count capacity and reap
    # another worker's containers.
    config = uvicorn.Config(app=app, uds=path, workers=1, log_level="info")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(), name="runner-uvicorn")
    try:
        await _await_socket(path, task, server)
        if task.done():
            await task  # surface the bind failure
            return
        _fix_socket_permissions(path)
        await task
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def _healthcheck() -> int:
    try:
        async with RunnerClient() as client:
            info = await client.healthz()
    except Exception as exc:
        print(f"runner healthcheck failed: {exc}", file=sys.stderr)
        return 1
    if info.ok:
        return 0
    print(f"runner unhealthy: {info.detail}", file=sys.stderr)
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m core.execution.runner",
        description="Trellis execution runner (Unix-socket control API).",
    )
    parser.add_argument(
        "--healthcheck",
        action="store_true",
        help="probe /v1/healthz over the runner socket and exit 0/1",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.healthcheck:
        return asyncio.run(_healthcheck())

    _require_configuration()
    try:
        asyncio.run(_serve_after_startup())
    except KeyboardInterrupt:
        return 0
    return 0


async def _serve_after_startup() -> None:
    # Startup and serving share one loop: the backend's HTTP client is loop-bound.
    await startup()
    await _serve()


def reset_for_tests() -> None:
    """Drop every piece of process state between tests (cache, health, capacity)."""
    global _capacity
    for session in list(_sessions.values()):
        if session.reader is not None:
            with suppress(Exception):
                session.reader.cancel()
    _sessions.clear()
    _manifest_cache.clear()
    _capacity = None
    _state.preflight_ok = False
    _state.preflight_detail = "startup preflight has not run"
    _state.canary_ok = True
    _state.canary_detail = ""
    canary.reset_for_tests()


if __name__ == "__main__":
    raise SystemExit(main())
