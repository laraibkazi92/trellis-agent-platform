# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
import json
import subprocess
import asyncio
import logging
import threading
import time
import httpx
import stamina
from pathlib import Path
import typing
from typing import Dict, Any, Optional
from fastmcp import FastMCP
from starlette.responses import JSONResponse
from core import agent_token as agent_token_module
from core import allowlist
from core import edge_secrets_central
from core.models import ToolConfig
from core.auth import get_identity_manager
from core.caller_identity import resolve_user_email
from core.env_sanitize import sanitized_env
from core.devmode import enforce_dev_mode_safety
from core import sandbox_preflight
# The execution core lives in core.tool_runtime so the edge proxy
# (core.proxy) can run tools identically without importing this module's
# etcd-backed identity manager. Re-exported here for existing callers.
from core.tool_runtime import (  # noqa: F401
    MAX_RESULT_CHARS,
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    RESTRICTED_ENV_VARS,
    TRUNCATION_MARKER,
    TransientToolError,
    _communicate_bounded,
    _kill_process_tree,
    execute_tool,
)
from core.background.tasks import (
    background_tasks as _background_tasks,
    drain_background_tasks as _drain_background_tasks,
    spawn_background as _spawn_background,
)

from core.health import HealthMonitor

# Initialize FastMCP server with host and port
mcp = FastMCP("Polyglot Tool Hub")

BASE_DIR = Path(__file__).parent.parent

identity_mgr = get_identity_manager()
health_monitor = HealthMonitor(identity_mgr)

logger = logging.getLogger(__name__)

# Fingerprint per registered FastMCP tool, so a reconcile pass only touches what
# changed. Guarded because the reconcile thread and startup both call register_tools().
_registered_tools: Dict[str, str] = {}
_registration_lock = threading.Lock()


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request):
    """Sandbox health probe for the container healthcheck.

    The payload normally comes from the startup probes cached by
    ``sandbox_preflight.warmup()``. After a classified tool failure invalidates
    that cache, this re-probes so the verdict reflects the host as it is now
    (cooldown-bounded). Probing forks helper processes, so it runs off the event
    loop instead of stalling in-flight tool I/O. Container-internal only:
    FastMCP custom routes bypass MCP auth, so do not publish this port outside
    the compose network.
    """
    status_code, payload = await asyncio.to_thread(
        sandbox_preflight.build_healthz_payload
    )
    return JSONResponse(payload, status_code=status_code)


class _LifespanDrainWrapper:
    """Delegates ASGI calls to the wrapped app, draining background tasks on shutdown.

    Relies on the wrapped Starlette lifespan calling ``receive()`` again for the
    shutdown message; the drain runs before that message is forwarded, so tasks
    finish while the app's session manager is still alive.
    """

    def __init__(self, app):
        self._app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "lifespan":
            await self._app(scope, receive, send)
            return

        async def receive_and_drain():
            message = await receive()
            if message["type"] == "lifespan.shutdown":
                await _drain_background_tasks()
            return message

        await self._app(scope, receive_and_drain, send)


# Names whose config could not be read or parsed during the last load. The reconcile
# pass must not treat those as deleted: one corrupt key would otherwise unregister a
# working tool, and a full read failure would empty the table.
_unreadable_tool_names: set[str] = set()


def load_tool_configs() -> Optional[Dict[str, tuple[ToolConfig, Optional[Path]]]]:
    """Fetch tool configurations from etcd.

    Returns ``None`` when the registry itself could not be listed (nothing can be
    trusted, and the caller must keep its current table). Per-tool failures do not
    abort the pass: the name is recorded in ``_unreadable_tool_names`` so the caller
    protects it from the prune and reconciles everything else.

    Remote (edge-hosted) tools carry no ``rel_path``: their ``remote`` block is the
    entire execution target, so they are returned with ``tool_dir=None``. Local tools
    keep the existing BASE_DIR containment check.
    """
    global _unreadable_tool_names

    configs: Dict[str, tuple[ToolConfig, Optional[Path]]] = {}
    unreadable: set[str] = set()
    try:
        tool_names = identity_mgr.list_tools()
    except Exception as e:
        logger.error(f"Error loading tools from etcd: {e}")
        return None

    for name in tool_names:
        ok, data = identity_mgr.get_tool_config_safe(name)
        if not ok:
            unreadable.add(name)
            continue
        if not data:
            continue
        try:
            rel_path = data.pop("rel_path", None)
            config = ToolConfig(**data)
            if config.remote is not None:
                # The edge relay writes this config; there is no directory on
                # this side and no rel_path to resolve.
                configs[config.name] = (config, None)
                continue
            if not rel_path:
                logger.error(f"Error loading tool {name}: missing rel_path")
                unreadable.add(name)
                continue
            tool_dir = (BASE_DIR / rel_path).resolve()
            if not str(tool_dir).startswith(str(BASE_DIR.resolve())):
                logger.error(f"Error: Tool directory {tool_dir} is outside BASE_DIR {BASE_DIR}")
                unreadable.add(name)
                continue
            configs[config.name] = (config, tool_dir)
        except Exception as e:
            logger.error(f"Error loading tool {name}: {e}")
            unreadable.add(name)

    _unreadable_tool_names = unreadable
    return configs


# Principals that are not agents: the gateway is an authenticated front door whose
# tool visibility is enforced by its own whitelist search, so it is not subject to
# an agent's `allowed_tools`.
SYSTEM_PRINCIPALS = frozenset({"gateway"})


async def _authorize_call(
    config: ToolConfig, raw_token: Optional[str], user_id: Optional[str]
) -> tuple[Optional[agent_token_module.Claims], Optional[Dict[str, Any]]]:
    """Verify the agent token and the agent's effective allowlist.

    Returns ``(claims, denial)``. ``denial`` is the result dict to send back, or
    ``None`` when the call may proceed. In ``log`` mode a refusal is recorded and
    the call still runs (one rollout window); ``off`` skips everything.
    """
    mode = agent_token_module.mode()
    if mode == "off":
        return None, None
    try:
        claims = agent_token_module.verify(raw_token)
    except agent_token_module.AgentTokenError as exc:
        if mode == "log" and exc.code in {"missing", "missing_secret"}:
            # Rollout mode with no key/token: nothing to enforce yet, and warning
            # on every call would drown the log.
            return None, None
        message = f"access_denied: agent token rejected ({exc.code})"
        if mode == "log":
            logger.warning("hub: would deny %r: %s", config.name, message)
            return None, None
        return None, {"error": message}

    if claims.principal == "system" or claims.agent in SYSTEM_PRINCIPALS:
        return claims, None

    # The token is the authority for *who* the agent acts for: a caller may not
    # borrow a valid token to read another user's injected secrets.
    if claims.user_id and user_id and user_id not in (
        claims.user_id,
        f"svc_agent_{claims.agent}",
    ):
        message = "access_denied: token identity does not match the calling user"
        if mode == "log":
            logger.warning("hub: would deny %r: %s", config.name, message)
            return claims, None
        return claims, {"error": message}

    config_data = await asyncio.to_thread(identity_mgr.get_agent_config, claims.agent)
    if not config_data:
        message = f"access_denied: unknown agent '{claims.agent}'"
        if mode == "log":
            logger.warning("hub: would deny %r: %s", config.name, message)
            return claims, None
        return claims, {"error": message}

    allowed = allowlist.resolve(config_data)
    if not allowlist.permits_tool(allowed, config.name):
        message = agent_token_module.deny_message(claims.agent, config.name)
        if mode == "log":
            logger.warning("hub: would deny %r: %s", config.name, message)
            return claims, None
        return claims, {"error": message}
    return claims, None


@stamina.retry(on=TransientToolError, attempts=3)
async def _run_tool_attempt(
    config: ToolConfig,
    tool_dir: Path,
    arguments: Dict[str, Any],
    user_id: Optional[str],
    claims: Optional[agent_token_module.Claims] = None,
    agent_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Builds the tool's environment, then delegates execution to core.tool_runtime."""
    # Constructed per call (not at import) so tests and callers that swap
    # hub.health_monitor keep working.
    def on_health(ok: bool, err: Optional[str]) -> Any:
        return health_monitor.record_event("tool", config.name, ok, err)

    try:
        env = await _build_tool_env(config, tool_dir, user_id)
    except Exception as e:
        error_msg = f"Failed to execute tool: {str(e)}"
        await asyncio.to_thread(on_health, False, error_msg)
        return {"error": error_msg}

    agent = claims.agent if claims is not None else (
        user_id[len("svc_agent_"):] if user_id and user_id.startswith("svc_agent_") else None
    )
    return await execute_tool(
        config,
        tool_dir,
        arguments,
        env=env,
        on_health=on_health,
        agent=agent,
        user_id=user_id,
        user_email=(claims.user_email if claims is not None else None)
        or env.get("TRELLIS_USER_EMAIL"),
        run_id=claims.run_id if claims is not None else None,
        agent_token=agent_token,
    )


async def _build_tool_env(config: ToolConfig, tool_dir: Path, user_id: Optional[str]) -> Dict[str, str]:
    """Sanitized env, per-tool bin dir, and identity-scoped secrets/variables."""
    env = sanitized_env()

    # A CLI binary dropped into this tool's own bin/ on the host becomes
    # available to it automatically — workspace/ is already bind-mounted
    # into this container, so this needs no docker-compose volume mount
    # and no image rebuild. Scoped per-tool (rather than one shared
    # directory) so different tools' binaries can't collide by name.
    tool_bin = str((tool_dir / "bin").resolve())
    env["PATH"] = f"{tool_bin}{os.pathsep}{env.get('PATH', '')}"

    if user_id:
        from core.discovery import _resolve_requirements
        is_background = user_id.startswith("svc_agent_")

        # Scoped Secret Injection
        secret_keys = _resolve_requirements(config.secrets, is_background)
        if secret_keys:
            secrets = await asyncio.to_thread(identity_mgr.get_resolved_config, user_id, "secrets", keys=secret_keys)
            safe_secrets = {str(k): str(v) for k, v in secrets.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
            env.update(safe_secrets)

        # Scoped Optional Secret Injection (absence does not block tool execution)
        optional_secret_keys = _resolve_requirements(getattr(config, "optional_secrets", None), is_background)
        if optional_secret_keys:
            optional_secrets = await asyncio.to_thread(identity_mgr.get_resolved_config, user_id, "secrets", keys=optional_secret_keys)
            safe_optional_secrets = {str(k): str(v) for k, v in optional_secrets.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
            env.update(safe_optional_secrets)

        # Scoped Variable Injection
        variable_keys = _resolve_requirements(config.variables, is_background)
        if variable_keys:
            variables = await asyncio.to_thread(identity_mgr.get_resolved_config, user_id, "variables", keys=variable_keys)
            safe_vars = {str(k): str(v) for k, v in variables.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
            env.update(safe_vars)

        # Auto-inject user identity (email)
        user_email = await resolve_user_email(identity_mgr, user_id)
        if user_email:
            env["TRELLIS_USER_EMAIL"] = user_email

    return env


def _relay_url() -> str:
    """Base URL of the in-cluster edge relay (compose service name by default)."""
    return os.getenv("EDGE_RELAY_URL", "http://edge-relay:8100").rstrip("/")


# Mirrors services/edge_relay/protocol.MAX_DEADLINE_MS. Duplicated on purpose:
# core must never import services/ (the relay is a separate process tree, and the
# import would drag FastAPI/WS deps into the hub's module graph). The relay clamps
# the value again on its side, so this is only an upper bound on the wire.
_MAX_DEADLINE_MS = 3_600_000


def _remote_client(timeout_seconds: float) -> httpx.AsyncClient:
    """Client factory seam for remote dispatch.

    One client per call: the hub has no shared client, and a remote call's edge
    round trip dwarfs the connection setup. Tests monkeypatch this seam to inject
    an ``httpx.MockTransport``, which keeps the request/response mapping under
    test without touching the network.
    """
    return httpx.AsyncClient(timeout=timeout_seconds)


def _edge_error_field(body: Dict[str, Any], field: str, default: str = "") -> str:
    """Reads ``error.<field>`` (or the string form of ``error``) from a call body."""
    error = body.get("error")
    if isinstance(error, dict):
        value = error.get(field)
        if isinstance(value, str) and value:
            return value
        return default
    if field == "message" and isinstance(error, str) and error:
        return error
    return default


def _cap_remote_result(name: str, result: Any) -> Any:
    """Apply the local 96k safety net to a remote result.

    ``core.tool_runtime`` enforces this on the edge, but the edge is semi-trusted: a
    modified or malicious proxy can simply not truncate, and an oversized result would
    land in the model's context (and the provider bill). The hub is the trust boundary,
    so it caps what it accepts.
    """
    try:
        stringified = json.dumps(result)
    except (TypeError, ValueError):
        return result
    if len(stringified) <= MAX_RESULT_CHARS:
        return result
    logger.warning(
        "Remote tool %s returned %d chars; truncating to the %d-char safety limit",
        name,
        len(stringified),
        MAX_RESULT_CHARS,
    )
    return {
        "error": (
            f"Global Safety Net: The tool '{name}' output exceeded the 24k token limit "
            f"({MAX_RESULT_CHARS:,} characters). Output was safely truncated to prevent "
            "model context crashes."
        ),
        "partial_data_preview": stringified[:90_000] + "... [TRUNCATED DUE TO SAFETY LIMITS]",
    }


@stamina.retry(on=TransientToolError, attempts=3)
async def _run_remote(
    config: ToolConfig,
    arguments: Dict[str, Any],
    user_id: Optional[str],
    *,
    agent_token: Optional[str] = None,
    claims: Optional[agent_token_module.Claims] = None,
) -> Dict[str, Any]:
    """Dispatches a remote (edge-hosted) tool through the edge relay's internal API.

    The relay owns the tunnel; this side only maps its HTTP contract onto the same
    result-dict shape a local tool returns. Arguments, results, and response bodies
    are never logged: they carry the customer's internal data.

    Decorated like ``_run_tool_attempt`` so ``retry_on_transient`` keeps the same
    meaning it has for local tools. Remote tools default to False (an in-flight edge
    call is never replayed), so a retry here is always an explicit operator choice.
    """
    remote = config.remote
    site = remote.site
    tool = remote.tool

    # Imported here (not at module scope) so a cold hub start does not pull the
    # tunables cache — mirrors core.tool_runtime's identical lookup.
    from core.tunables import resolve as resolve_tunable

    timeout_seconds = config.timeout_seconds or resolve_tunable("tool_execution_timeout")
    # The HTTP read timeout leads deadline_ms by 5 s so the edge's structured
    # timeout (or the relay's 504) wins the race and the caller sees a reason,
    # not a bare client-side read timeout.
    deadline_ms = int(min((timeout_seconds + 30) * 1000, _MAX_DEADLINE_MS))

    async def record_health(ok: bool, error: Optional[str] = None) -> None:
        # Health writes are etcd I/O: keep them off the event loop, and never let
        # a registry hiccup turn a completed call into an exception.
        try:
            await asyncio.to_thread(health_monitor.record_event, "tool", config.name, ok, error)
        except Exception as exc:
            logger.warning(f"Failed to record health for remote tool {config.name}: {exc}")

    # Resolved before the request so a slow (or failing) registry read cannot eat
    # into the call's timeout budget. Fail-open: an identity lookup hiccup costs
    # this call its email, not the call itself. A verified token's claim wins.
    user_email = claims.user_email if claims is not None else None
    if user_email is None:
        try:
            user_email = await resolve_user_email(identity_mgr, user_id)
        except Exception as exc:
            logger.warning(f"Could not resolve the caller email for remote tool {config.name}: {exc}")
            user_email = None

    # The caller's browser-sealed credential set for exactly this (site, tool, user).
    # It rides the relay body verbatim and is never logged here: central cannot open
    # it, and the relay treats it as opaque bytes.
    sealed: Optional[Dict[str, Any]] = None
    if user_id:
        try:
            sealed = await asyncio.to_thread(
                edge_secrets_central.get, identity_mgr, site, user_id, "tool", tool
            )
        except Exception as exc:
            # A registry hiccup costs this call its per-user credentials, not the call;
            # the edge then applies its credential_mode (which may fail closed).
            logger.warning(
                "Could not read sealed credentials for remote tool %s on edge %s (%s)",
                config.name,
                site,
                type(exc).__name__,
            )

    try:
        async with _remote_client(timeout_seconds + 35) as client:
            response = await client.post(
                f"{_relay_url()}/v1/sites/{site}/call",
                json={
                    "tool": tool,
                    "args": arguments,
                    "deadline_ms": deadline_ms,
                    "user": user_id,
                    "user_email": user_email,
                    # The relay verifies this and resolves the agent's allowlist
                    # itself; the edge proxy verifies the signature again.
                    "agent_token": agent_token,
                    "sealed": sealed,
                },
            )
    except httpx.TimeoutException as exc:
        # The hub's own read timeout fired, which means the relay did not answer in
        # time and the call may already have run on the edge. Never retried — the
        # same "timeouts are immediately fatal" rule local tools follow.
        message = (
            f"Tool '{config.name}' did not respond on edge '{site}' before the hub's "
            f"own deadline ({type(exc).__name__}). The call may still have run on the edge."
        )
        await record_health(False, message)
        return {"error": message}
    except httpx.ConnectError as exc:
        # Nothing was sent: the TCP connect itself failed, so a retry cannot
        # duplicate a call. Every other TransportError (ReadError, WriteError,
        # RemoteProtocolError) happens *after* the request left this process --
        # the relay may have forwarded it and the edge may have run it -- so those
        # take the never-retry path below.
        message = (
            f"Tool '{config.name}' is unreachable (the edge relay hop to edge "
            f"'{site}' failed: {type(exc).__name__})."
        )
        if config.retry_on_transient:
            raise TransientToolError(message)
        await record_health(False, message)
        return {"error": message}
    except (httpx.InvalidURL, httpx.UnsupportedProtocol) as exc:
        # A broken EDGE_RELAY_URL is a central config error, not a lost edge: nothing was
        # sent, so it is never transient and the message must name the cause.
        message = (
            f"Tool '{config.name}' could not be dispatched: the edge relay URL "
            f"'{_relay_url()}' is unusable ({type(exc).__name__}: {exc}). Check EDGE_RELAY_URL."
        )
        await record_health(False, message)
        return {"error": message}
    except httpx.TransportError as exc:
        message = (
            f"Tool '{config.name}' lost its connection to edge '{site}' mid-call "
            f"({type(exc).__name__}). It may already have run on the edge."
        )
        await record_health(False, message)
        return {"error": message}
    except httpx.HTTPError as exc:
        # Anything else httpx can raise on the way out (redirect loop, decoding, ...).
        # Never let it escape into an agent turn as a bare traceback.
        message = (
            f"Tool '{config.name}' could not be dispatched to edge '{site}' "
            f"({type(exc).__name__}: {exc}). Check the relay at '{_relay_url()}'."
        )
        await record_health(False, message)
        return {"error": message}

    try:
        body = response.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}

    status = response.status_code

    if status == 200:
        if "error" in body:
            message = _edge_error_field(body, "message", "the edge did not report a reason")
            error = f"Tool '{config.name}' failed on edge '{site}': {message}"
            await record_health(False, error)
            return {"error": error}
        result = body.get("result")
        await record_health(True)
        # A well-formed tool result is a JSON object; anything else is wrapped so
        # callers keep a dict contract.
        result = result if isinstance(result, dict) else {"result": result}
        return _cap_remote_result(config.name, result)

    if status == 400:
        # Schema rejection: permanent by construction, never retried.
        error = (
            f"Tool '{config.name}' rejected the arguments: "
            f"{_edge_error_field(body, 'message', 'the relay rejected the call')}"
        )
        await record_health(False, error)
        return {"error": error}

    if status == 404:
        error = (
            f"Edge '{site}' no longer exports tool '{config.name}'. The registration "
            "is stale; the edge's catalog changed since it was published."
        )
        await record_health(False, error)
        return {"error": error}

    if status == 503:
        code = _edge_error_field(body, "code")
        if code == "edge_overloaded":
            message = f"Edge '{site}' is busy and cannot accept tool '{config.name}' right now."
            if config.retry_on_transient:
                raise TransientToolError(message)
            await record_health(False, message)
            return {"error": message}
        if code in ("edge_offline", "edge_disconnected"):
            # Expected operational state, not a hub bug: surface it, never raise.
            error = f"Tool '{config.name}' is offline (edge '{site}' is not connected)."
            await record_health(False, error)
            return {"error": error}

    if status == 429:
        # Per-site rate limit at the relay. Retryable, but only explicitly: the
        # call was rejected before dispatch, so a retry cannot duplicate it.
        message = f"Edge '{site}' is rate-limiting tool calls; '{config.name}' was not sent."
        if config.retry_on_transient:
            raise TransientToolError(message)
        await record_health(False, message)
        return {"error": message}

    if status == 504:
        error = f"Tool '{config.name}' timed out on edge '{site}' (no result before the deadline)."
        await record_health(False, error)
        return {"error": error}

    # Unknown status: include the code, and at most a short body preview.
    preview = (response.text or "")[:200]
    error = f"Tool '{config.name}' failed on edge '{site}' (relay returned HTTP {status}: {preview})"
    await record_health(False, error)
    return {"error": error}


_HUB_CALL_DENIED = (
    "SYSTEM: Access denied. Tool '{name}' is not permitted for this principal."
)
_HUB_CALL_CHECK_FAILED = (
    "SYSTEM: Error checking tool access for '{name}'. Please try again later."
)


async def _authorize_hub_call(
    config: ToolConfig, raw_token: Optional[str], user_id: Optional[str]
) -> Optional[Dict[str, Any]]:
    """Default-deny check for a direct hub ``/tools/call`` (``hub_call_mode``).

    Agent-driven calls already carry the run's agent token, so this resolves the same
    principal ``use_tool`` would and runs the same evaluator under its own rollout key
    and its own ``surface="hub_direct"`` ring tag. Returns the result dict to send back
    or ``None`` when the tool may run.

    ``off`` (the default) is a no-I/O fast path once the authz snapshot is warm: no
    token verification, no policy evaluation. A malformed or expired token is not an
    error here -- the caller keeps its ``__user_id`` and the principal falls back to
    that (or ``anonymous``), because rejecting tokens belongs to the agent-token gate
    above, not to this one. The token's user id also supplies the caller's stored groups:
    this process has no request for the middleware to publish them from, and without
    them a ``group:`` rule would match on the host and deny here for the same call.
    Everything else fails closed: an exception inside the check never runs the tool.

    Note the same caveat as the other surfaces: if the authz state has never been
    readable, the cold snapshot says ``off`` and the gate fails open until a read
    succeeds.
    """
    from core import tool_authz

    surface = tool_authz.HUB_DIRECT_SURFACE

    def _verdict() -> Optional[Dict[str, Any]]:
        mode = tool_authz.cached_mode_for_surface(surface)
        if mode is None:
            mode = tool_authz.mode_for_surface(surface)
        if mode == "off":
            return None
        claims = agent_token_module.verify_or_none(raw_token)
        if claims is None and raw_token:
            logger.warning(
                "hub: agent token presented for %r did not verify; resolving the "
                "principal without claims (agent:/workflow: rules cannot match)",
                config.name,
            )
        if (
            claims is not None
            and claims.user_id
            # Service identities (`svc_agent_*`) never have a profile record, and a
            # synthetic one must not grant a workflow groups the host would not see.
            and not str(claims.user_id).startswith("svc_agent_")
        ):
            tool_authz.set_request_groups(tool_authz.stored_user_groups(claims.user_id))
        try:
            principal = tool_authz.principal_for(claims, user_id)
            if tool_authz.allowed(
                principal, config.name, "tools:call", surface=surface, mode=mode
            ):
                return None
            return {"error": _HUB_CALL_DENIED.format(name=config.name)}
        finally:
            # `to_thread` copies the context, so the copy would be discarded anyway;
            # clear it so a future non-threaded caller cannot leak one verdict's groups
            # into the next.
            tool_authz.clear_request_groups()

    try:
        return await asyncio.to_thread(_verdict)
    except Exception:
        logger.exception("Hub tool authorization check failed for %r", config.name)
        return {"error": _HUB_CALL_CHECK_FAILED.format(name=config.name)}


async def run_tool(config: ToolConfig, tool_dir: Optional[Path], arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Executes a tool locally (container) or remotely (edge relay)."""
    # stamina re-invokes with the same dict — never mutate the caller's arguments.
    arguments = dict(arguments)
    user_id = arguments.pop("__user_id", None)
    raw_token = agent_token_module.refresh(arguments.pop("__agent_token", None))
    # The former `__agent_name`-in-arguments path is gone: the token's claims are
    # the only source of agent identity (and they are verified, not asserted).
    claims, denial = await _authorize_call(config, raw_token, user_id)
    try:
        if denial is not None:
            return denial
        # Direct hub traffic has no principal until the call proves one: gate it before
        # anything is executed (locally or on an edge).
        hub_denial = await _authorize_hub_call(config, raw_token, user_id)
        if hub_denial is not None:
            return hub_denial
        if config.remote is not None:
            return await _run_remote(
                config, arguments, user_id, agent_token=raw_token, claims=claims
            )
        return await _run_tool_attempt(
            config, tool_dir, arguments, user_id, claims, raw_token
        )
    finally:
        # Usage is recorded once per invocation, not once per stamina retry attempt.
        if user_id:
            _spawn_background(
                asyncio.to_thread(identity_mgr.record_tool_usage, user_id, config.name),
                f"record_tool_usage:{config.name}",
            )


def _tool_fingerprint(config: ToolConfig, tool_dir: Optional[Path]) -> str:
    """Stable identity for a registered tool: config + the directory it runs from.

    The reconcile loop re-registers only when this changes, so a 10 s tick does not
    rebuild Go binaries or churn the FastMCP tool table.
    """
    payload = config.model_dump(mode="json")
    return f"{json.dumps(payload, sort_keys=True, default=str)}|{tool_dir or ''}"


def _remove_registered_tool(name: str) -> None:
    """Drop one tool from the live FastMCP table (best effort across versions)."""
    provider = getattr(mcp, "local_provider", None)
    remove = getattr(provider, "remove_tool", None)
    if remove is None:
        logger.debug("FastMCP build has no remove_tool; '%s' stays registered until restart", name)
        return
    try:
        remove(name)
    except Exception:
        logger.debug("Could not remove tool '%s' from FastMCP", name, exc_info=True)



def _create_tool_handler(c: ToolConfig, d: Optional[Path]) -> Any:
    import inspect

    sig_parts = []
    annotations = {}
    params = []

    if c.inputs:
        for input_name, input_def in c.inputs.items():
            input_type = input_def.get("type", "string")
            py_type = str
            if input_type == "string":
                # Historical: 'string' maps to Any (not str) so the handler's str()-coercion
                # below is the single place stringification happens; unknown types also
                # fall through to the str default.
                py_type = Any
            elif input_type == "integer": py_type = int
            elif input_type == "boolean": py_type = bool
            elif input_type == "array": py_type = list
            elif input_type == "object": py_type = dict

            is_req = input_def.get("required", False)
            default = inspect.Parameter.empty if is_req else None

            params.append(
                inspect.Parameter(
                    input_name,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=py_type,
                    default=default
                )
            )
            annotations[input_name] = py_type

    # Add __user_id
    params.append(
        inspect.Parameter(
            "__user_id",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=typing.Optional[str],
            default=None
        )
    )
    annotations["__user_id"] = typing.Optional[str]

    # Add __agent_token (reserved, like __user_id): verified before dispatch and
    # stripped before the tool ever sees its arguments. A FastMCP handler arg is
    # used rather than an HTTP header because the hub's MCP client is a
    # process-wide singleton shared by concurrent runs.
    params.append(
        inspect.Parameter(
            "__agent_token",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=typing.Optional[str],
            default=None
        )
    )
    annotations["__agent_token"] = typing.Optional[str]

    async def handler(**kwargs):
        filtered_kwargs = {}
        for k, v in kwargs.items():
            if v is not None:
                # Ensure we stringify string inputs properly
                if c.inputs and k in c.inputs:
                    if c.inputs[k].get("type", "string") == "string" and not isinstance(v, str):
                        filtered_kwargs[k] = str(v)
                    else:
                        filtered_kwargs[k] = v
                else:
                    filtered_kwargs[k] = v

        try:
            return await run_tool(c, d, filtered_kwargs)
        except TransientToolError as e:
            return {"error": f"Tool failed after retries: {str(e)}"}

    handler.__signature__ = inspect.Signature(params)
    handler.__annotations__ = annotations
    handler.__name__ = c.name.replace('-', '_')
    handler.__doc__ = c.description

    return handler

def register_tools() -> int:
    """Reconcile FastMCP's tool table with the registry; returns the change count.

    Called once at startup and then from ``_reconcile_loop``. Reconciling (rather
    than registering once) is what makes a newly connected edge's tools executable
    without restarting the hub, and what makes a removed tool stop being callable.
    """
    configs = load_tool_configs()
    if configs is None:
        # A failed read is not an empty registry: keep serving what is registered.
        logger.warning("Tool registry read failed; keeping the current tool table")
        return 0
    changed = 0

    with _registration_lock:
        for name, (config, tool_dir) in configs.items():
            if config.remote is not None:
                # Defense in depth: the relay derives the registry name from the
                # catalogue it published, so a mismatch means the entry was corrupted
                # (or hand-edited) and the tool would dispatch to the wrong site.
                expected_site = config.name.split("__", 1)[0]
                if config.remote.site != expected_site:
                    logger.error(
                        f"Skipping remote tool {name}: remote.site '{config.remote.site}' does not "
                        f"match the registry prefix '{expected_site}__'"
                    )
                    continue

            fingerprint = _tool_fingerprint(config, tool_dir)
            if _registered_tools.get(name) == fingerprint:
                continue

            if config.remote is None and config.runtime == "go":
                entrypoint_path = (tool_dir / config.entrypoint).resolve()
                if not str(entrypoint_path).startswith(str(tool_dir)) or not entrypoint_path.is_file():
                    logger.error(f"Skipping compilation of Go tool {name}: invalid entrypoint {config.entrypoint}")
                    continue

                logger.info(f"Pre-compiling Go tool: {name}")
                bin_dir = tool_dir / ".bin"
                bin_dir.mkdir(exist_ok=True)
                bin_path = bin_dir / config.name
                try:
                    subprocess.run(["go", "build", "-o", str(bin_path), config.entrypoint], cwd=str(tool_dir), check=True, env=sanitized_env())
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to compile Go tool {name}: {e}")
                    continue

            if name in _registered_tools:
                # The schema or entrypoint changed: replace the handler so the MCP
                # signature matches the catalog the agent is told about.
                _remove_registered_tool(name)
            mcp.tool(name=name, description=config.description)(_create_tool_handler(config, tool_dir))
            _registered_tools[name] = fingerprint
            changed += 1
            logger.info(f"Registered tool: {name}")

        # A tool whose config vanished is no longer callable. Its embedding and
        # usage history are separate concerns and are left to the registry owners.
        # Unreadable configs are protected: a corrupt or unreachable entry must not
        # unregister a tool that may be perfectly healthy.
        for stale in sorted(set(_registered_tools) - set(configs) - _unreadable_tool_names):
            _remove_registered_tool(stale)
            _registered_tools.pop(stale, None)
            changed += 1
            logger.info(f"Unregistered tool: {stale}")

    return changed


def _reconcile_loop(interval: float) -> None:
    """Keep the tool table in step with etcd (edge catalogs publish at runtime)."""
    while True:
        time.sleep(interval)
        try:
            if register_tools():
                logger.info("Tool registry reconciled (interval %.0fs)", interval)
        except Exception:
            # Keep serving the current tool set: a transient etcd error must not
            # empty the hub's tool table.
            logger.exception("Tool registry reconcile failed; keeping the current tools")

if __name__ == "__main__":
    # Startup gate: refuse to serve an unauthenticated DEV_MODE instance on a
    # remotely reachable bind host (see core/devmode.py).
    enforce_dev_mode_safety("hub")
    from core.agent_token import require_secret
    from core.log_redaction import install as install_redaction

    install_redaction()
    require_secret("hub")
    # Startup probes for /healthz. Never raises: a broken sandbox must not block
    # the hub from starting, it only flips the health payload to 503.
    sandbox_preflight.warmup()
    register_tools()
    # Edge catalogs are published at runtime, so the tool table has to follow etcd
    # instead of being read once at boot. 0 disables the watcher (tests/CI).
    try:
        reconcile_seconds = float(os.getenv("EDGE_TOOL_RECONCILE_SECONDS", "10"))
    except ValueError:
        # A typo here must not take every tool call in the instance down at boot; the
        # nginx entrypoint fails loud for the same class of mistake.
        logger.warning("EDGE_TOOL_RECONCILE_SECONDS is not a number; using 10s")
        reconcile_seconds = 10.0
    if reconcile_seconds > 0:
        threading.Thread(
            target=_reconcile_loop,
            args=(reconcile_seconds,),
            daemon=True,
            name="tool-registry-reconcile",
        ).start()
    import uvicorn
    app = _LifespanDrainWrapper(mcp.http_app(host_origin_protection=False))
    uvicorn.run(app, host=os.getenv("BIND_HOST", "0.0.0.0"), port=8001)
