# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
import secrets
import yaml
import asyncio
import copy
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from collections import OrderedDict

from pydantic_ai import Agent, RunContext

from fastmcp import Client as FastMCPClient
from fastmcp.client import SSETransport, StreamableHttpTransport

from subagents_pydantic_ai import SubAgentCapability, SubAgentConfig
from subagents_pydantic_ai.registry import DynamicAgentRegistry
from subagents_pydantic_ai.toolset import create_subagent_toolset
from subagents_pydantic_ai.types import CompiledSubAgent
from pydantic_ai_backends import ConsoleCapability
from pydantic_ai_shields import CostTracking, ToolGuard
from pydantic_ai_rlm import create_rlm_toolset

from core.auth import (
    EtcdContentionError,
    IdentityManager,
    agent_token_var,
    get_identity_manager,
    user_id_var,
)
from core import llm_defaults, llm_factory
from core.console_backend import RunnerConsoleBackend
from core.execution.spec import declared_env_keys, manifest_digest
from core.execution.stdio_transport import RunnerStdioTransport
from core.llm_factory import build_model_settings, resolve_model
from core.mcp_schema import normalize_schema_for_provider
from core.models import AgentConfig, MCPConfig, EDGE_MCP_WILDCARD_RE, is_agent_external, is_agent_internal
from core.health import HealthMonitor, evaluate_health_status
from core.discovery import is_agent_configured
from core.remote_mcp import call_edge_mcp
from core.tool_search import execute_whitelisted_tool
from core.tunables import resolve as resolve_tunable

logger = logging.getLogger(__name__)

# Shared global states and caches
_hub_client: Optional[FastMCPClient] = None
_hub_tools_cache: List[Any] = []
_external_mcp_tools: Dict[str, List[Any]] = {}
# Registry key -> (site, mcp) for the servers discovered as edge-exported (a `remote`
# block). Populated by discover_external_mcps so registration never has to guess an edge
# server from the shape of its key: a central MCP may be named `a__b` too.
_external_remote_mcps: Dict[str, tuple[str, str]] = {}
_last_discovery_time: float = 0
DISCOVERY_CACHE_TTL = 60 # Cache discovery for 60 seconds

# The loop that owns cached clients. Eviction can be triggered from the etcd
# watch thread (on_mcp_change), which cannot await a client's __aexit__ itself.
_mcp_loop: Optional[asyncio.AbstractEventLoop] = None


def _schedule_close(client: Any) -> None:
    """Close an evicted MCP client, on its own loop when called from a thread.

    Dropping the reference is not enough any more: a cached client owns a runner
    session container and a capacity slot, so only __aexit__ releases them.
    """
    async def _close() -> None:
        try:
            await client.__aexit__(None, None, None)
        except Exception:
            logger.debug("Failed to close an evicted MCP client", exc_info=True)

    loop = _mcp_loop
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is not None:
        running.create_task(_close())
    elif loop is not None and loop.is_running():
        asyncio.run_coroutine_threadsafe(_close(), loop)
    else:
        logger.debug("No event loop to close an evicted MCP client; it will die with the process")


class _McpClientCache:
    """TTL + LRU cache that closes what it evicts (see ``_schedule_close``)."""

    def __init__(self, maxsize: int = 100, ttl: float = 300.0) -> None:
        self._maxsize = maxsize
        self._ttl = ttl
        self._data: "OrderedDict[Any, tuple[Any, float]]" = OrderedDict()

    def get(self, key: Any) -> Any:
        item = self._data.get(key)
        if item is None:
            return None
        client, stamp = item
        if time.monotonic() - stamp > self._ttl:
            self.pop(key)
            return None
        self._data.move_to_end(key)
        return client

    def set(self, key: Any, client: Any) -> None:
        while len(self._data) >= self._maxsize:
            _, (old, _stamp) = self._data.popitem(last=False)
            _schedule_close(old)
        self._data[key] = (client, time.monotonic())

    def pop(self, key: Any, default: Any = None) -> Any:
        item = self._data.pop(key, None)
        if item is None:
            return default
        _schedule_close(item[0])
        return item[0]

    def keys(self) -> list:
        return list(self._data)

    def clear(self) -> None:
        for key in list(self._data):
            self.pop(key)


mcp_client_cache = _McpClientCache(maxsize=100, ttl=300)
_mcp_client_locks: Dict[tuple, asyncio.Lock] = {}

# Agent instance cache (Lever B). Built agents are user-agnostic — safe to share across users
# and concurrent requests. Invalidated per-agent via etcd watch in host.py.
_agent_cache: Dict[str, Agent] = {}
_agent_locks: Dict[str, asyncio.Lock] = {}

class SupervisorDeps:
    """Minimal deps for the supervisor agent satisfying SubAgentDepsProtocol."""
    def __init__(self):
        self.subagents: Dict[str, Any] = {}
        self._subagent_state: Dict[str, Any] = {}

    def clone_for_subagent(self, max_depth: int = 0) -> "SupervisorDeps":
        return SupervisorDeps()


def _registry_refresh_timeout() -> float:
    """Bounded-wait timeout for an on-demand supervisor snapshot refresh (admin-tunable
    ``registry_refresh_timeout``, env ``FRAMEWORK_REGISTRY_REFRESH_TIMEOUT``, default 5s)."""
    return max(0.1, resolve_tunable("registry_refresh_timeout"))


def _registry_snapshot_ttl() -> float:
    """Background refresh interval for the supervisor eligibility snapshot (admin-tunable
    ``registry_snapshot_ttl``, env ``FRAMEWORK_REGISTRY_SNAPSHOT_TTL``, default 15s)."""
    return max(1.0, resolve_tunable("registry_snapshot_ttl"))


class _RegistryEligibilitySnapshot:
    """Thread-refreshed {name: {"disabled", "offline", "external"}} eligibility view.

    get_compiled() must stay sync (vendored DynamicAgentRegistry API) and therefore
    cannot await asyncio.to_thread; it reads this snapshot instead of etcd.
    Fail-open: on refresh error the previous snapshot is kept; names absent from the
    snapshot fall through to super().get_compiled() (same as today's missing-config path).
    """

    def __init__(self, identity_mgr, health_monitor):
        self._identity_mgr = identity_mgr
        self._health_monitor = health_monitor
        self._entries = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def get(self, name):  # -> Optional[Dict[str, bool]]
        return self._entries.get(name)

    def set_for_testing(self, entries):
        self._entries = dict(entries)

    def refresh(self) -> None:
        try:
            configs = self._identity_mgr.get_all_agent_configs() or {}
            healths = self._identity_mgr.get_all_health_statuses("agent") or {}
            disabled = set(self._identity_mgr.get_disabled_standard_agents() or [])
            cooldown = getattr(self._health_monitor, "cooldown_seconds", None)
            entries = {}
            for name, cfg in configs.items():
                entries[name] = {
                    "disabled": name in disabled,
                    "offline": evaluate_health_status(healths.get(name) or {}, cooldown).get("status") == "Offline",
                    "external": is_agent_external(cfg),
                }
            for name in disabled:
                entries.setdefault(name, {"disabled": True, "offline": False, "external": True})
            self._entries = entries
        except Exception as e:
            if self._entries:
                logger.warning("Registry eligibility snapshot refresh failed (keeping previous snapshot): %s", e)
            else:
                logger.warning("Registry eligibility snapshot refresh failed (no previous snapshot; routing stays unrestricted): %s", e)

    def start(self) -> None:
        # Lazily start one daemon thread; the thread performs the first refresh
        # itself so the event loop is never blocked by snapshot I/O.
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._run, name="framework-registry-snapshot", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        self.refresh()
        while not self._stop.wait(_registry_snapshot_ttl()):
            self.refresh()

    def stop(self) -> None:
        self._stop.set()


class FrameworkAgentRegistry(DynamicAgentRegistry):
    """DynamicAgentRegistry backed by the framework's agent cache.

    Overrides get_compiled() to return None for disabled or offline agents so
    the supervisor's task() tool never routes to them. Eligibility is read from a
    thread-refreshed snapshot because get_compiled() is sync by vendored API
    contract and cannot await an off-loop etcd lookup.
    """
    def __init__(self, identity_mgr: "IdentityManager", health_monitor: "HealthMonitor"):
        super().__init__()
        self._identity_mgr = identity_mgr
        self._health_monitor = health_monitor
        self._snapshot = _RegistryEligibilitySnapshot(identity_mgr, health_monitor)

    def get_compiled(self, name: str) -> Optional[CompiledSubAgent]:
        entry = self._snapshot.get(name)
        if entry is not None and (entry.get("disabled") or entry.get("offline") or not entry.get("external", True)):
            return None
        return super().get_compiled(name)

    def _set_snapshot_for_testing(self, entries):
        self._snapshot.set_for_testing(entries)

    def _refresh_snapshot(self):
        self._snapshot.refresh()


_supervisor_registry: Optional[FrameworkAgentRegistry] = None


def get_supervisor_registry() -> FrameworkAgentRegistry:
    global _supervisor_registry
    if _supervisor_registry is None:
        _supervisor_registry = FrameworkAgentRegistry(get_identity_manager(), get_health_monitor())
        _supervisor_registry._snapshot.start()
    return _supervisor_registry


_registry_refresh_executor: Optional[ThreadPoolExecutor] = None


def _get_registry_refresh_executor() -> ThreadPoolExecutor:
    global _registry_refresh_executor
    if _registry_refresh_executor is None:
        _registry_refresh_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="registry-refresh")
    return _registry_refresh_executor


async def _refresh_registry_snapshot_bounded() -> None:
    """Refresh the supervisor eligibility snapshot without letting degraded etcd
    stall manage_agent: bounded wait, fail-open (the TTL refresh catches up)."""
    registry = get_supervisor_registry()
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(_get_registry_refresh_executor(), registry._refresh_snapshot),
            timeout=_registry_refresh_timeout(),
        )
    except asyncio.TimeoutError:
        logger.warning(
            "Registry snapshot refresh timed out after %.1fs; routing will reflect the toggle within the TTL (%.0fs).",
            _registry_refresh_timeout(),
            _registry_snapshot_ttl(),
        )


_health_monitor: Optional[HealthMonitor] = None
def get_health_monitor() -> HealthMonitor:
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = HealthMonitor(get_identity_manager())
    return _health_monitor

DEFAULT_HUB_URL = os.getenv("HUB_URL", "http://localhost:8001/mcp")

def _latest_user_text(ctx: RunContext) -> str:
    """Best-effort extraction of the current user prompt from a RunContext, used to query
    agent memory. Defensive across pydantic-ai versions; returns "" if not found."""
    prompt = getattr(ctx, "prompt", None)
    if isinstance(prompt, str) and prompt.strip():
        return prompt
    messages = getattr(ctx, "messages", None) or []
    for msg in reversed(messages):
        for part in getattr(msg, "parts", []) or []:
            if part.__class__.__name__ == "UserPromptPart":
                content = getattr(part, "content", None)
                if isinstance(content, str) and content.strip():
                    return content
    return ""

def _inject_config(
    env: Optional[Dict[str, str]], 
    req_data: Optional[Union[List[str], Dict[str, List[str]]]], 
    identity_mgr: IdentityManager,
    user_id: str,
    category: str,
    is_background: bool
) -> Dict[str, str]:
    from core.discovery import _resolve_requirements
    env_copy = env.copy() if env else {}
    req_list = _resolve_requirements(req_data, is_background)
    
    if not req_list:
        return env_copy

    # Scoped fetch for the required keys
    resolved_data = identity_mgr.get_resolved_config(user_id, category, keys=req_list)
    
    for req_key in req_list:
        val = resolved_data.get(req_key)
        if val:
            # Handle interpolation if the value is used in existing env vars (e.g. command args in env)
            interpolated = False
            for k, v in env_copy.items():
                if isinstance(v, str) and f"{{{req_key}}}" in v:
                    env_copy[k] = v.replace(f"{{{req_key}}}", str(val))
                    interpolated = True
            if not interpolated:
                env_copy[req_key] = str(val)
    return env_copy

async def get_external_mcp_client(mcp_name: str, user_id: str) -> FastMCPClient:
    global _mcp_loop
    _mcp_loop = asyncio.get_running_loop()
    cache_key = (mcp_name, user_id)
    cached_client = mcp_client_cache.get(cache_key)
    if cached_client is not None:
        return cached_client

    # One lock per (mcp, user): two concurrent first calls would otherwise open
    # two session containers, and only one of them would ever be reachable.
    lock = _mcp_client_locks.setdefault(cache_key, asyncio.Lock())
    async with lock:
        cached_client = mcp_client_cache.get(cache_key)
        if cached_client is not None:
            return cached_client
        client = await _open_external_mcp_client(mcp_name, user_id)
        mcp_client_cache.set(cache_key, client)
        return client


def invalidate_mcp_client(mcp_name: str, user_id: str) -> None:
    """Drop (and close) a cached client so the next call respawns its session."""
    mcp_client_cache.pop((mcp_name, user_id), None)


def _is_session_failure(exc: BaseException) -> bool:
    """A dead transport/session, as opposed to an ordinary tool-level error.

    Only a session failure should evict the cached client: evicting on a tool's
    own error would throw away a warm login state for nothing.
    """
    name = type(exc).__name__
    if name in {"RunnerCallError", "RunnerUnavailable", "ClosedResourceError", "BrokenResourceError"}:
        return True
    return "session" in str(exc).lower()


async def _open_external_mcp_client(mcp_name: str, user_id: str) -> FastMCPClient:
    identity_mgr = get_identity_manager()
    config_data = await asyncio.to_thread(identity_mgr.get_mcp_config, mcp_name)
    if not config_data: raise Exception(f"MCP config '{mcp_name}' not found")
    config = MCPConfig(**config_data)
    
    is_background = user_id.startswith("svc_agent_")
    
    # Inject Secrets (Scoped)
    env = _inject_config(config.env, config.secrets, identity_mgr, user_id, "secrets", is_background)

    # Inject Optional Secrets (Scoped — silently skipped when absent, never blocks startup)
    env = _inject_config(env, config.optional_secrets, identity_mgr, user_id, "secrets", is_background)

    # Inject Variables (Scoped)
    env = _inject_config(env, config.variables, identity_mgr, user_id, "variables", is_background)

    if config.transport == "stdio":
        # The server runs in a runner session container: only the manifest's
        # declared keys cross the socket (the runner rejects anything else), and
        # the control plane's own environment stays here. The session's identity is
        # the verified token's claims, so nothing identity-shaped is passed.
        declared = declared_env_keys(config)
        transport = RunnerStdioTransport(
            target=config.name,
            session_key=secrets.token_hex(16),
            env={k: v for k, v in env.items() if k in declared},
            manifest_digest=manifest_digest(config),
            agent_token=agent_token_var.get(),
            # The runner's hard lifetime; the cache TTL is the primary freshness
            # knob, so a session only outlives its useful life by the grace.
            deadline_ms=min(
                max(60, int(config.session_idle_ttl_minutes) * 60 + 300) * 1000,
                24 * 3600 * 1000,
            ),
        )
    elif config.transport in ["http", "streamable-http"]:
        transport = StreamableHttpTransport(url=config.command, headers=env)
    else:
        transport = SSETransport(url=config.command, headers=env)
    
    client = FastMCPClient(transport)
    await client.__aenter__()
    return client

def is_hub_connected() -> bool:
    return _hub_client is not None

async def get_hub_client() -> FastMCPClient:
    global _hub_client, _hub_tools_cache
    if _hub_client is None:
        identity_mgr = get_identity_manager()
        hub_url = await asyncio.to_thread(identity_mgr.get_config, "HUB_URL", DEFAULT_HUB_URL)
        _hub_client = FastMCPClient(hub_url)
        await _hub_client.__aenter__()
        _hub_tools_cache = await _hub_client.list_tools()
    return _hub_client

async def discover_external_mcps(force: bool = False):
    global _external_mcp_tools, _external_remote_mcps, _last_discovery_time
    
    now = time.time()
    if not force and (now - _last_discovery_time) < DISCOVERY_CACHE_TTL and _external_mcp_tools:
        return

    new_mcp_tools = {}
    new_remote_mcps: Dict[str, tuple[str, str]] = {}
    identity_mgr = get_identity_manager()
    mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
    for name in mcp_names:
        config_data = await asyncio.to_thread(identity_mgr.get_mcp_config, name)
        if not config_data: continue
        try:
            config = MCPConfig(**config_data)
            if config.remote is not None:
                # Edge-exported MCP server: the relay publishes its catalog
                # statically, so there is nothing to connect and no central secret
                # to resolve (the MCP session and its credentials live on the edge).
                if not config.tools:
                    logger.debug(f"Edge MCP '{name}' published no tools; skipping")
                    continue
                key = f"{config.remote.site}__{config.remote.mcp}"
                new_mcp_tools[key] = config.tools
                new_remote_mcps[key] = (config.remote.site, config.remote.mcp)
                continue
            if config.tools:
                new_mcp_tools[name] = config.tools
                continue

            transport = None
            if config.transport == "stdio":
                if not config.command: continue
                # Discovery is a throwaway session container: declared keys only,
                # 60 s deadline, no persisted state.
                declared = declared_env_keys(config)
                transport = RunnerStdioTransport(
                    target=config.name,
                    session_key=secrets.token_hex(16),
                    env={
                        k: v
                        for k, v in (config.env or {}).items()
                        if k in declared
                    },
                    manifest_digest=manifest_digest(config),
                    deadline_ms=60_000,
                    kind="discovery",
                    agent_token=agent_token_var.get(),
                )
            elif config.transport in ["http", "streamable-http"]:
                if not config.command: continue
                transport = StreamableHttpTransport(url=config.command, headers=config.env or {})
            elif config.transport == "sse":
                if not config.command: continue
                transport = SSETransport(url=config.command, headers=config.env or {})
            else:
                continue
            
            client = FastMCPClient(transport)
            async with client:
                tools = await client.list_tools()
                new_mcp_tools[name] = tools
        except Exception as e:
            logger.error(f"Failed to discover tools for MCP '{name}': {e}")
            
    _external_mcp_tools = new_mcp_tools
    _external_remote_mcps = new_remote_mcps
    _last_discovery_time = now

async def _bound_tool_denial(policy_tool_name: str) -> Optional[str]:
    """Gate one bound-tool call: a denial message, or ``None`` when it may execute.

    Tools bound to an agent from ``allowed_tools``/``allowed_mcps`` are called straight
    through their wrapper and never reach ``use_tool``, so this is their only gate. It
    uses the same evaluator, scope and principal as ``use_tool``, but reads the
    ``bound_tools_mode`` rollout key and tags its deny-ring entries
    ``surface="bound_tool"``.

    ``off`` (the default) is a no-I/O fast path once the authz cache is warm: the mode
    is read from the last snapshot and the principal is never resolved. A cold cache
    (first call after a start, or after a config change invalidated it) costs one read,
    as on the ``use_tool`` boundary.

    A denial is the recoverable string ``use_tool`` hands the model -- never a raised
    exception: one ungranted tool must not fail the whole turn. An exception inside the
    check also fails closed. Note the engine's documented caveat: if the authz state
    has *never* been readable, the cold snapshot says ``off``; this gate fails open
    only while the framework has never seen a policy, exactly like ``use_tool``.
    """
    from core import tool_authz

    surface = tool_authz.BOUND_TOOL_SURFACE

    def _verdict() -> Optional[str]:
        mode = tool_authz.cached_mode_for_surface(surface)
        if mode is None:
            mode = tool_authz.mode_for_surface(surface)
        if mode == "off":
            return None
        principal = tool_authz.resolve_current_principal()
        if tool_authz.allowed(
            principal, policy_tool_name, "tools:call", surface=surface, mode=mode
        ):
            return None
        return (
            f"SYSTEM: Access denied. Tool '{policy_tool_name}' is not permitted "
            "for this principal."
        )

    try:
        return await asyncio.to_thread(_verdict)
    except Exception:
        logger.exception("Bound-tool authorization check failed for %r", policy_tool_name)
        return (
            f"SYSTEM: Error checking tool access for '{policy_tool_name}'. "
            "Please try again later."
        )


def _register_mcp_tool(agent: Agent, mcp_tool: Any):
    safe_mcp_tool = copy.deepcopy(mcp_tool) if hasattr(mcp_tool, "model_copy") else mcp_tool
    tool_name_for_agent = safe_mcp_tool.name
    # Hub tools are addressed by their bare registry name in the policy, as in use_tool.
    policy_tool_name = safe_mcp_tool.name

    async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
        if denial := await _bound_tool_denial(policy_tool_name):
            return denial
        health_monitor = get_health_monitor()
        if (await asyncio.to_thread(health_monitor.get_status, "tool", safe_mcp_tool.name)).get("status") == "Offline":
            return "SYSTEM: Tool offline."
        kwargs["__user_id"] = user_id_var.get()
        kwargs["__agent_token"] = agent_token_var.get()
        client = await get_hub_client()
        result = await client.call_tool(safe_mcp_tool.name, kwargs)
        return result.content

    input_schema = getattr(safe_mcp_tool, "input_schema", None) or getattr(safe_mcp_tool, "inputSchema", None)
    if input_schema:
        from pydantic_ai.tools import Tool
        tool_obj = Tool.from_schema(
            function=tool_wrapper,
            name=tool_name_for_agent,
            description=safe_mcp_tool.description,
            json_schema=input_schema,
            takes_ctx=True
        )
        agent._function_toolset.add_tool(tool_obj)
    else:
        agent.tool(name=tool_name_for_agent, description=safe_mcp_tool.description)(tool_wrapper)

def _register_external_mcp_tool(
    agent: Agent, mcp_name: str, mcp_tool: Any, prefixed_name: str = None, provider: str = None
):
    """Registers one tool of a central MCP server.

    ``provider`` only affects the JSON schema handed to ``Tool.from_schema`` -- a root
    ``oneOf``/``anyOf`` is flattened for providers that cannot carry it (see
    ``core.mcp_schema``). The discovered tool keeps its verbatim schema: the registry
    and every other catalog still publish what the server declared.
    """
    safe_mcp_tool = copy.deepcopy(mcp_tool) if hasattr(mcp_tool, "model_copy") else mcp_tool
    tool_name_for_agent = prefixed_name or safe_mcp_tool.name
    # The policy namespaces MCP tools as `mcp__<server>__<tool>`, whatever the agent-side
    # name is -- the same string `use_tool` and the bootstrap generator use.
    policy_tool_name = f"mcp__{mcp_name}__{safe_mcp_tool.name}"

    async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
        if denial := await _bound_tool_denial(policy_tool_name):
            return denial
        health_monitor = get_health_monitor()
        if (await asyncio.to_thread(health_monitor.get_status, "tool", safe_mcp_tool.name)).get("status") == "Offline":
            return "SYSTEM: Tool offline."
        user_id = user_id_var.get()
        if not user_id: raise Exception("No user_id found")
        try:
            client = await get_external_mcp_client(mcp_name, user_id)
            result = await client.call_tool(safe_mcp_tool.name, kwargs)
            return result.content
        except Exception as e:
            if _is_session_failure(e):
                # Respawn lazily: the next call rebuilds the client and its
                # session container instead of failing until the cache TTL.
                invalidate_mcp_client(mcp_name, user_id)
                return (
                    f"Tool '{safe_mcp_tool.name}' returned an error: the MCP session "
                    f"was lost and will restart on the next call ({e})"
                )
            return f"Tool '{safe_mcp_tool.name}' returned an error: {e}"

    input_schema = getattr(safe_mcp_tool, "input_schema", None) or getattr(safe_mcp_tool, "inputSchema", None)
    if input_schema:
        from pydantic_ai.tools import Tool
        tool_obj = Tool.from_schema(
            function=tool_wrapper,
            name=tool_name_for_agent,
            description=safe_mcp_tool.description,
            json_schema=normalize_schema_for_provider(provider, input_schema),
            takes_ctx=True
        )
        agent._function_toolset.add_tool(tool_obj)
    else:
        agent.tool(name=tool_name_for_agent, description=safe_mcp_tool.description)(tool_wrapper)


def _register_remote_mcp_tool(
    agent: Agent, site: str, mcp: str, mcp_tool: Any, prefixed_name: str = None, provider: str = None
):
    """Registers one tool of an edge-exported MCP server.

    Deliberately never touches ``get_external_mcp_client``/``mcp_client_cache``:
    the MCP session lives on the edge (keyed per user) and central only POSTs the
    call to the relay. No health gate either: an edge MCP tool has no per-tool health
    record, and its readiness is ``discovery._remote_tool_configuration_status`` (is the
    owning edge connected), which the gateway and `is_tool_configured` both use — so
    nothing here needs to reset or probe health.

    ``provider`` behaves exactly as in ``_register_external_mcp_tool``: the edge's
    published catalog stays verbatim, only the provider-facing copy is normalized.
    """
    safe_mcp_tool = copy.deepcopy(mcp_tool) if hasattr(mcp_tool, "model_copy") else mcp_tool
    tool_name_for_agent = prefixed_name or f"mcp__{site}__{mcp}__{safe_mcp_tool.name}"
    # Edge tools are addressed `mcp__<site>__<mcp>__<tool>` in the policy namespace.
    policy_tool_name = f"mcp__{site}__{mcp}__{safe_mcp_tool.name}"

    async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
        if denial := await _bound_tool_denial(policy_tool_name):
            return denial
        user_id = user_id_var.get()
        if not user_id: raise Exception("No user_id found")
        result = await call_edge_mcp(
            site, mcp, safe_mcp_tool.name, kwargs, user_id,
            agent_token=agent_token_var.get(),
        )
        if isinstance(result, dict) and "error" in result:
            return f"Tool '{tool_name_for_agent}' returned an error: {result['error']}"
        return result.get("content") if isinstance(result, dict) else result

    input_schema = getattr(safe_mcp_tool, "input_schema", None) or getattr(safe_mcp_tool, "inputSchema", None)
    if input_schema:
        from pydantic_ai.tools import Tool
        tool_obj = Tool.from_schema(
            function=tool_wrapper,
            name=tool_name_for_agent,
            description=safe_mcp_tool.description,
            json_schema=normalize_schema_for_provider(provider, input_schema),
            takes_ctx=True
        )
        agent._function_toolset.add_tool(tool_obj)
    else:
        agent.tool(name=tool_name_for_agent, description=safe_mcp_tool.description)(tool_wrapper)


def _register_mcp_server_tools(agent: Agent, mcp_name: str, tools: List[Any], allowed_mcps: List[str], allowed_tools: List[str], provider: str = None) -> None:
    """Registers the allowed tools of one discovered MCP server on ``agent``.

    An edge-exported server (``<site>__<mcp>``) always takes the 4-part
    ``mcp__<site>__<mcp>__<tool>`` name: bare tool names would collide across
    sites, and 4-part is the only form the gateway can route back.

    Whether a server is edge-exported comes from ``discover_external_mcps``'s own record
    (``_external_remote_mcps``, keyed off the config's ``remote`` block) — never from
    ``"__" in mcp_name``, which would also match a central server named ``a__b``.

    ``allowed_mcps`` may also carry the ``<site>__*`` sugar: it grants every tool of every
    edge server *this site currently exports* — i.e. the ones in the discovery snapshot
    this rebuild just read. There is no stored expansion, and the match is on the
    discovered server's own site, so ``dc1__*`` can never reach ``dc10__x`` or a central
    server (only an edge server has ``edge_parts``).

    ``provider`` is the agent's effective provider; it only reaches the schema handed to
    ``Tool.from_schema`` (root-union normalization), never the catalogs.
    """
    edge_parts = _external_remote_mcps.get(mcp_name)
    wildcard = f"{edge_parts[0]}__*" if edge_parts else None
    for tool in tools:
        prefixed_name = f"mcp__{mcp_name}__{tool.name}"
        # Register if the entire MCP is allowed (by name or site wildcard), OR if the
        # specific tool (by prefixed or base name) is allowed.
        if not (
            mcp_name in allowed_mcps
            or (wildcard is not None and wildcard in allowed_mcps)
            or prefixed_name in allowed_tools
            or tool.name in allowed_tools
        ):
            continue
        if edge_parts:
            _register_remote_mcp_tool(agent, edge_parts[0], edge_parts[1], tool, prefixed_name=prefixed_name, provider=provider)
            continue
        name_to_use = prefixed_name if (mcp_name not in allowed_mcps and prefixed_name in allowed_tools) else tool.name
        _register_external_mcp_tool(agent, mcp_name, tool, prefixed_name=name_to_use, provider=provider)


def _edge_wildcard_sites(allowed_mcps: List[str]) -> Dict[str, str]:
    """``{site: entry}`` for the well-formed ``<site>__*`` entries in ``allowed_mcps``.

    A malformed entry (``*``, ``__*``, ``dc1*``, ``dc1__*__x``) is ignored with one
    debug line: it cannot match a discovered server (the grant compares the whole
    discovered ``<site>__*`` string), and a typo in an agent config must never fail a
    build.
    """
    sites: Dict[str, str] = {}
    for entry in allowed_mcps or []:
        if not isinstance(entry, str) or "*" not in entry:
            continue
        if EDGE_MCP_WILDCARD_RE.fullmatch(entry) is None:
            logger.debug(
                "Ignoring malformed allowed_mcps wildcard %r (expected '<site>__*')", entry
            )
            continue
        sites[entry[: -len("__*")]] = entry
    return sites


def _log_unmatched_mcp_wildcards(allowed_mcps: List[str]) -> None:
    """Debug-log ``<site>__*`` entries whose site has no discovered MCP right now.

    Not a warning: an edge that has not dialled in yet is a normal bring-up state, and
    the same config becomes effective on the next build once it does (the wildcard is
    expanded per build, never stored).
    """
    discovered_sites = {site for site, _mcp in _external_remote_mcps.values()}
    for site, entry in _edge_wildcard_sites(allowed_mcps).items():
        if site not in discovered_sites:
            logger.debug(
                "allowed_mcps wildcard %r matches no discovered MCPs for site '%s'; "
                "it grants nothing until that edge connects",
                entry,
                site,
            )

async def build_agent(agent_name: str) -> Agent:
    identity_mgr = get_identity_manager()
    
    # Use bulk fetching where possible within build_agent if appropriate
    # but build_agent is usually called for ONE agent.
    # However, discover_external_mcps IS now cached globally.
    
    if agent_name == "supervisor":
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, "supervisor")
        system_prompt = await asyncio.to_thread(identity_mgr.get_agent_skills, "supervisor")
        if not config_data:
            raise Exception("Supervisor config missing")
        config_data['a2a_access'] = []
    else:
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
        system_prompt = await asyncio.to_thread(identity_mgr.get_agent_skills, agent_name)
        if not config_data:
            raise Exception(f"Agent '{agent_name}' not found")
            
    config = AgentConfig(**config_data)
    if llm_defaults.needs_framework_defaults(config.provider, config.model):
        defaults = await asyncio.to_thread(llm_defaults.get_framework_defaults)
    else:
        defaults = llm_defaults.FrameworkDefaults()
    effective = llm_defaults.resolve_effective_llm_config(
        config.provider, config.model, config.base_url, defaults
    )
    provider = effective.provider
    # Prefetch the etcd-stored key off the event loop (build_agent already does its
    # other etcd I/O via asyncio.to_thread); resolve_model uses it directly.
    api_key = await asyncio.to_thread(llm_factory.get_provider_api_key, provider)
    model = resolve_model(provider, effective.model, effective.base_url, api_key=api_key)
    model_settings = build_model_settings(provider, effective.model, config.thinking_level)
    if effective.source != "explicit":
        logger.info(
            "LLM config unresolved for agent '%s'; using framework default %s/%s (source=%s)",
            agent_name,
            provider,
            effective.model,
            effective.source,
        )
    
    capabilities = []
    toolsets = []
    
    # 1. Observability
    capabilities.append(CostTracking(budget_usd=None))
    
    # 2. RLM
    if config.tags and "rlm" in config.tags:
        toolsets.append(create_rlm_toolset(sub_model=model))
        
    # 3. File Execution Standardizing
    allowed_tools = config.allowed_tools or []
    console_tool_names = ["ls", "read_file", "write_file", "edit_file", "glob", "grep", "execute"]
    allowed_console_tools = [t for t in console_tool_names if t in allowed_tools]
    
    if allowed_console_tools:
        # The background-shell tools (run_in_background/read_output/kill_shell/
        # list_shells) aren't part of the console tool allowlist and their spawn path
        # (BackgroundProcesses.start) has no env hook, so they can't be env-sanitized
        # -- disabled here.
        #
        # File tools are rooted at the agent's own report directory instead of the
        # whole workspace (risk 9): framework code needs no view of every tool's
        # source. `execute` leaves the process entirely (runner, network none).
        reports_root = (
            Path(os.getenv("WORKSPACE_ROOT", "/app/workspace")) / "reports" / agent_name
        ).resolve()
        capabilities.append(ConsoleCapability(
            backend=RunnerConsoleBackend(
                root_dir=reports_root,
                enable_execute=("execute" in allowed_console_tools),
            ),
            include_background=False,
        ))
        blocked_console_tools = [t for t in console_tool_names if t not in allowed_tools]
        if blocked_console_tools:
            capabilities.append(ToolGuard(blocked=blocked_console_tools))
            
    # 4. A2A Delegation (non-supervisor agents only; supervisor uses subagents-pydantic-ai toolset instead)
    subagent_configs = []
    for target in config.a2a_access or []:
        target_cfg = await asyncio.to_thread(identity_mgr.get_agent_config, target)
        if target_cfg:
            if not is_agent_internal(target_cfg):
                logger.warning(
                    f"Agent '{agent_name}' attempted to configure A2A delegation to "
                    f"'{target}', but '{target}' has internal=False. Skipping."
                )
                continue
            target_instructions = await asyncio.to_thread(identity_mgr.get_agent_skills, target)
            subagent_configs.append(SubAgentConfig(
                name=target,
                description=target_cfg.get("description", f"Call the {target} agent"),
                instructions=target_instructions or ""
            ))

    if subagent_configs:
        # default_model must be a resolved Model instance: pydantic-ai's infer_model
        # only accepts "provider:model" strings, so a bare name like "gemini-2.5-pro"
        # would raise UserError at subagent compile time.
        capabilities.append(SubAgentCapability(subagents=subagent_configs, default_model=model))

    # 5. Supervisor delegation toolset — task/check_task/wait_tasks/cancel etc.
    if agent_name == "supervisor":
        toolsets.append(create_subagent_toolset(
            subagents=[],
            include_general_purpose=False,
            default_model=model,
            max_nesting_depth=0,
            registry=get_supervisor_registry(),
        ))

    agent = Agent(
        model,
        system_prompt=system_prompt,
        name=config.name,
        model_settings=model_settings,
        retries=3,
        capabilities=capabilities,
        toolsets=toolsets
    )

    # 4.5 Agent Memory (Hindsight) — automatic recall, framework-level.
    # Gated by the admin 'agent_memory_enabled' feature flag AND the agent's config.
    from core.memory import get_memory_manager
    memory_mgr = get_memory_manager()
    if await asyncio.to_thread(memory_mgr.active_for, config):

        @agent.instructions
        async def _recall_memory(ctx: RunContext[None]) -> str:
            if not await asyncio.to_thread(memory_mgr.is_globally_enabled):
                return ""
            query = _latest_user_text(ctx)
            if not query:
                return ""
            # Bank is resolved at recall time, not build time: the isolation flag can
            # flip while this cached agent lives, and the user comes from the request
            # context (user_id_var), which is only known per-run.
            bank = await asyncio.to_thread(memory_mgr.bank_for, config.name, user_id_var.get())
            return await memory_mgr.recall(bank=bank, query=query)

    # 5. Hub Tools (skipping native console tools)
    hub_client = await get_hub_client()
    for tool in _hub_tools_cache:
        if tool.name in allowed_tools and tool.name not in console_tool_names:
            _register_mcp_tool(agent, tool)

    # 6. External MCP Tools (This is now CACHED globally)
    await discover_external_mcps()
    allowed_mcps = config.allowed_mcps or []
    _log_unmatched_mcp_wildcards(allowed_mcps)
    for mcp_name, tools in _external_mcp_tools.items():
        _register_mcp_server_tools(agent, mcp_name, tools, allowed_mcps, allowed_tools, provider=provider)

    # 7. Admin Tools
    if agent_name == "supervisor":
        _register_admin_tools(agent)

    return agent


async def get_agent(agent_name: str) -> Agent:
    """Cache-aware wrapper around build_agent. Returns a cached instance if available,
    otherwise builds, caches, and returns. Per-name lock prevents build stampedes."""
    if agent_name in _agent_cache:
        return _agent_cache[agent_name]
    if agent_name not in _agent_locks:
        _agent_locks[agent_name] = asyncio.Lock()
    async with _agent_locks[agent_name]:
        if agent_name in _agent_cache:
            return _agent_cache[agent_name]
        agent = await build_agent(agent_name)
        _agent_cache[agent_name] = agent
        if agent_name != "supervisor":
            identity_mgr = get_identity_manager()
            cfg = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
            description = (cfg or {}).get("description", "")
            registry = get_supervisor_registry()
            if not registry.exists(agent_name) and is_agent_external(cfg):
                registry.register(
                    SubAgentConfig(name=agent_name, description=description, instructions=""),
                    agent,
                )
        return agent


def evict_agent(agent_name: str, _visited: Optional[set] = None, _all_configs: Optional[Dict[str, Any]] = None) -> None:
    """Remove an agent from the cache (called from etcd watch thread — must be sync).

    Also cascades the eviction to every OTHER cached agent whose `a2a_access` lists
    `agent_name` as a delegation target. This closes a staleness gap: `build_agent()`'s
    A2A loop compiles a caller's reachable-subagent set once, at build time, into a static
    `SubAgentCapability` baked into the vendored subagents package (no live re-check like
    `FrameworkAgentRegistry.get_compiled()` does for `external`). If a target agent's
    `internal` flag flips to False after a caller has already been built, the caller's
    cached, already-compiled agent would otherwise keep a working delegation path to that
    target indefinitely. Evicting the caller too forces it to be rebuilt (re-running the
    A2A loop's `internal` check) the next time it's requested.

    `_visited` guards against infinite recursion on a2a_access cycles/diamonds; it's an
    internal recursion detail and defaults to None so existing callers (e.g. `on_agent_change`)
    are unaffected.

    `_all_configs` lets a bulk caller (``evict_all_agents``) fetch the config map once
    and reuse it across every eviction, instead of issuing one etcd read per cached
    agent on the shared watch thread. When None it is fetched here as before.
    """
    if _visited is None:
        _visited = set()
    if agent_name in _visited:
        return
    _visited.add(agent_name)

    _agent_cache.pop(agent_name, None)
    if agent_name != "supervisor" and _supervisor_registry is not None:
        _supervisor_registry.remove(agent_name)

    if _all_configs is None:
        try:
            all_configs = get_identity_manager().get_all_agent_configs()
        except Exception as e:
            logger.error(f"evict_agent: failed to fetch agent configs for reverse-dependency propagation: {e}")
            return
    else:
        all_configs = _all_configs

    for other_name, cfg in (all_configs or {}).items():
        if other_name == agent_name or other_name in _visited:
            continue
        if agent_name in ((cfg or {}).get("a2a_access") or []):
            evict_agent(other_name, _visited, all_configs)


def evict_all_agents() -> None:
    """Evict every cached agent (sync: called from the etcd watch thread).

    Fetches the agent configs once up front so the reverse-dependency walk in
    ``evict_agent`` doesn't issue one etcd read per cached agent.
    """
    try:
        all_configs = get_identity_manager().get_all_agent_configs() or {}
    except Exception as e:
        logger.error(f"evict_all_agents: failed to fetch agent configs: {e}")
        all_configs = {}
    for name in list(_agent_cache.keys()):
        evict_agent(name, _all_configs=all_configs)


_llm_key_watch_id: Any = None


def _on_llm_keys_change(event) -> None:
    """Sync etcd watch callback: flush every cache derived from the LLM keys.

    A key rotation/deletion must drop both the resolved-key TTL cache and every
    already-built agent (which baked a model bound to the old key), plus the
    cached embeddings client. Runs on the watch thread, so it must not await.
    """
    from core import embeddings, llm_factory
    llm_factory.reset_key_cache()
    embeddings.reset_client_cache()
    evict_all_agents()


def install_llm_key_watch() -> None:
    """Register the single etcd watch that invalidates LLM-key-derived caches.

    Idempotent: guarded by a module-level watch-id sentinel, so repeat calls are
    no-ops. The host process and the taskiq worker are separate processes with
    separate in-memory caches, so each calls this once at startup.
    """
    global _llm_key_watch_id
    if _llm_key_watch_id is not None:
        return
    identity_mgr = get_identity_manager()
    _llm_key_watch_id = identity_mgr.client.add_watch_prefix_callback(
        "/identities/system/system/llm_keys", _on_llm_keys_change
    )


def cancel_llm_key_watch() -> None:
    """Cancel the LLM-key etcd watch and clear the sentinel (idempotent)."""
    global _llm_key_watch_id
    watch_id = _llm_key_watch_id
    _llm_key_watch_id = None
    if watch_id is not None:
        get_identity_manager().client.cancel_watch(watch_id)


_llm_defaults_watch_id: Any = None


def _on_llm_defaults_change(event) -> None:
    """Sync etcd watch callback: flush every cache derived from the framework defaults.

    A changed default must drop the TTL cache *and* every already-built agent (which
    baked in the previous effective model/endpoint), otherwise an org-default change
    would only take effect after the agent is evicted for some other reason. Runs on
    the watch thread, so it must not await.
    """
    from core import llm_defaults

    llm_defaults.reset_defaults_cache()
    evict_all_agents()


def install_llm_defaults_watch() -> None:
    """Register the etcd watch that invalidates framework-default-derived caches.

    Idempotent. The host and the taskiq worker are separate processes with separate
    agent caches, so each calls this once at startup.
    """
    global _llm_defaults_watch_id
    if _llm_defaults_watch_id is not None:
        return
    identity_mgr = get_identity_manager()
    _llm_defaults_watch_id = identity_mgr.client.add_watch_prefix_callback(
        "/config/framework/default_llm_", _on_llm_defaults_change
    )


def cancel_llm_defaults_watch() -> None:
    """Cancel the framework-defaults etcd watch and clear the sentinel (idempotent)."""
    global _llm_defaults_watch_id
    watch_id = _llm_defaults_watch_id
    _llm_defaults_watch_id = None
    if watch_id is not None:
        get_identity_manager().client.cancel_watch(watch_id)


async def prewarm_agents() -> None:
    """Best-effort background build of all non-background agents after startup."""
    identity_mgr = get_identity_manager()
    _BACKGROUND_TYPES = ("background_agent", "background_script")
    try:
        agent_names = await asyncio.to_thread(identity_mgr.list_agents)
    except Exception as e:
        logger.error(f"Prewarm: failed to list agents: {e}")
        return
    for name in agent_names:
        try:
            cfg = await asyncio.to_thread(identity_mgr.get_agent_config, name)
            if not cfg or cfg.get("type") in _BACKGROUND_TYPES:
                continue
            await get_agent(name)
        except Exception as e:
            logger.error(f"Prewarm: skipping '{name}': {e}")


def _register_admin_tools(agent: Agent):
    identity_mgr = get_identity_manager()

    def _current_authz_principal() -> Optional[str]:
        """Best-effort authorization principal for the tool seams below.

        Taskiq/host turns resolve from the caller's token via the tool-authz
        engine; when that is unavailable we pass None and let the callee resolve
        (or fail closed) on its own rather than breaking the agent turn.
        """
        try:
            from core import tool_authz

            return tool_authz.resolve_current_principal()
        except Exception:
            logger.debug("Could not resolve tool-authorization principal", exc_info=True)
            return None

    @agent.tool_plain(
        name="search_agents",
        description=(
            "Find the specialized agents most relevant to a request. Returns a ranked "
            "shortlist of {name, description, status, configured}. Use this to pick an "
            "agent name, then call task(subagent_type, description) to run it. "
            "Do not delegate to agents where configured=false or status='Offline'. "
            "Disabled agents (status='disabled') can be re-enabled with manage_agent. "
            "Does not return the full catalog — search with a focused query."
        ),
    )
    async def search_agents(query: str, limit: Optional[int] = None) -> List[Dict]:
        from core.agent_search import search_agents as _search
        from core.discovery import is_agent_configured
        # include_disabled=True so manage_agent can still locate disabled agents to re-enable.
        results = await _search(query, limit=limit, include_disabled=True)
        user_id = user_id_var.get()
        if user_id and results:
            active_items = []
            for r in results:
                if r.get("unavailable_match") or r.get("status") == "Offline":
                    r["configured"] = False
                else:
                    active_items.append(r)

            if active_items:
                statuses = await asyncio.gather(
                    *(is_agent_configured(r["name"], user_id) for r in active_items),
                    return_exceptions=True,
                )
                for r, status_dict in zip(active_items, statuses):
                    if isinstance(status_dict, Exception) or not isinstance(status_dict, dict):
                        r["configured"] = True
                        continue
                    is_configured = status_dict.get("configured", True)
                    r["configured"] = is_configured
                    if not is_configured:
                        missing = []
                        if status_dict.get("missing_secrets"):
                            missing.append(f"secrets: {', '.join(status_dict['missing_secrets'])}")
                        if status_dict.get("missing_variables"):
                            missing.append(f"variables: {', '.join(status_dict['missing_variables'])}")
                        note = (
                            f" [NOT CONFIGURED — missing {'; '.join(missing)}. Configure at /agents/{r['name']}/configure]"
                            if missing else
                            f" [NOT CONFIGURED — configure at /agents/{r['name']}/configure]"
                        )
                        r["description"] = r.get("description", "") + note
        else:
            for r in results:
                if r.get("unavailable_match") or r.get("status") == "Offline":
                    r["configured"] = False
                else:
                    r["configured"] = True
        return results

    @agent.tool_plain(
        name="search_tools",
        description=(
            "Find deterministic tools available for direct execution — CLI lookups, "
            "resource inspections, status checks, single commands. Returns a ranked "
            "shortlist of Tool Cards {name, description, parameters, configured, status, "
            "source}. Use this to pick a tool name and its parameter schema, then call "
            "use_tool(tool_name, arguments) to execute it directly — no agent hop needed. "
            "Tools with configured=false are missing credentials — do not call use_tool "
            "on them; tell the user which credentials are missing instead. A card with "
            "detail='lazy' has no parameters yet — call describe_tool for its schema. "
            "Does not return the full catalog — search with a focused query."
        ),
    )
    async def search_tools(query: str, limit: Optional[int] = None) -> List[Dict]:
        from core.tool_search import search_tools as _search_tools_ranked
        user_id = user_id_var.get()
        return await _search_tools_ranked(
            query,
            limit=limit,
            user_id=user_id,
            principal=_current_authz_principal(),
        )

    @agent.tool_plain(
        name="describe_tool",
        description=(
            "Return the full schema (parameters and description) for exactly one tool. "
            "Use after search_tools when a card is summary-only (detail: 'lazy') or when "
            "the schema is needed without ranking. Takes the same name forms as use_tool "
            "and never executes the tool."
        ),
    )
    async def describe_tool(tool_name: str) -> Dict[str, Any]:
        from core.tool_search import describe_tool_entry

        return await describe_tool_entry(tool_name, user_id_var.get())

    @agent.tool_plain(
        name="use_tool",
        description=(
            "Directly execute a whitelisted deterministic tool with arguments, bypassing "
            "any agent delegation. Always call search_tools first to confirm the exact "
            "tool name, its parameter schema, and that it is configured — do not guess. "
            "Returns the raw structured tool output (e.g. stdout/JSON), not a "
            "conversational summary."
        ),
    )
    async def use_tool(tool_name: str, arguments: Dict[str, Any]) -> Any:
        user_id = user_id_var.get()
        from core.discovery import is_tool_configured
        return await execute_whitelisted_tool(
            tool_name,
            arguments,
            user_id,
            identity_manager=get_identity_manager(),
            is_configured=is_tool_configured,
            get_hub_client_fn=get_hub_client,
            get_external_mcp_client_fn=get_external_mcp_client,
            call_edge_mcp_fn=call_edge_mcp,
            principal=_current_authz_principal(),
        )

    @agent.tool_plain(name="manage_agent", description="Enable, disable or reload an agent.")
    async def manage_agent(name: str, action: str) -> str:
        if action not in ("disable", "enable", "reload"):
            return f"SYSTEM: Unknown action '{action}'. Supported actions: disable, enable, reload."
        cfg = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        is_workflow = bool(cfg and cfg.get("type") in ("background_agent", "background_script"))

        toggle = identity_mgr.toggle_disabled_workflow if is_workflow else identity_mgr.toggle_disabled_standard_agent
        try:
            await asyncio.to_thread(toggle, name, action == "disable")
        except EtcdContentionError:
            # The list was not modified; report in-band so the turn (and agent health) survives.
            return f"SYSTEM: Could not {action} agent '{name}' due to concurrent changes. Please retry."

        if action == "disable":
            await _refresh_registry_snapshot_bounded()
            return f"Agent {name} disabled."
        elif action in ("enable", "reload"):
            if action == "reload":
                await asyncio.to_thread(evict_agent, name)
            await _refresh_registry_snapshot_bounded()
            return f"Agent {name} enabled."
