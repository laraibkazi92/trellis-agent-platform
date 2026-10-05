# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
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

from asyncache import cached
from cachetools import TTLCache

from pydantic_ai import Agent, RunContext

from fastmcp import Client as FastMCPClient
from fastmcp.client import StdioTransport, SSETransport, StreamableHttpTransport

from subagents_pydantic_ai import SubAgentCapability, SubAgentConfig
from subagents_pydantic_ai.registry import DynamicAgentRegistry
from subagents_pydantic_ai.toolset import create_subagent_toolset
from subagents_pydantic_ai.types import CompiledSubAgent
from pydantic_ai_backends import ConsoleCapability, LocalBackend
from pydantic_ai_shields import CostTracking, ToolGuard
from pydantic_ai_rlm import create_rlm_toolset

from core.auth import EtcdContentionError, IdentityManager, get_identity_manager, user_id_var
from core.llm_factory import build_model_settings, resolve_model, resolve_provider
from core.models import AgentConfig, MCPConfig, is_agent_external, is_agent_internal
from core.health import HealthMonitor, evaluate_health_status, DEFAULT_HEALTH_COOLDOWN_SECONDS
from core.discovery import is_agent_configured
from core.tool_search import DEFAULT_LIMIT as TOOL_SEARCH_LIMIT, execute_whitelisted_tool

logger = logging.getLogger(__name__)

# Shared global states and caches
_hub_client: Optional[FastMCPClient] = None
_hub_tools_cache: List[Any] = []
_external_mcp_tools: Dict[str, List[Any]] = {}
_last_discovery_time: float = 0
DISCOVERY_CACHE_TTL = 60 # Cache discovery for 60 seconds

mcp_client_cache = TTLCache(maxsize=100, ttl=300)

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


try:
    REGISTRY_REFRESH_TIMEOUT = max(0.1, float(os.getenv("FRAMEWORK_REGISTRY_REFRESH_TIMEOUT", "5")))
except (TypeError, ValueError):
    REGISTRY_REFRESH_TIMEOUT = 5.0


class _RegistryEligibilitySnapshot:
    """Thread-refreshed {name: {"disabled", "offline", "external"}} eligibility view.

    get_compiled() must stay sync (vendored DynamicAgentRegistry API) and therefore
    cannot await asyncio.to_thread; it reads this snapshot instead of etcd.
    Fail-open: on refresh error the previous snapshot is kept; names absent from the
    snapshot fall through to super().get_compiled() (same as today's missing-config path).
    """
    try:
        TTL = max(1.0, float(os.getenv("FRAMEWORK_REGISTRY_SNAPSHOT_TTL", "15")))
    except (TypeError, ValueError):
        TTL = 15.0

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
            cooldown = getattr(self._health_monitor, "cooldown_seconds", DEFAULT_HEALTH_COOLDOWN_SECONDS)
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
        while not self._stop.wait(self.TTL):
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
            timeout=REGISTRY_REFRESH_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "Registry snapshot refresh timed out after %.1fs; routing will reflect the toggle within the TTL (%.0fs).",
            REGISTRY_REFRESH_TIMEOUT,
            _RegistryEligibilitySnapshot.TTL,
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

@cached(cache=mcp_client_cache)
async def get_external_mcp_client(mcp_name: str, user_id: str) -> FastMCPClient:
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
        full_env = os.environ.copy()
        full_env.update(env)
        transport = StdioTransport(command=config.command, args=config.args or [], env=full_env, keep_alive=True)
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
    global _external_mcp_tools, _last_discovery_time
    
    now = time.time()
    if not force and (now - _last_discovery_time) < DISCOVERY_CACHE_TTL and _external_mcp_tools:
        return

    new_mcp_tools = {}
    identity_mgr = get_identity_manager()
    mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
    for name in mcp_names:
        config_data = await asyncio.to_thread(identity_mgr.get_mcp_config, name)
        if not config_data: continue
        try:
            config = MCPConfig(**config_data)
            if config.tools:
                new_mcp_tools[name] = config.tools
                continue

            transport = None
            if config.transport == "stdio":
                if not config.command: continue
                transport = StdioTransport(command=config.command, args=config.args or [], env=config.env or {}, keep_alive=False)
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
    _last_discovery_time = now

def _register_mcp_tool(agent: Agent, mcp_tool: Any):
    safe_mcp_tool = copy.deepcopy(mcp_tool) if hasattr(mcp_tool, "model_copy") else mcp_tool
    tool_name_for_agent = safe_mcp_tool.name
    
    async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
        health_monitor = get_health_monitor()
        if (await asyncio.to_thread(health_monitor.get_status, "tool", safe_mcp_tool.name)).get("status") == "Offline":
            return "SYSTEM: Tool offline."
        kwargs["__user_id"] = user_id_var.get()
        client = await get_hub_client()
        result = await client.call_tool(safe_mcp_tool.name, kwargs)
        return result.content

    input_schema = getattr(safe_mcp_tool, "inputSchema", None) or getattr(safe_mcp_tool, "input_schema", None)
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

def _register_external_mcp_tool(agent: Agent, mcp_name: str, mcp_tool: Any, prefixed_name: str = None):
    safe_mcp_tool = copy.deepcopy(mcp_tool) if hasattr(mcp_tool, "model_copy") else mcp_tool
    tool_name_for_agent = prefixed_name or safe_mcp_tool.name

    async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
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
            return f"Tool '{safe_mcp_tool.name}' returned an error: {e}"

    input_schema = getattr(safe_mcp_tool, "inputSchema", None) or getattr(safe_mcp_tool, "input_schema", None)
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
    provider = resolve_provider(config.provider, config.model)
    model = resolve_model(provider, config.model, config.base_url)
    model_settings = build_model_settings(provider, config.model, config.thinking_level)
    
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
        capabilities.append(ConsoleCapability(backend=LocalBackend(root_dir="/workspace", enable_execute=("execute" in allowed_console_tools))))
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
    for mcp_name, tools in _external_mcp_tools.items():
        for tool in tools:
            prefixed_name = f"mcp__{mcp_name}__{tool.name}"
            # Register if the entire MCP is allowed, OR if the specific tool (by prefixed or base name) is allowed.
            if mcp_name in allowed_mcps or prefixed_name in allowed_tools or tool.name in allowed_tools:
                name_to_use = prefixed_name if (mcp_name not in allowed_mcps and prefixed_name in allowed_tools) else tool.name
                _register_external_mcp_tool(agent, mcp_name, tool, prefixed_name=name_to_use)

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


def evict_agent(agent_name: str, _visited: Optional[set] = None) -> None:
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
    """
    if _visited is None:
        _visited = set()
    if agent_name in _visited:
        return
    _visited.add(agent_name)

    _agent_cache.pop(agent_name, None)
    if agent_name != "supervisor" and _supervisor_registry is not None:
        _supervisor_registry.remove(agent_name)

    try:
        identity_mgr = get_identity_manager()
        all_configs = identity_mgr.get_all_agent_configs()
    except Exception as e:
        logger.error(f"evict_agent: failed to fetch agent configs for reverse-dependency propagation: {e}")
        return

    for other_name, cfg in (all_configs or {}).items():
        if other_name == agent_name or other_name in _visited:
            continue
        if agent_name in ((cfg or {}).get("a2a_access") or []):
            evict_agent(other_name, _visited)


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
    async def search_agents(query: str, limit: int = 8) -> List[Dict]:
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
            "on them; tell the user which credentials are missing instead. "
            "Does not return the full catalog — search with a focused query."
        ),
    )
    async def search_tools(query: str, limit: int = TOOL_SEARCH_LIMIT) -> List[Dict]:
        from core.tool_search import search_tools as _search_tools_ranked
        user_id = user_id_var.get()
        return await _search_tools_ranked(query, limit=limit, user_id=user_id)

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
