import os
import yaml
import asyncio
import copy
import time
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from asyncache import cached
from cachetools import TTLCache

from pydantic_ai import Agent, RunContext
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings

from fastmcp import Client as FastMCPClient
from fastmcp.client import StdioTransport, SSETransport, StreamableHttpTransport

from subagents_pydantic_ai import SubAgentCapability, SubAgentConfig
from subagents_pydantic_ai.registry import DynamicAgentRegistry
from subagents_pydantic_ai.toolset import create_subagent_toolset
from subagents_pydantic_ai.types import CompiledSubAgent
from pydantic_ai_backends import ConsoleCapability, LocalBackend
from pydantic_ai_shields import CostTracking, ToolGuard
from pydantic_ai_rlm import create_rlm_toolset

from core.auth import IdentityManager, user_id_var
from core.models import AgentConfig, MCPConfig, is_agent_external, is_agent_internal
from core.health import HealthMonitor
from core.discovery import is_agent_configured
from core.tool_search import DEFAULT_LIMIT as TOOL_SEARCH_LIMIT

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


class FrameworkAgentRegistry(DynamicAgentRegistry):
    """DynamicAgentRegistry backed by the framework's agent cache.

    Overrides get_compiled() to return None for disabled or offline agents so
    the supervisor's task() tool never routes to them.
    """
    def __init__(self, identity_mgr: "IdentityManager", health_monitor: "HealthMonitor"):
        super().__init__()
        self._identity_mgr = identity_mgr
        self._health_monitor = health_monitor

    def get_compiled(self, name: str) -> Optional[CompiledSubAgent]:
        if name in self._identity_mgr.get_disabled_standard_agents():
            return None
        if self._health_monitor.get_status("agent", name).get("status") == "Offline":
            return None
        cfg = self._identity_mgr.get_agent_config(name)
        if cfg and not is_agent_external(cfg):
            return None
        return super().get_compiled(name)


_supervisor_registry: Optional[FrameworkAgentRegistry] = None


def get_supervisor_registry() -> FrameworkAgentRegistry:
    global _supervisor_registry
    if _supervisor_registry is None:
        _supervisor_registry = FrameworkAgentRegistry(get_identity_manager(), get_health_monitor())
    return _supervisor_registry


_identity_mgr: Optional[IdentityManager] = None
def get_identity_manager() -> IdentityManager:
    global _identity_mgr
    if _identity_mgr is None:
        _identity_mgr = IdentityManager(
            host=os.getenv("ETCD_HOST", "127.0.0.1"),
            port=int(os.getenv("ETCD_PORT", 2379))
        )
    return _identity_mgr

_health_monitor: Optional[HealthMonitor] = None
def get_health_monitor() -> HealthMonitor:
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = HealthMonitor(get_identity_manager())
    return _health_monitor

DEFAULT_HUB_URL = os.getenv("HUB_URL", "http://localhost:8001/mcp")

GEMINI_2_5_PRO_MODELS = {"gemini-2.5-pro"}
GEMINI_2_5_FLASH_MODELS = {"gemini-2.5-flash"}
LITE_MODELS = {"gemini-3.1-flash-lite-preview", "gemini-2.5-flash-lite"}
GEMINI_3_MODELS = {"gemini-3.1-pro-preview", "gemini-3-flash-preview"}

GEMINI_2_5_PRO_BUDGETS = {"low": 1024, "medium": 8192, "high": 16384}
GEMINI_2_5_FLASH_BUDGETS = {"low": 1024, "medium": 4096, "high": 8192}

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

def _get_model_settings(model_name: str, thinking_level: str) -> Optional[GoogleModelSettings]:
    if not thinking_level or thinking_level in ("none", "n/a"): return None
    if model_name in LITE_MODELS: return None
    if model_name in GEMINI_2_5_PRO_MODELS:
        budget = GEMINI_2_5_PRO_BUDGETS.get(thinking_level.lower(), 8192)
        return GoogleModelSettings(google_thinking_config={"thinking_budget": budget, "include_thoughts": False})
    elif model_name in GEMINI_2_5_FLASH_MODELS:
        budget = GEMINI_2_5_FLASH_BUDGETS.get(thinking_level.lower(), 4096)
        return GoogleModelSettings(google_thinking_config={"thinking_budget": budget, "include_thoughts": False})
    elif model_name in GEMINI_3_MODELS:
        return GoogleModelSettings(google_thinking_config={"thinking_level": thinking_level.lower(), "include_thoughts": False})
    return None

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
        hub_url = identity_mgr.get_config("HUB_URL", DEFAULT_HUB_URL)
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
            print(f"Failed to discover tools for MCP '{name}': {e}")
            
    _external_mcp_tools = new_mcp_tools
    _last_discovery_time = now

def _register_mcp_tool(agent: Agent, mcp_tool: Any):
    safe_mcp_tool = copy.deepcopy(mcp_tool) if hasattr(mcp_tool, "model_copy") else mcp_tool
    tool_name_for_agent = safe_mcp_tool.name
    
    async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
        health_monitor = get_health_monitor()
        if health_monitor.get_status("tool", safe_mcp_tool.name).get("status") == "Offline":
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
        if health_monitor.get_status("tool", safe_mcp_tool.name).get("status") == "Offline":
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
    model = GoogleModel(config.model)
    model_settings = _get_model_settings(config.model, config.thinking_level)
    
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
                print(
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
        capabilities.append(SubAgentCapability(subagents=subagent_configs, default_model=config.model))

    # 5. Supervisor delegation toolset — task/check_task/wait_tasks/cancel etc.
    if agent_name == "supervisor":
        toolsets.append(create_subagent_toolset(
            subagents=[],
            include_general_purpose=False,
            default_model=config.model,
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
    if memory_mgr.active_for(config):
        memory_bank = config.name

        @agent.instructions
        async def _recall_memory(ctx: RunContext[None]) -> str:
            if not memory_mgr.is_globally_enabled():
                return ""
            query = _latest_user_text(ctx)
            if not query:
                return ""
            return await memory_mgr.recall(bank=memory_bank, query=query)

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
        print(f"evict_agent: failed to fetch agent configs for reverse-dependency propagation: {e}")
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
        print(f"Prewarm: failed to list agents: {e}")
        return
    for name in agent_names:
        try:
            cfg = await asyncio.to_thread(identity_mgr.get_agent_config, name)
            if not cfg or cfg.get("type") in _BACKGROUND_TYPES:
                continue
            await get_agent(name)
        except Exception as e:
            print(f"Prewarm: skipping '{name}': {e}")


async def _is_tool_publicly_whitelisted(tool_name: str) -> bool:
    """Authorization Guard for the supervisor's `use_tool`: check `public`/`public_tools`
    directly against the tool's/MCP's own registry config.

    Deliberately mirrors `core.gateway._is_tool_publicly_whitelisted` rather than importing
    it — `core/gateway.py` already imports `get_hub_client`/`get_external_mcp_client` from
    this module, so importing back from `gateway.py` here would create a circular import.
    Fails closed on anything unexpected (unknown tool, malformed `mcp__` name, non-`True`
    `public` value, non-list `public_tools`), matching `is_tool_configured`'s secure-by-default
    behavior.
    """
    identity_mgr = get_identity_manager()
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) != 3:
            return False
        _, server_name, sub_tool_name = parts
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, server_name)
        if not config:
            return False
        public_tools_raw = config.get("public_tools", [])
        public_tools = set(public_tools_raw) if isinstance(public_tools_raw, list) else set()
        return config.get("public") is True or sub_tool_name in public_tools

    config = await asyncio.to_thread(identity_mgr.get_tool_config, tool_name)
    if not config:
        return False
    return config.get("public") is True


def _extract_tool_output(result: Any) -> Any:
    """Unwrap a fastmcp `CallToolResult` into the raw structured value a direct caller
    expects (mirrors `core.gateway._extract_tool_output` — see that function's docstring
    for why `.data`/`.structured_content` are preferred over pydantic-ai's agent-facing
    `.content`)."""
    from mcp.types import TextContent
    if result.data is not None:
        return result.data
    if result.structured_content is not None:
        return result.structured_content
    texts = [c.text for c in (result.content or []) if isinstance(c, TextContent)]
    if texts:
        return "\n".join(texts)
    return None


def _register_admin_tools(agent: Agent):
    identity_mgr = get_identity_manager()

    @agent.tool_plain(
        name="search_agents",
        description=(
            "Find the specialized agents most relevant to a request. Returns a ranked "
            "shortlist of {name, description, status, configured}. Use this to pick an "
            "agent name, then call task(subagent_type, description) to run it. "
            "Agents with configured=false are missing credentials — do not delegate to them. "
            "Disabled agents (status='disabled') can be re-enabled with manage_agent. "
            "Does not return the full catalog — search with a focused query."
        ),
    )
    async def search_agents(query: str, limit: int = 8) -> List[Dict]:
        from core.agent_search import search_agents as _search
        from core.discovery import discover_agents
        # include_disabled=True so manage_agent can still locate disabled agents to re-enable.
        results = await _search(query, limit=limit, include_disabled=True)
        user_id = user_id_var.get()
        if user_id and results:
            discovered = await discover_agents(user_id=user_id)
            config_lookup = {a["name"]: a for a in discovered}
            for r in results:
                agent_dict = config_lookup.get(r["name"], {})
                is_configured = agent_dict.get("is_configured", True)
                r["configured"] = is_configured
                if not is_configured:
                    missing = []
                    if agent_dict.get("missing_secrets"):
                        missing.append(f"secrets: {', '.join(agent_dict['missing_secrets'])}")
                    if agent_dict.get("missing_variables"):
                        missing.append(f"variables: {', '.join(agent_dict['missing_variables'])}")
                    note = (
                        f" [NOT CONFIGURED — missing {'; '.join(missing)}. Configure at /agents/{r['name']}/configure]"
                        if missing else
                        f" [NOT CONFIGURED — configure at /agents/{r['name']}/configure]"
                    )
                    r["description"] = r.get("description", "") + note
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

        try:
            whitelisted = await _is_tool_publicly_whitelisted(tool_name)
        except Exception as e:
            return f"SYSTEM: Error checking tool access for '{tool_name}': {e}"
        if not whitelisted:
            return f"SYSTEM: Access denied. Tool '{tool_name}' is internal and not exposed for direct execution."

        try:
            from core.discovery import is_tool_configured
            status = await is_tool_configured(tool_name, user_id)
        except Exception as e:
            return f"SYSTEM: Error checking configuration for tool '{tool_name}': {e}"
        if not status["configured"]:
            missing = status["missing_secrets"] + status["missing_variables"]
            missing_text = ", ".join(missing) if missing else "required configuration"
            return f"SYSTEM: Tool '{tool_name}' requires configuration before it can be used. Missing: {missing_text}. Configure at /configuration"

        try:
            if tool_name.startswith("mcp__"):
                _, server_name, sub_tool_name = tool_name.split("__", 2)
                client = await get_external_mcp_client(server_name, user_id)
                result = await client.call_tool(sub_tool_name, arguments, raise_on_error=False)
            else:
                client = await get_hub_client()
                result = await client.call_tool(tool_name, {**arguments, "__user_id": user_id}, raise_on_error=False)
        except Exception as e:
            return f"SYSTEM: Error executing tool '{tool_name}': {e}"

        return _extract_tool_output(result)

    @agent.tool_plain(name="manage_agent", description="Enable, disable or reload an agent.")
    async def manage_agent(name: str, action: str) -> str:
        cfg = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        is_workflow = cfg and cfg.get("type") in ("background_agent", "background_script")
        
        if is_workflow:
            disabled = identity_mgr.get_disabled_workflows()
        else:
            disabled = identity_mgr.get_disabled_standard_agents()

        if action == "disable" and name not in disabled:
            disabled.append(name)
            if is_workflow:
                identity_mgr.set_disabled_workflows(disabled)
            else:
                identity_mgr.set_disabled_standard_agents(disabled)
            return f"Agent {name} disabled."
        elif action in ("enable", "reload") and name in disabled:
            disabled.remove(name)
            if is_workflow:
                identity_mgr.set_disabled_workflows(disabled)
            else:
                identity_mgr.set_disabled_standard_agents(disabled)
            return f"Agent {name} enabled."
        return f"Action {action} applied to {name}."
