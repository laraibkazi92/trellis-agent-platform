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
from pydantic_ai_backends import ConsoleCapability, LocalBackend
from pydantic_ai_shields import CostTracking, ToolGuard
from pydantic_ai_rlm import create_rlm_toolset

from core.auth import IdentityManager, user_id_var
from core.models import AgentConfig, MCPConfig
from core.health import HealthMonitor

# Shared global states and caches
_hub_client: Optional[FastMCPClient] = None
_hub_tools_cache: List[Any] = []
_external_mcp_tools: Dict[str, List[Any]] = {}
_last_discovery_time: float = 0
DISCOVERY_CACHE_TTL = 60 # Cache discovery for 60 seconds

mcp_client_cache = TTLCache(maxsize=100, ttl=300)

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
        
        client = await get_external_mcp_client(mcp_name, user_id)
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
            
    # 4. A2A Delegation
    subagent_configs = []
    if agent_name == "supervisor":
        all_agents = await asyncio.to_thread(identity_mgr.list_agents)
        for target in all_agents:
            if target != "supervisor":
                target_cfg = await asyncio.to_thread(identity_mgr.get_agent_config, target)
                if target_cfg and target_cfg.get("type") not in ("background_agent", "background_script"):
                    target_instructions = await asyncio.to_thread(identity_mgr.get_agent_skills, target)
                    subagent_configs.append(SubAgentConfig(
                        name=target,
                        description=target_cfg.get("description", f"Call the {target} agent"),
                        instructions=target_instructions or ""
                    ))
    else:
        for target in config.a2a_access or []:
            target_cfg = await asyncio.to_thread(identity_mgr.get_agent_config, target)
            if target_cfg:
                target_instructions = await asyncio.to_thread(identity_mgr.get_agent_skills, target)
                subagent_configs.append(SubAgentConfig(
                    name=target,
                    description=target_cfg.get("description", f"Call the {target} agent"),
                    instructions=target_instructions or ""
                ))

    if subagent_configs:
        capabilities.append(SubAgentCapability(subagents=subagent_configs, default_model=config.model))

    agent = Agent(
        model, 
        system_prompt=system_prompt, 
        name=config.name, 
        model_settings=model_settings, 
        retries=3,
        capabilities=capabilities,
        toolsets=toolsets
    )
    
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

def _register_admin_tools(agent: Agent):
    identity_mgr = get_identity_manager()
    
    @agent.tool_plain(name="list_agents", description="List all available specialized agents.")
    async def list_agents() -> List[Dict[str, str]]:
        disabled = identity_mgr.get_disabled_standard_agents()
        agents_info = []
        names = await asyncio.to_thread(identity_mgr.list_agents)
        for name in names:
            if name == "supervisor": continue
            cfg = await asyncio.to_thread(identity_mgr.get_agent_config, name)
            if cfg and cfg.get("type") not in ("background_agent", "background_script"):
                agents_info.append({"name": name, "description": cfg.get("description", ""), "status": "disabled" if name in disabled else "active"})
        return agents_info

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
