import os
import yaml
import asyncio
import copy
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, List, Any, Optional

from asyncache import cached
from cachetools import TTLCache

from pydantic_ai import Agent, RunContext
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings

from fastmcp import Client as FastMCPClient
from fastmcp.client import StdioTransport, SSETransport, StreamableHttpTransport

from core.auth import IdentityManager, user_id_var
from core.models import AgentConfig, MCPConfig
from core.health import HealthMonitor

# Shared global states and caches
_hub_client: Optional[FastMCPClient] = None
_hub_tools_cache: List[Any] = []
_external_mcp_tools: Dict[str, List[Any]] = {}

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

def _inject_secrets(env: Optional[Dict[str, str]], secrets: Optional[List[str]], user_secrets: Dict[str, str]) -> Dict[str, str]:
    env_copy = env.copy() if env else {}
    for req_secret in (secrets or []):
        val = user_secrets.get(req_secret)
        if val:
            interpolated = False
            for k, v in env_copy.items():
                if isinstance(v, str) and f"{{{req_secret}}}" in v:
                    env_copy[k] = v.replace(f"{{{req_secret}}}", val)
                    interpolated = True
            if not interpolated:
                env_copy[req_secret] = val
    return env_copy

@cached(cache=mcp_client_cache)
async def get_external_mcp_client(mcp_name: str, user_id: str) -> FastMCPClient:
    identity_mgr = get_identity_manager()
    user_secrets = await asyncio.to_thread(identity_mgr.get_resolved_secrets, user_id)
    config_data = await asyncio.to_thread(identity_mgr.get_mcp_config, mcp_name)
    if not config_data: raise Exception(f"MCP config '{mcp_name}' not found")
    config = MCPConfig(**config_data)
    
    env = _inject_secrets(config.env, config.secrets, user_secrets)
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

async def discover_external_mcps():
    global _external_mcp_tools
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

def _register_a2a_tool(agent: Agent, target_agent_name: str):
    async def a2a_tool_wrapper(ctx: RunContext[None], prompt: str) -> str:
        target_agent = await build_agent(target_agent_name)
        result = await target_agent.run(prompt)
        return result.output
    agent.tool(name=f"call_{target_agent_name}", description=f"Call the {target_agent_name} agent.")(a2a_tool_wrapper)

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
    
    agent = Agent(model, system_prompt=system_prompt, name=config.name, model_settings=model_settings, retries=3)
    
    # 1. Hub Tools
    allowed_tools = config.allowed_tools or []
    hub_client = await get_hub_client()
    for tool in _hub_tools_cache:
        if tool.name in allowed_tools:
            _register_mcp_tool(agent, tool)

    # 2. External MCP Tools
    await discover_external_mcps()
    allowed_mcps = config.allowed_mcps or []
    for mcp_name, tools in _external_mcp_tools.items():
        if mcp_name in allowed_mcps:
            for tool in tools:
                _register_external_mcp_tool(agent, mcp_name, tool, prefixed_name=f"mcp__{mcp_name}__{tool.name}")
        else:
            for tool in tools:
                prefixed_name = f"mcp__{mcp_name}__{tool.name}"
                if prefixed_name in allowed_tools or tool.name in allowed_tools:
                    name_to_use = prefixed_name if prefixed_name in allowed_tools else tool.name
                    _register_external_mcp_tool(agent, mcp_name, tool, prefixed_name=name_to_use)

    # 3. A2A Tools
    if agent_name == "supervisor":
        # Supervisor can call anyone except background agents
        all_agents = await asyncio.to_thread(identity_mgr.list_agents)
        for target in all_agents:
            if target != "supervisor":
                target_cfg = await asyncio.to_thread(identity_mgr.get_agent_config, target)
                if target_cfg and target_cfg.get("type") != "background":
                    _register_a2a_tool(agent, target)
        _register_admin_tools(agent)
    else:
        for target in config.a2a_access or []:
            _register_a2a_tool(agent, target)
            
    return agent

def _register_admin_tools(agent: Agent):
    identity_mgr = get_identity_manager()
    
    @agent.tool_plain(name="list_agents", description="List all available specialized agents.")
    async def list_agents() -> List[Dict[str, str]]:
        disabled = identity_mgr.get_disabled_agents()
        agents_info = []
        names = await asyncio.to_thread(identity_mgr.list_agents)
        for name in names:
            if name == "supervisor": continue
            cfg = await asyncio.to_thread(identity_mgr.get_agent_config, name)
            if cfg and cfg.get("type") != "background":
                agents_info.append({"name": name, "description": cfg.get("description", ""), "status": "disabled" if name in disabled else "active"})
        return agents_info

    @agent.tool_plain(name="manage_agent", description="Enable, disable or reload an agent.")
    async def manage_agent(name: str, action: str) -> str:
        disabled = identity_mgr.get_disabled_agents()
        if action == "disable" and name not in disabled:
            disabled.append(name)
            identity_mgr.set_disabled_agents(disabled)
            return f"Agent {name} disabled."
        elif action in ("enable", "reload") and name in disabled:
            disabled.remove(name)
            identity_mgr.set_disabled_agents(disabled)
            return f"Agent {name} enabled."
        return f"Action {action} applied to {name}."
