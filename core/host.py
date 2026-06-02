import os
import yaml
import asyncio
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from asyncache import cached
from cachetools import TTLCache
import copy

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings
from pydantic_ai.messages import ModelRequest, ModelResponse, UserPromptPart, TextPart

from fastmcp import Client as FastMCPClient
from fastmcp.client import StdioTransport, SSETransport, StreamableHttpTransport

from core.auth import AuthMiddleware, IdentityManager, user_id_var
from core.models import AgentConfig, MCPConfig
from core.health import HealthMonitor
from core.background.webhooks import router as webhooks_router
from core.tasks import run_background_agent

app = FastAPI(title="Universal Agent Host (Stateless)")
app.include_router(webhooks_router)

# CORS Setup
DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"
cors_origins_str = os.getenv("CORS_ALLOWED_ORIGINS", "")
if DEV_MODE:
    allow_origins = ["*"]
else:
    allow_origins = [origin.strip() for origin in cors_origins_str.split(",")] if cors_origins_str else []

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)
app.add_middleware(AuthMiddleware, identity_mgr=identity_mgr)
health_monitor = HealthMonitor(identity_mgr)

BASE_DIR = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
INTERNAL_ASSETS_DIR = BASE_DIR / "core" / "assets"
DEFAULT_HUB_URL = os.getenv("HUB_URL", "http://localhost:8001/mcp")

GEMINI_2_5_PRO_MODELS = {"gemini-2.5-pro"}
GEMINI_2_5_FLASH_MODELS = {"gemini-2.5-flash"}
LITE_MODELS = {"gemini-3.1-flash-lite-preview", "gemini-2.5-flash-lite"}
GEMINI_3_MODELS = {"gemini-3.1-pro-preview", "gemini-3-flash-preview"}

GEMINI_2_5_PRO_BUDGETS = {"low": 1024, "medium": 8192, "high": 16384}
GEMINI_2_5_FLASH_BUDGETS = {"low": 1024, "medium": 4096, "high": 8192}

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str
    messages: List[ChatMessage]

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

# --- Worker-level State ---
_hub_client: Optional[FastMCPClient] = None
_hub_tools_cache: List[Any] = []
_external_mcp_tools: Dict[str, List[Any]] = {}
_main_loop: Optional[asyncio.AbstractEventLoop] = None
_watch_id: Any = None

mcp_client_cache = TTLCache(maxsize=100, ttl=300)

@cached(cache=mcp_client_cache)
async def get_external_mcp_client(mcp_name: str, user_id: str) -> FastMCPClient:
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
        hub_url = identity_mgr.get_config("HUB_URL", DEFAULT_HUB_URL)
        _hub_client = FastMCPClient(hub_url)
        await _hub_client.__aenter__()
        _hub_tools_cache = await _hub_client.list_tools()
    return _hub_client

async def discover_external_mcps():
    global _external_mcp_tools
    new_mcp_tools = {}
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
            
    # Atomic swap
    _external_mcp_tools = new_mcp_tools

def on_mcp_change(event):
    for ev in event.events:
        key = ev.key.decode('utf-8')
        parts = key.split('/')
        if len(parts) >= 4:
            mcp_name = parts[3]
            # Invalidate specific cache keys
            keys_to_delete = [k for k in mcp_client_cache.keys() if mcp_name in str(k)]
            for k in keys_to_delete:
                mcp_client_cache.pop(k, None)
                
    if _main_loop and not _main_loop.is_closed():
        asyncio.run_coroutine_threadsafe(discover_external_mcps(), _main_loop)

@app.on_event("startup")
async def startup_event():
    global _main_loop, _watch_id
    print("Worker starting up...")
    _main_loop = asyncio.get_running_loop()
    _watch_id = identity_mgr.client.add_watch_prefix_callback("/registry/mcps/", on_mcp_change)
    await get_hub_client()
    await discover_external_mcps()
    print("Worker startup complete.")

@app.on_event("shutdown")
async def shutdown_event():
    print("Worker shutting down...")
    global _hub_client, _watch_id
    if _watch_id:
        identity_mgr.client.cancel_watch(_watch_id)
    if _hub_client:
        await _hub_client.__aexit__(None, None, None)
    # The asyncache TTL cache doesn't easily allow sweeping for async cleanup,
    # but the OS will clean up sockets on process exit since workers are ephemeral.

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

async def _build_agent(agent_name: str) -> Agent:
    if agent_name == "supervisor":
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, "supervisor")
        system_prompt = await asyncio.to_thread(identity_mgr.get_agent_skills, "supervisor")
        if not config_data:
            raise HTTPException(status_code=500, detail="Supervisor config missing")
        config_data['a2a_access'] = []
    else:
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
        system_prompt = await asyncio.to_thread(identity_mgr.get_agent_skills, agent_name)
        if not config_data:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")
            
    config = AgentConfig(**config_data)
    model = GoogleModel(config.model)
    model_settings = _get_model_settings(config.model, config.thinking_level)
    
    agent = Agent(model, system_prompt=system_prompt, name=config.name, model_settings=model_settings, retries=3)
    
    # 1. Hub Tools
    allowed_tools = config.allowed_tools or []
    for tool in _hub_tools_cache:
        if tool.name in allowed_tools:
            _register_mcp_tool(agent, tool)

    # 2. External MCP Tools
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
        for target in config.a2a_access:
            _register_a2a_tool(agent, target)
            
    return agent

def _register_a2a_tool(agent: Agent, target_agent_name: str):
    async def a2a_tool_wrapper(ctx: RunContext[None], prompt: str) -> str:
        target_agent = await _build_agent(target_agent_name)
        result = await target_agent.run(prompt)
        return result.output
    agent.tool(name=f"call_{target_agent_name}", description=f"Call the {target_agent_name} agent.")(a2a_tool_wrapper)

def _register_admin_tools(agent: Agent):
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

def _register_mcp_tool(agent: Agent, mcp_tool: Any):
    safe_mcp_tool = copy.deepcopy(mcp_tool) if hasattr(mcp_tool, "model_copy") else mcp_tool
    
    async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
        if health_monitor.get_status("tool", safe_mcp_tool.name).get("status") == "Offline":
            return "SYSTEM: Tool offline."
        kwargs["__user_id"] = user_id_var.get()
        client = await get_hub_client()
        result = await client.call_tool(safe_mcp_tool.name, kwargs)
        return result.content

    agent.tool(name=tool_name_for_agent, description=safe_mcp_tool.description)(tool_wrapper)

def _register_external_mcp_tool(agent: Agent, mcp_name: str, mcp_tool: Any, prefixed_name: str = None):
    safe_mcp_tool = copy.deepcopy(mcp_tool) if hasattr(mcp_tool, "model_copy") else mcp_tool
    tool_name_for_agent = prefixed_name or safe_mcp_tool.name
    
    async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
        if health_monitor.get_status("tool", safe_mcp_tool.name).get("status") == "Offline":
            return "SYSTEM: Tool offline."
        user_id = user_id_var.get()
        if not user_id: raise Exception("No user_id found")
        
        client = await get_external_mcp_client(mcp_name, user_id)
        result = await client.call_tool(safe_mcp_tool.name, kwargs)
        return result.content

    input_schema = getattr(safe_mcp_tool, "inputSchema", None)
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

@app.get("/health")
async def health():
    disabled = identity_mgr.get_disabled_agents()
    names = await asyncio.to_thread(identity_mgr.list_agents)
    agents_status = {}
    for name in names:
        if name == "supervisor" or name in disabled: continue
        cfg = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if not cfg: continue
        offline_tools = [t for t in cfg.get("allowed_tools", []) if health_monitor.get_status("tool", t).get("status") == "Offline"]
        agent_global_status = health_monitor.get_status("agent", name)
        status_str = "Offline" if agent_global_status.get("status") == "Offline" else ("Degraded" if offline_tools else "Online")
        agents_status[name] = {"status": status_str, "offline_tools": offline_tools, "agent_error": agent_global_status.get("last_error")}
    return {"status": "healthy", "agents": agents_status, "agents_disabled": disabled, "hub_connected": _hub_client is not None}

@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    if not request.messages or request.messages[-1].role != "user":
        raise HTTPException(status_code=400, detail="Invalid messages")

    disabled = identity_mgr.get_disabled_agents()
    if request.model in disabled:
        raise HTTPException(status_code=404, detail="Agent disabled")

    cfg_data = await asyncio.to_thread(identity_mgr.get_agent_config, request.model)
    if not cfg_data: raise HTTPException(status_code=404, detail="Agent not found")
    if cfg_data.get("type") == "background":
        raise HTTPException(status_code=403, detail="Background agents cannot be called directly.")

    if health_monitor.get_status("agent", request.model).get("status") == "Offline":
        raise HTTPException(status_code=503, detail="Agent offline")

    agent = await _build_agent(request.model)
    
    history = []
    for msg in request.messages[:-1]:
        if msg.role == "user": history.append(ModelRequest(parts=[UserPromptPart(content=msg.content)]))
        elif msg.role == "assistant": history.append(ModelResponse(parts=[TextPart(content=msg.content)]))
        elif msg.role == "system": history.append(ModelRequest(parts=[UserPromptPart(content=f"[System Note]: {msg.content}")]))
    
    try:
        result = await agent.run(request.messages[-1].content, message_history=history)
        health_monitor.record_event("agent", request.model, is_success=True)
        user_id = user_id_var.get()
        if user_id and hasattr(result, 'usage') and result.usage():
            u = result.usage()
            # Send usage to a background thread to not block return
            asyncio.create_task(asyncio.to_thread(identity_mgr.record_usage, user_id, u.request_tokens or 0, u.response_tokens or 0))
            asyncio.create_task(asyncio.to_thread(identity_mgr.record_agent_usage, user_id, request.model, u.request_tokens or 0, u.response_tokens or 0))
        return {"choices": [{"message": {"role": "assistant", "content": result.output}}]}
    except Exception as e:
        health_monitor.record_event("agent", request.model, is_success=False, error_details=str(e))
        raise HTTPException(status_code=500, detail=str(e))
