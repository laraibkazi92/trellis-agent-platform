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
import httpx
from contextlib import asynccontextmanager
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _main_loop, _watch_id, _agent_watch_id, _memory_watch_id
    print("Worker starting up...")
    _main_loop = asyncio.get_running_loop()
    app.state.http_client = httpx.AsyncClient(timeout=30.0)
    _watch_id = identity_mgr.client.add_watch_prefix_callback("/registry/mcps/", on_mcp_change)
    _agent_watch_id = identity_mgr.client.add_watch_prefix_callback("/registry/agents/", on_agent_change)
    _memory_watch_id = identity_mgr.client.add_watch_prefix_callback("/config/framework/agent_memory_enabled", on_memory_flag_change)
    await get_hub_client()
    await discover_external_mcps()
    asyncio.create_task(prewarm_agents())
    print("Worker startup complete.")
    yield
    print("Worker shutting down...")
    if _watch_id:
        identity_mgr.client.cancel_watch(_watch_id)
    if _agent_watch_id:
        identity_mgr.client.cancel_watch(_agent_watch_id)
    if _memory_watch_id:
        identity_mgr.client.cancel_watch(_memory_watch_id)
    hub_client = await get_hub_client()
    if hub_client:
        await hub_client.__aexit__(None, None, None)
    await app.state.http_client.aclose()

app = FastAPI(title="Universal Agent Host (Stateless)", lifespan=lifespan)
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

from core.agent_factory import (
    get_agent,
    evict_agent,
    prewarm_agents,
    discover_external_mcps,
    get_hub_client,
    get_identity_manager,
    get_health_monitor,
    mcp_client_cache,
    _hub_client,
    SupervisorDeps,
)
from core.memory import get_memory_manager

identity_mgr = get_identity_manager()
app.add_middleware(AuthMiddleware, identity_mgr=identity_mgr)
health_monitor = get_health_monitor()

BASE_DIR = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
INTERNAL_ASSETS_DIR = BASE_DIR / "core" / "assets"

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str = "auto"
    messages: List[ChatMessage]

_main_loop: Optional[asyncio.AbstractEventLoop] = None
_watch_id: Any = None
_agent_watch_id: Any = None
_memory_watch_id: Any = None

def on_mcp_change(event):
    for ev in event.events:
        key = ev.key.decode('utf-8')
        parts = key.split('/')
        if len(parts) >= 4:
            mcp_name = parts[3]
            keys_to_delete = [k for k in mcp_client_cache.keys() if mcp_name in str(k)]
            for k in keys_to_delete:
                mcp_client_cache.pop(k, None)

    if _main_loop and not _main_loop.is_closed():
        asyncio.run_coroutine_threadsafe(discover_external_mcps(), _main_loop)


def on_agent_change(event):
    for ev in event.events:
        key = ev.key.decode('utf-8')
        parts = key.split('/')
        # key format: /registry/agents/{name}/...
        if len(parts) >= 4:
            evict_agent(parts[3])


def on_memory_flag_change(event):
    """Evict all cached agents when the agent_memory_enabled flag toggles.

    When the flag is disabled: F-01's runtime guard stops recall immediately;
    eviction ensures agents also rebuild cleanly on next request.
    When the flag is enabled: eviction forces a rebuild so agents with
    agent_memory=true get their @agent.instructions callback wired in.
    """
    from core.agent_factory import _agent_cache
    for name in list(_agent_cache.keys()):
        evict_agent(name)
    if _main_loop and not _main_loop.is_closed():
        asyncio.run_coroutine_threadsafe(prewarm_agents(), _main_loop)

@app.get("/health")
async def health():
    disabled = identity_mgr.get_disabled_standard_agents()
    configs = await asyncio.to_thread(identity_mgr.get_all_agent_configs)
    agent_healths = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "agent")
    tool_healths = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "tool")
    
    agents_status = {}
    for name, cfg in configs.items():
        if name == "supervisor" or name in disabled: continue
        
        # Check tool status from the pre-fetched tool_healths
        offline_tools = [t for t in cfg.get("allowed_tools", []) if tool_healths.get(t, {}).get("status") == "Offline"]
        
        agent_global_status = agent_healths.get(name, {})
        status_str = "Offline" if agent_global_status.get("status") == "Offline" else ("Degraded" if offline_tools else "Online")
        agents_status[name] = {"status": status_str, "offline_tools": offline_tools, "agent_error": agent_global_status.get("last_error")}
    
    return {"status": "healthy", "agents": agents_status, "agents_disabled": disabled, "hub_connected": _hub_client is not None}

@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    if not request.messages or request.messages[-1].role != "user":
        raise HTTPException(status_code=400, detail="Invalid messages")

    if request.model == "auto":
        request = ChatRequest(model="supervisor", messages=request.messages)

    disabled = identity_mgr.get_disabled_standard_agents()
    if request.model in disabled:
        raise HTTPException(status_code=404, detail="Agent disabled")

    cfg_data = await asyncio.to_thread(identity_mgr.get_agent_config, request.model)
    if not cfg_data: raise HTTPException(status_code=404, detail="Agent not found")
    if cfg_data.get("type") in ("background_agent", "background_script"):
        raise HTTPException(status_code=403, detail="Background agents cannot be called directly.")

    if health_monitor.get_status("agent", request.model).get("status") == "Offline":
        raise HTTPException(status_code=503, detail="Agent offline")

    agent = await get_agent(request.model)
    
    history = []
    for msg in request.messages[:-1]:
        if msg.role == "user": history.append(ModelRequest(parts=[UserPromptPart(content=msg.content)]))
        elif msg.role == "assistant": history.append(ModelResponse(parts=[TextPart(content=msg.content)]))
        elif msg.role == "system": history.append(ModelRequest(parts=[UserPromptPart(content=f"[System Note]: {msg.content}")]))
    
    try:
        run_deps = SupervisorDeps() if request.model == "supervisor" else None
        result = await agent.run(request.messages[-1].content, message_history=history, deps=run_deps)
        health_monitor.record_event("agent", request.model, is_success=True)
        user_id = user_id_var.get()
        if user_id and hasattr(result, 'usage'):
            u = result.usage
            if callable(u):
                u = u()
            if u:
                # Send usage to a background thread to not block return
                asyncio.create_task(asyncio.to_thread(identity_mgr.record_usage, user_id, u.input_tokens or 0, u.output_tokens or 0))
                asyncio.create_task(asyncio.to_thread(identity_mgr.record_agent_usage, user_id, request.model, u.input_tokens or 0, u.output_tokens or 0))
        # Agent memory: retain this exchange (fire-and-forget; gated + fail-open internally).
        memory_mgr = get_memory_manager()
        if memory_mgr.active_for(cfg_data):
            asyncio.create_task(memory_mgr.retain(
                bank=request.model,
                user_msg=request.messages[-1].content,
                agent_output=result.output,
            ))
        return {"choices": [{"message": {"role": "assistant", "content": result.output}}]}
    except Exception as e:
        health_monitor.record_event("agent", request.model, is_success=False, error_details=str(e))
        raise HTTPException(status_code=500, detail=str(e))
