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

from core.agent_factory import (
    build_agent,
    discover_external_mcps,
    get_hub_client,
    get_identity_manager,
    get_health_monitor,
    mcp_client_cache,
    _hub_client
)

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
    model: str
    messages: List[ChatMessage]

_main_loop: Optional[asyncio.AbstractEventLoop] = None
_watch_id: Any = None

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
    global _watch_id
    if _watch_id:
        identity_mgr.client.cancel_watch(_watch_id)
    hub_client = await get_hub_client()
    if hub_client:
        await hub_client.__aexit__(None, None, None)

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
    if cfg_data.get("type") in ("background_agent", "background_script"):
        raise HTTPException(status_code=403, detail="Background agents cannot be called directly.")

    if health_monitor.get_status("agent", request.model).get("status") == "Offline":
        raise HTTPException(status_code=503, detail="Agent offline")

    agent = await build_agent(request.model)
    
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
