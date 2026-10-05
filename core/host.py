# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import json
import os
import yaml
import asyncio
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)
from pathlib import Path
from typing import Dict, List, Any, Optional
from asyncache import cached
from cachetools import TTLCache
import copy

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
from contextlib import asynccontextmanager
from pydantic_ai import Agent, RunContext
from pydantic_ai.messages import ModelRequest, ModelResponse, UserPromptPart, TextPart

from fastmcp import Client as FastMCPClient
from fastmcp.client import StdioTransport, SSETransport, StreamableHttpTransport

from core.auth import AuthMiddleware, IdentityManager, user_id_var
from core.devmode import enforce_dev_mode_safety
from core.models import AgentConfig, MCPConfig, is_agent_external, is_routable_agent_type
from core.health import HealthMonitor, compute_agent_operational_status
from core.background.webhooks import router as webhooks_router
from core.tasks import run_background_agent

_background_tasks: set[asyncio.Task] = set()

def _spawn_background(coro, name: str) -> asyncio.Task:
    task = asyncio.create_task(coro, name=name)
    _background_tasks.add(task)
    def _done(t: asyncio.Task):
        _background_tasks.discard(t)
        if not t.cancelled() and t.exception() is not None:
            logger.error("Background task %s failed: %s", name, t.exception())
    task.add_done_callback(_done)
    return task

async def _drain_background_tasks(timeout: float = 5.0) -> None:
    pending = {t for t in _background_tasks if not t.done()}
    if not pending:
        return
    _, still_pending = await asyncio.wait(pending, timeout=timeout)
    for task in still_pending:
        task.cancel()
    if still_pending:
        logger.warning("Cancelled %d background task(s) that did not finish within %.1fs", len(still_pending), timeout)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _main_loop, _watch_id, _agent_watch_id, _memory_watch_id
    enforce_dev_mode_safety("host")
    logger.info("Worker starting up...")
    _main_loop = asyncio.get_running_loop()
    app.state.http_client = httpx.AsyncClient(timeout=30.0)
    _watch_id = identity_mgr.client.add_watch_prefix_callback("/registry/mcps/", on_mcp_change)
    _agent_watch_id = identity_mgr.client.add_watch_prefix_callback("/registry/agents/", on_agent_change)
    _memory_watch_id = identity_mgr.client.add_watch_prefix_callback("/config/framework/agent_memory_enabled", on_memory_flag_change)
    await get_hub_client()
    await discover_external_mcps()
    _spawn_background(prewarm_agents(), "prewarm_agents")
    logger.info("Worker startup complete.")
    yield
    logger.info("Worker shutting down...")
    await _drain_background_tasks()
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
    is_hub_connected,
    SupervisorDeps,
)
from core.memory import get_memory_manager

identity_mgr = get_identity_manager()
app.add_middleware(AuthMiddleware, identity_mgr=identity_mgr)
health_monitor = get_health_monitor()

BASE_DIR = Path(__file__).parent.parent
INTERNAL_ASSETS_DIR = BASE_DIR / "core" / "assets"

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str = "auto"
    messages: List[ChatMessage]
    stream: bool = False

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
    disabled = await asyncio.to_thread(identity_mgr.get_disabled_standard_agents)
    configs = await asyncio.to_thread(identity_mgr.get_all_agent_configs)
    agent_healths = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "agent")
    tool_healths = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "tool")
    
    agents_status = {}
    for name, cfg in configs.items():
        if not is_routable_agent_type(name, cfg) or name in disabled: continue
        if not is_agent_external(cfg): continue

        # Shared with core/gateway.py's _get_visible_agents() (Phase D) -- see
        # core/health.py:compute_agent_operational_status.
        agents_status[name] = compute_agent_operational_status(
            cfg, agent_healths.get(name), tool_healths, cooldown_seconds=health_monitor.cooldown_seconds
        )
    
    return {"status": "healthy", "agents": agents_status, "agents_disabled": disabled, "hub_connected": is_hub_connected()}

@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    if not request.messages or request.messages[-1].role != "user":
        raise HTTPException(status_code=400, detail="Invalid messages")

    if request.model == "auto":
        request = ChatRequest(model="supervisor", messages=request.messages)

    disabled = await asyncio.to_thread(identity_mgr.get_disabled_standard_agents)
    if request.model in disabled:
        raise HTTPException(status_code=404, detail="Agent disabled")

    cfg_data = await asyncio.to_thread(identity_mgr.get_agent_config, request.model)
    if not cfg_data: raise HTTPException(status_code=404, detail="Agent not found")
    if cfg_data.get("type") in ("background_agent", "background_script"):
        raise HTTPException(status_code=403, detail="Background agents cannot be called directly.")
    if request.model != "supervisor" and not is_agent_external(cfg_data):
        raise HTTPException(status_code=403, detail=f"Access denied: Agent '{request.model}' is internal and cannot be called directly.")

    agent_health = await asyncio.to_thread(health_monitor.get_status, "agent", request.model)
    if agent_health.get("status") == "Offline":
        raise HTTPException(status_code=503, detail="Agent offline")

    agent = await get_agent(request.model)
    
    history = []
    for msg in request.messages[:-1]:
        if msg.role == "user": history.append(ModelRequest(parts=[UserPromptPart(content=msg.content)]))
        elif msg.role == "assistant": history.append(ModelResponse(parts=[TextPart(content=msg.content)]))
        elif msg.role == "system": history.append(ModelRequest(parts=[UserPromptPart(content=f"[System Note]: {msg.content}")]))
    
    async def execute_agent():
        run_deps = SupervisorDeps() if request.model == "supervisor" else None
        return await agent.run(request.messages[-1].content, message_history=history, deps=run_deps)

    captured_user_id = user_id_var.get()
    
    async def handle_success(result, user_id):
        await asyncio.to_thread(health_monitor.record_event, "agent", request.model, True)
        if user_id and hasattr(result, 'usage'):
            u = result.usage
            if callable(u):
                u = u()
            if u:
                input_tokens = getattr(u, 'input_tokens', 0) or 0
                output_tokens = getattr(u, 'output_tokens', 0) or 0
                try:
                    await asyncio.to_thread(identity_mgr.record_usage, user_id, input_tokens, output_tokens)
                    await asyncio.to_thread(identity_mgr.record_agent_usage, user_id, request.model, input_tokens, output_tokens)
                except Exception as e:
                    logger.error(f"Failed to record token usage for {user_id}: {e}")
        memory_mgr = get_memory_manager()
        if await asyncio.to_thread(memory_mgr.active_for, cfg_data):
            try:
                _spawn_background(memory_mgr.retain(
                    bank=request.model,
                    user_msg=request.messages[-1].content,
                    agent_output=result.output,
                ), f"memory_retain:{request.model}")
            except Exception as e:
                logger.error(f"Failed to retain memory for {request.model}: {e}")

    if request.stream:
        async def event_generator():
            event_queue = asyncio.Queue()
            
            async def event_handler(*args, **kwargs):
                # PydanticAI streams events natively via event_stream_handler passing (run_ctx, event)
                event = args[1] if len(args) > 1 else (args[0] if args else None)
                if event and type(event).__name__ == "ToolCallEvent":
                    try:
                        # Extract tool name based on the event structure
                        if hasattr(event, "part") and hasattr(event.part, "tool_name"):
                            event_queue.put_nowait({"status": "tool_call", "tool": event.part.tool_name})
                    except Exception:
                        pass
                        
            async def run_with_handler():
                run_deps = SupervisorDeps() if request.model == "supervisor" else None
                # Use run_stream to get events, but we just await the final result internally
                # while pushing events to the queue
                async with agent.run_stream(request.messages[-1].content, message_history=history, deps=run_deps, event_stream_handler=event_handler) as response:
                    output = await response.get_output()
                    return output, response.usage

            task = asyncio.create_task(run_with_handler())
            try:
                while not task.done():
                    try:
                        # Wait for an event, or timeout and send a processing tick
                        event_data = await asyncio.wait_for(event_queue.get(), timeout=5.0)
                        yield json.dumps(event_data) + "\n"
                    except asyncio.TimeoutError:
                        yield json.dumps({"status": "processing"}) + "\n"
                
                # Task completed, get the final result text and usage
                final_text, usage = task.result()
                
                # Mock a result object for handle_success with usage stats from stream
                class MockResult:
                    def __init__(self, output, usage):
                        self.output = output
                        self.usage = usage
                
                result = MockResult(final_text, usage)
                await handle_success(result, captured_user_id)
                yield json.dumps({"choices": [{"message": {"role": "assistant", "content": final_text}}]}) + "\n"
            except asyncio.CancelledError:
                if not task.done():
                    task.cancel()
                raise
            except Exception as e:
                if not task.done():
                    task.cancel()
                await asyncio.to_thread(health_monitor.record_event, "agent", request.model, False, str(e))
                yield json.dumps({"error": "Internal error while running the agent."}) + "\n"
            finally:
                if not task.done():
                    task.cancel()

        return StreamingResponse(event_generator(), media_type="application/x-ndjson")

    try:
        result = await execute_agent()
        await handle_success(result, captured_user_id)
        return {"choices": [{"message": {"role": "assistant", "content": result.output}}]}
    except Exception as e:
        await asyncio.to_thread(health_monitor.record_event, "agent", request.model, False, str(e))
        logger.exception("Agent '%s' execution failed", request.model)
        raise HTTPException(status_code=500, detail="Internal error while running the agent.")