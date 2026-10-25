# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import json
import asyncio
import time
import uuid
import logging

logger = logging.getLogger(__name__)
from pathlib import Path
from typing import List, Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import httpx
from contextlib import asynccontextmanager
from pydantic_ai.messages import ModelRequest, ModelResponse, UserPromptPart, TextPart

from core.auth import AuthMiddleware, agent_token_var, user_id_var
from core.agent_token import mint_for_run
from core.devmode import configure_cors, enforce_dev_mode_safety
from core.models import is_agent_external, is_routable_agent_type
from core.health import compute_agent_operational_status
from core.background.tasks import (
    background_tasks as _background_tasks,
    drain_background_tasks as _drain_background_tasks,
    spawn_background as _spawn_background,
)
from core.background.webhooks import router as webhooks_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _main_loop, _watch_id, _agent_watch_id, _memory_watch_id, _memory_isolation_watch_id
    enforce_dev_mode_safety("host")
    # Enforcing deployments refuse to start without the token key; rollout/dev
    # modes only warn, so a local run is not blocked.
    from core.agent_token import require_secret
    from core.log_redaction import install as install_redaction

    install_redaction()
    require_secret("host")
    logger.info("Worker starting up...")
    _main_loop = asyncio.get_running_loop()
    app.state.http_client = httpx.AsyncClient(timeout=30.0)
    _watch_id = identity_mgr.client.add_watch_prefix_callback("/registry/mcps/", on_mcp_change)
    _agent_watch_id = identity_mgr.client.add_watch_prefix_callback("/registry/agents/", on_agent_change)
    _memory_watch_id = identity_mgr.client.add_watch_prefix_callback("/config/framework/agent_memory_enabled", on_memory_flag_change)
    _memory_isolation_watch_id = identity_mgr.client.add_watch_prefix_callback("/config/framework/agent_memory_isolated_per_user", on_memory_flag_change)
    install_llm_key_watch()
    install_llm_defaults_watch()
    try:
        from core.tool_authz import install_tool_authz_watch

        install_tool_authz_watch()
    except Exception:
        logger.exception("Failed to install tool-authorization watch; continuing startup")
    # Warm the LLM provider-key cache off the event loop so the first request-path
    # lookup is a cache hit instead of a (possibly ~20s) etcd round-trip.
    await asyncio.to_thread(warm_key_cache)
    # Warm the framework LLM default cache (etcd read) beside the key cache so the
    # first inherit-the-default build is a cache hit.
    await asyncio.to_thread(warm_defaults_cache)
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
    if _memory_isolation_watch_id:
        identity_mgr.client.cancel_watch(_memory_isolation_watch_id)
    cancel_llm_key_watch()
    cancel_llm_defaults_watch()
    try:
        from core.tool_authz import cancel_tool_authz_watch

        cancel_tool_authz_watch()
    except Exception:
        logger.exception("Failed to cancel tool-authorization watch")
    hub_client = await get_hub_client()
    if hub_client:
        await hub_client.__aexit__(None, None, None)
    await app.state.http_client.aclose()

app = FastAPI(title="Universal Agent Host (Stateless)", lifespan=lifespan)
app.include_router(webhooks_router)

# CORS Setup
configure_cors(app)

from core.agent_factory import (
    get_agent,
    evict_agent,
    install_llm_key_watch,
    cancel_llm_key_watch,
    install_llm_defaults_watch,
    cancel_llm_defaults_watch,
    prewarm_agents,
    discover_external_mcps,
    get_hub_client,
    get_identity_manager,
    get_health_monitor,
    mcp_client_cache,
    is_hub_connected,
    SupervisorDeps,
)
from core.llm_defaults import warm_defaults_cache
from core.llm_factory import warm_key_cache
from core.llm_providers import ProviderConfigError
from core.memory import get_memory_manager

identity_mgr = get_identity_manager()
app.add_middleware(AuthMiddleware, identity_mgr=identity_mgr)
health_monitor = get_health_monitor()


async def _record_latency(provider, agent_name, user_id, ttft_ms, total_ms, ok):
    """Record one call's latency; metrics failures never affect the response."""
    try:
        await asyncio.to_thread(
            identity_mgr.record_agent_latency,
            user_id, agent_name, provider, ttft_ms, total_ms, ok,
        )
    except Exception as e:
        logger.warning(f"Failed to record LLM latency for {agent_name}: {e}")


BASE_DIR = Path(__file__).parent.parent

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
_memory_isolation_watch_id: Any = None

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
    """Evict all cached agents when an agent-memory flag toggles
    (agent_memory_enabled or agent_memory_isolated_per_user).

    When the master flag is disabled: F-01's runtime guard stops recall immediately;
    eviction ensures agents also rebuild cleanly on next request.
    When the master flag is enabled: eviction forces a rebuild so agents with
    agent_memory=true get their @agent.instructions callback wired in.
    For the isolation flag the recall closure re-resolves the bank per run anyway;
    eviction just keeps cached builds from outliving the flag transition. The
    MemoryManager's TTL-cached flag values are also dropped so rebuilt agents
    observe the new flag immediately instead of after the cache TTL.
    """
    from core.agent_factory import _agent_cache
    for name in list(_agent_cache.keys()):
        evict_agent(name)
    get_memory_manager().invalidate_flag_caches()
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
    t0 = time.monotonic()
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

    metric_provider = None
    try:
        from core.llm_defaults import provider_for_config

        metric_provider = await asyncio.to_thread(provider_for_config, cfg_data)
    except Exception as e:
        logger.warning(f"Failed to resolve provider for '{request.model}' latency metric: {e}")

    agent_health = await asyncio.to_thread(health_monitor.get_status, "agent", request.model)
    if agent_health.get("status") == "Offline":
        raise HTTPException(status_code=503, detail="Agent offline")

    try:
        agent = await get_agent(request.model)
    except ProviderConfigError as e:
        # A missing/invalid provider credential is a caller-actionable configuration
        # error, not an internal failure: return the registry's message so the caller
        # sees "set DEEPSEEK_API_KEY in Admin -> LLM Providers" instead of a bare 500.
        raise HTTPException(status_code=400, detail=str(e))

    # Guardrail input check: every client-supplied turn is evaluated (not just the
    # last one — earlier turns and system notes reach the model as history). Checked
    # text is written back in place so history, execute_agent, run_stream and memory
    # retain all see the same redaction. Fail-open: an error allows the request.
    guardrail_block = False
    all_hits = []
    try:
        from core import guardrails

        for message in request.messages:
            action, checked_text, hits = await asyncio.to_thread(
                guardrails.evaluate_agent_input, message.content, cfg_data)
            all_hits.extend(hits)
            if action == "block":
                guardrail_block = True
            elif action == "redact":
                message.content = checked_text
    except Exception as e:
        logger.warning(f"Guardrail input check failed for '{request.model}': {e}")
        guardrail_block = False
        all_hits = []
    if all_hits:
        try:
            _spawn_background(
                asyncio.to_thread(
                    identity_mgr.record_guardrail_hits,
                    request.model, guardrails.hit_counts(all_hits),
                ),
                f"guardrail_hits:{request.model}",
            )
        except Exception as e:
            logger.error(f"Failed to record guardrail hits for {request.model}: {e}")
    if guardrail_block:
        # Rule names only -- never echo the matched previews/payload back to the caller.
        raised = sorted({h.get("rule", "") for h in all_hits if isinstance(h, dict)})
        raise HTTPException(status_code=400, detail=f"Blocked by guardrail: {', '.join(raised)}")

    history = []
    for msg in request.messages[:-1]:
        if msg.role == "user": history.append(ModelRequest(parts=[UserPromptPart(content=msg.content)]))
        elif msg.role == "assistant": history.append(ModelResponse(parts=[TextPart(content=msg.content)]))
        elif msg.role == "system": history.append(ModelRequest(parts=[UserPromptPart(content=f"[System Note]: {msg.content}")]))
    
    async def execute_agent():
        agent_token_var.set(run_token)
        run_deps = SupervisorDeps() if request.model == "supervisor" else None
        return await agent.run(request.messages[-1].content, message_history=history, deps=run_deps)

    captured_user_id = user_id_var.get()
    # One token per run proves (agent, user, run) to the hub/relay/runner. Minting
    # here (not in a wrapper) means every tool call in this run inherits it.
    run_token = mint_for_run(
        request.model,
        captured_user_id,
        run_id=uuid.uuid4().hex,
        principal="system" if request.model == "supervisor" else None,
    )

    async def handle_success(result, user_id, ttft_ms=None):
        # Measure before usage/memory side effects so p95 reflects the model call,
        # not etcd retries from the bookkeeping that follows.
        total_ms = (time.monotonic() - t0) * 1000
        await asyncio.to_thread(health_monitor.record_event, "agent", request.model, True)

        # Guardrail output check. v1 only inspects the final assembled output, so a
        # streamed reply is checked once complete rather than per chunk.
        original_text = str(result.output or "")
        try:
            from core import guardrails

            out_action, checked_text, out_hits = await asyncio.to_thread(
                guardrails.evaluate_agent_output, original_text, cfg_data)
        except Exception as e:
            logger.warning(f"Guardrail output check failed for '{request.model}': {e}")
            out_action, checked_text, out_hits = "allow", original_text, []
        if out_hits:
            try:
                _spawn_background(
                    asyncio.to_thread(
                        identity_mgr.record_guardrail_hits,
                        request.model, guardrails.hit_counts(out_hits),
                    ),
                    f"guardrail_hits:{request.model}",
                )
            except Exception as e:
                logger.error(f"Failed to record guardrail hits for {request.model}: {e}")
        if out_action == "block":
            # The SYSTEM: prefix is load-bearing: client models degrade gracefully
            # instead of treating an empty/withheld assistant turn as a prompt.
            safe_text = "SYSTEM: Response blocked by guardrail policy. The agent output was withheld."
        elif out_action == "redact":
            safe_text = checked_text
        else:
            safe_text = original_text

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
                    bank=await asyncio.to_thread(memory_mgr.bank_for, request.model, user_id),
                    user_msg=request.messages[-1].content,
                    agent_output=safe_text,
                ), f"memory_retain:{request.model}")
            except Exception as e:
                logger.error(f"Failed to retain memory for {request.model}: {e}")

        _spawn_background(
            _record_latency(metric_provider, request.model, user_id, ttft_ms, total_ms, True),
            f"latency:{request.model}",
        )
        return safe_text
    if request.stream:
        async def event_generator():
            agent_token_var.set(run_token)
            event_queue = asyncio.Queue()
            first_event_at = None
            
            async def event_handler(*args, **kwargs):
                nonlocal first_event_at
                # PydanticAI streams events natively via event_stream_handler passing (run_ctx, event)
                event = args[1] if len(args) > 1 else (args[0] if args else None)
                if event and type(event).__name__ == "ToolCallEvent":
                    if first_event_at is None:
                        first_event_at = time.monotonic()
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
                if first_event_at is None:
                    first_event_at = time.monotonic()
                ttft_ms = (first_event_at - t0) * 1000
                safe_text = await handle_success(result, captured_user_id, ttft_ms=ttft_ms)
                yield json.dumps({"choices": [{"message": {"role": "assistant", "content": safe_text}}]}) + "\n"
            except asyncio.CancelledError:
                if not task.done():
                    task.cancel()
                raise
            except Exception as e:
                if not task.done():
                    task.cancel()
                await asyncio.to_thread(health_monitor.record_event, "agent", request.model, False, str(e))
                _spawn_background(
                    _record_latency(metric_provider, request.model, captured_user_id, None, (time.monotonic() - t0) * 1000, False),
                    f"latency:{request.model}",
                )
                yield json.dumps({"error": "Internal error while running the agent."}) + "\n"
            finally:
                if not task.done():
                    task.cancel()

        return StreamingResponse(event_generator(), media_type="application/x-ndjson")

    try:
        result = await execute_agent()
        text = await handle_success(result, captured_user_id)
        return {"choices": [{"message": {"role": "assistant", "content": text}}]}
    except Exception as e:
        await asyncio.to_thread(health_monitor.record_event, "agent", request.model, False, str(e))
        logger.exception("Agent '%s' execution failed", request.model)
        _spawn_background(
            _record_latency(metric_provider, request.model, captured_user_id, None, (time.monotonic() - t0) * 1000, False),
            f"latency:{request.model}",
        )
        raise HTTPException(status_code=500, detail="Internal error while running the agent.")