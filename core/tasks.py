import os
import asyncio
from typing import Dict, Any, Optional
from taskiq_redis import ListQueueBroker
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings

from fastmcp import Client as FastMCPClient
from fastmcp.client import StdioTransport, SSETransport, StreamableHttpTransport

from core.models import AgentConfig, MCPConfig
from core.auth import IdentityManager
from core.health import HealthMonitor

# Redis broker configuration
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
broker = ListQueueBroker(redis_url)

# Helper function to get IdentityManager (cached/reused)
_identity_mgr = None
def get_identity_manager() -> IdentityManager:
    global _identity_mgr
    if _identity_mgr is None:
        _identity_mgr = IdentityManager(
            host=os.getenv("ETCD_HOST", "127.0.0.1"),
            port=int(os.getenv("ETCD_PORT", 2379))
        )
    return _identity_mgr

_health_monitor = None
def get_health_monitor() -> HealthMonitor:
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = HealthMonitor(get_identity_manager())
    return _health_monitor

# --- Worker-level State for Tools ---
_hub_client: Optional[FastMCPClient] = None
_hub_tools_cache: list = []
DEFAULT_HUB_URL = os.getenv("HUB_URL", "sse://localhost:8001/sse")

async def get_hub_client() -> FastMCPClient:
    global _hub_client, _hub_tools_cache
    if _hub_client is None:
        identity_mgr = get_identity_manager()
        hub_url = identity_mgr.get_config("HUB_URL", DEFAULT_HUB_URL)
        _hub_client = FastMCPClient(hub_url)
        await _hub_client.__aenter__()
        _hub_tools_cache = await _hub_client.list_tools()
    return _hub_client

from taskiq import TaskiqScheduler
from taskiq.schedule_sources import LabelScheduleSource

scheduler = TaskiqScheduler(
    broker=broker,
    sources=[LabelScheduleSource(broker)],
)

# We use a single heartbeat task that runs every minute to check ETCD for dynamic cron jobs
import time
from datetime import datetime

@broker.task(schedule=[{"cron": "* * * * *"}])
async def dynamic_cron_heartbeat():
    """Runs every minute to trigger any dynamic background agents that have matching cron expressions."""
    # We use pycron to evaluate cron expressions against the current time
    import pycron
    
    identity_mgr = get_identity_manager()
    agent_names = await asyncio.to_thread(identity_mgr.list_agents)
    disabled_agents = identity_mgr.get_disabled_agents()
    
    now = datetime.now()
    
    for name in agent_names:
        if name in disabled_agents:
            continue
            
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if not config_data or config_data.get("type") != "background":
            continue
            
        trigger = config_data.get("trigger")
        if trigger and trigger.get("type") == "cron":
            expr = trigger.get("expression")
            if expr and pycron.is_now(expr, now):
                print(f"Triggering background agent {name} via cron: {expr}")
                # System prompt for cron runs
                xml_payload = f"<event_payload><![CDATA[\nScheduled execution triggered at {now.isoformat()}\n]]></event_payload>"
                
                await run_background_agent.kiq(
                    agent_name=name,
                    prompt=xml_payload,
                    user_id=f"svc_agent_{name}"
                )

@broker.task
async def run_background_agent(agent_name: str, prompt: str, user_id: str) -> str:
    """Executes an agent in the background as a Taskiq task."""
    identity_mgr = get_identity_manager()
    
    # 1. Fetch agent configuration
    config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    system_prompt = await asyncio.to_thread(identity_mgr.get_agent_skills, agent_name)
    
    if not config_data or not system_prompt:
        raise ValueError(f"Agent '{agent_name}' configuration or skills not found in etcd.")
        
    config = AgentConfig(**config_data)
    
    # Check if agent is disabled
    disabled_agents = identity_mgr.get_disabled_agents()
    if agent_name in disabled_agents:
        raise ValueError(f"Agent '{agent_name}' is currently disabled.")
    
    # 2. Build the PydanticAI Agent
    model = GoogleModel(config.model)
    model_settings = None
    
    # Model settings logic (simplified copy from host.py for background)
    thinking_level = config.thinking_level
    if thinking_level and thinking_level.lower() not in ("none", "n/a"):
        if "gemini-2.5-pro" in config.model:
            budget = {"low": 1024, "medium": 8192, "high": 16384}.get(thinking_level.lower(), 8192)
            model_settings = GoogleModelSettings(google_thinking_config={"thinking_budget": budget, "include_thoughts": False})
        elif "gemini-2.5-flash" in config.model:
            budget = {"low": 1024, "medium": 4096, "high": 8192}.get(thinking_level.lower(), 4096)
            model_settings = GoogleModelSettings(google_thinking_config={"thinking_budget": budget, "include_thoughts": False})
        elif "gemini-3" in config.model:
            model_settings = GoogleModelSettings(google_thinking_config={"thinking_level": thinking_level.lower(), "include_thoughts": False})
    
    agent = Agent(
        model,
        system_prompt=system_prompt,
        name=config.name,
        model_settings=model_settings,
        retries=3
    )
    
    # 2.5 Inject Tools
    import copy
    health_monitor = get_health_monitor()
    
    # Register Hub Tools
    if config.allowed_tools:
        hub_client = await get_hub_client()
        for tool in _hub_tools_cache:
            if tool.name in config.allowed_tools:
                safe_tool = copy.deepcopy(tool) if hasattr(tool, "model_copy") else tool
                
                async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
                    if health_monitor.get_status("tool", safe_tool.name).get("status") == "Offline":
                        return "SYSTEM: Tool offline."
                    kwargs["__user_id"] = user_id
                    client = await get_hub_client()
                    result = await client.call_tool(safe_tool.name, kwargs)
                    return result.content
                    
                agent.tool(name=safe_tool.name, description=safe_tool.description)(tool_wrapper)

    # Note: External MCP tools can be ported here similarly if background agents need them in the future.
    
    # 3. Execute the run
    try:
        result = await agent.run(prompt)
        
        # Log usage
        if hasattr(result, 'usage'):
            usage = result.usage()
            if usage:
                try:
                    await asyncio.to_thread(
                        identity_mgr.record_usage, 
                        user_id, 
                        usage.request_tokens or 0, 
                        usage.response_tokens or 0
                    )
                except Exception as e:
                    print(f"Failed to record token usage for {user_id}: {e}")
                    
        return result.output
        
    except Exception as e:
        print(f"Error running background agent '{agent_name}': {e}")
        raise
