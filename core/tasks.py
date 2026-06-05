import os
import asyncio
from typing import Dict, Any, Optional, List
from taskiq_redis import ListQueueBroker
from pydantic_ai import Agent

from core.auth import user_id_var
from core.agent_factory import (
    build_agent,
    get_identity_manager,
    get_health_monitor,
    get_hub_client,
)

# Redis broker configuration
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
broker = ListQueueBroker(redis_url)

from taskiq import TaskiqScheduler, Context, TaskiqDepends
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
                
                task = await run_background_agent.kiq(
                    agent_name=name,
                    prompt=xml_payload,
                    user_id=f"svc_agent_{name}"
                )
                try:
                    await asyncio.to_thread(
                        identity_mgr.record_agent_run_state,
                        name,
                        task.task_id,
                        "pending",
                        {"prompt": xml_payload, "user_id": f"svc_agent_{name}"}
                    )
                except Exception as e:
                    print(f"Failed to record pending state for {name}: {e}")

@broker.task
async def run_background_agent(
    agent_name: str,
    prompt: str,
    user_id: str,
    context: Context = TaskiqDepends(),
) -> str:
    """Executes an agent in the background as a Taskiq task."""
    # Set context variables for thread/async safety with robust try...finally cleanup
    token = user_id_var.set(user_id)
    task_id = context.message.task_id if (context and context.message) else "unknown"
    try:
        identity_mgr = get_identity_manager()
        
        # Record processing state
        try:
            await asyncio.to_thread(
                identity_mgr.record_agent_run_state,
                agent_name,
                task_id,
                "processing",
                {"prompt": prompt, "user_id": user_id}
            )
        except Exception as err:
            print(f"Failed to record processing state for {agent_name} run {task_id}: {err}")
            
        # 1. Fetch agent configuration
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
        if not config_data:
            raise ValueError(f"Agent '{agent_name}' configuration not found in etcd.")
            
        # Check if agent is disabled
        disabled_agents = identity_mgr.get_disabled_agents()
        if agent_name in disabled_agents:
            raise ValueError(f"Agent '{agent_name}' is currently disabled.")
        
        # 2. Build the PydanticAI Agent with full parity (Hub, MCP, A2A)
        agent = await build_agent(agent_name)
        
        # 3. Execute the run
        result = await agent.run(prompt)
        
        # Log usage
        usage_data = {}
        if hasattr(result, 'usage'):
            usage = result.usage
            if callable(usage):
                usage = usage()
            if usage:
                usage_data = {
                    "request_tokens": usage.request_tokens or 0,
                    "response_tokens": usage.response_tokens or 0,
                    "total_tokens": (usage.request_tokens or 0) + (usage.response_tokens or 0)
                }
                try:
                    await asyncio.to_thread(
                        identity_mgr.record_usage, 
                        user_id, 
                        usage.request_tokens or 0, 
                        usage.response_tokens or 0
                    )
                    # Support metric recording per-agent for observability
                    await asyncio.to_thread(
                        identity_mgr.record_agent_usage,
                        user_id,
                        agent_name,
                        usage.request_tokens or 0,
                        usage.response_tokens or 0
                    )
                except Exception as e:
                    print(f"Failed to record token usage for {user_id}: {e}")
                    
        # Record completed state
        try:
            await asyncio.to_thread(
                identity_mgr.record_agent_run_state,
                agent_name,
                task_id,
                "completed",
                {
                    "prompt": prompt,
                    "user_id": user_id,
                    "output": result.output,
                    "usage": usage_data
                }
            )
        except Exception as err:
            print(f"Failed to record completed state for {agent_name} run {task_id}: {err}")
                    
        return result.output
        
    except Exception as e:
        print(f"Error running background agent '{agent_name}': {e}")
        # Record failed state
        try:
            await asyncio.to_thread(
                identity_mgr.record_agent_run_state,
                agent_name,
                task_id,
                "failed",
                {
                    "prompt": prompt,
                    "user_id": user_id,
                    "error": str(e)
                }
            )
        except Exception as err:
            print(f"Failed to record failed state for {agent_name} run {task_id}: {err}")
        raise
    finally:
        # Guarantee ContextVar state cleanup
        user_id_var.reset(token)
