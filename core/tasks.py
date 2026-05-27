import os
import asyncio
from typing import Dict, Any, Optional
from taskiq_redis import ListQueueBroker
from pydantic_ai import Agent
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings

from core.models import AgentConfig
from core.auth import IdentityManager

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
    
    # Note: A background agent typically doesn't need external interactive tool connections (like FastMCP via host) 
    # unless specifically bridged. For now, it runs with core capabilities. If background tasks need tools,
    # we would inject them here via direct Tool Hub connections or similar.
    # Currently keeping simple as per refactor spec.
    
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
