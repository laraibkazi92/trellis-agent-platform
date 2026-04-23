import os
import asyncio
from typing import List, Dict
from core.auth import IdentityManager

# Initialize IdentityManager locally for discovery purposes
identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)

async def discover_agents() -> List[Dict]:
    """Scan etcd registry for agents."""
    agents = []
    agent_names = await asyncio.to_thread(identity_mgr.list_agents)
    
    for name in agent_names:
        if name == "supervisor":
            continue
            
        config = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if config:
            skills_content = await asyncio.to_thread(identity_mgr.get_agent_skills, name) or ""
            
            agents.append({
                "name": config.get("name", name),
                "author": config.get("author", "Unknown"),
                "description": config.get("description", ""),
                "tags": config.get("tags", []),
                "capabilities": config.get("capabilities", []),
                "skills": skills_content,
                "a2a_access": config.get("a2a_access", []),
                "model": config.get("model", "gemini-3-flash-preview"),
                "thinking_level": config.get("thinking_level", "medium"),
                "version": config.get("version", "0.1.0"),
            })
    return agents

async def discover_tools() -> List[Dict]:
    """Scan etcd registry for tools."""
    tools = []
    tool_names = await asyncio.to_thread(identity_mgr.list_tools)
    
    for name in tool_names:
        config = await asyncio.to_thread(identity_mgr.get_tool_config, name)
        if config:
            tools.append({
                "name": config.get("name", name),
                "description": config.get("description", ""),
                "runtime": config.get("runtime", "unknown"),
                "entrypoint": config.get("entrypoint", ""),
                "rel_path": config.get("rel_path", ""),
                "inputs": config.get("inputs", {}),
                "outputs": config.get("outputs", {}),
                "version": config.get("version", "0.1.0"),
            })
    return tools
