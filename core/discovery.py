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
            
            health = await asyncio.to_thread(identity_mgr.get_health_status, "agent", name)
            
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
                "health": health or {"status": "Online"}
            })
    return agents

async def discover_tools() -> List[Dict]:
    """Scan etcd registry for tools."""
    tools = []
    tool_names = await asyncio.to_thread(identity_mgr.list_tools)
    
    for name in tool_names:
        config = await asyncio.to_thread(identity_mgr.get_tool_config, name)
        if config:
            health = await asyncio.to_thread(identity_mgr.get_health_status, "tool", name)
            tools.append({
                "name": config.get("name", name),
                "description": config.get("description", ""),
                "runtime": config.get("runtime", "unknown"),
                "entrypoint": config.get("entrypoint", ""),
                "rel_path": config.get("rel_path", ""),
                "inputs": config.get("inputs", {}),
                "outputs": config.get("outputs", {}),
                "version": config.get("version", "0.1.0"),
                "health": health or {"status": "Online"},
                "is_mcp": False
            })
            
    mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
    for mcp_name in mcp_names:
        mcp_config = await asyncio.to_thread(identity_mgr.get_mcp_config, mcp_name)
        if mcp_config and "tools" in mcp_config:
            for t in mcp_config["tools"]:
                inputs = {}
                if "inputSchema" in t and "properties" in t["inputSchema"]:
                    required = t["inputSchema"].get("required", [])
                    for prop_name, prop_details in t["inputSchema"]["properties"].items():
                        inputs[prop_name] = {
                            "type": prop_details.get("type", "string"),
                            "description": prop_details.get("description", ""),
                            "required": prop_name in required
                        }
                tools.append({
                    "name": t.get("name", ""),
                    "description": t.get("description", ""),
                    "runtime": "mcp",
                    "entrypoint": mcp_name,
                    "rel_path": "",
                    "inputs": inputs,
                    "outputs": {},
                    "version": "1.0.0",
                    "health": {"status": "Online"},
                    "is_mcp": True,
                    "mcp_source": mcp_name
                })
                
    return tools
