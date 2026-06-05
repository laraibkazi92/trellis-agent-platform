import os
import asyncio
from typing import List, Dict, Optional
from core.auth import IdentityManager

# Initialize IdentityManager locally for discovery purposes
identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)

async def get_agent_required_secrets(config: Dict) -> List[str]:
    """Helper to determine all required secrets for an agent based on its tools/MCPs."""
    required = set()
    
    allowed_tools = config.get("allowed_tools", [])
    for tool_name in allowed_tools:
        tool_config = await asyncio.to_thread(identity_mgr.get_tool_config, tool_name)
        if tool_config and tool_config.get("secrets"):
            required.update(tool_config.get("secrets", []))
        elif tool_name.startswith("mcp__"):
            parts = tool_name.split("__")
            if len(parts) >= 3:
                mcp_name = parts[1]
                mcp_config = await asyncio.to_thread(identity_mgr.get_mcp_config, mcp_name)
                if mcp_config and mcp_config.get("secrets"):
                    required.update(mcp_config.get("secrets", []))
            
    allowed_mcps = config.get("allowed_mcps", [])
    for mcp_name in allowed_mcps:
        mcp_config = await asyncio.to_thread(identity_mgr.get_mcp_config, mcp_name)
        if mcp_config and mcp_config.get("secrets"):
            required.update(mcp_config.get("secrets", []))
            
    return sorted(list(required))

async def get_agent_required_variables(config: Dict) -> List[str]:
    """Helper to determine all required non-sensitive variables for an agent based on its tools/MCPs."""
    required = set()
    
    allowed_tools = config.get("allowed_tools", [])
    for tool_name in allowed_tools:
        tool_config = await asyncio.to_thread(identity_mgr.get_tool_config, tool_name)
        if tool_config and tool_config.get("variables"):
            required.update(tool_config.get("variables", []))
        elif tool_name.startswith("mcp__"):
            parts = tool_name.split("__")
            if len(parts) >= 3:
                mcp_name = parts[1]
                mcp_config = await asyncio.to_thread(identity_mgr.get_mcp_config, mcp_name)
                if mcp_config and mcp_config.get("variables"):
                    required.update(mcp_config.get("variables", []))
            
    allowed_mcps = config.get("allowed_mcps", [])
    for mcp_name in allowed_mcps:
        mcp_config = await asyncio.to_thread(identity_mgr.get_mcp_config, mcp_name)
        if mcp_config and mcp_config.get("variables"):
            required.update(mcp_config.get("variables", []))
            
    return sorted(list(required))

async def is_agent_configured(agent_name: str, user_id: str) -> bool:
    """Fast check to determine if a specific agent is configured for a user."""
    if agent_name == "supervisor":
        return True
        
    config = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    if not config:
        return False
        
    is_background = config.get("type") == "background"
    
    required_secrets = await get_agent_required_secrets(config)
    required_variables = await get_agent_required_variables(config)
    
    if not required_secrets and not required_variables:
        return True
        
    global_secrets = await asyncio.to_thread(identity_mgr.get_global_secrets)
    global_variables = await asyncio.to_thread(identity_mgr.get_global_variables)
    
    user_required_secrets = [s for s in required_secrets if s not in global_secrets]
    user_required_variables = [s for s in required_variables if s not in global_variables]
    
    if not user_required_secrets and not user_required_variables:
        return True
        
    if is_background:
        svc_secrets = await asyncio.to_thread(identity_mgr.get_user_secrets, f"svc_agent_{agent_name}")
        svc_variables = await asyncio.to_thread(identity_mgr.get_user_variables, f"svc_agent_{agent_name}")
        
        for req in user_required_secrets:
            if req not in svc_secrets:
                return False
        for req in user_required_variables:
            if req not in svc_variables:
                return False
    else:
        if not user_id:
            return False
            
        human_user_secrets = await asyncio.to_thread(identity_mgr.get_user_secrets, user_id)
        human_user_variables = await asyncio.to_thread(identity_mgr.get_user_variables, user_id)
        
        for req in user_required_secrets:
            if req not in human_user_secrets:
                return False
        for req in user_required_variables:
            if req not in human_user_variables:
                return False
                
    return True

async def discover_agents(user_id: Optional[str] = None, include_background: bool = False) -> List[Dict]:
    """Scan etcd registry for agents."""
    agents = []
    agent_names = await asyncio.to_thread(identity_mgr.list_agents)
    
    # Cache global secrets and variables once per discovery
    global_secrets = await asyncio.to_thread(identity_mgr.get_global_secrets)
    global_variables = await asyncio.to_thread(identity_mgr.get_global_variables)
    
    # If a user is provided, pre-fetch their secrets and variables for standard agents
    human_user_secrets = {}
    human_user_variables = {}
    if user_id:
        human_user_secrets = await asyncio.to_thread(identity_mgr.get_user_secrets, user_id)
        human_user_variables = await asyncio.to_thread(identity_mgr.get_user_variables, user_id)
    
    for name in agent_names:
        if name == "supervisor":
            continue
            
        config = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if config:
            is_background = config.get("type") == "background"
            
            if is_background and not include_background:
                continue
                
            skills_content = await asyncio.to_thread(identity_mgr.get_agent_skills, name) or ""
            health = await asyncio.to_thread(identity_mgr.get_health_status, "agent", name)
            
            required_secrets = await get_agent_required_secrets(config)
            required_variables = await get_agent_required_variables(config)
            
            # Determine configuration status based on identity
            is_configured = True
            missing_secrets = []
            missing_variables = []
            
            # We filter out globals from required so UI knows what user actually needs to provide
            user_required_secrets = [s for s in required_secrets if s not in global_secrets]
            user_required_variables = [s for s in required_variables if s not in global_variables]
            
            if user_required_secrets:
                if is_background:
                    # Check background service account
                    svc_secrets = await asyncio.to_thread(identity_mgr.get_user_secrets, f"svc_agent_{name}")
                    for req in user_required_secrets:
                        if req not in svc_secrets:
                            is_configured = False
                            missing_secrets.append(req)
                else:
                    # Check human user account
                    if not user_id:
                        is_configured = False
                        missing_secrets = user_required_secrets
                    else:
                        for req in user_required_secrets:
                            if req not in human_user_secrets:
                                  is_configured = False
                                  missing_secrets.append(req)
                                  
            if user_required_variables:
                if is_background:
                    svc_variables = await asyncio.to_thread(identity_mgr.get_user_variables, f"svc_agent_{name}")
                    for req in user_required_variables:
                        if req not in svc_variables:
                            is_configured = False
                            missing_variables.append(req)
                else:
                    if not user_id:
                        is_configured = False
                        missing_variables = user_required_variables
                    else:
                        for req in user_required_variables:
                            if req not in human_user_variables:
                                is_configured = False
                                missing_variables.append(req)
            
            agents.append({
                "name": config.get("name", name),
                "type": config.get("type", "standard"),
                "author": config.get("author", "Unknown"),
                "description": config.get("description", ""),
                "tags": config.get("tags", []),
                "capabilities": config.get("capabilities", []),
                "skills": skills_content,
                "a2a_access": config.get("a2a_access", []),
                "model": config.get("model", "gemini-3-flash-preview"),
                "thinking_level": config.get("thinking_level", "medium"),
                "version": config.get("version", "0.1.0"),
                "health": health or {"status": "Online"},
                "required_secrets": user_required_secrets,
                "required_variables": user_required_variables,
                "is_configured": is_configured,
                "missing_secrets": missing_secrets,
                "missing_variables": missing_variables,
                "current_variables": human_user_variables if not is_background else svc_variables
             })
    agents.sort(key=lambda x: x["name"].lower())
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
                
    tools.sort(key=lambda x: x["name"].lower())
    return tools
