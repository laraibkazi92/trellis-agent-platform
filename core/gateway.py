import os
import httpx
import yaml
import asyncio
from pathlib import Path
from typing import Dict, List
import uvicorn
import aiofiles
from fastmcp import FastMCP
from core.auth import AuthMiddleware, IdentityManager, auth_token_var

# Initialize FastMCP server with host and port
mcp = FastMCP("Agent Gateway")

BASE_DIR = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
HOST_URL = os.getenv("HOST_URL", "http://localhost:8000")

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)

async def get_agent_description(config: dict, skills_path: Path) -> str:
    """Extracts description from config.yaml or the first paragraph of the skills.md file."""
    if config.get("description"):
        return config["description"]
        
    try:
        async with aiofiles.open(skills_path, "r") as f:
            content = await f.read()
            # Split by newlines and find the first non-empty paragraph that isn't a header
            paragraphs = [p.strip() for p in content.split("\n\n") if p.strip() and not p.strip().startswith("#")]
            if paragraphs:
                return paragraphs[0]
    except Exception:
        pass
    return "No description available."

@mcp.tool()
async def list_agents() -> List[Dict[str, str]]:
    """List all available agents and their descriptions."""
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{HOST_URL}/health", timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                agents_data = data.get("agents", {})
            else:
                return [{"name": "Error", "description": f"Host API unreachable (HTTP {resp.status_code})"}]
    except Exception as e:
        print(f"Error fetching active agents from host: {e}")
        return [{"name": "Error", "description": f"Host API unreachable ({str(e)})"}]

    agents = []
    
    for agent_name, agent_info in agents_data.items():
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
        skills = await asyncio.to_thread(identity_mgr.get_agent_skills, agent_name)
        
        description = "No description available."
        if config_data and "description" in config_data:
            description = config_data["description"]
        elif skills:
            paragraphs = [p.strip() for p in skills.split("\n\n") if p.strip() and not p.strip().startswith("#")]
            if paragraphs:
                description = paragraphs[0]
                
        status = agent_info.get("status", "Online")
        offline_tools = agent_info.get("offline_tools", [])
        
        if status == "Offline":
            description += " [STATUS: OFFLINE - DO NOT ROUTE REQUESTS HERE]"
        elif status == "Degraded":
            description += f" [STATUS: DEGRADED - Offline tools: {', '.join(offline_tools)}]"
            
        agents.append({
            "name": agent_name,
            "description": description
        })
        
    return agents

@mcp.tool()
async def use_agent(agent_name: str, prompt: str) -> str:
    """Call a specific agent with a prompt."""
    token = auth_token_var.get()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{HOST_URL}/v1/chat/completions",
                json={
                    "model": agent_name,
                    "messages": [{"role": "user", "content": prompt}]
                },
                headers=headers,
                timeout=60.0
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 503:
            return f"SYSTEM: The agent '{agent_name}' is currently offline due to technical failures and cannot process requests."
        if e.response.status_code == 404:
            return f"SYSTEM: The agent '{agent_name}' was not found or is disabled."
        return f"SYSTEM: Error calling agent '{agent_name}': {e.response.text}"
    except Exception as e:
        return f"SYSTEM: Failed to connect to agent '{agent_name}': {str(e)}"

@mcp.tool()
async def marketplace_router(prompt: str) -> str:
    """Route a request through the Supervisor agent with a dynamic agent roster."""
    agents = await list_agents()
    roster = "\n".join([f"- {a['name']}: {a['description']}" for a in agents if a['name'] != 'supervisor'])
    
    routing_prompt = f"Available Agents:\n{roster}\n\nUser Request: {prompt}"
    
    return await use_agent("supervisor", routing_prompt)

if __name__ == "__main__":
    app = mcp.http_app()
    app.add_middleware(AuthMiddleware, identity_mgr=identity_mgr)
    uvicorn.run(app, host="0.0.0.0", port=8002)
