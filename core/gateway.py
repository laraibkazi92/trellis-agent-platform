import os
import httpx
import yaml
import asyncio
from pathlib import Path
from typing import Dict, List
import uvicorn
import aiofiles
from mcp.server.fastmcp import FastMCP
from core.auth import AuthMiddleware, IdentityManager, auth_token_var

# Initialize FastMCP server with host and port
mcp = FastMCP("Agent Gateway", host="0.0.0.0", port=8002)

BASE_DIR = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
HOST_URL = os.getenv("HOST_URL", "http://localhost:8000")

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
    agents = []
    if not await asyncio.to_thread(AGENTS_DIR.exists):
        return agents

    for agent_dir in await asyncio.to_thread(lambda: list(AGENTS_DIR.iterdir())):
        is_dir = await asyncio.to_thread(agent_dir.is_dir)
        if is_dir:
            config_path = agent_dir / "config.yaml"
            skills_path = agent_dir / "skills.md"
            
            config_exists = await asyncio.to_thread(config_path.exists)
            skills_exists = await asyncio.to_thread(skills_path.exists)
            
            if config_exists and skills_exists:
                try:
                    async with aiofiles.open(config_path, "r") as f:
                        content = await f.read()
                        config = yaml.safe_load(content)
                    
                    description = await get_agent_description(config, skills_path)
                    agents.append({
                        "name": config.get("name", agent_dir.name),
                        "description": description
                    })
                except Exception:
                    continue
    return agents

@mcp.tool()
async def use_agent(agent_name: str, prompt: str) -> str:
    """Call a specific agent with a prompt."""
    token = auth_token_var.get()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

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

@mcp.tool()
async def marketplace_router(prompt: str) -> str:
    """Route a request through the Supervisor agent with a dynamic agent roster."""
    agents = await list_agents()
    roster = "\n".join([f"- {a['name']}: {a['description']}" for a in agents if a['name'] != 'supervisor'])
    
    routing_prompt = f"Available Agents:\n{roster}\n\nUser Request: {prompt}"
    
    return await use_agent("supervisor", routing_prompt)

if __name__ == "__main__":
    app = mcp.sse_app()
    identity_mgr = IdentityManager(
        host=os.getenv("ETCD_HOST", "127.0.0.1"),
        port=int(os.getenv("ETCD_PORT", 2379))
    )
    app.add_middleware(AuthMiddleware, identity_mgr=identity_mgr)
    uvicorn.run(app, host="0.0.0.0", port=8002)
