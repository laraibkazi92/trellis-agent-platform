import os
import httpx
import yaml
from pathlib import Path
from typing import Dict, List
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server with host and port
mcp = FastMCP("Agent Gateway", host="0.0.0.0", port=8002)

BASE_DIR = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
HOST_URL = os.getenv("HOST_URL", "http://localhost:8000")

def get_agent_description(config: dict, skills_path: Path) -> str:
    """Extracts description from config.yaml or the first paragraph of the skills.md file."""
    if config.get("description"):
        return config["description"]
        
    try:
        with open(skills_path, "r") as f:
            content = f.read()
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
    if not AGENTS_DIR.exists():
        return agents

    for agent_dir in AGENTS_DIR.iterdir():
        if agent_dir.is_dir():
            config_path = agent_dir / "config.yaml"
            skills_path = agent_dir / "skills.md"
            if config_path.exists() and skills_path.exists():
                try:
                    with open(config_path, "r") as f:
                        config = yaml.safe_load(f)
                    agents.append({
                        "name": config.get("name", agent_dir.name),
                        "description": get_agent_description(config, skills_path)
                    })
                except Exception:
                    continue
    return agents

@mcp.tool()
async def use_agent(agent_name: str, prompt: str) -> str:
    """Call a specific agent with a prompt."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{HOST_URL}/v1/chat/completions",
            json={
                "model": agent_name,
                "messages": [{"role": "user", "content": prompt}]
            },
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
    mcp.run(transport="sse")
