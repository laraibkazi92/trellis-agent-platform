import os
import httpx
import yaml
import asyncio
from pathlib import Path
from typing import Dict, List
import uvicorn
import aiofiles
from contextlib import asynccontextmanager
from fastmcp import FastMCP
from core.auth import AuthMiddleware, IdentityManager, auth_token_var, user_id_var
from fastapi.middleware.cors import CORSMiddleware
from core.discovery import discover_agents, is_agent_configured
from core.agent_search import search_agents as _search_agents_ranked, DEFAULT_LIMIT as AGENT_SEARCH_LIMIT

@asynccontextmanager
async def lifespan(app):
    app.state.http_client = httpx.AsyncClient(timeout=30.0)
    yield
    await app.state.http_client.aclose()

# Initialize FastMCP server with host and port
mcp = FastMCP("Agent Gateway")

# FastMCP underlying FastAPI app
if hasattr(mcp, "_app"):
    app = mcp._app
    app.router.lifespan_context = lifespan
    
    DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"
    cors_origins_str = os.getenv("CORS_ALLOWED_ORIGINS", "")
    if DEV_MODE:
        allow_origins = ["*"]
    else:
        allow_origins = [origin.strip() for origin in cors_origins_str.split(",")] if cors_origins_str else []
        
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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

async def _get_visible_agents() -> List[Dict[str, str]]:
    """Internal: agents visible to the current user, with health-decorated descriptions.

    Applies the same filtering the old public ``list_agents`` tool did (disabled /
    offline / background / unconfigured), scoped to the calling user. No longer exposed
    as an MCP tool — clients use ``search_agents`` instead to avoid dumping every agent.
    """
    user_id = user_id_var.get()
    
    try:
        discovered_agents = await discover_agents(user_id=user_id)
        agent_lookup = {a["name"]: a for a in discovered_agents}
    except Exception as e:
        print(f"Error checking agent configurations: {e}")
        return [{"name": "Error", "description": f"Failed to verify agent configurations: {e}"}]
    
    try:
        if hasattr(app, "state") and hasattr(app.state, "http_client"):
            client = app.state.http_client
            resp = await client.get(f"{HOST_URL}/health", timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                agents_data = data.get("agents", {})
            else:
                return [{"name": "Error", "description": f"Host API unreachable (HTTP {resp.status_code})"}]
        else:
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
    disabled_agents = identity_mgr.get_disabled_standard_agents()
    
    for agent_name, agent_info in agents_data.items():
        if agent_name in disabled_agents:
            continue
            
        if agent_name == "supervisor":
            description = "Intelligent routing agent."
            status = agent_info.get("status", "Online")
            if status == "Offline":
                description += " [STATUS: OFFLINE]"
            agents.append({"name": agent_name, "description": description})
            continue

        agent_dict = agent_lookup.get(agent_name)
        if not agent_dict:
            continue
            
        if agent_dict.get("type") in ("background_agent", "background_script"):
            continue
            
        if not agent_dict.get("is_configured", False):
            continue
            
        description = agent_dict.get("description") or "No description available."
        
        if not description or description == "No description available.":
            skills = agent_dict.get("skills", "")
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
async def search_agents(query: str, limit: int = AGENT_SEARCH_LIMIT) -> List[Dict[str, str]]:
    """Find the agents most relevant to a request.

    Use this to discover which specialized agent(s) can handle a task, then call the
    chosen one with `use_agent`. Returns a short, ranked list of `{name, description}` —
    not the full catalog — so it scales to large numbers of agents.
    """
    visible = await _get_visible_agents()
    # _get_visible_agents already drops the supervisor's offline marker etc.; keep its
    # (health-decorated) descriptions, but order/limit by semantic relevance.
    visible_by_name = {a["name"]: a for a in visible if a["name"] != "supervisor"}
    if not visible_by_name:
        return []

    ranked = await _search_agents_ranked(query, limit=0, include_disabled=False)

    results: List[Dict[str, str]] = []
    for r in ranked:
        agent = visible_by_name.get(r["name"])
        if agent:
            results.append({"name": agent["name"], "description": agent["description"]})
            if len(results) >= limit:
                break
    return results

@mcp.tool()
async def use_agent(agent_name: str, prompt: str) -> str:
    """Call a specific agent with a prompt."""
    token = auth_token_var.get()
    user_id = user_id_var.get()
    
    if agent_name != "supervisor":
        try:
            status = await is_agent_configured(agent_name, user_id)
            if not status["configured"]:
                parts = [f"SYSTEM: Agent '{agent_name}' requires configuration before it can be used."]
                if status["missing_secrets"]:
                    parts.append(f"Missing secrets: {', '.join(status['missing_secrets'])}.")
                if status["missing_variables"]:
                    parts.append(f"Missing variables: {', '.join(status['missing_variables'])}.")
                parts.append(f"Configure it at: /agents/{agent_name}/configure")
                return " ".join(parts)
        except Exception as e:
            print(f"Error checking agent configuration for '{agent_name}': {e}")
            return f"SYSTEM: Error checking agent configuration for '{agent_name}': {e}"
            
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req_kwargs = {
            "json": {
                "model": agent_name,
                "messages": [{"role": "user", "content": prompt}]
            },
            "headers": headers,
            "timeout": 60.0
        }
        
        if hasattr(app, "state") and hasattr(app.state, "http_client"):
            client = app.state.http_client
            response = await client.post(f"{HOST_URL}/v1/chat/completions", **req_kwargs)
        else:
            async with httpx.AsyncClient() as client:
                response = await client.post(f"{HOST_URL}/v1/chat/completions", **req_kwargs)
                
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
async def auto_select(prompt: str) -> str:
    """Automatically pick the best agent for a request and run it.

    Hands the request to the Supervisor, which searches for the most relevant
    specialized agent(s) and delegates to them. Use this when you don't know which
    agent to call — it routes for you. To target a specific agent yourself, use
    `search_agents` then `use_agent` instead.
    """
    return await use_agent("supervisor", prompt)

if __name__ == "__main__":
    app = mcp.http_app()
    app.add_middleware(AuthMiddleware, identity_mgr=identity_mgr)
    uvicorn.run(app, host="0.0.0.0", port=8002)
