import json
import os
import httpx
import yaml
import asyncio
from pathlib import Path
from typing import Any, Dict, List
import uvicorn
import aiofiles
from contextlib import asynccontextmanager
from fastmcp import FastMCP, Context
from mcp.types import TextContent, ToolAnnotations
from core.auth import AuthMiddleware, IdentityManager, auth_token_var, user_id_var
from fastapi.middleware.cors import CORSMiddleware
from core.discovery import discover_agents, is_agent_configured, is_tool_configured
from core.agent_search import search_agents as _search_agents_ranked, DEFAULT_LIMIT as AGENT_SEARCH_LIMIT
from core.tool_search import search_tools as _search_tools_ranked, DEFAULT_LIMIT as TOOL_SEARCH_LIMIT
from core.agent_factory import get_hub_client, get_external_mcp_client
from core.models import is_agent_external

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

async def _get_visible_agents() -> List[Dict]:
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
            
        agent_dict = agent_lookup.get(agent_name)
        if not agent_dict:
            continue
            
        if agent_dict.get("type") in ("background_agent", "background_script"):
            continue
        if not is_agent_external(agent_dict):
            continue

        is_configured = agent_dict.get("is_configured", False)

        description = agent_dict.get("description") or "No description available."

        if not description or description == "No description available.":
            skills = agent_dict.get("skills", "")
            paragraphs = [p.strip() for p in skills.split("\n\n") if p.strip() and not p.strip().startswith("#")]
            if paragraphs:
                description = paragraphs[0]

        if not is_configured:
            missing = []
            if agent_dict.get("missing_secrets"):
                missing.append(f"secrets: {', '.join(agent_dict['missing_secrets'])}")
            if agent_dict.get("missing_variables"):
                missing.append(f"variables: {', '.join(agent_dict['missing_variables'])}")
            config_note = f" [NOT CONFIGURED — missing {'; '.join(missing)}. Configure at /agents/{agent_name}/configure]" if missing else " [NOT CONFIGURED — configure at /agents/{agent_name}/configure]"
            description += config_note
        else:
            status = agent_info.get("status", "Online")
            offline_tools = agent_info.get("offline_tools", [])
            if status == "Offline":
                description += " [STATUS: OFFLINE - DO NOT ROUTE REQUESTS HERE]"
            elif status == "Degraded":
                description += f" [STATUS: DEGRADED - Offline tools: {', '.join(offline_tools)}]"

        agents.append({
            "name": agent_name,
            "description": description,
            "configured": is_configured,
        })
        
    return agents

@mcp.tool(
    title="Search Agents",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True),
)
async def search_agents(ctx: Context, query: str, limit: int = AGENT_SEARCH_LIMIT) -> List[Dict]:
    """Find the agents most relevant to a request.

    Use this to discover which specialized agent(s) can handle a task, then call the
    chosen one with `use_agent`. Returns a short, ranked list of
    `{name, description, configured}` — not the full catalog — so it scales to large
    numbers of agents.

    Unconfigured agents are included with `configured: false` and a note in their
    description listing the missing credentials and a configure URL. Only call
    `use_agent` on agents where `configured` is true.

    Args:
        query: Natural-language description of the task or topic to find agents for.
        limit: Maximum number of agents to return (default: 5).
    """
    await ctx.report_progress(0, 2, message=f"Searching agents for: '{query}'")

    visible = await _get_visible_agents()
    visible_by_name = {a["name"]: a for a in visible}
    if not visible_by_name:
        await ctx.report_progress(2, 2, message="No agents are currently available.")
        return []

    await ctx.report_progress(1, 2, message="Ranking results...")
    ranked = await _search_agents_ranked(query, limit=0, include_disabled=False)

    results: List[Dict] = []
    for r in ranked:
        agent = visible_by_name.get(r["name"])
        if agent:
            results.append({
                "name": agent["name"],
                "description": agent["description"],
                "configured": agent.get("configured", True),
            })
            if len(results) >= limit:
                break

    names = [r["name"] for r in results]
    await ctx.report_progress(2, 2, message=f"Found {len(results)} agent(s): {', '.join(names) if names else 'none'}")
    return results

@mcp.tool(
    title="Use Agent",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False),
)
async def use_agent(ctx: Context, agent_name: str, prompt: str) -> str:
    """Call a specific agent with a prompt and return its response.

    Always call `search_agents` first to confirm the agent name and that it is
    configured. Do not guess agent names.

    Args:
        agent_name: Exact name of the agent to call (from `search_agents`).
        prompt: The full, self-contained request to send to the agent.
    """
    token = auth_token_var.get()
    user_id = user_id_var.get()

    prompt_preview = prompt[:150] + "..." if len(prompt) > 150 else prompt
    await ctx.report_progress(1, 3, message=f"Routing to agent: {agent_name} — \"{prompt_preview}\"")

    cfg = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    if cfg and not is_agent_external(cfg):
        return f"SYSTEM: Access denied. Agent '{agent_name}' is internal and cannot be called directly."

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

    await ctx.report_progress(2, 3, message=f"Calling {agent_name}...")

    try:
        req_kwargs = {
            "json": {
                "model": agent_name,
                "messages": [{"role": "user", "content": prompt}],
                "stream": True
            },
            "headers": headers,
            "timeout": httpx.Timeout(600.0, connect=10.0)
        }

        async def _consume_stream(client_obj):
            async with client_obj.stream("POST", f"{HOST_URL}/v1/chat/completions", **req_kwargs) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        if data.get("status") == "processing":
                            await ctx.report_progress(2, 3, message=f"Agent '{agent_name}' is thinking...")
                        elif data.get("status") == "tool_call":
                            await ctx.report_progress(2, 3, message=f"Agent '{agent_name}' is calling tool: {data.get('tool')}...")
                        elif "choices" in data:
                            return data["choices"][0]["message"]["content"]
                        elif "error" in data:
                            return f"SYSTEM: Agent '{agent_name}' execution failed: {data['error']}"
                    except json.JSONDecodeError as e:
                        print(f"Warning: Failed to parse JSON from agent stream: {e}. Raw line: {line}")
            return f"SYSTEM: Agent '{agent_name}' returned no content."

        if hasattr(app, "state") and hasattr(app.state, "http_client"):
            content = await _consume_stream(app.state.http_client)
        else:
            async with httpx.AsyncClient() as client:
                content = await _consume_stream(client)

        if not content.startswith("SYSTEM:"):
            await ctx.report_progress(3, 3, message=f"Agent '{agent_name}' responded ({len(content)} chars)")
        return content
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 503:
            return f"SYSTEM: The agent '{agent_name}' is currently offline due to technical failures and cannot process requests."
        if e.response.status_code == 404:
            return f"SYSTEM: The agent '{agent_name}' was not found or is disabled."
        return f"SYSTEM: Error calling agent '{agent_name}': {e.response.text}"
    except Exception as e:
        return f"SYSTEM: Failed to connect to agent '{agent_name}': {str(e)}"

async def _is_tool_publicly_whitelisted(tool_name: str) -> bool:
    """Authorization Guard for `use_tool`: check `public`/`public_tools` directly against
    the tool's/MCP's own registry config, independent of `search_tools`. This must not
    assume every whitelisted tool was necessarily discoverable via search — an MCP server
    without a static `tools:` list in its `mcp.yaml` never surfaces in `search_tools`
    output even once marked public (see core/tool_search.py), but its whitelisted tools
    must still be directly executable here.

    Fails closed on anything unexpected (unknown tool, malformed `mcp__` name, non-`True`
    `public` value, non-list `public_tools`) — mirrors the secure-by-default checks
    already applied in `is_tool_configured`/`search_tools`.
    """
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) != 3:
            return False
        _, server_name, sub_tool_name = parts
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, server_name)
        if not config:
            return False
        public_tools_raw = config.get("public_tools", [])
        public_tools = set(public_tools_raw) if isinstance(public_tools_raw, list) else set()
        return config.get("public") is True or sub_tool_name in public_tools

    config = await asyncio.to_thread(identity_mgr.get_tool_config, tool_name)
    if not config:
        return False
    return config.get("public") is True


def _extract_tool_output(result: Any) -> Any:
    """Unwrap a fastmcp `CallToolResult` into the raw structured value a direct caller
    expects, preserving full stdout/JSON/error codes rather than pydantic-ai's
    agent-facing `.content` (a list of MCP content blocks).

    Local hub tools (see core/hub.py's `run_tool`) return a plain dict (e.g.
    `{"stdout", "stderr", "exit_code"}`) which FastMCP surfaces as `structured_content`/
    `data` — prefer those. Falls back to joined text content for tools that only ever
    emit unstructured text.
    """
    if result.data is not None:
        return result.data
    if result.structured_content is not None:
        return result.structured_content
    texts = [c.text for c in (result.content or []) if isinstance(c, TextContent)]
    if texts:
        return "\n".join(texts)
    return None


@mcp.tool(
    title="Search Tools",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True),
)
async def search_tools(ctx: Context, query: str, limit: int = TOOL_SEARCH_LIMIT) -> List[Dict]:
    """Find deterministic tools available for direct execution.

    Use this to discover which whitelisted tool can handle a request — a CLI lookup,
    status check, or single deterministic operation — then call `use_tool` to execute
    it directly, with no intermediate agent hop.

    Returns a short, ranked list of Tool Cards: `{name, description, parameters,
    configured, status, source}`. Unconfigured tools are included with `configured:
    false` and a note in their description listing the missing secrets/variables. Only
    call `use_tool` on tools where `configured` is true.

    Args:
        query: Natural-language description of the command or lookup to find a tool for.
        limit: Maximum number of tools to return (default: 8).
    """
    user_id = user_id_var.get()
    await ctx.report_progress(0, 1, message=f"Searching tools for: '{query}'")

    results = await _search_tools_ranked(query=query, limit=limit, user_id=user_id)

    names = [r["name"] for r in results]
    await ctx.report_progress(1, 1, message=f"Found {len(results)} tool(s): {', '.join(names) if names else 'none'}")
    return results


@mcp.tool(
    title="Use Tool",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False),
)
async def use_tool(ctx: Context, tool_name: str, arguments: Dict[str, Any]) -> Any:
    """Directly execute a whitelisted deterministic tool with arguments.

    Bypasses all agent hops and returns the raw structured output. Always call
    `search_tools` first to confirm the exact tool name, its parameter schema, and
    that it is configured — do not guess.

    Args:
        tool_name: Exact name of the tool (e.g. 'opsctl', 'netctl', or an MCP tool's
            'mcp__{server}__{name}' form as returned by `search_tools`).
        arguments: Dictionary of arguments matching the tool's input schema.
    """
    user_id = user_id_var.get()

    await ctx.report_progress(0, 3, message=f"Checking access for: {tool_name}")
    try:
        whitelisted = await _is_tool_publicly_whitelisted(tool_name)
    except Exception as e:
        return f"SYSTEM: Error checking tool access for '{tool_name}': {e}"
    if not whitelisted:
        return f"SYSTEM: Access denied. Tool '{tool_name}' is internal and not exposed for direct execution."

    await ctx.report_progress(1, 3, message=f"Checking configuration for: {tool_name}")
    try:
        status = await is_tool_configured(tool_name, user_id)
    except Exception as e:
        return f"SYSTEM: Error checking configuration for tool '{tool_name}': {e}"
    if not status["configured"]:
        missing = status["missing_secrets"] + status["missing_variables"]
        missing_text = ", ".join(missing) if missing else "required configuration"
        return f"SYSTEM: Tool '{tool_name}' requires configuration before it can be used. Missing: {missing_text}. Configure at /configuration"

    await ctx.report_progress(2, 3, message=f"Executing {tool_name}...")
    try:
        if tool_name.startswith("mcp__"):
            _, server_name, sub_tool_name = tool_name.split("__", 2)
            client = await get_external_mcp_client(server_name, user_id)
            result = await client.call_tool(sub_tool_name, arguments, raise_on_error=False)
        else:
            client = await get_hub_client()
            result = await client.call_tool(tool_name, {**arguments, "__user_id": user_id}, raise_on_error=False)
    except Exception as e:
        return f"SYSTEM: Error executing tool '{tool_name}': {e}"

    output = _extract_tool_output(result)
    await ctx.report_progress(3, 3, message=f"Tool '{tool_name}' execution complete.")
    return output


if __name__ == "__main__":
    app = mcp.http_app()
    app.add_middleware(AuthMiddleware, identity_mgr=identity_mgr)
    uvicorn.run(app, host="0.0.0.0", port=8002)
