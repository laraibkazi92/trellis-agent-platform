import os
import asyncio
from fastapi import APIRouter, Request, Depends
from core.discovery import discover_agents, discover_tools
from core.dependencies import identity_mgr

router = APIRouter(prefix="/api/v1", tags=["Search Index API"])

@router.get("/search-index/tools")
async def get_tools_index(request: Request):
    user = request.session.get('user')
    if not user:
        return []
    tools = await discover_tools()
    return [{"name": t.get("name", ""), "description": t.get("description", ""), "runtime": t.get("runtime", "")} for t in tools]

@router.get("/search-index/agents")
async def get_agents_index(request: Request):
    user = request.session.get('user')
    if not user:
        return []
    agents = await discover_agents(user_id=user.get('sub'), include_background=False)
    return [{"name": a.get("name", ""), "description": a.get("description", ""), "author": a.get("author", ""), "tags": a.get("tags", [])} for a in agents]

@router.get("/search-index/workflows")
async def get_workflows_index(request: Request):
    user = request.session.get('user')
    if not user:
        return []
    agent_names = await asyncio.to_thread(identity_mgr.list_agents)
    result = []
    for name in agent_names:
        config = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if config and config.get("type") in ("background_agent", "background_script"):
            result.append({
                "name": name,
                "description": config.get("description", "")
            })
    return result
