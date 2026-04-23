import os
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates
from core.discovery import discover_agents, discover_tools

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    agents = await discover_agents()
    tools = await discover_tools()
    
    dev_mode = os.getenv("DEV_MODE", "false").lower() == "true"
    public_host_url = os.getenv("PUBLIC_HOST_URL", "http://localhost:8000")
    public_mcp_url = os.getenv("PUBLIC_MCP_URL", "http://localhost:8002/mcp")

    return templates.TemplateResponse(
        request=request,
        name="index.html", 
        context={
            "user": user,
            "agents_count": len(agents),
            "tools_count": len(tools),
            "dev_mode": dev_mode,
            "public_host_url": public_host_url,
            "public_mcp_url": public_mcp_url
        }
    )

@router.get("/agents", response_class=HTMLResponse)
async def agents(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_users = os.getenv("ADMIN_USERS", "").split(",")
    is_admin = user.get("email") in admin_users
    
    agents = await discover_agents()
    
    flash_msg = request.session.pop("flash_msg", None)
    
    public_host_url = os.getenv("PUBLIC_HOST_URL", "http://localhost:8000")
    public_mcp_url = os.getenv("PUBLIC_MCP_URL", "http://localhost:8002/mcp")
    
    return templates.TemplateResponse(
        request=request,
        name="agents.html", 
        context={
            "user": user,
            "agents": agents,
            "is_admin": is_admin,
            "flash_msg": flash_msg,
            "public_host_url": public_host_url,
            "public_mcp_url": public_mcp_url
        }
    )

@router.get("/tools", response_class=HTMLResponse)
async def tools(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_users = os.getenv("ADMIN_USERS", "").split(",")
    is_admin = user.get("email") in admin_users
    
    tools = await discover_tools()
    
    flash_msg = request.session.pop("flash_msg", None)
    
    return templates.TemplateResponse(
        request=request,
        name="tools.html", 
        context={
            "user": user,
            "tools": tools,
            "is_admin": is_admin,
            "flash_msg": flash_msg
        }
    )

@router.get("/catalog")
async def catalog_redirect():
    return RedirectResponse(url='/')
