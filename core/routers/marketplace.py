import os
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates
from core.discovery import discover_agents, discover_tools

router = APIRouter()

@router.get("/catalog", response_class=HTMLResponse)
async def catalog(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_users = os.getenv("ADMIN_USERS", "").split(",")
    is_admin = user.get("email") in admin_users
    
    agents = await discover_agents()
    tools = await discover_tools()
    
    # Check for flash messages
    flash_msg = request.session.pop("flash_msg", None)
    
    return templates.TemplateResponse(
        request=request,
        name="catalog.html", 
        context={
            "user": user,
            "agents": agents,
            "tools": tools,
            "is_admin": is_admin,
            "flash_msg": flash_msg
        }
    )