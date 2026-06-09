import os
import json
import asyncio
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, identity_mgr, CSRFRoute
from core.discovery import discover_agents, discover_tools, get_agent_required_secrets, get_agent_required_variables
from core.auth import is_admin
from core.models import Identity, IdentityType

router = APIRouter(route_class=CSRFRoute)

@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    agents = await discover_agents(user_id=user.get('sub'))
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
        
    admin_access = is_admin(request)
    agents = await discover_agents(user_id=user.get('sub'), include_background=False)
    disabled_agents = identity_mgr.get_disabled_standard_agents()
    
    # Enrich agents with disabled status
    for agent in agents:
        agent["is_disabled"] = agent["name"] in disabled_agents

    flash_msg = request.session.pop("flash_msg", None)
    
    public_host_url = os.getenv("PUBLIC_HOST_URL", "http://localhost:8000")
    public_mcp_url = os.getenv("PUBLIC_MCP_URL", "http://localhost:8002/mcp")
    
    return templates.TemplateResponse(
        request=request,
        name="agents.html", 
        context={
            "user": user,
            "agents": agents,
            "flash_msg": flash_msg,
            "public_host_url": public_host_url,
            "public_mcp_url": public_mcp_url,
            "is_admin": admin_access
        }
    )

@router.post("/agents/{agent_name}/configure")
async def configure_agent_secrets(request: Request, agent_name: str):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    form = await request.form()
    
    # Check if agent is background and if user is admin
    config = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    if not config:
        request.session["flash_msg"] = "Agent not found."
        return RedirectResponse(url='/agents', status_code=303)
        
    is_bg = config.get("type") in ("background_agent", "background_script")
    
    if is_bg:
        if not is_admin(request):
            request.session["flash_msg"] = "Admin access required to configure background agents."
            return RedirectResponse(url='/agents', status_code=303)
        identity = Identity(id=agent_name, type=IdentityType.WORKFLOW)
    else:
        identity = Identity.from_string(user['sub'])
        
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)

    current_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, identity, "secrets")
    current_variables = await asyncio.to_thread(identity_mgr.get_identity_config, identity, "variables")
    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    global_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")
    
    required_secrets = await get_agent_required_secrets(config)
    required_variables = await get_agent_required_variables(config)
    
    secrets_updated = False
    variables_updated = False
    
    for key, value in form.items():
        if key in ("csrf_token",):
            continue
            
        val_str = str(value).strip()
        
        if key in required_secrets and key not in global_secrets:
            if val_str:
                current_secrets[key] = val_str
                secrets_updated = True
        elif key in required_variables and key not in global_variables:
            current_variables[key] = val_str
            variables_updated = True
            
    if secrets_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, identity, "secrets", current_secrets)
    if variables_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, identity, "variables", current_variables)
    
    request.session["flash_msg"] = f"Configuration and secrets saved for {agent_name} successfully."
    return RedirectResponse(url='/agents', status_code=303)

@router.post("/agents/{agent_name}/toggle-status")
async def toggle_agent_status(request: Request, agent_name: str):
    if not is_admin(request):
        request.session["flash_msg"] = "Unauthorized access."
        return RedirectResponse(url='/agents', status_code=303)
        
    disabled = identity_mgr.get_disabled_standard_agents()
    if agent_name in disabled:
        disabled.remove(agent_name)
        action = "enabled"
    else:
        disabled.append(agent_name)
        action = "disabled"
        
    identity_mgr.set_disabled_standard_agents(disabled)
    request.session["flash_msg"] = f"Agent '{agent_name}' {action} successfully."
    return RedirectResponse(url='/agents', status_code=303)

@router.get("/tools", response_class=HTMLResponse)
async def tools(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    tools = await discover_tools()
    
    flash_msg = request.session.pop("flash_msg", None)
    
    return templates.TemplateResponse(
        request=request,
        name="tools.html", 
        context={
            "user": user,
            "tools": tools,
            "flash_msg": flash_msg
        }
    )

@router.get("/mcps", response_class=HTMLResponse)
async def mcps_page(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
    mcps = []
    for name in mcp_names:
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, name)
        if config:
            mcps.append(config)
            
    flash_msg = request.session.pop("flash_msg", None)
    admin_access = is_admin(request)
    
    return templates.TemplateResponse(
        request=request,
        name="mcps.html", 
        context={
            "user": user,
            "mcps": mcps,
            "flash_msg": flash_msg,
            "is_admin": admin_access
        }
    )

@router.post("/mcps")
async def add_mcp(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    if not is_admin(request):
        request.session["flash_msg"] = "Admin access required."
        return RedirectResponse(url='/mcps', status_code=303)
        
    form = await request.form()
    
    name = form.get("name")
    transport = form.get("transport", "stdio")
    command = form.get("command")
    args_str = form.get("args", "")
    env_str = form.get("env", "")
    secrets_str = form.get("secrets", "")
    
    if not name or not command:
        request.session["flash_msg"] = "Name and Command are required."
        return RedirectResponse(url='/mcps', status_code=303)
        
    try:
        args = [a.strip() for a in args_str.split(",") if a.strip()]
        env = json.loads(env_str) if env_str.strip() else {}
        secrets = [s.strip() for s in secrets_str.split(",") if s.strip()]
        
        config = {
            "name": name,
            "transport": transport,
            "command": command,
            "args": args,
            "env": env,
            "secrets": secrets
        }
        
        await asyncio.to_thread(identity_mgr.save_mcp_config, name, config)
        request.session["flash_msg"] = f"MCP '{name}' added successfully."
    except Exception as e:
        request.session["flash_msg"] = f"Error adding MCP: {str(e)}"
        
    return RedirectResponse(url='/mcps', status_code=303)

@router.get("/catalog")
async def catalog_redirect():
    return RedirectResponse(url='/')
