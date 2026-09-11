import os
import json
import asyncio
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, identity_mgr, CSRFRoute
from core.discovery import discover_agents, discover_tools, get_agent_required_secrets, get_agent_required_variables, get_agent_secret_groups, get_tool_configuration_context, flatten_secret_group_keys
from core.auth import is_admin
from core.health import evaluate_health_status
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
        # This is an operational view of whether an agent is currently usable, so it
        # shows the same cooldown-aware status (e.g. "Half-Open") that routing decisions
        # actually honor, rather than the raw "Offline" discover_agents() returns.
        agent["health"] = evaluate_health_status(agent.get("health") or {})

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
    secret_groups = await get_agent_secret_groups(config)
    grouped_secret_keys = flatten_secret_group_keys(secret_groups)

    secrets_updated = False
    variables_updated = False

    for key, value in form.items():
        if key in ("csrf_token",):
            continue

        val_str = str(value).strip()

        if (key in required_secrets or key in grouped_secret_keys) and key not in global_secrets:
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
    user_id = user.get('sub')

    # Publicly-exposed local tools are callable directly via the MCP gateway/supervisor's
    # search_tools/use_tool (see __spec_docs/direct_tool_gateway_execution_spec.md) —
    # highlight them and let the user configure their own credentials right here, since
    # they're no longer necessarily reachable only through an agent's "Configure Agent"
    # flow. Scoped to local tools only: MCP-sourced tools are whitelisted per-server via
    # `public`/`public_tools` and their credentials are configured at the server level.
    direct_access_tools = [t for t in tools if t.get("public") and not t.get("is_mcp")]
    for tool in direct_access_tools:
        context = await get_tool_configuration_context(tool["name"], user_id)
        if context:
            tool.update(context)

    flash_msg = request.session.pop("flash_msg", None)

    return templates.TemplateResponse(
        request=request,
        name="tools.html",
        context={
            "user": user,
            "tools": tools,
            "direct_access_tools": direct_access_tools,
            "flash_msg": flash_msg
        }
    )

@router.post("/tools/{tool_name}/configure")
async def configure_tool_secrets(request: Request, tool_name: str):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')

    config = await asyncio.to_thread(identity_mgr.get_tool_config, tool_name)
    if not config or config.get("public") is not True:
        request.session["flash_msg"] = "Tool not found or not directly configurable."
        return RedirectResponse(url='/tools', status_code=303)

    user_id = user['sub']
    context = await get_tool_configuration_context(tool_name, user_id)
    if not context:
        request.session["flash_msg"] = "Tool not found or not directly configurable."
        return RedirectResponse(url='/tools', status_code=303)

    form = await request.form()
    identity = Identity.from_string(user_id)

    current_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, identity, "secrets")
    current_variables = await asyncio.to_thread(identity_mgr.get_identity_config, identity, "variables")

    known_secrets = (
        set(context["required_secrets"])
        | set(context["optional_secrets"])
        | flatten_secret_group_keys(config.get("secret_groups") or [])
    )
    known_variables = set(context["required_variables"])

    secrets_updated = False
    variables_updated = False

    for key, value in form.items():
        if key == "csrf_token":
            continue

        val_str = str(value).strip()

        if key in known_secrets:
            if val_str:  # only update secret if not empty
                current_secrets[key] = val_str
                secrets_updated = True
        elif key in known_variables:
            current_variables[key] = val_str
            variables_updated = True

    if secrets_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, identity, "secrets", current_secrets)
    if variables_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, identity, "variables", current_variables)

    request.session["flash_msg"] = f"Configuration and secrets saved for {tool_name} successfully."
    return RedirectResponse(url='/tools', status_code=303)

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
