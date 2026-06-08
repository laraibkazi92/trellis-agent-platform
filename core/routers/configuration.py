import asyncio
from typing import Dict, List
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, identity_mgr, CSRFRoute
from core.models import Identity, IdentityType

router = APIRouter(route_class=CSRFRoute)

@router.get("/secrets")
async def secrets_redirect():
    """Redirect legacy /secrets URL to /configuration."""
    return RedirectResponse(url='/configuration', status_code=301)

@router.post("/secrets")
async def secrets_post_redirect():
    """Redirect legacy /secrets POST to /configuration."""
    return RedirectResponse(url='/configuration', status_code=307)

@router.get("/configuration", response_class=HTMLResponse)
async def configuration_page(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    user_id = user['sub']
    
    # 1. Gather all required secrets and variables from registered tools and MCPs
    tool_names = await asyncio.to_thread(identity_mgr.list_tools)
    mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
    required_secrets: Dict[str, List[str]] = {}
    required_variables: Dict[str, List[str]] = {}
    
    for name in tool_names:
        config = await asyncio.to_thread(identity_mgr.get_tool_config, name)
        if config:
            secrets_data = config.get("secrets", [])
            if isinstance(secrets_data, dict):
                secrets_list = list(secrets_data.get("general", [])) + list(secrets_data.get("user", []))
            else:
                secrets_list = secrets_data

            if secrets_list:
                for secret_key in secrets_list:
                    if secret_key not in required_secrets:
                        required_secrets[secret_key] = []
                    required_secrets[secret_key].append(f"Tool: {name}")

            vars_data = config.get("variables", [])
            if isinstance(vars_data, dict):
                vars_list = list(vars_data.get("general", [])) + list(vars_data.get("user", []))
            else:
                vars_list = vars_data

            if vars_list:
                for var_key in vars_list:
                    if var_key not in required_variables:
                        required_variables[var_key] = []
                    required_variables[var_key].append(f"Tool: {name}")

    for name in mcp_names:
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, name)
        if config:
            secrets_data = config.get("secrets", [])
            if isinstance(secrets_data, dict):
                secrets_list = list(secrets_data.get("general", [])) + list(secrets_data.get("user", []))
            else:
                secrets_list = secrets_data

            if secrets_list:
                for secret_key in secrets_list:
                    if secret_key not in required_secrets:
                        required_secrets[secret_key] = []
                    required_secrets[secret_key].append(f"MCP: {name}")

            vars_data = config.get("variables", [])
            if isinstance(vars_data, dict):
                vars_list = list(vars_data.get("general", [])) + list(vars_data.get("user", []))
            else:
                vars_list = vars_data

            if vars_list:
                for var_key in vars_list:
                    if var_key not in required_variables:
                        required_variables[var_key] = []
                    required_variables[var_key].append(f"MCP: {name}")
                
    # 2. Get current user/global secrets and variables
    user_identity = Identity.from_string(user_id)
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)

    current_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, user_identity, "secrets")
    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    current_variables = await asyncio.to_thread(identity_mgr.get_identity_config, user_identity, "variables")
    global_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")
    
    # 3. Compile unified configuration items (filtering out system-wide overridden globals)
    items = []
    
    # Process variables
    for var_key, tools in required_variables.items():
        if var_key not in global_variables:
            items.append({
                "key": var_key,
                "type": "variable",
                "label": "Variable",
                "tools": tools,
                "is_global": False,
                "value": current_variables.get(var_key, ''),
                "placeholder": f"Enter {var_key}"
            })
            
    # Process secrets
    for secret_key, tools in required_secrets.items():
        if secret_key not in global_secrets:
            items.append({
                "key": secret_key,
                "type": "secret",
                "label": "Secret",
                "tools": tools,
                "is_global": False,
                "value": "",  # Secrets are masked from display
                "placeholder": "******** (leave blank to keep current)" if secret_key in current_secrets else f"Enter {secret_key}"
            })
            
    # Sort items alphabetically by key name
    items.sort(key=lambda x: x["key"].lower())
    
    flash_msg = request.session.pop("flash_msg", None)
    
    return templates.TemplateResponse(
        request=request,
        name="configuration.html",
        context={
            "user": user,
            "items": items,
            "flash_msg": flash_msg
        }
    )

@router.post("/configuration")
async def save_configuration(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    user_id = user['sub']
    form = await request.form()
    
    tool_names = await asyncio.to_thread(identity_mgr.list_tools)
    mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
    known_secrets = set()
    known_variables = set()
    
    for name in tool_names:
        config = await asyncio.to_thread(identity_mgr.get_tool_config, name)
        if config:
            secrets_data = config.get("secrets", [])
            if isinstance(secrets_data, dict):
                known_secrets.update(secrets_data.get("general", []))
                known_secrets.update(secrets_data.get("user", []))
            elif isinstance(secrets_data, list):
                known_secrets.update(secrets_data)

            vars_data = config.get("variables", [])
            if isinstance(vars_data, dict):
                known_variables.update(vars_data.get("general", []))
                known_variables.update(vars_data.get("user", []))
            elif isinstance(vars_data, list):
                known_variables.update(vars_data)

    for name in mcp_names:
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, name)
        if config:
            secrets_data = config.get("secrets", [])
            if isinstance(secrets_data, dict):
                known_secrets.update(secrets_data.get("general", []))
                known_secrets.update(secrets_data.get("user", []))
            elif isinstance(secrets_data, list):
                known_secrets.update(secrets_data)

            vars_data = config.get("variables", [])
            if isinstance(vars_data, dict):
                known_variables.update(vars_data.get("general", []))
                known_variables.update(vars_data.get("user", []))
            elif isinstance(vars_data, list):
                known_variables.update(vars_data)
    
    user_identity = Identity.from_string(user_id)
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)

    current_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, user_identity, "secrets")
    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    current_variables = await asyncio.to_thread(identity_mgr.get_identity_config, user_identity, "variables")
    global_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")
    
    secrets_updated = False
    variables_updated = False
    
    for key, value in form.items():
        if key in ("csrf_token",):
            continue
            
        val_str = str(value).strip()
        
        if key in known_secrets and key not in global_secrets:
            if val_str: # only update secret if not empty
                current_secrets[key] = val_str
                secrets_updated = True
                
        elif key in known_variables and key not in global_variables:
            # For variables, we can save empty value if they clear it
            current_variables[key] = val_str
            variables_updated = True
            
    if secrets_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, user_identity, "secrets", current_secrets)
    if variables_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, user_identity, "variables", current_variables)
    
    request.session["flash_msg"] = "Settings and configuration saved successfully."
    return RedirectResponse(url='/configuration', status_code=303)
