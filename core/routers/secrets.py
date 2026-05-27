import asyncio
from typing import Dict, List
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, identity_mgr

router = APIRouter()

@router.get("/secrets", response_class=HTMLResponse)
async def secrets_page(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    user_id = user['sub']
    
    # 1. Gather all required secrets from registered tools and MCPs
    tool_names = await asyncio.to_thread(identity_mgr.list_tools)
    mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
    required_secrets: Dict[str, List[str]] = {}
    
    for name in tool_names:
        config = await asyncio.to_thread(identity_mgr.get_tool_config, name)
        if config and config.get("secrets"):
            for secret_key in config.get("secrets", []):
                if secret_key not in required_secrets:
                    required_secrets[secret_key] = []
                required_secrets[secret_key].append(f"Tool: {name}")

    for name in mcp_names:
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, name)
        if config and config.get("secrets"):
            for secret_key in config.get("secrets", []):
                if secret_key not in required_secrets:
                    required_secrets[secret_key] = []
                required_secrets[secret_key].append(f"MCP: {name}")
                
    # 2. Get current user secrets and global secrets
    current_secrets = await asyncio.to_thread(identity_mgr.get_user_secrets, user_id)
    global_secrets = await asyncio.to_thread(identity_mgr.get_global_secrets)
    
    flash_msg = request.session.pop("flash_msg", None)
    
    return templates.TemplateResponse(
        request=request,
        name="secrets.html",
        context={
            "user": user,
            "required_secrets": required_secrets,
            "current_secrets": current_secrets,
            "global_secrets": global_secrets,
            "flash_msg": flash_msg
        }
    )

@router.post("/secrets")
async def save_secrets(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    user_id = user['sub']
    form = await request.form()
    
    # We only want to save keys that the user actually submitted, but it's simpler
    # to update the existing dictionary so we don't wipe out secrets not currently displayed.
    current_secrets = await asyncio.to_thread(identity_mgr.get_user_secrets, user_id)
    global_secrets = await asyncio.to_thread(identity_mgr.get_global_secrets)
    
    for key, value in form.items():
        if key in global_secrets:
            continue # Skip updating if admin manages this
        if value.strip(): # only update if not empty
            current_secrets[key] = value.strip()
            
    await asyncio.to_thread(identity_mgr.save_user_secrets, user_id, current_secrets)
    
    request.session["flash_msg"] = "Secrets saved successfully."
    return RedirectResponse(url='/secrets', status_code=303)
