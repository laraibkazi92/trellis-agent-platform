import asyncio
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, identity_mgr, CSRFRoute
from core.discovery import discover_agents, discover_tools

router = APIRouter(route_class=CSRFRoute)

@router.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
    
    user_id = user['sub']
    
    # Fetch usage metrics
    global_usage = await asyncio.to_thread(identity_mgr.get_user_usage, user_id)
    agent_usage = await asyncio.to_thread(identity_mgr.get_user_agent_usage, user_id)
    tool_usage = await asyncio.to_thread(identity_mgr.get_user_tool_usage, user_id)
    
    # Discover agents and tools to count how many were created by this user
    all_agents = await discover_agents()
    all_tools = await discover_tools()
    
    # Assuming author is matched against user email or name
    user_email = user.get("email", "")
    agents_created = len([a for a in all_agents if a.get("author") == user_email])
    tools_created = len([t for t in all_tools if t.get("author") == user_email])
    
    keys = await asyncio.to_thread(identity_mgr.list_keys, user_id)
    
    flash_msg = request.session.pop("flash_msg", None)
    generated_key = request.session.pop("generated_key", None)
    active_tab = request.query_params.get("tab", "details")
    
    return templates.TemplateResponse(
        request=request,
        name="profile.html", 
        context={
            "user": user,
            "keys": keys,
            "flash_msg": flash_msg,
            "generated_key": generated_key,
            "global_usage": global_usage,
            "agent_usage": agent_usage,
            "tool_usage": tool_usage,
            "agents_created": agents_created,
            "tools_created": tools_created,
            "active_tab": active_tab
        }
    )

@router.post("/profile/keys/generate")
async def generate_key(request: Request, key_name: str = Form(..., max_length=50)):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    keys = await asyncio.to_thread(identity_mgr.list_keys, user['sub'])
    if len(keys) >= 5:
        request.session["flash_msg"] = "Maximum number of API keys (5) reached. Please revoke an existing key first."
        return RedirectResponse(url='/profile?tab=keys', status_code=303)
        
    api_key = await asyncio.to_thread(identity_mgr.create_key, user['sub'], key_name)
    request.session["flash_msg"] = f"Key '{key_name}' generated successfully."
    request.session["generated_key"] = api_key
    return RedirectResponse(url='/profile?tab=keys', status_code=303)

@router.post("/profile/keys/revoke")
async def revoke_key(request: Request, key_id: str = Form(...)):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    # Verify the key belongs to the user before deleting
    keys = await asyncio.to_thread(identity_mgr.list_keys, user['sub'])
    if any(k.get("key_id") == key_id for k in keys):
        success = await asyncio.to_thread(identity_mgr.delete_key_by_id, key_id)
        if success:
            request.session["flash_msg"] = "Key revoked successfully."
        else:
            request.session["flash_msg"] = "Failed to revoke key."
    else:
        request.session["flash_msg"] = "Invalid key or unauthorized to revoke."
        
    return RedirectResponse(url='/profile?tab=keys', status_code=303)
