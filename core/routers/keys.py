import asyncio
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, identity_mgr, CSRFRoute

router = APIRouter(route_class=CSRFRoute)

@router.get("/keys", response_class=HTMLResponse)
async def keys_page(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
    
    keys = await asyncio.to_thread(identity_mgr.list_keys, user['sub'])
    flash_msg = request.session.pop("flash_msg", None)
    generated_key = request.session.pop("generated_key", None)
    
    return templates.TemplateResponse(
        request=request,
        name="keys.html", 
        context={
            "user": user,
            "keys": keys,
            "flash_msg": flash_msg,
            "generated_key": generated_key
        }
    )

@router.post("/keys/generate")
async def generate_key(request: Request, key_name: str = Form(..., max_length=50)):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    keys = await asyncio.to_thread(identity_mgr.list_keys, user['sub'])
    if len(keys) >= 5:
        request.session["flash_msg"] = "Maximum number of API keys (5) reached. Please revoke an existing key first."
        return RedirectResponse(url='/keys', status_code=303)
        
    api_key = await asyncio.to_thread(identity_mgr.create_key, user['sub'], key_name)
    request.session["flash_msg"] = f"Key '{key_name}' generated successfully."
    request.session["generated_key"] = api_key
    return RedirectResponse(url='/keys', status_code=303)

@router.post("/keys/revoke")
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
        
    return RedirectResponse(url='/keys', status_code=303)