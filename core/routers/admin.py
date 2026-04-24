import os
import re
import json
import yaml
import base64
import httpx
import asyncio
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates
from core.auth import IdentityManager
from core.health import HealthMonitor

router = APIRouter()

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)
health_monitor = HealthMonitor(identity_mgr)

GITHUB_REPO = os.getenv("GITHUB_REPO", "") # e.g. user/repo
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

async def commit_to_github(path: str, content: str, message: str) -> bool:
    """Commits a file change to GitHub. Returns True on success, False on failure."""
    if not GITHUB_REPO or not GITHUB_TOKEN:
        print("GitHub integration not configured. Skipping commit.")
        return False
        
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{path}"
    
    try:
        async with httpx.AsyncClient() as client:
            # Get file SHA if it exists
            sha = None
            get_resp = await client.get(url, headers=headers)
            if get_resp.status_code == 200:
                sha = get_resp.json().get("sha")
                
            data = {
                "message": f"{message} [skip ci]",
                "content": base64.b64encode(content.encode()).decode()
            }
            if sha:
                data["sha"] = sha
                
            put_resp = await client.put(url, headers=headers, json=data)
            if put_resp.status_code not in (200, 201):
                print(f"Failed to commit to GitHub: {put_resp.text}")
                return False
            return True
    except Exception as e:
        print(f"Error during GitHub commit: {e}")
        return False

def sanitize_name(name: str) -> str:
    """Sanitize name parameter to prevent path traversal and registry injection."""
    return re.sub(r'[^a-zA-Z0-9_\.-]', '', name)

def require_admin(request: Request, fallback_url: str):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_users = os.getenv("ADMIN_USERS", "").split(",")
    if user.get("email") not in admin_users:
        request.session["flash_msg"] = "Unauthorized access."
        return RedirectResponse(url=fallback_url, status_code=303)
    return None

@router.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    if redirect := require_admin(request, '/'):
        return redirect
    
    user = request.session.get('user')
    
    # Gather global stats
    users = await asyncio.to_thread(identity_mgr.list_all_users)
    keys = await asyncio.to_thread(identity_mgr.list_all_keys)
    agents = await asyncio.to_thread(identity_mgr.list_agents)
    
    # Enhance users with usage stats
    for u in users:
        usage = await asyncio.to_thread(identity_mgr.get_user_usage, u["sub"])
        u["usage"] = usage
        
    # Map keys to user emails for display
    user_email_map = {u["sub"]: u.get("email", "Unknown") for u in users}
    for k in keys:
        k["user_email"] = user_email_map.get(k.get("user_id"), "Unknown User")
        
    flash_msg = request.session.pop("flash_msg", None)
    
    return templates.TemplateResponse(
        request=request,
        name="admin.html", 
        context={
            "user": user,
            "users": users,
            "keys": keys,
            "stats": {
                "total_users": len(users),
                "total_keys": len(keys),
                "total_agents": len(agents)
            },
            "flash_msg": flash_msg
        }
    )

@router.post("/admin/users/toggle_ban")
async def toggle_user_ban(request: Request, user_id: str = Form(...), is_banned: str = Form(...)):
    if redirect := require_admin(request, '/admin'):
        return redirect
        
    should_ban = is_banned.lower() == 'true'
    await asyncio.to_thread(identity_mgr.toggle_user_ban, user_id, should_ban)
    
    status_str = "banned" if should_ban else "unbanned"
    request.session["flash_msg"] = f"User {status_str} successfully."
    return RedirectResponse(url='/admin', status_code=303)

@router.post("/admin/keys/revoke_global")
async def revoke_global_key(request: Request, api_key: str = Form(...)):
    if redirect := require_admin(request, '/admin'):
        return redirect
        
    success = await asyncio.to_thread(identity_mgr.delete_key, api_key)
    if success:
        request.session["flash_msg"] = "Key revoked globally."
    else:
        request.session["flash_msg"] = "Failed to revoke key or key not found."
        
    return RedirectResponse(url='/admin', status_code=303)

@router.get("/editor/{type}/{name}", response_class=HTMLResponse)
async def editor_page(request: Request, type: str, name: str):
    fallback_url = '/agents' if type == 'agent' else '/tools'
    if redirect := require_admin(request, fallback_url):
        return redirect
    
    user = request.session.get('user')
        
    safe_name = sanitize_name(name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid name parameter."
        return RedirectResponse(url='/agents', status_code=303)

    if type == "agent":
        config = await asyncio.to_thread(identity_mgr.get_agent_config, safe_name)
        skills_content = await asyncio.to_thread(identity_mgr.get_agent_skills, safe_name) or ""
        all_agents = await asyncio.to_thread(identity_mgr.list_agents)
        all_tools = await asyncio.to_thread(identity_mgr.list_tools)
        
        if not config:
            request.session["flash_msg"] = "Agent not found."
            return RedirectResponse(url='/agents', status_code=303)
            
        return templates.TemplateResponse(
            request=request,
            name="editor.html", 
            context={
                "user": user,
                "type": type,
                "name": safe_name,
                "config": config,
                "skills_content": skills_content,
                "all_agents": all_agents,
                "all_tools": all_tools
            }
        )
    elif type == "tool":
        config = await asyncio.to_thread(identity_mgr.get_tool_config, safe_name)
        if not config:
            request.session["flash_msg"] = "Tool not found."
    return RedirectResponse(url='/tools', status_code=303)

@router.post("/reset-health/{entity_type}/{name}")
async def reset_health(request: Request, entity_type: str, name: str):
    if entity_type not in ["agent", "tool"]:
        request.session["flash_msg"] = "Invalid entity type."
        return RedirectResponse(url='/', status_code=303)
        
    fallback_url = f'/{entity_type}s'
    if redirect := require_admin(request, fallback_url):
        return redirect
        
    safe_name = sanitize_name(name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid name parameter."
        return RedirectResponse(url=fallback_url, status_code=303)
        
    await asyncio.to_thread(health_monitor.reset_status, entity_type, safe_name)
    
    request.session["flash_msg"] = f"Health status for {entity_type} '{safe_name}' has been reset."
    return RedirectResponse(url=fallback_url, status_code=303)

@router.post("/editor/agent/{name}")
async def save_agent(request: Request, name: str):
    if redirect := require_admin(request, '/agents'):
        return redirect
        
    safe_name = sanitize_name(name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid name parameter."
        return RedirectResponse(url='/agents', status_code=303)
        
    form = await request.form()
    
    # 1. Update etcd immediately
    config = await asyncio.to_thread(identity_mgr.get_agent_config, safe_name) or {"name": safe_name}
    config["model"] = form.get("model")
    config["thinking_level"] = form.get("thinking_level")
    # if it's disabled in UI, it won't be sent, but let's handle lite models correctly
    LITE_MODELS = {"gemini-3.1-flash-lite-preview", "gemini-2.5-flash-lite"}
    if config["model"] and config["model"] in LITE_MODELS:
        config["thinking_level"] = "n/a"
    
    config["version"] = form.get("version")
    config["description"] = form.get("description")
    
    # Handle multiple a2a_access values
    config["a2a_access"] = form.getlist("a2a_access")
    config["allowed_tools"] = form.getlist("allowed_tools")
    skills_content = form.get("skills_content", "")
    
    await asyncio.to_thread(identity_mgr.save_agent_config, safe_name, config)
    await asyncio.to_thread(identity_mgr.save_agent_skills, safe_name, skills_content)
    
    # 2. Sync to GitHub
    agent_dir = f"agents/{safe_name}" if safe_name != "supervisor" else "core/assets/supervisor"
    yaml_content = yaml.dump(config, sort_keys=False)
    
    success_config = await commit_to_github(f"{agent_dir}/config.yaml", yaml_content, f"Update config for {safe_name}")
    success_skills = await commit_to_github(f"{agent_dir}/skills.md", skills_content, f"Update skills for {safe_name}")
    
    if GITHUB_REPO and GITHUB_TOKEN and (not success_config or not success_skills):
        request.session["flash_msg"] = f"Agent {safe_name} updated locally, but GitHub sync failed."
    else:
        request.session["flash_msg"] = f"Agent {safe_name} updated successfully."
        
    return RedirectResponse(url='/agents', status_code=303)

@router.post("/editor/tool/{name}")
async def save_tool(request: Request, name: str):
    if redirect := require_admin(request, '/tools'):
        return redirect
        
    safe_name = sanitize_name(name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid name parameter."
        return RedirectResponse(url='/tools', status_code=303)
        
    form = await request.form()
    
    # 1. Update etcd immediately
    config = await asyncio.to_thread(identity_mgr.get_tool_config, safe_name) or {"name": safe_name}
    config["runtime"] = form.get("runtime")
    config["version"] = form.get("version")
    config["description"] = form.get("description")
    config["entrypoint"] = form.get("entrypoint")
    # Discard form's rel_path, keep existing etcd rel_path to prevent path manipulation
    
    await asyncio.to_thread(identity_mgr.save_tool_config, safe_name, config)
    
    # 2. Sync to GitHub
    if config.get("rel_path"):
        yaml_content = yaml.dump({k:v for k,v in config.items() if k != "rel_path"}, sort_keys=False)
        success = await commit_to_github(f"{config['rel_path']}/tool.yaml", yaml_content, f"Update config for {safe_name}")
        
        if GITHUB_REPO and GITHUB_TOKEN and not success:
            request.session["flash_msg"] = f"Tool {safe_name} updated locally, but GitHub sync failed."
        else:
            request.session["flash_msg"] = f"Tool {safe_name} updated successfully."
    else:
        request.session["flash_msg"] = f"Tool {safe_name} updated successfully."
        
    return RedirectResponse(url='/tools', status_code=303)
