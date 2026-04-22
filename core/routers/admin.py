import os
import aiofiles
import asyncio
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates

router = APIRouter()

@router.get("/editor/{agent_name}", response_class=HTMLResponse)
async def editor_page(request: Request, agent_name: str):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_users = os.getenv("ADMIN_USERS", "").split(",")
    if user.get("email") not in admin_users:
        request.session["flash_msg"] = "Unauthorized access to editor."
        return RedirectResponse(url='/catalog', status_code=303)
        
    # Sanitize agent_name to prevent path traversal
    safe_agent_name = os.path.basename(agent_name)
    agents_dir = os.path.join(os.path.dirname(__file__), "..", "..", "agents")
    skills_path = os.path.join(agents_dir, safe_agent_name, "skills.md")
    
    # Ensure the path is strictly within agents_dir
    if not os.path.normpath(skills_path).startswith(os.path.normpath(agents_dir)):
        request.session["flash_msg"] = "Invalid agent path."
        return RedirectResponse(url='/catalog', status_code=303)
    
    skills_content = ""
    if await asyncio.to_thread(os.path.exists, skills_path):
        async with aiofiles.open(skills_path, "r") as f:
            skills_content = await f.read()
            
    return templates.TemplateResponse("editor.html", {
        "request": request,
        "agent_name": safe_agent_name,
        "skills_content": skills_content
    })

@router.post("/editor/{agent_name}")
async def save_skills(request: Request, agent_name: str, skills_content: str = Form(...)):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_users = os.getenv("ADMIN_USERS", "").split(",")
    if user.get("email") not in admin_users:
        request.session["flash_msg"] = "Unauthorized access to editor."
        return RedirectResponse(url='/catalog', status_code=303)
        
    # Sanitize agent_name to prevent path traversal
    safe_agent_name = os.path.basename(agent_name)
    agents_dir = os.path.join(os.path.dirname(__file__), "..", "..", "agents")
    agent_dir = os.path.join(agents_dir, safe_agent_name)
    
    # Ensure the path is strictly within agents_dir
    if not os.path.normpath(agent_dir).startswith(os.path.normpath(agents_dir)):
        request.session["flash_msg"] = "Invalid agent path."
        return RedirectResponse(url='/catalog', status_code=303)
    
    if not await asyncio.to_thread(os.path.exists, agent_dir):
        request.session["flash_msg"] = "Agent not found."
        return RedirectResponse(url='/catalog', status_code=303)
        
    skills_path = os.path.join(agent_dir, "skills.md")
    async with aiofiles.open(skills_path, "w") as f:
        await f.write(skills_content)
        
    request.session["flash_msg"] = f"Skills for {safe_agent_name} updated successfully."
    return RedirectResponse(url='/catalog', status_code=303)