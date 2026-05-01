import json
import asyncio
from typing import Dict, Any, List
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from core.auth import get_current_user, get_identity_mgr
from core.background.queue import EtcdQueue

router = APIRouter(tags=["Background Agents"])
templates = Jinja2Templates(directory="templates")
queue = EtcdQueue()

@router.get("/background-agents", response_class=HTMLResponse)
async def background_agents_view(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")
        
    identity_mgr = get_identity_mgr()
    app_config = await asyncio.to_thread(identity_mgr.get_app_config)
    
    agent_names = await asyncio.to_thread(identity_mgr.list_agents)
    disabled_agents = identity_mgr.get_disabled_agents()
    
    background_agents = []
    for name in agent_names:
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if config_data and config_data.get("type") == "background":
            status = "disabled" if name in disabled_agents else "active"
            background_agents.append({
                "name": name,
                "config": config_data,
                "status": status
            })

    # Fetch Queue observability data
    # (Since this is UI, let's fetch directly from etcd to get the live snapshot)
    pending_tasks = []
    processing_tasks = []
    completed_tasks = []
    failed_tasks = []
    
    for val, meta in identity_mgr.client.get_prefix("/queue/pending/"):
        pending_tasks.append({"id": meta.key.decode('utf-8').split('/')[-1], "payload": json.loads(val.decode('utf-8'))})
    for val, meta in identity_mgr.client.get_prefix("/queue/processing/"):
        processing_tasks.append({"id": meta.key.decode('utf-8').split('/')[-1], "payload": json.loads(val.decode('utf-8'))})
    for val, meta in identity_mgr.client.get_prefix("/queue/completed/"):
        # Just getting the last few completed
        completed_tasks.append({"id": meta.key.decode('utf-8').split('/')[-1], "payload": json.loads(val.decode('utf-8'))})
    for val, meta in identity_mgr.client.get_prefix("/queue/failed/"):
        failed_tasks.append({"id": meta.key.decode('utf-8').split('/')[-1], "payload": json.loads(val.decode('utf-8'))})

    return templates.TemplateResponse("background_agents.html", {
        "request": request,
        "user": user,
        "app_name": app_config.get("APP_NAME", "Marketplace"),
        "app_logo_url": app_config.get("APP_LOGO_URL", ""),
        "app_favicon_url": app_config.get("APP_FAVICON_URL", ""),
        "app_accent_color": app_config.get("APP_ACCENT_COLOR", "#0ea5e9"),
        "app_accent_color_dark": app_config.get("APP_ACCENT_COLOR_DARK", "#38bdf8"),
        "background_agents": background_agents,
        "queue": {
            "pending": pending_tasks,
            "processing": processing_tasks,
            "completed": completed_tasks[-10:], # last 10
            "failed": failed_tasks[-10:]
        }
    })

@router.post("/background-agents/config")
async def update_background_trigger(
    request: Request,
    agent_name: str = Form(...),
    trigger_type: str = Form(...),
    cron_expression: str = Form(None),
    webhook_provider: str = Form(None),
    webhook_secret: str = Form(None)
):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")
        
    identity_mgr = get_identity_mgr()
    config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    
    if config_data and config_data.get("type") == "background":
        trigger = {"type": trigger_type}
        if trigger_type == "cron" and cron_expression:
            trigger["expression"] = cron_expression
        elif trigger_type == "webhook":
            trigger["provider"] = webhook_provider or "generic"
            trigger["secret"] = webhook_secret or "secret"
            
        config_data["trigger"] = trigger
        await asyncio.to_thread(identity_mgr.save_agent_config, agent_name, config_data)
        
    return RedirectResponse(url="/background-agents", status_code=303)
