import json
import asyncio
import yaml
from typing import Dict, Any, List
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.auth import get_current_user, is_admin
from core.dependencies import templates, identity_mgr, CSRFRoute
from core.routers.admin import sanitize_name, commit_to_github
from core.discovery import get_agent_required_secrets, get_agent_required_variables

router = APIRouter(tags=["Background Agents"])

@router.get("/background-agents", response_class=HTMLResponse)
async def background_agents_view(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")
        
    agent_names = await asyncio.to_thread(identity_mgr.list_agents)
    disabled_agents = identity_mgr.get_disabled_agents()
    global_secrets = await asyncio.to_thread(identity_mgr.get_global_secrets)
    global_variables = await asyncio.to_thread(identity_mgr.get_global_variables)
    
    background_agents = []
    for name in agent_names:
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if config_data and config_data.get("type") == "background":
            status = "disabled" if name in disabled_agents else "active"
            skills_content = await asyncio.to_thread(identity_mgr.get_agent_skills, name) or ""
            
            required_secrets = await get_agent_required_secrets(config_data)
            required_variables = await get_agent_required_variables(config_data)
            is_configured = True
            missing_secrets = []
            missing_variables = []
            
            user_required_secrets = [s for s in required_secrets if s not in global_secrets]
            user_required_variables = [s for s in required_variables if s not in global_variables]
            
            if user_required_secrets:
                svc_secrets = await asyncio.to_thread(identity_mgr.get_user_secrets, f"svc_agent_{name}")
                for s in user_required_secrets:
                    if s not in svc_secrets:
                        is_configured = False
                        missing_secrets.append(s)
                        
            if user_required_variables:
                svc_variables = await asyncio.to_thread(identity_mgr.get_user_variables, f"svc_agent_{name}")
                for s in user_required_variables:
                    if s not in svc_variables:
                        is_configured = False
                        missing_variables.append(s)
            
            background_agents.append({
                "name": name,
                "config": config_data,
                "skills": skills_content,
                "status": status,
                "required_secrets": user_required_secrets,
                "missing_secrets": missing_secrets,
                "required_variables": user_required_variables,
                "missing_variables": missing_variables,
                "is_configured": is_configured
            })

    background_agents.sort(key=lambda x: x["name"].lower())
    all_mcps = await asyncio.to_thread(identity_mgr.list_mcps)
    # Fetch all tools for configuration modal
    all_tools_data = []
    local_tool_configs = await asyncio.to_thread(identity_mgr.get_all_tool_configs)
    mcp_configs = await asyncio.to_thread(identity_mgr.get_all_mcp_configs)
    
    for t_name, t_config in local_tool_configs.items():
        all_tools_data.append({
            "name": t_name, 
            "type": "local", 
            "source": "Hub",
            "version": t_config.get("version", ""),
            "description": t_config.get("description", "")
        })
        
    for mcp_name, mcp_config in mcp_configs.items():
        if mcp_config and "tools" in mcp_config:
            for t in mcp_config["tools"]:
                all_tools_data.append({
                    "name": t.get("name", ""), 
                    "type": "mcp", 
                    "source": mcp_name,
                    "version": t.get("version", ""),
                    "description": t.get("description", "")
                })
                
    all_tools_data.sort(key=lambda x: x["name"])

    # Taskiq queue observability can be added here later.
    # For now, returning empty sets to preserve UI template.
    return templates.TemplateResponse(
        request=request,
        name="background_agents.html",
        context={
            "user": user,
            "background_agents": background_agents,
            "all_agents": agent_names,
            "all_tools": all_tools_data,
            "all_mcps": all_mcps,
            "is_admin": is_admin(request),
            "queue": {
                "pending": [],
                "processing": [],
                "completed": [],
                "failed": []
            }
        }
    )

@router.post("/background-agents/{agent_name}/configure-secrets")
async def configure_background_agent_secrets(request: Request, agent_name: str):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login')
        
    if not is_admin(request):
        request.session["flash_msg"] = "Admin access required to configure background agents."
        return RedirectResponse(url='/background-agents', status_code=303)
        
    form = await request.form()
    
    config = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    if not config or config.get("type") != "background":
        request.session["flash_msg"] = "Background agent not found."
        return RedirectResponse(url='/background-agents', status_code=303)
        
    target_user_id = f"svc_agent_{agent_name}"
        
    current_secrets = await asyncio.to_thread(identity_mgr.get_user_secrets, target_user_id)
    global_secrets = await asyncio.to_thread(identity_mgr.get_global_secrets)
    current_variables = await asyncio.to_thread(identity_mgr.get_user_variables, target_user_id)
    global_variables = await asyncio.to_thread(identity_mgr.get_global_variables)
    
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
        await asyncio.to_thread(identity_mgr.save_user_secrets, target_user_id, current_secrets)
    if variables_updated:
        await asyncio.to_thread(identity_mgr.save_user_variables, target_user_id, current_variables)
    
    request.session["flash_msg"] = f"Configuration and secrets saved for {agent_name} successfully."
    return RedirectResponse(url='/background-agents', status_code=303)

@router.post("/background-agents/config")
async def update_background_trigger(
    request: Request,
    agent_name: str = Form(...),
    trigger_type: str = Form(None),
    cron_expression: str = Form(None),
    webhook_provider: str = Form(None),
    webhook_secret: str = Form(None)
):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")
        
    is_admin_user = is_admin(request)
    safe_name = sanitize_name(agent_name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid agent name parameter."
        return RedirectResponse(url='/background-agents', status_code=303)
        
    config_data = await asyncio.to_thread(identity_mgr.get_agent_config, safe_name) or {"name": safe_name}
    
    # Trigger update (allowed for any authenticated user? Or only admin? Prompt says "we need to implement all the configuration options available, but ONLY for an admin user". So if non-admin can't configure trigger either, we should block them. Actually the user said "entire configure" should be hidden. So we block non-admins entirely).
    if not is_admin_user:
        request.session["flash_msg"] = "Unauthorized access."
        return RedirectResponse(url='/background-agents', status_code=303)
        
    form = await request.form()
    
    if config_data.get("type") == "background":
        if trigger_type and trigger_type != "none":
            trigger = {"type": trigger_type}
            if trigger_type == "cron" and cron_expression:
                trigger["expression"] = cron_expression
            elif trigger_type == "webhook":
                trigger["provider"] = webhook_provider or "generic"
                trigger["secret"] = webhook_secret or "secret"
            config_data["trigger"] = trigger
        elif trigger_type == "none" and "trigger" in config_data:
            del config_data["trigger"]

        config_data["model"] = form.get("model")
        config_data["thinking_level"] = form.get("thinking_level")
        
        LITE_MODELS = {"gemini-3.1-flash-lite-preview", "gemini-2.5-flash-lite"}
        if config_data.get("model") in LITE_MODELS:
            config_data["thinking_level"] = "n/a"
            
        config_data["version"] = form.get("version")
        config_data["description"] = form.get("description")
        config_data["a2a_access"] = form.getlist("a2a_access")
        config_data["allowed_tools"] = form.getlist("allowed_tools")
        config_data["allowed_mcps"] = form.getlist("allowed_mcps")
        skills_content = form.get("skills_content", "")

        await asyncio.to_thread(identity_mgr.save_agent_config, safe_name, config_data)
        await asyncio.to_thread(identity_mgr.save_agent_skills, safe_name, skills_content)
        
        # Sync to GitHub
        agent_dir = f"background_agents/{safe_name}"
        yaml_content = yaml.dump(config_data, sort_keys=False)
        
        success_config = await commit_to_github(f"{agent_dir}/config.yaml", yaml_content, f"Update config for {safe_name}")
        success_skills = await commit_to_github(f"{agent_dir}/skills.md", skills_content, f"Update skills for {safe_name}")
        
    return RedirectResponse(url="/background-agents", status_code=303)
