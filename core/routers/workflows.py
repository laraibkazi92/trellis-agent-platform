import json
import asyncio
import yaml
from typing import Dict, Any, List, Optional, Literal
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, ValidationError
from core.auth import get_current_user, is_admin
from core.dependencies import templates, identity_mgr, CSRFRoute
from core.routers.admin import sanitize_name, commit_to_github
from core.discovery import get_agent_required_secrets, get_agent_required_variables

from datetime import datetime

class TriggerUpdate(BaseModel):
    trigger_type: Literal["none", "cron", "webhook"] = "none"
    cron_expression: Optional[str] = None
    webhook_provider: Optional[str] = None
    webhook_secret: Optional[str] = None

class AgentUpdateModel(TriggerUpdate):
    model: str
    thinking_level: str
    version: Optional[str] = ""
    description: Optional[str] = ""
    a2a_access: List[str] = []
    allowed_tools: List[str] = []
    allowed_mcps: List[str] = []
    skills_content: Optional[str] = ""

class ScriptUpdateModel(TriggerUpdate):
    pass

router = APIRouter(tags=["Workflows"], route_class=CSRFRoute)

@router.get("/workflows", response_class=HTMLResponse)
async def workflows_view(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")
        
    agent_names = await asyncio.to_thread(identity_mgr.list_agents)
    disabled_agents = identity_mgr.get_disabled_agents()
    global_secrets = await asyncio.to_thread(identity_mgr.get_global_secrets)
    global_variables = await asyncio.to_thread(identity_mgr.get_global_variables)
    
    workflows_list = []
    for name in agent_names:
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if config_data and config_data.get("type") in ("agent", "script"):
            status = "disabled" if name in disabled_agents else "active"
            skills_content = await asyncio.to_thread(identity_mgr.get_agent_skills, name) or ""
            
            required_secrets = await get_agent_required_secrets(config_data)
            required_variables = await get_agent_required_variables(config_data)
            is_configured = True
            missing_secrets = []
            missing_variables = []
            
            user_required_secrets = [s for s in required_secrets if s not in global_secrets]
            user_required_variables = [s for s in required_variables if s not in global_variables]
            
            svc_variables = await asyncio.to_thread(identity_mgr.get_user_variables, f"svc_agent_{name}")
            
            if user_required_secrets:
                svc_secrets = await asyncio.to_thread(identity_mgr.get_user_secrets, f"svc_agent_{name}")
                for s in user_required_secrets:
                    if s not in svc_secrets:
                        is_configured = False
                        missing_secrets.append(s)
                        
            if user_required_variables:
                for s in user_required_variables:
                    if s not in svc_variables:
                        is_configured = False
                        missing_variables.append(s)
            
            workflows_list.append({
                "name": name,
                "config": config_data,
                "skills": skills_content,
                "status": status,
                "required_secrets": user_required_secrets,
                "missing_secrets": missing_secrets,
                "required_variables": user_required_variables,
                "missing_variables": missing_variables,
                "current_variables": svc_variables,
                "is_configured": is_configured,
                "run_stats": {
                    "pending": 0,
                    "processing": 0,
                    "failed": 0,
                    "completed": 0
                },
                "is_running": False
            })

    workflows_list.sort(key=lambda x: x["name"].lower())
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

    # Taskiq queue observability
    queue = {
        "pending": [],
        "processing": [],
        "completed": [],
        "failed": []
    }
    for w_item in workflows_list:
        w_name = w_item["name"]
        agent_runs = await asyncio.to_thread(identity_mgr.get_agent_runs, w_name)
        for run in agent_runs:
            state = run.get("state")
            if state in queue:
                queue[state].append(run)
                w_item["run_stats"][state] += 1
                
        if w_item["run_stats"]["processing"] > 0:
            w_item["is_running"] = True

    return templates.TemplateResponse(
        request=request,
        name="background_workflows.html",
        context={
            "user": user,
            "workflows_list": workflows_list,
            "all_agents": agent_names,
            "all_tools": all_tools_data,
            "all_mcps": all_mcps,
            "is_admin": is_admin(request),
            "queue": queue
        }
    )

@router.post("/workflows/{agent_name}/configure-secrets")
async def configure_background_agent_secrets(request: Request, agent_name: str):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login')
        
    if not is_admin(request):
        request.session["flash_msg"] = "Admin access required to configure workflows."
        return RedirectResponse(url='/workflows', status_code=303)
        
    form = await request.form()
    
    config = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    if not config or config.get("type") not in ("agent", "script"):
        request.session["flash_msg"] = "Workflow not found."
        return RedirectResponse(url='/workflows', status_code=303)
        
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
    return RedirectResponse(url='/workflows', status_code=303)

@router.post("/workflows/{agent_name}/run")
async def run_background_agent_manual(request: Request, agent_name: str):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login')
        
    if not is_admin(request):
        request.session["flash_msg"] = "Admin access required to run workflows."
        return RedirectResponse(url='/workflows', status_code=303)
        
    safe_name = sanitize_name(agent_name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid agent name parameter."
        return RedirectResponse(url='/workflows', status_code=303)
        
    config = await asyncio.to_thread(identity_mgr.get_agent_config, safe_name)
    if not config or config.get("type") not in ("agent", "script"):
        request.session["flash_msg"] = "Workflow not found."
        return RedirectResponse(url='/workflows', status_code=303)
        
    # Deferred import to prevent potential circular dependency during startup
    from core.tasks import run_background_agent, run_background_script
    
    now = datetime.now()
    xml_payload = f"<event_payload><![CDATA[\nManual execution triggered at {now.isoformat()}\n]]></event_payload>"
    
    if config.get("type") == "script":
        task = await run_background_script.kiq(
            agent_name=safe_name,
            prompt=xml_payload,
            user_id=f"svc_agent_{safe_name}"
        )
    else:
        task = await run_background_agent.kiq(
            agent_name=safe_name,
            prompt=xml_payload,
            user_id=f"svc_agent_{safe_name}"
        )
    
    try:
        await asyncio.to_thread(
            identity_mgr.record_agent_run_state,
            safe_name,
            task.task_id,
            "pending",
            {"prompt": xml_payload, "user_id": f"svc_agent_{safe_name}"}
        )
    except Exception as e:
        print(f"Failed to record pending state for {safe_name}: {e}")
    
    request.session["flash_msg"] = f"Task for '{safe_name}' has been successfully enqueued for execution."
    return RedirectResponse(url='/workflows', status_code=303)

@router.post("/workflows/config")
async def update_background_trigger(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")
        
    is_admin_user = is_admin(request)
    if not is_admin_user:
        request.session["flash_msg"] = "Unauthorized access."
        return RedirectResponse(url='/workflows', status_code=303)

    form = await request.form()
    agent_name = form.get("agent_name", "")
    safe_name = sanitize_name(agent_name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid agent name parameter."
        return RedirectResponse(url='/workflows', status_code=303)
        
    config_data = await asyncio.to_thread(identity_mgr.get_agent_config, safe_name) or {"name": safe_name}
    workflow_type = config_data.get("type", "agent")
    
    if workflow_type not in ("agent", "script"):
        return RedirectResponse(url="/workflows", status_code=303)

    # Extract form data into a dictionary for Pydantic
    form_dict = {}
    for key in form.keys():
        if key in ["a2a_access", "allowed_tools", "allowed_mcps"]:
            form_dict[key] = form.getlist(key)
        else:
            form_dict[key] = form.get(key)
            
    try:
        if workflow_type == "script":
            validated_data = ScriptUpdateModel(**form_dict)
        else:
            validated_data = AgentUpdateModel(**form_dict)
    except ValidationError as e:
        request.session["flash_msg"] = f"Validation error: {e.errors()[0]['msg']}"
        return RedirectResponse(url='/workflows', status_code=303)
    
    # Process Trigger Settings
    if validated_data.trigger_type and validated_data.trigger_type != "none":
        trigger = {"type": validated_data.trigger_type}
        if validated_data.trigger_type == "cron" and validated_data.cron_expression:
            parts = [p.strip() for p in validated_data.cron_expression.split('|') if p.strip()]
            trigger["expression"] = parts if len(parts) > 1 else (parts[0] if parts else "")
        elif validated_data.trigger_type == "webhook":
            trigger["provider"] = validated_data.webhook_provider or "generic"
            trigger["secret"] = validated_data.webhook_secret or "secret"
        config_data["trigger"] = trigger
    elif validated_data.trigger_type == "none" and "trigger" in config_data:
        del config_data["trigger"]

    skills_content = ""
    # Process Agent-specific Settings
    if workflow_type == "agent":
        config_data["model"] = validated_data.model
        config_data["thinking_level"] = validated_data.thinking_level
        
        LITE_MODELS = {"gemini-3.1-flash-lite-preview", "gemini-2.5-flash-lite"}
        if config_data.get("model") in LITE_MODELS:
            config_data["thinking_level"] = "n/a"
            
        config_data["version"] = validated_data.version
        config_data["description"] = validated_data.description
        config_data["a2a_access"] = validated_data.a2a_access
        config_data["allowed_tools"] = validated_data.allowed_tools
        config_data["allowed_mcps"] = validated_data.allowed_mcps
        skills_content = validated_data.skills_content or ""
        
        await asyncio.to_thread(identity_mgr.save_agent_skills, safe_name, skills_content)
    
    await asyncio.to_thread(identity_mgr.save_agent_config, safe_name, config_data)
    
    # Sync to GitHub
    agent_dir = f"workspace/workflows/{safe_name}"
    yaml_content = yaml.dump(config_data, sort_keys=False)
    
    success_config = await commit_to_github(f"{agent_dir}/config.yaml", yaml_content, f"Update config for {safe_name}")
    if workflow_type == "agent":
        success_skills = await commit_to_github(f"{agent_dir}/skills.md", skills_content, f"Update skills for {safe_name}")
        
    return RedirectResponse(url="/workflows", status_code=303)
