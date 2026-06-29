import json
import os
import asyncio
import secrets as secrets_module
import yaml
from typing import Dict, Any, List, Optional, Literal
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, ValidationError
from core.auth import get_current_user, is_admin
from core.dependencies import templates, identity_mgr, CSRFRoute
from core.routers.admin import sanitize_name, commit_to_github
from core.discovery import get_agent_required_secrets, get_agent_required_variables
from core.models import Identity, IdentityType

from datetime import datetime

_REDIS_QUEUE_NAME = "taskiq"

async def _dequeue_pending_task_from_redis(task_id: str) -> bool:
    """Remove a pending task from the Redis queue by task_id.

    Returns True if removed, False if not found or on error.
    Only pending tasks (not yet picked up by a worker) will be in the queue.
    """
    try:
        import redis.asyncio as aioredis
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        client = aioredis.from_url(redis_url, decode_responses=True)
        lua_script = """
local items = redis.call('LRANGE', KEYS[1], 0, -1)
for _, item in ipairs(items) do
    local ok, data = pcall(cjson.decode, item)
    if ok and data['task_id'] == ARGV[1] then
        redis.call('LREM', KEYS[1], 1, item)
        return 1
    end
end
return 0
"""
        try:
            result = await client.eval(lua_script, 1, _REDIS_QUEUE_NAME, task_id)
            return bool(result)
        finally:
            await client.aclose()
    except Exception as e:
        print(f"Redis dequeue failed for task {task_id}: {e}")
        return False

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
    disabled_workflows = identity_mgr.get_disabled_workflows()
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)
    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    global_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")
    
    workflows_list = []
    for name in agent_names:
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if config_data and config_data.get("type") in ("background_agent", "background_script"):
            # Determine configuration status
            required_secrets = await get_agent_required_secrets(config_data)
            required_variables = await get_agent_required_variables(config_data)
            
            is_configured = True
            missing_secrets = []
            missing_variables = []
            
            # We filter out globals from required
            user_required_secrets = [s for s in required_secrets if s not in global_secrets]
            user_required_variables = [s for s in required_variables if s not in global_variables]
            
            agent_identity = Identity(id=name, type=IdentityType.WORKFLOW)
            current_config_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, agent_identity, "secrets")
            current_config_variables = await asyncio.to_thread(identity_mgr.get_identity_config, agent_identity, "variables")

            if user_required_secrets:
                for s in user_required_secrets:
                    if s not in current_config_secrets:
                        is_configured = False
                        missing_secrets.append(s)
            
            if user_required_variables:
                for v in user_required_variables:
                    if v not in current_config_variables:
                        is_configured = False
                        missing_variables.append(v)
            
            workflows_list.append({
                "name": name,
                "config": config_data,
                "status": "Disabled by Admin" if name in disabled_workflows else "active",
                "is_disabled": name in disabled_workflows,
                "description": config_data.get("description", ""),
                "trigger": config_data.get("trigger", {}),
                "is_configured": is_configured,
                "required_secrets": user_required_secrets,
                "required_variables": user_required_variables,
                "missing_secrets": missing_secrets,
                "missing_variables": missing_variables,
                "current_variables": current_config_variables,
                "is_running": False,
                "run_stats": {
                    "pending": 0,
                    "processing": 0,
                    "completed": 0,
                    "failed": 0
                }
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
        request.session["flash_msg"] = "Admin access required."
        return RedirectResponse(url='/workflows', status_code=303)

    form = await request.form()
    
    config = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    if not config:
        request.session["flash_msg"] = f"Agent {agent_name} not found."
        return RedirectResponse(url='/workflows', status_code=303)
        
    agent_identity = Identity(id=agent_name, type=IdentityType.WORKFLOW)
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)

    current_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, agent_identity, "secrets")
    current_variables = await asyncio.to_thread(identity_mgr.get_identity_config, agent_identity, "variables")
    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    global_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")
    
    required_secrets = await get_agent_required_secrets(config)
    required_variables = await get_agent_required_variables(config)
    
    secrets_updated = False
    variables_updated = False
    
    for key, value in form.items():
        if key in ("csrf_token",):
            continue
            
        val_str = str(value).strip()
        
        if key in required_secrets and key not in global_secrets:
            if val_str: # only update secret if not empty
                current_secrets[key] = val_str
                secrets_updated = True
        elif key in required_variables and key not in global_variables:
            current_variables[key] = val_str
            variables_updated = True
                
    if secrets_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, agent_identity, "secrets", current_secrets)
    if variables_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, agent_identity, "variables", current_variables)
    
    request.session["flash_msg"] = f"Configuration for {agent_name} saved successfully."
    return RedirectResponse(url='/workflows', status_code=303)

@router.post("/workflows/{agent_name}/runs/{run_id}/cancel")
async def cancel_background_run(request: Request, agent_name: str, run_id: str):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login')
        
    if not is_admin(request):
        request.session["flash_msg"] = "Admin access required to cancel workflows."
        return RedirectResponse(url='/workflows', status_code=303)

    safe_name = sanitize_name(agent_name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid agent name parameter."
        return RedirectResponse(url='/workflows', status_code=303)
        
    try:
        # Get current run state
        runs = await asyncio.to_thread(identity_mgr.get_agent_runs, safe_name)
        run_record = next((r for r in runs if r.get("run_id") == run_id), None)
        
        if not run_record:
            request.session["flash_msg"] = f"Run {run_id} not found."
            return RedirectResponse(url='/workflows', status_code=303)
            
        current_state = run_record.get("state")
        
        # Only allow cancelling if pending or processing
        if current_state not in ("pending", "processing"):
            request.session["flash_msg"] = f"Cannot cancel run in state: {current_state}."
            return RedirectResponse(url='/workflows', status_code=303)
            
        metadata = run_record.get("metadata", {})
        metadata["cancelled_by"] = user.id
        metadata["cancelled_at"] = datetime.now().isoformat()

        wrote = await asyncio.to_thread(
            identity_mgr.record_agent_run_state,
            safe_name,
            run_id,
            "cancelled",
            metadata
        )

        # Best-effort: remove from Redis queue if it hasn't been picked up yet
        if current_state == "pending":
            await _dequeue_pending_task_from_redis(run_id)

        if wrote:
            request.session["flash_msg"] = f"Run {run_id} for '{safe_name}' has been cancelled."
        else:
            request.session["flash_msg"] = f"Run {run_id} for '{safe_name}' is already in a terminal state."
    except Exception as e:
        print(f"Error cancelling run: {e}")
        request.session["flash_msg"] = f"Failed to cancel run: {str(e)}"

    return RedirectResponse(url='/workflows', status_code=303)

@router.post("/workflows/{agent_name}/runs/clear-active")
async def clear_agent_active_runs(request: Request, agent_name: str):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login')
        
    if not is_admin(request):
        request.session["flash_msg"] = "Admin access required."
        return RedirectResponse(url='/workflows', status_code=303)

    safe_name = sanitize_name(agent_name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid agent name parameter."
        return RedirectResponse(url='/workflows', status_code=303)
        
    cleared_count = 0
    error_count = 0
    try:
        runs = await asyncio.to_thread(identity_mgr.get_agent_runs, safe_name)
        pending_run_ids = []
        etcd_tasks = []
        for run_record in runs:
            state = run_record.get("state")
            if state in ("pending", "processing"):
                run_id = run_record.get("run_id")
                metadata = run_record.get("metadata", {})
                metadata["cancelled_by"] = user.id
                metadata["cancelled_at"] = datetime.now().isoformat()
                metadata["reason"] = "Mass cleared by admin"
                etcd_tasks.append(
                    asyncio.to_thread(
                        identity_mgr.record_agent_run_state,
                        safe_name,
                        run_id,
                        "cancelled",
                        metadata
                    )
                )
                if state == "pending":
                    pending_run_ids.append(run_id)

        if etcd_tasks:
            results = await asyncio.gather(*etcd_tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    error_count += 1
                    print(f"Error cancelling run for {safe_name}: {r}")
                elif r:
                    cleared_count += 1

        # Best-effort: remove pending tasks from Redis queue
        if pending_run_ids:
            await asyncio.gather(
                *[_dequeue_pending_task_from_redis(rid) for rid in pending_run_ids],
                return_exceptions=True
            )

        if error_count:
            request.session["flash_msg"] = f"Cleared {cleared_count} run(s) for '{safe_name}' ({error_count} failed)."
        else:
            request.session["flash_msg"] = f"Successfully cleared {cleared_count} active run(s) for '{safe_name}'."
    except Exception as e:
        print(f"Error clearing active runs for {safe_name}: {e}")
        request.session["flash_msg"] = f"Failed to clear runs: {str(e)}"

    return RedirectResponse(url='/workflows', status_code=303)

@router.post("/workflows/runs/clear-all-active")
async def clear_all_active_runs(request: Request):
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login')
        
    if not is_admin(request):
        request.session["flash_msg"] = "Admin access required."
        return RedirectResponse(url='/workflows', status_code=303)

    cleared_count = 0
    error_count = 0
    try:
        agent_names = await asyncio.to_thread(identity_mgr.list_agents)
        pending_run_ids = []
        etcd_tasks = []
        for name in agent_names:
            config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
            if config_data and config_data.get("type") in ("background_agent", "background_script"):
                runs = await asyncio.to_thread(identity_mgr.get_agent_runs, name)
                for run_record in runs:
                    state = run_record.get("state")
                    if state in ("pending", "processing"):
                        run_id = run_record.get("run_id")
                        metadata = run_record.get("metadata", {})
                        metadata["cancelled_by"] = user.id
                        metadata["cancelled_at"] = datetime.now().isoformat()
                        metadata["reason"] = "Global mass cleared by admin"
                        etcd_tasks.append(
                            asyncio.to_thread(
                                identity_mgr.record_agent_run_state,
                                name,
                                run_id,
                                "cancelled",
                                metadata
                            )
                        )
                        if state == "pending":
                            pending_run_ids.append(run_id)

        if etcd_tasks:
            results = await asyncio.gather(*etcd_tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    error_count += 1
                    print(f"Error cancelling run (global clear): {r}")
                elif r:
                    cleared_count += 1

        # Best-effort: remove pending tasks from Redis queue
        if pending_run_ids:
            await asyncio.gather(
                *[_dequeue_pending_task_from_redis(rid) for rid in pending_run_ids],
                return_exceptions=True
            )

        if error_count:
            request.session["flash_msg"] = f"Cleared {cleared_count} run(s) across all workflows ({error_count} failed)."
        else:
            request.session["flash_msg"] = f"Successfully cleared {cleared_count} active run(s) across all workflows."
    except Exception as e:
        print(f"Error clearing all active runs: {e}")
        request.session["flash_msg"] = f"Failed to globally clear runs: {str(e)}"

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
    if not config or config.get("type") not in ("background_agent", "background_script"):
        request.session["flash_msg"] = "Workflow not found."
        return RedirectResponse(url='/workflows', status_code=303)
        
    # Deferred import to prevent potential circular dependency during startup
    from core.tasks import run_background_agent, run_background_script
    
    now = datetime.now()
    xml_payload = f"<event_payload><![CDATA[\nManual execution triggered at {now.isoformat()}\n]]></event_payload>"
    
    agent_identity = Identity(id=safe_name, type=IdentityType.WORKFLOW)
    
    if config.get("type") == "background_script":
        task = await run_background_script.kiq(
            agent_name=safe_name,
            prompt=xml_payload,
            user_id=agent_identity.to_legacy_string()
        )
    else:
        task = await run_background_agent.kiq(
            agent_name=safe_name,
            prompt=xml_payload,
            user_id=agent_identity.to_legacy_string()
        )
    
    try:
        await asyncio.to_thread(
            identity_mgr.record_agent_run_state,
            safe_name,
            task.task_id,
            "pending",
            {"prompt": xml_payload, "user_id": agent_identity.to_legacy_string()}
        )
    except Exception as e:
        print(f"Failed to record pending state for {safe_name}: {e}")
    
    request.session["flash_msg"] = f"Task for '{safe_name}' has been successfully enqueued for execution."
    return RedirectResponse(url='/workflows', status_code=303)

@router.post("/workflows/{agent_name}/toggle-status")
async def toggle_workflow_status(request: Request, agent_name: str):
    if not is_admin(request):
        request.session["flash_msg"] = "Unauthorized access."
        return RedirectResponse(url='/workflows', status_code=303)
        
    disabled = identity_mgr.get_disabled_workflows()
    if agent_name in disabled:
        disabled.remove(agent_name)
        action = "enabled"
    else:
        disabled.append(agent_name)
        action = "disabled"
        
    identity_mgr.set_disabled_workflows(disabled)
    request.session["flash_msg"] = f"Workflow '{agent_name}' {action} successfully."
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
    workflow_type = config_data.get("type", "background_agent")
    
    if workflow_type not in ("background_agent", "background_script"):
        return RedirectResponse(url="/workflows", status_code=303)

    # Extract form data into a dictionary for Pydantic
    form_dict = {}
    for key in form.keys():
        if key in ["a2a_access", "allowed_tools", "allowed_mcps"]:
            form_dict[key] = form.getlist(key)
        else:
            form_dict[key] = form.get(key)
            
    try:
        if workflow_type == "background_script":
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
            webhook_secret = validated_data.webhook_secret or secrets_module.token_hex(32)
            trigger["secret"] = webhook_secret
            if not validated_data.webhook_secret:
                request.session["flash_msg"] = (
                    f"No webhook secret provided — a random secret was generated: {webhook_secret}  "
                    f"Copy this value and configure it in your webhook provider."
                )
        config_data["trigger"] = trigger
    elif validated_data.trigger_type == "none" and "trigger" in config_data:
        del config_data["trigger"]

    skills_content = ""
    # Process Agent-specific Settings
    if workflow_type == "background_agent":
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
    if workflow_type == "background_agent":
        success_skills = await commit_to_github(f"{agent_dir}/skills.md", skills_content, f"Update skills for {safe_name}")
        
    return RedirectResponse(url="/workflows", status_code=303)
