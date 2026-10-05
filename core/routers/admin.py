# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
import re
import json
import yaml
import base64
import httpx
import asyncio
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, CSRFRoute
from core.auth import get_identity_manager
from core.health import HealthMonitor
from core.models import Identity, IdentityType, is_agent_internal, coerce_bool_flag, ALLOWED_PROVIDERS
from core.rules_engine import RULES_EVALUATION_TIMEOUT as RULES_EVALUATION_TIMEOUT_DEFAULT

router = APIRouter(route_class=CSRFRoute)

identity_mgr = get_identity_manager()
health_monitor = HealthMonitor(identity_mgr)

GITHUB_REPO = os.getenv("GITHUB_REPO", "") # e.g. user/repo
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

async def commit_to_github(path: str, content: str, message: str, client: httpx.AsyncClient = None) -> bool:
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
        if client:
            get_resp = await client.get(url, headers=headers)
        else:
            async with httpx.AsyncClient(timeout=10.0) as local_client:
                get_resp = await local_client.get(url, headers=headers)

        sha = None
        if get_resp.status_code == 200:
            sha = get_resp.json().get("sha")
            
        data = {
            "message": f"{message} [skip ci]",
            "content": base64.b64encode(content.encode()).decode()
        }
        if sha:
            data["sha"] = sha
            
        if client:
            put_resp = await client.put(url, headers=headers, json=data)
        else:
            async with httpx.AsyncClient(timeout=10.0) as local_client:
                put_resp = await local_client.put(url, headers=headers, json=data)
                
        if put_resp.status_code not in (200, 201):
            print(f"Failed to commit to GitHub: {put_resp.text}")
            return False
        return True
    except Exception as e:
        print(f"Error during GitHub commit: {e}")
        return False

def sanitize_name(name: str) -> str:
    """Sanitize name parameter to prevent path traversal and registry injection."""
    return re.sub(r'[^a-zA-Z0-9_-]', '', name)

def require_admin(request: Request, fallback_url: str):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_users = [u.strip() for u in os.getenv("ADMIN_USERS", "").split(",") if u.strip()]
    if user.get("email") not in admin_users:
        request.session["flash_msg"] = "Unauthorized access."
        return RedirectResponse(url=fallback_url, status_code=303)
    return None

@router.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    if redirect := require_admin(request, '/'):
        return redirect
    
    user = request.session.get('user')
    
    # Gather global stats concurrently
    users, keys, agents = await asyncio.gather(
        asyncio.to_thread(identity_mgr.list_all_users),
        asyncio.to_thread(identity_mgr.list_all_keys),
        asyncio.to_thread(identity_mgr.list_agents)
    )
    
    # Enhance users with usage stats concurrently, limiting concurrency
    sem = asyncio.Semaphore(10)
    async def fetch_usage(u):
        async with sem:
            user_id = u.get("sub") or u.get("id") or u.get("user_id")
            if not user_id:
                # Fallback for legacy or malformed records
                u["usage"] = {"input_tokens": 0, "output_tokens": 0, "total_requests": 0}
                return
            u["usage"] = await asyncio.to_thread(identity_mgr.get_user_usage, user_id)
        
    await asyncio.gather(*(fetch_usage(u) for u in users))
        
    # Map keys to user emails for display
    user_email_map = {}
    for u in users:
        uid = u.get("sub") or u.get("id") or u.get("user_id")
        if uid:
            user_email_map[uid] = u.get("email", "Unknown")
    for k in keys:
        k["user_email"] = user_email_map.get(k.get("user_id"), "Unknown User")
        
    flash_msg = request.session.pop("flash_msg", None)

    agent_memory_enabled = await asyncio.to_thread(identity_mgr.get_agent_memory_enabled)
    agent_memory_isolated = await asyncio.to_thread(identity_mgr.get_agent_memory_isolated_per_user)
    rules_evaluation_timeout_override = await asyncio.to_thread(identity_mgr.get_rules_evaluation_timeout)

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
            "feature_flags": {
                "agent_memory_enabled": agent_memory_enabled,
                "agent_memory_isolated_per_user": agent_memory_isolated,
            },
            "rules_engine": {
                "timeout_override": rules_evaluation_timeout_override,
                "timeout_default": RULES_EVALUATION_TIMEOUT_DEFAULT,
                "effective_timeout": (
                    rules_evaluation_timeout_override
                    if rules_evaluation_timeout_override is not None
                    else RULES_EVALUATION_TIMEOUT_DEFAULT
                ),
            },
            "flash_msg": flash_msg
        }
    )

@router.post("/admin/feature-flags/agent-memory")
async def toggle_agent_memory_flag(request: Request, enabled: str = Form(...)):
    if redirect := require_admin(request, '/admin'):
        return redirect

    should_enable = enabled.lower() == 'true'
    await asyncio.to_thread(identity_mgr.set_agent_memory_enabled, should_enable)

    state_str = "enabled" if should_enable else "disabled"
    request.session["flash_msg"] = f"Agent Memory {state_str} globally. Changes take effect within ~20 seconds."
    return RedirectResponse(url='/admin', status_code=303)

@router.post("/admin/feature-flags/agent-memory-isolation")
async def toggle_agent_memory_isolation(request: Request, enabled: str = Form(...)):
    if redirect := require_admin(request, '/admin'):
        return redirect

    should_enable = enabled.lower() == 'true'
    await asyncio.to_thread(identity_mgr.set_agent_memory_isolated_per_user, should_enable)

    state_str = "enabled" if should_enable else "disabled"
    request.session["flash_msg"] = (
        f"Per-user memory isolation {state_str}. New memories use per-user banks "
        "(agent:userid); background runs key by workflow identity; existing "
        "shared banks are not migrated."
    )
    return RedirectResponse(url='/admin', status_code=303)

@router.post("/admin/rules-engine/timeout")
async def set_rules_evaluation_timeout(request: Request, timeout_seconds: str = Form(...)):
    if redirect := require_admin(request, '/admin'):
        return redirect

    raw = timeout_seconds.strip()
    if raw == "":
        # Empty submission means "reset to default".
        await asyncio.to_thread(identity_mgr.clear_rules_evaluation_timeout)
        request.session["flash_msg"] = (
            f"Rules Engine timeout reset to the default ({RULES_EVALUATION_TIMEOUT_DEFAULT}s). "
            "Changes take effect within ~30 seconds."
        )
        return RedirectResponse(url='/admin', status_code=303)

    try:
        value = float(raw)
    except ValueError:
        request.session["flash_msg"] = f"Invalid timeout value '{raw}' — must be a number."
        return RedirectResponse(url='/admin', status_code=303)

    if not (0.1 <= value <= 30.0):
        request.session["flash_msg"] = "Timeout must be between 0.1 and 30.0 seconds."
        return RedirectResponse(url='/admin', status_code=303)

    await asyncio.to_thread(identity_mgr.set_rules_evaluation_timeout, value)
    request.session["flash_msg"] = f"Rules Engine timeout set to {value}s. Changes take effect within ~30 seconds."
    return RedirectResponse(url='/admin', status_code=303)

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
async def revoke_global_key(request: Request, key_id: str = Form(...)):
    if redirect := require_admin(request, '/admin'):
        return redirect
        
    success = await asyncio.to_thread(identity_mgr.delete_key_by_id, key_id)
    if success:
        request.session["flash_msg"] = "Key revoked globally."
    else:
        request.session["flash_msg"] = "Failed to revoke key or key not found."
        
    return RedirectResponse(url='/admin', status_code=303)

@router.get("/admin/secrets")
async def admin_secrets_redirect():
    """Redirect legacy /admin/secrets URL to /admin/configuration."""
    return RedirectResponse(url='/admin/configuration', status_code=301)

@router.post("/admin/secrets")
async def admin_secrets_post_redirect():
    """Redirect legacy /admin/secrets POST to /admin/configuration."""
    return RedirectResponse(url='/admin/configuration', status_code=307)

@router.post("/admin/secrets/delete")
async def admin_secrets_delete_redirect():
    """Redirect legacy /admin/secrets/delete POST to /admin/configuration/delete."""
    return RedirectResponse(url='/admin/configuration/delete', status_code=307)

@router.get("/admin/configuration", response_class=HTMLResponse)
async def admin_configuration_page(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    user = request.session.get('user')
    
    # Gather all required secrets and variables across all tools/MCPs
    tool_names = await asyncio.to_thread(identity_mgr.list_tools)
    mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
    required_secrets = {}
    required_variables = {}
    
    for name in tool_names:
        config = await asyncio.to_thread(identity_mgr.get_tool_config, name)
        if config:
            secrets_data = config.get("secrets", [])
            if isinstance(secrets_data, dict):
                secrets_list = list(secrets_data.get("general", [])) + list(secrets_data.get("user", []))
            else:
                secrets_list = secrets_data

            if secrets_list:
                for s in secrets_list:
                    if s not in required_secrets: required_secrets[s] = []
                    required_secrets[s].append(f"Tool: {name}")

            vars_data = config.get("variables", [])
            if isinstance(vars_data, dict):
                vars_list = list(vars_data.get("general", [])) + list(vars_data.get("user", []))
            else:
                vars_list = vars_data

            if vars_list:
                for v in vars_list:
                    if v not in required_variables: required_variables[v] = []
                    required_variables[v].append(f"Tool: {name}")
                
    for name in mcp_names:
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, name)
        if config:
            secrets_data = config.get("secrets", [])
            if isinstance(secrets_data, dict):
                secrets_list = list(secrets_data.get("general", [])) + list(secrets_data.get("user", []))
            else:
                secrets_list = secrets_data

            if secrets_list:
                for s in secrets_list:
                    if s not in required_secrets: required_secrets[s] = []
                    required_secrets[s].append(f"MCP: {name}")

            vars_data = config.get("variables", [])
            if isinstance(vars_data, dict):
                vars_list = list(vars_data.get("general", [])) + list(vars_data.get("user", []))
            else:
                vars_list = vars_data

            if vars_list:
                for v in vars_list:
                    if v not in required_variables: required_variables[v] = []
                    required_variables[v].append(f"MCP: {name}")

    system_identity = Identity(id="system", type=IdentityType.SYSTEM)
    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    global_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")
    
    items = []
    
    # Process variables
    for var_key, tools in required_variables.items():
        items.append({
            "key": var_key,
            "type": "variable",
            "label": "Variable",
            "tools": tools,
            "is_global": var_key in global_variables,
            "value": global_variables.get(var_key, ''),
            "placeholder": f"Enter global {var_key}"
        })
        
    # Process secrets
    for secret_key, tools in required_secrets.items():
        items.append({
            "key": secret_key,
            "type": "secret",
            "label": "Secret",
            "tools": tools,
            "is_global": secret_key in global_secrets,
            "value": "",
            "placeholder": "******** (leave blank to keep current)" if secret_key in global_secrets else f"Enter global {secret_key}"
        })
        
    items.sort(key=lambda x: x["key"].lower())
    
    flash_msg = request.session.pop("flash_msg", None)

    return templates.TemplateResponse(
        request=request,
        name="admin_configuration.html",
        context={
            "user": user,
            "items": items,
            "flash_msg": flash_msg
        }
    )

@router.post("/admin/configuration")
async def save_admin_configuration(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

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
                
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)
    current_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    current_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")
    
    secrets_updated = False
    variables_updated = False
    
    for key, value in form.items():
        if key in ("csrf_token",):
            continue
            
        val_str = str(value).strip()
        
        if key in known_secrets:
            if val_str: # only update secret if not empty
                current_secrets[key] = val_str
                secrets_updated = True
        elif key in known_variables:
            if val_str:
                current_variables[key] = val_str
                variables_updated = True
            elif key in current_variables:
                del current_variables[key]
                variables_updated = True
            
    if secrets_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, system_identity, "secrets", current_secrets)
    if variables_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, system_identity, "variables", current_variables)
    
    request.session["flash_msg"] = "Global configurations and secrets saved successfully."
    return RedirectResponse(url='/admin/configuration', status_code=303)

@router.post("/admin/configuration/delete")
async def delete_admin_configuration_key(request: Request, secret_key: str = Form(...)):
    if redirect := require_admin(request, '/admin'):
        return redirect
        
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)
    current_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    current_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")
    
    if secret_key in current_secrets:
        del current_secrets[secret_key]
        await asyncio.to_thread(identity_mgr.save_identity_config, system_identity, "secrets", current_secrets)
        request.session["flash_msg"] = f"Global secret '{secret_key}' removed."
    elif secret_key in current_variables:
        del current_variables[secret_key]
        await asyncio.to_thread(identity_mgr.save_identity_config, system_identity, "variables", current_variables)
        request.session["flash_msg"] = f"Global variable '{secret_key}' removed."
        
    return RedirectResponse(url='/admin/configuration', status_code=303)

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
        all_agent_configs = await asyncio.to_thread(identity_mgr.get_all_agent_configs)
        internal_agents = {n: cfg.get("internal", True) for n, cfg in all_agent_configs.items()}
        a2a_dependents = [
            n for n, cfg in all_agent_configs.items()
            if n != safe_name and safe_name in (cfg.get("a2a_access") or [])
        ]

        all_tools_data = []
        # Bulk fetch all tools and MCPs
        local_tool_configs = await asyncio.to_thread(identity_mgr.get_all_tool_configs)
        mcp_configs = await asyncio.to_thread(identity_mgr.get_all_mcp_configs)
        
        # Local Tools
        for t_name, t_config in local_tool_configs.items():
            all_tools_data.append({
                "name": t_name, 
                "type": "local", 
                "source": "Hub",
                "version": t_config.get("version", ""),
                "description": t_config.get("description", "")
            })
            
        # MCP Tools
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
        all_tools = all_tools_data
        all_mcps = await asyncio.to_thread(identity_mgr.list_mcps)
        
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
                "internal_agents": internal_agents,
                "a2a_dependents": a2a_dependents,
                "all_tools": all_tools,
                "all_mcps": all_mcps
            }
        )
    elif type == "tool":
        config = await asyncio.to_thread(identity_mgr.get_tool_config, safe_name)
        if not config:
            request.session["flash_msg"] = "Tool not found."
            return RedirectResponse(url='/tools', status_code=303)
        return templates.TemplateResponse(
            request=request,
            name="editor.html", 
            context={
                "user": user,
                "type": type,
                "name": safe_name,
                "config": config
            }
        )
    elif type == "mcp":
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, safe_name)
        if not config:
            request.session["flash_msg"] = "MCP not found."
            return RedirectResponse(url='/mcps', status_code=303)
        return templates.TemplateResponse(
            request=request,
            name="editor.html", 
            context={
                "user": user,
                "type": type,
                "name": safe_name,
                "config": config
            }
        )
    return RedirectResponse(url='/admin', status_code=303)

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

    # Multi-provider support: empty provider means "infer from the model name".
    provider = (form.get("provider") or "").strip().lower()
    if provider and provider not in ALLOWED_PROVIDERS:
        request.session["flash_msg"] = (
            f"Invalid provider '{provider}'. Must be one of: {', '.join(ALLOWED_PROVIDERS)}."
        )
        return RedirectResponse(url=f'/editor/agent/{safe_name}', status_code=303)
    config["provider"] = provider or None
    config["base_url"] = (form.get("base_url") or "").strip() or None
    
    config["version"] = form.get("version")
    config["description"] = form.get("description")
    # Checkboxes: only present in form when checked. A hidden "_submitted" sentinel
    # (always present when this form is actually submitted from editor.html) lets us
    # distinguish a deliberate browser uncheck from a raw/scripted POST that never
    # included these newer fields at all -- the latter must preserve the agent's
    # existing value rather than silently flipping it to False.
    if "external_submitted" in form:
        config["external"] = form.get("external") == "true"
    else:
        config["external"] = coerce_bool_flag(config.get("external"), True)

    if "internal_submitted" in form:
        config["internal"] = form.get("internal") == "true"
    else:
        config["internal"] = coerce_bool_flag(config.get("internal"), True)

    # Handle multiple a2a_access values, filtering out targets with internal: False
    # (prevents misconfiguration even if bypassed via raw POST).
    all_agent_configs = await asyncio.to_thread(identity_mgr.get_all_agent_configs)
    config["a2a_access"] = [
        target for target in form.getlist("a2a_access")
        if is_agent_internal(all_agent_configs.get(target, {}))
    ]
    config["allowed_tools"] = form.getlist("allowed_tools")
    config["allowed_mcps"] = form.getlist("allowed_mcps")
    # Checkbox: only present in form when checked.
    config["agent_memory"] = form.get("agent_memory") == "true"
    skills_content = form.get("skills_content", "")
    
    await asyncio.to_thread(identity_mgr.save_agent_config, safe_name, config)
    await asyncio.to_thread(identity_mgr.save_agent_skills, safe_name, skills_content)
    
    # 2. Sync to GitHub
    agent_dir = f"agents/{safe_name}" if safe_name != "supervisor" else "core/assets/supervisor"
    yaml_content = yaml.dump(config, sort_keys=False)
    
    client = getattr(request.app.state, "http_client", None)
    
    success_config = await commit_to_github(f"{agent_dir}/config.yaml", yaml_content, f"Update config for {safe_name}", client=client)
    success_skills = await commit_to_github(f"{agent_dir}/skills.md", skills_content, f"Update skills for {safe_name}", client=client)
    
    if GITHUB_REPO and GITHUB_TOKEN and (not success_config or not success_skills):
        request.session["flash_msg"] = f"Agent {safe_name} updated locally, but GitHub sync failed."
    else:
        request.session["flash_msg"] = f"Agent {safe_name} updated successfully."
        
    return RedirectResponse(url='/agents', status_code=303)

@router.post("/editor/mcp/{name}")
async def save_mcp(request: Request, name: str):
    if redirect := require_admin(request, '/mcps'):
        return redirect
        
    safe_name = sanitize_name(name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid name parameter."
        return RedirectResponse(url='/mcps', status_code=303)
        
    form = await request.form()
    
    config = await asyncio.to_thread(identity_mgr.get_mcp_config, safe_name) or {"name": safe_name}
    config["transport"] = form.get("transport")
    config["command"] = form.get("command")
    
    args_str = form.get("args", "")
    config["args"] = [a.strip() for a in args_str.split(",") if a.strip()] if args_str else []
    
    env_str = form.get("env", "")
    if env_str:
        try:
            config["env"] = json.loads(env_str)
        except:
            pass
    else:
        config["env"] = {}
            
    secrets_str = form.get("secrets", "")
    config["secrets"] = [s.strip() for s in secrets_str.split(",") if s.strip()] if secrets_str else []
    
    await asyncio.to_thread(identity_mgr.save_mcp_config, safe_name, config)
    
    # Sync to GitHub
    yaml_content = yaml.dump(config, sort_keys=False)
    client = getattr(request.app.state, "http_client", None)
    success = await commit_to_github(f"mcps/{safe_name}/mcp.yaml", yaml_content, f"Update config for MCP {safe_name}", client=client)
    
    if GITHUB_REPO and GITHUB_TOKEN and not success:
        request.session["flash_msg"] = f"MCP {safe_name} updated locally, but GitHub sync failed."
    else:
        request.session["flash_msg"] = f"MCP {safe_name} updated successfully."
        
    return RedirectResponse(url='/mcps', status_code=303)

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
        client = getattr(request.app.state, "http_client", None)
        success = await commit_to_github(f"{config['rel_path']}/tool.yaml", yaml_content, f"Update config for {safe_name}", client=client)
        
        if GITHUB_REPO and GITHUB_TOKEN and not success:
            request.session["flash_msg"] = f"Tool {safe_name} updated locally, but GitHub sync failed."
        else:
            request.session["flash_msg"] = f"Tool {safe_name} updated successfully."
    else:
        request.session["flash_msg"] = f"Tool {safe_name} updated successfully."
        
    return RedirectResponse(url='/tools', status_code=303)
