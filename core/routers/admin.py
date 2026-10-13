# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
import re
import json
import yaml
import asyncio
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, CSRFRoute
from core.auth import get_identity_manager
from core.health import HealthMonitor
from core.llm_factory import LLM_PROVIDER_KEY_NAMES
from core.models import Identity, IdentityType, is_agent_internal, coerce_bool_flag, ALLOWED_PROVIDERS
from core.rules_engine import (
    RULES_EVALUATION_TIMEOUT as RULES_EVALUATION_TIMEOUT_DEFAULT,
    RULES_EVALUATION_MODEL as RULES_EVALUATION_MODEL_DEFAULT,
    RULES_EVALUATION_PROVIDER as RULES_EVALUATION_PROVIDER_DEFAULT,
    RULES_EVALUATION_BASE_URL as RULES_EVALUATION_BASE_URL_DEFAULT,
    RULES_CONFIDENCE_THRESHOLD as RULES_CONFIDENCE_THRESHOLD_DEFAULT,
)
from core import tunables
from core.workspace_io import delete_repo_path, write_repo_file

router = APIRouter(route_class=CSRFRoute)

identity_mgr = get_identity_manager()
health_monitor = HealthMonitor(identity_mgr)

# Display metadata for the "Limits & Tuning" card (name -> (label, help text)); the
# authoritative registry (env var, default, type) lives in core/tunables.py.
_TUNABLE_LABELS = {
    "max_run_output_chars": ("Max Run Output Chars", "Stdout/stderr stored per workflow run (characters)."),
    "max_run_error_chars": ("Max Run Error Chars", "Error trace stored per workflow run (characters)."),
    "tool_execution_timeout": ("Tool Execution Timeout", "Seconds before a hub tool subprocess is killed."),
    "tool_search_limit": ("Tool Search Limit", "Max tools returned by search_tools."),
    "agent_search_limit": ("Agent Search Limit", "Max agents returned by search_agents."),
    "health_failure_threshold": ("Health Failure Threshold", "Consecutive failures before an entity trips to Offline."),
    "health_cooldown_seconds": ("Health Cooldown", "Seconds before an Offline entity is probed (Half-Open)."),
    "registry_refresh_timeout": ("Registry Refresh Timeout", "Bounded wait (seconds) for an on-demand supervisor snapshot refresh."),
    "registry_snapshot_ttl": ("Registry Snapshot TTL", "Seconds between background supervisor eligibility snapshot refreshes."),
    "agent_embedding_model": ("Agent Embedding Model", "Model used to embed agents for semantic search."),
    "public_host_url": ("Public Host URL", "Base URL shown for the REST/host API."),
    "public_mcp_url": ("Public MCP URL", "MCP endpoint URL shown for the gateway."),
}

_EMBEDDING_MODEL_WARNING = (
    "Changing this invalidates previously stored embeddings — agents must be "
    "re-embedded (rebuild / registry sync) before semantic search works again."
)

# Framework-level LLM provider API keys, managed under Admin -> Global Tool
# Configuration. They are stored encrypted in etcd via IdentityManager (never in
# environment variables). Derived from core.llm_factory's LLM_PROVIDER_KEY_NAMES
# (first/canonical name per provider, deduped), so adding a provider there surfaces
# here automatically. OPENAI_API_KEY also serves openai-compatible providers.
_LLM_PROVIDER_KEY_NAMES = tuple(dict.fromkeys(names[0] for names in LLM_PROVIDER_KEY_NAMES.values()))
_LLM_PROVIDER_TOOL_LABEL = "Framework (LLM Providers)"


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
    rules_engine_model_override = await asyncio.to_thread(identity_mgr.get_rules_evaluation_model)
    rules_engine_provider_override = await asyncio.to_thread(identity_mgr.get_rules_evaluation_provider)
    rules_engine_base_url_override = await asyncio.to_thread(identity_mgr.get_rules_evaluation_base_url)
    rules_confidence_override = await asyncio.to_thread(identity_mgr.get_rules_confidence_threshold)
    branding = {
        key: await asyncio.to_thread(identity_mgr.get_branding, key)
        for key in identity_mgr.BRANDING_KEYS
    }
    tunables_ctx = []
    for name, spec in tunables.TUNABLES.items():
        override = await asyncio.to_thread(identity_mgr.get_tunable, name)
        label, help_text = _TUNABLE_LABELS.get(name, (name, ""))
        tunables_ctx.append({
            "name": name,
            "env_var": spec.env_var,
            "type": spec.type.__name__,
            "default": tunables.env_default(name),
            "override": override,
            "effective": tunables.effective(name, override),
            "label": label,
            "help": help_text,
            "warning": _EMBEDDING_MODEL_WARNING if name == "agent_embedding_model" else None,
        })

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
                "model_override": rules_engine_model_override,
                "model_default": RULES_EVALUATION_MODEL_DEFAULT,
                "provider_override": rules_engine_provider_override,
                "provider_default": RULES_EVALUATION_PROVIDER_DEFAULT,
                "base_url_override": rules_engine_base_url_override,
                "base_url_default": RULES_EVALUATION_BASE_URL_DEFAULT,
                "confidence_override": rules_confidence_override,
                "confidence_default": RULES_CONFIDENCE_THRESHOLD_DEFAULT,
            },
            "branding": branding,
            "branding_keys": identity_mgr.BRANDING_KEYS,
            "tunables": tunables_ctx,
            "allowed_providers": sorted(ALLOWED_PROVIDERS),
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

@router.post("/admin/rules-engine/model")
async def set_rules_engine_model(
    request: Request,
    model: str = Form(""),
    provider: str = Form(""),
    base_url: str = Form(""),
    confidence_threshold: str = Form(""),
):
    if redirect := require_admin(request, '/admin'):
        return redirect

    provider = provider.strip()
    if provider and provider.lower() not in ALLOWED_PROVIDERS:
        request.session["flash_msg"] = (
            f"Unknown provider '{provider}'. Valid providers: {', '.join(sorted(ALLOWED_PROVIDERS))}."
        )
        return RedirectResponse(url='/admin', status_code=303)

    raw_threshold = confidence_threshold.strip()
    threshold: Optional[float] = None
    if raw_threshold:
        try:
            threshold = float(raw_threshold)
        except ValueError:
            request.session["flash_msg"] = f"Invalid confidence threshold '{raw_threshold}' — must be a number."
            return RedirectResponse(url='/admin', status_code=303)
        if not (0.0 <= threshold <= 1.0):
            request.session["flash_msg"] = "Confidence threshold must be between 0.0 and 1.0."
            return RedirectResponse(url='/admin', status_code=303)

    # Empty submission for a field means "clear the override", reverting to its env default.
    if provider:
        await asyncio.to_thread(identity_mgr.set_rules_evaluation_provider, provider)
    else:
        await asyncio.to_thread(identity_mgr.clear_config, "rules_evaluation_provider")

    if base_url.strip():
        await asyncio.to_thread(identity_mgr.set_rules_evaluation_base_url, base_url.strip())
    else:
        await asyncio.to_thread(identity_mgr.clear_config, "rules_evaluation_base_url")

    if model.strip():
        await asyncio.to_thread(identity_mgr.set_rules_evaluation_model, model.strip())
    else:
        await asyncio.to_thread(identity_mgr.clear_config, "rules_evaluation_model")

    if threshold is not None:
        await asyncio.to_thread(identity_mgr.set_rules_confidence_threshold, threshold)
    else:
        await asyncio.to_thread(identity_mgr.clear_config, "rules_confidence_threshold")

    request.session["flash_msg"] = "Rules Engine model settings updated. Changes take effect within ~30 seconds."
    return RedirectResponse(url='/admin', status_code=303)

@router.post("/admin/branding")
async def set_branding(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    form = await request.form()
    for key in identity_mgr.BRANDING_KEYS:
        value = str(form.get(key, "")).strip()
        if value and key in ("accent_color", "accent_color_dark"):
            if not re.match(r"^#(?:[0-9a-fA-F]{3}){1,2}$", value):
                request.session["flash_msg"] = f"Invalid hex color for {key}: '{value}'."
                return RedirectResponse(url='/admin', status_code=303)
        if value:
            await asyncio.to_thread(identity_mgr.set_branding, key, value)
        else:
            # Empty field = clear the override, reverting to the APP_* env default.
            await asyncio.to_thread(identity_mgr.clear_branding, key)

    request.session["flash_msg"] = "Branding updated. Changes take effect within ~30 seconds."
    return RedirectResponse(url='/admin', status_code=303)

@router.post("/admin/tunables")
async def set_tunables(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    form = await request.form()
    updates = []  # (name, value); a None value clears the override
    errors = []
    for name, spec in tunables.TUNABLES.items():
        raw_value = form.get(name)
        if raw_value is None:
            # Field absent from this submission -- leave the override untouched.
            continue
        raw = str(raw_value).strip()
        if raw == "":
            # Empty field = clear the override, reverting to the env/default value.
            updates.append((name, None))
            continue
        try:
            value = tunables.coerce(name, raw)
        except (TypeError, ValueError):
            errors.append(f"{spec.env_var} must be a valid {spec.type.__name__}")
            continue
        if spec.type is int and value < 1:
            errors.append(f"{spec.env_var} must be >= 1")
            continue
        if spec.type is float and value <= 0:
            errors.append(f"{spec.env_var} must be > 0")
            continue
        updates.append((name, value))

    if errors:
        request.session["flash_msg"] = "Limits & Tuning not saved: " + "; ".join(errors) + "."
        return RedirectResponse(url='/admin', status_code=303)

    for name, value in updates:
        if value is None:
            await asyncio.to_thread(tunables.clear_tunable, name, identity_mgr)
        else:
            await asyncio.to_thread(tunables.set_tunable, name, value, identity_mgr)

    request.session["flash_msg"] = "Limits & Tuning updated. Changes take effect within ~30 seconds."
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

    # Framework LLM provider keys form a distinct leading group. Skip any key a
    # tool/MCP already declares so it renders exactly once (keep the tool entry).
    llm_provider_keys = await asyncio.to_thread(identity_mgr.get_llm_provider_keys)
    already_declared = set(required_secrets) | set(required_variables)
    llm_items = []
    for llm_key in _LLM_PROVIDER_KEY_NAMES:
        if llm_key in already_declared:
            continue
        configured = llm_key in llm_provider_keys
        llm_items.append({
            "key": llm_key,
            "type": "secret",
            "label": "LLM",
            "tools": [_LLM_PROVIDER_TOOL_LABEL],
            "is_global": configured,
            "value": "",
            "placeholder": "******** (leave blank to keep current)" if configured
                           else "Set provider key (stored encrypted in etcd)",
        })
    items = llm_items + items

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
    current_llm_keys = await asyncio.to_thread(identity_mgr.get_llm_provider_keys)
    llm_keys = dict(current_llm_keys)
    
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

    # Framework LLM provider keys live in their own encrypted store; a non-empty
    # value sets the key, an empty value leaves the stored key unchanged.
    for llm_key in _LLM_PROVIDER_KEY_NAMES:
        if llm_key not in form:
            continue
        val_str = str(form.get(llm_key)).strip()
        if val_str:
            llm_keys[llm_key] = val_str

    if secrets_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, system_identity, "secrets", current_secrets)
    if variables_updated:
        await asyncio.to_thread(identity_mgr.save_identity_config, system_identity, "variables", current_variables)
    if llm_keys != current_llm_keys:
        await asyncio.to_thread(identity_mgr.save_llm_provider_keys, llm_keys)
    
    request.session["flash_msg"] = "Global configurations and secrets saved successfully."
    return RedirectResponse(url='/admin/configuration', status_code=303)

@router.post("/admin/configuration/delete")
async def delete_admin_configuration_key(request: Request, secret_key: str = Form(...)):
    if redirect := require_admin(request, '/admin'):
        return redirect
        
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)
    current_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    current_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")

    if secret_key in _LLM_PROVIDER_KEY_NAMES:
        llm_keys = dict(await asyncio.to_thread(identity_mgr.get_llm_provider_keys))
        if secret_key in llm_keys:
            del llm_keys[secret_key]
            await asyncio.to_thread(identity_mgr.save_llm_provider_keys, llm_keys)
            request.session["flash_msg"] = f"Global secret '{secret_key}' removed."

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
    
    # 2. Persist to the workspace files so the registry sync re-applies this edit on the
    #    next rebuild instead of overwriting it with the previous on-disk version. The
    #    supervisor's files live in the image (core/assets/supervisor), not the bind-mounted
    #    workspace, so it stays registry-only and resets to the bundled defaults on rebuild.
    if safe_name == "supervisor":
        request.session["flash_msg"] = (
            "Supervisor updated in the registry (bundled files are not writable; changes "
            "will not survive a rebuild)."
        )
        return RedirectResponse(url='/agents', status_code=303)

    yaml_content = yaml.dump(config, sort_keys=False)
    wrote_config = write_repo_file(f"workspace/agents/{safe_name}/config.yaml", yaml_content)
    wrote_skills = write_repo_file(f"workspace/agents/{safe_name}/skills.md", skills_content)

    if wrote_config and wrote_skills:
        request.session["flash_msg"] = f"Agent {safe_name} updated successfully."
    else:
        request.session["flash_msg"] = (
            f"Agent {safe_name} updated in the registry, but its workspace file could not be "
            f"written — the change may not survive a rebuild (check volume permissions)."
        )
        
    return RedirectResponse(url='/agents', status_code=303)

@router.post("/admin/mcps/delete")
async def delete_mcp(request: Request, name: str = Form(...)):
    if redirect := require_admin(request, '/mcps'):
        return redirect

    safe_name = sanitize_name(name)
    if not safe_name:
        request.session["flash_msg"] = "Invalid name parameter."
        return RedirectResponse(url='/mcps', status_code=303)

    await asyncio.to_thread(identity_mgr.delete_mcp, safe_name)
    await asyncio.to_thread(identity_mgr.delete_mcp_tool_embeddings, safe_name)

    # Remove the workspace source file too: sync_to_db re-adds any
    # workspace/mcps/<name>/mcp.yaml on the next rebuild, so deleting only the registry
    # entry would silently resurrect it.
    removed = delete_repo_path(f"workspace/mcps/{safe_name}/mcp.yaml")

    if removed:
        request.session["flash_msg"] = f"MCP {safe_name} deleted (registry, embeddings and workspace source)."
    else:
        request.session["flash_msg"] = (
            f"MCP {safe_name} removed from the registry, but its workspace file could not be "
            f"deleted — it may be re-added on the next rebuild (check volume permissions)."
        )

    return RedirectResponse(url='/mcps', status_code=303)

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
    
    # Dual-write to the workspace file so the registry sync re-applies this edit on the
    # next rebuild instead of reverting it to the previous on-disk version.
    yaml_content = yaml.dump(config, sort_keys=False)
    if write_repo_file(f"workspace/mcps/{safe_name}/mcp.yaml", yaml_content):
        request.session["flash_msg"] = f"MCP {safe_name} updated successfully."
    else:
        request.session["flash_msg"] = (
            f"MCP {safe_name} updated in the registry, but its workspace file could not be "
            f"written — the change may not survive a rebuild (check volume permissions)."
        )
        
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
    
    # 2. Persist to the workspace file so the registry sync re-applies this edit on the
    #    next rebuild instead of reverting it to the previous on-disk version.
    if config.get("rel_path"):
        yaml_content = yaml.dump({k:v for k,v in config.items() if k != "rel_path"}, sort_keys=False)
        if write_repo_file(f"{config['rel_path']}/tool.yaml", yaml_content):
            request.session["flash_msg"] = f"Tool {safe_name} updated successfully."
        else:
            request.session["flash_msg"] = (
                f"Tool {safe_name} updated in the registry, but its workspace file could not be "
                f"written — the change may not survive a rebuild (check volume permissions)."
            )
    else:
        request.session["flash_msg"] = f"Tool {safe_name} updated successfully."
        
    return RedirectResponse(url='/tools', status_code=303)
