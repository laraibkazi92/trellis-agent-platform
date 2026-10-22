# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
import re
import json
import yaml
import time
import asyncio
import httpx
from typing import Optional
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, CSRFRoute
from core.auth import get_identity_manager
from core.health import HealthMonitor
from core.llm_factory import ProviderConfigError, infer_provider
from core.llm_providers import (
    FRAMEWORK_PROVIDER_KEY_ENV,
    default_model_for,
    get_spec,
    provider_accepts_base_url,
    provider_is_usable,
    provider_requires_base_url,
    provider_ui_specs,
)
from core.llm_defaults import (
    FrameworkDefaults,
    get_framework_defaults,
    reset_defaults_cache,
    resolve_effective_llm_config,
    validate_defaults,
)
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

# Every key name the Admin -> LLM Providers page can write or clear: all accepted
# credential names (canonical + aliases) and the global base_url key (if any) of
# each provider. Used as the delete whitelist.
# The page writes the same encrypted /identities/system/system/llm_keys store as
# the legacy configuration table, so the etcd watch in
# core.agent_factory._on_llm_keys_change already resets the key cache and evicts
# agents after a save.
_LLM_PROVIDER_PAGE_KEY_NAMES = frozenset(
    name
    for spec in provider_ui_specs()
    for name in (*spec["key_names"], spec["base_url_key"])
    if name
)


def sanitize_name(name: str) -> str:
    """Sanitize name parameter to prevent path traversal and registry injection."""
    return re.sub(r'[^a-zA-Z0-9_-]', '', name)

def _provider_label(provider_id: str) -> str:
    try:
        return get_spec(provider_id).label
    except ProviderConfigError:
        return provider_id

def _inherit_hint(
    provider: str | None,
    model: str | None,
    base_url: str | None,
    defaults: FrameworkDefaults | None,
    default_provider_label: str | None,
) -> str | None:
    """Read-only editor hint for the inherit paths (plan §9).

    Two states inherit a model and get a hint: both provider and model blank (the
    framework default), and provider set with a blank model (the provider's registry
    default, or the framework default when it is that same provider). A
    fully-specified agent, an inferred model, or an unknown provider renders nothing.
    """
    if (model or "").strip():
        return None
    try:
        effective = resolve_effective_llm_config(provider, model, base_url, defaults)
    except ProviderConfigError:
        return None
    # A stored default only counts when it is complete. `_normalize_defaults` never yields a
    # provider without a model, so this only guards a hand-built default -- and it strips,
    # deliberately stricter than the resolver's `has_defaults`.
    defaults_provider = None
    if defaults and defaults.provider and (defaults.model or "").strip():
        defaults_provider = defaults.provider

    if (defaults_provider and defaults_provider == effective.provider
            and effective.source in ("framework", "provider-default")):
        return f"Inherits framework default: {default_provider_label or defaults_provider} / {effective.model}"
    if effective.source == "provider-default":
        return f"Uses {_provider_label(effective.provider)} default: {effective.model}"
    return None

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

    # Resolve the effective provider so the (provider, base_url) pair can be
    # validated and a known, non-inferable model (llama3.2, openai/gpt-5) does not
    # silently fail every evaluation.
    from core.llm_providers import PROVIDERS
    model_clean = model.strip()
    effective_provider = provider.lower()
    if not effective_provider and model_clean:
        try:
            effective_provider = infer_provider(model_clean)
        except ProviderConfigError:
            effective_provider = next(
                (spec.id for spec in PROVIDERS.values() if model_clean in spec.known_models), ""
            )

    stripped_url = base_url.strip()
    if provider_requires_base_url(effective_provider) and not stripped_url:
        request.session["flash_msg"] = (
            f"Provider '{effective_provider}' requires a base_url pointing at the endpoint."
        )
        return RedirectResponse(url='/admin', status_code=303)
    if stripped_url and effective_provider and not provider_accepts_base_url(effective_provider):
        request.session["flash_msg"] = (
            f"Provider '{effective_provider}' does not accept a base_url; remove it."
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

    # Resolve the model to persist before any write, so a rejected save writes nothing.
    # A provider override with a blank model must never fall through to the env
    # RULES_EVALUATION_MODEL, which would egress one vendor's query to another.
    model_value = model.strip()
    if not model_value and effective_provider:
        model_value = default_model_for(effective_provider) or ""
        if not model_value:
            request.session["flash_msg"] = (
                f"Provider '{effective_provider}' requires an explicit model."
            )
            return RedirectResponse(url='/admin', status_code=303)

    # Empty submission for a field means "clear the override", reverting to its env default.
    if effective_provider:
        await asyncio.to_thread(identity_mgr.set_rules_evaluation_provider, effective_provider)
    else:
        await asyncio.to_thread(identity_mgr.clear_config, "rules_evaluation_provider")

    if stripped_url:
        await asyncio.to_thread(identity_mgr.set_rules_evaluation_base_url, stripped_url)
    else:
        await asyncio.to_thread(identity_mgr.clear_config, "rules_evaluation_base_url")

    if model_value:
        await asyncio.to_thread(identity_mgr.set_rules_evaluation_model, model_value)
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

    # Provider credentials moved to Admin -> LLM Providers. A stale form (opened
    # before the upgrade) would otherwise look like it saved; say so explicitly.
    ignored_llm_keys = sorted(
        key for key in form
        if key in FRAMEWORK_PROVIDER_KEY_ENV
        and key not in known_secrets
        and key not in known_variables
    )
    message = "Global configurations and secrets saved successfully."
    if ignored_llm_keys:
        message += (
            " LLM provider keys are managed in Admin -> LLM Providers; ignored: "
            + ", ".join(ignored_llm_keys) + "."
        )
    request.session["flash_msg"] = message
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

@router.get("/admin/llm-providers", response_class=HTMLResponse)
async def admin_llm_providers_page(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    user = request.session.get('user')
    llm_keys = await asyncio.to_thread(identity_mgr.get_llm_provider_keys)

    cards = []
    for spec in provider_ui_specs():
        # An alias (GOOGLE_API_KEY, OPENAI_API_KEY, …) may be the stored name, so
        # remember which one is actually present: the Clear button must target it.
        configured_key = next((name for name in spec["key_names"] if llm_keys.get(name)), None)
        base_url_value = llm_keys.get(spec["base_url_key"]) if spec["base_url_key"] else None
        cards.append({
            **spec,
            "configured": configured_key is not None,
            "configured_key": configured_key,
            "base_url_value": base_url_value,
            "value_preview": None,
        })

    # Framework defaults view: the provider select offers only providers that could
    # actually serve traffic (provider_is_usable); the model select is that provider's
    # curated known_models. A stored-but-now-unusable default is kept and flagged (D14).
    stored_provider = (await asyncio.to_thread(identity_mgr.get_default_llm_provider) or "").strip().lower()
    stored_model = (await asyncio.to_thread(identity_mgr.get_default_llm_model) or "").strip()
    stored_base_url = (await asyncio.to_thread(identity_mgr.get_default_llm_base_url) or "").strip()

    usable_specs = [
        spec for spec in provider_ui_specs()
        if provider_is_usable(get_spec(spec["id"]), llm_keys)
    ]
    usable_ids = {spec["id"] for spec in usable_specs}
    try:
        stored_spec = get_spec(stored_provider) if stored_provider else None
    except ProviderConfigError:
        stored_spec = None
    # No stored default => leave the None option selected; never invent a provider.
    selected_provider = stored_provider
    if stored_spec is not None:
        selected_spec = stored_spec
    elif stored_provider:
        # Unknown stored provider: render it selected-but-flagged with a free-text model.
        selected_spec = None
    else:
        selected_spec = get_spec(usable_specs[0]["id"]) if usable_specs else None
    model_options = list(selected_spec.known_models) if selected_spec else []
    selected_model = stored_model or (
        selected_spec.default_model if (selected_spec and selected_provider) else ""
    ) or ""
    model_free_text = selected_spec is None or not selected_spec.known_models
    stored_provider_unusable = bool(stored_provider) and (
        stored_spec is None or stored_spec.id not in usable_ids
    )

    flash_msg = request.session.pop("flash_msg", None)

    return templates.TemplateResponse(
        request=request,
        name="admin_llm_providers.html",
        context={
            "user": user,
            "cards": cards,
            "flash_msg": flash_msg,
            "defaults": {"provider": stored_provider or None, "model": stored_model or None, "base_url": stored_base_url or None},
            "usable_providers": usable_specs,
            "selected_provider": selected_provider,
            "selected_model": selected_model,
            "model_options": model_options,
            "model_free_text": model_free_text,
            "model_free_text_value": stored_model,
            "stored_provider": stored_provider or None,
            "stored_provider_label": stored_spec.label if stored_spec else stored_provider,
            "stored_provider_unusable": stored_provider_unusable,
            "has_usable": bool(usable_specs),
            "stored_base_url": stored_base_url,
            "selected_supports_base_url": bool(selected_provider and selected_spec and selected_spec.supports_base_url),
            "selected_base_url_placeholder": (selected_spec.base_url_placeholder or selected_spec.default_base_url or "") if selected_spec else "",
        }
    )

@router.post("/admin/llm-providers")
async def save_llm_providers(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    form = await request.form()
    current = dict(await asyncio.to_thread(identity_mgr.get_llm_provider_keys))
    updated = dict(current)

    for spec in provider_ui_specs():
        for name in (spec["canonical_key"], spec["base_url_key"]):
            if not name or name not in form:
                continue
            value = str(form.get(name)).strip()
            if value:  # blank keeps the stored value
                updated[name] = value

    if updated != current:
        await asyncio.to_thread(identity_mgr.save_llm_provider_keys, updated)
        request.session["flash_msg"] = "LLM provider settings saved."
    else:
        request.session["flash_msg"] = "No changes to LLM provider settings."
    return RedirectResponse(url='/admin/llm-providers', status_code=303)

@router.post("/admin/llm-providers/defaults")
async def save_llm_defaults(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    form = await request.form()
    provider = str(form.get("provider", "")).strip().lower()
    model = str(form.get("model", "")).strip()
    base_url = str(form.get("base_url", "")).strip()

    # Provider blank -> clear all three, ignore model/base_url (revert to legacy).
    if not provider:
        await asyncio.to_thread(identity_mgr.clear_default_llm_provider)
        await asyncio.to_thread(identity_mgr.clear_default_llm_model)
        await asyncio.to_thread(identity_mgr.clear_default_llm_base_url)
        reset_defaults_cache()
        request.session["flash_msg"] = "Framework LLM default cleared."
        return RedirectResponse(url='/admin/llm-providers', status_code=303)

    try:
        spec = get_spec(provider)
    except ProviderConfigError as e:
        request.session["flash_msg"] = str(e)
        return RedirectResponse(url='/admin/llm-providers', status_code=303)

    # D14: an already-stored provider may be re-saved even when its credential is gone;
    # only a *newly* selected unusable provider is rejected.
    stored_provider = (await asyncio.to_thread(identity_mgr.get_default_llm_provider) or "").strip().lower()
    keys = await asyncio.to_thread(identity_mgr.get_llm_provider_keys)
    if not provider_is_usable(spec, keys) and provider != stored_provider:
        request.session["flash_msg"] = (
            f"Provider '{provider}' has no credential/endpoint configured (or its SDK is missing)."
        )
        return RedirectResponse(url='/admin/llm-providers', status_code=303)

    if not model:
        model = default_model_for(provider) or ""
        if not model:
            request.session["flash_msg"] = f"Provider '{provider}' requires an explicit model."
            return RedirectResponse(url='/admin/llm-providers', status_code=303)

    # Curated allowlist, exempting only the currently-stored (provider, model) pair
    # (D14: a stored de-listed model is kept/flagged, not silently changed).
    stored_model = (await asyncio.to_thread(identity_mgr.get_default_llm_model) or "").strip()
    if (
        spec.known_models
        and model not in spec.known_models
        and not (model == stored_model and provider == stored_provider)
    ):
        request.session["flash_msg"] = f"Model '{model}' is not one of the curated models for '{provider}'."
        return RedirectResponse(url='/admin/llm-providers', status_code=303)

    errors = validate_defaults(provider, model, base_url, check_curated=False)
    if errors:
        request.session["flash_msg"] = errors[0]
        return RedirectResponse(url='/admin/llm-providers', status_code=303)

    await asyncio.to_thread(identity_mgr.set_default_llm_provider, provider)
    await asyncio.to_thread(identity_mgr.set_default_llm_model, model)
    if base_url:
        await asyncio.to_thread(identity_mgr.set_default_llm_base_url, base_url)
    else:
        await asyncio.to_thread(identity_mgr.clear_default_llm_base_url)
    reset_defaults_cache()
    request.session["flash_msg"] = "Framework LLM default saved."
    return RedirectResponse(url='/admin/llm-providers', status_code=303)

@router.post("/admin/llm-providers/defaults/clear")
async def clear_llm_defaults(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    await asyncio.to_thread(identity_mgr.clear_default_llm_provider)
    await asyncio.to_thread(identity_mgr.clear_default_llm_model)
    await asyncio.to_thread(identity_mgr.clear_default_llm_base_url)
    reset_defaults_cache()
    request.session["flash_msg"] = "Framework LLM default cleared."
    return RedirectResponse(url='/admin/llm-providers', status_code=303)

@router.post("/admin/llm-providers/delete")
async def delete_llm_provider_key(request: Request, key_name: str = Form(...)):
    if redirect := require_admin(request, '/admin'):
        return redirect

    if key_name not in _LLM_PROVIDER_PAGE_KEY_NAMES:
        request.session["flash_msg"] = "Unknown LLM provider key."
        return RedirectResponse(url='/admin/llm-providers', status_code=303)

    keys = dict(await asyncio.to_thread(identity_mgr.get_llm_provider_keys))
    if key_name in keys:
        del keys[key_name]
        await asyncio.to_thread(identity_mgr.save_llm_provider_keys, keys)
        request.session["flash_msg"] = f"'{key_name}' removed."
    else:
        request.session["flash_msg"] = f"'{key_name}' was not set."

    return RedirectResponse(url='/admin/llm-providers', status_code=303)

# --- Edge nodes (trellis-proxy) ------------------------------------------------
#
# The central host cannot dial a site, so an edge registers itself and its tools are
# published into /registry/tools/<site>__<tool> by the relay. These routes own the site
# lifecycle (enrollment token, exports allowlist, delete); tool configs are the relay's.

# Site names become the `<site>__<tool>` registry prefix, so they must be a safe etcd key
# segment and must not collide with the separator or a reserved prefix.
_EDGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_EDGE_RESERVED_NAMES = frozenset({"mcp"})

# An enrollment token is handed to the operator exactly once. The POST handlers redirect
# (303, the admin-UI convention) and the plaintext rides in this process until the next
# /admin/edges render -- never in the session (a client-readable cookie), never in etcd,
# and never in a URL (nginx/uvicorn access logs would record it). Entries are popped on
# read and expire, so a missed render cannot leak one later.
_EDGE_TOKEN_TTL_SECONDS = 300.0
_pending_edge_tokens: dict[str, tuple[float, str]] = {}


def _stash_edge_token(site: str, token: str) -> None:
    _pending_edge_tokens[site] = (time.monotonic(), token)


def _pop_edge_tokens() -> list[dict]:
    """Hand every pending token to the next page render, then forget them."""
    now = time.monotonic()
    expired = [
        site for site, (created, _) in _pending_edge_tokens.items()
        if now - created > _EDGE_TOKEN_TTL_SECONDS
    ]
    for stale in expired:
        _pending_edge_tokens.pop(stale, None)
    entries = [
        {"site": site, "token": token}
        for site, (_, token) in sorted(_pending_edge_tokens.items())
    ]
    _pending_edge_tokens.clear()
    return entries


def _edge_name_error(name: str) -> str | None:
    if not name:
        return "Edge name is required."
    if "__" in name:
        return "Invalid edge name: '__' is reserved as the tool-name separator."
    if name.lower() in _EDGE_RESERVED_NAMES:
        return f"Invalid edge name: '{name}' is reserved."
    if not _EDGE_NAME_RE.match(name):
        return (
            "Invalid edge name: use letters, digits, '-' or '_', start with a letter or "
            "digit, and keep it to 64 characters."
        )
    return None


def _parse_edge_exports(raw: str) -> list[str]:
    return [item.strip() for item in (raw or "").split(",") if item.strip()]


def _parse_edge_rate(raw: str | None) -> int | None:
    """Operator override for the relay's per-site call budget; blank = default."""
    if raw in (None, ""):
        return None
    try:
        rate = int(raw)
    except (TypeError, ValueError):
        return None
    return max(1, min(rate, 6000))


def _normalize_edge_mcp(entry) -> dict | None:
    """One status MCP entry -> {name, tools, transport}; junk is dropped.

    A v0.5 relay writes ``{"name", "tools", "transport"}``; a bare name is accepted so
    the page survives a relay that publishes a plain list of server names.
    """
    if isinstance(entry, str):
        name = entry.strip()
        return {"name": name, "tools": 0, "transport": ""} if name else None
    if not isinstance(entry, dict):
        return None
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    try:
        tools = max(0, int(entry.get("tools")))
    except (TypeError, ValueError):
        tools = 0
    transport = entry.get("transport")
    return {
        "name": name.strip(),
        "tools": tools,
        "transport": transport.strip() if isinstance(transport, str) else "",
    }


def _normalize_edge_mcps(raw) -> list[dict]:
    """Tolerate v0.4 (absent), a single mapping, and any junk value."""
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return []
    return [mcp for mcp in (_normalize_edge_mcp(entry) for entry in raw) if mcp]


def _normalize_edge_proto(raw) -> int | None:
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None
    return raw


def _normalize_edge_caps(raw) -> list[str]:
    """Caps default to tools-only: that is what a v0.4 relay is worth."""
    if isinstance(raw, (list, tuple)):
        caps = [cap for cap in raw if isinstance(cap, str) and cap]
        if caps:
            return caps
    return ["tools"]


@router.get("/admin/edges", response_class=HTMLResponse)
async def admin_edges_page(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    user = request.session.get('user')
    names = await asyncio.to_thread(identity_mgr.list_edges)

    edges = []
    for name in sorted(names):
        config = await asyncio.to_thread(identity_mgr.get_edge_config, name) or {}
        status = await asyncio.to_thread(identity_mgr.get_edge_status, name) or {}
        # The relay publishes the catalog as names, but tolerate {name: ...} dicts so a
        # status written by a newer relay never breaks this page.
        raw_tools = status.get("tools") or []
        tools = [t.get("name", "") if isinstance(t, dict) else str(t) for t in raw_tools]
        edges.append({
            "name": name,
            "display_name": config.get("display_name") or name,
            "enabled": config.get("enabled", True) is not False,
            "connected": status.get("connected") is True,
            "edge_version": status.get("edge_version") or config.get("edge_version") or "",
            "tools": tools,
            "exports": config.get("exports") or [],
            "public": config.get("public") is True,
            "public_tools": config.get("public_tools") or [],
            "token_preview": config.get("token_preview") or "",
            "created_at": config.get("created_at") or "",
            "last_error": status.get("last_error") or "",
            "mcps": _normalize_edge_mcps(status.get("mcps")),
            "proto": _normalize_edge_proto(status.get("proto")),
            "caps": _normalize_edge_caps(status.get("caps")),
            "last_seen": (
                status.get("connected_at") or status.get("disconnected_at")
                or config.get("last_seen") or ""
            ),
            "rate_limit_per_min": config.get("rate_limit_per_min"),
        })

    return templates.TemplateResponse(
        request=request,
        name="admin_edges.html",
        context={
            "user": user,
            "edges": edges,
            "flash_msg": request.session.pop("flash_msg", None),
            "new_tokens": _pop_edge_tokens(),
            "rate_limit_default": os.getenv("EDGE_RATE_LIMIT_PER_MIN", "120"),
        },
    )


@router.post("/admin/edges/create")
async def create_edge(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    form = await request.form()
    name = (form.get("name") or "").strip()
    display_name = (form.get("display_name") or "").strip() or name
    exports = _parse_edge_exports(form.get("exports") or "")

    if error := _edge_name_error(name):
        request.session["flash_msg"] = error
        return RedirectResponse(url='/admin/edges', status_code=303)

    created_by = (request.session.get("user") or {}).get("email") or "unknown"
    try:
        token = await asyncio.to_thread(
            identity_mgr.create_edge, name, display_name, created_by, exports
        )
    except ValueError as exc:
        request.session["flash_msg"] = str(exc)
        return RedirectResponse(url='/admin/edges', status_code=303)

    request.session["flash_msg"] = (
        f"Edge '{name}' created. Its enrollment token is shown once on this page -- copy "
        f"it now, it cannot be retrieved again."
    )
    _stash_edge_token(name, token)
    return RedirectResponse(url='/admin/edges', status_code=303)


@router.post("/admin/edges/update")
async def update_edge(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    form = await request.form()
    name = (form.get("name") or "").strip()

    config = await asyncio.to_thread(identity_mgr.get_edge_config, name)
    if not config:
        request.session["flash_msg"] = f"Edge '{name}' not found."
        return RedirectResponse(url='/admin/edges', status_code=303)

    # Only these three fields are operator-editable. The token hash, ownership and status
    # deliberately stay exactly as the registry has them -- never round-tripped via a form.
    config["display_name"] = (form.get("display_name") or "").strip() or name
    config["exports"] = _parse_edge_exports(form.get("exports") or "")
    config["public"] = form.get("public") == "true"
    # Per-tool whitelist: names here are public even when the site is not.
    config["public_tools"] = _parse_edge_exports(form.get("public_tools") or "")
    # Blank clears the override, so the site follows EDGE_RATE_LIMIT_PER_MIN.
    rate = _parse_edge_rate(form.get("rate_limit_per_min"))
    if rate is None:
        config.pop("rate_limit_per_min", None)
    else:
        config["rate_limit_per_min"] = rate
    await asyncio.to_thread(identity_mgr.save_edge_config, name, config)

    request.session["flash_msg"] = f"Edge '{name}' updated."
    return RedirectResponse(url='/admin/edges', status_code=303)


@router.post("/admin/edges/test")
async def test_edge(request: Request):
    """Report whether the relay currently holds a live tunnel for this site.

    A real tool call needs a tool and its arguments, so this is a connectivity probe:
    it answers "is the tunnel up, and what does it publish" without side effects.
    """
    if redirect := require_admin(request, '/admin'):
        return redirect

    form = await request.form()
    name = (form.get("name") or "").strip()
    base = os.getenv("EDGE_RELAY_URL", "http://edge-relay:8100").rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(f"{base}/healthz")
            response.raise_for_status()
            sites = (response.json() or {}).get("sites") or {}
    except Exception as exc:
        request.session["flash_msg"] = (
            f"Could not reach the edge relay ({type(exc).__name__}); check the edge-relay service."
        )
        return RedirectResponse(url='/admin/edges', status_code=303)

    info = sites.get(name)
    if not info:
        request.session["flash_msg"] = (
            f"Edge '{name}' is offline: the relay has no live tunnel for it."
        )
    else:
        request.session["flash_msg"] = (
            f"Edge '{name}' is connected: {info.get('tools', 0)} tool(s) published, "
            f"{info.get('inflight', 0)} call(s) in flight."
        )
    return RedirectResponse(url='/admin/edges', status_code=303)


@router.post("/admin/edges/rotate")
async def rotate_edge(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    form = await request.form()
    name = (form.get("name") or "").strip()
    rotated_by = (request.session.get("user") or {}).get("email") or "unknown"

    try:
        token = await asyncio.to_thread(identity_mgr.rotate_edge_token, name, rotated_by)
    except ValueError as exc:
        request.session["flash_msg"] = str(exc)
        return RedirectResponse(url='/admin/edges', status_code=303)

    request.session["flash_msg"] = (
        f"Token for edge '{name}' rotated. The previous token no longer works; the new "
        f"enrollment token is shown once on this page -- copy it now."
    )
    _stash_edge_token(name, token)
    return RedirectResponse(url='/admin/edges', status_code=303)


@router.post("/admin/edges/revoke")
async def revoke_edge(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    form = await request.form()
    name = (form.get("name") or "").strip()
    await asyncio.to_thread(identity_mgr.revoke_edge_token, name)

    request.session["flash_msg"] = (
        f"Token for edge '{name}' revoked. The live tunnel is refused at its next "
        f"handshake and the current socket closes."
    )
    return RedirectResponse(url='/admin/edges', status_code=303)


@router.post("/admin/edges/delete")
async def delete_edge(request: Request):
    if redirect := require_admin(request, '/admin'):
        return redirect

    form = await request.form()
    name = (form.get("name") or "").strip()

    config = await asyncio.to_thread(identity_mgr.get_edge_config, name)
    if not config:
        request.session["flash_msg"] = f"Edge '{name}' not found."
        return RedirectResponse(url='/admin/edges', status_code=303)

    # Deleting the site also removes its catalogued tools, configs and embeddings.
    await asyncio.to_thread(identity_mgr.delete_edge, name)

    request.session["flash_msg"] = (
        f"Edge '{name}' deleted, along with the tools it published. The edge must be "
        f"re-registered with a new token to reconnect."
    )
    return RedirectResponse(url='/admin/edges', status_code=303)


def _agent_editor_tool_rows(local_tool_configs, mcp_configs):
    """Rows the agent editor's "Allowed MCP Tools" picker renders.

    Hub tools plus every tool of every registered MCP (central and edge). Shared by the
    page and its save handler so the save can tell an entry it *could* have rendered
    (governed by the form) from one it never showed (must be preserved).
    """
    rows = [
        {
            "name": t_name,
            "type": "local",
            "source": "Hub",
            "version": (t_config or {}).get("version", ""),
            "description": (t_config or {}).get("description", ""),
        }
        for t_name, t_config in local_tool_configs.items()
    ]
    for mcp_name, mcp_config in mcp_configs.items():
        for tool in (mcp_config or {}).get("tools") or []:
            rows.append({
                "name": tool.get("name", ""),
                "type": "mcp",
                "source": mcp_name,
                "version": tool.get("version", ""),
                "description": tool.get("description", ""),
            })
    rows.sort(key=lambda row: row["name"])
    return rows


async def _agent_editor_catalog():
    """``(tool configs, mcp configs, mcp names)`` -- one bulk read per editor surface."""
    local_tool_configs = await asyncio.to_thread(identity_mgr.get_all_tool_configs)
    mcp_configs = await asyncio.to_thread(identity_mgr.get_all_mcp_configs)
    all_mcps = await asyncio.to_thread(identity_mgr.list_mcps)
    return local_tool_configs, mcp_configs, all_mcps


def _merge_unrendered_entries(submitted, existing, rendered):
    """Union the submitted allowlist with entries the editor had no checkbox for.

    The editor renders one checkbox per registered tool / MCP name, so a config can
    legitimately carry entries the form cannot show: a `<site>__*` edge wildcard, or a
    reference to an edge MCP that has not connected yet. The form is authoritative only
    for what it rendered; rewriting the list from `form.getlist` alone would delete the
    rest on every save -- and dual-write the deletion to `workspace/agents/<name>/`.
    """
    ordered = list(submitted)
    ordered.extend(
        entry for entry in existing or []
        if entry not in rendered and entry not in ordered
    )
    return ordered


@router.get("/editor/{type}/{name}", response_class=HTMLResponse)
async def editor_page(request: Request, type: str, name: str):
    fallback_url = '/agents' if type == 'agent' else '/tools'
    if redirect := require_admin(request, fallback_url):
        return redirect
    
    user = request.session.get('user')
    # The editor is a standalone page (it does not extend base.html), so a flash set
    # just before redirecting here -- e.g. by save_agent's provider/base_url checks --
    # must be rendered through editor.html's own `error` block.
    flash_msg = request.session.pop("flash_msg", None)

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

        local_tool_configs, mcp_configs, all_mcps = await _agent_editor_catalog()
        all_tools = _agent_editor_tool_rows(local_tool_configs, mcp_configs)
        
        if not config:
            request.session["flash_msg"] = "Agent not found."
            return RedirectResponse(url='/agents', status_code=303)

        # §9: read-only inherit hint. Display-only -- never prefill config.provider/model.
        default_llm = await asyncio.to_thread(get_framework_defaults)
        default_llm_provider_label = _provider_label(default_llm.provider) if default_llm.provider else None
        inherit_hint = _inherit_hint(
            config.get("provider"),
            config.get("model"),
            config.get("base_url"),
            default_llm,
            default_llm_provider_label,
        )

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
                "all_mcps": all_mcps,
                "error": flash_msg,
                "inherit_hint": inherit_hint,
            }
        )
    elif type == "tool":
        config = await asyncio.to_thread(identity_mgr.get_tool_config, safe_name)
        if not config:
            request.session["flash_msg"] = "Tool not found."
            return RedirectResponse(url='/tools', status_code=303)
        # Remote tools are published by the edge relay from the edge's own catalog, so
        # their schema cannot be edited here: the editor renders read-only and names the
        # owning site.
        edge_site = (config.get("remote") or {}).get("site") or (
            safe_name.split("__", 1)[0] if "__" in safe_name else ""
        )
        return templates.TemplateResponse(
            request=request,
            name="editor.html", 
            context={
                "user": user,
                "type": type,
                "name": safe_name,
                "config": config,
                "error": flash_msg,
                "edge_managed": config.get("managed_by") == "edge-relay",
                "edge_site": edge_site,
            }
        )
    elif type == "mcp":
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, safe_name)
        if not config:
            request.session["flash_msg"] = "MCP not found."
            return RedirectResponse(url='/mcps', status_code=303)
        # Edge-exported servers are published by the relay from the edge's own catalog;
        # the editor renders read-only and names the owning site.
        edge_site = (config.get("remote") or {}).get("site") or (
            safe_name.split("__", 1)[0] if "__" in safe_name else ""
        )
        return templates.TemplateResponse(
            request=request,
            name="editor.html", 
            context={
                "user": user,
                "type": type,
                "name": safe_name,
                "config": config,
                "error": flash_msg,
                "edge_managed": config.get("managed_by") == "edge-relay",
                "edge_site": edge_site,
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
    # Auto provider: validate an explicit endpoint against the provider the model
    # implies, otherwise a legitimate Auto + base_url combination is unsaveable.
    validation_provider = provider
    if not validation_provider and config["base_url"]:
        try:
            validation_provider = infer_provider(config["model"] or "")
        except ProviderConfigError:
            request.session["flash_msg"] = (
                "Cannot infer a provider for the supplied base_url; select a provider explicitly."
            )
            return RedirectResponse(url=f'/editor/agent/{safe_name}', status_code=303)
    if provider_requires_base_url(validation_provider) and not config["base_url"]:
        request.session["flash_msg"] = (
            f"Provider '{validation_provider}' requires a base_url pointing at the endpoint."
        )
        return RedirectResponse(url=f'/editor/agent/{safe_name}', status_code=303)
    if config["base_url"] and not provider_accepts_base_url(validation_provider):
        request.session["flash_msg"] = (
            f"Provider '{validation_provider}' does not accept a base_url; remove it."
        )
        return RedirectResponse(url=f'/editor/agent/{safe_name}', status_code=303)
    
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
    # Union, not overwrite: the editor renders one checkbox per registered tool / MCP,
    # so anything it cannot show -- a `<site>__*` wildcard, a reference to an edge MCP
    # that has not connected yet -- is absent from the form and must survive the save.
    local_tool_configs, mcp_configs, all_mcps = await _agent_editor_catalog()
    rendered_tools = {
        row["name"] for row in _agent_editor_tool_rows(local_tool_configs, mcp_configs)
    }
    config["allowed_tools"] = _merge_unrendered_entries(
        form.getlist("allowed_tools"), config.get("allowed_tools"), rendered_tools
    )
    config["allowed_mcps"] = _merge_unrendered_entries(
        form.getlist("allowed_mcps"), config.get("allowed_mcps"), set(all_mcps)
    )
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

    # An edge-published MCP is the relay's: deleting it here would be silently undone by
    # the next catalog publish, and it is the site (not the entry) that owns it.
    config = await asyncio.to_thread(identity_mgr.get_mcp_config, safe_name)
    if (config or {}).get("managed_by") == "edge-relay":
        request.session["flash_msg"] = (
            f"MCP '{safe_name}' is managed by the edge relay and cannot be deleted here. "
            f"Remove it from the edge's export_mcps and reconnect, or delete the site."
        )
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
    # Same defence as save_tool: an edge-published MCP is the relay's, and a save here
    # would be overwritten on the next catalog publish.
    if config.get("managed_by") == "edge-relay":
        request.session["flash_msg"] = (
            f"MCP '{safe_name}' is managed by the edge relay and cannot be edited here. "
            f"Change it on the edge and reconnect."
        )
        return RedirectResponse(url='/mcps', status_code=303)
    config["transport"] = form.get("transport")
    # `remote` is a registry pointer written by the relay, not a transport an operator can
    # pick: a hand-written one has no usable `remote` block and would be routed nowhere.
    if config.get("transport") == "remote":
        request.session["flash_msg"] = (
            "Transport 'remote' is assigned by the edge relay and cannot be selected here."
        )
        return RedirectResponse(url=f'/editor/mcp/{safe_name}', status_code=303)
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
    
    try:
        await asyncio.to_thread(identity_mgr.save_mcp_config, safe_name, config)
    except ValueError as exc:
        # Name rule violations (e.g. a central name containing "__") are user input
        # problems, not server faults.
        request.session["flash_msg"] = str(exc)
        return RedirectResponse(url='/mcps', status_code=303)
    
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
    # Defence in depth: the editor renders read-only for edge tools, but a stale form
    # (opened before the tool moved to an edge, or before the upgrade) can still POST.
    # The relay owns these configs; a save here would be overwritten on the next catalog
    # publish and could poison the schema in between.
    if config.get("managed_by") == "edge-relay":
        request.session["flash_msg"] = (
            f"Tool '{safe_name}' is managed by the edge relay and cannot be edited here. "
            f"Change it on the edge and reconnect."
        )
        return RedirectResponse(url='/tools', status_code=303)
    config["runtime"] = form.get("runtime")
    # `remote` is a registry pointer, not a runtime an operator can pick. A local tool
    # marked remote has no `remote` block, fails ToolConfig validation, and silently
    # disappears from the hub at the next reconcile.
    if config.get("runtime") == "remote":
        request.session["flash_msg"] = (
            "Runtime 'remote' is assigned by the edge relay and cannot be selected here."
        )
        return RedirectResponse(url=f'/editor/tool/{safe_name}', status_code=303)
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
