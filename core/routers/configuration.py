# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import asyncio
from typing import Dict, List
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import templates, identity_mgr, CSRFRoute
from core.discovery import _build_secret_group_view
from core.routers._config_shared import apply_configuration_form
from core.models import Identity, IdentityType

router = APIRouter(route_class=CSRFRoute)

@router.get("/secrets")
async def secrets_redirect():
    """Redirect legacy /secrets URL to /configuration."""
    return RedirectResponse(url='/configuration', status_code=301)

@router.post("/secrets")
async def secrets_post_redirect():
    """Redirect legacy /secrets POST to /configuration."""
    return RedirectResponse(url='/configuration', status_code=307)

@router.get("/configuration", response_class=HTMLResponse)
async def configuration_page(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    user_id = user['sub']

    # 1. Gather all required/optional secrets, variables, and secret groups from
    # registered tools and MCPs
    tool_names = await asyncio.to_thread(identity_mgr.list_tools)
    mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
    required_secrets: Dict[str, List[str]] = {}
    optional_secrets_map: Dict[str, List[str]] = {}
    required_variables: Dict[str, List[str]] = {}
    secret_groups: List[Dict] = []
    grouped_keys: set = set()

    def _collect(config: Dict, label: str, name: str):
        secrets_data = config.get("secrets", [])
        if isinstance(secrets_data, dict):
            secrets_list = list(secrets_data.get("general", [])) + list(secrets_data.get("user", []))
        else:
            secrets_list = secrets_data

        for secret_key in secrets_list or []:
            required_secrets.setdefault(secret_key, []).append(f"{label}: {name}")

        for secret_key in config.get("optional_secrets", []) or []:
            optional_secrets_map.setdefault(secret_key, []).append(f"{label}: {name}")

        vars_data = config.get("variables", [])
        if isinstance(vars_data, dict):
            vars_list = list(vars_data.get("general", [])) + list(vars_data.get("user", []))
        else:
            vars_list = vars_data

        for var_key in vars_list or []:
            required_variables.setdefault(var_key, []).append(f"{label}: {name}")

        for group in config.get("secret_groups", []) or []:
            group_entry = {**group, "tools": [f"{label}: {name}"]}
            secret_groups.append(group_entry)
            for option in group.get("options", []):
                for field in option.get("fields", []):
                    grouped_keys.add(field["key"])

    for name in tool_names:
        config = await asyncio.to_thread(identity_mgr.get_tool_config, name)
        if config:
            _collect(config, "Tool", name)

    for name in mcp_names:
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, name)
        if config:
            _collect(config, "MCP", name)
                
    # 2. Get current user/global secrets and variables
    user_identity = Identity.from_string(user_id)
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)

    current_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, user_identity, "secrets")
    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    current_variables = await asyncio.to_thread(identity_mgr.get_identity_config, user_identity, "variables")
    global_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")
    
    # 3. Compile unified configuration items (filtering out system-wide overridden globals)
    items = []
    
    # Process variables
    for var_key, tools in required_variables.items():
        if var_key not in global_variables:
            items.append({
                "key": var_key,
                "type": "variable",
                "label": "Variable",
                "tools": tools,
                "is_global": False,
                "value": current_variables.get(var_key, ''),
                "placeholder": f"Enter {var_key}"
            })
            
    # Process secrets (required)
    for secret_key, tools in required_secrets.items():
        if secret_key not in global_secrets and secret_key not in grouped_keys:
            items.append({
                "key": secret_key,
                "type": "secret",
                "label": "Secret",
                "tools": tools,
                "is_global": False,
                "value": "",  # Secrets are masked from display
                "placeholder": "******** (leave blank to keep current)" if secret_key in current_secrets else f"Enter {secret_key}"
            })

    # Process secrets (optional) — absence never blocks the agent, but the user
    # can still fill them in here.
    for secret_key, tools in optional_secrets_map.items():
        if secret_key not in global_secrets and secret_key not in required_secrets and secret_key not in grouped_keys:
            items.append({
                "key": secret_key,
                "type": "secret",
                "label": "Optional Secret",
                "tools": tools,
                "is_global": False,
                "value": "",
                "placeholder": "******** (leave blank to keep current)" if secret_key in current_secrets else f"Enter {secret_key} (optional)"
            })

    # Process secret groups (e.g. netctl's per-environment credentials) — one
    # card per group, with every option's fields present so switching the
    # selector never discards values already entered for other options.
    for group, group_view in zip(secret_groups, _build_secret_group_view(secret_groups, current_secrets)):
        for option in group_view["options"]:
            for field in option["fields"]:
                key = field["key"]
                field["value"] = ""
                field["placeholder"] = "******** (leave blank to keep current)" if key in current_secrets else f"Enter {field.get('label', key)}"
        items.append({
            "key": group_view.get("label", "Credential Group"),
            "type": "secret_group",
            "label": "Credential Group",
            "tools": group.get("tools", []),
            "select_label": group_view.get("select_label", "Option"),
            "options": group_view["options"]
        })

    # Sort items alphabetically by key name
    items.sort(key=lambda x: x["key"].lower())
    
    flash_msg = request.session.pop("flash_msg", None)
    
    return templates.TemplateResponse(
        request=request,
        name="configuration.html",
        context={
            "user": user,
            "items": items,
            "flash_msg": flash_msg
        }
    )

@router.post("/configuration")
async def save_configuration(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    user_id = user['sub']
    form = await request.form()
    
    tool_names = await asyncio.to_thread(identity_mgr.list_tools)
    mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
    known_secrets = set()
    known_variables = set()

    def _collect_known(config: Dict):
        secrets_data = config.get("secrets", [])
        if isinstance(secrets_data, dict):
            known_secrets.update(secrets_data.get("general", []))
            known_secrets.update(secrets_data.get("user", []))
        elif isinstance(secrets_data, list):
            known_secrets.update(secrets_data)

        known_secrets.update(config.get("optional_secrets", []) or [])

        for group in config.get("secret_groups", []) or []:
            for option in group.get("options", []):
                for field in option.get("fields", []):
                    known_secrets.add(field["key"])

        vars_data = config.get("variables", [])
        if isinstance(vars_data, dict):
            known_variables.update(vars_data.get("general", []))
            known_variables.update(vars_data.get("user", []))
        elif isinstance(vars_data, list):
            known_variables.update(vars_data)

    for name in tool_names:
        config = await asyncio.to_thread(identity_mgr.get_tool_config, name)
        if config:
            _collect_known(config)

    for name in mcp_names:
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, name)
        if config:
            _collect_known(config)
    
    user_identity = Identity.from_string(user_id)
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)

    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    global_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")

    await apply_configuration_form(
        form,
        user_identity,
        known_secrets=known_secrets,
        known_variables=known_variables,
        global_secrets=global_secrets,
        global_variables=global_variables,
        identity_mgr=identity_mgr,
    )

    request.session["flash_msg"] = "Settings and configuration saved successfully."
    return RedirectResponse(url='/configuration', status_code=303)
