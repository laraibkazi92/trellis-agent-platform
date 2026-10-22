# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
import asyncio
import logging
from typing import Any, List, Dict, Optional
from core.auth import get_identity_manager
from core.models import BACKGROUND_AGENT_TYPES, Identity, IdentityType

logger = logging.getLogger(__name__)

# Bind the shared IdentityManager singleton for discovery purposes
identity_mgr = get_identity_manager()

def _resolve_requirements(req_data, is_background: bool) -> List[str]:
    """Resolves requirements based on agent context (background vs standard)."""
    if not req_data:
        return []
    if isinstance(req_data, list):
        return req_data
    if isinstance(req_data, dict):
        result = list(req_data.get("general", []))
        if is_background:
            result.extend(req_data.get("background", []))
        else:
            result.extend(req_data.get("user", []))
        return result
    return []

async def get_agent_required_secrets(config: Dict, strict: bool = False) -> List[str]:
    """Helper to determine all required secrets for an agent based on its config, tools, and MCPs.

    Delegates to the shared :func:`_resolve_agent_requirements` algorithm via
    :func:`_fetch_agent_tool_mcp_configs`. Fail-soft by default: failed tool/MCP
    lookups are dropped instead of raising on the first failure -- the same
    tolerance :func:`is_agent_configured` already had. Pass ``strict=True`` to
    re-raise a failed tool/MCP lookup instead (preserving the pre-refactor
    behavior); the default fails soft.
    """
    tool_configs, mcp_configs = await _fetch_agent_tool_mcp_configs(config, strict=strict)
    return sorted(_resolve_agent_requirements(config, tool_configs, mcp_configs)["required_secrets"])

async def get_agent_optional_secrets(config: Dict, strict: bool = False) -> List[str]:
    """Helper to determine all optional secrets for an agent's allowed tools and MCPs.

    Optional secrets are informational — their absence does not block the agent
    from being configured. When present they are injected into the MCP process env.

    Delegates to the shared :func:`_resolve_agent_requirements` algorithm via
    :func:`_fetch_agent_tool_mcp_configs`. Fail-soft by default: failed tool/MCP
    lookups are dropped instead of raising on the first failure -- the same
    tolerance :func:`is_agent_configured` already had. Pass ``strict=True`` to
    re-raise a failed tool/MCP lookup instead (preserving the pre-refactor
    behavior); the default fails soft.
    """
    tool_configs, mcp_configs = await _fetch_agent_tool_mcp_configs(config, strict=strict)
    return sorted(_resolve_agent_requirements(config, tool_configs, mcp_configs)["optional_secrets"])

async def get_agent_secret_groups(config: Dict, strict: bool = False) -> List[Dict]:
    """Helper to determine all secret-group credential sets (e.g. netctl's
    per-environment username/password dropdown) declared by an agent's
    directly-attached tools and MCPs.

    An ``mcp__``-prefixed ``allowed_tools`` entry resolves to its owning MCP's
    ``secret_groups``, exactly as :func:`get_agent_required_secrets` already resolves
    that same entry's ``secrets`` — fixed as part of Phase C (§2C.3 of the rules
    engine hardening plan), since this function's caller
    (``core/routers/marketplace.py``'s configure-agent save handler) is the only way a
    user can satisfy a secret_groups requirement that :func:`is_agent_configured`/
    :func:`discover_agents` now (correctly, post-Phase-C) gate on.

    Resolves via the shared :func:`_resolve_agent_requirements` helper. Fail-soft by
    default: failed tool/MCP lookups are dropped instead of raising on the first
    failure -- the same tolerance :func:`is_agent_configured` already had. Pass
    ``strict=True`` to re-raise a failed tool/MCP lookup instead (preserving the
    pre-refactor behavior); the default fails soft.
    """
    tool_configs, mcp_configs = await _fetch_agent_tool_mcp_configs(config, strict=strict)
    return _resolve_agent_requirements(config, tool_configs, mcp_configs)["secret_groups"]

def flatten_secret_group_keys(secret_groups: List[Dict]) -> set:
    """Flattens a list of secret_groups into the set of underlying secret keys."""
    keys = set()
    for group in secret_groups:
        for option in group.get("options", []):
            for field in option.get("fields", []):
                keys.add(field["key"])
    return keys

def _build_secret_group_view(secret_groups_raw: List[Dict], current_secrets: Dict) -> List[Dict]:
    """Normalize raw secret_groups into the per-field ``is_set`` view used by the UI.

    Shared by :func:`discover_agents` and :func:`get_tool_configuration_context`
    (and, via :func:`flatten_secret_group_keys`, by the routers' save handlers).
    """
    view = []
    for group in secret_groups_raw:
        options = []
        for option in group.get("options", []):
            fields = []
            for field in option.get("fields", []):
                fields.append({
                    "key": field["key"],
                    "label": field.get("label", field["key"]),
                    "type": field.get("type", "password"),
                    "is_set": field["key"] in current_secrets,
                })
            options.append({
                "value": option.get("value"),
                "label": option.get("label", option.get("value")),
                "fields": fields
            })
        view.append({
            "label": group.get("label", "Credential Group"),
            "select_label": group.get("select_label", "Option"),
            "options": options
        })
    return view

def _unsatisfied_secret_group_keys(secret_groups: List[Dict], available_secrets: Dict) -> List[str]:
    """Returns the keys of secret_groups where no single option has all its fields set.

    Grouped credentials (e.g. netctl's per-environment username/password) are declared as
    optional_secrets precisely because a user only needs ONE option (e.g. one environment)
    configured, not all of them. But "at least one option's keys are individually present in
    optional_secrets" is not the same as "at least one option is fully configured" — a group
    with zero options configured must still surface as missing, or is_tool_configured/
    is_agent_configured silently reports configured=True for a tool the user has never set up.
    """
    missing = []
    for group in secret_groups:
        options = group.get("options", [])
        if not options:
            continue
        satisfied = any(
            option.get("fields") and all(f["key"] in available_secrets for f in option["fields"])
            for option in options
        )
        if not satisfied:
            for option in options:
                for field in option.get("fields", []):
                    if field["key"] not in available_secrets and field["key"] not in missing:
                        missing.append(field["key"])
    return missing

async def get_agent_required_variables(config: Dict, strict: bool = False) -> List[str]:
    """Helper to determine all required non-sensitive variables for an agent based on its config, tools, and MCPs.

    Delegates to the shared :func:`_resolve_agent_requirements` algorithm via
    :func:`_fetch_agent_tool_mcp_configs`. Fail-soft by default: failed tool/MCP
    lookups are dropped instead of raising on the first failure -- the same
    tolerance :func:`is_agent_configured` already had. Pass ``strict=True`` to
    re-raise a failed tool/MCP lookup instead (preserving the pre-refactor
    behavior); the default fails soft.
    """
    tool_configs, mcp_configs = await _fetch_agent_tool_mcp_configs(config, strict=strict)
    return sorted(_resolve_agent_requirements(config, tool_configs, mcp_configs)["required_variables"])

def _mcp_key_for_tool_name(tool_name: str, mcp_configs: Dict[str, Dict]) -> Optional[str]:
    """Registry key of the MCP server owning an ``mcp__...`` tool name.

    Resolution is against the configs at hand, never the name's shape alone: a 4+-part
    name is an edge server (``<site>__<mcp>``) only when that config exists, otherwise it
    is a central server whose *tool* name contains ``__`` (``mcp__srv__do__thing`` ->
    ``srv``). Without the 4-vs-3 branch, a 4-part edge name would look up the site name
    as a central MCP and absorb that unrelated server's secrets.
    """
    parts = tool_name.split("__")
    if len(parts) < 3:
        return None
    if len(parts) >= 4:
        edge_key = f"{parts[1]}__{parts[2]}"
        if edge_key in mcp_configs:
            return edge_key
    return parts[1]


async def resolve_edge_mcp_target(
    tool_name: str, identity_manager: Optional[Any] = None
) -> Optional[tuple[str, str, str]]:
    """``(site, mcp, tool)`` when ``tool_name`` names an edge-exported MCP tool.

    Registry-backed, never shape-based: an ``mcp__`` name is an edge target only when
    ``<parts[1]>__<parts[2]>`` is a registered MCP config **carrying a ``remote`` block**.
    Everything else -- including a central server whose own tool name contains ``__``
    (``mcp__srv__do__thing``) -- reads as central and returns ``None``. The tool half is
    re-joined so an edge tool name may itself contain ``__``.
    """
    if not tool_name.startswith("mcp__"):
        return None
    parts = tool_name.split("__")
    if len(parts) < 4 or not parts[1] or not parts[2]:
        return None
    mgr = identity_manager or identity_mgr
    config = await asyncio.to_thread(mgr.get_mcp_config, f"{parts[1]}__{parts[2]}")
    remote = (config or {}).get("remote")
    if not isinstance(remote, dict) or not remote.get("site") or not remote.get("mcp"):
        return None
    return str(remote["site"]), str(remote["mcp"]), "__".join(parts[3:])


def _resolve_agent_requirements(
    config: Dict,
    tool_configs: Dict[str, Dict],
    mcp_configs: Dict[str, Dict],
) -> Dict:
    """Pure aggregation of an agent's required/optional secrets, required variables,
    and raw ``secret_groups`` from its own config plus its ``allowed_tools``/
    ``allowed_mcps``, given pre-fetched tool/mcp config dicts.

    This is the single requirement-resolution algorithm shared by
    :func:`is_agent_configured` (which fetches just the handful of tool/mcp configs
    this one agent needs) and :func:`discover_agents` (which passes in its own
    bulk-prefetched ``all_tool_configs``/``all_mcp_configs`` for the whole catalog) —
    no I/O happens here, so neither caller's performance characteristics change.
    """
    is_background = config.get("type") in BACKGROUND_AGENT_TYPES
    required_secrets = set()
    required_variables = set()
    optional_secrets = set()
    secret_groups: List[Dict] = []

    if config.get("secrets"):
        required_secrets.update(_resolve_requirements(config.get("secrets"), is_background))
    if config.get("variables"):
        required_variables.update(_resolve_requirements(config.get("variables"), is_background))

    def _absorb(cfg: Dict):
        if cfg.get("secrets"):
            required_secrets.update(_resolve_requirements(cfg.get("secrets"), is_background))
        if cfg.get("variables"):
            required_variables.update(_resolve_requirements(cfg.get("variables"), is_background))
        if cfg.get("optional_secrets"):
            optional_secrets.update(_resolve_requirements(cfg.get("optional_secrets"), is_background))
        if cfg.get("secret_groups"):
            secret_groups.extend(cfg.get("secret_groups"))

    for tool_name in config.get("allowed_tools", []):
        tool_config = tool_configs.get(tool_name)
        if tool_config:
            _absorb(tool_config)
        elif tool_name.startswith("mcp__"):
            mcp_key = _mcp_key_for_tool_name(tool_name, mcp_configs)
            if mcp_key:
                mcp_config = mcp_configs.get(mcp_key)
                if mcp_config:
                    _absorb(mcp_config)

    for mcp_name in config.get("allowed_mcps", []):
        mcp_config = mcp_configs.get(mcp_name)
        if mcp_config:
            _absorb(mcp_config)

    return {
        "required_secrets": required_secrets,
        "required_variables": required_variables,
        "optional_secrets": optional_secrets,
        "secret_groups": secret_groups,
    }


def _evaluate_agent_configuration(
    required_secrets,
    required_variables,
    optional_secrets,
    secret_groups: List[Dict],
    global_secrets: Dict,
    global_variables: Dict,
    identity_secrets: Dict,
    identity_variables: Dict,
) -> Dict:
    """Given an agent's aggregated requirements (from :func:`_resolve_agent_requirements`)
    plus pre-fetched global/identity secret & variable dicts, compute the
    configured/missing_secrets/missing_variables/optional_missing_secrets result.

    Mirrors :func:`is_tool_configured`'s already-correct pattern: a key declared via a
    ``secret_groups`` option is excluded from the plain required/optional lists (it's
    only satisfiable as part of its group, not individually) and group satisfaction is
    checked via :func:`_unsatisfied_secret_group_keys`. Previously neither
    ``is_agent_configured`` nor ``discover_agents`` performed this group-satisfaction
    check at all, so an agent depending on a tool/MCP with ``secret_groups`` where the
    user has configured zero complete option could incorrectly report
    ``is_configured: True`` (rules engine hardening plan §4, finding 5) --
    this function fixes that for both callers at once.
    """
    grouped_keys = flatten_secret_group_keys(secret_groups)

    user_required_secrets = sorted(s for s in required_secrets if s not in global_secrets and s not in grouped_keys)
    user_required_variables = sorted(v for v in required_variables if v not in global_variables)
    user_optional_secrets = sorted(s for s in optional_secrets if s not in global_secrets and s not in grouped_keys)

    available_secrets = {**global_secrets, **identity_secrets}
    missing_group_keys = _unsatisfied_secret_group_keys(secret_groups, available_secrets)

    missing_secrets = [s for s in user_required_secrets if s not in identity_secrets]
    missing_secrets += [k for k in missing_group_keys if k not in missing_secrets]
    missing_variables = [v for v in user_required_variables if v not in identity_variables]
    optional_missing_secrets = [s for s in user_optional_secrets if s not in identity_secrets]

    return {
        "configured": not missing_secrets and not missing_variables,
        "missing_secrets": missing_secrets,
        "missing_variables": missing_variables,
        "optional_missing_secrets": optional_missing_secrets,
        "required_secrets": user_required_secrets,
        "required_variables": user_required_variables,
    }


async def _fetch_agent_tool_mcp_configs(config: Dict, strict: bool = False) -> "tuple[Dict[str, Dict], Dict[str, Dict]]":
    """Fetch just the tool/mcp configs this one agent's ``allowed_tools``/``allowed_mcps``
    reference, keyed the same way :func:`discover_agents`'s bulk
    ``all_tool_configs``/``all_mcp_configs`` are -- so both can be handed to the same
    :func:`_resolve_agent_requirements`. Deliberately per-agent (not a full bulk fetch):
    this is the single-agent path, called from a point-of-use context where fetching
    the entire catalog's tool/mcp configs would be wasted work.
    """
    direct_tools: List[str] = []
    mcp_names = set(config.get("allowed_mcps", []))

    for tool_name in config.get("allowed_tools", []):
        if tool_name.startswith("mcp__"):
            # Same registry-backed branch the aggregation uses: a 4-part name is an
            # edge server only if that server is actually registered, so a central
            # MCP never gets looked up under an edge site's name.
            try:
                target = await resolve_edge_mcp_target(tool_name)
            except Exception as exc:
                # Fail soft like the config gathers below: a registry hiccup must not
                # turn into an exception out of is_agent_configured when the caller did
                # not ask for strict mode.
                if strict:
                    raise
                logger.warning("Could not resolve edge MCP target for %r: %s", tool_name, exc)
                target = None
            if target:
                mcp_names.add(f"{target[0]}__{target[1]}")
            else:
                parts = tool_name.split("__", 2)
                if len(parts) >= 3 and parts[1]:
                    mcp_names.add(parts[1])
            continue
        direct_tools.append(tool_name)

    tool_configs: Dict[str, Dict] = {}
    if direct_tools:
        tool_results = await asyncio.gather(
            *(asyncio.to_thread(identity_mgr.get_tool_config, t) for t in direct_tools),
            return_exceptions=True,
        )
        for t_name, t_cfg in zip(direct_tools, tool_results):
            if isinstance(t_cfg, BaseException):
                if strict:
                    raise t_cfg
                logger.warning("Dropping failed %s config lookup for %r: %s", "tool", t_name, t_cfg)
            elif t_cfg:
                tool_configs[t_name] = t_cfg

    mcp_configs: Dict[str, Dict] = {}
    if mcp_names:
        sorted_mcps = sorted(mcp_names)
        mcp_results = await asyncio.gather(
            *(asyncio.to_thread(identity_mgr.get_mcp_config, m) for m in sorted_mcps),
            return_exceptions=True,
        )
        for m_name, m_cfg in zip(sorted_mcps, mcp_results):
            if isinstance(m_cfg, BaseException):
                if strict:
                    raise m_cfg
                logger.warning("Dropping failed %s config lookup for %r: %s", "mcp", m_name, m_cfg)
            elif m_cfg:
                mcp_configs[m_name] = m_cfg

    return tool_configs, mcp_configs


async def is_agent_configured(agent_name: str, user_id: Optional[str] = None) -> Dict:
    """Check if a specific agent is configured for a user.

    Returns a dict with keys:
      - configured (bool)
      - missing_secrets (List[str])
      - missing_variables (List[str])
      - optional_missing_secrets (List[str])  — informational; does not affect configured
    """
    if agent_name == "supervisor":
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    config = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    if not config:
        return {"configured": False, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    is_background = config.get("type") in BACKGROUND_AGENT_TYPES

    tool_configs, mcp_configs = await _fetch_agent_tool_mcp_configs(config)
    resolved = _resolve_agent_requirements(config, tool_configs, mcp_configs)

    system_identity = Identity(id="system", type=IdentityType.SYSTEM)
    global_secrets, global_variables = await asyncio.gather(
        asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets"),
        asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables"),
    )

    grouped_keys = flatten_secret_group_keys(resolved["secret_groups"])
    user_required_secrets = [s for s in resolved["required_secrets"] if s not in global_secrets and s not in grouped_keys]
    user_required_variables = [v for v in resolved["required_variables"] if v not in global_variables]
    user_optional_secrets = [s for s in resolved["optional_secrets"] if s not in global_secrets and s not in grouped_keys]

    # Cheap early exit before paying for the identity secrets/variables fetch below --
    # preserved from the pre-Phase-C implementation for the common case (nothing
    # required at all). Unlike the pre-Phase-C version, this also requires
    # `secret_groups` to be empty: a group can be unsatisfied even when nothing is
    # required outside of it, and that can only be determined by checking it against
    # the identity's configured secrets below.
    if not user_required_secrets and not user_required_variables and not user_optional_secrets and not resolved["secret_groups"]:
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    if is_background:
        identity = Identity(id=agent_name, type=IdentityType.WORKFLOW)
    elif user_id:
        identity = Identity.from_string(user_id)
    else:
        identity = None

    if identity:
        ident_secrets, ident_variables = await asyncio.gather(
            asyncio.to_thread(identity_mgr.get_identity_config, identity, "secrets"),
            asyncio.to_thread(identity_mgr.get_identity_config, identity, "variables"),
        )
    else:
        ident_secrets = {}
        ident_variables = {}

    # Pass the raw (unfiltered) resolved requirements plus the real global dicts --
    # `_evaluate_agent_configuration` does its own global/grouped-key exclusion, so
    # filtering again here would be redundant work and, worse, would need `global_secrets`
    # passed as real data anyway for the group-satisfaction check (a group can be
    # satisfied by a globally-set secret, not just a per-identity one).
    evaluated = _evaluate_agent_configuration(
        required_secrets=resolved["required_secrets"],
        required_variables=resolved["required_variables"],
        optional_secrets=resolved["optional_secrets"],
        secret_groups=resolved["secret_groups"],
        global_secrets=global_secrets,
        global_variables=global_variables,
        identity_secrets=ident_secrets,
        identity_variables=ident_variables,
    )

    return {
        "configured": evaluated["configured"],
        "missing_secrets": evaluated["missing_secrets"],
        "missing_variables": evaluated["missing_variables"],
        "optional_missing_secrets": evaluated["optional_missing_secrets"],
    }

async def discover_agents(
    user_id: Optional[str] = None,
    include_background: bool = False,
    agent_configs: Optional[Dict[str, Dict]] = None,
    agent_health: Optional[Dict[str, Dict]] = None,
) -> List[Dict]:
    """Scan etcd registry for agents using optimized bulk fetching.

    ``agent_configs``/``agent_health`` may be passed in by a caller that already did
    this exact bulk fetch for its own purposes (e.g. ``core/gateway.py``'s
    ``_get_visible_agents()``, which also needs them directly to compute per-agent
    operational status) -- this avoids fetching the whole catalog's configs/health
    twice in the same request. Fetched internally, as before, when omitted.

    Background agents' per-identity secrets/variables are prefetched concurrently
    before the scan loop; if either fetch fails for an identity, both fall back to
    ``{}`` for that identity (fail-soft -- the legacy per-agent awaits propagated
    the exception).
    """
    agents = []

    # Bulk fetch everything needed for agents
    if agent_configs is None:
        agent_configs = await asyncio.to_thread(identity_mgr.get_all_agent_configs)
    if agent_health is None:
        agent_health = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "agent")
    agent_skills = await asyncio.to_thread(identity_mgr.get_all_agent_skills)

    system_identity = Identity(id="system", type=IdentityType.SYSTEM)
    # Cache global secrets and variables once per discovery
    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    global_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")
    
    # If a user is provided, pre-fetch their secrets and variables for standard agents
    human_user_secrets = {}
    human_user_variables = {}
    if user_id:
        user_identity = Identity.from_string(user_id)
        human_user_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, user_identity, "secrets")
        human_user_variables = await asyncio.to_thread(identity_mgr.get_identity_config, user_identity, "variables")
    
    # Pre-fetch tool and MCP configs to speed up secret resolution
    all_tool_configs = await asyncio.to_thread(identity_mgr.get_all_tool_configs)
    all_mcp_configs = await asyncio.to_thread(identity_mgr.get_all_mcp_configs)

    bg_config_secrets: Dict[str, Dict] = {}
    bg_config_variables: Dict[str, Dict] = {}
    if include_background:
        bg_identities = [
            Identity(id=n, type=IdentityType.WORKFLOW)
            for n, c in agent_configs.items()
            if n != "supervisor" and c.get("type") in BACKGROUND_AGENT_TYPES
        ]
        if bg_identities:
            identity_results = await asyncio.gather(
                *(asyncio.gather(
                    asyncio.to_thread(identity_mgr.get_identity_config, ident, "secrets"),
                    asyncio.to_thread(identity_mgr.get_identity_config, ident, "variables"),
                ) for ident in bg_identities),
                return_exceptions=True,
            )
            for ident, result in zip(bg_identities, identity_results):
                if isinstance(result, BaseException):
                    logger.warning("Dropping failed identity lookup for %r: %s", ident.id, result)
                    bg_config_secrets[ident.id] = {}
                    bg_config_variables[ident.id] = {}
                    continue
                s, v = result
                bg_config_secrets[ident.id] = {} if not s else s
                bg_config_variables[ident.id] = {} if not v else v

    for name, config in agent_configs.items():
        if name == "supervisor":
            continue
            
        is_background = config.get("type") in BACKGROUND_AGENT_TYPES
        
        if is_background and not include_background:
            continue
            
        skills_content = agent_skills.get(name, "")
        health = agent_health.get(name)

        # Requirement resolution using pre-fetched bulk configs -- same pure algorithm
        # is_agent_configured uses, just handed the whole catalog's tool/mcp configs
        # instead of fetching a per-agent subset, preserving this function's bulk
        # performance design.
        resolved = _resolve_agent_requirements(config, all_tool_configs, all_mcp_configs)
        secret_groups_raw = resolved["secret_groups"]

        current_config_secrets = {}
        current_config_variables = {}

        if is_background:
            current_config_secrets = bg_config_secrets.get(name, {})
            current_config_variables = bg_config_variables.get(name, {})
        else:
            current_config_secrets = human_user_secrets
            current_config_variables = human_user_variables

        # Same evaluator is_agent_configured uses -- this is what wires
        # _unsatisfied_secret_group_keys into discover_agents for the first time,
        # fixing the bug where an agent depending on a tool/MCP with secret_groups and
        # zero fully-configured options could incorrectly report is_configured: True
        # (see rules_engine_hardening_plan.md §4 finding 5 / Phase C).
        evaluated = _evaluate_agent_configuration(
            required_secrets=resolved["required_secrets"],
            required_variables=resolved["required_variables"],
            optional_secrets=resolved["optional_secrets"],
            secret_groups=secret_groups_raw,
            global_secrets=global_secrets,
            global_variables=global_variables,
            identity_secrets=current_config_secrets,
            identity_variables=current_config_variables,
        )
        is_configured = evaluated["configured"]
        missing_secrets = evaluated["missing_secrets"]
        missing_variables = evaluated["missing_variables"]
        optional_missing_secrets = evaluated["optional_missing_secrets"]
        user_required_secrets = evaluated["required_secrets"]
        user_required_variables = evaluated["required_variables"]

        agent_secret_groups = _build_secret_group_view(secret_groups_raw, current_config_secrets)

        agents.append({
            "name": config.get("name", name),
            "type": config.get("type", "user_agent"),
            "author": config.get("author", "Unknown"),
            "description": config.get("description", ""),
            "tags": config.get("tags", []),
            "capabilities": config.get("capabilities", []),
            "skills": skills_content,
            "a2a_access": config.get("a2a_access", []),
            "model": config.get("model") or "gemini-3-flash-preview",
            "thinking_level": config.get("thinking_level", "medium"),
            "version": config.get("version", "0.1.0"),
            "external": config.get("external", True),
            "internal": config.get("internal", True),
            "health": health or {"status": "Online"},
            "required_secrets": user_required_secrets,
            "required_variables": user_required_variables,
            "is_configured": is_configured,
            "missing_secrets": missing_secrets,
            "missing_variables": missing_variables,
            "optional_missing_secrets": optional_missing_secrets,
            "current_variables": current_config_variables,
            "secret_groups": agent_secret_groups
         })

    agents.sort(key=lambda x: x["name"].lower())
    return agents

async def _remote_tool_configuration_status(site: str) -> Dict:
    """Readiness of an edge-hosted tool: connected edge or nothing.

    Mirrors :func:`is_tool_configured`'s return shape exactly. There are no central
    secrets to check (they live on the edge), so an offline edge is reported as the
    missing requirement — labelled so the caller gets an actionable message instead
    of a blank "not configured".

    Fails **open** on a registry read error: an etcd hiccup must not make every
    remote tool look broken.
    """
    try:
        status = await asyncio.to_thread(identity_mgr.get_edge_status, site)
    except Exception as e:
        logger.warning(f"Could not read edge status for '{site}': {e}")
        status = {"connected": True}
    if isinstance(status, dict) and status.get("connected") is True:
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}
    return {
        "configured": False,
        "missing_secrets": [],
        "missing_variables": [f"edge '{site}' is not connected"],
        "optional_missing_secrets": [],
    }


async def is_tool_configured(tool_name: str, user_id: Optional[str] = None) -> Dict:
    """Check if a specific tool (local or MCP, e.g. ``mcp__{server}__{name}``) is
    configured for a user.

    An edge-hosted MCP tool (``mcp__{site}__{mcp}__{name}``) resolves to its
    ``<site>__<mcp>`` registry entry and, being a remote entry, is gated on edge
    connectivity instead of central secrets. Which reading applies is decided by
    :func:`resolve_edge_mcp_target` (registry-backed), never by the name's shape.

    Reuses the same secret/variable resolution primitives as :func:`is_agent_configured`
    (``_resolve_requirements``, ``flatten_secret_group_keys``) but resolves requirements
    from the tool's/MCP's own config rather than an agent's ``allowed_tools``/``allowed_mcps``
    aggregation. Direct tool execution has no "background" context, so ``_resolve_requirements``
    is always called with ``is_background=False`` (i.e. dict-shaped requirements resolve their
    ``general`` + ``user`` keys).

    A tool declaring ``secret_groups`` (e.g. opsctl/netctl's per-environment credential picker)
    is only considered configured once at least one option's full field set is present —
    see :func:`_unsatisfied_secret_group_keys`. As of Phase C of the rules engine
    hardening plan, :func:`is_agent_configured` and
    :func:`discover_agents` apply this same group-satisfaction check via
    :func:`_evaluate_agent_configuration`, so all three configuration-readiness checks now
    agree on secret_groups semantics.

    Returns a dict with keys:
      - configured (bool)
      - missing_secrets (List[str])
      - missing_variables (List[str])
      - optional_missing_secrets (List[str])  — informational; does not affect configured
    """
    not_configured = {"configured": False, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    if tool_name.startswith("mcp__"):
        target = await resolve_edge_mcp_target(tool_name)
        if target:
            # Edge-exported MCP server: the registry key is <site>__<mcp>.
            server_name = f"{target[0]}__{target[1]}"
        else:
            # Central reading: the tail after `mcp__<server>__` is the tool name, even
            # when it contains "__" itself.
            parts = tool_name.split("__", 2)
            if len(parts) < 3 or not parts[1]:
                return not_configured
            server_name = parts[1]
        config = await asyncio.to_thread(identity_mgr.get_mcp_config, server_name)
    else:
        config = await asyncio.to_thread(identity_mgr.get_tool_config, tool_name)

    if not config:
        return not_configured

    # Edge-hosted tools and MCP servers have no central secrets or variables at
    # all: their only requirement is that the owning edge is currently connected.
    # A remote spec short-circuits before the secret resolution below (which would
    # otherwise report every remote entry as configured and hide an offline edge).
    remote = config.get("remote")
    if isinstance(remote, dict) and remote.get("site"):
        return await _remote_tool_configuration_status(str(remote["site"]))

    required_secrets = _resolve_requirements(config.get("secrets"), False)
    required_variables = _resolve_requirements(config.get("variables"), False)
    optional_secrets = _resolve_requirements(config.get("optional_secrets"), False)
    secret_groups = config.get("secret_groups") or []
    grouped_keys = flatten_secret_group_keys(secret_groups)

    system_identity = Identity(id="system", type=IdentityType.SYSTEM)
    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")
    global_variables = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "variables")

    user_required_secrets = [s for s in required_secrets if s not in global_secrets and s not in grouped_keys]
    user_required_variables = [v for v in required_variables if v not in global_variables]
    user_optional_secrets = [s for s in optional_secrets if s not in global_secrets and s not in grouped_keys]

    if not user_id:
        available_secrets = global_secrets
        missing_group_keys = _unsatisfied_secret_group_keys(secret_groups, available_secrets)
        missing_secrets = user_required_secrets + [k for k in missing_group_keys if k not in user_required_secrets]
        return {
            "configured": not missing_secrets and not user_required_variables,
            "missing_secrets": missing_secrets,
            "missing_variables": user_required_variables,
            "optional_missing_secrets": user_optional_secrets,
        }

    identity = Identity.from_string(user_id)
    ident_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, identity, "secrets")
    ident_variables = await asyncio.to_thread(identity_mgr.get_identity_config, identity, "variables")

    # Reuse the agent-level evaluator (same grouped-key exclusion + group-satisfaction
    # check) instead of re-deriving the user-path result by hand.
    evaluated = _evaluate_agent_configuration(
        required_secrets=required_secrets,
        required_variables=required_variables,
        optional_secrets=optional_secrets,
        secret_groups=secret_groups,
        global_secrets=global_secrets,
        global_variables=global_variables,
        identity_secrets=ident_secrets,
        identity_variables=ident_variables,
    )

    return {
        "configured": evaluated["configured"],
        "missing_secrets": evaluated["missing_secrets"],
        "missing_variables": evaluated["missing_variables"],
        "optional_missing_secrets": evaluated["optional_missing_secrets"],
    }

async def get_tool_configuration_context(tool_name: str, user_id: str) -> Optional[Dict]:
    """Build the full credential-configuration context for a single publicly-exposed
    local tool, for rendering an inline "Configure Tool" form directly on the Tools page.

    This is the per-tool analog of ``discover_agents()``'s per-agent secret/variable/
    secret_group aggregation — but a tool's config is already flat (no allowed_tools/
    allowed_mcps aggregation needed, unlike an agent which can pull requirements from
    many attached tools/MCPs). Delegates the configured/missing-secrets determination to
    :func:`is_tool_configured` (single source of truth) and only adds what that function
    doesn't return: the *full* required/optional secret and variable lists (so the form
    can show already-configured fields too, not just missing ones), current variable
    values, and per-field ``is_set`` flags for secret_groups — mirroring the shape
    ``discover_agents()`` already builds for agent cards.

    Returns ``None`` if the tool isn't found. Only intended for local tools (MCP tools'
    credentials are configured at the server level, not per-tool).
    """
    config = await asyncio.to_thread(identity_mgr.get_tool_config, tool_name)
    if not config:
        return None

    status = await is_tool_configured(tool_name, user_id)

    required_secrets = _resolve_requirements(config.get("secrets"), False)
    optional_secrets = _resolve_requirements(config.get("optional_secrets"), False)
    required_variables = _resolve_requirements(config.get("variables"), False)
    secret_groups_raw = config.get("secret_groups") or []
    grouped_keys = flatten_secret_group_keys(secret_groups_raw)

    identity = Identity.from_string(user_id)
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)
    current_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, identity, "secrets")
    current_variables = await asyncio.to_thread(identity_mgr.get_identity_config, identity, "variables")
    global_secrets = await asyncio.to_thread(identity_mgr.get_identity_config, system_identity, "secrets")

    secret_groups = _build_secret_group_view(secret_groups_raw, current_secrets)

    return {
        "required_secrets": [s for s in required_secrets if s not in global_secrets and s not in grouped_keys],
        "optional_secrets": [s for s in optional_secrets if s not in global_secrets and s not in grouped_keys],
        "missing_secrets": status["missing_secrets"],
        "required_variables": required_variables,
        "missing_variables": status["missing_variables"],
        "current_variables": current_variables,
        "secret_groups": secret_groups,
        "is_configured": status["configured"],
    }

async def build_all_tools_view() -> List[Dict]:
    """Merged local + MCP tool list for configuration modals.

    Shape per entry: ``{name, type, source, version, description}`` where ``type`` is
    ``"local"`` (source ``"Hub"``) or ``"mcp"`` (source is the MCP server name).
    Sorted by name.
    """
    all_tools_data: List[Dict] = []
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
    return all_tools_data

async def discover_tools() -> List[Dict]:
    """Scan etcd registry for tools using optimized bulk fetching."""
    tools = []

    tool_configs = await asyncio.to_thread(identity_mgr.get_all_tool_configs)
    mcp_configs = await asyncio.to_thread(identity_mgr.get_all_mcp_configs)
    tool_health = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "tool")

    for name, config in tool_configs.items():
        health = tool_health.get(name)
        remote_spec = config.get("remote") if isinstance(config.get("remote"), dict) else None
        entry = {
            "name": config.get("name", name),
            "description": config.get("description", ""),
            "runtime": config.get("runtime") or ("remote" if remote_spec else "unknown"),
            "entrypoint": config.get("entrypoint", ""),
            "rel_path": config.get("rel_path", ""),
            "inputs": config.get("inputs", {}),
            "outputs": config.get("outputs", {}),
            "version": config.get("version", "0.1.0"),
            "health": health or {"status": "Online"},
            "is_mcp": False,
            "public": config.get("public") is True
        }
        if remote_spec:
            # Edge-hosted tools render their owning site; the payload shape for
            # every other tool is unchanged.
            entry["site"] = remote_spec.get("site")
        tools.append(entry)

    for mcp_name, mcp_config in mcp_configs.items():
        mcp_public = mcp_config.get("public") is True
        public_tools_raw = mcp_config.get("public_tools", [])
        public_tools = set(public_tools_raw) if isinstance(public_tools_raw, list) else set()
        if "tools" in mcp_config:
            for t in mcp_config["tools"]:
                inputs = {}
                if "inputSchema" in t and "properties" in t["inputSchema"]:
                    required = t["inputSchema"].get("required", [])
                    for prop_name, prop_details in t["inputSchema"]["properties"].items():
                        inputs[prop_name] = {
                            "type": prop_details.get("type", "string"),
                            "description": prop_details.get("description", ""),
                            "required": prop_name in required
                        }
                tools.append({
                    "name": t.get("name", ""),
                    "description": t.get("description", ""),
                    "runtime": "mcp",
                    "entrypoint": mcp_name,
                    "rel_path": "",
                    "inputs": inputs,
                    "outputs": {},
                    "version": "1.0.0",
                    "health": {"status": "Online"},
                    "is_mcp": True,
                    "mcp_source": mcp_name,
                    "public": mcp_public or t.get("name", "") in public_tools
                })

    tools.sort(key=lambda x: x["name"].lower())
    return tools
