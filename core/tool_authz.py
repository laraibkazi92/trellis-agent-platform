# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Default-deny tool authorization: the boundary policy for tool listing and calls.

A tool is reachable only through an explicit matching rule -- no rule, no access.
Rollout is staged so the gate ships dark: ``off`` (no-op) -> ``shadow`` (log
would-be denials, still allow) -> ``enforcing`` (deny). The policy document, the
mode and the principal->group map are read through one 30 s snapshot that etcd
watches invalidate, so admin edits apply without a restart.

Denials are logged as structured JSON (principal, tool, scope, rule index) and
never include tool arguments.

Surfaces share this engine but not their rollout switch: ``use_tool``/``search_tools``
are governed by ``tool_authz_mode``, tools bound directly to an agent call
``allowed(..., surface="bound_tool")`` and follow ``bound_tools_mode``, and direct hub
``/tools/call`` traffic uses ``hub_call_mode`` via ``surface="hub_direct"`` (see
``mode_for_surface``).

Two operational caveats: (1) if the very first policy read fails, the cache falls
back to the cold snapshot (mode ``off``) until a read succeeds -- authz fails open
only while the framework has never seen a policy; (2) tool calls made *through an
agent* resolve to ``agent:<name>``/``workflow:<name>``, so user- and group-scoped
rules only apply to direct gateway calls unless the rule names those principals.

Group membership comes from the identity provider's groups claim (stored on the user
record at login), unioned with the manual ``/config/framework/principal_groups``
mapping. The claim is published per request by the ASGI middleware; without it
(hub-dispatched calls, background runs, the admin page) the stored record is read
through a 30 s cache.
"""

import fnmatch
import json
import logging
import threading
import time
from collections import deque
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

MODES = ("off", "shadow", "enforcing")
SCOPES = ("tools:read", "tools:call")
SHADOW_DENY_CAP = 200

# Denial-ring tag for the gate that produced an entry. Bound tools (registered straight
# onto an agent from `allowed_tools`/`allowed_mcps`) never reach `use_tool`, so their
# wrappers run the same evaluator under their own rollout mode. Direct hub `/tools/call`
# requests are the other untagged surface: they carry a principal only because the hub
# verifies the agent token on the call itself.
BOUND_TOOL_SURFACE = "bound_tool"
HUB_DIRECT_SURFACE = "hub_direct"

POLICY_PATH = "/registry/tool_policies"
MODE_KEY = "tool_authz_mode"
BOUND_TOOLS_MODE_KEY = "bound_tools_mode"
HUB_CALL_MODE_KEY = "hub_call_mode"
GROUPS_KEY = "principal_groups"
_WATCH_PREFIXES = (
    POLICY_PATH,
    f"/config/framework/{MODE_KEY}",
    f"/config/framework/{BOUND_TOOLS_MODE_KEY}",
    f"/config/framework/{HUB_CALL_MODE_KEY}",
    f"/config/framework/{GROUPS_KEY}",
)

# Which snapshot field holds each surface's rollout mode. A surface missing from this
# map is a bug in the caller, not a reason to inherit someone else's rollout state.
_SURFACE_MODE_KEYS = {
    None: "mode",
    BOUND_TOOL_SURFACE: "bound_mode",
    HUB_DIRECT_SURFACE: "hub_mode",
}


CACHE_TTL_S = 30.0
CACHE_ERROR_TTL_S = 5.0

# --- snapshot cache (policy + mode + groups) ---------------------------------

_snapshot: Optional[Dict[str, Any]] = None
_snapshot_expiry: float = 0.0
_snapshot_generation = 0
_snapshot_lock = threading.Lock()

# Groups asserted by the caller (the OIDC claim path). None == "no claim seen".
_request_groups: ContextVar[Optional[Tuple[str, ...]]] = ContextVar(
    "tool_authz_request_groups", default=None
)

# IdP groups stored on the user record at login, read only when no request-scoped
# claim was published (hub-dispatched calls, background runs, the admin page). Small
# and short-lived: a group change at the IdP is visible within a login refresh.
USER_GROUPS_TTL_S = 30.0
USER_GROUPS_ERROR_TTL_S = 5.0
USER_GROUPS_CACHE_MAX = 256
_user_groups_cache: Dict[str, Tuple[float, Tuple[str, ...]]] = {}
_user_groups_lock = threading.Lock()

# --- shadow-deny ring ---------------------------------------------------------

_deny_ring: "deque[Dict[str, Any]]" = deque(maxlen=SHADOW_DENY_CAP)
_deny_lock = threading.Lock()
_DENY_PERSIST_MIN_INTERVAL_S = 1.0
# Throttled per surface: a busy use_tool denial must not starve bound_tool entries out
# of the shared ring (the operator reads it to decide whether a surface is safe to flip).
_last_deny_persist: Dict[str, float] = {}

# Cache of agent name -> is background (for workflow principal classification).
_agent_type_cache: Dict[str, Tuple[float, bool]] = {}
_agent_type_lock = threading.Lock()
_AGENT_TYPE_TTL_S = 60.0

_watch_ids: Optional[List[Any]] = None


def _cold_snapshot() -> Dict[str, Any]:
    return {
        "policy": {},
        "mode": "off",
        "bound_mode": "off",
        "hub_mode": "off",
        "groups": {},
    }


def _snapshot_values(attempt: int = 0) -> Dict[str, Any]:
    """Cached authz state; any read failure keeps the previous snapshot."""
    global _snapshot, _snapshot_expiry
    with _snapshot_lock:
        if _snapshot is not None and time.monotonic() < _snapshot_expiry:
            return _snapshot
        generation = _snapshot_generation

    try:
        from core.auth import get_identity_manager

        mgr = get_identity_manager()
        policy = mgr.get_tool_policies()
        mode = mgr.get_tool_authz_mode()
        # A registry stand-in without the bound-tools accessor is simply "never rolled
        # out" (off); a real manager that returns junk fails closed, as above.
        read_bound_mode = getattr(mgr, "get_bound_tools_mode", None)
        bound_mode = read_bound_mode() if callable(read_bound_mode) else "off"
        read_hub_mode = getattr(mgr, "get_hub_call_mode", None)
        hub_mode = read_hub_mode() if callable(read_hub_mode) else "off"
        groups = mgr.get_principal_groups()
        fresh = {
            "policy": policy if isinstance(policy, dict) else {},
            "mode": mode if mode in MODES else "off",
            "bound_mode": bound_mode if bound_mode in MODES else "enforcing",
            "hub_mode": hub_mode if hub_mode in MODES else "enforcing",
            "groups": groups if isinstance(groups, dict) else {},
        }
    except Exception as e:
        logger.warning("Failed to read tool authorization state: %s", e)
        with _snapshot_lock:
            # Short negative window, as in guardrails: otherwise a cold/expired
            # cache retries the full @retry_etcd budget on every single tool call.
            if _snapshot is None:
                _snapshot = _cold_snapshot()
            _snapshot_expiry = time.monotonic() + CACHE_ERROR_TTL_S
            return _snapshot

    with _snapshot_lock:
        if _snapshot_generation == generation:
            _snapshot = fresh
            _snapshot_expiry = time.monotonic() + CACHE_TTL_S
            return fresh

    # A reset landed mid-read: re-read once rather than handing this caller the
    # stale document the reset meant to discard.
    if attempt == 0:
        return _snapshot_values(attempt + 1)
    return fresh


def reset_cache() -> None:
    """Drop the cached policy/mode/groups snapshot; the next read goes to etcd."""
    global _snapshot, _snapshot_expiry, _snapshot_generation
    with _snapshot_lock:
        _snapshot_generation += 1
        _snapshot = None
        _snapshot_expiry = 0.0


def get_mode() -> str:
    """Current rollout mode (``off`` when unset or unreadable)."""
    mode = _snapshot_values().get("mode")
    return mode if mode in MODES else "off"


def get_bound_tools_mode() -> str:
    """Current agent-bound-tool rollout mode (``off`` when unset or unreadable)."""
    mode = _snapshot_values().get("bound_mode")
    return mode if mode in MODES else "off"


def get_hub_call_mode() -> str:
    """Current direct-hub-call rollout mode (``off`` when unset or unreadable)."""
    mode = _snapshot_values().get("hub_mode")
    return mode if mode in MODES else "off"


def cached_mode_for_surface(surface: Optional[str] = None) -> Optional[str]:
    """The mode from the last snapshot, without any etcd I/O; ``None`` when cold.

    Bound tools and hub calls need this: ``off`` (the default) must stay free of authz
    reads, and a full snapshot load under an etcd outage blocks for the retry budget. A
    caller that gets ``None`` must fall back to :func:`mode_for_surface` (one blocking
    read). An unknown surface fails closed to ``enforcing`` here too, so a caller that
    never teaches this map about its surface cannot inherit the ``use_tool`` switch.
    """
    with _snapshot_lock:
        snapshot = _snapshot
    if snapshot is None:
        return None
    key = _SURFACE_MODE_KEYS.get(surface)
    if key is None:
        logger.error(
            "tool_authz: unknown surface %r; failing closed to 'enforcing'", surface
        )
        return "enforcing"
    mode = snapshot.get(key)
    return mode if mode in MODES else None


def mode_for_surface(surface: Optional[str] = None) -> str:
    """The rollout mode governing ``surface``.

    ``bound_tool`` and ``hub_direct`` have their own keys so each gate can be promoted
    on its own schedule; ``None`` is the ``use_tool``/``search_tools`` gate and uses
    ``tool_authz_mode``. A surface with no configured switch fails closed: a new
    enforcement point must never silently inherit someone else's rollout state.
    """
    if surface == BOUND_TOOL_SURFACE:
        return get_bound_tools_mode()
    if surface == HUB_DIRECT_SURFACE:
        return get_hub_call_mode()
    if surface is None:
        return get_mode()
    logger.error("tool_authz: unknown surface %r; failing closed to 'enforcing'", surface)
    return "enforcing"


def load_policy() -> Dict[str, Any]:
    """The raw policy document ({} when unset or unreadable)."""
    policy = _snapshot_values().get("policy")
    return policy if isinstance(policy, dict) else {}


def _load_groups() -> Dict[str, List[str]]:
    raw = _snapshot_values().get("groups")
    if not isinstance(raw, dict):
        return {}
    return {
        str(principal): [str(group) for group in groups]
        for principal, groups in raw.items()
        if isinstance(groups, (list, tuple, set))
    }


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_policy(policy: Any) -> List[str]:
    """Human-readable schema errors; ``[]`` means the policy is usable."""
    if not isinstance(policy, dict):
        return ["policy must be a JSON object"]
    errors: List[str] = []
    unknown = set(policy) - {"default_action", "rules"}
    if unknown:
        errors.append(f"unknown policy fields: {', '.join(sorted(map(str, unknown)))}")
    try:
        json.dumps(policy)
    except (TypeError, ValueError):
        errors.append("policy must be JSON-serializable (quote values such as dates)")
    if policy.get("default_action") != "deny":
        errors.append('default_action must be "deny"')
    rules = policy.get("rules")
    if not isinstance(rules, list):
        errors.append("rules must be a list")
        return errors

    for index, rule in enumerate(rules):
        prefix = f"rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix} must be an object")
            continue
        unknown_rule = set(rule) - {"tools", "allow_principals", "scopes", "rate_limit_per_min"}
        if unknown_rule:
            errors.append(
                f"{prefix} has unknown fields: {', '.join(sorted(map(str, unknown_rule)))}"
            )
        for field in ("tools", "allow_principals"):
            value = rule.get(field)
            if not isinstance(value, list):
                errors.append(f"{prefix}.{field} must be a list")
            elif any(not isinstance(entry, str) or not entry.strip() for entry in value):
                errors.append(f"{prefix}.{field} must contain non-empty strings")
        scopes = rule.get("scopes")
        if scopes is not None:
            if not isinstance(scopes, list):
                errors.append(f"{prefix}.scopes must be a list")
            elif any(not isinstance(s, str) or s not in SCOPES for s in scopes):
                errors.append(f"{prefix}.scopes must contain only {', '.join(SCOPES)}")
        rate = rule.get("rate_limit_per_min")
        if rate is not None and not _is_number(rate):
            errors.append(f"{prefix}.rate_limit_per_min must be a number")
    return errors


def _principal_matches(pattern: Any, principal: str, groups: Set[str]) -> bool:
    if not isinstance(pattern, str):
        return False
    if pattern == "*" or pattern == principal:
        return True
    if pattern.startswith("group:"):
        return pattern[len("group:"):] in groups
    return False


def _rule_matches(rule: Dict[str, Any], principal: str, tool: str, scope: str, groups: Set[str]) -> bool:
    scopes = rule.get("scopes")
    if scopes is None:
        scopes = SCOPES  # absent scopes == both scopes
    elif not isinstance(scopes, list):
        return False
    if scope not in scopes:
        return False

    tools = rule.get("tools")
    if not isinstance(tools, list):
        return False
    if not any(isinstance(p, str) and fnmatch.fnmatchcase(tool, p) for p in tools):
        return False

    principals = rule.get("allow_principals")
    if not isinstance(principals, list):
        return False
    return any(_principal_matches(p, principal, groups) for p in principals)


def _stored_user_groups(principal: str) -> Set[str]:
    """IdP groups stored on ``user:<id>``'s record, cached for ~30 s.

    Only reachable for user principals: ``agent:``/``workflow:`` calls have no user
    record of their own. Any read failure grants "no groups" (a ``group:``
    rule then simply does not match) and is cached for a few seconds so an etcd
    outage cannot turn every tool call into a retry-budget read.
    """
    if not principal.startswith("user:"):
        return set()
    user_id = principal[len("user:"):]
    if not user_id:
        return set()

    now = time.monotonic()
    with _user_groups_lock:
        cached = _user_groups_cache.get(user_id)
        if cached is not None and now < cached[0]:
            return set(cached[1])

    expiry = now + USER_GROUPS_TTL_S
    values: Tuple[str, ...] = ()
    try:
        from core.auth import get_identity_manager, normalize_groups

        read_user = getattr(get_identity_manager(), "get_user", None)
        record = read_user(user_id) if callable(read_user) else None
        if isinstance(record, dict):
            values = tuple(normalize_groups(record.get("groups")))
    except Exception as e:
        logger.debug("Failed to read stored groups for %r: %s", principal, e)
        expiry = now + USER_GROUPS_ERROR_TTL_S

    with _user_groups_lock:
        if len(_user_groups_cache) >= USER_GROUPS_CACHE_MAX:
            _user_groups_cache.clear()
        _user_groups_cache[user_id] = (expiry, values)
    return set(values)


def _groups_for(principal: str) -> Set[str]:
    """Caller groups: the request claim (else the stored IdP groups) ∪ the etcd mapping.

    The mapping is a manual grant unioned on top -- it can add a group but cannot
    revoke one the identity provider asserted.
    """
    claimed = _request_groups.get()
    groups: Set[str] = set(claimed or ())
    if claimed is None:
        # No claim in this context (hub-dispatched call, background run, admin page):
        # fall back to what the identity provider stored on the user record at login.
        groups |= _stored_user_groups(principal)
    config = _load_groups()

    direct = config.get(principal)
    if isinstance(direct, list):
        groups.update(direct)
    if principal.startswith("user:"):
        bare = config.get(principal[len("user:"):])
        if isinstance(bare, list):
            groups.update(bare)
    return groups


def resolved_groups(principal: str) -> List[str]:
    """Sorted groups a principal resolves to right now (read-only, for the admin UI)."""
    return sorted(_groups_for(principal or "anonymous"))


def evaluate(principal: str, tool: str, scope: str) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Ordered, mode-independent verdict; first matching rule wins, no match denies."""
    principal = principal or "anonymous"
    policy = load_policy()
    if validate_policy(policy):
        return "deny", None
    groups = _groups_for(principal)
    for rule in policy["rules"]:
        if _rule_matches(rule, principal, tool or "", scope or "", groups):
            return "allow", rule
    return "deny", None


def _record_deny(
    principal: str, tool: str, scope: str, mode: str, surface: Optional[str] = None
) -> None:
    global _last_deny_persist
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "principal": principal,
        "tool": tool,
        "scope": scope,
        "mode": mode,
        # Default-deny means a refusal never matches a rule; the field is kept so
        # the ring/log shape stays stable if rule-level reasons are added later.
        "matched_rule": None,
    }
    # Only tagged surfaces carry it: entries written before bound tools existed (and
    # by the use_tool gate, which is the default) keep their exact shape.
    if surface:
        entry["surface"] = surface
    with _deny_lock:
        _deny_ring.append(entry)
    logged = {
        "event": "tool_authz_deny",
        "mode": mode,
        "principal": principal,
        "tool": tool,
        "scope": scope,
        "matched_rule": entry["matched_rule"],
    }
    if surface:
        logged["surface"] = surface
    logger.warning(json.dumps(logged))

    # Persist a sampled copy to the shared ring: the Admin UI is a separate process
    # and cannot see this one's deque. Throttled per surface so a deny-everything
    # policy cannot turn every tool call into an etcd write, while one surface's
    # traffic cannot hide another's denials from the operator.
    now = time.monotonic()
    key = surface or ""
    if now - _last_deny_persist.get(key, 0.0) < _DENY_PERSIST_MIN_INTERVAL_S:
        return
    _last_deny_persist[key] = now
    try:
        from core.auth import get_identity_manager

        get_identity_manager().append_tool_authz_deny(dict(entry), SHADOW_DENY_CAP)
    except Exception as e:
        logger.debug("Failed to persist tool_authz denial: %s", e)


def allowed(
    principal: str,
    tool: str,
    scope: str,
    surface: Optional[str] = None,
    mode: Optional[str] = None,
) -> bool:
    """Mode-aware verdict for ``surface`` (default: the ``use_tool`` gate).

    ``off`` never denies, ``shadow`` logs and allows, ``enforcing`` denies. The mode is
    resolved per surface (``bound_tool`` has its own key), and the denial is tagged with
    the surface it came from. Pass ``mode`` when the caller already resolved it (the
    bound-tool fast path does) so a single call cannot see two different modes.
    """
    resolved = mode or mode_for_surface(surface)
    if resolved == "off":
        return True
    decision, _rule = evaluate(principal, tool, scope)
    if decision == "allow":
        return True
    _record_deny(principal or "anonymous", tool or "", scope or "", resolved, surface)
    return resolved != "enforcing"


def shadow_denies() -> List[Dict[str, Any]]:
    """Denials, newest first: the shared etcd ring when readable, else this process."""
    try:
        from core.auth import get_identity_manager

        shared = get_identity_manager().get_tool_authz_denies()
        if shared:
            return shared[:SHADOW_DENY_CAP]
    except Exception as e:
        logger.debug("Failed to read shared tool_authz denials: %s", e)
    with _deny_lock:
        return [dict(entry) for entry in reversed(_deny_ring)]


def clear_shadow_denies() -> None:
    """Empty the shared and in-process denial rings."""
    with _deny_lock:
        _deny_ring.clear()
    try:
        from core.auth import get_identity_manager

        get_identity_manager().clear_tool_authz_denies()
    except Exception as e:
        logger.debug("Failed to clear shared tool_authz denials: %s", e)


def set_request_groups(groups: Iterable[str]) -> None:
    """Publish the caller's group claim for the current request/task.

    Set by the ASGI auth middleware from the user record it already loaded (the
    identity provider's groups claim, stored at login). While it is set, ``group:``
    rules resolve from it instead of re-reading the record.
    """
    if isinstance(groups, str):
        groups = [groups]
    values = sorted({str(group).strip() for group in (groups or ()) if str(group).strip()})
    _request_groups.set(tuple(values))


def clear_request_groups() -> None:
    """Forget the request-scoped group claim."""
    _request_groups.set(None)


def _is_background_agent(name: str) -> bool:
    """True when the agent's config type is a background workflow (cached 60s)."""
    if not name:
        return False
    now = time.monotonic()
    with _agent_type_lock:
        cached = _agent_type_cache.get(name)
        if cached and now < cached[0]:
            return cached[1]
    try:
        from core.auth import get_identity_manager

        config = get_identity_manager().get_agent_config(name) or {}
        is_background = config.get("type") in ("background_agent", "background_script")
    except Exception:
        logger.debug("Could not classify agent %r for principal resolution", name, exc_info=True)
        return False
    with _agent_type_lock:
        _agent_type_cache[name] = (now + _AGENT_TYPE_TTL_S, is_background)
    return is_background


def principal_for(claims: Optional[Any], user_id: Optional[str]) -> str:
    """Classify one caller from verified token claims plus the resolved user id.

    Shared by both enforcement paths so they cannot disagree about who is calling:
    :func:`resolve_current_principal` feeds it the run context's token, and the hub's
    direct ``/tools/call`` gate feeds it the token verified off the request. Ordering
    is fixed -- background run/agent (``workflow:<agent>``), gateway-with-user
    (``user:<id>``), any other token (``agent:<name>``), then the user id alone, then
    ``anonymous``.
    """
    if claims is not None:
        # Background runs are classified by the named agent's config type, not just
        # the `svc_agent_` identity convention (webhook runs use `user_id="webhook"`).
        if (claims.user_id and str(claims.user_id).startswith("svc_agent_")) or _is_background_agent(
            claims.agent
        ):
            return f"workflow:{claims.agent}"
        if claims.agent == "gateway" and user_id:
            return f"user:{user_id}"
        return f"agent:{claims.agent}"
    return f"user:{user_id}" if user_id else "anonymous"


def resolve_current_principal() -> str:
    """Classify the current caller from the run token plus user context."""
    try:
        from core import agent_token
        from core.auth import agent_token_var, user_id_var

        claims = agent_token.verify_or_none(agent_token_var.get())
        user_id = user_id_var.get()
    except Exception:  # no auth module / no contextvars in this process
        logger.debug("Principal resolution unavailable", exc_info=True)
        return "anonymous"

    return principal_for(claims, user_id)


def _mcp_names_for_server(server: str, config: Any) -> Set[str]:
    """Every ``mcp__<server>__<tool>`` name one MCP config declares."""
    if not isinstance(config, dict):
        return set()
    tools = config.get("tools")
    if not isinstance(tools, list):
        return set()
    names: Set[str] = set()
    for entry in tools:
        if isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str) and name:
                names.add(f"mcp__{server}__{name}")
    return names


def _agent_bound_names(config: Dict[str, Any], mcps_map: Dict[str, Any]) -> Set[str]:
    """Policy names of the tools one agent binds directly (``allowed_tools``/``allowed_mcps``).

    Bound tools never pass through ``use_tool``, so nothing else would ever put them in
    the bootstrap document. Console tools are capabilities, not hub tools: they are not
    part of the policy language and must not appear in a generated rule.
    """
    from core.allowlist import CONSOLE_TOOLS

    names: Set[str] = set()
    for tool in config.get("allowed_tools") or []:
        if isinstance(tool, str) and tool and tool not in CONSOLE_TOOLS:
            names.add(tool)
    for entry in config.get("allowed_mcps") or []:
        if not isinstance(entry, str) or not entry:
            continue
        if entry.endswith("__*"):
            site = entry[: -len("__*")]
            for server in mcps_map:
                if server.startswith(f"{site}__"):
                    names |= _mcp_names_for_server(server, mcps_map[server])
        elif entry in mcps_map:
            names |= _mcp_names_for_server(entry, mcps_map[entry])
        else:
            names.update(n for n in _mcp_names_for_server(entry, {}) if n)
    return names


def bootstrap_policy(
    tool_configs: Dict[str, Any],
    mcp_configs: Dict[str, Any],
    agent_configs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """One explicit rule per currently-public tool, callable by everyone.

    Tightening later is deleting lines, so the generated document doubles as an
    inventory of what used to be reachable. Malformed configs are skipped.

    When ``agent_configs`` is supplied, each agent also gets one rule per tool it binds
    directly (``allowed_tools``/``allowed_mcps``), granted to its own principal only
    (``agent:<name>``, or ``workflow:<name>`` for background types). Those tools never
    reach ``use_tool``, so without this the bound-tool gate would have no rule to match
    and no in-product remediation path.
    """
    tools_map = tool_configs if isinstance(tool_configs, dict) else {}
    mcps_map = mcp_configs if isinstance(mcp_configs, dict) else {}

    names: Set[str] = set()
    for key, config in tools_map.items():
        if not isinstance(config, dict) or config.get("public") is not True:
            continue
        name = config.get("name", key)
        if isinstance(name, str) and name:
            names.add(name)

    for server, config in mcps_map.items():
        if not isinstance(server, str) or not server or not isinstance(config, dict):
            continue
        public_tools_raw = config.get("public_tools", [])
        public_tools = set(public_tools_raw) if isinstance(public_tools_raw, list) else set()
        every_tool = config.get("public") is True
        tools = config.get("tools", [])
        if not isinstance(tools, list):
            continue
        for entry in tools:
            if not isinstance(entry, dict):
                continue
            tool_name = entry.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                continue
            if every_tool or tool_name in public_tools:
                names.add(f"mcp__{server}__{tool_name}")

    rules = [
        {"tools": [name], "allow_principals": ["*"], "scopes": list(SCOPES)}
        for name in sorted(names)
    ]
    if isinstance(agent_configs, dict):
        for agent_name, config in agent_configs.items():
            if not isinstance(agent_name, str) or not agent_name or not isinstance(config, dict):
                continue
            bound = _agent_bound_names(config, mcps_map)
            if not bound:
                continue
            kind = (
                "workflow"
                if config.get("type") in ("background_agent", "background_script")
                else "agent"
            )
            rules.append(
                {
                    "tools": sorted(bound),
                    "allow_principals": [f"{kind}:{agent_name}"],
                    "scopes": list(SCOPES),
                }
            )
    return {"default_action": "deny", "rules": rules}


def _on_authz_change(event) -> None:
    """etcd watch callback (sync): drop the cached snapshot."""
    reset_cache()


def install_tool_authz_watch() -> None:
    """Register the authz etcd watches (idempotent, one per process)."""
    global _watch_ids
    if _watch_ids is not None:
        return
    from core.auth import get_identity_manager

    client = get_identity_manager().client
    watch_ids: List[Any] = []
    try:
        for prefix in _WATCH_PREFIXES:
            watch_ids.append(client.add_watch_prefix_callback(prefix, _on_authz_change))
    except Exception:
        for watch_id in watch_ids:
            try:
                client.cancel_watch(watch_id)
            except Exception:
                logger.debug("Failed to cancel a partial authz watch", exc_info=True)
        raise
    _watch_ids = watch_ids


def cancel_tool_authz_watch() -> None:
    """Cancel the authz watches and clear the sentinel (idempotent)."""
    global _watch_ids
    watch_ids, _watch_ids = _watch_ids, None
    if not watch_ids:
        return
    from core.auth import get_identity_manager

    client = get_identity_manager().client
    for watch_id in watch_ids:
        client.cancel_watch(watch_id)
