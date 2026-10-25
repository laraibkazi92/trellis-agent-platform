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

Two operational caveats: (1) if the very first policy read fails, the cache falls
back to the cold snapshot (mode ``off``) until a read succeeds -- authz fails open
only while the framework has never seen a policy; (2) tool calls made *through an
agent* resolve to ``agent:<name>``/``workflow:<name>``, so user- and group-scoped
rules only apply to direct gateway calls unless the rule names those principals.
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

POLICY_PATH = "/registry/tool_policies"
MODE_KEY = "tool_authz_mode"
GROUPS_KEY = "principal_groups"
_WATCH_PREFIXES = (POLICY_PATH, f"/config/framework/{MODE_KEY}", f"/config/framework/{GROUPS_KEY}")

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

# --- shadow-deny ring ---------------------------------------------------------

_deny_ring: "deque[Dict[str, Any]]" = deque(maxlen=SHADOW_DENY_CAP)
_deny_lock = threading.Lock()
_DENY_PERSIST_MIN_INTERVAL_S = 1.0
_last_deny_persist: float = 0.0

# Cache of agent name -> is background (for workflow principal classification).
_agent_type_cache: Dict[str, Tuple[float, bool]] = {}
_agent_type_lock = threading.Lock()
_AGENT_TYPE_TTL_S = 60.0

_watch_ids: Optional[List[Any]] = None


def _cold_snapshot() -> Dict[str, Any]:
    return {"policy": {}, "mode": "off", "groups": {}}


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
        groups = mgr.get_principal_groups()
        fresh = {
            "policy": policy if isinstance(policy, dict) else {},
            "mode": mode if mode in MODES else "off",
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


def _groups_for(principal: str) -> Set[str]:
    """Request-claim groups unioned with the etcd principal->group mapping."""
    groups: Set[str] = set(_request_groups.get() or ())
    config = _load_groups()

    direct = config.get(principal)
    if isinstance(direct, list):
        groups.update(direct)
    if principal.startswith("user:"):
        bare = config.get(principal[len("user:"):])
        if isinstance(bare, list):
            groups.update(bare)
    return groups


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


def _record_deny(principal: str, tool: str, scope: str, mode: str) -> None:
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
    with _deny_lock:
        _deny_ring.append(entry)
    logger.warning(json.dumps({
        "event": "tool_authz_deny",
        "mode": mode,
        "principal": principal,
        "tool": tool,
        "scope": scope,
        "matched_rule": entry["matched_rule"],
    }))

    # Persist a sampled copy to the shared ring: the Admin UI is a separate process
    # and cannot see this one's deque. Throttled so a deny-everything policy cannot
    # turn every tool call into an etcd write.
    now = time.monotonic()
    if now - _last_deny_persist < _DENY_PERSIST_MIN_INTERVAL_S:
        return
    _last_deny_persist = now
    try:
        from core.auth import get_identity_manager

        get_identity_manager().append_tool_authz_deny(dict(entry), SHADOW_DENY_CAP)
    except Exception as e:
        logger.debug("Failed to persist tool_authz denial: %s", e)


def allowed(principal: str, tool: str, scope: str) -> bool:
    """Mode-aware verdict: ``off`` never denies, ``shadow`` logs and allows."""
    mode = get_mode()
    if mode == "off":
        return True
    decision, _rule = evaluate(principal, tool, scope)
    if decision == "allow":
        return True
    _record_deny(principal or "anonymous", tool or "", scope or "", mode)
    return mode != "enforcing"


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
    """Publish the caller's OIDC group claim for the current request/task.

    Not wired by the HTTP layer yet: no current entry point exposes OIDC groups to
    a tool call, so ``group:`` rules resolve from ``/config/framework/principal_groups``
    in practice. Kept as the seam for when the claim is propagated.
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


def bootstrap_policy(tool_configs: Dict[str, Any], mcp_configs: Dict[str, Any]) -> Dict[str, Any]:
    """One explicit rule per currently-public tool, callable by everyone.

    Tightening later is deleting lines, so the generated document doubles as an
    inventory of what used to be reachable. Malformed configs are skipped.
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

    return {
        "default_action": "deny",
        "rules": [
            {"tools": [name], "allow_principals": ["*"], "scopes": list(SCOPES)}
            for name in sorted(names)
        ],
    }


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
