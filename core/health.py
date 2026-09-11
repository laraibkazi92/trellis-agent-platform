import json
import os
import copy
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from core.auth import IdentityManager
import core.health_db as health_db

DEFAULT_HEALTH_COOLDOWN_SECONDS = int(os.getenv("HEALTH_COOLDOWN_SECONDS", "60"))


def compute_agent_operational_status(
    cfg: Dict[str, Any],
    agent_health: Optional[Dict[str, Any]],
    tool_healths: Dict[str, Dict[str, Any]],
    cooldown_seconds: int = DEFAULT_HEALTH_COOLDOWN_SECONDS,
) -> Dict[str, Any]:
    """Cross-reference an agent's own evaluated health against its ``allowed_tools``'
    health to derive the combined Online/Offline/Degraded status.

    Pure function (no I/O) so the two call sites that need this exact combined view --
    ``core/host.py``'s ``/health`` handler and ``core/gateway.py``'s
    ``_get_visible_agents()`` (Phase D, see ``rules_engine_hardening_plan.md`` §2D) --
    derive it identically instead of maintaining two independently-drifting copies of
    the same cross-reference logic.

    Returns ``{"status", "offline_tools", "agent_error"}``.
    """
    offline_tools = [
        t for t in cfg.get("allowed_tools", [])
        if evaluate_health_status(tool_healths.get(t) or {}, cooldown_seconds).get("status") == "Offline"
    ]
    agent_eval_status = evaluate_health_status(agent_health or {}, cooldown_seconds)
    status_val = agent_eval_status.get("status", "Online")
    status = "Offline" if status_val == "Offline" else ("Degraded" if offline_tools else status_val)
    return {
        "status": status,
        "offline_tools": offline_tools,
        "agent_error": agent_eval_status.get("last_error"),
    }


def evaluate_health_status(
    status: Dict[str, Any], cooldown_seconds: int = DEFAULT_HEALTH_COOLDOWN_SECONDS
) -> Dict[str, Any]:
    """Evaluate if an Offline status has exceeded its cooldown period and should
    transition to Half-Open for probe requests.

    Pure function (no I/O, only reads ``status`` and the system clock) so every
    caller that needs to know whether an agent is *actually* usable right now --
    ``core.agent_search._resolve_rule_lock``'s post-match availability check (rules
    engine, Phase E), the ``/agents`` marketplace page, and the ``/health`` endpoint --
    derives the same evaluated status from the same raw stored record, instead of
    independently reimplementing (and silently disagreeing on) the cooldown transform.
    """
    if not status or status.get("status") != "Offline":
        return status

    last_failure_str = status.get("last_failure_time") or status.get("offline_since")
    if last_failure_str:
        try:
            ts = last_failure_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if (now - dt).total_seconds() >= cooldown_seconds:
                eval_status = copy.deepcopy(status)
                eval_status["status"] = "Half-Open"
                return eval_status
        except Exception:
            pass
    return status


class HealthMonitor:
    def __init__(self, identity_mgr: "IdentityManager"):
        self.identity_mgr = identity_mgr
        self.failure_threshold = int(os.getenv("HEALTH_FAILURE_THRESHOLD", "10"))
        self.cooldown_seconds = int(os.getenv("HEALTH_COOLDOWN_SECONDS", "60"))
        # Initialize the health events database
        health_db.init_db()

    def _evaluate_status(self, status: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate if an Offline status has exceeded its cooldown period
        and should transition to Half-Open for probe requests.
        """
        return evaluate_health_status(status, self.cooldown_seconds)

    def record_event(self, entity_type: str, name: str, is_success: bool, error_details: Optional[str] = None) -> Dict[str, Any]:
        """
        Record a health event for an entity.
        Global failures (is_success=False) increment the failure counter.
        User-scoped failures should not be recorded as failures here.
        """
        raw_status = self.identity_mgr.get_health_status(entity_type, name) or {
            "status": "Online",
            "consecutive_failures": 0,
            "last_error": None
        }
        current_status = self._evaluate_status(raw_status)
        old_status_val = current_status.get("status", "Online")
        now_iso = datetime.now(timezone.utc).isoformat()
        
        if is_success:
            current_status["status"] = "Online"
            current_status["consecutive_failures"] = 0
            current_status["last_error"] = None
            current_status["last_failure_time"] = None
            current_status["offline_since"] = None
        else:
            current_status["consecutive_failures"] = current_status.get("consecutive_failures", 0) + 1
            current_status["last_failure_time"] = now_iso
            if error_details:
                current_status["last_error"] = error_details[:1000] # Truncate to prevent etcd bloat
            if old_status_val == "Half-Open" or current_status["consecutive_failures"] >= self.failure_threshold:
                current_status["status"] = "Offline"
                if not current_status.get("offline_since") or old_status_val != "Offline":
                    current_status["offline_since"] = now_iso
                
        new_status_val = current_status["status"]
        
        if old_status_val != new_status_val:
            # Log the change
            if new_status_val == "Offline":
                logger.warning(f"Circuit breaker tripped to Offline for {entity_type}/{name}. Consecutive failures: {current_status.get('consecutive_failures')}. Last error: {current_status.get('last_error')}")
            elif new_status_val == "Online":
                logger.info(f"Health status restored to Online for {entity_type}/{name}.")
            health_db.log_event(entity_type, name, new_status_val, current_status.get("last_error"))
            
            # Run cleanup synchronously; it's throttled internally to run at most once a day
            health_db.cleanup_old_events(30)

        self.identity_mgr.save_health_status(entity_type, name, current_status)
        return current_status

    def get_status(self, entity_type: str, name: str) -> Dict[str, Any]:
        """
        Retrieve the current health status of an entity, evaluating half-open state if cooled down.
        """
        status = self.identity_mgr.get_health_status(entity_type, name)
        if status is None:
            return {"status": "Online", "consecutive_failures": 0, "last_error": None}
        return self._evaluate_status(status)

    def reset_status(self, entity_type: str, name: str) -> Dict[str, Any]:
        """
        Manually reset the health status to Online.
        """
        return self.record_event(entity_type, name, is_success=True)
