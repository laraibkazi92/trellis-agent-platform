"""Tests for the Phase B consolidation: core.health.evaluate_health_status is now
the single, shared, pure derivation of cooldown-aware status used by
HealthMonitor._evaluate_status, core.rules_engine.filter_eligible_agents, and the
/agents marketplace page. See __spec_docs/rules_engine_hardening_plan.md §2A.5 / Phase B.
"""
from datetime import datetime, timedelta, timezone

from core.health import HealthMonitor, compute_agent_operational_status, evaluate_health_status


def _offline(seconds_ago=None):
    status = {"status": "Offline", "consecutive_failures": 10, "last_error": "boom"}
    if seconds_ago is not None:
        status["last_failure_time"] = (
            datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
        ).isoformat()
    return status


def test_evaluate_health_status_passthrough_for_non_offline():
    status = {"status": "Online"}
    assert evaluate_health_status(status) is status


def test_evaluate_health_status_empty_dict_passthrough():
    assert evaluate_health_status({}) == {}


def test_evaluate_health_status_offline_within_cooldown_stays_offline():
    status = _offline(seconds_ago=5)
    result = evaluate_health_status(status, cooldown_seconds=60)
    assert result["status"] == "Offline"


def test_evaluate_health_status_offline_past_cooldown_becomes_half_open():
    status = _offline(seconds_ago=120)
    result = evaluate_health_status(status, cooldown_seconds=60)
    assert result["status"] == "Half-Open"
    # Pure function: deep-copies before mutating, never touches the caller's dict.
    assert status["status"] == "Offline"


def test_evaluate_health_status_offline_with_no_timestamp_stays_offline():
    """Fail-safe: an Offline record with no timestamp (e.g. malformed/legacy data)
    can never be cooled down, so it must never silently become Half-Open."""
    status = {"status": "Offline"}
    result = evaluate_health_status(status)
    assert result["status"] == "Offline"


def test_evaluate_health_status_respects_custom_cooldown():
    status = _offline(seconds_ago=15)
    assert evaluate_health_status(status, cooldown_seconds=10)["status"] == "Half-Open"
    assert evaluate_health_status(status, cooldown_seconds=20)["status"] == "Offline"


class _FakeIdentityMgrForHealthMonitor:
    """HealthMonitor.__init__ only stores this; _evaluate_status never touches it."""
    pass


def test_health_monitor_evaluate_status_delegates_to_free_function():
    monitor = HealthMonitor(_FakeIdentityMgrForHealthMonitor())
    monitor.cooldown_seconds = 30

    within_cooldown = _offline(seconds_ago=5)
    past_cooldown = _offline(seconds_ago=45)

    assert monitor._evaluate_status(within_cooldown)["status"] == "Offline"
    assert monitor._evaluate_status(past_cooldown)["status"] == "Half-Open"
    assert monitor._evaluate_status(past_cooldown) == evaluate_health_status(
        past_cooldown, cooldown_seconds=30
    )


# --- compute_agent_operational_status (Phase D: shared by core/host.py's /health
# handler and core/gateway.py's _get_visible_agents(), see
# __spec_docs/rules_engine_hardening_plan.md §2D) ---------------------------------

def test_compute_agent_operational_status_online_when_everything_healthy():
    result = compute_agent_operational_status(
        cfg={"allowed_tools": ["netctl"]},
        agent_health={"status": "Online"},
        tool_healths={"netctl": {"status": "Online"}},
    )
    assert result == {"status": "Online", "offline_tools": [], "agent_error": None}


def test_compute_agent_operational_status_offline_agent_takes_precedence_over_tools():
    """An agent's own Offline status wins even if none of its tools are offline --
    mirrors core/host.py's original 'Offline > Degraded > passthrough' precedence."""
    result = compute_agent_operational_status(
        cfg={"allowed_tools": ["netctl"]},
        agent_health=_offline(),
        tool_healths={"netctl": {"status": "Online"}},
    )
    assert result["status"] == "Offline"
    assert result["offline_tools"] == []
    assert result["agent_error"] == "boom"


def test_compute_agent_operational_status_degraded_when_tool_offline():
    result = compute_agent_operational_status(
        cfg={"allowed_tools": ["netctl", "other-tool"]},
        agent_health={"status": "Online"},
        tool_healths={"netctl": {"status": "Offline"}, "other-tool": {"status": "Online"}},
    )
    assert result["status"] == "Degraded"
    assert result["offline_tools"] == ["netctl"]


def test_compute_agent_operational_status_half_open_tool_is_not_offline():
    """A tool past its cooldown (Half-Open) is not counted as offline for Degraded."""
    result = compute_agent_operational_status(
        cfg={"allowed_tools": ["netctl"]},
        agent_health={"status": "Online"},
        tool_healths={"netctl": _offline(seconds_ago=120)},
        cooldown_seconds=60,
    )
    assert result["status"] == "Online"
    assert result["offline_tools"] == []


def test_compute_agent_operational_status_handles_missing_cfg_and_health_gracefully():
    """Decoration-only, no crash: an agent absent from every etcd map defaults cleanly."""
    result = compute_agent_operational_status(cfg={}, agent_health=None, tool_healths={})
    assert result == {"status": "Online", "offline_tools": [], "agent_error": None}
