"""Integration tests for the Trellis Rules Engine wiring — see
__spec_docs/rules_engine_spec.md and, for the Phase E behavior below,
__spec_docs/rules_engine_hardening_plan.md.

Covers core.agent_search.search_agents():
  - A confident, available rule match short-circuits ranking entirely (embed_text
    never called) and returns **exactly one** result, regardless of `limit` --
    including `limit <= 0` (Phase E, E1: no more "fill remaining slots").
  - A confident match on an agent that turns out to be offline or unconfigured is
    NOT honored as a lock -- it falls through to the ranked semantic fallback with a
    leading "unavailable match" note that does not count against `limit` (Phase E,
    E2/E3).
  - Health/configuration-readiness no longer affect rule *eligibility* -- an
    offline/unconfigured agent's rules are still compiled into the LLM prompt; only
    administratively disabled agents are excluded from eligibility outright (silent,
    no note).
  - No active rules configured anywhere skips the rules engine entirely (no
    discover_agents call) and behaves exactly like pre-rules-engine search.
  - A null rule match (e.g. confidence below threshold, or no rule fires) falls
    through cleanly to embedding-based ranking.
  - Any failure inside rule-lock resolution (etcd, discovery, or evaluate_rules
    itself) fails open to semantic ranking without raising.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from core import agent_search
from core.models import RuleEvaluationResult


class FakeIdentityManagerAgentSearch:
    def __init__(self, agent_configs, routing_rules=None):
        self._agent_configs = agent_configs
        self._routing_rules = routing_rules

    def get_all_agent_configs(self):
        return dict(self._agent_configs)

    def get_all_agent_embeddings(self):
        return {}

    def get_disabled_standard_agents(self):
        return []

    def get_all_health_statuses(self, kind):
        return {}

    def get_routing_rules(self):
        return self._routing_rules


def _troubleshooting_cfg(**overrides):
    cfg = dict(
        name="troubleshooting-agent",
        type="user_agent",
        external=True,
        description="Specialized agent for debugging Acme Troubleshooting Service issues.",
        rules=[
            {
                "description": "Acme troubleshooting service, packet captures, and flow-level network drops",
                "use_when": ["User requests packet capture (PCAP) inspection or troubleshooting session diagnostics"],
                "do_not_use_when": ["User is asking for an executive ticket summary or customer-facing status update"],
                "examples": ["Analyze the PCAP trace from Acme troubleshooting session 948"],
            }
        ],
    )
    cfg.update(overrides)
    return cfg


def _case_summary_cfg(**overrides):
    cfg = dict(
        name="ticket-summary-agent",
        type="user_agent",
        external=True,
        description="Generates structured executive summaries and ticket reports.",
        rules=[],
    )
    cfg.update(overrides)
    return cfg


async def _fake_discover_agents_all_configured(user_id=None):
    return [
        {"name": "troubleshooting-agent", "is_configured": True},
        {"name": "ticket-summary-agent", "is_configured": True},
    ]


def _fail_embed(*args, **kwargs):
    raise AssertionError("embed_text should not have been called")


def _fail_discover(*args, **kwargs):
    raise AssertionError("discover_agents should not have been called when no rules are configured")


# --- Rule short-circuit ---

def test_search_agents_rule_short_circuit_bypasses_embedding(monkeypatch):
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerAgentSearch(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "discover_agents", _fake_discover_agents_all_configured)
    monkeypatch.setattr(agent_search, "embed_text", _fail_embed)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        assert set(eligible_agents.keys()) == {"troubleshooting-agent"}
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="matched")

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    # limit == 1 exercises the pure short-circuit path — no fallback fill, no embedding call.
    results = asyncio.run(agent_search.search_agents("Analyze the PCAP trace from Acme troubleshooting session 948", limit=1))

    assert results == [{
        "name": "troubleshooting-agent",
        "description": "Specialized agent for debugging Acme Troubleshooting Service issues.",
        "status": "Online",
    }]


def test_search_agents_rule_lock_ignores_caller_limit(monkeypatch):
    """Phase E, E1: a rule lock always returns exactly one result, regardless of the
    caller's `limit` -- no more "fill remaining slots with semantic fallback". The
    embedding call must never happen once a lock fires, for any limit value."""
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerAgentSearch(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "discover_agents", _fake_discover_agents_all_configured)
    monkeypatch.setattr(agent_search, "embed_text", _fail_embed)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="matched")

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    expected = [{
        "name": "troubleshooting-agent",
        "description": "Specialized agent for debugging Acme Troubleshooting Service issues.",
        "status": "Online",
    }]

    for limit in (5, 0, -1, None):
        results = asyncio.run(agent_search.search_agents(
            "Analyze the PCAP trace from Acme troubleshooting session 948", limit=limit
        ))
        assert results == expected


# --- Locked agent's reported status is the evaluated one, not the raw one (Phase B) ---

def test_search_agents_locked_half_open_agent_reports_evaluated_status(monkeypatch):
    """Phase B/E: a circuit-breaker-recovered "Half-Open" agent counts as available for
    rules-engine locking. This availability check now happens in _resolve_rule_lock
    itself, post-match (Phase E, E3) -- filter_eligible_agents no longer considers
    health at all, so eligibility is unconditional; the match still resolves to a
    normal lock (not an "unavailable" note), and the lock's own `status` field must
    reflect the evaluated "Half-Open" status, not the raw stored "Offline" (see
    rules_engine_hardening_plan.md §2B, finding F3 from the Phase B adversarial
    review)."""
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    stale_failure = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()

    class FakeIdentityManagerHalfOpen(FakeIdentityManagerAgentSearch):
        def get_all_health_statuses(self, kind):
            return {"troubleshooting-agent": {"status": "Offline", "last_failure_time": stale_failure}}

    fake_identity = FakeIdentityManagerHalfOpen(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "discover_agents", _fake_discover_agents_all_configured)
    monkeypatch.setattr(agent_search, "embed_text", _fail_embed)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        # Eligibility is unconditional now (E2) -- present regardless of health.
        assert "troubleshooting-agent" in eligible_agents
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="matched")

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    results = asyncio.run(agent_search.search_agents("Analyze the PCAP trace from Acme troubleshooting session 948", limit=1))

    assert results == [{
        "name": "troubleshooting-agent",
        "description": "Specialized agent for debugging Acme Troubleshooting Service issues.",
        "status": "Half-Open",
    }]


# --- Disabled agents are never eligible for a rule lock; offline/unconfigured agents
# are eligible but produce an "unavailable match" note instead of a lock (Phase E) ---

def test_search_agents_unconfigured_matched_agent_produces_note_and_fallback(monkeypatch):
    """Phase E, E2/E3: an unconfigured agent's rules ARE compiled into the LLM prompt
    (no longer excluded from eligibility) -- but a confident match on it is not honored
    as a lock. search_agents falls through to the ranked semantic fallback and prepends
    an "unavailable match" note naming it, instead of silently hiding its rules from
    consideration the way pre-Phase-E filter_eligible_agents did."""
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerAgentSearch(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)

    async def fake_discover_agents_unconfigured(user_id=None):
        return [
            {"name": "troubleshooting-agent", "is_configured": False},
            {"name": "ticket-summary-agent", "is_configured": True},
        ]

    monkeypatch.setattr(agent_search, "discover_agents", fake_discover_agents_unconfigured)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0 if b else 0.0)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        # Eligibility no longer excludes unconfigured agents (E2).
        assert "troubleshooting-agent" in eligible_agents
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="matched")

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    results = asyncio.run(agent_search.search_agents("Analyze the PCAP trace from Acme troubleshooting session 948", limit=5))

    assert results[0] == {
        "name": "troubleshooting-agent",
        "description": (
            "The routing policy identified 'troubleshooting-agent' as the best match "
            "for this query, but it is currently not configured. Showing next-best "
            "alternatives below."
        ),
        "status": "Unconfigured",
        "unavailable_match": True,
    }
    # Both real candidates still appear as ranked alternatives after the note -- the
    # note is additional, per E1/E3, not a replacement for one of the real results.
    alternative_names = {r["name"] for r in results[1:]}
    assert alternative_names == {"troubleshooting-agent", "ticket-summary-agent"}
    assert len(results) == 3
    assert "unavailable_match" not in results[1]
    assert "unavailable_match" not in results[2]


def test_search_agents_offline_matched_agent_note_does_not_count_against_limit(monkeypatch):
    """Phase E, E1/E3: the "unavailable match" note is additional to the caller's
    `limit`, not subtracted from it -- a caller requesting `limit=2` still gets 2 real
    ranked alternatives, plus the note, when the rules engine's confident match turns
    out to be genuinely offline (no last_failure_time -- Phase B's fail-safe: it never
    cools down to Half-Open)."""
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
        "general-agent": _case_summary_cfg(name="general-agent", description="Handles general requests."),
    }

    class FakeIdentityManagerOffline(FakeIdentityManagerAgentSearch):
        def get_all_health_statuses(self, kind):
            return {"troubleshooting-agent": {"status": "Offline"}}

    fake_identity = FakeIdentityManagerOffline(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "discover_agents", _fake_discover_agents_all_configured)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0 if b else 0.0)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        assert "troubleshooting-agent" in eligible_agents
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="matched")

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    results = asyncio.run(agent_search.search_agents(
        "Analyze the PCAP trace from Acme troubleshooting session 948", limit=2
    ))

    assert results[0]["status"] == "Offline"
    assert results[0]["name"] == "troubleshooting-agent"
    assert "currently offline" in results[0]["description"]
    assert results[0]["unavailable_match"] is True
    # 2 real alternatives (the caller's limit), plus the note = 3 total.
    assert len(results) == 3
    assert len(results[1:]) == 2


def test_search_agents_offline_takes_precedence_over_unconfigured_in_note_reason(monkeypatch):
    """An agent that is BOTH offline AND unconfigured must resolve deterministically to
    a single note reason, not raise or produce an ambiguous/combined one.
    _resolve_rule_lock checks health before configuration-readiness, so "offline" wins
    -- added during Phase E's adversarial review pass, which found this combined state
    was previously untested (and is the exact combination that made the
    core/agent_factory.py double-annotation bug worse)."""
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }

    class FakeIdentityManagerOffline(FakeIdentityManagerAgentSearch):
        def get_all_health_statuses(self, kind):
            return {"troubleshooting-agent": {"status": "Offline"}}

    fake_identity = FakeIdentityManagerOffline(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)

    async def fake_discover_agents_unconfigured(user_id=None):
        return [
            {"name": "troubleshooting-agent", "is_configured": False},
            {"name": "ticket-summary-agent", "is_configured": True},
        ]

    monkeypatch.setattr(agent_search, "discover_agents", fake_discover_agents_unconfigured)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0 if b else 0.0)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="matched")

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    results = asyncio.run(agent_search.search_agents("Analyze the PCAP trace from Acme troubleshooting session 948", limit=5))

    assert results[0]["status"] == "Offline"
    assert "currently offline" in results[0]["description"]
    assert "not configured" not in results[0]["description"]


def test_search_agents_excludes_disabled_agent_from_rule_eligibility(monkeypatch):
    """A disabled agent's rules must never be evaluated, even with rules configured and
    even though core.discovery.discover_agents doesn't know about the disabled set."""

    class FakeIdentityManagerWithDisabled(FakeIdentityManagerAgentSearch):
        def get_disabled_standard_agents(self):
            return ["troubleshooting-agent"]

    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerWithDisabled(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "discover_agents", _fake_discover_agents_all_configured)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0 if b else 0.0)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        assert "troubleshooting-agent" not in eligible_agents
        return None

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    # include_disabled=True (as the Supervisor passes) still must not admit the disabled
    # agent into rule eligibility -- it only affects the semantic-fallback candidate pool.
    results = asyncio.run(agent_search.search_agents(
        "Analyze the PCAP trace from Acme troubleshooting session 948", limit=5, include_disabled=True
    ))

    names = {r["name"] for r in results}
    assert "ticket-summary-agent" in names
    troubleshooting = next((r for r in results if r["name"] == "troubleshooting-agent"), None)
    assert troubleshooting is not None
    assert troubleshooting["status"] == "disabled"


# --- No rules configured: rules engine is skipped entirely ---

def test_search_agents_skips_rules_engine_when_none_configured(monkeypatch):
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(rules=[]),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerAgentSearch(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "discover_agents", _fail_discover)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0)

    results = asyncio.run(agent_search.search_agents("Analyze the PCAP trace", limit=5))

    names = {r["name"] for r in results}
    assert names == {"troubleshooting-agent", "ticket-summary-agent"}


# --- Semantic fallback on null/negative rule match ---

def test_search_agents_semantic_fallback_on_null_match(monkeypatch):
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerAgentSearch(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "discover_agents", _fake_discover_agents_all_configured)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        return None

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    embed_calls = []

    def fake_embed_text(query, task_type):
        embed_calls.append(query)
        return [1.0, 0.0]

    monkeypatch.setattr(agent_search, "embed_text", fake_embed_text)
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0 if b else 0.0)

    results = asyncio.run(agent_search.search_agents("Generate an executive summary of ticket FD-8921", limit=5))

    assert len(embed_calls) == 1
    names = {r["name"] for r in results}
    assert names == {"troubleshooting-agent", "ticket-summary-agent"}


# --- Fail-open resilience ---

def test_search_agents_fail_open_on_rule_engine_error(monkeypatch):
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerAgentSearch(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)

    async def raising_discover_agents(user_id=None):
        raise TimeoutError("simulated rules-engine/etcd timeout")

    monkeypatch.setattr(agent_search, "discover_agents", raising_discover_agents)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0 if b else 0.0)

    results = asyncio.run(agent_search.search_agents("Analyze the PCAP trace from Acme troubleshooting session 948", limit=5))

    names = {r["name"] for r in results}
    assert names == {"troubleshooting-agent", "ticket-summary-agent"}


def test_search_agents_fail_open_when_routing_rules_fetch_raises(monkeypatch):
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }

    class RaisingIdentityManager(FakeIdentityManagerAgentSearch):
        def get_routing_rules(self):
            raise ConnectionError("simulated etcd outage")

    fake_identity = RaisingIdentityManager(configs)
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "discover_agents", _fail_discover)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0 if b else 0.0)

    results = asyncio.run(agent_search.search_agents("Analyze the PCAP trace from Acme troubleshooting session 948", limit=5))

    names = {r["name"] for r in results}
    assert names == {"troubleshooting-agent", "ticket-summary-agent"}
