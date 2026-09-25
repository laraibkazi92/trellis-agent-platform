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


async def _fake_is_agent_configured(agent_name, user_id=None):
    return {
        "configured": True,
        "missing_secrets": [],
        "missing_variables": [],
        "optional_missing_secrets": [],
    }


def _fail_embed(*args, **kwargs):
    raise AssertionError("embed_text should not have been called")


def _fail_configured(*args, **kwargs):
    raise AssertionError("is_agent_configured should not have been called")


# --- Rule short-circuit ---

def test_search_agents_rule_short_circuit_bypasses_embedding(monkeypatch):
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerAgentSearch(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "is_agent_configured", _fake_is_agent_configured)
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
    monkeypatch.setattr(agent_search, "is_agent_configured", _fake_is_agent_configured)
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
    monkeypatch.setattr(agent_search, "is_agent_configured", _fake_is_agent_configured)
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

    async def fake_is_agent_configured_unconfigured(agent_name, user_id=None):
        if agent_name == "troubleshooting-agent":
            return {"configured": False, "missing_secrets": ["ACME_API_KEY"], "missing_variables": []}
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    monkeypatch.setattr(agent_search, "is_agent_configured", fake_is_agent_configured_unconfigured)
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
    # Deduplication: the unavailable matched agent must NOT appear again in the ranked alternatives below.
    alternative_names = {r["name"] for r in results[1:]}
    assert alternative_names == {"ticket-summary-agent"}
    assert "troubleshooting-agent" not in alternative_names
    assert len(results) == 2
    assert "unavailable_match" not in results[1]


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
    # An offline match short-circuits before configuration readiness check; is_agent_configured must not be called
    monkeypatch.setattr(agent_search, "is_agent_configured", _fail_configured)
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
    alternative_names = {r["name"] for r in results[1:]}
    assert "troubleshooting-agent" not in alternative_names
    assert alternative_names == {"ticket-summary-agent", "general-agent"}


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
    monkeypatch.setattr(agent_search, "is_agent_configured", _fail_configured)
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
    """A disabled agent's rules must never be evaluated, even with rules configured."""

    class FakeIdentityManagerWithDisabled(FakeIdentityManagerAgentSearch):
        def get_disabled_standard_agents(self):
            return ["troubleshooting-agent"]

    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerWithDisabled(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "is_agent_configured", _fake_is_agent_configured)
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
    monkeypatch.setattr(agent_search, "is_agent_configured", _fail_configured)
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
    # Due to inverted execution order, is_agent_configured must NOT be called on null rule match
    monkeypatch.setattr(agent_search, "is_agent_configured", _fail_configured)

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

    async def raising_is_agent_configured(agent_name, user_id=None):
        raise TimeoutError("simulated rules-engine/etcd timeout")

    monkeypatch.setattr(agent_search, "is_agent_configured", raising_is_agent_configured)
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
    monkeypatch.setattr(agent_search, "is_agent_configured", _fail_configured)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0 if b else 0.0)

    results = asyncio.run(agent_search.search_agents("Analyze the PCAP trace from Acme troubleshooting session 948", limit=5))

    names = {r["name"] for r in results}
    assert names == {"troubleshooting-agent", "ticket-summary-agent"}


def test_resolve_rule_lock_calls_targeted_is_agent_configured(monkeypatch):
    """_resolve_rule_lock must call targeted is_agent_configured on the matched agent
    rather than triggering whole-catalog scans in discover_agents."""
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerAgentSearch(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)

    configured_calls = []

    async def fake_is_agent_configured(agent_name, user_id=None):
        configured_calls.append(agent_name)
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    monkeypatch.setattr(agent_search, "is_agent_configured", fake_is_agent_configured)
    monkeypatch.setattr(agent_search, "embed_text", _fail_embed)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="matched")

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    results = asyncio.run(agent_search.search_agents("Analyze PCAP", limit=1))
    assert results[0]["name"] == "troubleshooting-agent"
    assert configured_calls == ["troubleshooting-agent"]


def test_search_agents_rule_lock_defers_embeddings_fetch(monkeypatch):
    """Rule locks must not fetch all embeddings from etcd upfront."""
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }

    class FakeIdentityEmbeddingsCheck(FakeIdentityManagerAgentSearch):
        def get_all_agent_embeddings(self):
            raise AssertionError("get_all_agent_embeddings should NOT be called when a rule locks")

    fake_identity = FakeIdentityEmbeddingsCheck(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "is_agent_configured", _fake_is_agent_configured)
    monkeypatch.setattr(agent_search, "embed_text", _fail_embed)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="matched")

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    results = asyncio.run(agent_search.search_agents("Analyze PCAP", limit=1))
    assert results[0]["name"] == "troubleshooting-agent"


def test_identity_mgr_toggle_disabled_agents_atomic():
    from core.auth import IdentityManager

    class FakeEtcdClient:
        def __init__(self):
            self.storage = {}

        def get(self, key):
            val = self.storage.get(key)
            return (val, None)

        def put(self, key, val):
            self.storage[key] = val.encode("utf-8") if isinstance(val, str) else val

        def put_if_not_exists(self, key, val):
            if key not in self.storage:
                self.storage[key] = val
                return True
            return False

        def replace(self, key, prev_val, new_val):
            if self.storage.get(key) == prev_val:
                self.storage[key] = new_val
                return True
            return False

    mgr = IdentityManager.__new__(IdentityManager)
    mgr.client = FakeEtcdClient()

    # Initially empty, toggle should disable
    is_disabled = mgr.toggle_disabled_standard_agent("agent-1")
    assert is_disabled is True
    assert mgr.get_disabled_standard_agents() == ["agent-1"]

    # Explicit disable when already disabled
    is_disabled = mgr.toggle_disabled_standard_agent("agent-1", disable=True)
    assert is_disabled is True
    assert mgr.get_disabled_standard_agents() == ["agent-1"]

    # Toggle to enable
    is_disabled = mgr.toggle_disabled_standard_agent("agent-1")
    assert is_disabled is False
    assert mgr.get_disabled_standard_agents() == []

    # Explicit enable when already enabled
    is_disabled = mgr.toggle_disabled_standard_agent("agent-1", disable=False)
    assert is_disabled is False
    assert mgr.get_disabled_standard_agents() == []

    # Workflow toggle
    is_wf_disabled = mgr.toggle_disabled_workflow("wf-1", disable=True)
    assert is_wf_disabled is True
    assert mgr.get_disabled_workflows() == ["wf-1"]

    is_wf_disabled = mgr.toggle_disabled_workflow("wf-1", disable=False)
    assert is_wf_disabled is False
    assert mgr.get_disabled_workflows() == []


def test_atomic_update_config_list_resolves_after_contention(monkeypatch):
    """CAS should survive transient contention (another writer winning a handful of
    races) by backing off and retrying, converging on the correct final list rather
    than giving up or corrupting the write."""
    import json
    from core import auth as auth_module
    from core.auth import IdentityManager

    full_key = "/config/framework/disabled_standard_agents"

    class ContendedEtcdClient:
        def __init__(self, fail_replace_times):
            self.storage = {full_key: json.dumps([]).encode("utf-8")}
            self.fail_replace_times = fail_replace_times
            self.replace_calls = 0
            self.put_calls = []

        def get(self, key):
            return (self.storage.get(key), None)

        def put(self, key, val):
            self.put_calls.append((key, val))
            self.storage[key] = val.encode("utf-8") if isinstance(val, str) else val

        def put_if_not_exists(self, key, val):
            if key not in self.storage:
                self.storage[key] = val
                return True
            return False

        def replace(self, key, prev_val, new_val):
            self.replace_calls += 1
            if self.replace_calls <= self.fail_replace_times:
                # Simulate a concurrent writer winning the race out from under us.
                self.storage[key] = json.dumps(["someone-else"]).encode("utf-8")
                return False
            if self.storage.get(key) == prev_val:
                self.storage[key] = new_val
                return True
            return False

    sleep_calls = []
    monkeypatch.setattr(auth_module.time, "sleep", lambda s: sleep_calls.append(s))

    mgr = IdentityManager.__new__(IdentityManager)
    mgr.client = ContendedEtcdClient(fail_replace_times=5)

    is_disabled = mgr.toggle_disabled_standard_agent("agent-x", disable=True)

    assert is_disabled is True
    # The concurrent writer's change ("someone-else") is preserved (no lost update)
    # and our own update is correctly merged in once the CAS finally wins.
    assert set(mgr.get_disabled_standard_agents()) == {"someone-else", "agent-x"}
    # Backed off between each of the 5 lost races.
    assert len(sleep_calls) == 5
    assert all(0 <= s <= 0.02 for s in sleep_calls)
    # Never fell back to a blind unconditional put() of the final key.
    assert mgr.client.put_calls == []


def test_atomic_update_config_list_exhaustion_raises_and_never_blind_overwrites(monkeypatch):
    """When contention never resolves, the CAS loop must raise instead of falling
    back to an unconditional put() (which would silently discard a concurrent
    writer's change and falsely report success)."""
    import json
    from core import auth as auth_module
    from core.auth import IdentityManager, EtcdContentionError

    full_key = "/config/framework/disabled_standard_agents"

    class AlwaysContendedEtcdClient:
        def __init__(self):
            self.storage = {full_key: json.dumps(["existing-agent"]).encode("utf-8")}
            self.put_calls = []
            self.replace_calls = 0

        def get(self, key):
            return (self.storage.get(key), None)

        def put(self, key, val):
            # Should never be called by _atomic_update_config_list -- there is no
            # blind-overwrite fallback anymore.
            self.put_calls.append((key, val))
            self.storage[key] = val.encode("utf-8") if isinstance(val, str) else val

        def put_if_not_exists(self, key, val):
            if key not in self.storage:
                self.storage[key] = val
                return True
            return False

        def replace(self, key, prev_val, new_val):
            self.replace_calls += 1
            # Another writer always wins -- contention never resolves.
            return False

    monkeypatch.setattr(auth_module.time, "sleep", lambda s: None)

    mgr = IdentityManager.__new__(IdentityManager)
    client = AlwaysContendedEtcdClient()
    mgr.client = client

    # Call the CAS helper directly (not through the @retry_etcd()-wrapped
    # toggle_disabled_standard_agent) so this test isolates the CAS loop's own
    # 20-attempt exhaustion behavior from the outer retry_etcd decorator's separate
    # (and much longer) retry-with-delay behavior around the whole call.
    with pytest.raises(EtcdContentionError):
        mgr._atomic_update_config_list("disabled_standard_agents", lambda cur: cur + ["agent-y"])

    assert client.replace_calls == 20
    # No blind overwrite: put() was never invoked, and the stored value is untouched.
    assert client.put_calls == []
    assert client.storage[full_key] == json.dumps(["existing-agent"]).encode("utf-8")

    # Through the @retry_etcd()-wrapped public method, contention must fail fast rather
    # than re-run the whole 20-attempt CAS loop up to 10 more times.
    client.replace_calls = 0
    with pytest.raises(EtcdContentionError):
        mgr.toggle_disabled_standard_agent("agent-y", disable=True)
    assert client.replace_calls == 20
    assert client.put_calls == []


def test_atomic_update_config_list_corrupt_json_defaults_to_empty_list(monkeypatch):
    """Corrupt JSON or a non-list value stored under the key must still be treated
    as an empty list (unchanged pre-existing behavior), not raise or crash."""
    from core.auth import IdentityManager

    full_key = "/config/framework/disabled_standard_agents"

    class CorruptThenGoodEtcdClient:
        def __init__(self, initial_raw):
            self.storage = {full_key: initial_raw}

        def get(self, key):
            return (self.storage.get(key), None)

        def put(self, key, val):
            self.storage[key] = val.encode("utf-8") if isinstance(val, str) else val

        def put_if_not_exists(self, key, val):
            if key not in self.storage:
                self.storage[key] = val
                return True
            return False

        def replace(self, key, prev_val, new_val):
            if self.storage.get(key) == prev_val:
                self.storage[key] = new_val
                return True
            return False

    # Case 1: corrupt (non-JSON) bytes stored.
    mgr = IdentityManager.__new__(IdentityManager)
    mgr.client = CorruptThenGoodEtcdClient(b"not-json-!!!")
    is_disabled = mgr.toggle_disabled_standard_agent("agent-z", disable=True)
    assert is_disabled is True
    assert mgr.get_disabled_standard_agents() == ["agent-z"]

    # Case 2: valid JSON but not a list (e.g. a dict).
    mgr2 = IdentityManager.__new__(IdentityManager)
    mgr2.client = CorruptThenGoodEtcdClient(b'{"not": "a list"}')
    is_disabled2 = mgr2.toggle_disabled_standard_agent("agent-w", disable=True)
    assert is_disabled2 is True
    assert mgr2.get_disabled_standard_agents() == ["agent-w"]
