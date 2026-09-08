"""Integration tests for Phase 4 (Trellis Rules Engine wiring) — see
__spec_docs/rules_engine_spec.md.

Covers core.agent_search.search_agents():
  - A confident rule match short-circuits ranking entirely (embed_text never called).
  - A rule match with limit > 1 places the locked agent first and fills remaining
    slots from the ranked semantic fallback (excluding the locked agent).
  - No active rules configured anywhere skips the rules engine entirely (no
    discover_agents call) and behaves exactly like pre-Phase-4 search.
  - A null rule match (e.g. confidence below threshold, or no rule fires) falls
    through cleanly to embedding-based ranking.
  - Any failure inside rule-lock resolution (etcd, discovery, or evaluate_rules
    itself) fails open to semantic ranking without raising.
"""
import asyncio

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


def test_search_agents_rule_short_circuit_fills_remaining_slots(monkeypatch):
    configs = {
        "troubleshooting-agent": _troubleshooting_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    fake_identity = FakeIdentityManagerAgentSearch(configs, routing_rules={"version": "1.0", "global_rules": []})
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "discover_agents", _fake_discover_agents_all_configured)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0)

    async def fake_evaluate_rules(query, global_rules, eligible_agents):
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="matched")

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    results = asyncio.run(agent_search.search_agents("Analyze the PCAP trace from Acme troubleshooting session 948", limit=5))

    assert [r["name"] for r in results] == ["troubleshooting-agent", "ticket-summary-agent"]


# --- Disabled / unconfigured agents are never eligible for a rule lock ---

def test_search_agents_excludes_unconfigured_agent_from_rule_eligibility(monkeypatch):
    """The real discover_agents()-derived configured_agents map and the real disabled
    set must both flow through to filter_eligible_agents -- an agent that carries rules
    but is unconfigured for this user must never appear in eligible_agents, even though
    it would otherwise be exactly what the query is asking for."""
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
        assert "troubleshooting-agent" not in eligible_agents
        return None

    monkeypatch.setattr(agent_search, "evaluate_rules", fake_evaluate_rules)

    results = asyncio.run(agent_search.search_agents("Analyze the PCAP trace from Acme troubleshooting session 948", limit=5))

    names = {r["name"] for r in results}
    assert names == {"troubleshooting-agent", "ticket-summary-agent"}


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
