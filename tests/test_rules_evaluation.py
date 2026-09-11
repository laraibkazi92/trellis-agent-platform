import asyncio

import pytest

from core import rules_engine
from core.models import RuleEvaluationResult


def _agent_cfg(**overrides):
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
                "examples": ["Why are packets dropping on connector CX-102?"],
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
        description="Generates structured executive summaries and ticket reports from Issues and Support.",
        rules=[
            {
                "description": "Executive summaries and case recaps",
                "use_when": ["User requests an executive summary or status overview for customer leadership"],
                "do_not_use_when": ["User asks to run live diagnostic commands or capture packets"],
                "examples": ["Generate an executive summary of ticket FD-8921"],
            }
        ],
    )
    cfg.update(overrides)
    return cfg


def _global_rule(**overrides):
    rule = dict(
        rule_id="override-acme-infrastructure-troubleshooting",
        target_agent="troubleshooting-agent",
        description="Acme core networking data plane issues take strict precedence over generic ticket summary",
        use_when=["Query involves deep-dive data plane troubleshooting"],
        do_not_use_when=["User explicitly asks to draft or summarize an end-of-day customer ticket report"],
        examples=["Triage BGP route flapping on Acme connector CX-405"],
    )
    rule.update(overrides)
    return rule


class FakeRunResult:
    def __init__(self, output):
        self.output = output


class FakeAgent:
    """Stand-in for pydantic_ai.Agent — captures constructor kwargs and lets each test
    control what `.run()` returns/raises without hitting a real Gemini endpoint."""

    behavior = None  # set per-test: callable(prompt) -> RuleEvaluationResult, or an exception instance/class

    def __init__(self, model, **kwargs):
        self.model = model
        self.kwargs = kwargs

    async def run(self, prompt):
        behavior = FakeAgent.behavior
        if isinstance(behavior, BaseException):
            raise behavior
        if isinstance(behavior, type) and issubclass(behavior, BaseException):
            raise behavior("boom")
        if callable(behavior):
            return FakeRunResult(behavior(prompt))
        return FakeRunResult(behavior)


@pytest.fixture(autouse=True)
def _isolate_rules_engine(monkeypatch):
    """Reset the query-result cache and stub out the real LLM client for every test.

    Also pre-seeds the admin-timeout-override cache as "just refreshed, no override" so
    tests never trigger a background etcd refresh (there is none in this environment;
    the refresh is fire-and-forget and would otherwise leak a lingering thread per test).
    """
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.setattr(rules_engine, "Agent", FakeAgent)
    monkeypatch.setattr(rules_engine, "_cached_timeout_override", None)
    monkeypatch.setattr(rules_engine, "_timeout_override_checked_at", rules_engine.time.monotonic())
    rules_engine._query_result_cache.clear()
    FakeAgent.behavior = None
    yield
    rules_engine._query_result_cache.clear()
    FakeAgent.behavior = None


# --- fast paths ---

def test_no_active_rules_returns_none_without_calling_llm():
    def _fail(prompt):
        raise AssertionError("LLM must not be called when there are no active rules")

    FakeAgent.behavior = _fail
    result = asyncio.run(rules_engine.evaluate_rules("Any query", [], {}))
    assert result is None


# --- positive / negative matches ---

def test_llm_positive_rule_lock():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    FakeAgent.behavior = RuleEvaluationResult(
        matched_agent="troubleshooting-agent", confidence=0.95, reasoning="Matches PCAP use_when."
    )
    result = asyncio.run(
        rules_engine.evaluate_rules("Analyze the PCAP trace from Acme troubleshooting session 948", [], eligible)
    )
    assert result is not None
    assert result.matched_agent == "troubleshooting-agent"
    assert result.confidence == 0.95


def test_llm_negative_boundary_rejection():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    FakeAgent.behavior = RuleEvaluationResult(
        matched_agent=None, confidence=0.0, reasoning="Query requests an executive summary; do_not_use_when triggered."
    )
    result = asyncio.run(
        rules_engine.evaluate_rules("Fetch executive ticket summary for Acme connector CX-102", [], eligible)
    )
    assert result is None


def test_global_override_precedence():
    eligible = {
        "troubleshooting-agent": _agent_cfg(),
        "ticket-summary-agent": _case_summary_cfg(),
    }
    FakeAgent.behavior = RuleEvaluationResult(
        matched_agent="troubleshooting-agent",
        confidence=0.93,
        reasoning="Global override for data plane triage takes precedence.",
    )
    result = asyncio.run(
        rules_engine.evaluate_rules(
            "Triage BGP route flapping on Acme connector CX-405", [_global_rule()], eligible
        )
    )
    assert result is not None
    assert result.matched_agent == "troubleshooting-agent"


def test_confidence_threshold_fallback():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    FakeAgent.behavior = RuleEvaluationResult(
        matched_agent="troubleshooting-agent", confidence=0.72, reasoning="Weak match."
    )
    result = asyncio.run(rules_engine.evaluate_rules("Something ambiguous about Acme", [], eligible))
    assert result is None


def test_matched_agent_not_eligible_falls_open():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    FakeAgent.behavior = RuleEvaluationResult(
        matched_agent="some-hallucinated-agent", confidence=0.99, reasoning="Invented agent name."
    )
    result = asyncio.run(rules_engine.evaluate_rules("Analyze the PCAP trace", [], eligible))
    assert result is None


# --- fail-open ---

def test_llm_timeout_fail_open(monkeypatch):
    eligible = {"troubleshooting-agent": _agent_cfg()}

    class HangingAgent(FakeAgent):
        async def run(self, prompt):
            await asyncio.sleep(10)
            return FakeRunResult(None)

    monkeypatch.setattr(rules_engine, "Agent", HangingAgent)
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_TIMEOUT", 0.01)

    result = asyncio.run(rules_engine.evaluate_rules("Analyze the PCAP trace", [], eligible))
    assert result is None


def test_llm_api_error_fail_open():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    FakeAgent.behavior = RuntimeError("429 rate limited")
    result = asyncio.run(rules_engine.evaluate_rules("Analyze the PCAP trace", [], eligible))
    assert result is None


# --- query cache ---

def test_query_cache_hit():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    call_count = 0

    def _behavior(prompt):
        nonlocal call_count
        call_count += 1
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="Match.")

    FakeAgent.behavior = _behavior

    query = "Analyze the PCAP trace from Acme troubleshooting session 948"
    first = asyncio.run(rules_engine.evaluate_rules(query, [], eligible))
    second = asyncio.run(rules_engine.evaluate_rules(query, [], eligible))

    assert call_count == 1
    assert first == second
    assert first.matched_agent == "troubleshooting-agent"


def test_query_cache_caches_null_decision_too():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    call_count = 0

    def _behavior(prompt):
        nonlocal call_count
        call_count += 1
        return RuleEvaluationResult(matched_agent=None, confidence=0.0, reasoning="No match.")

    FakeAgent.behavior = _behavior

    query = "What's the weather like today?"
    first = asyncio.run(rules_engine.evaluate_rules(query, [], eligible))
    second = asyncio.run(rules_engine.evaluate_rules(query, [], eligible))

    assert call_count == 1
    assert first is None
    assert second is None


def test_query_cache_invalidated_by_changed_rule_catalog():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    call_count = 0

    def _behavior(prompt):
        nonlocal call_count
        call_count += 1
        return RuleEvaluationResult(matched_agent="troubleshooting-agent", confidence=0.95, reasoning="Match.")

    FakeAgent.behavior = _behavior

    query = "Analyze the PCAP trace"
    asyncio.run(rules_engine.evaluate_rules(query, [], eligible))

    changed_eligible = {"troubleshooting-agent": _agent_cfg(description="A changed description")}
    asyncio.run(rules_engine.evaluate_rules(query, [], changed_eligible))

    assert call_count == 2
