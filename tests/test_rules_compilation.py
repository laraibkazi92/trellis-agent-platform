import pytest

from core import rules_engine
from core.rules_engine import (
    compile_rules_prompt,
    filter_eligible_agents,
    has_active_rules,
)


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


@pytest.fixture(autouse=True)
def _reset_prompt_cache():
    """Prevent the in-process compiled-prompt cache from leaking between tests."""
    rules_engine._cached_catalog_hash = None
    rules_engine._cached_prompt = None
    rules_engine._cached_expires_at = 0.0
    yield
    rules_engine._cached_catalog_hash = None
    rules_engine._cached_prompt = None
    rules_engine._cached_expires_at = 0.0


# --- filter_eligible_agents ---

def test_gating_excludes_supervisor():
    configs = {"supervisor": _agent_cfg(name="supervisor")}
    eligible = filter_eligible_agents(configs, {}, set(), {})
    assert eligible == {}


def test_gating_excludes_background_types():
    configs = {
        "bg-agent": _agent_cfg(name="bg-agent", type="background_agent"),
        "bg-script": _agent_cfg(name="bg-script", type="background_script"),
    }
    eligible = filter_eligible_agents(configs, {}, set(), {})
    assert eligible == {}


def test_gating_internal_only_agent():
    configs = {"internal-agent": _agent_cfg(name="internal-agent", external=False)}
    eligible = filter_eligible_agents(configs, {}, set(), {})
    assert eligible == {}


def test_gating_disabled_agent():
    configs = {"troubleshooting-agent": _agent_cfg()}
    eligible = filter_eligible_agents(configs, {}, {"troubleshooting-agent"}, {})
    assert eligible == {}


def test_gating_offline_agent():
    configs = {"troubleshooting-agent": _agent_cfg()}
    health = {"troubleshooting-agent": {"status": "Offline"}}
    eligible = filter_eligible_agents(configs, health, set(), {})
    assert eligible == {}


def test_gating_unconfigured_agent():
    configs = {"troubleshooting-agent": _agent_cfg()}
    configured_agents = {"troubleshooting-agent": False}
    eligible = filter_eligible_agents(configs, {}, set(), configured_agents)
    assert eligible == {}


def test_gating_excludes_agents_with_no_rules():
    configs = {"ticket-summary-agent": _agent_cfg(name="ticket-summary-agent", rules=[])}
    eligible = filter_eligible_agents(configs, {}, set(), {})
    assert eligible == {}


def test_gating_retains_healthy_configured_eligible_agent():
    configs = {"troubleshooting-agent": _agent_cfg()}
    health = {"troubleshooting-agent": {"status": "Online"}}
    configured_agents = {"troubleshooting-agent": True}
    eligible = filter_eligible_agents(configs, health, set(), configured_agents)
    assert "troubleshooting-agent" in eligible


def test_gating_agent_missing_from_health_and_configured_maps_is_retained():
    """Fail-open: an agent absent from the health/configured maps (e.g. no health
    record ever written, or discovery not queried for it) must not be excluded."""
    configs = {"troubleshooting-agent": _agent_cfg()}
    eligible = filter_eligible_agents(configs, {}, set(), {})
    assert "troubleshooting-agent" in eligible


def test_gating_multiple_agents_mixed_eligibility():
    configs = {
        "troubleshooting-agent": _agent_cfg(),
        "ticket-summary-agent": _agent_cfg(
            name="ticket-summary-agent",
            description="Generates structured executive summaries and ticket reports from Issues and Support.",
            rules=[
                {
                    "description": "Executive summaries and case recaps",
                    "use_when": ["User requests an executive summary or status overview for customer leadership"],
                    "do_not_use_when": ["User asks to run live diagnostic commands or capture packets"],
                    "examples": ["Generate an executive summary of ticket FD-8921"],
                }
            ],
        ),
        "disabled-agent": _agent_cfg(name="disabled-agent"),
        "internal-agent": _agent_cfg(name="internal-agent", external=False),
    }
    eligible = filter_eligible_agents(
        configs,
        health={"disabled-agent": {"status": "Online"}},
        disabled_agents={"disabled-agent"},
        configured_agents={"troubleshooting-agent": True, "ticket-summary-agent": True},
    )
    assert set(eligible.keys()) == {"troubleshooting-agent", "ticket-summary-agent"}


# --- has_active_rules ---

def test_zero_rules_short_circuit():
    assert has_active_rules([], {}) is False


def test_has_active_rules_true_with_global_rules_only():
    assert has_active_rules([_global_rule()], {}) is True


def test_has_active_rules_true_with_agent_rules_only():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    assert has_active_rules([], eligible) is True


def test_has_active_rules_false_when_eligible_agent_has_no_rules():
    eligible = {"ticket-summary-agent": _agent_cfg(name="ticket-summary-agent", rules=[])}
    assert has_active_rules([], eligible) is False


# --- compile_rules_prompt ---

def test_compilation_prompt_format_global_overrides_first():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    prompt = compile_rules_prompt([_global_rule()], eligible)

    global_idx = prompt.index("=== GLOBAL OVERRIDES (HIGHEST PRIORITY) ===")
    agents_idx = prompt.index("=== ELIGIBLE AGENT RULES ===")
    assert global_idx < agents_idx
    assert "Override ID: override-acme-infrastructure-troubleshooting" in prompt
    assert "Target Agent: troubleshooting-agent" in prompt
    assert "Query involves deep-dive data plane troubleshooting" in prompt
    assert '"Triage BGP route flapping on Acme connector CX-405"' in prompt


def test_compilation_prompt_format_agent_rules():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    prompt = compile_rules_prompt([], eligible)

    assert "=== GLOBAL OVERRIDES (HIGHEST PRIORITY) ===" not in prompt
    assert "=== ELIGIBLE AGENT RULES ===" in prompt
    assert "Agent: troubleshooting-agent" in prompt
    assert "Description: Specialized agent for debugging Acme Troubleshooting Service issues." in prompt
    assert "Description: Acme troubleshooting service, packet captures, and flow-level network drops" in prompt
    assert "User requests packet capture (PCAP) inspection or troubleshooting session diagnostics" in prompt
    assert '"Why are packets dropping on connector CX-102?"' in prompt


def test_compilation_prompt_empty_when_no_rules():
    assert compile_rules_prompt([], {}) == ""


def test_compilation_prompt_multiple_agents_sorted_deterministically():
    eligible = {
        "zzz-agent": _agent_cfg(name="zzz-agent"),
        "aaa-agent": _agent_cfg(name="aaa-agent"),
    }
    prompt = compile_rules_prompt([], eligible)
    assert prompt.index("Agent: aaa-agent") < prompt.index("Agent: zzz-agent")


def test_compile_rules_prompt_caches_identical_input():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    first = compile_rules_prompt([_global_rule()], eligible)
    second = compile_rules_prompt([_global_rule()], eligible)
    assert first == second
    assert first is second


def test_compile_rules_prompt_invalidates_on_changed_input():
    eligible = {"troubleshooting-agent": _agent_cfg()}
    first = compile_rules_prompt([_global_rule()], eligible)
    changed_eligible = {"troubleshooting-agent": _agent_cfg(description="Different description")}
    second = compile_rules_prompt([_global_rule()], changed_eligible)
    assert first != second


def test_compile_rules_prompt_recomputes_after_ttl_expiry(monkeypatch):
    eligible = {"troubleshooting-agent": _agent_cfg()}
    fake_now = [1000.0]
    monkeypatch.setattr(rules_engine.time, "monotonic", lambda: fake_now[0])

    first = compile_rules_prompt([_global_rule()], eligible)
    assert rules_engine._cached_expires_at == 1000.0 + rules_engine._PROMPT_CACHE_TTL_SECONDS

    fake_now[0] += rules_engine._PROMPT_CACHE_TTL_SECONDS + 1
    second = compile_rules_prompt([_global_rule()], eligible)

    assert first == second
    assert first is not second
