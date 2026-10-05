# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import yaml
import pytest
from pydantic import ValidationError

from core.models import (
    AgentConfig,
    AgentRule,
    GlobalRule,
    RoutingRulesConfig,
    RuleEvaluationResult,
)


def _agent_rule_kwargs(**overrides):
    kwargs = dict(
        description="Acme troubleshooting service, packet captures, and flow-level network drops",
        use_when=["User requests packet capture (PCAP) inspection or troubleshooting session diagnostics"],
        do_not_use_when=["User is asking for an executive ticket summary or customer-facing status update"],
        examples=["Why are packets dropping on connector CX-102?"],
    )
    kwargs.update(overrides)
    return kwargs


def _global_rule_kwargs(**overrides):
    kwargs = dict(
        rule_id="override-acme-infrastructure-troubleshooting",
        target_agent="troubleshooting-agent",
        description="Acme core networking data plane issues take strict precedence over generic ticket summary",
        use_when=["Query involves deep-dive data plane troubleshooting"],
        do_not_use_when=["User explicitly asks to draft or summarize an end-of-day customer ticket report"],
        examples=["Triage BGP route flapping on Acme connector CX-405"],
    )
    kwargs.update(overrides)
    return kwargs


# --- AgentRule ---

def test_agent_rule_valid():
    rule = AgentRule(**_agent_rule_kwargs())
    assert rule.description.startswith("Acme troubleshooting")
    assert rule.use_when == ["User requests packet capture (PCAP) inspection or troubleshooting session diagnostics"]
    assert rule.do_not_use_when == ["User is asking for an executive ticket summary or customer-facing status update"]
    assert rule.examples == ["Why are packets dropping on connector CX-102?"]


def test_agent_rule_defaults_to_empty_lists():
    rule = AgentRule()
    assert rule.description is None
    assert rule.use_when == []
    assert rule.do_not_use_when == []
    assert rule.examples == []


def test_agent_rule_serialization_round_trip():
    rule = AgentRule(**_agent_rule_kwargs())
    data = rule.model_dump()
    restored = AgentRule(**data)
    assert restored == rule


def test_agent_config_with_rules():
    raw_yaml = """
name: troubleshooting-agent
description: Specialized agent for debugging Acme Troubleshooting Service issues.
rules:
  - description: "Acme troubleshooting service, packet captures, and flow-level network drops"
    use_when:
      - "User requests packet capture (PCAP) inspection or troubleshooting session diagnostics"
    do_not_use_when:
      - "User is asking for an executive ticket summary or customer-facing status update"
    examples:
      - "Why are packets dropping on connector CX-102?"
"""
    data = yaml.safe_load(raw_yaml)
    config = AgentConfig(**data)
    assert len(config.rules) == 1
    assert config.rules[0].use_when == ["User requests packet capture (PCAP) inspection or troubleshooting session diagnostics"]


def test_agent_config_rules_default_empty():
    config = AgentConfig(name="ticket-summary-agent")
    assert config.rules == []


# --- GlobalRule ---

def test_global_rule_valid():
    rule = GlobalRule(**_global_rule_kwargs())
    assert rule.rule_id == "override-acme-infrastructure-troubleshooting"
    assert rule.target_agent == "troubleshooting-agent"


def test_global_rule_missing_target_agent_raises():
    kwargs = _global_rule_kwargs()
    del kwargs["target_agent"]
    with pytest.raises(ValidationError):
        GlobalRule(**kwargs)


def test_global_rule_missing_rule_id_raises():
    kwargs = _global_rule_kwargs()
    del kwargs["rule_id"]
    with pytest.raises(ValidationError):
        GlobalRule(**kwargs)


def test_global_rule_serialization_round_trip():
    rule = GlobalRule(**_global_rule_kwargs())
    data = rule.model_dump()
    restored = GlobalRule(**data)
    assert restored == rule


# --- RoutingRulesConfig ---

def test_global_rules_config_valid():
    raw_yaml = """
version: "1.0"
global_rules:
  - rule_id: "override-acme-infrastructure-troubleshooting"
    target_agent: "troubleshooting-agent"
    description: "Acme core networking data plane issues take strict precedence over generic ticket summary"
    use_when:
      - "Query involves deep-dive data plane troubleshooting, routing flaps, or connector packet loss"
    do_not_use_when:
      - "User explicitly asks to draft or summarize an end-of-day customer ticket report"
    examples:
      - "Triage BGP route flapping on Acme connector CX-405"
  - rule_id: "override-customer-executive-summary"
    target_agent: "ticket-summary-agent"
"""
    data = yaml.safe_load(raw_yaml)
    config = RoutingRulesConfig(**data)
    assert config.version == "1.0"
    assert len(config.global_rules) == 2
    assert config.global_rules[0].target_agent == "troubleshooting-agent"
    assert config.global_rules[1].target_agent == "ticket-summary-agent"


def test_routing_rules_config_defaults():
    config = RoutingRulesConfig()
    assert config.version == "1.0"
    assert config.global_rules == []


def test_routing_rules_config_serialization_round_trip():
    config = RoutingRulesConfig(global_rules=[GlobalRule(**_global_rule_kwargs())])
    data = config.model_dump()
    restored = RoutingRulesConfig(**data)
    assert restored == config
    dumped_yaml = yaml.safe_dump(data)
    reloaded = RoutingRulesConfig(**yaml.safe_load(dumped_yaml))
    assert reloaded == config


# --- RuleEvaluationResult ---

def test_rule_evaluation_result_valid():
    result = RuleEvaluationResult(
        matched_agent="troubleshooting-agent",
        confidence=0.95,
        reasoning="Query explicitly requests PCAP analysis.",
    )
    assert result.matched_agent == "troubleshooting-agent"
    assert result.confidence == 0.95


def test_rule_evaluation_result_defaults():
    result = RuleEvaluationResult()
    assert result.matched_agent is None
    assert result.confidence == 0.0
    assert result.reasoning == ""


def test_rule_evaluation_result_bounds():
    with pytest.raises(ValidationError):
        RuleEvaluationResult(confidence=1.5)
    with pytest.raises(ValidationError):
        RuleEvaluationResult(confidence=-0.1)


def test_rule_evaluation_result_serialization_round_trip():
    result = RuleEvaluationResult(matched_agent="ticket-summary-agent", confidence=0.9, reasoning="matched")
    data = result.model_dump()
    restored = RuleEvaluationResult(**data)
    assert restored == result
