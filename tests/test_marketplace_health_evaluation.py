# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for Phase B: core.routers.marketplace.agents() (the /agents route backing
templates/agents.html) now overwrites each agent's `health` field with the shared
cooldown-aware evaluation (core.health.evaluate_health_status) before it reaches the
template, instead of the raw discover_agents() status -- see
__spec_docs/rules_engine_hardening_plan.md, Phase B decision on raw-vs-evaluated status.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from core.routers import marketplace


class FakeIdentityManagerMarketplace:
    def __init__(self, disabled=None, agent_configs=None, tool_health=None):
        self._disabled = disabled or []
        self._agent_configs = agent_configs or {}
        self._tool_health = tool_health or {}

    def get_disabled_standard_agents(self):
        return list(self._disabled)

    def get_all_agent_configs(self):
        return dict(self._agent_configs)

    def get_all_health_statuses(self, kind):
        if kind == "tool":
            return dict(self._tool_health)
        return {}


def _agent(name, health):
    return {
        "name": name,
        "health": health,
        "is_configured": True,
        "missing_secrets": [],
        "missing_variables": [],
        "secret_groups": [],
        "required_secrets": [],
        "required_variables": [],
        "description": "d",
        "author": "a",
    }


def _offline(seconds_ago):
    return {
        "status": "Offline",
        "consecutive_failures": 12,
        "last_failure_time": (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat(),
    }


def _run_agents_route(monkeypatch, agents, agent_configs=None, tool_health=None):
    async def fake_discover_agents(user_id=None, include_background=False):
        return agents

    monkeypatch.setattr(marketplace, "discover_agents", fake_discover_agents)
    monkeypatch.setattr(
        marketplace,
        "identity_mgr",
        FakeIdentityManagerMarketplace(agent_configs=agent_configs, tool_health=tool_health),
    )

    captured = {}

    def fake_template_response(request=None, name=None, context=None):
        captured["context"] = context
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(marketplace.templates, "TemplateResponse", fake_template_response)

    request = SimpleNamespace(session={"user": {"sub": "user-1", "email": "user@example.com"}})
    asyncio.run(marketplace.agents(request))
    return captured["context"]["agents"]


def test_agents_route_evaluates_offline_past_cooldown_as_half_open(monkeypatch):
    rendered = _run_agents_route(monkeypatch, [_agent("stale-agent", _offline(120))])
    assert rendered[0]["health"]["status"] == "Half-Open"


def test_agents_route_keeps_offline_within_cooldown_window(monkeypatch):
    rendered = _run_agents_route(monkeypatch, [_agent("recent-agent", _offline(5))])
    assert rendered[0]["health"]["status"] == "Offline"


def test_agents_route_leaves_online_agent_unchanged(monkeypatch):
    rendered = _run_agents_route(monkeypatch, [_agent("healthy-agent", {"status": "Online"})])
    assert rendered[0]["health"]["status"] == "Online"


def test_agents_route_shows_degraded_when_allowed_tool_is_offline(monkeypatch):
    """An agent whose own health is fine but depends on an offline tool now shows
    Degraded on the marketplace card -- previously this route only ever showed
    Offline/Half-Open/Online, never Degraded, unlike core/host.py's /health handler
    and core/gateway.py's search results (see rules_engine_hardening_plan.md review
    finding: marketplace UI didn't surface Degraded)."""
    rendered = _run_agents_route(
        monkeypatch,
        [_agent("tool-dependent-agent", {"status": "Online"})],
        agent_configs={"tool-dependent-agent": {"allowed_tools": ["netctl"]}},
        tool_health={"netctl": {"status": "Offline"}},
    )
    assert rendered[0]["health"]["status"] == "Degraded"
    assert rendered[0]["offline_tools"] == ["netctl"]


def test_agents_route_offline_agent_stays_offline_even_with_healthy_tools(monkeypatch):
    """Agent-Offline still takes precedence over tool health -- an agent whose own
    health is Offline is not somehow "Degraded"-downgraded by unrelated healthy tools."""
    rendered = _run_agents_route(
        monkeypatch,
        [_agent("broken-agent", _offline(5))],
        agent_configs={"broken-agent": {"allowed_tools": ["netctl"]}},
        tool_health={"netctl": {"status": "Online"}},
    )
    assert rendered[0]["health"]["status"] == "Offline"
