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
    def __init__(self, disabled=None):
        self._disabled = disabled or []

    def get_disabled_standard_agents(self):
        return list(self._disabled)


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


def _run_agents_route(monkeypatch, agents):
    async def fake_discover_agents(user_id=None, include_background=False):
        return agents

    monkeypatch.setattr(marketplace, "discover_agents", fake_discover_agents)
    monkeypatch.setattr(marketplace, "identity_mgr", FakeIdentityManagerMarketplace())

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
