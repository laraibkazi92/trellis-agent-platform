import asyncio
from types import SimpleNamespace

import pytest

from core.models import AgentConfig
import core.discovery as discovery_module


def _agent_kwargs(**overrides):
    kwargs = dict(name="triage-lead")
    kwargs.update(overrides)
    return kwargs


def test_agent_config_visibility_defaults_true():
    config = AgentConfig(**_agent_kwargs())
    assert config.external is True
    assert config.internal is True


def test_agent_config_explicit_internal_worker():
    config = AgentConfig(**_agent_kwargs(external=False, internal=True))
    assert config.external is False
    assert config.internal is True


def test_agent_config_explicit_front_door_only():
    config = AgentConfig(**_agent_kwargs(external=True, internal=False))
    assert config.external is True
    assert config.internal is False


def test_agent_config_explicit_private_offline():
    config = AgentConfig(**_agent_kwargs(external=False, internal=False))
    assert config.external is False
    assert config.internal is False


class FakeIdentityManager:
    """Minimal stand-in for IdentityManager covering discover_agents()'s calls."""

    def __init__(self, agent_configs):
        self._agent_configs = agent_configs

    def get_all_agent_configs(self):
        return dict(self._agent_configs)

    def get_all_agent_skills(self):
        return {}

    def get_all_health_statuses(self, kind):
        return {}

    def get_identity_config(self, identity, category):
        return {}

    def get_all_tool_configs(self):
        return {}

    def get_all_mcp_configs(self):
        return {}


def test_discover_agents_reports_default_visibility_flags(monkeypatch):
    fake_identity = FakeIdentityManager({
        "general-agent": {"name": "general-agent", "type": "user_agent"},
    })
    monkeypatch.setattr(discovery_module, "identity_mgr", fake_identity)

    agents = asyncio.run(discovery_module.discover_agents())

    assert len(agents) == 1
    assert agents[0]["external"] is True
    assert agents[0]["internal"] is True


def test_discover_agents_reports_explicit_visibility_flags(monkeypatch):
    fake_identity = FakeIdentityManager({
        "internal-worker": {
            "name": "internal-worker",
            "type": "user_agent",
            "external": False,
            "internal": True,
        },
        "front-door-bot": {
            "name": "front-door-bot",
            "type": "user_agent",
            "external": True,
            "internal": False,
        },
    })
    monkeypatch.setattr(discovery_module, "identity_mgr", fake_identity)

    agents = asyncio.run(discovery_module.discover_agents())
    by_name = {a["name"]: a for a in agents}

    assert by_name["internal-worker"]["external"] is False
    assert by_name["internal-worker"]["internal"] is True
    assert by_name["front-door-bot"]["external"] is True
    assert by_name["front-door-bot"]["internal"] is False
