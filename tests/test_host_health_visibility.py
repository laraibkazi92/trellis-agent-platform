# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for the GET /health route in core.host excluding external: False agents.

See __spec_docs/internal_external_agents_spec.md — /health is reachable without
authentication (it is not under any of AuthMiddleware's protected prefixes:
/v1/, /sse, /messages, /mcp), so it must not leak the existence or status of
agents marked external: False, mirroring core.gateway._get_visible_agents and
core.host.chat_completions.
"""
import asyncio

import pytest

from core import host


class FakeIdentityManagerHealth:
    def __init__(self, agent_configs, disabled=None):
        self._agent_configs = agent_configs
        self._disabled = disabled or []

    def get_disabled_standard_agents(self):
        return list(self._disabled)

    def get_all_agent_configs(self):
        return dict(self._agent_configs)

    def get_all_health_statuses(self, entity_type):
        return {}


def test_health_excludes_external_false_agent(monkeypatch):
    fake_identity = FakeIdentityManagerHealth({
        "general-agent": {"name": "general-agent", "type": "user_agent", "external": True, "allowed_tools": []},
        "data-parser": {"name": "data-parser", "type": "user_agent", "external": False, "allowed_tools": []},
    })
    monkeypatch.setattr(host, "identity_mgr", fake_identity)
    monkeypatch.setattr(host, "is_hub_connected", lambda: True)

    result = asyncio.run(host.health())

    assert "general-agent" in result["agents"]
    assert "data-parser" not in result["agents"]


def test_health_includes_external_true_agent_with_expected_shape(monkeypatch):
    fake_identity = FakeIdentityManagerHealth({
        "general-agent": {"name": "general-agent", "type": "user_agent", "external": True, "allowed_tools": []},
    })
    monkeypatch.setattr(host, "identity_mgr", fake_identity)
    monkeypatch.setattr(host, "is_hub_connected", lambda: True)

    result = asyncio.run(host.health())

    assert result["status"] == "healthy"
    assert result["hub_connected"] is True
    assert result["agents_disabled"] == []
    agent_entry = result["agents"]["general-agent"]
    assert set(agent_entry.keys()) == {"status", "offline_tools", "agent_error"}
    assert agent_entry["status"] == "Online"
    assert agent_entry["offline_tools"] == []
    assert agent_entry["agent_error"] is None


def test_health_omits_supervisor_and_disabled_agents_alongside_external_filter(monkeypatch):
    fake_identity = FakeIdentityManagerHealth(
        {
            "supervisor": {"name": "supervisor", "type": "supervisor", "external": True, "allowed_tools": []},
            "disabled-agent": {"name": "disabled-agent", "type": "user_agent", "external": True, "allowed_tools": []},
            "data-parser": {"name": "data-parser", "type": "user_agent", "external": False, "allowed_tools": []},
            "general-agent": {"name": "general-agent", "type": "user_agent", "external": True, "allowed_tools": []},
        },
        disabled=["disabled-agent"],
    )
    monkeypatch.setattr(host, "identity_mgr", fake_identity)
    monkeypatch.setattr(host, "is_hub_connected", lambda: False)

    result = asyncio.run(host.health())

    assert list(result["agents"].keys()) == ["general-agent"]
    assert result["agents_disabled"] == ["disabled-agent"]


def test_health_excludes_background_agent_types(monkeypatch):
    """Background agents/scripts are not directly invocable and should not be
    reported in /health alongside ordinary routable agents (Phase A dedup:
    core.host.health now shares core.models.is_routable_agent_type with the
    other four exclusion sites instead of only checking for "supervisor")."""
    fake_identity = FakeIdentityManagerHealth({
        "general-agent": {"name": "general-agent", "type": "user_agent", "external": True, "allowed_tools": []},
        "bg-agent": {"name": "bg-agent", "type": "background_agent", "external": True, "allowed_tools": []},
        "bg-script": {"name": "bg-script", "type": "background_script", "external": True, "allowed_tools": []},
    })
    monkeypatch.setattr(host, "identity_mgr", fake_identity)
    monkeypatch.setattr(host, "is_hub_connected", lambda: True)

    result = asyncio.run(host.health())

    assert list(result["agents"].keys()) == ["general-agent"]
