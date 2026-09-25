import asyncio
from types import SimpleNamespace

import pytest

from core.models import AgentConfig, coerce_bool_flag
import core.discovery as discovery_module
from scripts.sync_to_db import sync_agent


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


# --- coerce_bool_flag --------------------------------------------------------------

def test_coerce_bool_flag_bool_passthrough():
    assert coerce_bool_flag(True) is True
    assert coerce_bool_flag(False) is False


def test_coerce_bool_flag_string_variants():
    assert coerce_bool_flag("true") is True
    assert coerce_bool_flag("True") is True
    assert coerce_bool_flag("yes") is True
    assert coerce_bool_flag("1") is True
    assert coerce_bool_flag("on") is True
    assert coerce_bool_flag("false") is False
    assert coerce_bool_flag("False") is False
    assert coerce_bool_flag("no") is False
    assert coerce_bool_flag("0") is False
    assert coerce_bool_flag("off") is False


def test_coerce_bool_flag_none_returns_default():
    assert coerce_bool_flag(None) is True
    assert coerce_bool_flag(None, default=False) is False


def test_coerce_bool_flag_unrecognized_string_returns_default():
    assert coerce_bool_flag("maybe") is True
    assert coerce_bool_flag("maybe", default=False) is False


def test_coerce_bool_flag_non_bool_non_str_uses_bool_conversion():
    assert coerce_bool_flag(1) is True
    assert coerce_bool_flag(0) is False
    assert coerce_bool_flag([]) is False
    assert coerce_bool_flag(["x"]) is True


# --- sync_agent (scripts/sync_to_db.py) --------------------------------------------

class FakeIdentityManagerSync:
    """Minimal stand-in for IdentityManager covering sync_agent()'s calls."""

    def __init__(self):
        self.saved_configs = {}

    def save_agent_config(self, name, config):
        self.saved_configs[name] = dict(config)

    def save_agent_skills(self, name, skills):
        pass

    def save_agent_embedding(self, name, vector):
        pass


def _write_agent_config(tmp_path, yaml_text):
    agent_dir = tmp_path / "some-agent"
    agent_dir.mkdir()
    (agent_dir / "config.yaml").write_text(yaml_text)
    return agent_dir


def test_sync_agent_coerces_legacy_string_external_false(tmp_path):
    agent_dir = _write_agent_config(
        tmp_path,
        'name: some-agent\ntype: background_script\nexternal: "false"\ninternal: "true"\n',
    )
    fake_identity = FakeIdentityManagerSync()

    sync_agent(fake_identity, agent_dir)

    saved = fake_identity.saved_configs["some-agent"]
    assert saved["external"] is False
    assert saved["internal"] is True


def test_sync_agent_coerces_legacy_string_external_true(tmp_path):
    agent_dir = _write_agent_config(
        tmp_path,
        'name: some-agent\ntype: background_script\nexternal: "true"\ninternal: "false"\n',
    )
    fake_identity = FakeIdentityManagerSync()

    sync_agent(fake_identity, agent_dir)

    saved = fake_identity.saved_configs["some-agent"]
    assert saved["external"] is True
    assert saved["internal"] is False


def test_sync_agent_overrides_mismatched_config_name_and_warns(tmp_path, capsys):
    """config.yaml's name: must never silently diverge from the directory/registry
    key -- a mismatch is a real lockout risk (see the WARNING comment in sync_agent
    itself). The registry key always wins, and the override must be loud."""
    agent_dir = tmp_path / "real-agent"
    agent_dir.mkdir()
    (agent_dir / "config.yaml").write_text(
        'name: wrong-name\ntype: background_script\nexternal: "true"\ninternal: "true"\n'
    )
    fake_identity = FakeIdentityManagerSync()

    sync_agent(fake_identity, agent_dir)

    saved = fake_identity.saved_configs["real-agent"]
    assert saved["name"] == "real-agent"

    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "wrong-name" in out
    assert "real-agent" in out


def test_sync_agent_matching_config_name_produces_no_warning(tmp_path, capsys):
    """The normal case -- config.yaml's name: already agrees with the directory/
    registry key -- must stay silent; only a genuine mismatch should warn."""
    agent_dir = _write_agent_config(
        tmp_path,
        'name: some-agent\ntype: background_script\nexternal: "true"\ninternal: "true"\n',
    )
    fake_identity = FakeIdentityManagerSync()

    sync_agent(fake_identity, agent_dir)

    saved = fake_identity.saved_configs["some-agent"]
    assert saved["name"] == "some-agent"

    out = capsys.readouterr().out
    assert "WARNING" not in out
