# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for the registry prune guard in scripts/sync_to_db.py.

The guard exists so a mis-pointed TRELLIS_WORKSPACE_DIR (or a missing bind mount)
cannot silently wipe the registry: if sync saw nothing at all in the workspace while
etcd still holds entries, pruning is refused unless explicitly forced.
"""

import pytest

from scripts import sync_to_db


class _FakeClient:
    def __init__(self, manager):
        self._manager = manager

    def delete(self, path):
        self._manager.deleted.append(path)


class FakeIdentityManager:
    def __init__(self, agents=(), tools=(), mcps=()):
        self._prefix_map = {
            "/registry/agents/": dict.fromkeys(agents, {}),
            "/registry/tools/": dict.fromkeys(tools, {}),
            "/registry/mcps/": dict.fromkeys(mcps, {}),
        }
        self.deleted = []
        self.saved_configs = {}
        self.client = _FakeClient(self)

    def _get_all_configs_by_prefix(self, prefix):
        return self._prefix_map.get(prefix, {})

    def delete_mcp_tool_embeddings(self, name):
        self.deleted.append(f"<mcp-embeddings:{name}>")

    def save_agent_config(self, name, config):
        self.saved_configs[name] = dict(config)

    def save_agent_skills(self, name, skills):
        pass

    def save_agent_embedding(self, name, vector):
        pass

    def save_tool_config(self, name, config):
        self.saved_configs[name] = dict(config)

    def save_tool_embedding(self, name, vector):
        pass

    def save_mcp_config(self, name, config):
        self.saved_configs[name] = dict(config)

    def save_routing_rules(self, rules):
        pass


@pytest.fixture
def sync_env(monkeypatch, tmp_path):
    """Point sync_to_db at empty tmp workspace dirs and a nonexistent supervisor.

    SUPERVISOR_DIR must not resolve: the real one lives in the image and would be
    synced regardless of the workspace, masking the "empty workspace/agents/" case.
    """
    ws = tmp_path / "workspace"
    for sub in ("agents", "workflows", "tools", "mcps"):
        (ws / sub).mkdir(parents=True)
    monkeypatch.setattr(sync_to_db, "WORKSPACE_DIR", ws)
    monkeypatch.setattr(sync_to_db, "AGENTS_DIR", ws / "agents")
    monkeypatch.setattr(sync_to_db, "WORKFLOWS_DIR", ws / "workflows")
    monkeypatch.setattr(sync_to_db, "TOOLS_DIR", ws / "tools")
    monkeypatch.setattr(sync_to_db, "MCPS_DIR", ws / "mcps")
    monkeypatch.setattr(sync_to_db, "SUPERVISOR_DIR", ws / "no-supervisor")
    monkeypatch.setattr(sync_to_db, "embed_text", lambda *args, **kwargs: None)
    monkeypatch.delenv("SYNC_FORCE_PRUNE", raising=False)
    return ws


def _install_registry(monkeypatch, fake):
    monkeypatch.setattr(sync_to_db, "IdentityManager", lambda **kwargs: fake)


# --- _registry_would_be_wiped ------------------------------------------------------

def test_would_be_wiped_only_when_nothing_synced_but_registry_populated():
    blank = (set(), set(), set())
    assert sync_to_db._registry_would_be_wiped(({"a"}, set(), set()), blank) is True
    assert sync_to_db._registry_would_be_wiped((set(), {"t"}, set()), blank) is True
    # A blank workspace against an empty registry is fine (first run).
    assert sync_to_db._registry_would_be_wiped(blank, blank) is False
    # Anything synced anywhere means it is not a total blank -> allowed.
    assert sync_to_db._registry_would_be_wiped(({"a"}, set(), set()), (set(), {"t"}, set())) is False
    assert sync_to_db._registry_would_be_wiped(({"a"}, set(), set()), ({"a"}, set(), set())) is False


# --- _force_prune_requested --------------------------------------------------------

def test_force_prune_requested_default_false(monkeypatch):
    monkeypatch.delenv("SYNC_FORCE_PRUNE", raising=False)
    assert sync_to_db._force_prune_requested([]) is False


def test_force_prune_requested_flag():
    assert sync_to_db._force_prune_requested(["--force-prune"]) is True


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_force_prune_requested_env_truthy(monkeypatch, value):
    monkeypatch.setenv("SYNC_FORCE_PRUNE", value)
    assert sync_to_db._force_prune_requested([]) is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe"])
def test_force_prune_requested_env_falsy(monkeypatch, value):
    monkeypatch.setenv("SYNC_FORCE_PRUNE", value)
    assert sync_to_db._force_prune_requested([]) is False


# --- main() integration ------------------------------------------------------------

def test_main_refuses_to_wipe_populated_categories(sync_env, monkeypatch, capsys):
    fake = FakeIdentityManager(agents={"ticket-agent"}, tools={"tickets"}, mcps={"github"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 1
    assert fake.deleted == []
    out = capsys.readouterr().out
    assert "REFUSING TO PRUNE" in out
    for category, count in (("agents", 1), ("tools", 1), ("mcps", 1)):
        assert f"{category}: {count}" in out


def test_main_force_prune_allows_the_wipe(sync_env, monkeypatch):
    fake = FakeIdentityManager(agents={"ticket-agent"}, tools={"tickets"}, mcps={"github"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main(["--force-prune"])

    assert rc == 0
    # Every obsolete entry is removed for real.
    assert "/registry/agents/ticket-agent/config" in fake.deleted
    assert "/registry/agents/ticket-agent/skills" in fake.deleted
    assert "/registry/agents/ticket-agent/embedding" in fake.deleted
    assert "/registry/tools/tickets/config" in fake.deleted
    assert "/registry/tools/tickets/embedding" in fake.deleted
    assert "/registry/mcps/github/config" in fake.deleted
    assert "<mcp-embeddings:github>" in fake.deleted


def test_main_allows_ordinary_partial_prune(sync_env, monkeypatch):
    """The guard must not block the normal case: one agent deleted, others kept."""
    agent_dir = sync_env / "agents" / "keep-agent"
    agent_dir.mkdir()
    (agent_dir / "config.yaml").write_text(
        "name: keep-agent\ntype: user_agent\n"
    )
    fake = FakeIdentityManager(agents={"keep-agent", "gone-agent"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert "keep-agent" in fake.saved_configs
    assert fake.deleted == [
        "/registry/agents/gone-agent/config",
        "/registry/agents/gone-agent/skills",
        "/registry/agents/gone-agent/embedding",
    ]


def test_main_allows_a_whole_empty_category_when_another_category_syncs(sync_env, monkeypatch, capsys):
    """The guard is global, not per-category: an org with its own agents but no tools of
    its own yet must be able to prune the shipped demo tool without SYNC_FORCE_PRUNE --
    otherwise the documented first-run flow (delete the demo content, docs/deploy.md)
    would block the stack from starting."""
    agent_dir = sync_env / "agents" / "keep-agent"
    agent_dir.mkdir()
    (agent_dir / "config.yaml").write_text("name: keep-agent\ntype: user_agent\n")
    # text_stats is a registry entry with no source in this workspace: a whole category
    # that syncs nothing while agents still sync fine.
    fake = FakeIdentityManager(agents={"keep-agent", "demo-assistant"}, tools={"text_stats"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert "REFUSING TO PRUNE" not in capsys.readouterr().out
    assert "keep-agent" in fake.saved_configs
    assert "/registry/agents/demo-assistant/config" in fake.deleted
    assert "/registry/tools/text_stats/config" in fake.deleted


def test_main_no_guard_when_registry_is_empty(sync_env, monkeypatch, capsys):
    fake = FakeIdentityManager()
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert fake.deleted == []
    assert "REFUSING TO PRUNE" not in capsys.readouterr().out


def test_main_env_force_prune_allows_the_wipe(sync_env, monkeypatch):
    """The SYNC_FORCE_PRUNE env var (what the compose db-sync container uses) bypasses
    the guard end-to-end through main(), not just in the flag parser."""
    monkeypatch.setenv("SYNC_FORCE_PRUNE", "true")
    fake = FakeIdentityManager(agents={"ticket-agent"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert "/registry/agents/ticket-agent/config" in fake.deleted


def test_main_does_not_treat_supervisor_as_a_workspace_agent(sync_env, monkeypatch, capsys):
    """supervisor is synced from the image, not the workspace, so a registry holding
    only supervisor must NOT read as "agents category would be wiped" -- otherwise the
    guard would fire on an empty workspace/agents/ that is actually fine."""
    # SUPERVISOR_DIR is made to resolve nowhere by the fixture, so the only registry
    # agent is supervisor; the guard must still stay silent.
    fake = FakeIdentityManager(agents={"supervisor"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert "REFUSING TO PRUNE" not in capsys.readouterr().out
