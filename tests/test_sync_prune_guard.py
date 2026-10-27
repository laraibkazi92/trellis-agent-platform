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
        # The tool-access policy is published before the prune pass; those writes are
        # not deletions, so they stay out of `manager.deleted`.
        self.documents = {}

    def put(self, path, value):
        self.documents[path] = value

    def get(self, path, **_kwargs):
        return self.documents.get(path), None

    def delete(self, path):
        self._manager.deleted.append(path)


class FakeIdentityManager:
    def __init__(self, agents=(), tools=(), mcps=(), tool_configs=None, mcp_configs=None):
        self._prefix_map = {
            "/registry/agents/": dict.fromkeys(agents, {}),
            "/registry/tools/": {
                name: dict((tool_configs or {}).get(name, {})) for name in tools
            },
            "/registry/mcps/": {
                name: dict((mcp_configs or {}).get(name, {})) for name in mcps
            },
        }
        self.deleted = []
        self.saved_configs = {}
        self.prefix_reads = []
        self.client = _FakeClient(self)

    def _get_all_configs_by_prefix(self, prefix):
        self.prefix_reads.append(prefix)
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
    # Tool sync computes rel_path relative to BASE_DIR; keep it inside the tmp tree so
    # a seeded tool.yaml does not resolve outside the sandbox.
    monkeypatch.setattr(sync_to_db, "BASE_DIR", tmp_path)
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


# --- edge-managed tools survive the prune ------------------------------------------
#
# The edge relay writes /registry/tools/<site>__<tool> for tools that never exist
# on the central disk. Sync is authoritative for everything else, so without this
# carve-out every rebuild would silently delete every remote tool.

EDGE_TOOL = "plant-floor__boiler_status"
EDGE_CONFIG = {"name": EDGE_TOOL, "runtime": "remote", "managed_by": "edge-relay"}


def _seed_local_tool(sync_env):
    """Give the workspace one real tool so the wiped-workspace guard stays out of the way."""
    tool_dir = sync_env / "tools" / "local_tool"
    tool_dir.mkdir(parents=True)
    (tool_dir / "tool.yaml").write_text(
        "name: local_tool\ndescription: local\nruntime: python\nentrypoint: main.py\n"
    )


def test_main_keeps_edge_managed_tools(sync_env, monkeypatch, capsys):
    _seed_local_tool(sync_env)
    fake = FakeIdentityManager(
        agents={"ticket-agent"}, tools={EDGE_TOOL}, tool_configs={EDGE_TOOL: EDGE_CONFIG}
    )
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert not [d for d in fake.deleted if EDGE_TOOL in d]
    assert "Keeping 1 edge-managed tool(s)" in capsys.readouterr().out


def test_force_prune_still_keeps_edge_managed_tools(sync_env, monkeypatch, capsys):
    """--force-prune bypasses the wiped-workspace guard, never the ownership carve-out."""
    fake = FakeIdentityManager(tools={EDGE_TOOL}, tool_configs={EDGE_TOOL: EDGE_CONFIG})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main(["--force-prune"])

    assert rc == 0
    assert fake.deleted == []
    assert "Keeping 1 edge-managed tool(s)" in capsys.readouterr().out


def test_main_prunes_local_tools_but_keeps_edge_tools(sync_env, monkeypatch):
    _seed_local_tool(sync_env)
    fake = FakeIdentityManager(
        agents={"ticket-agent"},
        tools={EDGE_TOOL, "text_stats"},
        tool_configs={EDGE_TOOL: EDGE_CONFIG, "text_stats": {}},
    )
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert "/registry/tools/text_stats/config" in fake.deleted
    assert "/registry/tools/text_stats/embedding" in fake.deleted
    assert f"/registry/tools/{EDGE_TOOL}/config" not in fake.deleted
    assert f"/registry/tools/{EDGE_TOOL}/embedding" not in fake.deleted


def test_main_treats_an_unmanaged_marker_as_a_normal_tool(sync_env, monkeypatch):
    """Only the exact marker protects a tool; a typo or another manager does not."""
    _seed_local_tool(sync_env)
    config = {"name": EDGE_TOOL, "runtime": "remote", "managed_by": "someone-else"}
    fake = FakeIdentityManager(
        agents={"ticket-agent"}, tools={EDGE_TOOL}, tool_configs={EDGE_TOOL: config}
    )
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert f"/registry/tools/{EDGE_TOOL}/config" in fake.deleted


# --- undecodable configs ------------------------------------------------------------


class _Meta:
    def __init__(self, key):
        self.key = key.encode("utf-8")


def test_prune_never_deletes_an_undecodable_tool_config(sync_env, monkeypatch):
    """A config that fails json.loads is dropped by the prefix parser, so it never
    enters the prune's name set. That is the fail-closed behaviour we want: an
    unreadable entry survives instead of being deleted as 'unknown'."""
    from core.auth import IdentityManager

    store = {"/registry/tools/broken/config": b"{not json"}

    class _Client:
        def get_prefix(self, prefix):
            return [
                (value, _Meta(key))
                for key, value in sorted(store.items())
                if key.startswith(prefix)
            ]

        def put(self, key, value):
            store[key] = value.encode("utf-8") if isinstance(value, str) else value

        def delete(self, path):
            store.pop(path, None)
            return True

    mgr = IdentityManager.__new__(IdentityManager)
    mgr.client = _Client()
    monkeypatch.setattr(sync_to_db, "IdentityManager", lambda **kwargs: mgr)
    _seed_local_tool(sync_env)

    rc = sync_to_db.main(["--force-prune"])

    assert rc == 0
    assert "/registry/tools/broken/config" in store


# --- edge references warn, never fail (Phase 7) -------------------------------------
#
# An agent authored against an edge that has not dialled in yet (or whose catalog the
# relay has not published yet) is a normal bring-up state. db-sync names the reference
# and carries on: exit code and prune behaviour are untouched, and the reference starts
# working the moment the edge connects (resolution is at runtime, not at sync).

EDGE_MCP_KEY = "dc1__devops-cli"
GHOST_MCP_KEY = "dc1__ghost-mcp"
EDGE_WILDCARD = "dc1__*"


def _edge_mcp_config(name):
    site, mcp = name.split("__", 1)
    return {
        "name": name,
        "transport": "remote",
        "remote": {"site": site, "mcp": mcp},
        "managed_by": "edge-relay",
        "tools": [],
    }


def _seed_agent(sync_env, name, **allowlists):
    """Write a workspace agent whose config.yaml declares ``allowlists``."""
    agent_dir = sync_env / "agents" / name
    agent_dir.mkdir()
    lines = [f"name: {name}", "type: user_agent"]
    for key, entries in allowlists.items():
        lines.append(f"{key}:")
        lines.extend(f"  - {entry}" for entry in entries)
    (agent_dir / "config.yaml").write_text("\n".join(lines) + "\n")


@pytest.mark.parametrize(
    "entry,expected",
    [
        (EDGE_MCP_KEY, ("pair", EDGE_MCP_KEY)),
        (EDGE_WILDCARD, ("site", "dc1")),
        ("mcp__dc1__devops-cli__tenant_account_tools", ("mcp", EDGE_MCP_KEY)),
        # Central / not-a-reference forms are never judged by db-sync.
        ("mcp__devops-cli__action", None),
        ("devops-cli", None),
        ("text_stats", None),
        # Ambiguous shapes resolve to nothing rather than to a guessed edge key.
        ("dc1__a__b", None),
        ("dc1__", None),
        (42, None),
    ],
)
def test_edge_ref_kind(entry, expected):
    assert sync_to_db._edge_ref_kind(entry) == expected


def test_main_warns_on_a_reference_to_a_not_yet_connected_edge_mcp(
    sync_env, monkeypatch, capsys
):
    _seed_agent(sync_env, "edge-agent", allowed_mcps=[GHOST_MCP_KEY])
    fake = FakeIdentityManager(agents={"edge-agent"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    out = capsys.readouterr().out
    assert rc == 0
    assert "WARNING:" in out
    assert "agent 'edge-agent'" in out
    assert GHOST_MCP_KEY in out
    assert "edge not connected / catalog not published yet" in out
    # The agent was still saved: a warning never aborts the sync.
    assert "edge-agent" in fake.saved_configs


def test_a_warning_does_not_change_the_prune(sync_env, monkeypatch, capsys):
    _seed_agent(sync_env, "edge-agent", allowed_mcps=[GHOST_MCP_KEY])
    fake = FakeIdentityManager(
        agents={"edge-agent", "gone-agent"},
        tools={"text_stats"},
    )
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    out = capsys.readouterr().out
    assert rc == 0
    assert "WARNING:" in out
    assert "/registry/agents/gone-agent/config" in fake.deleted
    assert "/registry/tools/text_stats/config" in fake.deleted


def test_no_warning_for_a_registered_edge_mcp(sync_env, monkeypatch, capsys):
    _seed_agent(sync_env, "edge-agent", allowed_mcps=[EDGE_MCP_KEY])
    fake = FakeIdentityManager(
        agents={"edge-agent"},
        mcps={EDGE_MCP_KEY},
        mcp_configs={EDGE_MCP_KEY: _edge_mcp_config(EDGE_MCP_KEY)},
    )
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert "WARNING" not in capsys.readouterr().out
    assert fake.deleted == []


def test_no_warning_for_central_mcp_references(sync_env, monkeypatch, capsys):
    """A plain server name or a 3-part `mcp__<server>__<tool>` is central: silent."""
    _seed_agent(
        sync_env,
        "central-agent",
        allowed_mcps=["example-mcp"],
        allowed_tools=["mcp__example-mcp__list", "text_stats"],
    )
    fake = FakeIdentityManager(agents={"central-agent"}, mcps={"example-mcp"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert "WARNING" not in capsys.readouterr().out


def test_a_wildcard_resolves_against_any_mcp_of_that_site(sync_env, monkeypatch, capsys):
    """`<site>__*` is satisfied by any `<site>__…` registry entry, and only by that site:
    `dc1__*` must not be satisfied by `dc10__x`."""
    _seed_agent(sync_env, "edge-agent", allowed_mcps=[EDGE_WILDCARD, "dc9__*"])
    fake = FakeIdentityManager(
        agents={"edge-agent"},
        mcps={EDGE_MCP_KEY},
        mcp_configs={EDGE_MCP_KEY: _edge_mcp_config(EDGE_MCP_KEY)},
    )
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    out = capsys.readouterr().out
    assert rc == 0
    assert "dc9__*" in out
    assert "dc1__*" not in out


def test_a_four_part_reference_to_a_ghost_edge_mcp_warns(sync_env, monkeypatch, capsys):
    entry = "mcp__dc1__ghost-mcp__chat"
    _seed_agent(sync_env, "edge-agent", allowed_tools=[entry])
    fake = FakeIdentityManager(agents={"edge-agent"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    out = capsys.readouterr().out
    assert rc == 0
    assert entry in out
    assert "edge not connected / catalog not published yet" in out


def test_a_two_part_reference_to_a_registered_edge_tool_does_not_warn(
    sync_env, monkeypatch, capsys
):
    """`<site>__<name>` is also the edge *tool* form; the tools prefix decides."""
    _seed_agent(sync_env, "edge-agent", allowed_tools=[EDGE_TOOL])
    fake = FakeIdentityManager(
        agents={"edge-agent"}, tools={EDGE_TOOL}, tool_configs={EDGE_TOOL: EDGE_CONFIG}
    )
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert "WARNING" not in capsys.readouterr().out
    assert f"/registry/tools/{EDGE_TOOL}/config" not in fake.deleted


def test_edge_reference_resolution_reads_the_mcps_prefix_once(sync_env, monkeypatch, capsys):
    """Four edge references, one `/registry/mcps/` read.

    The prune already needs the prefix, and the reference pass must reuse that snapshot:
    a per-reference read would put an etcd round trip on every `allowed_mcps` entry of
    every agent in the workspace.
    """
    _seed_agent(
        sync_env,
        "edge-agent",
        allowed_mcps=[EDGE_WILDCARD, GHOST_MCP_KEY, EDGE_MCP_KEY],
        allowed_tools=["mcp__dc1__ghost-mcp__chat", EDGE_TOOL],
    )
    fake = FakeIdentityManager(agents={"edge-agent"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert fake.prefix_reads.count("/registry/mcps/") == 1
    assert "edge not connected / catalog not published yet" in capsys.readouterr().out



# --- unreferenceable names ----------------------------------------------------------


def test_main_keeps_a_central_tool_name_ending_in_underscore(sync_env, monkeypatch, capsys):
    """A central tool is addressed by its bare name, so a trailing `_` stays legal --
    the reference-segment rule only applies to edge `<site>__<tool>` keys."""
    tool_dir = sync_env / "tools" / "odd"
    tool_dir.mkdir(parents=True)
    (tool_dir / "tool.yaml").write_text(
        "name: boiler_status_\nruntime: python\nentrypoint: run.py\n"
    )
    agent_dir = sync_env / "agents" / "keep-agent"
    agent_dir.mkdir()
    (agent_dir / "config.yaml").write_text("name: keep-agent\ntype: user_agent\n")
    fake = FakeIdentityManager(agents={"keep-agent"})
    _install_registry(monkeypatch, fake)

    rc = sync_to_db.main([])

    assert rc == 0
    assert "boiler_status_" in fake.saved_configs
