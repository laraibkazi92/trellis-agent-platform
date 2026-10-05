# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import asyncio

from core import tool_search
from scripts import sync_to_db


MCP_CONFIG = {
    "name": "example-mcp",
    "public": True,
    "public_tools": [],
    "tools": [
        {
            "name": "clusters_get_all",
            "description": "List all clusters and tenants.",
            "inputSchema": {"properties": {"env": {"type": "string"}}, "required": ["env"]},
        },
        {
            "name": "connector_restart",
            "description": "Restart a connector by id.",
            "inputSchema": {
                "properties": {
                    "connector_id": {"type": "string"},
                    "force": {"type": "boolean"},
                }
            },
        },
        {"name": "", "description": "Malformed entry with no name.", "inputSchema": {}},
    ],
}

# What real registration paths persist: transport/command/args/env/secrets but no
# tools list -- neither mcp.yaml nor marketplace add_mcp / admin save_mcp writes one.
TOOLS_LESS_CONFIG = {
    "name": "example-mcp",
    "transport": "stdio",
    "command": "npx",
    "args": ["-y", "@example/example-mcp-server"],
    "env": {"API_TOKEN": "{MY_API_KEY}"},
}


class FakeClient:
    """Records raw etcd key deletions (the prune path talks to the client directly)."""

    def __init__(self):
        self.deleted = []

    def delete(self, key):
        self.deleted.append(key)


class FakeIdentityManager:
    def __init__(self):
        self.saved_mcps = {}
        self.saved_tool_embeddings = {}
        self.client = FakeClient()
        self.deleted_mcp_embeddings = []

    def save_mcp_config(self, name, config):
        self.saved_mcps[name] = config

    def save_tool_embedding(self, name, vector):
        self.saved_tool_embeddings[name] = vector

    def delete_mcp_tool_embeddings(self, mcp_name):
        self.deleted_mcp_embeddings.append(mcp_name)


def _patch_registry(monkeypatch, tool_configs=None, mcp_configs=None, embeddings=None):
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_tool_configs", lambda: tool_configs or {})
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_mcp_configs", lambda: {"example-mcp": mcp_configs})
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_tool_embeddings", lambda: embeddings or {})
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_health_statuses", lambda entity_type: {})


# --- sync path (scripts/sync_to_db.py sync_mcp) --------------------------------------

def test_sync_mcp_indexes_one_embedding_per_tool(monkeypatch):
    mgr = FakeIdentityManager()
    calls = []

    def fake_embed_text(text, task_type):
        calls.append((text, task_type))
        return [1.0, 0.0, 0.0]

    monkeypatch.setattr(sync_to_db, "embed_text", fake_embed_text)

    sync_to_db.sync_mcp(mgr, MCP_CONFIG)

    assert set(mgr.saved_mcps) == {"example-mcp"}
    assert set(mgr.saved_tool_embeddings) == {
        "mcp__example-mcp__clusters_get_all",
        "mcp__example-mcp__connector_restart",
    }
    assert all(v == [1.0, 0.0, 0.0] for v in mgr.saved_tool_embeddings.values())
    assert all(task == "retrieval_document" for _, task in calls)
    # Embedding basis mirrors local tools: tool name + description + input schema params.
    cluster_text = next(t for t, _ in calls if "clusters_get_all" in t)
    assert "List all clusters and tenants." in cluster_text
    assert "env:string" in cluster_text
    assert not any(t for t, _ in calls if "Malformed entry" in t)


def test_sync_mcp_skips_embeddings_when_unavailable(monkeypatch):
    mgr = FakeIdentityManager()
    monkeypatch.setattr(sync_to_db, "embed_text", lambda text, task_type: None)

    sync_to_db.sync_mcp(mgr, MCP_CONFIG)

    assert set(mgr.saved_mcps) == {"example-mcp"}
    assert mgr.saved_tool_embeddings == {}


def test_sync_mcp_skips_discovery_when_tools_declared(monkeypatch):
    """A hand-declared tools list is the fast path: sync must not connect anywhere."""
    mgr = FakeIdentityManager()
    monkeypatch.setattr(
        sync_to_db, "_discover_mcp_tools", lambda config: (_ for _ in ()).throw(AssertionError("must not discover"))
    )
    monkeypatch.setattr(sync_to_db, "embed_text", lambda text, task_type: [1.0, 0.0, 0.0])

    sync_to_db.sync_mcp(mgr, MCP_CONFIG)

    assert set(mgr.saved_tool_embeddings) == {
        "mcp__example-mcp__clusters_get_all",
        "mcp__example-mcp__connector_restart",
    }


def test_sync_mcp_discovers_tools_when_config_has_none(monkeypatch):
    """No writer persists a tools list, so sync must live-discover one, persist it
    back into the etcd config, and index an embedding per discovered tool."""
    mgr = FakeIdentityManager()
    discovered = [
        {
            "name": "logs_search",
            "description": "Search logs.",
            "inputSchema": {"properties": {"q": {"type": "string"}}},
        },
        {"name": "logs_tail", "description": "Tail logs.", "inputSchema": {}},
    ]
    monkeypatch.setattr(sync_to_db, "_discover_mcp_tools", lambda config: discovered)
    monkeypatch.setattr(sync_to_db, "embed_text", lambda text, task_type: [1.0, 0.0, 0.0])

    sync_to_db.sync_mcp(mgr, dict(TOOLS_LESS_CONFIG))

    persisted = mgr.saved_mcps["example-mcp"]
    assert persisted["tools"] == discovered
    assert set(mgr.saved_tool_embeddings) == {
        "mcp__example-mcp__logs_search",
        "mcp__example-mcp__logs_tail",
    }


def test_sync_mcp_discovery_failure_is_non_fatal(monkeypatch):
    """An unreachable server must not fail the sync: config saved unchanged, no
    embeddings, no crash -- the runtime still discovers live."""
    mgr = FakeIdentityManager()
    monkeypatch.setattr(sync_to_db, "_discover_mcp_tools", lambda config: None)
    monkeypatch.setattr(sync_to_db, "embed_text", lambda text, task_type: [1.0, 0.0, 0.0])

    config = dict(TOOLS_LESS_CONFIG)
    sync_to_db.sync_mcp(mgr, config)

    assert mgr.saved_mcps["example-mcp"] == config
    assert "tools" not in mgr.saved_mcps["example-mcp"]
    assert mgr.saved_tool_embeddings == {}


def test_discover_mcp_tools_returns_none_for_unusable_transports():
    # No command to spawn/connect to.
    assert sync_to_db._discover_mcp_tools({"name": "x", "transport": "stdio"}) is None
    # Unknown transport type.
    assert (
        sync_to_db._discover_mcp_tools({"name": "x", "transport": "carrier-pigeon", "command": "coop"}) is None
    )


def test_discover_mcp_tools_tolerates_unspawnable_command():
    assert (
        sync_to_db._discover_mcp_tools(
            {"name": "broken", "transport": "stdio", "command": "/nonexistent/trellis-test-mcp-binary"}
        )
        is None
    )


# --- obsolescence prune (scripts/sync_to_db.py prune_obsolete_mcps) --------------------

def test_prune_obsolete_mcp_deletes_config_and_tool_embeddings():
    mgr = FakeIdentityManager()

    sync_to_db.prune_obsolete_mcps(mgr, existing_mcps={"gone-mcp", "kept-mcp"}, seen_mcps={"kept-mcp"})

    assert mgr.client.deleted == ["/registry/mcps/gone-mcp/config"]
    assert mgr.deleted_mcp_embeddings == ["gone-mcp"]


# --- search path (core/tool_search.py search_tools) ----------------------------------

def test_mcp_tool_with_embedding_ranks_via_cosine(monkeypatch):
    embeddings = {
        "mcp__example-mcp__clusters_get_all": [1.0, 0.0, 0.0],
        "mcp__example-mcp__connector_restart": [0.0, 1.0, 0.0],
    }
    _patch_registry(monkeypatch, mcp_configs=MCP_CONFIG, embeddings=embeddings)
    # Query embeds along clusters_get_all's vector and orthogonal to connector_restart's.
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: [1.0, 0.0, 0.0])

    results = asyncio.run(tool_search.search_tools("list customer service nodes"))

    assert results[0]["name"] == "mcp__example-mcp__clusters_get_all"


def test_mcp_tool_still_found_via_keyword_fallback_when_embeddings_unavailable(monkeypatch):
    _patch_registry(monkeypatch, mcp_configs=MCP_CONFIG, embeddings={})
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)

    results = asyncio.run(tool_search.search_tools("restart connector"))

    assert results[0]["name"] == "mcp__example-mcp__connector_restart"


def test_synced_mcp_embedding_keys_match_search_lookups(monkeypatch):
    """Closes the loop between the sync write key and the search read key: the vectors
    saved by sync_mcp are fed straight back through get_all_tool_embeddings, so any key
    drift (e.g. a bare tool name) silently zeroes both cosines."""
    mgr = FakeIdentityManager()

    def fake_sync_embed(text, task_type):
        return [1.0, 0.0, 0.0] if "clusters_get_all" in text else [0.0, 1.0, 0.0]

    monkeypatch.setattr(sync_to_db, "embed_text", fake_sync_embed)
    sync_to_db.sync_mcp(mgr, MCP_CONFIG)

    _patch_registry(monkeypatch, mcp_configs=MCP_CONFIG, embeddings=mgr.saved_tool_embeddings)
    # Query along connector_restart's vector — it is inserted after clusters_get_all, so a
    # key-mismatch tie (both cosines 0.0) would keep clusters_get_all first via stable sort
    # and fail this assertion.
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: [0.0, 1.0, 0.0])

    results = asyncio.run(tool_search.search_tools("customer service nodes"))

    assert results[0]["name"] == "mcp__example-mcp__connector_restart"
