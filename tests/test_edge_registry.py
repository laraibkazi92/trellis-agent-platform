# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for the P1 edge registry: site records, tokens, catalog publishing.

Two properties carry the design and are easy to lose in a refactor:

* the relay is the **sole writer** of ``/registry/tools/<site>__<tool>`` and
  ``managed_by: "edge-relay"`` is what proves ownership -- a name with the same
  prefix that we did not write must never be deleted or overwritten;
* enrollment tokens are shown once, stored only as a SHA-256 hash, and resolved
  through the ``/edge_tokens/<sha256> -> site`` index so the unauthenticated
  handshake is a single get.

The registry is a real ``IdentityManager`` bound to an in-memory etcd stand-in, so
the etcd key layout in these tests is the layout production uses.
"""

import asyncio
import json
import logging

import pytest

from core.auth import EDGE_TOKENS_PREFIX, IdentityManager
from services.edge_relay import registry
from services.edge_relay.protocol import EdgeMcp, EdgeMcpTool, EdgeTool

SITE = "plant-floor"
TOOL = "boiler_status"
REGISTRY_NAME = f"{SITE}__{TOOL}"
MCP = "devops-cli"
MCP_REGISTRY_NAME = f"{SITE}__{MCP}"
MCP_TOOL = "tenant_account_tools"
# Deliberately over the workload's ~26 KB: the schema must never reach the embedder.
_BIG_SCHEMA = {
    "type": "object",
    "oneOf": [
        {"properties": {"action": {"const": f"branch_{i}"}, "params": {"type": "object"}}}
        for i in range(900)
    ],
}


class _Meta:
    """The subset of pyetcd's ``KVMetadata`` the registry code reads."""

    def __init__(self, key):
        self.key = key.encode("utf-8")


class FakeClient:
    """In-memory stand-in for the pyetcd client (bytes in, ``(value, meta)`` out)."""

    def __init__(self):
        self.store = {}
        self.deleted = []

    def put(self, key, value):
        self.store[key] = value.encode("utf-8") if isinstance(value, str) else value

    def get(self, key):
        return self.store.get(key), None

    def delete(self, key):
        self.deleted.append(key)
        return self.store.pop(key, None) is not None

    def delete_prefix(self, prefix):
        for key in [k for k in self.store if k.startswith(prefix)]:
            self.store.pop(key, None)
        return True

    def get_prefix(self, prefix):
        return [
            (value, _Meta(key)) for key, value in sorted(self.store.items())
            if key.startswith(prefix)
        ]


def fake_identity_manager():
    """A real ``IdentityManager`` (real token + registry methods) with a fake client."""
    mgr = IdentityManager.__new__(IdentityManager)
    mgr.client = FakeClient()
    return mgr


@pytest.fixture
def mgr():
    return fake_identity_manager()


@pytest.fixture(autouse=True)
def _embeddings(monkeypatch):
    """Never call a provider from a unit test; a fixed vector proves the write."""
    monkeypatch.setattr("core.tool_index.embed_text", lambda *a, **k: [0.5, 0.25])


@pytest.fixture(autouse=True)
def _silence_health(monkeypatch):
    """publish_catalog resets tool health on reconnect; keep that out of sqlite."""
    monkeypatch.setattr(registry, "HealthMonitor", _NoopHealth)


class _NoopHealth:
    def __init__(self, identity_mgr):
        pass

    def record_event(self, *args, **kwargs):
        pass


def _tool(name=TOOL, description="read the boiler", **inputs):
    return EdgeTool(
        name=name,
        description=description,
        inputs=inputs or {"unit": {"type": "string", "required": True}},
    )


def _publish(mgr, tools, version="0.3.0"):
    return registry.publish_catalog(mgr, SITE, tools, version)


def _config(mgr, name):
    return mgr.get_tool_config(name)


def _embedding(mgr, name):
    value, _ = mgr.client.get(f"/registry/tools/{name}/embedding")
    return value


# --- publish_catalog ---------------------------------------------------------------


def test_publish_writes_the_remote_tool_config(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    published = _publish(mgr, [_tool()])

    assert published == [REGISTRY_NAME]
    assert _config(mgr, REGISTRY_NAME) == {
        "name": REGISTRY_NAME,
        "description": "read the boiler",
        "runtime": "remote",
        "inputs": {"unit": {"type": "string", "required": True}},
        "remote": {"site": SITE, "tool": TOOL},
        "managed_by": "edge-relay",
        "public": False,
        "public_tools": [],
        "retry_on_transient": False,
        "version": "0.1.0",
    }


def test_publish_never_borrows_central_secrets_or_paths(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    _publish(mgr, [_tool()])

    config = _config(mgr, REGISTRY_NAME)
    for forbidden in ("secrets", "variables", "secret_groups", "entrypoint", "rel_path"):
        assert forbidden not in config


def test_publish_inherits_public_visibility_from_the_site(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    config = mgr.get_edge_config(SITE)
    config["public"] = True
    config["public_tools"] = [TOOL]
    mgr.save_edge_config(SITE, config)

    _publish(mgr, [_tool()])

    published = _config(mgr, REGISTRY_NAME)
    assert published["public"] is True
    assert published["public_tools"] == [TOOL]


def _make_public(mgr, tools=None):
    config = mgr.get_edge_config(SITE)
    config["public"] = True
    config["public_tools"] = list(tools or [])
    mgr.save_edge_config(SITE, config)


def test_publish_indexes_an_embedding_per_public_tool(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _make_public(mgr)

    _publish(mgr, [_tool(), _tool(name="plant_readings", description="readings")])

    assert _embedding(mgr, REGISTRY_NAME) == b"[0.5, 0.25]"
    assert _embedding(mgr, f"{SITE}__plant_readings") == b"[0.5, 0.25]"


def test_publish_does_not_embed_internal_tools(mgr):
    """Matches local sync: only gateway-visible tools get a vector (cost + noise)."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    _publish(mgr, [_tool()])

    assert _config(mgr, REGISTRY_NAME) is not None
    assert _embedding(mgr, REGISTRY_NAME) is None


def test_publish_embeds_a_tool_whitelisted_even_when_the_site_is_private(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _make_public(mgr, tools=[TOOL])

    _publish(mgr, [_tool()])

    assert _embedding(mgr, REGISTRY_NAME) is not None


def test_publish_skips_reembedding_an_unchanged_tool(mgr, monkeypatch):
    """A flapping edge must not rebuild every vector on each reconnect."""
    index_calls = []
    monkeypatch.setattr(
        registry, "index_tool", lambda m, n, d, i: index_calls.append(n) or True
    )
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _make_public(mgr)

    _publish(mgr, [_tool()])
    _publish(mgr, [_tool()])

    assert index_calls == [REGISTRY_NAME]


def test_publish_reembeds_when_the_description_changes(mgr, monkeypatch):
    index_calls = []
    monkeypatch.setattr(
        registry, "index_tool", lambda m, n, d, i: index_calls.append(n) or True
    )
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _make_public(mgr)

    _publish(mgr, [_tool()])
    _publish(mgr, [_tool(description="read the boiler, v2")])

    assert index_calls == [REGISTRY_NAME, REGISTRY_NAME]


def test_publish_still_offers_every_public_tool_to_the_indexer_when_embeddings_are_off(mgr, monkeypatch):
    """An unreachable embedder must not silently skip the tool: configs still land."""
    seen = []
    monkeypatch.setattr(registry, "index_tool", lambda m, n, d, i: seen.append(n))
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _make_public(mgr)

    _publish(mgr, [_tool()])

    assert seen == [REGISTRY_NAME]
    assert _config(mgr, REGISTRY_NAME)["runtime"] == "remote"


def test_non_empty_exports_filter_the_catalog(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com", exports=[TOOL])

    published = _publish(mgr, [_tool(), _tool(name="plant_readings")])

    assert published == [REGISTRY_NAME]
    assert _config(mgr, f"{SITE}__plant_readings") is None


def test_empty_exports_accept_whatever_the_edge_publishes(mgr):
    """The edge enforces its own allowlist; an empty admin list must not mean "none"."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com", exports=[])

    published = _publish(mgr, [_tool(), _tool(name="plant_readings")])

    assert published == [REGISTRY_NAME, f"{SITE}__plant_readings"]


def test_a_local_tool_with_the_same_name_wins(mgr, caplog):
    local = {"name": REGISTRY_NAME, "runtime": "python", "entrypoint": "main.py"}
    mgr.client.put(f"/registry/tools/{REGISTRY_NAME}/config", json.dumps(local))
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    with caplog.at_level(logging.WARNING, logger="services.edge_relay.registry"):
        published = _publish(mgr, [_tool()])

    assert published == []
    assert _config(mgr, REGISTRY_NAME) == local
    assert _embedding(mgr, REGISTRY_NAME) is None
    assert "collides with an existing non-edge tool" in caplog.text


def test_publish_prunes_tools_dropped_from_the_catalog(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _make_public(mgr)
    _publish(mgr, [_tool(), _tool(name="plant_readings")])
    assert _embedding(mgr, f"{SITE}__plant_readings") is not None

    _publish(mgr, [_tool()])

    assert _config(mgr, f"{SITE}__plant_readings") is None
    assert _embedding(mgr, f"{SITE}__plant_readings") is None
    assert _config(mgr, REGISTRY_NAME) is not None


def test_prune_never_deletes_a_tool_the_relay_does_not_own(mgr):
    foreign = {"name": f"{SITE}__legacy", "runtime": "python", "entrypoint": "main.py"}
    unmarked = {"name": f"{SITE}__older", "runtime": "remote", "managed_by": "someone-else"}
    import json

    mgr.client.put(f"/registry/tools/{SITE}__legacy/config", json.dumps(foreign))
    mgr.client.put(f"/registry/tools/{SITE}__older/config", json.dumps(unmarked))
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    _publish(mgr, [_tool()])

    assert _config(mgr, f"{SITE}__legacy") == foreign
    assert _config(mgr, f"{SITE}__older") == unmarked


def test_publish_refuses_a_deleted_or_disabled_site(mgr):
    with pytest.raises(ValueError, match="not registered or is disabled"):
        _publish(mgr, [_tool()])

    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    mgr.revoke_edge_token(SITE)
    with pytest.raises(ValueError, match="not registered or is disabled"):
        _publish(mgr, [_tool()])


def test_publish_writes_a_connected_status(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    _publish(mgr, [_tool()], version="0.4.1")

    status = mgr.get_edge_status(SITE)
    assert status["connected"] is True
    assert status["edge_version"] == "0.4.1"
    assert status["tools"] == [REGISTRY_NAME]
    assert status["last_error"] is None
    assert status["connected_at"]


# --- mark_disconnected -------------------------------------------------------------


class _Recorder:
    events = []

    def __init__(self, identity_mgr):
        self.identity_mgr = identity_mgr

    def record_event(self, entity_type, name, is_success, error_details=None):
        _Recorder.events.append((entity_type, name, is_success, error_details))


@pytest.fixture
def health_events(monkeypatch):
    _Recorder.events = []
    monkeypatch.setattr(registry, "HealthMonitor", _Recorder)
    return _Recorder.events


def test_mark_disconnected_flips_status_and_keeps_the_inventory(mgr, health_events):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _make_public(mgr)
    _publish(mgr, [_tool()], version="0.3.0")
    connected_at = mgr.get_edge_status(SITE)["connected_at"]

    health_events.clear()  # drop the connect-time reset recorded by publish
    registry.mark_disconnected(mgr, SITE, "socket closed")

    status = mgr.get_edge_status(SITE)
    assert status["connected"] is False
    assert status["connected_at"] == connected_at
    assert status["disconnected_at"]
    assert status["edge_version"] == "0.3.0"
    assert status["tools"] == [REGISTRY_NAME]
    assert status["last_error"] == "socket closed"
    # The tool survives so an admin can still see (and re-connect) what the site offers.
    assert _config(mgr, REGISTRY_NAME) is not None
    assert _embedding(mgr, REGISTRY_NAME) is not None


def test_mark_disconnected_records_a_health_failure_per_published_tool(mgr, health_events):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish(mgr, [_tool(), _tool(name="plant_readings")])

    health_events.clear()  # drop the connect-time reset recorded by publish
    registry.mark_disconnected(mgr, SITE, "socket closed")

    assert health_events == [
        ("tool", REGISTRY_NAME, False, "edge 'plant-floor' disconnected: socket closed"),
        ("tool", f"{SITE}__plant_readings", False, "edge 'plant-floor' disconnected: socket closed"),
    ]


# --- delete_edge / delete_edge_tools ----------------------------------------------


def test_delete_edge_tools_counts_only_edge_owned_tools(mgr, caplog):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish(mgr, [_tool()])
    foreign = {"name": f"{SITE}__legacy", "runtime": "python", "entrypoint": "main.py"}
    import json

    mgr.client.put(f"/registry/tools/{SITE}__legacy/config", json.dumps(foreign))

    with caplog.at_level(logging.WARNING, logger="core.auth"):
        removed = mgr.delete_edge_tools(SITE)

    assert removed == 1
    assert _config(mgr, REGISTRY_NAME) is None
    assert _embedding(mgr, REGISTRY_NAME) is None
    assert _config(mgr, f"{SITE}__legacy") == foreign
    assert "not managed by the edge relay" in caplog.text


def test_delete_edge_removes_config_status_token_and_tools(mgr):
    token = mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    digest = mgr.get_edge_config(SITE)["token_hash"]
    _publish(mgr, [_tool()])

    mgr.delete_edge(SITE)

    assert mgr.get_edge_config(SITE) is None
    assert mgr.get_edge_status(SITE) is None
    assert mgr.client.get(f"{EDGE_TOKENS_PREFIX}{digest}") == (None, None)
    assert _config(mgr, REGISTRY_NAME) is None
    assert mgr.resolve_edge_token(token) is None
    assert mgr.list_edges() == []


def test_delete_edge_removes_the_mcp_catalog_and_its_embeddings(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish(mgr, [_tool()])
    _publish_mcps(mgr, [_mcp(), _mcp(name="k8s-tools")])
    assert _mcp_embedding(mgr) is not None

    mgr.delete_edge(SITE)

    assert _mcp_config(mgr) is None
    assert _mcp_config(mgr, f"{SITE}__k8s-tools") is None
    assert _mcp_embedding(mgr) is None
    assert _mcp_embedding(mgr, mcp="k8s-tools") is None
    # The tools half is still removed by the same call.
    assert _config(mgr, REGISTRY_NAME) is None


def test_delete_edge_mcps_refuses_a_server_the_relay_does_not_own(mgr, caplog):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish_mcps(mgr, [_mcp()])
    foreign = {"name": f"{SITE}__legacy", "transport": "stdio", "command": "npx"}
    mgr.client.put(f"/registry/mcps/{SITE}__legacy/config", json.dumps(foreign))

    with caplog.at_level(logging.WARNING, logger="core.auth"):
        removed = mgr.delete_edge_mcps(SITE)

    assert removed == 1
    assert _mcp_config(mgr) is None
    assert _mcp_config(mgr, f"{SITE}__legacy") == foreign
    assert "not managed by the edge relay" in caplog.text


# --- Token lifecycle ---------------------------------------------------------------


def test_create_edge_returns_a_token_once_and_stores_only_its_hash(mgr):
    token = mgr.create_edge(SITE, "Plant floor", "admin@example.com", exports=[TOOL])

    config = mgr.get_edge_config(SITE)
    assert token.startswith(f"edge_{SITE}_")
    assert config["token_hash"] != token
    assert config["token_preview"] == f"edge_{SITE}_...{token[-4:]}"
    assert config["version"] == "v1"
    assert config["created_by"] == "admin@example.com"
    assert config["enabled"] is True
    assert config["public"] is False
    assert config["public_tools"] == []
    assert config["exports"] == [TOOL]
    # The plaintext exists nowhere in the registry, only as the index key's hash.
    assert not [v for v in mgr.client.store.values() if token.encode("utf-8") in v]
    assert mgr.resolve_edge_token(token) == SITE
    assert mgr.list_edges() == [SITE]


def test_create_edge_rejects_duplicates(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    with pytest.raises(ValueError, match="already exists"):
        mgr.create_edge(SITE, "Again", "admin@example.com")


@pytest.mark.parametrize("bad", ["bad__site", "has space", "x" * 65, "", "-leading", "a/b"])
def test_create_edge_rejects_invalid_site_names(mgr, bad):
    with pytest.raises(ValueError):
        mgr.create_edge(bad, "Bad", "admin@example.com")


def test_rotate_invalidates_the_old_token_and_keeps_the_record(mgr):
    old = mgr.create_edge(SITE, "Plant floor", "admin@example.com", exports=[TOOL])
    before = mgr.get_edge_config(SITE)

    new = mgr.rotate_edge_token(SITE, "admin@example.com")

    after = mgr.get_edge_config(SITE)
    assert new != old
    assert mgr.resolve_edge_token(old) is None
    assert mgr.resolve_edge_token(new) == SITE
    assert after["token_hash"] != before["token_hash"]
    assert after["token_preview"] == f"edge_{SITE}_...{new[-4:]}"
    for unchanged in ("display_name", "created_by", "created_at", "exports", "public"):
        assert after[unchanged] == before[unchanged]
    # Exactly one index entry survives, so the old key cannot be resurrected.
    index_keys = [key for key in mgr.client.store if key.startswith(EDGE_TOKENS_PREFIX)]
    assert index_keys == [f"{EDGE_TOKENS_PREFIX}{after['token_hash']}"]


def test_rotate_unknown_site_raises(mgr):
    with pytest.raises(ValueError, match="not found"):
        mgr.rotate_edge_token("ghost", "admin@example.com")


def test_rotate_re_enables_a_revoked_site(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    mgr.revoke_edge_token(SITE)

    token = mgr.rotate_edge_token(SITE, "admin@example.com")

    assert mgr.get_edge_config(SITE)["enabled"] is True
    assert mgr.resolve_edge_token(token) == SITE


def test_revoke_fails_closed_even_if_the_index_entry_survives(mgr):
    token = mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    digest = mgr.get_edge_config(SITE)["token_hash"]

    mgr.revoke_edge_token(SITE)

    config = mgr.get_edge_config(SITE)
    assert config["enabled"] is False
    # Kept for audit, and the index key is gone.
    assert config["token_hash"] == digest
    assert mgr.client.get(f"{EDGE_TOKENS_PREFIX}{digest}") == (None, None)
    assert mgr.resolve_edge_token(token) is None

    # Simulate the interrupted case: index present, site revoked -> still refused.
    mgr.client.put(f"{EDGE_TOKENS_PREFIX}{digest}", json.dumps(SITE))
    assert mgr.resolve_edge_token(token) is None


def test_revoke_unknown_site_is_a_noop(mgr, caplog):
    with caplog.at_level(logging.WARNING, logger="core.auth"):
        mgr.revoke_edge_token("ghost")

    assert "nothing to revoke" in caplog.text


def test_resolve_rejects_a_stale_index_entry(mgr):
    """A rotation whose index delete was lost must not keep the old token alive."""
    token = mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    digest = mgr.get_edge_config(SITE)["token_hash"]
    mgr.rotate_edge_token(SITE, "admin@example.com")
    # Re-create the old index entry by hand: the stored hash no longer matches.
    mgr.client.put(f"{EDGE_TOKENS_PREFIX}{digest}", json.dumps(SITE))

    assert mgr.resolve_edge_token(token) is None


def test_resolve_ignores_unknown_and_empty_tokens(mgr):
    assert mgr.resolve_edge_token("") is None
    assert mgr.resolve_edge_token("edge_nobody_abc") is None


def test_reserved_site_names_are_refused_by_the_manager(mgr):
    """`mcp` is reserved for MCP tool names; a manager that accepts it would create
    tools in the mcp__ prefix that tool_search treats as server-owned."""
    with pytest.raises(ValueError):
        mgr.create_edge("mcp", "MCP", "admin@example.com")
    with pytest.raises(ValueError):
        mgr.create_edge("a__b", "Nested", "admin@example.com")
    with pytest.raises(ValueError):
        mgr.create_edge("bad name!", "Bad", "admin@example.com")


def test_dev_hatch_site_can_publish_without_a_registry_record(mgr, monkeypatch):
    """.env.example advertises the DEV_MODE tunnel without enrollment; it must work."""
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("EDGE_DEV_SITE", "dev-edge")

    published = registry.publish_catalog(mgr, "dev-edge", [_tool()], "0.0.0")

    assert published == ["dev-edge__boiler_status"]
    assert _config(mgr, "dev-edge__boiler_status")["managed_by"] == "edge-relay"


def test_dev_hatch_does_not_open_a_production_relay(mgr, monkeypatch):
    monkeypatch.setenv("DEV_MODE", "false")
    monkeypatch.setenv("EDGE_DEV_SITE", "dev-edge")

    with pytest.raises(ValueError):
        registry.publish_catalog(mgr, "dev-edge", [_tool()], "0.0.0")


def test_a_whitelisted_tool_is_public_even_when_the_site_is_not(mgr):
    """tool_search only honours `public` for non-mcp tools, so a public_tools entry
    has to be folded into the flag or it means nothing."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    config = mgr.get_edge_config(SITE)
    config["public_tools"] = [TOOL]
    mgr.save_edge_config(SITE, config)

    _publish(mgr, [_tool()])

    published = _config(mgr, REGISTRY_NAME)
    assert published["public"] is True
    assert _embedding(mgr, REGISTRY_NAME) is not None


def test_an_empty_catalog_keeps_the_existing_inventory(mgr):
    """A mistyped tools_dir must not wipe the site's central tools."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish(mgr, [_tool()])

    published = _publish(mgr, [])

    assert published == [REGISTRY_NAME]
    assert _config(mgr, REGISTRY_NAME) is not None
    assert "empty catalog" in (mgr.get_edge_status(SITE) or {}).get("last_error", "")


def test_an_admin_driven_empty_catalog_still_prunes(mgr):
    """Narrowing exports to nothing is explicit intent, not a misconfiguration."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish(mgr, [_tool()])

    published = registry.publish_catalog(mgr, SITE, [], "0.3.0", allow_empty=True)

    assert published == []
    assert _config(mgr, REGISTRY_NAME) is None


# --- publish_mcp_catalog -----------------------------------------------------------


def _mcp_tool(name=MCP_TOOL, description="manage tenants", schema=None):
    return EdgeMcpTool(
        name=name,
        description=description,
        input_schema=schema
        if schema is not None
        else {"type": "object", "oneOf": [{"properties": {"action": {"const": "list_actions"}}}]},
    )


def _mcp(name=MCP, transport="stdio", tools=None):
    return EdgeMcp(name=name, transport=transport, tools=tools or [_mcp_tool()])


def _publish_mcps(mgr, mcps, version="0.5.0", **kwargs):
    return registry.publish_mcp_catalog(mgr, SITE, mcps, version, **kwargs)


def _mcp_config(mgr, name=MCP_REGISTRY_NAME):
    return mgr.get_mcp_config(name)


def _mcp_embedding(mgr, tool=MCP_TOOL, mcp=MCP):
    value, _ = mgr.client.get(f"/registry/tools/mcp__{SITE}__{mcp}__{tool}/embedding")
    return value


def test_publish_mcp_writes_the_remote_server_config(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    published = _publish_mcps(mgr, [_mcp()])

    assert published == [MCP_REGISTRY_NAME]
    assert _mcp_config(mgr) == {
        "name": MCP_REGISTRY_NAME,
        "description": "",
        "transport": "remote",
        "tools": [
            {
                "name": MCP_TOOL,
                "description": "manage tenants",
                "inputSchema": {
                    "type": "object",
                    "oneOf": [{"properties": {"action": {"const": "list_actions"}}}],
                },
            }
        ],
        "remote": {"site": SITE, "mcp": MCP},
        "managed_by": "edge-relay",
        "public": False,
        "public_tools": [],
        "edge_transport": "stdio",
        "version": "0.1.0",
    }


def test_publish_mcp_never_borrows_credentials_or_a_launch_command(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    _publish_mcps(mgr, [_mcp()])

    config = _mcp_config(mgr)
    for forbidden in ("command", "args", "env", "secrets", "variables", "secret_groups"):
        assert forbidden not in config


def test_publish_mcp_carries_the_schema_verbatim(mgr):
    """L6: a 26 KB+ root-level `oneOf` must survive the registry untouched."""
    schema = _BIG_SCHEMA
    assert len(json.dumps(schema, separators=(",", ":")).encode("utf-8")) > 26_000
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    _publish_mcps(mgr, [_mcp(tools=[_mcp_tool(schema=schema)])])

    stored = _mcp_config(mgr)["tools"][0]["inputSchema"]
    assert stored == schema
    assert (
        json.dumps(stored, separators=(",", ":"))
        == json.dumps(schema, separators=(",", ":"))
    )


def test_publish_mcp_status_carries_mcps_proto_and_caps(mgr):
    """One handshake, one status record: the tool half must survive the MCP write."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    mcps = [_mcp(), _mcp(name="k8s-tools", transport="http")]

    registry.publish_catalog(
        mgr, SITE, [_tool()], "0.5.0", mcps=mcps, proto=2, caps=["tools", "mcp"]
    )
    _publish_mcps(mgr, mcps, proto=2, caps=["tools", "mcp"])

    status = mgr.get_edge_status(SITE)
    assert status["connected"] is True
    assert status["tools"] == [REGISTRY_NAME]
    assert status["mcps"] == [
        {"name": MCP, "tools": 1, "transport": "stdio"},
        {"name": "k8s-tools", "tools": 1, "transport": "http"},
    ]
    assert status["proto"] == 2
    assert status["caps"] == ["tools", "mcp"]


def test_a_tools_only_edge_still_writes_an_empty_mcp_list(mgr):
    """v0.4 semantics on a v0.5 relay: the admin page must show "no MCPs", not unknown."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    registry.publish_catalog(
        mgr, SITE, [_tool()], "0.4.1", mcps=[], proto=1, caps=["tools"]
    )
    _publish_mcps(mgr, [], proto=1, caps=["tools"])

    status = mgr.get_edge_status(SITE)
    assert status["mcps"] == []
    assert status["tools"] == [REGISTRY_NAME]


def test_publish_mcp_prunes_servers_dropped_from_the_catalog(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish_mcps(mgr, [_mcp(), _mcp(name="k8s-tools")])
    assert _mcp_embedding(mgr, mcp="k8s-tools") is not None

    _publish_mcps(mgr, [_mcp()])

    assert _mcp_config(mgr, f"{SITE}__k8s-tools") is None
    # A pruned server's tool embeddings must go too, or search keeps ranking them.
    assert _mcp_embedding(mgr, mcp="k8s-tools") is None
    assert _mcp_config(mgr) is not None


def test_prune_never_deletes_an_mcp_the_relay_does_not_own(mgr):
    foreign = {"name": f"{SITE}__legacy", "transport": "stdio", "command": "npx"}
    mgr.client.put(f"/registry/mcps/{SITE}__legacy/config", json.dumps(foreign))
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    _publish_mcps(mgr, [_mcp()])

    assert _mcp_config(mgr, f"{SITE}__legacy") == foreign


def test_a_local_mcp_with_the_same_name_wins(mgr, caplog):
    local = {"name": MCP_REGISTRY_NAME, "transport": "stdio", "command": "npx"}
    mgr.client.put(f"/registry/mcps/{MCP_REGISTRY_NAME}/config", json.dumps(local))
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    with caplog.at_level(logging.WARNING, logger="services.edge_relay.registry"):
        published = _publish_mcps(mgr, [_mcp()])

    assert published == []
    assert _mcp_config(mgr) == local
    assert _mcp_embedding(mgr) is None
    assert "collides with an existing non-edge MCP" in caplog.text


def test_an_empty_mcp_catalog_keeps_the_existing_inventory(mgr):
    """A mistyped export_mcps must not wipe the site's central MCP servers."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish_mcps(mgr, [_mcp(transport="sse")])

    published = _publish_mcps(mgr, [])

    assert published == [MCP_REGISTRY_NAME]
    assert _mcp_config(mgr) is not None
    status = mgr.get_edge_status(SITE)
    assert "no MCPs" in status["last_error"]
    # The kept catalog is still described in the status (transport included).
    assert status["mcps"] == [{"name": MCP, "tools": 1, "transport": "sse"}]


def test_an_admin_driven_empty_mcp_catalog_still_prunes(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish_mcps(mgr, [_mcp()])

    published = _publish_mcps(mgr, [], allow_empty=True)

    assert published == []
    assert _mcp_config(mgr) is None


def test_mcp_embeddings_use_the_description_only(mgr, monkeypatch):
    """The schema (26 KB+) must never be embedding input; inputs=None proves it."""
    calls = []
    monkeypatch.setattr(
        registry,
        "index_tool",
        lambda m, name, description, inputs=None, *, embedding_name=None: calls.append(
            (name, description, inputs, embedding_name)
        )
        or True,
    )
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    _publish_mcps(mgr, [_mcp(tools=[_mcp_tool(schema=_BIG_SCHEMA)])])

    key = f"mcp__{SITE}__{MCP}__{MCP_TOOL}"
    assert calls == [(key, "manage tenants", None, key)]


def test_mcp_embeddings_are_not_rebuilt_for_an_unchanged_catalog(mgr, monkeypatch):
    calls = []
    monkeypatch.setattr(
        registry,
        "index_tool",
        lambda m, name, *args, **kwargs: calls.append(name) or True,
    )
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    _publish_mcps(mgr, [_mcp()])
    _publish_mcps(mgr, [_mcp()])

    assert calls == [f"mcp__{SITE}__{MCP}__{MCP_TOOL}"]


def test_mcp_embeddings_are_rebuilt_when_a_description_changes(mgr, monkeypatch):
    calls = []
    monkeypatch.setattr(
        registry,
        "index_tool",
        lambda m, name, *args, **kwargs: calls.append(name) or True,
    )
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    _publish_mcps(mgr, [_mcp()])
    _publish_mcps(mgr, [_mcp(tools=[_mcp_tool(description="manage tenants, v2")])])

    assert calls == [f"mcp__{SITE}__{MCP}__{MCP_TOOL}"] * 2


def test_an_unavailable_embedder_still_publishes_the_mcp(mgr, monkeypatch, caplog):
    monkeypatch.setattr(registry, "index_tool", lambda *args, **kwargs: False)
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    with caplog.at_level(logging.WARNING, logger="services.edge_relay.registry"):
        _publish_mcps(mgr, [_mcp()])

    assert _mcp_config(mgr)["transport"] == "remote"
    assert "embeddings unavailable" in caplog.text


def test_publish_mcp_refuses_a_deleted_or_disabled_site(mgr):
    with pytest.raises(ValueError, match="not registered or is disabled"):
        _publish_mcps(mgr, [_mcp()])


def test_mark_disconnected_preserves_the_mcp_catalog(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    registry.publish_catalog(
        mgr, SITE, [_tool()], "0.5.0", mcps=[_mcp()], proto=2, caps=["tools", "mcp"]
    )
    _publish_mcps(mgr, [_mcp()], proto=2, caps=["tools", "mcp"])

    registry.mark_disconnected(mgr, SITE, "socket closed")

    status = mgr.get_edge_status(SITE)
    assert status["connected"] is False
    assert status["mcps"] == [{"name": MCP, "tools": 1, "transport": "stdio"}]
    assert status["proto"] == 2
    assert status["caps"] == ["tools", "mcp"]
    assert _mcp_config(mgr) is not None


# --- db-sync carve-out --------------------------------------------------------------
#
# /registry/mcps/<site>__<mcp> never exists on the central disk either, so the prune
# needs the same ownership rule it already has for tools.


class _SyncClient:
    def __init__(self, deleted):
        self._deleted = deleted

    def delete(self, path):
        self._deleted.append(path)
        return True

    def delete_prefix(self, prefix):
        self._deleted.append(f"<prefix:{prefix}>")
        return True


class _SyncMgr:
    """The slice of IdentityManager ``sync_to_db.main()`` touches, with no etcd."""

    def __init__(self, mcp_configs, agent_configs=None):
        self.mcp_configs = mcp_configs
        self.agent_configs = agent_configs or {}
        self.deleted = []
        self.saved = {}
        self.client = _SyncClient(self.deleted)

    def _get_all_configs_by_prefix(self, prefix):
        if prefix == "/registry/mcps/":
            return dict(self.mcp_configs)
        if prefix == "/registry/agents/":
            return dict(self.agent_configs)
        return {}

    def delete_mcp_tool_embeddings(self, name):
        self.deleted.append(f"<mcp-embeddings:{name}>")

    def save_agent_config(self, name, config):
        self.saved[name] = dict(config)

    def save_agent_skills(self, name, skills):
        pass

    def save_agent_embedding(self, name, vector):
        pass

    def save_tool_config(self, name, config):
        self.saved[name] = dict(config)

    def save_tool_embedding(self, name, vector):
        pass

    def save_mcp_config(self, name, config):
        self.saved[name] = dict(config)

    def save_routing_rules(self, rules):
        pass


@pytest.fixture
def sync_module(monkeypatch, tmp_path):
    """Point ``scripts.sync_to_db`` at an empty tmp workspace and a fake registry."""
    from scripts import sync_to_db

    ws = tmp_path / "workspace"
    for sub in ("agents", "workflows", "tools", "mcps"):
        (ws / sub).mkdir(parents=True)
    monkeypatch.setattr(sync_to_db, "BASE_DIR", tmp_path)
    monkeypatch.setattr(sync_to_db, "WORKSPACE_DIR", ws)
    monkeypatch.setattr(sync_to_db, "AGENTS_DIR", ws / "agents")
    monkeypatch.setattr(sync_to_db, "WORKFLOWS_DIR", ws / "workflows")
    monkeypatch.setattr(sync_to_db, "TOOLS_DIR", ws / "tools")
    monkeypatch.setattr(sync_to_db, "MCPS_DIR", ws / "mcps")
    monkeypatch.setattr(sync_to_db, "SUPERVISOR_DIR", ws / "no-supervisor")
    monkeypatch.setattr(sync_to_db, "embed_text", lambda *a, **k: None)
    monkeypatch.delenv("SYNC_FORCE_PRUNE", raising=False)
    return sync_to_db


EDGE_MCP = f"{SITE}__{MCP}"
EDGE_MCP_CONFIG = {
    "name": EDGE_MCP,
    "transport": "remote",
    "remote": {"site": SITE, "mcp": MCP},
    "managed_by": "edge-relay",
}


def _seed_synced_agent(sync_module, ws_root):
    agent_dir = ws_root / "agents" / "keep-agent"
    agent_dir.mkdir(parents=True)
    (agent_dir / "config.yaml").write_text("name: keep-agent\ntype: user_agent\n")


def test_sync_prune_keeps_edge_managed_mcps(sync_module, monkeypatch, capsys):
    fake = _SyncMgr(
        {EDGE_MCP: EDGE_MCP_CONFIG, "legacy-mcp": {"name": "legacy-mcp"}},
        agent_configs={"keep-agent": {}},
    )
    monkeypatch.setattr(sync_module, "IdentityManager", lambda **kwargs: fake)
    _seed_synced_agent(sync_module, sync_module.WORKSPACE_DIR)

    assert sync_module.main([]) == 0

    assert f"/registry/mcps/{EDGE_MCP}/config" not in fake.deleted
    # A central MCP with no workspace/mcp.yaml is still pruned...
    assert "/registry/mcps/legacy-mcp/config" in fake.deleted
    assert "<mcp-embeddings:legacy-mcp>" in fake.deleted
    # ...and the relay-owned one is reported, not silently skipped.
    assert "Keeping 1 edge-managed MCP(s)" in capsys.readouterr().out


def test_force_prune_still_keeps_edge_managed_mcps(sync_module, monkeypatch, capsys):
    """--force-prune bypasses the wiped-workspace guard, never ownership."""
    fake = _SyncMgr({EDGE_MCP: EDGE_MCP_CONFIG})
    monkeypatch.setattr(sync_module, "IdentityManager", lambda **kwargs: fake)

    assert sync_module.main(["--force-prune"]) == 0

    assert fake.deleted == []
    assert "Keeping 1 edge-managed MCP(s)" in capsys.readouterr().out


# --- published MCP visibility (the gateway/search half of L1) -----------------------
#
# The relay writes `/registry/mcps/<site>__<mcp>, and `core.tool_search` is the only
# path an external client has to it: a config with `public: false` and an empty
# `public_tools` is invisible to search and denied by `use_tool`, which made the whole
# edge-MCP feature unreachable before visibility was derived from the site record.


def _make_site_public(mgr, **overrides):
    config = mgr.get_edge_config(SITE)
    config.update(overrides)
    mgr.save_edge_config(SITE, config)
    return config


def _patch_tool_search(monkeypatch, mgr):
    """Point tool_search at this fake registry and skip the embedder (keyword rank)."""
    from core import tool_search

    monkeypatch.setattr(tool_search, "identity_mgr", mgr)
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: None)
    return tool_search


def _search(tool_search, query):
    return asyncio.run(tool_search.search_tools(query))


def test_a_public_site_opts_its_mcps_into_search_and_use_tool(mgr, monkeypatch):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _make_site_public(mgr, public=True, public_tools=[])
    _publish_mcps(mgr, [_mcp()])

    config = _mcp_config(mgr)
    assert config["public"] is True
    assert config["public_tools"] == []

    tool_search = _patch_tool_search(monkeypatch, mgr)
    tool_name = f"mcp__{SITE}__{MCP}__{MCP_TOOL}"
    assert [r["name"] for r in _search(tool_search, "tenants")] == [tool_name]
    assert asyncio.run(tool_search.is_tool_publicly_whitelisted(tool_name, mgr)) is True

    calls = []

    async def fake_call_edge_mcp(site, mcp, tool, args, user_id, **kwargs):
        calls.append((site, mcp, tool, args, user_id))
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}

    async def connected(_tool_name, _user_id=None):
        return {"configured": True, "missing_secrets": [], "missing_variables": [],
                "optional_missing_secrets": []}

    result = asyncio.run(
        tool_search.execute_whitelisted_tool(
            tool_name,
            {"action": "list_actions"},
            "user-1",
            identity_manager=mgr,
            is_configured=connected,
            call_edge_mcp_fn=fake_call_edge_mcp,
        )
    )

    assert result == "ok"
    assert calls == [(SITE, MCP, MCP_TOOL, {"action": "list_actions"}, "user-1")]


def test_a_private_mcp_is_neither_searchable_nor_callable(mgr, monkeypatch):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish_mcps(mgr, [_mcp()])

    tool_search = _patch_tool_search(monkeypatch, mgr)
    tool_name = f"mcp__{SITE}__{MCP}__{MCP_TOOL}"

    assert _search(tool_search, "tenants") == []
    assert asyncio.run(tool_search.is_tool_publicly_whitelisted(tool_name, mgr)) is False


@pytest.mark.parametrize(
    "ref",
    [
        f"mcp__{SITE}__{MCP}__{MCP_TOOL}",
        f"{SITE}__{MCP}__{MCP_TOOL}",
    ],
)
def test_public_tools_accepts_a_prefixed_mcp_tool_ref(mgr, ref):
    """The site record may whitelist one MCP tool in either documented ref form; the
    config stores the *bare* name because that is what search_tools compares."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _make_site_public(mgr, public=False, public_tools=[ref])

    _publish_mcps(mgr, [_mcp(tools=[_mcp_tool(), _mcp_tool(name="other_tool")])])

    published = _mcp_config(mgr)
    assert published["public"] is False
    assert published["public_tools"] == [MCP_TOOL]


@pytest.mark.parametrize("ref", [f"mcp__{SITE}__{MCP}", f"{SITE}__{MCP}"])
def test_public_tools_accepts_a_whole_mcp_ref(mgr, ref):
    """Naming the server opts in every tool it publishes."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _make_site_public(mgr, public=False, public_tools=[ref])

    _publish_mcps(mgr, [_mcp(tools=[_mcp_tool(), _mcp_tool(name="other_tool")])])

    published = _mcp_config(mgr)
    assert published["public"] is False
    assert published["public_tools"] == ["other_tool", MCP_TOOL]


def test_a_republish_keeps_the_connect_time_the_first_write_set(mgr):
    """The MCP write must not shift the timestamp the tool write just set."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish_mcps(mgr, [_mcp()])
    status = mgr.get_edge_status(SITE)
    status["connected_at"] = "2026-01-01T00:00:00+00:00"
    mgr.save_edge_status(SITE, status)

    _make_site_public(mgr, public=True)
    _publish_mcps(mgr, [_mcp()])

    assert _mcp_config(mgr)["public"] is True
    assert mgr.get_edge_status(SITE)["connected_at"] == "2026-01-01T00:00:00+00:00"


def test_a_reconnect_after_a_disconnect_records_a_new_connect_time(mgr):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")
    _publish_mcps(mgr, [_mcp()])
    status = mgr.get_edge_status(SITE)
    status["connected_at"] = "2026-01-01T00:00:00+00:00"
    mgr.save_edge_status(SITE, status)
    registry.mark_disconnected(mgr, SITE, "socket closed")
    assert mgr.get_edge_status(SITE)["connected_at"] == "2026-01-01T00:00:00+00:00"

    _publish_mcps(mgr, [_mcp()])

    status = mgr.get_edge_status(SITE)
    assert status["connected"] is True
    assert status["connected_at"] != "2026-01-01T00:00:00+00:00"


# --- unreferenceable names ---------------------------------------------------------


def test_publish_skips_a_tool_name_ending_in_underscore(mgr, caplog):
    """`<site>__<tool>` needs a non-underscore last character; publishing a name that
    can never be referenced would leave a callable tool no manifest can name."""
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    with caplog.at_level(logging.WARNING):
        published = registry.publish_catalog(
            mgr, SITE, [_tool(name="boiler_status_")], "0.5.0"
        )

    assert published == []
    assert mgr.get_tool_config(f"{SITE}__boiler_status_") is None
    assert "has no reference form; skipped" in caplog.text


def test_publish_mcp_skips_a_name_ending_in_underscore(mgr, caplog):
    mgr.create_edge(SITE, "Plant floor", "admin@example.com")

    with caplog.at_level(logging.WARNING):
        published = _publish_mcps(mgr, [_mcp(name="devops-cli_")])

    assert published == []
    assert _mcp_config(mgr, f"{SITE}__devops-cli_") is None
    assert "has no reference form; skipped" in caplog.text
