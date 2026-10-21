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

import json
import logging

import pytest

from core.auth import EDGE_TOKENS_PREFIX, IdentityManager
from services.edge_relay import registry
from services.edge_relay.protocol import EdgeTool

SITE = "plant-floor"
TOOL = "boiler_status"
REGISTRY_NAME = f"{SITE}__{TOOL}"


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
