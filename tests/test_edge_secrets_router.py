# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Write-time gate for browser-sealed per-user edge credentials.

Each test is one refusal the server must make on its own: a key the manifest never
declared, a ``variables`` name, a blob sealed for another user or another edge key, an
envelope above the size cap. The accepted path is exercised with a real envelope from
``edge_crypto.seal`` (the browser's mirror) so the stored bytes are the bytes an edge
would have to open. No etcd, no relay, no network: the fake client is a dict.
"""

import base64
import json
from types import SimpleNamespace

import pytest

from core import edge_crypto, edge_keypair, edge_secrets_central
from core.routers import edge_secrets

SITE = "dc1"
TOOL = "node_ssh"
TOOL_CONFIG = {
    "name": f"{SITE}__{TOOL}",
    "managed_by": "edge-relay",
    "remote": {"site": SITE, "tool": TOOL},
    "secrets": ["NODE_SSH_USER", "NODE_SSH_PASSWORD"],
    "optional_secrets": ["NODE_SSH_KEY"],
    "variables": ["NODE_SSH_HOST"],
}
MCP_CONFIG = {
    "name": f"{SITE}__devops-cli",
    "managed_by": "edge-relay",
    "remote": {"site": SITE, "mcp": "devops-cli"},
    "secrets": {"general": ["DEVOPS_TOKEN"], "user": ["DEVOPS_USER"]},
    "variables": ["DEVOPS_URL"],
}
VALUES = {"NODE_SSH_USER": "operator-01", "NODE_SSH_PASSWORD": "correct horse battery"}
CSRF = "csrf-token-value"


# --- fakes -------------------------------------------------------------------


class _Meta:
    def __init__(self, key: str) -> None:
        self.key = key.encode("utf-8")


class FakeEtcd:
    """The four pyetcd calls the store uses, over a dict."""

    def __init__(self) -> None:
        self.store = {}

    def put(self, key, value):
        self.store[key] = value.encode("utf-8") if isinstance(value, str) else value

    def get(self, key):
        return self.store.get(key, b""), _Meta(key)

    def get_prefix(self, prefix):
        return [
            (self.store[key], _Meta(key))
            for key in sorted(self.store)
            if key.startswith(prefix)
        ]

    def delete(self, key):
        return self.store.pop(key, None) is not None


class FakeIdentityManager:
    def __init__(self, edges=None, tool_configs=None, mcp_configs=None):
        self.client = FakeEtcd()
        self._edges = edges or {}
        self._tool_configs = tool_configs or {}
        self._mcp_configs = mcp_configs or {}

    def get_edge_config(self, name):
        config = self._edges.get(name)
        return dict(config) if config else None

    def get_tool_config(self, name):
        config = self._tool_configs.get(name)
        return dict(config) if config else None

    def get_mcp_config(self, name):
        config = self._mcp_configs.get(name)
        return dict(config) if config else None


class FakeRequest:
    def __init__(self, session=None, body=None, method="GET", headers=None):
        self.session = session if session is not None else {}
        self._body = body
        self.method = method
        self.headers = headers or {}
        self.query_params = {}

    async def json(self):
        if self._body is None:
            raise ValueError("no JSON body")
        return self._body


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    root = tmp_path_factory.mktemp("edge-secrets-keys")
    return edge_keypair.generate(root / "edge-key", bits=2048), edge_keypair.generate(
        root / "edge-key-2", bits=2048
    )


@pytest.fixture
def manager(keys):
    current, _previous = keys
    return FakeIdentityManager(
        edges={
            SITE: {
                "name": SITE,
                "edge_pubkey": current.spki_b64,
                "edge_key_fp": current.fingerprint,
                "edge_key_fps": [],
                # An admin approved this key (Admin -> Edges): sealing is enabled.
                "edge_key_approved": True,
                "edge_key_approved_fp": current.fingerprint,
                "edge_key_approved_by": "admin@example.com",
                "edge_key_approved_at": "2026-10-26T10:00:00+00:00",
            }
        },
        tool_configs={f"{SITE}__{TOOL}": TOOL_CONFIG, TOOL: TOOL_CONFIG},
        mcp_configs={f"{SITE}__devops-cli": MCP_CONFIG},
    )


@pytest.fixture(autouse=True)
def _patched(monkeypatch, manager):
    monkeypatch.setattr(edge_secrets, "identity_mgr", manager)
    return manager


def _session(csrf=CSRF, sub="alice-id", email="Alice@Example.com"):
    return {"user": {"sub": sub, "email": email}, "csrf_token": csrf}


def _headers(csrf=CSRF):
    return {"x-csrf-token": csrf}


def _seal(key, values=VALUES, *, identity="alice@example.com", site=SITE, kind="tool",
          name=TOOL):
    return edge_crypto.seal(
        key.spki_b64,
        values,
        site=site,
        kind=kind,
        name=name,
        identity=identity,
        key_id=key.key_id,
    )


async def _post(blob, request=None, site=SITE, kind="tool", name=TOOL):
    request = request or FakeRequest(session=_session(), body=blob, method="POST",
                                     headers=_headers())
    response = await edge_secrets.store_edge_secret(request, site, kind, name)
    return response, json.loads(response.body)


# --- GET pubkey ---------------------------------------------------------------


def test_pubkey_returns_the_site_key_and_only_declared_names(_patched, keys):
    current, _ = keys
    request = FakeRequest(session=_session())

    import asyncio

    response = asyncio.run(
        edge_secrets.edge_secret_pubkey(request, SITE, "tool", TOOL)
    )
    body = json.loads(response.body)

    assert response.status_code == 200
    assert body["key_fp"] == current.fingerprint
    assert body["key_id"] == current.key_id
    assert body["spki"] == current.spki_b64
    assert body["secret_keys"] == ["NODE_SSH_KEY", "NODE_SSH_PASSWORD", "NODE_SSH_USER"]
    assert body["variable_keys"] == ["NODE_SSH_HOST"]
    # The endpoint describes the target; it never carries a value or a blob.
    assert "variables" not in body


def test_pubkey_404_when_the_site_has_no_key(_patched, manager):
    import asyncio

    manager._edges[SITE] = {"name": SITE}
    response = asyncio.run(
        edge_secrets.edge_secret_pubkey(FakeRequest(session=_session()), SITE, "tool", TOOL)
    )

    assert response.status_code == 404
    assert json.loads(response.body)["error"] == "no_edge_key"


def test_pubkey_404_for_an_unregistered_target(_patched):
    import asyncio

    response = asyncio.run(
        edge_secrets.edge_secret_pubkey(FakeRequest(session=_session()), SITE, "tool", "nope")
    )

    assert response.status_code == 404
    assert json.loads(response.body)["error"] == "unknown_target"


def test_pubkey_requires_a_session(_patched):
    import asyncio

    response = asyncio.run(
        edge_secrets.edge_secret_pubkey(FakeRequest(), SITE, "tool", TOOL)
    )

    assert response.status_code == 401


def test_pubkey_is_refused_until_the_fingerprint_is_approved(_patched, manager, keys):
    """A published key nobody approved is not sealing material: no SPKI, no encryption."""
    import asyncio

    current, _ = keys
    for field in ("edge_key_approved", "edge_key_approved_fp"):
        manager._edges[SITE].pop(field)

    response = asyncio.run(
        edge_secrets.edge_secret_pubkey(FakeRequest(session=_session()), SITE, "tool", TOOL)
    )
    body = json.loads(response.body)

    assert response.status_code == 409
    assert body["error"] == "key_pending_approval"
    assert current.fingerprint in body["detail"]
    # The page needs the fingerprint; it must never get the key itself.
    assert "spki" not in body


def test_pubkey_refuses_the_new_key_during_a_rotation_overlap(_patched, manager, keys):
    """Rotation: the approved fingerprint stays the trusted one until the new one is approved."""
    import asyncio

    current, rotated = keys
    manager._edges[SITE].update({
        "edge_pubkey": rotated.spki_b64,
        "edge_key_fp": rotated.fingerprint,
        "edge_key_id": rotated.key_id,
        "prev_edge_key_fp": current.fingerprint,
        "edge_key_fps": [current.fingerprint],
        "edge_key_approved": False,
    })

    response = asyncio.run(
        edge_secrets.edge_secret_pubkey(FakeRequest(session=_session()), SITE, "tool", TOOL)
    )
    body = json.loads(response.body)

    assert response.status_code == 409
    assert body["error"] == "key_pending_approval"
    assert body["key_fp"] == rotated.fingerprint
    assert body["approved_fp"] == current.fingerprint
    assert rotated.fingerprint in body["detail"]
    assert "spki" not in body


def test_pubkey_serves_the_rotated_key_once_it_is_approved(_patched, manager, keys):
    import asyncio

    _current, rotated = keys
    manager._edges[SITE].update({
        "edge_pubkey": rotated.spki_b64,
        "edge_key_fp": rotated.fingerprint,
        "edge_key_id": rotated.key_id,
        "edge_key_approved": True,
        "edge_key_approved_fp": rotated.fingerprint,
    })

    response = asyncio.run(
        edge_secrets.edge_secret_pubkey(FakeRequest(session=_session()), SITE, "tool", TOOL)
    )
    body = json.loads(response.body)

    assert response.status_code == 200
    assert body["key_fp"] == rotated.fingerprint
    assert body["spki"] == rotated.spki_b64


# --- POST ---------------------------------------------------------------------


def test_post_accepts_a_well_formed_envelope(_patched, manager, keys):
    import asyncio

    current, _ = keys
    blob = _seal(current)

    response, body = asyncio.run(_post(blob))

    assert response.status_code == 200, body
    assert body["stored"] is True
    assert body["keys"] == sorted(VALUES)
    # No ciphertext or wrapped key is echoed back.
    assert "ciphertext" not in body and "wrapped_key" not in body

    path = edge_secrets_central.record_path(SITE, "alice-id", "tool", TOOL)
    stored = json.loads(manager.client.store[path])
    assert stored["ciphertext"] == blob["ciphertext"]
    assert stored["wrapped_key"] == blob["wrapped_key"]
    assert stored["created_at"]
    assert stored["created_by"] == "Alice@Example.com"
    # A central dump has names, never values.
    dump = json.dumps(stored)
    for value in VALUES.values():
        assert value not in dump


def test_post_rejects_a_key_the_manifest_never_declared(_patched, keys):
    import asyncio

    current, _ = keys
    blob = _seal(current, {"NODE_SSH_USER": "u", "AWS_SECRET_ACCESS_KEY": "x"})

    response, body = asyncio.run(_post(blob))

    assert response.status_code == 400
    assert body["error"] == "undeclared_keys"


def test_post_rejects_a_variable_name(_patched, keys):
    import asyncio

    current, _ = keys
    blob = _seal(current, {"NODE_SSH_HOST": "https://attacker.example"})

    response, body = asyncio.run(_post(blob))

    assert response.status_code == 400
    assert body["error"] == "variable_key_not_allowed"


def test_post_rejects_a_blob_sealed_for_another_identity(_patched, keys):
    import asyncio

    current, _ = keys
    blob = _seal(current, identity="bob@example.com")

    response, body = asyncio.run(_post(blob))

    assert response.status_code == 400
    assert body["error"] == edge_crypto.CREDENTIAL_REJECTED


def test_post_rejects_a_blob_sealed_for_another_site(_patched, keys):
    import asyncio

    current, _ = keys
    blob = _seal(current, site="dc2")

    response, body = asyncio.run(_post(blob))

    assert response.status_code == 400
    assert body["error"] == edge_crypto.CREDENTIAL_REJECTED


def test_post_rejects_a_retired_key(_patched, manager, keys):
    import asyncio

    _current, previous = keys
    blob = _seal(previous)

    response, body = asyncio.run(_post(blob))

    assert response.status_code == 400
    assert body["error"] == "retired_key"
    assert edge_secrets_central.list_for_site(manager, SITE) == []


def test_post_accepts_the_previous_key_during_the_rotation_overlap(_patched, manager, keys):
    import asyncio

    current, previous = keys
    manager._edges[SITE]["edge_key_fps"] = [previous.fingerprint]
    blob = _seal(previous)

    response, body = asyncio.run(_post(blob))

    assert response.status_code == 200, body
    assert body["key_fp"] == previous.fingerprint


def test_post_still_stores_a_blob_sealed_to_the_old_approved_key(_patched, manager, keys):
    """Rotation overlap: the previous key keeps working while the new one awaits approval."""
    import asyncio

    current, rotated = keys
    manager._edges[SITE].update({
        "edge_pubkey": rotated.spki_b64,
        "edge_key_fp": rotated.fingerprint,
        "edge_key_id": rotated.key_id,
        "prev_edge_key_fp": current.fingerprint,
        "edge_key_fps": [current.fingerprint],
        "edge_key_approved": False,
    })

    response, body = asyncio.run(_post(_seal(current)))

    assert response.status_code == 200, body
    assert body["key_fp"] == current.fingerprint


def test_post_refuses_a_blob_sealed_to_a_pending_key(_patched, manager, keys):
    """While the current key is pending, only the approved (previous) one may be sealed."""
    import asyncio

    _current, rotated = keys
    manager._edges[SITE].update({
        "edge_pubkey": rotated.spki_b64,
        "edge_key_fp": rotated.fingerprint,
        "edge_key_id": rotated.key_id,
        "edge_key_approved": False,
    })

    response, body = asyncio.run(_post(_seal(rotated)))

    assert response.status_code == 409
    assert body["error"] == "key_pending_approval"
    assert rotated.fingerprint in body["detail"]
    assert edge_secrets_central.list_for_site(manager, SITE) == []


def test_post_rejects_a_key_id_that_does_not_match_the_fingerprint(_patched, keys):
    import asyncio

    current, _ = keys
    blob = _seal(current)
    blob["key_id"] = "0000000000000000"

    response, body = asyncio.run(_post(blob))

    assert response.status_code == 400
    assert body["error"] in ("key_mismatch", edge_crypto.CREDENTIAL_REJECTED)


def test_post_rejects_an_oversized_envelope(_patched, keys):
    import asyncio

    current, _ = keys
    blob = _seal(current)
    blob["ciphertext"] = base64.b64encode(b"x" * (edge_crypto.MAX_SEALED_BYTES + 1)).decode()

    response, body = asyncio.run(_post(blob))

    assert response.status_code == 400
    assert body["error"] == edge_crypto.MALFORMED


def test_post_requires_the_csrf_header(_patched, keys):
    import asyncio

    current, _ = keys
    request = FakeRequest(session=_session(), body=_seal(current), method="POST")

    response, body = asyncio.run(_post(_seal(current), request=request))

    assert response.status_code == 403
    assert body["error"] == "csrf_failed"


def test_post_requires_a_session(_patched, keys):
    import asyncio

    current, _ = keys
    request = FakeRequest(body=_seal(current), method="POST", headers=_headers())

    response, _body = asyncio.run(_post(_seal(current), request=request))

    assert response.status_code == 401


def test_post_accepts_the_mcp_shape_with_a_grouped_secrets_block(_patched, keys):
    import asyncio

    current, _ = keys
    blob = _seal(
        current,
        {"DEVOPS_TOKEN": "t0ken", "DEVOPS_USER": "alice"},
        kind="mcp",
        name="devops-cli",
    )

    response, body = asyncio.run(_post(blob, kind="mcp", name="devops-cli"))

    assert response.status_code == 200, body
    assert body["kind"] == "mcp"


# --- DELETE -------------------------------------------------------------------


def test_delete_clears_only_the_callers_record(_patched, manager, keys):
    import asyncio

    current, _ = keys
    asyncio.run(_post(_seal(current)))

    response = asyncio.run(
        edge_secrets.clear_edge_secret(
            FakeRequest(session=_session(), headers=_headers()), SITE, "tool", TOOL
        )
    )
    assert response.status_code == 200
    assert json.loads(response.body) == {"deleted": True}

    second = asyncio.run(
        edge_secrets.clear_edge_secret(
            FakeRequest(session=_session(), headers=_headers()), SITE, "tool", TOOL
        )
    )
    assert json.loads(second.body) == {"deleted": False}
    assert edge_secrets_central.list_for_site(manager, SITE) == []


# --- listing ------------------------------------------------------------------


def test_admin_site_list_is_names_only(_patched, manager, monkeypatch, keys):
    import asyncio

    current, _ = keys
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    edge_secrets_central.put(
        manager, SITE, "alice-id", "tool", TOOL, _seal(current), created_by="alice@example.com"
    )
    edge_secrets_central.put(
        manager, SITE, "bob-id", "tool", TOOL, _seal(current), created_by="bob@example.com"
    )

    response = asyncio.run(
        edge_secrets.list_site_secrets(
            FakeRequest(session={"user": {"sub": "admin-id", "email": "admin@example.com"}}),
            SITE,
        )
    )
    body = json.loads(response.body)

    assert response.status_code == 200
    assert {record["user_id"] for record in body["records"]} == {"alice-id", "bob-id"}
    for record in body["records"]:
        assert set(record) == {
            "site", "user_id", "kind", "name", "key_fp", "created_at", "created_by",
            "active",
        }
        assert record["active"] is True
    dump = json.dumps(body)
    assert "ciphertext" not in dump and "wrapped_key" not in dump


def test_admin_site_list_marks_a_blob_sealed_to_an_inactive_key(_patched, manager, monkeypatch, keys):
    """The admin page shows which records the edge can still open (rotation UX)."""
    import asyncio

    current, previous = keys
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    edge_secrets_central.put(manager, SITE, "alice-id", "tool", TOOL, _seal(current))
    edge_secrets_central.put(manager, SITE, "bob-id", "tool", TOOL, _seal(previous))

    response = asyncio.run(
        edge_secrets.list_site_secrets(
            FakeRequest(session={"user": {"sub": "admin-id", "email": "admin@example.com"}}),
            SITE,
        )
    )
    body = json.loads(response.body)
    active = {record["user_id"]: record["active"] for record in body["records"]}

    assert active == {"alice-id": True, "bob-id": False}


def test_site_list_is_admin_only(_patched, manager):
    import asyncio

    response = asyncio.run(
        edge_secrets.list_site_secrets(
            FakeRequest(session={"user": {"sub": "alice-id", "email": "alice@example.com"}}),
            SITE,
        )
    )

    assert response.status_code == 403
    assert json.loads(response.body)["error"] == "forbidden"


def test_mine_is_scoped_to_the_caller(_patched, manager, keys):
    import asyncio

    current, _ = keys
    edge_secrets_central.put(manager, SITE, "alice-id", "tool", TOOL, _seal(current))
    edge_secrets_central.put(manager, SITE, "bob-id", "tool", TOOL, _seal(current))

    response = asyncio.run(
        edge_secrets.list_my_secrets(FakeRequest(session=_session()))
    )
    body = json.loads(response.body)

    assert response.status_code == 200
    assert [record["user_id"] for record in body["records"]] == ["alice-id"]
    assert body["records"][0]["site"] == SITE


def test_retired_blobs_counts_records_outside_the_active_set(_patched, manager, keys):
    current, previous = keys
    edge_secrets_central.put(manager, SITE, "alice-id", "tool", TOOL, _seal(current))
    edge_secrets_central.put(manager, SITE, "bob-id", "tool", TOOL, _seal(previous))

    active = edge_secrets_central.active_fingerprints(manager._edges[SITE])
    retired = edge_secrets_central.retired_blobs(manager, SITE, active)

    assert [record["user_id"] for record in retired] == ["bob-id"]


def test_identity_prefers_the_normalized_email():
    assert edge_secrets_central.sealed_identity("abc", " Alice@Example.COM ") == "alice@example.com"
    assert edge_secrets_central.sealed_identity("abc", "") == "abc"
    assert edge_secrets_central.sealed_identity("abc", None) == "abc"


def test_configuration_cards_discover_keys_from_the_site_record(monkeypatch):
    """Relay-published configs omit secrets: the card must use credential_keys.

    Without this fallback /configuration renders no edge credential card at all,
    so no user can reach the seal form.
    """
    import asyncio

    from core.routers import configuration as configuration_router

    config = {
        "name": "dc1__node_ssh",
        "description": "Edge SSH",
        "runtime": "remote",
        "managed_by": "edge-relay",
        "remote": {"site": "dc1", "tool": "node_ssh"},
        # Deliberately no secrets/variables: this is what the relay publishes.
    }
    monkeypatch.setattr(
        configuration_router.edge_secrets_central,
        "list_for_user",
        lambda mgr, uid: [],
    )
    monkeypatch.setattr(
        configuration_router.identity_mgr,
        "get_edge_config",
        lambda site: {
            "edge_key_fp": "SHA256:" + "x" * 43,
            "credential_keys": {
                "node_ssh": {"secret_keys": ["NODE_SSH_USER", "NODE_SSH_PASSWORD"], "variable_keys": []}
            },
        },
    )

    cards = asyncio.run(
        configuration_router._edge_credential_cards(
            "user-1", {"dc1__node_ssh": config}, {}
        )
    )

    assert [card["name"] for card in cards] == ["node_ssh"]
    assert cards[0]["secret_keys"] == ["NODE_SSH_PASSWORD", "NODE_SSH_USER"]
