# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""End-to-end shape of Phase 4: browser seals, central stores, edge decrypts.

Each test walks the real envelope through the same hops the deployment uses -- public
key out of the hello frame, JSON in and out of etcd, verbatim through the relay, a 0400
file on the edge -- because the property that matters is "central never sees a value",
not "the AEAD function works". The container env is the final assertion: what the tool
would receive is exactly the user's set, filtered to declared secret names.
"""

import json
import stat

import pytest

from core import edge_crypto, edge_keypair

TOOL_DECLARED = ("NODE_SSH_USER", "NODE_SSH_PASSWORD", "NODE_SSH_KEY")
SHARED_SERVICE_ACCOUNT = {
    "NODE_SSH_USER": "svc-shared",
    "NODE_SSH_PASSWORD": "shared-password",
    "NODE_SSH_KEY": "shared-key",
}
BROWSER_VALUES = {
    "NODE_SSH_USER": "operator-01",
    "NODE_SSH_PASSWORD": "correct horse ⚡ battery",
    "NODE_SSH_KEY": "",
}


@pytest.fixture
def edge(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
    path = tmp_path / "etc-trellis" / "edge-key"
    key = edge_keypair.generate(path)
    return key, path


def _seal_for_browser(key, identity, values=BROWSER_VALUES, **target):
    public = key.public_json()  # what the hello frame publishes
    args = {"site": "dc1", "kind": "tool", "name": "node_ssh", **target}
    return edge_crypto.seal(
        public["spki"], values, identity=identity, key_id=public["key_id"], **args
    )


def _edge_env(key, blob, identity, declared=TOOL_DECLARED, **target):
    """The edge's last mile: decrypt with the 0400 key, filter to declared names."""
    args = {"site": "dc1", "kind": "tool", "name": "node_ssh", **target}
    opened = edge_crypto.open_sealed(blob, key, identity=identity, **args)
    return {name: value for name, value in opened.items() if name in declared}


def test_browser_to_container_round_trip_is_byte_identical(edge, tmp_path):
    key, path = edge
    sealed = _seal_for_browser(key, "alice@example.com")

    # central: store the envelope, serve it back, forward it verbatim.
    etcd_record = json.loads(json.dumps({**sealed, "created_at": "2026-10-23T00:00:00Z"}))
    forwarded = json.loads(json.dumps(etcd_record))

    # edge: the key never left this file.
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    loaded = edge_keypair.load(path)
    env = _edge_env(loaded, forwarded, "alice@example.com")

    assert env == BROWSER_VALUES
    assert env["NODE_SSH_PASSWORD"] == "correct horse ⚡ battery"
    assert env["NODE_SSH_KEY"] == ""
    assert len(json.dumps(etcd_record).encode()) <= edge_crypto.MAX_SEALED_BYTES


def test_central_dump_contains_names_but_never_values(edge):
    key, _ = edge
    sealed = _seal_for_browser(key, "alice@example.com")
    dump = json.dumps(sealed)

    assert sealed["keys"] == sorted(BROWSER_VALUES)
    for value in BROWSER_VALUES.values():
        if value:
            assert value not in dump
    assert "svc-shared" not in dump
    assert "BEGIN PRIVATE KEY" not in dump


def test_a_blob_cannot_be_replayed_for_another_site_or_user(edge):
    key, _ = edge
    sealed = _seal_for_browser(key, "alice@example.com")

    with pytest.raises(edge_crypto.SealedError) as exc:
        _edge_env(key, sealed, "bob@example.com")
    assert exc.value.code == edge_crypto.CREDENTIAL_REJECTED

    with pytest.raises(edge_crypto.SealedError) as exc:
        _edge_env(key, sealed, "alice@example.com", site="dc2")
    assert exc.value.code == edge_crypto.CREDENTIAL_REJECTED

    with pytest.raises(edge_crypto.SealedError) as exc:
        _edge_env(key, sealed, "alice@example.com", kind="mcp", name="devops-cli")
    assert exc.value.code == edge_crypto.CREDENTIAL_REJECTED


def test_partial_user_set_never_falls_back_to_the_shared_account(edge):
    key, _ = edge
    partial = {"NODE_SSH_USER": "operator-01", "NODE_SSH_PASSWORD": "only-two"}
    sealed = _seal_for_browser(key, "alice@example.com", values=partial)

    env = _edge_env(key, sealed, "alice@example.com")

    assert env == partial
    # The missing key stays missing: the shared set is a different branch, not a gap filler.
    assert "NODE_SSH_KEY" not in env
    assert not set(SHARED_SERVICE_ACCOUNT.values()) & set(env.values())


def test_rotation_keeps_old_blobs_readable_until_the_old_key_is_dropped(edge):
    key, path = edge
    sealed = _seal_for_browser(key, "alice@example.com")

    current = edge_keypair.rotate(path)
    retained = edge_keypair.load_old(path)
    assert retained is not None and retained.key_id == key.key_id

    with pytest.raises(edge_crypto.SealedError) as exc:
        _edge_env(current, sealed, "alice@example.com")
    assert exc.value.code == edge_crypto.CREDENTIAL_REJECTED
    # Only the explicit key object opens it -- the blob cannot choose its own key.
    assert _edge_env(retained, sealed, "alice@example.com") == BROWSER_VALUES

    assert edge_keypair.drop_old(path) is True
    assert edge_keypair.load_old(path) is None
    with pytest.raises(edge_crypto.SealedError) as exc:
        _edge_env(current, sealed, "alice@example.com")
    assert exc.value.code == edge_crypto.CREDENTIAL_REJECTED


def test_a_value_that_looks_like_an_endpoint_stays_a_value(edge):
    key, _ = edge
    # Phase 4 rejects variables at write time; at the edge the name is simply not in
    # the declared secret set, so even a well-sealed blob cannot move an endpoint.
    sealed = _seal_for_browser(
        key, "alice@example.com", values={"DEVOPS_URL": "https://attacker.invalid"}
    )
    assert _edge_env(key, sealed, "alice@example.com") == {}
