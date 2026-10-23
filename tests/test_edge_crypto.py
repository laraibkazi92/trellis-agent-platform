# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Envelope validation, the AAD replay matrix, and the no-plaintext-at-rest property.

The interesting failures are the quiet ones: a blob that opens for the wrong target,
or a "names only" envelope that leaks a value through a field nobody checks. Both are
asserted here, against real RSA/AES operations (no mocks).
"""

import base64
import json

import pytest

from core import edge_crypto, edge_keypair


@pytest.fixture(scope="module")
def edge_key(tmp_path_factory):
    return edge_keypair.generate(tmp_path_factory.mktemp("edge") / "edge-key")


@pytest.fixture(scope="module")
def other_key(tmp_path_factory):
    return edge_keypair.generate(tmp_path_factory.mktemp("other") / "edge-key")


SECRETS = {
    "NODE_SSH_USER": "ssh-bot-01",
    "NODE_SSH_PASSWORD": "hunter2-🎯",
    "NODE_SSH_KEY": "",
}
TARGET = dict(site="dc1", kind="tool", name="node_ssh", identity="alice")


def _seal(key, secrets=SECRETS, **overrides):
    args = {**TARGET, **overrides}
    return edge_crypto.seal(key.spki_b64, secrets, key_id=key.key_id, **args)


def _code(exc_info):
    return exc_info.value.code


def _tamper(blob, field, offset=0):
    raw = bytearray(base64.b64decode(blob[field]))
    raw[offset] ^= 0x01
    return {**blob, field: base64.b64encode(bytes(raw)).decode()}


def test_canonical_aad_is_the_spec_string():
    assert (
        edge_crypto.canonical_aad("dc1", "tool", "node_ssh", "alice", "AbCdEf0123456789")
        == "v1|dc1|tool|node_ssh|alice|AbCdEf0123456789"
    )


def test_canonical_plaintext_is_sorted_compact_utf8():
    assert edge_crypto.canonical_plaintext({"B": "ü", "A": "1"}) == '{"A":"1","B":"ü"}'.encode()


def test_seal_emits_a_complete_envelope(edge_key):
    blob = _seal(edge_key)

    assert blob["v"] == 1
    assert blob["alg"] == "RSA-OAEP-256/AES-256-GCM"
    assert blob["key_fp"] == edge_key.fingerprint
    assert blob["key_id"] == edge_key.key_id
    assert blob["aad"] == "v1|dc1|tool|node_ssh|alice|" + edge_key.key_id
    assert blob["keys"] == sorted(SECRETS)
    assert len(base64.b64decode(blob["iv"])) == 12
    assert len(base64.b64decode(blob["wrapped_key"])) == 384  # RSA-3072
    edge_crypto.validate_blob(blob)


def test_round_trip_is_byte_identical(edge_key):
    opened = edge_crypto.open_sealed(_seal(edge_key), edge_key, **TARGET)
    assert opened == SECRETS
    assert opened["NODE_SSH_PASSWORD"] == "hunter2-🎯"
    assert opened["NODE_SSH_KEY"] == ""


def test_round_trip_of_an_empty_set(edge_key):
    assert edge_crypto.open_sealed(_seal(edge_key, {}), edge_key, **TARGET) == {}


def test_only_names_listed_in_the_envelope_are_returned(edge_key):
    blob = {**_seal(edge_key), "keys": ["NODE_SSH_USER"]}
    assert edge_crypto.open_sealed(blob, edge_key, **TARGET) == {"NODE_SSH_USER": "ssh-bot-01"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"kind": "mcp", "name": "devops-cli"},
        {"identity": "bob"},
        {"site": "dc2"},
        {"name": "other_tool"},
    ],
)
def test_replay_for_another_target_is_rejected(edge_key, overrides):
    blob = _seal(edge_key)
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed(blob, edge_key, **{**TARGET, **overrides})
    assert _code(exc) == edge_crypto.CREDENTIAL_REJECTED


def test_blob_for_another_key_is_rejected(edge_key, other_key):
    foreign = _seal(other_key)
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed(foreign, edge_key, **TARGET)
    assert _code(exc) == edge_crypto.CREDENTIAL_REJECTED


def test_rewriting_key_id_and_fp_of_a_foreign_blob_is_rejected(edge_key, other_key):
    foreign = _seal(other_key)
    swapped = {
        **foreign,
        "key_id": edge_key.key_id,
        "key_fp": edge_key.fingerprint,
    }
    # key_id alone no longer matches the AAD string that was authenticated ...
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed(swapped, edge_key, **TARGET)
    assert _code(exc) == edge_crypto.CREDENTIAL_REJECTED

    # ... and rewriting the AAD too still fails the key-id check.
    forged = {
        **swapped,
        "aad": edge_crypto.canonical_aad(
            "dc1", "tool", "node_ssh", "alice", edge_key.key_id
        ),
    }
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed(forged, edge_key, **TARGET)
    assert _code(exc) == edge_crypto.CREDENTIAL_REJECTED


@pytest.mark.parametrize("field", ["ciphertext", "iv", "wrapped_key"])
def test_tampering_is_a_credential_rejection(edge_key, field):
    blob = _tamper(_seal(edge_key), field)
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed(blob, edge_key, **TARGET)
    assert _code(exc) == edge_crypto.CREDENTIAL_REJECTED


def test_wrong_private_key_for_the_same_id_is_rejected(edge_key, other_key):
    blob = _seal(other_key)
    impostor = edge_keypair.EdgeKey(
        private_key=edge_key.private_key,
        spki_b64=other_key.spki_b64,
        fingerprint=other_key.fingerprint,
        key_id=other_key.key_id,
    )
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed(blob, impostor, **TARGET)
    assert _code(exc) == edge_crypto.CREDENTIAL_REJECTED


def test_names_only_envelope_and_no_plaintext_at_rest(edge_key):
    blob = _seal(edge_key)
    serialised = json.dumps(blob)
    assert set(blob) == {
        "v",
        "alg",
        "key_fp",
        "key_id",
        "aad",
        "wrapped_key",
        "iv",
        "ciphertext",
        "keys",
    }
    assert all(isinstance(name, str) for name in blob["keys"])
    # Identity is in the AAD by design; values never are.
    for value in SECRETS.values():
        if value:
            assert value not in serialised
    assert "hunter2" not in base64.b64decode(blob["ciphertext"]).decode("latin-1")


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda b: {k: v for k, v in b.items() if k != "iv"}, id="missing-field"),
        pytest.param(lambda b: {**b, "v": 2}, id="version"),
        pytest.param(lambda b: {**b, "alg": "RSA-OAEP-256/AES-128-GCM"}, id="algorithm"),
        pytest.param(lambda b: {**b, "key_fp": "deadbeef"}, id="fingerprint-shape"),
        pytest.param(lambda b: {**b, "key_id": ""}, id="empty-key-id"),
        pytest.param(lambda b: {**b, "wrapped_key": "not base64!!"}, id="base64"),
        pytest.param(lambda b: {**b, "keys": ["OK", 7]}, id="keys-types"),
        pytest.param(lambda b: {**b, "keys": "NODE_SSH_USER"}, id="keys-not-list"),
        pytest.param(lambda b: {**b, "ciphertext": ""}, id="empty-ciphertext"),
    ],
)
def test_malformed_envelopes(edge_key, mutation):
    blob = mutation(_seal(edge_key))
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed(blob, edge_key, **TARGET)
    assert exc.value.code == edge_crypto.MALFORMED


def test_oversized_envelope_is_malformed(edge_key):
    blob = _seal(edge_key)
    blob = {**blob, "ciphertext": base64.b64encode(b"x" * edge_crypto.MAX_SEALED_BYTES).decode()}
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed(blob, edge_key, **TARGET)
    assert exc.value.code == edge_crypto.MALFORMED


def test_non_string_values_are_malformed(edge_key):
    blob = _seal(edge_key, {"NODE_SSH_PORT": 22, "NODE_SSH_USER": "alice"})
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed(blob, edge_key, **TARGET)
    assert exc.value.code == edge_crypto.MALFORMED


def test_validation_runs_before_any_crypto(edge_key):
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed({"v": 1}, None, **TARGET)
    assert exc.value.code == edge_crypto.MALFORMED


def test_seal_rejects_a_bad_public_key():
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.seal("bm90IGEga2V5", {}, key_id="x", **TARGET)
    assert exc.value.code == edge_crypto.MALFORMED


def test_zeroise_overwrites_in_place():
    buf = bytearray(b"secret")
    edge_crypto.zeroise(buf)
    assert buf == bytearray(len(buf))
