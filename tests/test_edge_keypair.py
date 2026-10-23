# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The edge keypair file: 0400, outside the workspace, rotatable without data loss.

The private key is the one credential on an edge that cannot be regenerated, so the
tests pin the three refusals (missing, wider than 0400, inside the workspace) and the
rotation overlap rather than just the happy path.
"""

import base64
import hashlib
import json
import stat

import pytest
from cryptography.hazmat.primitives import serialization

from core import edge_crypto, edge_keypair


@pytest.fixture
def key_path(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
    path = tmp_path / "keys" / "edge-key"
    monkeypatch.setenv(edge_keypair.EDGE_KEY_ENV, str(path))
    return path


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def _code(exc_info):
    return exc_info.value.code


def test_generate_writes_0400_pkcs8_and_pins_the_parent(key_path):
    edge_keypair.generate(key_path)

    assert _mode(key_path) == 0o400
    assert _mode(key_path.parent) == 0o700
    pem = key_path.read_bytes()
    assert b"BEGIN PRIVATE KEY" in pem  # PKCS#8, not PKCS#1
    key = serialization.load_pem_private_key(pem, password=None)
    assert key.key_size == 3072


def test_load_round_trips_and_matches_a_manual_spki_hash(key_path):
    generated = edge_keypair.generate(key_path)
    loaded = edge_keypair.load(key_path)

    der = loaded.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert loaded.spki_b64 == base64.b64encode(der).decode()
    assert loaded.fingerprint == "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()
    assert loaded.key_id == loaded.fingerprint[7:23]
    assert len(loaded.key_id) == 16
    assert (loaded.fingerprint, loaded.spki_b64) == (generated.fingerprint, generated.spki_b64)


def test_default_path_comes_from_the_environment(key_path):
    generated = edge_keypair.generate()
    assert key_path.exists()
    assert edge_keypair.load().fingerprint == generated.fingerprint


def test_repr_never_shows_the_private_key(key_path):
    key = edge_keypair.generate(key_path)
    assert "private_key" not in repr(key)
    assert "BEGIN" not in repr(key)


def test_refuses_a_missing_file(key_path):
    with pytest.raises(edge_keypair.EdgeKeyError) as exc:
        edge_keypair.load(key_path)

    message = str(exc.value)
    assert "does not exist" in message
    assert edge_keypair.EDGE_KEY_ENV in message
    assert "trellis-proxy edge-keygen" in message


@pytest.mark.parametrize("mode", [0o644, 0o600, 0o440])
def test_refuses_a_file_wider_than_0400(key_path, mode):
    edge_keypair.generate(key_path)
    key_path.chmod(mode)

    with pytest.raises(edge_keypair.EdgeKeyError) as exc:
        edge_keypair.load(key_path)

    message = str(exc.value)
    assert oct(mode) in message
    assert "0400" in message
    assert "trellis-proxy edge-keygen" in message


def test_refuses_a_path_inside_the_workspace(key_path, tmp_path):
    inside = tmp_path / "workspace" / "edge-key"
    inside.parent.mkdir(parents=True, exist_ok=True)

    with pytest.raises(edge_keypair.EdgeKeyError, match="inside the workspace"):
        edge_keypair.generate(inside)
    assert not inside.exists()

    edge_keypair.generate(key_path)
    inside.write_bytes(key_path.read_bytes())
    inside.chmod(0o400)
    with pytest.raises(edge_keypair.EdgeKeyError, match="inside the workspace"):
        edge_keypair.load(inside)


def test_refuses_a_file_that_is_not_a_private_key(key_path):
    key_path.parent.mkdir(parents=True)
    key_path.write_text("not a key\n")
    key_path.chmod(0o400)

    with pytest.raises(edge_keypair.EdgeKeyError, match="PEM private key"):
        edge_keypair.load(key_path)


def test_rotate_keeps_the_old_key_at_0600_and_drop_old_removes_it(key_path):
    first = edge_keypair.generate(key_path)
    second = edge_keypair.rotate(key_path)

    old = key_path.with_name(key_path.name + ".old")
    assert old.exists() and _mode(old) == 0o600
    assert _mode(key_path) == 0o400
    assert second.fingerprint != first.fingerprint
    assert edge_keypair.load(key_path).fingerprint == second.fingerprint
    assert edge_keypair.load_old(key_path).fingerprint == first.fingerprint

    assert edge_keypair.drop_old(key_path) is True
    assert not old.exists()
    assert edge_keypair.load_old(key_path) is None
    assert edge_keypair.drop_old(key_path) is False


def test_rotate_without_an_existing_key_simply_generates(key_path):
    key = edge_keypair.rotate(key_path)
    assert key_path.exists()
    assert not key_path.with_name(key_path.name + ".old").exists()


def test_rotation_overlap_decrypts_old_and_new_seals_only_with_their_own_key(key_path):
    first = edge_keypair.generate(key_path)
    before = edge_crypto.seal(
        first.spki_b64,
        {"NODE_SSH_PASSWORD": "one"},
        site="dc1",
        kind="tool",
        name="node_ssh",
        identity="alice",
        key_id=first.key_id,
    )
    second = edge_keypair.rotate(key_path)

    old_key = edge_keypair.load_old(key_path)
    current = edge_keypair.load(key_path)
    args = dict(site="dc1", kind="tool", name="node_ssh", identity="alice")
    assert edge_crypto.open_sealed(before, old_key, **args) == {"NODE_SSH_PASSWORD": "one"}
    with pytest.raises(edge_crypto.SealedError) as exc:
        edge_crypto.open_sealed(before, current, **args)
    assert _code(exc) == edge_crypto.CREDENTIAL_REJECTED

    after = edge_crypto.seal(
        second.spki_b64,
        {"NODE_SSH_PASSWORD": "two"},
        key_id=second.key_id,
        **args,
    )
    assert edge_crypto.open_sealed(after, current, **args) == {"NODE_SSH_PASSWORD": "two"}


def test_cli_keygen_and_show_emit_public_material_only(key_path, capsys):
    assert edge_keypair.main(["--keygen", "--path", str(key_path)]) == 0
    assert key_path.exists()
    capsys.readouterr()

    assert edge_keypair.main(["--show", "--path", str(key_path)]) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert set(payload) == {"key_id", "fingerprint", "spki"}
    assert payload["key_id"] == payload["fingerprint"][7:23]
    assert "PRIVATE" not in out


def test_cli_reports_errors_without_a_traceback(tmp_path, capsys):
    missing = tmp_path / "nope" / "edge-key"
    assert edge_keypair.main(["--show", "--path", str(missing)]) == 1
    err = capsys.readouterr().err
    assert "trellis-proxy edge-keygen" in err
    assert "Traceback" not in err


def test_cli_rotate_and_drop_old(key_path):
    edge_keypair.generate(key_path)
    assert edge_keypair.main(["--rotate", "--path", str(key_path)]) == 0
    assert key_path.with_name(key_path.name + ".old").exists()

    assert edge_keypair.main(["--drop-old-key", "--path", str(key_path)]) == 0
    assert not key_path.with_name(key_path.name + ".old").exists()
