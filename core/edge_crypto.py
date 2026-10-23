# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Open credentials the browser sealed to the edge's public key.

The envelope is what central stores verbatim in etcd: RSA-OAEP-SHA256 wraps a random
AES-256 key, AES-256-GCM encrypts the canonical JSON of ``{"NAME": "VALUE", ...}``,
and the AAD is a canonical string binding *site + kind + target + user + key id*.
Central never sees a plaintext value or the key that could unwrap one.

The AAD is the anti-replay mechanism. A blob for ``(dc1, tool, node_ssh, alice)``
fails to open as ``(dc1, mcp, devops-cli, alice)``, for ``bob``, or for ``dc2`` --
not because we compare metadata, but because GCM authentication fails on the AAD we
recompute here. Everything else (missing field, oversized envelope, non-string
value) is ``malformed``; anything that only crypto can decide is
``credential_rejected`` and never retried.

``seal`` exists so tests and the headless round-trip fixture can play the browser.
It is the same three WebCrypto steps, but it is deliberately absent from every
production call path: on a real edge only the browser seals.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.edge_keypair import fingerprint

MAX_SEALED_BYTES = 16 * 1024
SEAL_VERSION = 1
SEAL_ALG = "RSA-OAEP-256/AES-256-GCM"
AAD_PREFIX = "v1"

CREDENTIAL_REJECTED = "credential_rejected"
MALFORMED = "malformed"

AES_KEY_BYTES = 32
GCM_IV_BYTES = 12
GCM_TAG_BYTES = 16

_REQUIRED: dict[str, type] = {
    "v": int,
    "alg": str,
    "key_fp": str,
    "key_id": str,
    "aad": str,
    "wrapped_key": str,
    "iv": str,
    "ciphertext": str,
    "keys": list,
}

_B64_FIELDS = ("wrapped_key", "iv", "ciphertext")


class SealedError(Exception):
    """A sealed blob was refused. ``code`` travels to central as the error code."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


def _malformed(message: str) -> SealedError:
    return SealedError(MALFORMED, message)


def _rejected(message: str) -> SealedError:
    return SealedError(CREDENTIAL_REJECTED, message)


def canonical_aad(site: str, kind: str, name: str, identity: str, key_id: str) -> str:
    """The exact AAD string the browser passes to ``additionalData``."""
    return f"{AAD_PREFIX}|{site}|{kind}|{name}|{identity}|{key_id}"


def canonical_plaintext(mapping: Mapping[str, str]) -> bytes:
    """Sorted, whitespace-free UTF-8 JSON -- bytes the browser's JSON.stringify matches."""
    return json.dumps(mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _b64decode(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise _malformed(f"{field_name} must be a non-empty base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise _malformed(f"{field_name} is not valid base64") from None


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def validate_blob(blob: Any) -> None:
    """Structural checks only: no key material is touched here.

    Unknown fields are allowed on purpose -- the etcd record adds ``created_at`` /
    ``created_by`` beside the envelope, and central must be able to hand us the
    stored record without a rewrite.
    """
    if not isinstance(blob, Mapping):
        raise _malformed("sealed blob must be a JSON object")

    for name, expected in _REQUIRED.items():
        if name not in blob:
            raise _malformed(f"sealed blob is missing {name!r}")
        value = blob[name]
        # bool is an int subclass; a JSON `true` is not a version number.
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            raise _malformed(f"sealed blob field {name!r} must be {expected.__name__}")

    if blob["v"] != SEAL_VERSION:
        raise _malformed(f"unsupported sealed blob version {blob['v']!r}")
    if blob["alg"] != SEAL_ALG:
        raise _malformed(f"unsupported sealed blob algorithm {blob['alg']!r}")
    if not blob["key_fp"].startswith("SHA256:"):
        raise _malformed("key_fp must be a SHA256: fingerprint")
    for name in ("key_id", "aad"):
        if not blob[name]:
            raise _malformed(f"{name} must be a non-empty string")

    keys = blob["keys"]
    if not all(isinstance(k, str) for k in keys):
        raise _malformed("keys must be a list of names")

    for name in _B64_FIELDS:
        _b64decode(blob[name], name)

    try:
        size = len(json.dumps(blob, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        raise _malformed("sealed blob is not JSON-serialisable") from None
    if size > MAX_SEALED_BYTES:
        raise _malformed(
            f"sealed blob is {size} bytes, above the {MAX_SEALED_BYTES}-byte cap"
        )


def open_sealed(
    blob: Mapping[str, Any],
    key: Any,
    *,
    site: str,
    kind: str,
    name: str,
    identity: str,
) -> dict[str, str]:
    """Decrypt a sealed blob for exactly one ``(site, kind, name, identity)``.

    ``key`` is the edge key object to open with -- the current one, or the retained
    ``.old`` key during a rotation overlap. Passing the old key is the *only* way a
    pre-rotation blob opens: the id check compares against that object, so a blob
    cannot pick its own key.
    """
    validate_blob(blob)

    expected_aad = canonical_aad(site, kind, name, identity, blob["key_id"])
    if not hmac.compare_digest(blob["aad"].encode("utf-8"), expected_aad.encode("utf-8")):
        raise _rejected("sealed blob is bound to another site, target or user")
    if blob["key_id"] != key.key_id or not hmac.compare_digest(
        blob["key_fp"].encode("utf-8"), key.fingerprint.encode("utf-8")
    ):
        raise _rejected("sealed blob is bound to a different edge key")

    wrapped = _b64decode(blob["wrapped_key"], "wrapped_key")
    iv = _b64decode(blob["iv"], "iv")
    ciphertext = _b64decode(blob["ciphertext"], "ciphertext")
    aad = blob["aad"].encode("utf-8")

    try:
        aes_key = bytearray(
            key.private_key.decrypt(
                wrapped,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        )
    except Exception:  # noqa: BLE001 - every failure is "not for this key"
        raise _rejected("sealed blob could not be unwrapped by this edge key") from None

    try:
        plaintext = AESGCM(bytes(aes_key)).decrypt(iv, ciphertext, aad)
    except (InvalidTag, ValueError):
        raise _rejected(
            "sealed blob failed authentication (tampered or sealed for another target)"
        ) from None
    finally:
        zeroise(aes_key)

    try:
        parsed = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _malformed("sealed plaintext is not UTF-8 JSON") from None
    if not isinstance(parsed, dict):
        raise _malformed("sealed plaintext must be a JSON object")
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()):
        raise _malformed("sealed plaintext must map names to string values")

    allowed = set(blob["keys"])
    return {k: v for k, v in parsed.items() if k in allowed}


def seal(
    public_spki_b64: str,
    plaintext: Mapping[str, str],
    *,
    site: str,
    kind: str,
    name: str,
    identity: str,
    key_id: str,
) -> dict:
    """Mirror the browser's WebCrypto sealing steps (tests / headless fixtures only)."""
    try:
        spki_der = base64.b64decode(public_spki_b64, validate=True)
        public_key = serialization.load_der_public_key(spki_der)
    except (binascii.Error, ValueError, TypeError, UnsupportedAlgorithm):
        raise _malformed("edge public key is not base64 DER SPKI") from None

    aad = canonical_aad(site, kind, name, identity, key_id)
    aes_key = os.urandom(AES_KEY_BYTES)
    iv = os.urandom(GCM_IV_BYTES)
    ciphertext = AESGCM(aes_key).encrypt(iv, canonical_plaintext(plaintext), aad.encode("utf-8"))
    wrapped = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "v": SEAL_VERSION,
        "alg": SEAL_ALG,
        "key_fp": fingerprint(spki_der),
        "key_id": key_id,
        "aad": aad,
        "wrapped_key": _b64encode(wrapped),
        "iv": _b64encode(iv),
        "ciphertext": _b64encode(ciphertext),
        "keys": sorted(plaintext),
    }


def zeroise(buf: bytearray) -> None:
    """Overwrite best-effort. Python cannot promise this: copies may already exist."""
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except (TypeError, BufferError):  # pragma: no cover - defensive only
        pass
