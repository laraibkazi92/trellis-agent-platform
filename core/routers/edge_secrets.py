# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Browser-sealed per-user edge credentials: pubkey, write-time gate, listing.

The browser seals a credential set to the edge's public key (``core/edge_crypto``); this
router is the only writer of the resulting envelope. Three decisions live here, and each
is the server's rather than the browser's:

* **which names may be sealed** -- only the manifest's declared secret keys; a
  ``variables`` name is refused outright (endpoint overrides are edge config, never
  per-user material -- §6 invariant 10);
* **which user the blob belongs to** -- the AAD is recomputed from the session and
  compared, so a caller cannot store a blob for somebody else even with a valid
  envelope;
* **which edge key** -- the fingerprint must be the site's current key or one still in
  the rotation overlap.

No response, log line or error message here contains ``wrapped_key`` or ``ciphertext``;
the store's summaries are names and a fingerprint only.
"""

from __future__ import annotations

import asyncio
import hmac
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core import edge_crypto, edge_keypair, edge_secrets_central
from core.auth import is_admin
from core.dependencies import CSRFRoute, identity_mgr
# The flattening rules are shared with the edge (core/edge_env.py) so central can
# never accept a key the edge would not export, or vice versa.
from core.manifest_keys import declared_keys

router = APIRouter(route_class=CSRFRoute)

_SERVER_ERRORS = {
    edge_crypto.MALFORMED: "sealed blob is malformed",
    edge_crypto.CREDENTIAL_REJECTED: "sealed blob is bound to another site, target or user",
}


def _json(status_code: int, payload: Dict[str, Any]) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=payload)


def _error(status_code: int, code: str, message: str = "") -> JSONResponse:
    # Callers send ciphertext; never echo anything from the body back.
    return _json(status_code, {"error": code, "detail": message or code})


def _session_user(request: Request) -> Optional[Dict[str, Any]]:
    user = request.session.get("user")
    return user if isinstance(user, dict) else None


def _user_id(user: Dict[str, Any]) -> str:
    return str(user.get("sub") or "").strip()


def _csrf_ok(request: Request) -> bool:
    """JSON bodies bypass ``CSRFRoute``; require the session token in a header.

    The token is the same value rendered into the page's form; the partial sends it as
    ``X-CSRF-Token``. A missing session token fails closed rather than skipping the
    check, so an unauthenticated JSON writer cannot ride an empty session.
    """
    expected = request.session.get("csrf_token")
    if not expected:
        return False
    headers = getattr(request, "headers", None) or {}
    provided = headers.get("x-csrf-token") or headers.get("X-CSRF-Token") or ""
    if not isinstance(provided, str):
        return False
    return hmac.compare_digest(provided, str(expected))


# --- manifest → declared keys ------------------------------------------------
#
# ``declared_keys(config) -> (secret_keys, variable_keys)`` lives in
# ``core/manifest_keys`` because the edge applies the same rules to the same
# manifest. It is imported above and re-exported here for the configuration page.


def _target_manifest(
    kind: str, site: str, name: str
) -> Optional[Dict[str, Any]]:
    """The edge tool/MCP manifest as published to central.

    Edge tools are registered as ``<site>__<tool>`` by the relay; a same-named local
    tool is the fallback so a site that publishes a manifest identical to a central
    suite still resolves. MCPs are always site-scoped.
    """
    if kind == "tool":
        return identity_mgr.get_tool_config(f"{site}__{name}") or identity_mgr.get_tool_config(name)
    return identity_mgr.get_mcp_config(f"{site}__{name}")


def _declared_for(site: str, kind: str, name: str, config: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Declared keys from the manifest, else the site record's published map.

    Relay-published ``<site>__<name>`` configs deliberately omit ``secrets`` and
    ``variables`` (the edge owns them), so the hello frame publishes
    ``credential_keys`` and the relay stores it on the site record.
    """
    secret_keys, variable_keys = declared_keys(config)
    if secret_keys or variable_keys:
        return secret_keys, variable_keys
    record = _site_record(site)
    published = (record.get("credential_keys") or {}).get(name) or {}
    if not isinstance(published, dict):
        return [], []
    return (
        sorted({str(k) for k in published.get("secret_keys") or [] if k}),
        sorted({str(k) for k in published.get("variable_keys") or [] if k}),
    )


def _site_record(site: str) -> Dict[str, Any]:
    return identity_mgr.get_edge_config(site) or {}


def _pubkey_material(record: Dict[str, Any]) -> Tuple[str, str]:
    """``(fingerprint, key_id)`` from a site record."""
    raw_fp = record.get("edge_key_fp")
    fp = raw_fp if isinstance(raw_fp, str) else ""
    key_id = record.get("edge_key_id")
    if not isinstance(key_id, str) or not key_id:
        key_id = edge_keypair.key_id(fp) if fp else ""
    return fp, key_id


def _valid_kind(kind: str) -> bool:
    return kind in edge_secrets_central.KINDS


# --- routes ------------------------------------------------------------------

# Registered before ``/{site}`` so a site literally named "mine" never shadows the
# user's own list.
@router.get("/configuration/edge-secrets/mine")
async def list_my_secrets(request: Request):
    user = _session_user(request)
    user_id = _user_id(user or {})
    if not user or not user_id:
        return _error(401, "unauthorized", "sign in to view your edge credentials")

    records = await asyncio.to_thread(edge_secrets_central.list_for_user, identity_mgr, user_id)
    return _json(200, {"records": records})


@router.get("/configuration/edge-secrets/{site}/{kind}/{name}/pubkey")
async def edge_secret_pubkey(request: Request, site: str, kind: str, name: str):
    user = _session_user(request)
    if not user:
        return _error(401, "unauthorized", "sign in to configure edge credentials")
    if not _valid_kind(kind):
        return _error(404, "unknown_kind", f"kind must be one of {', '.join(edge_secrets_central.KINDS)}")

    config = await asyncio.to_thread(_target_manifest, kind, site, name)
    if config is None:
        return _error(404, "unknown_target", "no manifest is registered for this edge target")

    record = await asyncio.to_thread(_site_record, site)
    fp, key_id = _pubkey_material(record)
    spki = record.get("edge_pubkey")
    if not fp or not isinstance(spki, str) or not spki:
        return _error(404, "no_edge_key", "this edge has not published a credential key yet")

    secret_keys, variable_keys = _declared_for(site, kind, name, config)
    return _json(
        200,
        {
            "key_fp": fp,
            "key_id": key_id,
            "spki": spki,
            "secret_keys": secret_keys,
            "variable_keys": variable_keys,
        },
    )


@router.post("/configuration/edge-secrets/{site}/{kind}/{name}")
async def store_edge_secret(request: Request, site: str, kind: str, name: str):
    user = _session_user(request)
    user_id = _user_id(user or {})
    if not user or not user_id:
        return _error(401, "unauthorized", "sign in to store edge credentials")
    if not _csrf_ok(request):
        return _error(403, "csrf_failed", "refresh the page and try again")
    if not _valid_kind(kind):
        return _error(404, "unknown_kind", f"kind must be one of {', '.join(edge_secrets_central.KINDS)}")

    try:
        blob = await request.json()
    except Exception:  # noqa: BLE001 - any parse failure is a malformed body
        return _error(400, edge_crypto.MALFORMED, "sealed blob is malformed")

    try:
        edge_crypto.validate_blob(blob)
    except edge_crypto.SealedError as exc:
        return _error(400, exc.code, _SERVER_ERRORS.get(exc.code, "sealed blob is malformed"))

    config = await asyncio.to_thread(_target_manifest, kind, site, name)
    if config is None:
        return _error(404, "unknown_target", "no manifest is registered for this edge target")

    secret_keys, variable_keys = _declared_for(site, kind, name, config)
    keys = list(blob["keys"])
    if len(set(keys)) != len(keys):
        return _error(400, edge_crypto.MALFORMED, "sealed blob lists the same key twice")
    if set(keys) & set(variable_keys):
        return _error(
            400,
            "variable_key_not_allowed",
            "variables are configured on the edge, never per user",
        )
    if set(keys) - set(secret_keys):
        return _error(400, "undeclared_keys", "sealed blob contains keys this tool does not declare")

    identity = edge_secrets_central.sealed_identity(user_id, user.get("email"))
    expected_aad = edge_crypto.canonical_aad(site, kind, name, identity, blob["key_id"])
    if not hmac.compare_digest(blob["aad"].encode("utf-8"), expected_aad.encode("utf-8")):
        return _error(
            400,
            edge_crypto.CREDENTIAL_REJECTED,
            _SERVER_ERRORS[edge_crypto.CREDENTIAL_REJECTED],
        )

    key_fp = blob["key_fp"]
    if blob["key_id"] != edge_keypair.key_id(key_fp):
        return _error(400, "key_mismatch", "sealed blob's key id does not match its fingerprint")

    record = await asyncio.to_thread(_site_record, site)
    if key_fp not in edge_secrets_central.active_fingerprints(record):
        return _error(
            400,
            "retired_key",
            "the edge key this blob was sealed to is retired; reload the page and retry",
        )

    created_by = str(user.get("email") or user_id)
    stored = await asyncio.to_thread(
        edge_secrets_central.put,
        identity_mgr,
        site,
        user_id,
        kind,
        name,
        blob,
        created_by=created_by,
    )
    return _json(
        200,
        {
            "stored": True,
            "site": site,
            "kind": kind,
            "name": name,
            "key_fp": stored["key_fp"],
            "key_id": stored["key_id"],
            "keys": list(stored["keys"]),
        },
    )


@router.delete("/configuration/edge-secrets/{site}/{kind}/{name}")
async def clear_edge_secret(request: Request, site: str, kind: str, name: str):
    user = _session_user(request)
    user_id = _user_id(user or {})
    if not user or not user_id:
        return _error(401, "unauthorized", "sign in to clear edge credentials")
    if not _csrf_ok(request):
        return _error(403, "csrf_failed", "refresh the page and try again")
    if not _valid_kind(kind):
        return _error(404, "unknown_kind", f"kind must be one of {', '.join(edge_secrets_central.KINDS)}")

    deleted = await asyncio.to_thread(
        edge_secrets_central.delete, identity_mgr, site, user_id, kind, name
    )
    return _json(200, {"deleted": bool(deleted)})


@router.get("/configuration/edge-secrets/{site}")
async def list_site_secrets(request: Request, site: str):
    user = _session_user(request)
    if not user:
        return _error(401, "unauthorized", "sign in to view edge credentials")
    if not is_admin(request):
        return _error(403, "forbidden", "admin access is required")

    record = await asyncio.to_thread(_site_record, site)
    active = edge_secrets_central.active_fingerprints(record)
    records = await asyncio.to_thread(edge_secrets_central.list_for_site, identity_mgr, site)
    # ``active`` lets the admin page distinguish a usable blob from one sealed to a
    # retired key (the user must re-enter it) without shipping the key state again.
    for item in records:
        item["active"] = bool(item.get("key_fp")) and item["key_fp"] in active
    return _json(200, {"site": site, "records": records})
