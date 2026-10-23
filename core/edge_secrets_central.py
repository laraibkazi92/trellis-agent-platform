# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Central storage for browser-sealed per-user edge credentials.

The record this module stores is exactly the envelope the browser produced
(``core/edge_crypto``) plus bookkeeping -- ``created_at`` / ``created_by``. There is no
plaintext value here and no way to derive one: the AES key is wrapped to the edge's
public key, whose private half never reaches this process. Readers of this module
(``core/routers/edge_secrets.py``) therefore only ever see names, a fingerprint and a
timestamp.

Layout::

    /registry/edge_user_secrets/<site>/<user_id>/<kind>/<name>   kind in {tool, mcp}

The user segment is percent-encoded so an OIDC subject containing ``/`` (or anything
else that would split the key) cannot forge a second path segment. ``site`` / ``kind`` /
``name`` are rejected if they would do the same.

Everything is synchronous etcd I/O on ``identity_mgr.client``; callers run it via
``asyncio.to_thread`` like the rest of the configuration routers.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional
from urllib.parse import quote, unquote

logger = logging.getLogger(__name__)

EDGE_USER_SECRETS_PREFIX = "/registry/edge_user_secrets/"
KINDS = ("tool", "mcp")


def sealed_identity(user_id: Any, user_email: Any = None) -> str:
    """The AAD identity for a user: normalized email, else the raw user id.

    The edge must compute this exact value at call time, so there is one definition
    and it lives here. Case/whitespace normalization is deliberate: the same person
    arrives as ``Alice@Example.com`` from an OIDC claim and ``alice@example.com`` from
    a token, and both must open the same blob.
    """
    email = str(user_email or "").strip().lower()
    if email:
        return email
    return str(user_id or "").strip()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _segment(value: Any, what: str) -> str:
    """One path segment that cannot escape or split the etcd key."""
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{what} is required")
    if "/" in text or text in (".", "..") or any(ord(ch) < 32 for ch in text):
        raise ValueError(f"{what} contains an unsafe character")
    return text


def _user_segment(user_id: Any) -> str:
    """Percent-encoded user id: an OIDC subject may contain ``/`` or ``%``.

    ``safe=""`` encodes every reserved byte, so the decoded value round-trips through
    :func:`_summaries` while the stored key always has exactly four segments.
    """
    text = str(user_id or "").strip()
    if not text:
        raise ValueError("user_id is required")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError("user_id contains an unsafe character")
    return quote(text, safe="")


def record_path(site: str, user_id: str, kind: str, name: str) -> str:
    """The etcd key for one sealed credential record.

    ``user_id`` is percent-encoded; every other segment is validated by
    :func:`_segment`. ``kind`` is checked against :data:`KINDS`.
    """
    site = _segment(site, "site")
    name = _segment(name, "name")
    kind = _segment(kind, "kind")
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    return f"{EDGE_USER_SECRETS_PREFIX}{site}/{_user_segment(user_id)}/{kind}/{name}"


def _parse_record(value: Any) -> Optional[Dict[str, Any]]:
    if not value:
        return None
    try:
        parsed = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def put(
    identity_mgr: Any,
    site: str,
    user_id: str,
    kind: str,
    name: str,
    blob: Mapping[str, Any],
    *,
    created_at: Optional[str] = None,
    created_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Store one envelope verbatim (plus bookkeeping). Returns the stored record.

    No validation happens here on purpose: the router is the write-time gate, and a
    store that silently rewrote or dropped fields would make an edge rejection
    impossible to diagnose. Unknown fields are preserved.
    """
    record = dict(blob)
    record["created_at"] = created_at or _now_iso()
    if created_by:
        record["created_by"] = str(created_by)
    identity_mgr.client.put(record_path(site, user_id, kind, name), json.dumps(record))
    return record


def get(
    identity_mgr: Any, site: str, user_id: str, kind: str, name: str
) -> Optional[Dict[str, Any]]:
    """Read one record, or ``None``. Corrupt JSON reads as missing (fail closed)."""
    value, _ = identity_mgr.client.get(record_path(site, user_id, kind, name))
    return _parse_record(value)


def delete(identity_mgr: Any, site: str, user_id: str, kind: str, name: str) -> bool:
    """Delete one record. Returns whether etcd reported a deletion."""
    return bool(identity_mgr.client.delete(record_path(site, user_id, kind, name)))


def _summaries(identity_mgr: Any, prefix: str, site: Optional[str] = None) -> List[Dict[str, Any]]:
    """Names-only summaries for every record under ``prefix``.

    ``prefix`` is either the global store (``site`` parsed from each key) or one
    site's subtree (``site`` supplied by the caller).
    """
    out: List[Dict[str, Any]] = []
    for value, metadata in identity_mgr.client.get_prefix(prefix):
        raw_key = getattr(metadata, "key", b"")
        key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix):].split("/")
        if site is None:
            if len(parts) != 4:
                # <site>/<user>/<kind>/<name> under the global prefix
                continue
            record_site, user_segment, kind, name = parts
        else:
            if len(parts) != 3:
                continue
            user_segment, kind, name = parts
            record_site = site
        record = _parse_record(value) or {}
        out.append(
            {
                "site": record_site,
                "user_id": unquote(user_segment),
                "kind": kind,
                "name": name,
                "key_fp": record.get("key_fp") or "",
                "created_at": record.get("created_at") or "",
                "created_by": record.get("created_by") or "",
            }
        )
    out.sort(key=lambda item: (item["site"], item["user_id"], item["kind"], item["name"]))
    return out


def list_for_site(identity_mgr: Any, site: str) -> List[Dict[str, Any]]:
    """Every record for one site, names only -- never the envelope or its values."""
    site = _segment(site, "site")
    return _summaries(identity_mgr, f"{EDGE_USER_SECRETS_PREFIX}{site}/", site)


def list_for_user(identity_mgr: Any, user_id: str) -> List[Dict[str, Any]]:
    """Every record belonging to one user across sites, names only.

    etcd has no secondary index here, so this is one prefix scan filtered by the
    decoded user segment. The store is per-user credentials for a handful of tools,
    not a ledger.
    """
    wanted = str(user_id or "").strip()
    if not wanted:
        raise ValueError("user_id is required")
    return [
        item
        for item in _summaries(identity_mgr, EDGE_USER_SECRETS_PREFIX)
        if item["user_id"] == wanted
    ]


# --- site key state ---------------------------------------------------------
# The site record is written by the relay. ``edge_key_fps`` is the rotation history;
# a record may carry bare fingerprints or ``{fp, retired_at}`` dicts, so both are
# tolerated here rather than in each caller.


def key_history(site_record: Optional[Mapping[str, Any]]) -> List[Dict[str, str]]:
    """Rotation history as ``[{fp, retired_at}]``, current key excluded."""
    record = site_record or {}
    raw = record.get("edge_key_fps") or []
    if isinstance(raw, dict):
        raw = [raw]
    entries: List[Dict[str, str]] = []
    if isinstance(raw, (list, tuple)):
        for entry in raw:
            if isinstance(entry, str) and entry:
                entries.append({"fp": entry, "retired_at": ""})
            elif isinstance(entry, dict):
                fp = entry.get("fp") or entry.get("fingerprint")
                if isinstance(fp, str) and fp:
                    entries.append(
                        {
                            "fp": fp,
                            "retired_at": str(
                                entry.get("retired_at") or entry.get("rotated_at") or ""
                            ),
                        }
                    )
    previous = record.get("prev_edge_key_fp")
    if isinstance(previous, str) and previous:
        entries.append({"fp": previous, "retired_at": ""})

    seen: set = set()
    unique: List[Dict[str, str]] = []
    for entry in entries:
        if entry["fp"] not in seen:
            seen.add(entry["fp"])
            unique.append(entry)
    return unique


def active_fingerprints(site_record: Optional[Mapping[str, Any]]) -> set:
    """Fingerprints a blob may still be sealed to: the current key plus the overlap."""
    record = site_record or {}
    active = {entry["fp"] for entry in key_history(record)}
    current = record.get("edge_key_fp")
    if isinstance(current, str) and current:
        active.add(current)
    return active


def last_rotated_at(site_record: Optional[Mapping[str, Any]]) -> str:
    """Best-effort "last rotation" for the admin view; empty when unknown."""
    record = site_record or {}
    explicit = record.get("edge_key_rotated_at")
    if isinstance(explicit, str) and explicit:
        return explicit
    stamps = [entry["retired_at"] for entry in key_history(record) if entry["retired_at"]]
    return max(stamps) if stamps else ""


def retired_blobs(
    identity_mgr: Any, site: str, active_fps: Iterable[str]
) -> List[Dict[str, Any]]:
    """Records sealed to a key that is neither current nor previous.

    These are inert: the edge cannot open them, so the user must re-enter the
    credential set. The list carries names only.
    """
    active = {fp for fp in active_fps if fp}
    return [item for item in list_for_site(identity_mgr, site) if item["key_fp"] not in active]
