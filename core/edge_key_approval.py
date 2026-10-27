# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Admin approval of the edge's credential-sealing key.

The edge publishes its sealing public key on every ``hello`` and the relay pins it on the
site record. A published key is **not** usable until an admin approves its fingerprint
(Admin -> Edges): the browser seals to whatever SPKI central serves, so a swapped key file
-- or a site record written by a compromised tunnel -- would otherwise hand that edge
every user's plaintext.

State on the site record:

* ``edge_key_fp`` -- the fingerprint the edge currently publishes;
* ``edge_key_approved_fp`` -- the fingerprint an admin approved. It survives a rotation,
  so the old key stays the one central trusts until the new one is approved;
* ``edge_key_approved`` -- whether the *current* fingerprint is that approved one. It is
  derived here and flips to ``True`` only in :func:`approve_current_key`;
* ``edge_key_approved_by`` / ``edge_key_approved_at`` -- who approved, and when.

:func:`with_pending_state` runs on every site-record write
(``core.auth.IdentityManager.save_edge_config``), so any writer that publishes key
material -- a first hello, a rotation -- lands pending without the relay having to know
about approvals.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple

# The error code the pubkey endpoint returns while a fingerprint awaits approval.
PENDING_CODE = "key_pending_approval"


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def current_fingerprint(record: Optional[Mapping[str, Any]]) -> str:
    """The fingerprint the edge currently publishes (``""`` when it has none)."""
    return _text((record or {}).get("edge_key_fp"))


def approved_fingerprint(record: Optional[Mapping[str, Any]]) -> str:
    """The fingerprint an admin approved (``""`` before the first approval)."""
    return _text((record or {}).get("edge_key_approved_fp"))


def is_current_key_approved(record: Optional[Mapping[str, Any]]) -> bool:
    """Whether the *current* fingerprint is the approved one."""
    record = record or {}
    fp = current_fingerprint(record)
    if not fp or record.get("edge_key_approved") is not True:
        return False
    return fp == approved_fingerprint(record)


def pending_fingerprint(record: Optional[Mapping[str, Any]]) -> str:
    """The published fingerprint awaiting approval (``""`` when none is)."""
    return "" if is_current_key_approved(record) else current_fingerprint(record)


def approved_by(record: Optional[Mapping[str, Any]]) -> str:
    """Who approved the current fingerprint (audit, display only)."""
    return _text((record or {}).get("edge_key_approved_by"))


def approved_at(record: Optional[Mapping[str, Any]]) -> str:
    """When the current fingerprint was approved (audit, display only)."""
    return _text((record or {}).get("edge_key_approved_at"))


def pending_message(record: Optional[Mapping[str, Any]]) -> str:
    """The one wording the endpoint and the seal form both show."""
    fp = pending_fingerprint(record)
    if fp:
        return f"key fingerprint {fp} is pending admin approval; sealing is disabled"
    return "this edge has no approved credential key; sealing is disabled"


def with_pending_state(record: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Return the record with ``edge_key_approved`` recomputed, pending unless approved.

    Never approves anything: the flag only becomes true through
    :func:`approve_current_key`, and a later fingerprint change clears it again.
    """
    updated = dict(record or {})
    updated["edge_key_approved"] = is_current_key_approved(updated)
    return updated


def approve_current_key(
    record: Optional[Mapping[str, Any]], approver: Any, *, now: Optional[str] = None
) -> Tuple[Dict[str, Any], bool]:
    """Approve the fingerprint the edge currently publishes.

    Returns ``(record, changed)``. Raises ``ValueError`` when the edge has published no
    key yet, since there is nothing to approve. Re-approving the same fingerprint is a
    no-op so the recorded approver and timestamp stay the ones that enabled sealing.
    """
    updated = dict(record or {})
    fp = current_fingerprint(updated)
    if not fp:
        raise ValueError("this edge has not published a credential key yet")
    if is_current_key_approved(updated):
        return updated, False

    updated.update(
        {
            "edge_key_approved": True,
            "edge_key_approved_fp": fp,
            "edge_key_approved_by": str(approver or "").strip() or "unknown",
            "edge_key_approved_at": now or _now_iso(),
        }
    )
    return updated, True
