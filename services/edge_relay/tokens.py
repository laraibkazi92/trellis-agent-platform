# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Enrollment-token resolution for the edge relay.

The site name is derived only from ``sha256(token)``, looked up in the
``/edge_tokens/<sha256> -> site`` index -- never from anything the client sends --
so a leaked token cannot be replayed as a different site. Neither the token nor its
hash is ever logged.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_DEV_TRUTHY = ("1", "true", "yes")


def hash_token(token: str) -> str:
    """SHA-256 of a token; this is the only form that may be persisted."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _dev_identity(token: str) -> Optional[Dict[str, Any]]:
    """Return a synthetic site when the DEV_MODE escape hatch is armed.

    Checked before the registry so local testing works with etcd down, and only
    when the operator explicitly opted in; a production deploy never sets both
    DEV_MODE and EDGE_DEV_TOKEN.
    """
    if os.getenv("DEV_MODE", "false").lower() not in _DEV_TRUTHY:
        return None
    expected = os.getenv("EDGE_DEV_TOKEN")
    if not expected:
        return None
    if not hmac.compare_digest(token, expected):
        return None
    return {"name": os.getenv("EDGE_DEV_SITE", "dev-edge"), "enabled": True}


def resolve_token(token: str, identity_mgr: Any = None) -> Optional[Dict[str, Any]]:
    """Resolve a bearer token to its edge config, or ``None`` if unknown/disabled.

    Registry failures are swallowed: a brief etcd outage must degrade to
    "unknown token" (the edge reconnects with backoff) rather than crash the
    relay's connection handler.
    """
    if not token:
        return None

    dev = _dev_identity(token)
    if dev is not None:
        return dev

    if identity_mgr is None:
        from core.auth import get_identity_manager

        identity_mgr = get_identity_manager()

    # A single hash-index get (``/edge_tokens/<sha256>`` -> site) rather than a scan
    # of every site: this runs pre-upgrade, on the only unauthenticated path in the
    # relay, so its cost must not grow with the number of registered edges.
    try:
        site = identity_mgr.resolve_edge_token(token)
        if not site:
            return None
        config = identity_mgr.get_edge_config(site)
    except Exception:
        logger.warning("edge token lookup failed: registry unavailable")
        return None

    if not isinstance(config, dict):
        return None
    return {**config, "name": site}
