# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Append-only audit trail for edge activity.

The relay sees tool arguments and results in transit; neither may reach a log.
This module writes one JSON line per event with only the metadata an operator
needs to answer "who called what, when, and did it work":

    {"ts": "...", "event": "call", "site": "plant-floor",
     "tool": "boiler_status", "call_id": "...", "user": "...",
     "outcome": "ok", "ms": 42, "args_bytes": 18, "result_bytes": 210}

Destination is ``EDGE_AUDIT_LOG`` (compose points it at the shared health volume).
Unset means stdout-only through the normal logger, which is what tests get.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Optional

logger = logging.getLogger("trellis.edge.audit")
logger.setLevel(logging.INFO)
logger.propagate = False

_configured = False


def configure(path: Optional[str] = None) -> None:
    """Attach the rotating file handler once per process."""
    global _configured
    if _configured:
        return
    # Always keep a stderr handler: a compliance-adjacent control must not go
    # silent because the volume is full or read-only, and a failure to attach the
    # file needs somewhere to be reported.
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        logger.addHandler(logging.StreamHandler())
    target = path or os.getenv("EDGE_AUDIT_LOG", "")
    if target:
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            handler = RotatingFileHandler(
                target, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
        except OSError as exc:  # unwritable volume must not stop the relay
            logger.warning("edge audit log disabled (%s): %s", target, exc)
    _configured = True


def record(
    event: str,
    *,
    site: str,
    outcome: str,
    tool: Optional[str] = None,
    call_id: Optional[str] = None,
    user: Optional[str] = None,
    ms: Optional[int] = None,
    args_bytes: Optional[int] = None,
    result_bytes: Optional[int] = None,
) -> None:
    """Emit one audit line. Never pass payloads through here."""
    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "site": site,
        "outcome": outcome,
    }
    if tool is not None:
        entry["tool"] = tool
    if call_id is not None:
        entry["call_id"] = call_id
    if user is not None:
        entry["user"] = user
    if ms is not None:
        entry["ms"] = ms
    if args_bytes is not None:
        entry["args_bytes"] = args_bytes
    if result_bytes is not None:
        entry["result_bytes"] = result_bytes
    logger.info(json.dumps(entry, separators=(",", ":")))
