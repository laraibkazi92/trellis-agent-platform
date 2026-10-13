# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import logging
import os

from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)


def configure_cors(app) -> None:
    """Attach CORS middleware honoring DEV_MODE and CORS_ALLOWED_ORIGINS.

    DEV_MODE allows every origin; otherwise the comma-separated
    CORS_ALLOWED_ORIGINS list is used (empty when unset).
    """
    dev_mode = os.getenv("DEV_MODE", "false").lower() == "true"
    cors_origins_str = os.getenv("CORS_ALLOWED_ORIGINS", "")
    if dev_mode:
        allow_origins = ["*"]
    else:
        allow_origins = [origin.strip() for origin in cors_origins_str.split(",")] if cors_origins_str else []

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def enforce_dev_mode_safety(service_name: str) -> None:
    """Announce loudly that DEV_MODE has disabled all authentication.

    Historically this refused to start a DEV_MODE service on a non-loopback
    bind host (opt-out via DEV_MODE_ALLOW_REMOTE_BIND). It is warning-only now:
    dev instances are routinely reached from other machines (the dev host is
    not the deployment target), so it signals but never blocks startup.
    """
    if os.getenv("DEV_MODE", "false").lower() != "true":
        return

    logger.warning(
        "\n%s\n  WARNING: %s is running in DEV_MODE -- ALL AUTHENTICATION IS DISABLED.\n"
        "  Never expose a DEV_MODE instance to production or untrusted networks.\n%s",
        "=" * 74,
        service_name,
        "=" * 74,
    )
