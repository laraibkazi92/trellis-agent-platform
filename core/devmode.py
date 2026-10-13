# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import logging
import os

logger = logging.getLogger(__name__)


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
