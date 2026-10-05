# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import logging
import os

logger = logging.getLogger(__name__)

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def enforce_dev_mode_safety(service_name: str) -> None:
    """Guard against DEV_MODE being enabled on a remotely reachable bind address.

    DEV_MODE disables all authentication, so it must only ever serve loopback
    traffic unless the operator explicitly opts in via DEV_MODE_ALLOW_REMOTE_BIND.
    """
    if os.getenv("DEV_MODE", "false").lower() != "true":
        return

    bind_host = os.getenv("HOST_BIND") or os.getenv("BIND_HOST") or "0.0.0.0"

    logger.warning(
        "\n%s\n  WARNING: %s is running in DEV_MODE -- ALL AUTHENTICATION IS DISABLED.\n%s",
        "=" * 74,
        service_name,
        "=" * 74,
    )

    if bind_host in _LOOPBACK_HOSTS:
        return

    if os.getenv("DEV_MODE_ALLOW_REMOTE_BIND", "false").lower() != "true":
        raise RuntimeError(
            f"{service_name}: DEV_MODE=true refuses to bind non-loopback host "
            f"'{bind_host}' because it would expose an unauthenticated service to "
            "the network. Either set HOST_BIND=127.0.0.1 (or BIND_HOST), set "
            "DEV_MODE=false, or explicitly accept the risk with "
            "DEV_MODE_ALLOW_REMOTE_BIND=true."
        )

    logger.warning(
        "\n%s\n  DANGER: %s is bound to '%s' with DEV_MODE authentication DISABLED --\n"
        "  remote clients can access this service. (DEV_MODE_ALLOW_REMOTE_BIND=true is set.)\n%s",
        "!" * 74,
        service_name,
        bind_host,
        "!" * 74,
    )
