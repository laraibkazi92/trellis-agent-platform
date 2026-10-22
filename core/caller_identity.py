# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Caller identity resolution shared by the hub and remote (edge) dispatch.

Kept out of ``core.hub`` so a caller that only needs the email does not import the
FastMCP server or the etcd-backed identity manager.
"""

import asyncio
import os
from typing import Any, Optional


async def resolve_user_email(identity_mgr: Any, user_id: Optional[str]) -> Optional[str]:
    """The caller's email, or None when the identity has no profile.

    This is the only user attribute that leaves the control plane: the hub exports
    it to tool processes and forwards it with a remote call, so it is resolved here
    centrally rather than trusted from the request.

    No user id means anonymous: no profile is read and no dev fallback is asserted
    (an anonymous remote call carries no identity rather than the dev email).
    """
    if not user_id:
        return None

    if os.getenv("DEV_MODE", "false").lower() == "true":
        return os.getenv("DEV_USER_EMAIL", "dev-user@local.host")

    user_profile = await asyncio.to_thread(identity_mgr.get_user, user_id)
    if user_profile and user_profile.get("email"):
        return user_profile["email"]
    return None
