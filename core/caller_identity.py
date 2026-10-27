# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Caller identity resolved ONCE at mint time.

Identity travels only in the verified agent token (v0.7.1 Phase 2): every enforcement
point reads ``Claims`` instead of a request body. Resolving the user's attributes is
therefore a *mint-time* operation -- the runtime reads the record once, the token
carries the result, and no call redeems it from the registry again.

Kept out of ``core.hub`` so a caller that only mints does not import the FastMCP
server; the only import here is the dependency-free token module.
"""

import asyncio
import logging
import os
from typing import Any, Optional

from core.agent_token import normalize_groups

logger = logging.getLogger(__name__)

# Stable refusal code for a per-user-credential call it cannot serve: the edge seals
# credentials per user and needs the caller's email, but the verified token has none.
IDENTITY_INCOMPLETE = "identity_incomplete"


async def resolve_mint_identity(identity_mgr: Any, user_id: Optional[str]) -> dict:
    """``{"user_email": str | None, "groups": tuple}`` for one user, read once.

    The groups field is the one the login path stores on the record (already
    normalized from the configured ``OIDC_GROUPS_CLAIM``); it is normalized again here
    so a hand-edited record cannot smuggle a malformed claim into a token.

    Fail-open by design: an unreadable record costs the token its email and groups,
    never the run. A service identity (``svc_agent_*``) has no profile record and is
    deliberately given nothing -- background runs fail closed on any group rule.
    No user id means anonymous: nothing is read.
    """
    empty: dict = {"user_email": None, "groups": ()}
    if not user_id:
        return empty
    if str(user_id).startswith("svc_agent_"):
        # Service identity: no email, no groups. A background run must not inherit the
        # groups of the user who triggered it, so nothing is read or asserted here --
        # that is the fail-closed contract for workflows, not an oversight.
        return empty

    record: Any = None
    try:
        record = await asyncio.to_thread(identity_mgr.get_user, user_id)
    except Exception as exc:
        logger.warning(
            "Could not read the identity record for %r while minting a token (%s); "
            "the token carries no email or groups",
            user_id,
            type(exc).__name__,
        )
    if not isinstance(record, dict):
        record = {}

    email = record.get("email")
    email = email.strip() if isinstance(email, str) and email.strip() else None
    if email is None and os.getenv("DEV_MODE", "false").lower() == "true":
        # DEV_MODE only: a local login may have no persisted record.
        email = os.getenv("DEV_USER_EMAIL", "dev-user@local.host")

    return {"user_email": email, "groups": normalize_groups(record.get("groups"))}


def identity_incomplete_error(subject: str, site: str) -> dict:
    """The refusal for a per-user-credential call whose token carries no email.

    Never ``credential_rejected``: that code tells an operator to re-seal credentials,
    which cannot fix a caller whose identity is missing. The message names what is
    missing, so the operator knows to look at the identity provider, not the seal.
    """
    return {
        "error": (
            f"{IDENTITY_INCOMPLETE}: {subject} on edge '{site}' uses per-user "
            "credentials, which are sealed to the caller's email, and the verified "
            "agent token carries no email. Sign in with an identity provider that "
            "asserts one (or use a token minted for a user with an email)."
        )
    }
