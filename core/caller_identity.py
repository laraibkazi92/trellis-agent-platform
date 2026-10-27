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

# Background runs act as a service identity (``svc_agent_<agent>``) and are email-less
# by design: they have no profile record, so there is no address to seal to. Callers
# that decide "this identity cannot serve a per-user credential" must not treat that
# deliberate emptiness as a broken identity.
SERVICE_IDENTITY_PREFIX = "svc_agent_"


def is_service_identity(user_id: Any) -> bool:
    """Whether ``user_id`` is a background run's service identity."""
    return str(user_id or "").startswith(SERVICE_IDENTITY_PREFIX)


def lacks_credential_identity(claims: Any, *, sealed: bool = False) -> bool:
    """Whether a *sealed* credential set cannot be attributed to this identity.

    A blob is sealed to ``edge_secrets_central.sealed_identity``: the caller's
    lowercased email, **else their user id**. So the identity a blob needs is "an email
    or a user id", not "an email" -- that fallback is what lets an identity with no
    email address still use per-user credentials, and refusing it would break a working
    path (a webhook-triggered run mints the literal user id ``webhook`` and has no email
    by design).

    Central cannot see an edge export's ``credential_mode``, so this only answers the
    question it *can*: a blob arrived and there is nothing to attribute it to. Whether a
    per-user *mode* may run for an email-less caller is the edge's decision -- it knows
    the mode, and ``core.edge_user_secrets.resolve`` refuses it with the same
    ``identity_incomplete`` code.
    """
    if not sealed:
        return False
    if claims is None:
        # A blob with no token: nothing was verified, so there is no subject at all.
        return True
    if getattr(claims, "user_email", None):
        return False
    # The seal's own fallback: a user id is a usable subject when there is no email.
    return not getattr(claims, "user_id", None)


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
    if is_service_identity(user_id):
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
    # One normalized spelling (strip + lowercase) for everything the email feeds: the
    # minted token claim, ``TRELLIS_USER_EMAIL``, the edge's MCP session key and the
    # sealed-credential AAD identity. An OIDC claim can arrive as ``Alice@Example.COM``
    # for the same person who sealed under ``alice@example.com``, and two spellings are
    # two identities. Deliberately local rather than
    # ``core.edge_user_secrets.normalize_email``: that one returns a filesystem stem
    # (slug + hash), not an address, and is edge-only by design.
    email = email.strip().lower() if isinstance(email, str) and email.strip() else None
    if email is None and os.getenv("DEV_MODE", "false").lower() == "true":
        # DEV_MODE only: a local login may have no persisted record. Normalized the same
        # way, so the dev identity is not a second spelling of itself.
        email = os.getenv("DEV_USER_EMAIL", "dev-user@local.host").strip().lower() or None

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
