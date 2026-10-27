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
    """Whether a per-user credential call cannot be attributed to this identity.

    ``claims`` is a verified ``agent_token.Claims`` (or ``None`` when no token was
    presented). A sealed set is bound to the caller's email, so an identity without one
    can never open -- or be matched to -- any per-user material. Central cannot see an
    edge export's ``credential_mode`` either, so a real *user* identity with no email is
    refused here instead of letting the edge answer ``missing_credentials`` (or
    ``credential_rejected``), which sends the operator to re-seal a key that was never
    the problem.

    Two cases stay allowed, because refusing them would break what is not per-user:

    * no claims at all -- nothing is asserted, and the edge's ``credential_mode`` is the
      only authority (the documented no-token rollout posture);
    * a service identity (``svc_agent_*``) with no sealed set -- email-less by design,
      and it can never hold one.
    """
    if claims is None:
        return False
    if getattr(claims, "user_email", None):
        return False
    if sealed:
        return True
    user_id = getattr(claims, "user_id", None)
    return bool(user_id) and not is_service_identity(user_id)


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
