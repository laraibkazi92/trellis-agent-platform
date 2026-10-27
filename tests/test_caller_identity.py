# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Mint-time identity resolution (v0.7.1 Phase 2).

``resolve_mint_identity`` is the ONE place the runtime reads a user's attributes: the
result is minted into the agent token, and every enforcement point (hub, runner,
relay, edge) reads it back from ``Claims``. Nothing resolves identity per call any
more, so these tests pin the resolution rules -- including the ones that must stay
empty on purpose.

No etcd: the identity manager is a fake, as in the other hub/gateway suites.
"""

import asyncio

from core import agent_token
from core.caller_identity import (
    IDENTITY_INCOMPLETE,
    identity_incomplete_error,
    lacks_credential_identity,
    resolve_mint_identity,
)


class FakeIdentity:
    def __init__(self, record=None, *, error: Exception | None = None):
        self.record = record
        self.error = error
        self.calls = []

    def get_user(self, user_id):
        self.calls.append(user_id)
        if self.error is not None:
            raise self.error
        return self.record


def resolve(monkeypatch, record=None, *, user_id="user-1", error=None):
    monkeypatch.delenv("DEV_MODE", raising=False)
    fake = FakeIdentity(record, error=error)
    return asyncio.run(resolve_mint_identity(fake, user_id)), fake


# --------------------------------------------------------------------------- #
# the record
# --------------------------------------------------------------------------- #


def test_resolves_the_email_and_the_stored_groups(monkeypatch):
    identity, fake = resolve(
        monkeypatch, {"email": "ops@example.com", "groups": ["sre", "ops", "sre"]}
    )

    assert identity == {"user_email": "ops@example.com", "groups": ("ops", "sre")}
    assert fake.calls == ["user-1"]


def test_blank_email_and_garbage_groups_read_as_empty(monkeypatch):
    identity, _ = resolve(monkeypatch, {"email": "   ", "groups": "ops,sre"})

    assert identity == {"user_email": None, "groups": ()}


def test_a_record_without_email_or_groups_still_resolves(monkeypatch):
    identity, _ = resolve(monkeypatch, {"name": "Ops User"})

    assert identity == {"user_email": None, "groups": ()}


def test_an_email_is_trimmed(monkeypatch):
    identity, _ = resolve(monkeypatch, {"email": "  ops@example.com  "})

    assert identity["user_email"] == "ops@example.com"


def test_a_mixed_case_email_is_normalized_at_mint_time(monkeypatch):
    """One spelling for the token, ``TRELLIS_USER_EMAIL``, the session key and the AAD.

    An OIDC claim can carry ``User@Example.com`` for the same person who sealed under
    ``user@example.com``; two spellings would be two identities (two MCP sessions, and
    a sealed set that never opens).
    """
    monkeypatch.setenv("AGENT_TOKEN_SECRET", "caller-identity-unit-secret-0123456789")
    identity, _ = resolve(monkeypatch, {"email": "User@Example.com"})

    assert identity["user_email"] == "user@example.com"
    # What rides the token -- and therefore TRELLIS_USER_EMAIL on every call.
    token = agent_token.mint(
        "supervisor", user_id="user-1", user_email=identity["user_email"]
    )
    assert agent_token.verify(token).user_email == "user@example.com"


def test_a_mixed_case_dev_email_is_normalized_too(monkeypatch):
    """The DEV_MODE fallback is an identity like any other: same form, not a second one."""
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("DEV_USER_EMAIL", " Dev@Local.Host ")
    fake = FakeIdentity(None)

    identity = asyncio.run(resolve_mint_identity(fake, "user-1"))

    assert identity["user_email"] == "dev@local.host"


# --------------------------------------------------------------------------- #
# identities that must resolve to nothing
# --------------------------------------------------------------------------- #


def test_no_user_id_reads_nothing(monkeypatch):
    identity, fake = resolve(monkeypatch, {"email": "ops@example.com"}, user_id=None)

    assert identity == {"user_email": None, "groups": ()}
    assert fake.calls == []


def test_a_service_identity_gets_no_email_and_no_groups(monkeypatch):
    """Fail closed for background runs, even if a record exists under the id.

    The host cannot see a workflow's groups, so the mint must not assert any: a
    `group:` rule must deny a workflow rather than let it inherit the triggering
    user's membership.
    """
    identity, fake = resolve(
        monkeypatch,
        {"email": "ops@example.com", "groups": ["ops"]},
        user_id="svc_agent_nightly",
    )

    assert identity == {"user_email": None, "groups": ()}
    assert fake.calls == []


def test_an_unreadable_record_costs_the_token_its_identity_not_the_run(monkeypatch):
    identity, fake = resolve(monkeypatch, error=RuntimeError("etcd unavailable"))

    assert identity == {"user_email": None, "groups": ()}
    assert fake.calls == ["user-1"]


def test_dev_mode_supplies_an_email_when_the_record_has_none(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("DEV_USER_EMAIL", "local@corp.example")
    fake = FakeIdentity(None)

    identity = asyncio.run(resolve_mint_identity(fake, "user-1"))

    assert identity == {"user_email": "local@corp.example", "groups": ()}


def test_dev_mode_keeps_the_stored_email(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    fake = FakeIdentity({"email": "ops@example.com", "groups": ["ops"]})

    identity = asyncio.run(resolve_mint_identity(fake, "user-1"))

    assert identity == {"user_email": "ops@example.com", "groups": ("ops",)}


# --------------------------------------------------------------------------- #
# the mint actually carries what was resolved
# --------------------------------------------------------------------------- #


def test_a_minted_token_carries_the_resolved_groups(monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN_SECRET", "caller-identity-unit-secret-0123456789")
    monkeypatch.delenv("DEV_MODE", raising=False)
    fake = FakeIdentity({"email": "ops@example.com", "groups": ["sre", "ops"]})

    identity = asyncio.run(resolve_mint_identity(fake, "user-1"))
    token = agent_token.mint(
        "supervisor",
        user_id="user-1",
        user_email=identity["user_email"],
        groups=identity["groups"],
    )

    claims = agent_token.verify(token)
    assert claims.user_email == "ops@example.com"
    assert claims.groups == ("ops", "sre")


def test_a_service_token_carries_no_email_or_groups(monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN_SECRET", "caller-identity-unit-secret-0123456789")
    monkeypatch.delenv("DEV_MODE", raising=False)
    fake = FakeIdentity({"email": "ops@example.com", "groups": ["ops"]})

    identity = asyncio.run(resolve_mint_identity(fake, "svc_agent_nightly"))
    token = agent_token.mint(
        "nightly",
        user_id="svc_agent_nightly",
        user_email=identity["user_email"],
        groups=identity["groups"],
    )

    claims = agent_token.verify(token)
    assert claims.user_email is None
    assert claims.groups == ()


# --------------------------------------------------------------------------- #
# the refusal for a per-user-credential call with no email
# --------------------------------------------------------------------------- #


def test_identity_incomplete_names_what_is_missing_and_is_not_a_credential_error():
    result = identity_incomplete_error("MCP tool 'dc1__cli__list'", "dc1")

    assert set(result) == {"error"}
    message = result["error"]
    assert message.startswith(f"{IDENTITY_INCOMPLETE}:")
    assert "MCP tool 'dc1__cli__list'" in message
    assert "'dc1'" in message
    assert "no email" in message
    # An operator must not be sent to re-seal a key that is not the problem.
    assert "credential_rejected" not in message


# --------------------------------------------------------------------------- #
# which identities can serve a per-user credential call
# --------------------------------------------------------------------------- #


class Claims:
    """The two claim fields the decision reads."""

    def __init__(self, user_id=None, user_email=None):
        self.user_id = user_id
        self.user_email = user_email


def test_an_email_less_user_is_left_to_the_edge_without_a_blob():
    """Central cannot see the edge's ``credential_mode``, so it does not guess.

    ``per_user_required`` is refused by the edge, which knows the mode and answers with
    the same ``identity_incomplete`` code (v0.7.2 R7.1). Refusing centrally on "no
    email" alone would break a shipped caller: a webhook run mints the literal user id
    ``webhook`` and has no email by design, and the shared edge file serves it fine.
    """
    assert lacks_credential_identity(Claims("user-1")) is False
    assert lacks_credential_identity(Claims("webhook")) is False


def test_an_email_claim_makes_the_identity_complete():
    assert lacks_credential_identity(Claims("user-1", "user@example.com")) is False


def test_no_token_asserts_nothing_and_leaves_it_to_the_edge():
    assert lacks_credential_identity(None) is False


def test_a_service_identity_is_email_less_by_design():
    """A background run has no address for a blob, so a paired one is a contradiction."""
    assert lacks_credential_identity(Claims("svc_agent_nightly")) is False


def test_a_sealed_set_needs_a_subject_not_an_email():
    """A blob is sealed to the email *or the user id*, so a user id alone is enough."""
    assert lacks_credential_identity(Claims("user-1"), sealed=True) is False


def test_a_sealed_set_without_a_token_has_no_subject():
    assert lacks_credential_identity(None, sealed=True) is True
