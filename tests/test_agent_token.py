# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The short-lived HMAC agent token (v0.6 Phase 3).

Pins the wire format, every refusal code the enforcement points branch on
(``missing`` / ``malformed`` / ``bad_sig`` / ``expired`` / ``missing_secret``), the
``;``-separated rotation rule (sign with the first key, verify with any) and the
DEV_MODE-only fixed key. No etcd, no service processes: pure functions plus
``monkeypatch`` env.
"""

import dataclasses

import pytest

from core import agent_token
from core.agent_token import DEFAULT_TTL_S, AgentTokenError, Claims

SECRET = "agent-token-unit-secret-0123456789abcdef"
ISSUED = 1_700_000_000


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.delenv("DEV_MODE", raising=False)


def _mint(**overrides) -> str:
    kwargs = {
        "user_id": "user-1",
        "user_email": "user@example.test",
        "run_id": "run-1",
        "now": ISSUED,
    }
    kwargs.update(overrides)
    return agent_token.mint("agent-a", **kwargs)


def _code(token, **verify_kwargs) -> str:
    with pytest.raises(AgentTokenError) as excinfo:
        agent_token.verify(token, **verify_kwargs)
    return excinfo.value.code


def _signed(encoded: str, key: str) -> str:
    """A correctly signed token wrapped around an arbitrary payload string."""
    signing_input = f"{agent_token.TOKEN_VERSION}.{encoded}"
    return f"{signing_input}.{agent_token._sign(key, signing_input)}"


def _payload(value: bytes) -> str:
    return _signed(agent_token._b64url(value), agent_token.signing_keys()[0])


def _corrupt_signature(token: str) -> str:
    head, signature = token.rsplit(".", 1)
    index = len(signature) // 2
    flipped = "A" if signature[index] != "A" else "B"
    return f"{head}.{signature[:index]}{flipped}{signature[index + 1:]}"


# --------------------------------------------------------------------------- #
# round trip
# --------------------------------------------------------------------------- #


def test_mint_and_verify_round_trip():
    token = _mint()

    assert token.startswith("t1.")
    assert len(token.split(".")) == 3

    claims = agent_token.verify(token, now=ISSUED)
    assert isinstance(claims, Claims)
    assert claims.agent == "agent-a"
    assert claims.user_id == "user-1"
    assert claims.user_email == "user@example.test"
    assert claims.run_id == "run-1"
    assert claims.iat == ISSUED
    assert claims.exp == ISSUED + DEFAULT_TTL_S
    assert len(claims.jti) == 32


def test_claims_are_frozen_and_carry_a_unique_jti():
    first = agent_token.verify(_mint(), now=ISSUED)
    second = agent_token.verify(_mint(), now=ISSUED)

    # Same run, same agent, different token instance.
    assert first.run_id == second.run_id
    assert first.jti != second.jti
    with pytest.raises(dataclasses.FrozenInstanceError):
        first.agent = "agent-b"


def test_claims_identity_and_expiry_helpers():
    claims = agent_token.verify(_mint(user_id="svc_agent_reporter"), now=ISSUED)

    assert claims.identity() == "svc_agent_reporter"
    assert claims.expired(now=claims.exp + 10) is False
    assert claims.expired(now=claims.exp + 60) is True


def test_missing_user_id_reads_as_anonymous():
    claims = agent_token.verify(_mint(user_id=None, user_email=None), now=ISSUED)

    assert claims.user_id is None
    assert claims.user_email is None
    assert claims.identity() == "anonymous"


def test_ttl_is_clamped_to_at_least_one_second():
    claims = agent_token.verify(_mint(ttl_s=0), now=ISSUED)

    assert claims.exp == ISSUED + 1


# --------------------------------------------------------------------------- #
# refusals
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("token", [None, ""])
def test_missing_token_is_refused(token):
    assert _code(token) == "missing"


@pytest.mark.parametrize(
    "token",
    [
        "nope",  # no separators at all
        "t2.abc.def",  # wrong version prefix
        "t1.abc",  # missing the signature
        "t1.a.b.c",  # too many segments
    ],
)
def test_structurally_broken_tokens_are_malformed(token):
    assert _code(token) == "malformed"


def test_unparseable_or_incomplete_payloads_are_malformed():
    # Valid signature over a payload that is not base64url / not JSON / not an object.
    assert _code(_signed("*", agent_token.signing_keys()[0])) == "malformed"
    assert _code(_payload(b"not json")) == "malformed"
    assert _code(_payload(b'["not-an-object"]')) == "malformed"
    # Correct shape, missing the required claims.
    assert _code(_payload(b'{"v": 1}')) == "malformed"
    # Correct claims, unsupported schema version.
    assert _code(_payload(b'{"v": 2, "a": "x", "i": 1, "x": 2, "r": "r", "j": "j"}')) == "malformed"


def test_bad_signature_is_refused():
    assert _code(_corrupt_signature(_mint()), now=ISSUED) == "bad_sig"


def test_token_signed_with_an_unconfigured_key_is_refused(monkeypatch):
    token = _mint()

    monkeypatch.setenv("AGENT_TOKEN_SECRET", "some-other-secret-entirely")

    assert _code(token, now=ISSUED) == "bad_sig"


def test_expired_token_is_refused():
    # CLOCK_SKEW_S is 30 s, so "expired" starts strictly after exp + 30.
    token = _mint(ttl_s=1)

    assert _code(token, now=ISSUED + 40) == "expired"


def test_future_issued_token_is_refused():
    token = _mint(now=ISSUED + 120)

    assert _code(token, now=ISSUED) == "malformed"


def test_clock_skew_is_tolerated_then_enforced():
    claims = agent_token.verify(_mint(), now=ISSUED)

    assert agent_token.verify(_mint(), now=claims.exp + 10).agent == "agent-a"
    assert _code(_mint(), now=claims.exp + 60) == "expired"


# --------------------------------------------------------------------------- #
# key rotation
# --------------------------------------------------------------------------- #


def test_rotation_signs_with_the_first_key_and_verifies_with_any(monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN_SECRET", "k1;k2")
    assert agent_token.signing_keys() == ["k1", "k2"]
    token = _mint()

    # The new key moved to the front: a token minted by the old signer still verifies.
    monkeypatch.setenv("AGENT_TOKEN_SECRET", "k2;k1")
    assert agent_token.verify(token, now=ISSUED).agent == "agent-a"

    # Once the old key is dropped, the token is no longer accepted.
    monkeypatch.setenv("AGENT_TOKEN_SECRET", "k2")
    assert _code(token, now=ISSUED) == "bad_sig"


def test_key_list_ignores_whitespace_and_empty_entries(monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN_SECRET", " k1 ; ; k2 ")

    assert agent_token.signing_keys() == ["k1", "k2"]


# --------------------------------------------------------------------------- #
# secret configuration / DEV_MODE
# --------------------------------------------------------------------------- #


def test_no_secret_refuses_mint_and_verify(monkeypatch):
    token = _mint()

    monkeypatch.delenv("AGENT_TOKEN_SECRET")

    with pytest.raises(AgentTokenError) as excinfo:
        agent_token.mint("agent-a")
    assert excinfo.value.code == "missing_secret"
    assert _code(token, now=ISSUED) == "missing_secret"


def test_dev_mode_uses_the_fixed_development_key(monkeypatch):
    monkeypatch.delenv("AGENT_TOKEN_SECRET")
    monkeypatch.setenv("DEV_MODE", "true")

    # The constant, not a random per-process value: that is what lets two local
    # processes (host + hub + runner) verify each other's tokens.
    assert agent_token.signing_keys() == [agent_token._DEV_SECRET]

    first = agent_token.mint("agent-a", user_id="user-1")
    second = agent_token.mint("agent-b", user_id="svc_agent_b")

    assert agent_token.verify(first).agent == "agent-a"
    assert agent_token.verify(second).agent == "agent-b"


def test_require_secret_passes_with_a_key():
    agent_token.require_secret("hub")


def test_require_secret_exits_when_enforcing_without_a_key(monkeypatch):
    monkeypatch.delenv("AGENT_TOKEN_SECRET")
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")

    with pytest.raises(SystemExit):
        agent_token.require_secret("hub")


def test_require_secret_only_warns_in_rollout_mode(monkeypatch, caplog):
    monkeypatch.delenv("AGENT_TOKEN_SECRET")
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")

    agent_token.require_secret("hub")

    assert any("AGENT_TOKEN_SECRET" in r.getMessage() for r in caplog.records)


def test_require_secret_allows_dev_mode(monkeypatch):
    monkeypatch.delenv("AGENT_TOKEN_SECRET")
    monkeypatch.setenv("DEV_MODE", "true")

    agent_token.require_secret("hub")


# --------------------------------------------------------------------------- #
# minting entry points / mode
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("agent", ["", "   ", None])
def test_mint_rejects_an_empty_agent(agent):
    with pytest.raises(AgentTokenError) as excinfo:
        agent_token.mint(agent)

    assert excinfo.value.code == "invalid_agent"


def test_mint_for_run_publishes_the_token_and_run_id():
    from core.auth import agent_token_var, run_id_var

    try:
        token = agent_token.mint_for_run(
            "agent-a", "user-1", user_email="user@example.test", run_id="run-42"
        )

        assert agent_token_var.get() == token
        assert run_id_var.get() == "run-42"
        assert agent_token.current_token() == token
        assert agent_token.verify(token).run_id == "run-42"
    finally:
        agent_token_var.set(None)
        run_id_var.set(None)


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, "log"),  # unset
        ("off", "off"),
        ("log", "log"),
        ("enforce", "enforce"),
        (" ENFORCE ", "enforce"),
        ("", "log"),
        ("garbage", "log"),
    ],
)
def test_mode_parses_the_rollout_knob(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("ENFORCE_AGENT_TOKENS", raising=False)
    else:
        monkeypatch.setenv("ENFORCE_AGENT_TOKENS", value)

    assert agent_token.mode() == expected
