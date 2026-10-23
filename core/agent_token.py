# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Short-lived HMAC tokens that prove *which agent* is calling, and for whom.

The token is minted by the agent runtime (host, taskiq worker, gateway) once per
run and carried on every hub / relay / runner call. Enforcement points verify it
and resolve the agent's effective allowlist themselves: the caller does not get
to assert its own permissions.

Format::

    t1.<b64url(payload)>.<b64url(hmac_sha256(key, "t1." + payload))>

``AGENT_TOKEN_SECRET`` is a ``;``-separated key list: the first key signs, every
key verifies, so a rotation can deploy before the old value is removed. A token
is short-lived (900 s by default) and there is no revocation list -- documented.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

TOKEN_VERSION = "t1"
DEFAULT_TTL_S = 900
CLOCK_SKEW_S = 30
# DEV_MODE only. All services derive the same value so local multi-process runs
# can verify each other's tokens; never acceptable outside development.
_DEV_SECRET = "trellis-dev-insecure-agent-token-secret"
_WARNED_DEV = False


class AgentTokenError(Exception):
    """A refused token; ``code`` is stable for callers/tests."""

    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(f"agent token {code}: {self.message}")


@dataclass(frozen=True)
class Claims:
    agent: str
    user_id: Optional[str]
    user_email: Optional[str]
    run_id: str
    iat: int
    exp: int
    jti: str
    # "system" for the framework's own entry points (gateway, supervisor). A
    # user-created agent cannot obtain this: only the runtime mints tokens.
    principal: Optional[str] = None

    def identity(self) -> str:
        """The identity the agent acts for: `svc_agent_<agent>` for background runs."""
        return self.user_id or "anonymous"

    def expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) > self.exp + CLOCK_SKEW_S


def _dev_mode() -> bool:
    return os.getenv("DEV_MODE", "false").lower() == "true"


def signing_keys() -> list[str]:
    """Signing/verification keys, newest first."""
    raw = os.getenv("AGENT_TOKEN_SECRET", "")
    keys = [part.strip() for part in raw.split(";") if part.strip()]
    if keys:
        return keys
    if _dev_mode():
        if mode() == "enforce":
            raise AgentTokenError(
                "missing_secret",
                "AGENT_TOKEN_SECRET is required when ENFORCE_AGENT_TOKENS=enforce "
                "(the DEV_MODE fallback key is public)",
            )
        global _WARNED_DEV
        if not _WARNED_DEV:
            _WARNED_DEV = True
            logger.warning(
                "AGENT_TOKEN_SECRET is unset in DEV_MODE; using a well-known insecure "
                "development key. Never deploy this."
            )
        return [_DEV_SECRET]
    raise AgentTokenError(
        "missing_secret",
        "AGENT_TOKEN_SECRET is not set; refusing to mint or verify agent tokens",
    )


def require_secret(service: str) -> None:
    """Startup gate: an *enforcing* deployment refuses to start without a key.

    In `log`/`off` mode a missing key is only a warning: that is the rollout and
    local-dev posture, and exiting would make the framework unusable before the
    operator has generated the secret.
    """
    try:
        signing_keys()
    except AgentTokenError as exc:
        if mode() == "enforce":
            raise SystemExit(
                f"{service}: {exc.message}. Set AGENT_TOKEN_SECRET (>=32 bytes, "
                "semicolon-separated for rotation) on host/hub/gateway/relay/taskiq/runner."
            ) from None
        logger.warning(
            "%s: AGENT_TOKEN_SECRET is not set and ENFORCE_AGENT_TOKENS=%s; agent "
            "tokens are not verified.",
            service,
            mode(),
        )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(key: str, signing_input: str) -> str:
    digest = hmac.new(
        key.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    return _b64url(digest)


def mint(
    agent: str,
    *,
    user_id: Optional[str] = None,
    user_email: Optional[str] = None,
    run_id: Optional[str] = None,
    ttl_s: Optional[int] = None,
    now: Optional[float] = None,
    principal: Optional[str] = None,
) -> str:
    """Mint one token; the first key signs."""
    if not agent or not str(agent).strip():
        raise AgentTokenError("invalid_agent", "agent name is required")
    issued = int(now if now is not None else time.time())
    ttl = DEFAULT_TTL_S if ttl_s is None else max(1, int(ttl_s))
    payload = {
        "v": 1,
        "a": str(agent),
        "u": user_id,
        "e": user_email,
        "r": run_id or uuid.uuid4().hex,
        "i": issued,
        "x": issued + ttl,
        "j": uuid.uuid4().hex,
    }
    if principal:
        payload["k"] = str(principal)
    encoded = _b64url(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{TOKEN_VERSION}.{encoded}"
    return f"{signing_input}.{_sign(signing_keys()[0], signing_input)}"


def _decode_payload(encoded: str) -> dict:
    try:
        value = json.loads(_b64url_decode(encoded))
    except (ValueError, json.JSONDecodeError) as exc:
        raise AgentTokenError("malformed", "payload is not valid base64url JSON") from exc
    if not isinstance(value, dict):
        raise AgentTokenError("malformed", "payload is not an object")
    return value


def verify(token: Optional[str], *, now: Optional[float] = None) -> Claims:
    """Verify signature, expiry and shape; raise ``AgentTokenError`` on refusal."""
    if not token:
        raise AgentTokenError("missing", "no agent token supplied")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_VERSION:
        raise AgentTokenError("malformed", "token is not t1.<payload>.<sig>")
    _, encoded, signature = parts
    try:
        keys = signing_keys()
    except AgentTokenError as exc:
        raise AgentTokenError("missing_secret", exc.message) from exc
    if not any(
        hmac.compare_digest(_sign(key, f"{TOKEN_VERSION}.{encoded}"), signature)
        for key in keys
    ):
        raise AgentTokenError("bad_sig", "signature does not match any configured key")

    payload = _decode_payload(encoded)
    if payload.get("v") != 1:
        raise AgentTokenError("malformed", f"unsupported token version {payload.get('v')!r}")
    try:
        agent = str(payload["a"])
        issued = int(payload["i"])
        expires = int(payload["x"])
        run_id = str(payload["r"])
        jti = str(payload["j"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AgentTokenError("malformed", "token is missing required claims") from exc

    reference = now if now is not None else time.time()
    if reference > expires + CLOCK_SKEW_S:
        raise AgentTokenError("expired", f"token expired at {expires}")
    if issued > reference + CLOCK_SKEW_S:
        raise AgentTokenError("malformed", "token was issued in the future")

    return Claims(
        agent=agent,
        user_id=payload.get("u"),
        user_email=payload.get("e"),
        run_id=run_id,
        iat=issued,
        exp=expires,
        jti=jti,
        principal=payload.get("k"),
    )


def verify_or_none(token: Optional[str]) -> Optional[Claims]:
    """Verification that returns ``None`` instead of raising (log-only mode)."""
    try:
        return verify(token)
    except AgentTokenError:
        return None


def mint_for_run(
    agent: str,
    user_id: Optional[str],
    *,
    user_email: Optional[str] = None,
    run_id: Optional[str] = None,
    ttl_s: Optional[int] = None,
    principal: Optional[str] = None,
) -> str:
    """Mint a token and publish it (plus the run id) to the current context."""
    try:
        token = mint(
            agent,
            user_id=user_id,
            user_email=user_email,
            run_id=run_id,
            ttl_s=ttl_s,
            principal=principal,
        )
    except AgentTokenError as exc:
        # Rollout (off/log) without a key must not break calls; enforce does.
        if exc.code == "missing_secret" and mode() != "enforce":
            logger.debug("No AGENT_TOKEN_SECRET; minting is disabled")
            return ""
        raise
    if not token:
        return ""
    try:
        from core.auth import agent_token_var, run_id_var

        agent_token_var.set(token)
        if run_id:
            run_id_var.set(run_id)
    except Exception:  # the edge has no auth module; minting must still work
        logger.debug("agent token contextvars unavailable", exc_info=True)
    return token


def current_token() -> Optional[str]:
    try:
        from core.auth import agent_token_var

        return agent_token_var.get()
    except Exception:
        return None


def refresh(token: Optional[str], *, min_validity_s: int = 60) -> Optional[str]:
    """Re-mint a token that is about to expire, keeping its identity.

    A run can outlive the 900 s default (background agents have no run timeout), so
    every boundary re-checks the token instead of failing mid-run. Returns the
    original token when it is still comfortably valid.
    """
    if not token:
        return token
    try:
        claims = verify(token)
    except AgentTokenError:
        return token
    if claims.exp - time.time() > min_validity_s:
        return token
    try:
        fresh = mint(
            claims.agent,
            user_id=claims.user_id,
            user_email=claims.user_email,
            run_id=claims.run_id,
            principal=claims.principal,
        )
    except AgentTokenError:
        return token
    try:
        from core.auth import agent_token_var

        agent_token_var.set(fresh)
    except Exception:
        logger.debug("agent token contextvars unavailable", exc_info=True)
    return fresh


def mode() -> str:
    """``off`` | ``log`` | ``enforce`` (compose ships ``enforce``)."""
    value = (os.getenv("ENFORCE_AGENT_TOKENS") or "log").strip().lower()
    return value if value in {"off", "log", "enforce"} else "log"


def deny_message(agent: str, target: str) -> str:
    return f"access_denied: tool '{target}' is not in agent '{agent}' allowlist"
