# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""End-to-end MCP OAuth 2.1 flow tests for core/routers/mcp_oauth.py.

Builds a FastAPI app with SessionMiddleware plus the real router, and swaps
the router's ``identity_mgr`` module attribute for an in-memory fake that
mirrors the IdentityManager oauth surface (dynamic client registration with
SHA-256-only secret storage, one-time authorization codes, JWT secret, and
the jti revocation denylist). Covers RFC 7591 registration, RFC 8414/9728
discovery, the authorize/consent endpoint (session + CSRF + PKCE S256), the
token endpoint, and RFC 7009 revocation. No etcd or network I/O.

Accommodations forced by the actual implementation (asserted as-is):

  - The token endpoint consumes the authorization code BEFORE verifying
    PKCE (get_and_delete_oauth_code runs first), so a wrong-verifier attempt
    burns the code: a retry with the correct verifier is rejected as
    invalid_grant.
  - Client authentication failures (unknown client / wrong secret) return
    401, and are checked before the code is consumed.
"""
import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from core.routers import mcp_oauth

REDIRECT_URI = "http://localhost:43121/callback"
SESSION_SECRET = "test-session-secret"
JWT_SECRET = b"test-oauth-jwt-signing-secret-0123456789abcdef"
SESSION_USER_SUB = "oauth-user"
SESSION_CSRF = "test-csrf-token"


class FakeOAuthStore:
    """In-memory stand-in for the IdentityManager methods the router uses.

    Persists clients/codes/revocations in dicts, faithfully copying the real
    storage semantics (notably: save_oauth_client keeps only the SHA-256 of
    the client_secret, and get_and_delete_oauth_code is destructive).
    """

    def __init__(self):
        self.clients = {}
        self.codes = {}
        self.revoked = {}

    def save_oauth_client(self, client_id, client_secret, metadata):
        record = {
            "client_id": client_id,
            "client_secret_hash": hashlib.sha256(client_secret.encode()).hexdigest(),
            **metadata,
        }
        self.clients[client_id] = record

    def get_oauth_client(self, client_id):
        return self.clients.get(client_id)

    def save_oauth_code(self, code, data, ttl=300):
        self.codes[code] = dict(data)

    def get_and_delete_oauth_code(self, code):
        return self.codes.pop(code, None)

    def get_or_create_jwt_secret(self):
        return JWT_SECRET

    def save_revoked_token(self, jti, exp):
        self.revoked[jti] = exp

    def is_token_revoked(self, jti):
        return jti in self.revoked


def _make_client(monkeypatch, logged_in=True):
    fake = FakeOAuthStore()
    monkeypatch.setattr(mcp_oauth, "identity_mgr", fake)

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
    app.include_router(mcp_oauth.router)

    @app.get("/__test/login")
    async def test_login(request: Request):
        # Test-only session bootstrap: stands in for the real /login flow.
        request.session["user"] = {
            "sub": SESSION_USER_SUB,
            "name": "OAuth Tester",
            "email": "tester@example.test",
        }
        request.session["csrf_token"] = SESSION_CSRF
        return {"ok": True}

    client = TestClient(app, follow_redirects=False)
    if logged_in:
        assert client.get("/__test/login").status_code == 200
    return client, fake


def _s256(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _register(client):
    resp = client.post(
        "/oauth/register",
        json={
            "redirect_uris": [REDIRECT_URI],
            "client_name": "MCP Test CLI",
            "scope": "mcp:tools",
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _approve(client, reg, verifier, action="approve", state="st-abc-123"):
    return client.post(
        "/oauth/authorize",
        data={
            "client_id": reg["client_id"],
            "redirect_uri": REDIRECT_URI,
            "state": state,
            "code_challenge": _s256(verifier),
            "code_challenge_method": "S256",
            "action": action,
            "csrf_token": SESSION_CSRF,
        },
    )


def _issued_code(resp):
    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    assert location.startswith(REDIRECT_URI)
    query = parse_qs(urlparse(location).query)
    return query["code"][0]


def _exchange(client, reg, code, verifier, redirect_uri=REDIRECT_URI, client_secret=None):
    return client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": reg["client_id"],
            "client_secret": (
                reg["client_secret"] if client_secret is None else client_secret
            ),
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )


def _get_access_token(client):
    """Run register -> approve -> exchange; return (reg, access_token)."""
    reg = _register(client)
    verifier = "a-sufficiently-long-test-pkce-verifier-string"
    code = _issued_code(_approve(client, reg, verifier))
    resp = _exchange(client, reg, code, verifier)
    assert resp.status_code == 200, resp.text
    return reg, resp.json()["access_token"]


# --- RFC 7591 dynamic client registration -------------------------------------


def test_register_returns_credentials_once_and_persists_only_the_hash(monkeypatch):
    client, fake = _make_client(monkeypatch)
    body = _register(client)

    assert body["client_id"].startswith("mcp_")
    assert body["client_secret"]
    assert body["redirect_uris"] == [REDIRECT_URI]
    assert body["client_name"] == "MCP Test CLI"
    assert body["client_secret_expires_at"] == 0

    record = fake.clients[body["client_id"]]
    assert "client_secret" not in record
    assert record["client_secret_hash"] == hashlib.sha256(
        body["client_secret"].encode()
    ).hexdigest()
    assert record["redirect_uris"] == [REDIRECT_URI]


# --- Discovery documents --------------------------------------------------------


def test_openid_configuration_document(monkeypatch):
    client, _ = _make_client(monkeypatch, logged_in=False)

    resp = client.get("/.well-known/openid-configuration")

    assert resp.status_code == 200
    doc = resp.json()
    # _base_url() defaults to https + the Host header ("testserver").
    base = "https://testserver"
    assert doc["issuer"] == base
    assert doc["authorization_endpoint"] == f"{base}/oauth/authorize"
    assert doc["token_endpoint"] == f"{base}/oauth/token"
    assert doc["registration_endpoint"] == f"{base}/oauth/register"
    assert doc["revocation_endpoint"] == f"{base}/oauth/revoke"
    assert doc["response_types_supported"] == ["code"]
    assert doc["grant_types_supported"] == ["authorization_code"]
    assert doc["code_challenge_methods_supported"] == ["S256"]


def test_protected_resource_metadata_document(monkeypatch):
    client, _ = _make_client(monkeypatch, logged_in=False)

    resp = client.get("/.well-known/oauth-protected-resource")

    assert resp.status_code == 200
    doc = resp.json()
    assert doc["resource"] == "https://testserver/mcp"
    assert doc["authorization_servers"] == ["https://testserver"]
    assert doc["bearer_methods_supported"] == ["header"]


# --- Authorization endpoint ------------------------------------------------------


def test_authorize_without_session_redirects_to_login(monkeypatch):
    client, _ = _make_client(monkeypatch, logged_in=False)
    reg = _register(client)

    resp = client.get(
        "/oauth/authorize",
        params={"client_id": reg["client_id"], "redirect_uri": REDIRECT_URI},
    )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_authorize_unknown_client_rejected(monkeypatch):
    client, _ = _make_client(monkeypatch)

    resp = client.get(
        "/oauth/authorize",
        params={"client_id": "mcp_unknown", "redirect_uri": REDIRECT_URI},
    )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client"


def test_authorize_unregistered_redirect_uri_rejected_without_redirect(monkeypatch):
    # RFC 6749 §4.1.2.1 — a mismatching redirect_uri must NOT redirect.
    client, _ = _make_client(monkeypatch)
    reg = _register(client)

    resp = client.get(
        "/oauth/authorize",
        params={
            "client_id": reg["client_id"],
            "redirect_uri": "http://evil.example/cb",
        },
    )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"
    assert "location" not in resp.headers


def test_authorize_renders_consent_screen(monkeypatch):
    client, _ = _make_client(monkeypatch)
    reg = _register(client)
    verifier = "consent-screen-verifier"

    resp = client.get(
        "/oauth/authorize",
        params={
            "client_id": reg["client_id"],
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "code_challenge": _s256(verifier),
            "code_challenge_method": "S256",
            "state": "st-1",
        },
    )

    assert resp.status_code == 200
    assert "MCP Test CLI" in resp.text
    assert reg["client_id"] in resp.text
    assert REDIRECT_URI in resp.text


def test_authorize_approve_requires_matching_csrf_token(monkeypatch):
    client, fake = _make_client(monkeypatch)
    reg = _register(client)
    verifier = "csrf-check-verifier"

    for bad_csrf in (None, "wrong-csrf"):
        data = {
            "client_id": reg["client_id"],
            "redirect_uri": REDIRECT_URI,
            "state": "st-x",
            "code_challenge": _s256(verifier),
            "code_challenge_method": "S256",
            "action": "approve",
        }
        if bad_csrf is not None:
            data["csrf_token"] = bad_csrf
        resp = client.post("/oauth/authorize", data=data)

        assert resp.status_code == 400
        body = resp.json()
        assert body["error"] == "invalid_request"
        assert "CSRF" in body["error_description"]

    assert fake.codes == {}


def test_authorize_approve_redirects_with_code_and_state(monkeypatch):
    client, fake = _make_client(monkeypatch)
    reg = _register(client)
    verifier = "approve-flow-verifier-with-entropy"

    resp = _approve(client, reg, verifier, state="st-approve-1")

    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(REDIRECT_URI)
    query = parse_qs(urlparse(location).query)
    assert query["state"] == ["st-approve-1"]

    code = query["code"][0]
    stored = fake.codes[code]
    assert stored["client_id"] == reg["client_id"]
    assert stored["user_id"] == SESSION_USER_SUB
    assert stored["redirect_uri"] == REDIRECT_URI
    assert stored["code_challenge"] == _s256(verifier)
    assert stored["code_challenge_method"] == "S256"


def test_authorize_deny_redirects_with_access_denied(monkeypatch):
    client, fake = _make_client(monkeypatch)
    reg = _register(client)

    resp = _approve(client, reg, "deny-flow-verifier", action="deny")

    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["error"] == ["access_denied"]
    assert "code" not in query
    assert fake.codes == {}


# --- Token endpoint --------------------------------------------------------------


def test_token_exchange_with_s256_pkce_returns_jwt(monkeypatch):
    client, fake = _make_client(monkeypatch)
    reg = _register(client)
    verifier = "token-flow-verifier-0123456789abcdef"
    code = _issued_code(_approve(client, reg, verifier))

    resp = _exchange(client, reg, code, verifier)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 3600

    payload = pyjwt.decode(
        body["access_token"], JWT_SECRET, algorithms=["HS256"], audience="mcp:tools"
    )
    assert payload["sub"] == SESSION_USER_SUB
    assert payload["jti"]
    assert payload["exp"] - payload["iat"] == 3600

    # RFC 6749 §5.1 — token responses must not be cached; code is single-use.
    assert resp.headers["cache-control"] == "no-store"
    assert code not in fake.codes


def test_token_wrong_pkce_verifier_rejected_and_code_burned(monkeypatch):
    client, fake = _make_client(monkeypatch)
    reg = _register(client)
    verifier = "correct-verifier-for-burn-test"
    code = _issued_code(_approve(client, reg, verifier))

    resp = _exchange(client, reg, code, "wrong-verifier-entirely")

    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_grant"
    assert body["error_description"] == "PKCE verification failed"
    assert code not in fake.codes  # consumed by the failed attempt

    # The code was single-use: even the correct verifier cannot replay it.
    retry = _exchange(client, reg, code, verifier)
    assert retry.status_code == 400
    assert retry.json()["error"] == "invalid_grant"


def test_token_redirect_uri_mismatch_rejected(monkeypatch):
    client, _ = _make_client(monkeypatch)
    reg = _register(client)
    verifier = "redirect-mismatch-verifier"
    code = _issued_code(_approve(client, reg, verifier))

    resp = _exchange(
        client, reg, code, verifier, redirect_uri="http://localhost:43121/other"
    )

    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_grant"
    assert body["error_description"] == "redirect_uri mismatch"


def test_token_wrong_client_secret_401_and_code_spared(monkeypatch):
    client, fake = _make_client(monkeypatch)
    reg = _register(client)
    verifier = "wrong-secret-verifier"
    code = _issued_code(_approve(client, reg, verifier))

    resp = _exchange(client, reg, code, verifier, client_secret="wrong-secret")

    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"
    # Client auth runs before the code is fetched, so the code survives.
    assert code in fake.codes


def test_token_unknown_code_rejected(monkeypatch):
    client, _ = _make_client(monkeypatch)
    reg = _register(client)

    resp = _exchange(client, reg, "no-such-code", "some-verifier")

    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_grant"
    assert "not found or expired" in body["error_description"]


def test_token_unsupported_grant_type(monkeypatch):
    client, _ = _make_client(monkeypatch)

    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "mcp_x",
            "client_secret": "secret",
        },
    )

    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"


# --- Revocation endpoint (RFC 7009) ----------------------------------------------


def test_revoke_adds_token_jti_to_denylist(monkeypatch):
    client, fake = _make_client(monkeypatch)
    reg, access_token = _get_access_token(client)
    payload = pyjwt.decode(
        access_token, JWT_SECRET, algorithms=["HS256"], audience="mcp:tools"
    )

    resp = client.post(
        "/oauth/revoke",
        data={
            "token": access_token,
            "client_id": reg["client_id"],
            "client_secret": reg["client_secret"],
        },
    )

    assert resp.status_code == 200
    assert resp.json() == {}
    assert payload["jti"] in fake.revoked


def test_revoke_unknown_token_still_returns_200(monkeypatch):
    # RFC 7009 §2.2 — never reveal whether the token was valid.
    client, _ = _make_client(monkeypatch)
    reg = _register(client)

    resp = client.post(
        "/oauth/revoke",
        data={
            "token": "not-a-jwt-at-all",
            "client_id": reg["client_id"],
            "client_secret": reg["client_secret"],
        },
    )

    assert resp.status_code == 200
    assert resp.json() == {}


def test_revoke_wrong_client_secret_401(monkeypatch):
    client, _ = _make_client(monkeypatch)
    reg, access_token = _get_access_token(client)

    resp = client.post(
        "/oauth/revoke",
        data={
            "token": access_token,
            "client_id": reg["client_id"],
            "client_secret": "wrong-secret",
        },
    )

    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"
