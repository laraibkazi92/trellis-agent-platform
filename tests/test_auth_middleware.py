# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Raw-ASGI tests for AuthMiddleware (core/auth.py).

The middleware is driven directly with hand-built scope dicts against a fake
inner ASGI app and a fake IdentityManager -- no Starlette app, no etcd, no
network. Covers:

  - path triage: unprotected paths pass through untouched; the protected
    prefixes (/v1/, /sse, /messages, /mcp) demand a Bearer token.
  - the RFC 9728 WWW-Authenticate challenge emitted on 401s
    (Bearer realm="mcp" + resource_metadata URL built from forwarded headers).
  - token-shape triage: "exec_..." -> validate_execution_token, two-dot JWT ->
    _validate_jwt, anything else -> validate_key; the resolved user lands in
    the auth contextvars and scope["state"]["user_id"].
  - ban enforcement (403) and the DEV_MODE bypass (no header -> dev-user-id,
    but a presented Bearer token is still validated).
"""
import asyncio
import json

import pytest

from core.auth import AuthMiddleware, auth_token_var, user_id_var


class FakeInnerApp:
    """Records each request's scope plus the auth contextvars, replies 200."""

    def __init__(self):
        self.requests = []

    async def __call__(self, scope, receive, send):
        self.requests.append(
            {
                "scope": scope,
                "user_id": user_id_var.get(),
                "auth_token": auth_token_var.get(),
            }
        )
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"inner-app-ok"})


class FakeIdentityManager:
    """IdentityManager stand-in for the surface AuthMiddleware touches."""

    def __init__(self, key_user=None, exec_user=None, user_profile=None, key_error=None):
        self.calls = []
        self.key_user = key_user
        self.exec_user = exec_user
        self.user_profile = user_profile
        self.key_error = key_error

    def validate_key(self, api_key):
        self.calls.append(("validate_key", api_key))
        if self.key_error is not None:
            raise self.key_error
        return self.key_user

    def validate_execution_token(self, token):
        self.calls.append(("validate_execution_token", token))
        return self.exec_user

    def get_user(self, user_id):
        self.calls.append(("get_user", user_id))
        return self.user_profile

    def get_or_create_jwt_secret(self):
        return b"test-jwt-secret"

    def is_token_revoked(self, jti):
        return False

    def called(self, method):
        return [arg for name, arg in self.calls if name == method]


def _scope(path, headers=None):
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or [])],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }


def _make_middleware(monkeypatch, inner, identity_mgr, dev_mode=False):
    # dev_mode is latched in __init__, so the env must be set before construction.
    if dev_mode:
        monkeypatch.setenv("DEV_MODE", "true")
    else:
        monkeypatch.delenv("DEV_MODE", raising=False)
    return AuthMiddleware(app=inner, identity_mgr=identity_mgr)


def _run(middleware, scope):
    """Drive one request through the middleware; return the sent ASGI messages."""

    async def scenario():
        sent = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        await middleware(scope, receive, send)
        return sent

    return asyncio.run(scenario())


def _response(messages):
    start = messages[0]
    headers = {k.decode(): v.decode() for k, v in start.get("headers", [])}
    body = b"".join(m.get("body", b"") for m in messages[1:])
    return start["status"], headers, body


def _bearer(token):
    return [("Authorization", f"Bearer {token}")]


# --- Path triage --------------------------------------------------------------


def test_unprotected_paths_pass_through_without_auth(monkeypatch):
    for path in ("/", "/login", "/docs", "/agents"):
        inner = FakeInnerApp()
        middleware = _make_middleware(
            monkeypatch, inner, FakeIdentityManager(key_user="u1")
        )

        messages = _run(middleware, _scope(path))

        status, _, body = _response(messages)
        assert status == 200
        assert body == b"inner-app-ok"
        assert len(inner.requests) == 1
        assert inner.requests[0]["scope"]["path"] == path


def test_protected_prefixes_require_bearer_token(monkeypatch):
    for path in ("/v1/agents", "/mcp", "/sse", "/messages"):
        inner = FakeInnerApp()
        middleware = _make_middleware(monkeypatch, inner, FakeIdentityManager())

        messages = _run(middleware, _scope(path))

        status, headers, body = _response(messages)
        assert status == 401, path
        assert json.loads(body) == {"error": "Missing or invalid Authorization header"}
        assert "www-authenticate" in headers
        assert inner.requests == []


# --- 401 challenge shape (RFC 9728) -------------------------------------------


def test_missing_auth_header_www_authenticate_uses_forwarded_headers(monkeypatch):
    inner = FakeInnerApp()
    middleware = _make_middleware(monkeypatch, inner, FakeIdentityManager())

    scope = _scope(
        "/v1/chat",
        headers=[("host", "trellis.example"), ("x-forwarded-proto", "https")],
    )
    status, headers, body = _response(_run(middleware, scope))

    assert status == 401
    challenge = headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'realm="mcp"' in challenge
    assert (
        'resource_metadata="https://trellis.example/.well-known/oauth-protected-resource"'
        in challenge
    )


def test_missing_auth_header_www_authenticate_defaults(monkeypatch):
    middleware = _make_middleware(
        monkeypatch, FakeInnerApp(), FakeIdentityManager()
    )

    status, headers, _ = _response(_run(middleware, _scope("/mcp")))

    assert status == 401
    # No forwarded headers -> proto defaults to https, host to localhost.
    assert (
        'resource_metadata="https://localhost/.well-known/oauth-protected-resource"'
        in headers["www-authenticate"]
    )


def test_non_bearer_scheme_rejected(monkeypatch):
    inner = FakeInnerApp()
    middleware = _make_middleware(monkeypatch, inner, FakeIdentityManager())

    scope = _scope("/v1/keys", headers=[("Authorization", "Basic dXNlcjpwYXNz")])
    status, headers, body = _response(_run(middleware, scope))

    assert status == 401
    assert json.loads(body) == {"error": "Missing or invalid Authorization header"}
    assert "www-authenticate" in headers
    assert inner.requests == []


# --- Invalid tokens ------------------------------------------------------------


def test_bearer_unknown_api_key_rejected(monkeypatch):
    inner = FakeInnerApp()
    fake = FakeIdentityManager(key_user=None)  # validate_key -> unknown token
    middleware = _make_middleware(monkeypatch, inner, fake)

    status, headers, body = _response(
        _run(middleware, _scope("/v1/agents", headers=_bearer("tl_unknown")))
    )

    assert status == 401
    assert json.loads(body) == {"error": "Invalid or expired token"}
    assert 'realm="mcp"' in headers["www-authenticate"]
    assert fake.called("validate_key") == ["tl_unknown"]
    assert inner.requests == []


def test_bearer_validator_exception_treated_as_invalid(monkeypatch):
    inner = FakeInnerApp()
    fake = FakeIdentityManager(key_error=RuntimeError("etcd unreachable"))
    middleware = _make_middleware(monkeypatch, inner, fake)

    status, _, body = _response(
        _run(middleware, _scope("/v1/agents", headers=_bearer("tl_boom")))
    )

    assert status == 401
    assert json.loads(body) == {"error": "Invalid or expired token"}
    assert inner.requests == []


# --- Token triage --------------------------------------------------------------


def test_exec_token_routes_to_execution_token_validator(monkeypatch):
    inner = FakeInnerApp()
    fake = FakeIdentityManager(exec_user="wf-user", user_profile={"sub": "wf-user"})
    middleware = _make_middleware(monkeypatch, inner, fake)

    messages = _run(middleware, _scope("/v1/run/x", headers=_bearer("exec_signedbody")))

    assert _response(messages)[0] == 200
    assert fake.called("validate_execution_token") == ["exec_signedbody"]
    assert fake.called("validate_key") == []
    assert fake.called("get_user") == ["wf-user"]

    request = inner.requests[0]
    assert request["user_id"] == "wf-user"
    assert request["auth_token"] == "exec_signedbody"
    assert request["scope"]["state"]["user_id"] == "wf-user"


def test_jwt_shaped_token_routes_to_jwt_validator(monkeypatch):
    inner = FakeInnerApp()
    fake = FakeIdentityManager(user_profile={"sub": "jwt-user"})
    middleware = _make_middleware(monkeypatch, inner, fake)

    seen = []

    async def fake_validate_jwt(token):
        seen.append(token)
        return "jwt-user"

    monkeypatch.setattr(middleware, "_validate_jwt", fake_validate_jwt)

    token = "eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.c2ln"
    messages = _run(middleware, _scope("/mcp", headers=_bearer(token)))

    assert _response(messages)[0] == 200
    assert seen == [token]
    assert fake.called("validate_key") == []
    assert fake.called("validate_execution_token") == []

    request = inner.requests[0]
    assert request["user_id"] == "jwt-user"
    assert request["auth_token"] == token
    assert request["scope"]["state"]["user_id"] == "jwt-user"


def test_plain_api_key_routes_to_validate_key(monkeypatch):
    inner = FakeInnerApp()
    fake = FakeIdentityManager(key_user="key-user", user_profile={"sub": "key-user"})
    middleware = _make_middleware(monkeypatch, inner, fake)

    messages = _run(middleware, _scope("/v1/agents", headers=_bearer("tl_plainkey")))

    assert _response(messages)[0] == 200
    assert fake.called("validate_key") == ["tl_plainkey"]
    assert inner.requests[0]["scope"]["state"]["user_id"] == "key-user"


# --- Ban enforcement ------------------------------------------------------------


def test_banned_user_gets_403_without_challenge(monkeypatch):
    inner = FakeInnerApp()
    fake = FakeIdentityManager(
        key_user="banned-user", user_profile={"sub": "banned-user", "is_banned": True}
    )
    middleware = _make_middleware(monkeypatch, inner, fake)

    status, headers, body = _response(
        _run(middleware, _scope("/v1/agents", headers=_bearer("tl_banned")))
    )

    assert status == 403
    assert json.loads(body) == {"error": "Account suspended"}
    assert "www-authenticate" not in headers
    assert inner.requests == []


def test_valid_token_with_missing_user_profile_still_passes(monkeypatch):
    # get_user() returning None (e.g. key owned by a deleted user) is not a ban.
    inner = FakeInnerApp()
    fake = FakeIdentityManager(key_user="ghost-user", user_profile=None)
    middleware = _make_middleware(monkeypatch, inner, fake)

    status, _, _ = _response(
        _run(middleware, _scope("/v1/agents", headers=_bearer("tl_ghost")))
    )

    assert status == 200
    assert inner.requests[0]["scope"]["state"]["user_id"] == "ghost-user"


# --- Unexpected failures ---------------------------------------------------------


def test_identity_store_failure_returns_500(monkeypatch):
    inner = FakeInnerApp()

    class ExplodingManager(FakeIdentityManager):
        def get_user(self, user_id):
            raise RuntimeError("etcd cluster unavailable")

    middleware = _make_middleware(
        monkeypatch, inner, ExplodingManager(key_user="u1")
    )

    status, _, body = _response(
        _run(middleware, _scope("/v1/agents", headers=_bearer("tl_u1")))
    )

    assert status == 500
    assert json.loads(body) == {"error": "Internal Server Error"}
    assert inner.requests == []


# --- DEV_MODE bypass --------------------------------------------------------------


def test_dev_mode_without_header_bypasses_as_dev_user(monkeypatch):
    inner = FakeInnerApp()
    fake = FakeIdentityManager()  # no validator would ever succeed
    middleware = _make_middleware(monkeypatch, inner, fake, dev_mode=True)

    messages = _run(middleware, _scope("/v1/agents"))

    assert _response(messages)[0] == 200
    request = inner.requests[0]
    assert request["user_id"] == "dev-user-id"
    assert request["auth_token"] == "dev-token"
    assert request["scope"]["state"]["user_id"] == "dev-user-id"
    assert fake.calls == []


def test_dev_mode_still_validates_presented_bearer_token(monkeypatch):
    inner = FakeInnerApp()
    fake = FakeIdentityManager(key_user=None)  # unknown token
    middleware = _make_middleware(monkeypatch, inner, fake, dev_mode=True)

    status, _, body = _response(
        _run(middleware, _scope("/v1/agents", headers=_bearer("tl_still_bad")))
    )

    assert status == 401
    assert json.loads(body) == {"error": "Invalid or expired token"}
    assert fake.called("validate_key") == ["tl_still_bad"]
    assert inner.requests == []
