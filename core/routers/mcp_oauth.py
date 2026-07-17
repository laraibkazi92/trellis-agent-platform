import asyncio
import base64
import hashlib
import hmac
import secrets
import time
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse

import jwt
from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from core.dependencies import identity_mgr, templates

logger = logging.getLogger(__name__)

router = APIRouter()


def _base_url(request: Request) -> str:
    """Build the external base URL from forwarded headers."""
    proto = request.headers.get("x-forwarded-proto", "https")
    host = request.headers.get("host", "localhost")
    return f"{proto}://{host}"


# ---------------------------------------------------------------------------
# Public well-known / discovery endpoints (no auth required)
# ---------------------------------------------------------------------------

@router.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(request: Request) -> JSONResponse:
    """RFC 9728 Protected Resource Metadata.

    Tells MCP clients which Authorization Server governs this resource.
    """
    base = _base_url(request)
    return JSONResponse({
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base}/docs",
    })


@router.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request) -> JSONResponse:
    """OAuth 2.0 / OIDC Authorization Server discovery document.

    The issuer value must exactly match this URL for strict MCP clients.
    """
    base = _base_url(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_post"],
    })


# ---------------------------------------------------------------------------
# Dynamic Client Registration (RFC 7591)
# ---------------------------------------------------------------------------

class DCRRequest(BaseModel):
    redirect_uris: List[str]
    client_name: Optional[str] = None
    token_endpoint_auth_method: Optional[str] = "client_secret_post"
    grant_types: Optional[List[str]] = None
    response_types: Optional[List[str]] = None
    scope: Optional[str] = None

    model_config = {"extra": "allow"}


@router.post("/oauth/register", status_code=201)
async def register_client(request: Request, body: DCRRequest) -> JSONResponse:
    """RFC 7591 Dynamic Client Registration.

    Issues a client_id and client_secret. The raw secret is returned once here
    and never stored — only its SHA-256 hash is persisted in etcd.
    """
    client_id = f"mcp_{secrets.token_urlsafe(16)}"
    client_secret = secrets.token_urlsafe(32)
    issued_at = int(time.time())

    metadata: Dict[str, Any] = {
        "redirect_uris": body.redirect_uris,
        "token_endpoint_auth_method": body.token_endpoint_auth_method or "client_secret_post",
        "grant_types": body.grant_types or ["authorization_code"],
        "response_types": body.response_types or ["code"],
        "client_id_issued_at": issued_at,
        "client_secret_expires_at": 0,
    }
    if body.client_name:
        metadata["client_name"] = body.client_name
    if body.scope:
        metadata["scope"] = body.scope

    try:
        await asyncio.to_thread(
            identity_mgr.save_oauth_client, client_id, client_secret, metadata
        )
    except Exception:
        logger.exception("Failed to persist OAuth client registration")
        return JSONResponse(
            {"error": "server_error", "error_description": "Failed to register client"},
            status_code=500,
        )

    return JSONResponse(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            **metadata,
        },
        status_code=201,
    )


# ---------------------------------------------------------------------------
# Authorization endpoint (Phase 4)
# ---------------------------------------------------------------------------

def _build_redirect_url(base_uri: str, **params) -> str:
    """Append non-None query params to a redirect URI."""
    parsed = urlparse(base_uri)
    query = urlencode({k: v for k, v in params.items() if v is not None})
    return urlunparse(parsed._replace(query=query))


@router.get("/oauth/authorize")
async def authorize_get(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = "S256",
    state: Optional[str] = None,
    scope: Optional[str] = None,
):
    """Consent screen. Redirects to login when session is absent."""
    user = request.session.get("user")
    if not user:
        request.session["post_login_redirect"] = str(request.url)
        return RedirectResponse(url="/login", status_code=302)

    client = await asyncio.to_thread(identity_mgr.get_oauth_client, client_id)
    if not client:
        return JSONResponse({"error": "invalid_client", "error_description": "Unknown client_id"}, status_code=400)

    if redirect_uri not in client.get("redirect_uris", []):
        # RFC 6749 §4.1.2.1 — must NOT redirect; show error directly.
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)

    return templates.TemplateResponse(
        request=request,
        name="mcp_consent.html",
        context={
            "request": request,
            "client_id": client_id,
            "client_name": client.get("client_name") or client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "scope": scope,
            "user": user,
        },
    )


@router.post("/oauth/authorize")
async def authorize_post(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: Optional[str] = Form(None),
    code_challenge: Optional[str] = Form(None),
    code_challenge_method: Optional[str] = Form(None),
    action: str = Form(...),
    csrf_token: Optional[str] = Form(None),
):
    """Handle consent approval or denial."""
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    # CSRF guard — consent form includes the session CSRF token.
    session_csrf = request.session.get("csrf_token")
    if not csrf_token or not session_csrf or not hmac.compare_digest(csrf_token, session_csrf):
        return JSONResponse({"error": "invalid_request", "error_description": "CSRF check failed"}, status_code=400)

    if action != "approve":
        redirect_url = _build_redirect_url(redirect_uri, error="access_denied", state=state)
        return RedirectResponse(url=redirect_url, status_code=302)

    client = await asyncio.to_thread(identity_mgr.get_oauth_client, client_id)
    if not client or redirect_uri not in client.get("redirect_uris", []):
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    code = secrets.token_urlsafe(32)
    code_data: Dict[str, Any] = {
        "client_id": client_id,
        "user_id": user.get("sub"),
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method or "S256",
    }
    try:
        await asyncio.to_thread(identity_mgr.save_oauth_code, code, code_data)
    except Exception:
        logger.exception("Failed to persist authorization code")
        redirect_url = _build_redirect_url(redirect_uri, error="server_error", state=state)
        return RedirectResponse(url=redirect_url, status_code=302)

    redirect_url = _build_redirect_url(redirect_uri, code=code, state=state)
    return RedirectResponse(url=redirect_url, status_code=302)


# ---------------------------------------------------------------------------
# Token endpoint (Phase 4)
# ---------------------------------------------------------------------------

@router.post("/oauth/token")
async def token_endpoint(request: Request) -> JSONResponse:
    """Exchange an authorization code for a JWT access token."""
    form = await request.form()
    grant_type = form.get("grant_type", "")
    client_id = form.get("client_id", "")
    client_secret = form.get("client_secret", "")
    code = form.get("code", "")
    redirect_uri = form.get("redirect_uri", "")
    code_verifier = form.get("code_verifier", "")

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    if not client_id or not client_secret:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    client = await asyncio.to_thread(identity_mgr.get_oauth_client, client_id)
    if not client:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    expected_hash = hashlib.sha256(client_secret.encode()).hexdigest()
    if not hmac.compare_digest(expected_hash, client.get("client_secret_hash", "")):
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    code_data = await asyncio.to_thread(identity_mgr.get_and_delete_oauth_code, code)
    if not code_data:
        return JSONResponse({"error": "invalid_grant", "error_description": "Code not found or expired"}, status_code=400)

    if code_data.get("client_id") != client_id:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    if code_data.get("redirect_uri") != redirect_uri:
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

    # PKCE verification (S256).
    stored_challenge = code_data.get("code_challenge")
    if stored_challenge:
        if not code_verifier:
            return JSONResponse({"error": "invalid_grant", "error_description": "code_verifier required"}, status_code=400)
        digest = hashlib.sha256(code_verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if not hmac.compare_digest(computed, stored_challenge):
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)

    user_id = code_data.get("user_id")
    now = int(time.time())
    jti = secrets.token_urlsafe(16)
    try:
        secret = await asyncio.to_thread(identity_mgr.get_or_create_jwt_secret)
        access_token = jwt.encode(
            {"sub": user_id, "aud": "mcp:tools", "iat": now, "exp": now + 3600, "jti": jti},
            secret,
            algorithm="HS256",
        )
    except Exception:
        logger.exception("Failed to issue JWT")
        return JSONResponse({"error": "server_error"}, status_code=500)

    # RFC 6749 §5.1 — token responses must not be cached.
    return JSONResponse(
        {"access_token": access_token, "token_type": "bearer", "expires_in": 3600},
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


# ---------------------------------------------------------------------------
# Token Revocation endpoint (RFC 7009) — Phase 5
# ---------------------------------------------------------------------------

@router.post("/oauth/revoke")
async def revoke_token(request: Request) -> JSONResponse:
    """RFC 7009 Token Revocation.

    Adds the token's JTI to an etcd denylist so the middleware can reject it
    before it would naturally expire. Per RFC 7009 §2.2 the server MUST return
    200 for invalid/unknown tokens — never reveal whether a token was valid.
    """
    form = await request.form()
    token = str(form.get("token", ""))
    client_id = str(form.get("client_id", ""))
    client_secret = str(form.get("client_secret", ""))

    # Authenticate the revoking client (same rules as the token endpoint).
    if not client_id or not client_secret:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    client = await asyncio.to_thread(identity_mgr.get_oauth_client, client_id)
    if not client:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    expected_hash = hashlib.sha256(client_secret.encode()).hexdigest()
    if not hmac.compare_digest(expected_hash, client.get("client_secret_hash", "")):
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    if not token:
        return JSONResponse({}, status_code=200)

    try:
        secret = await asyncio.to_thread(identity_mgr.get_or_create_jwt_secret)
        # Decode without exp verification so already-expired tokens can still be
        # explicitly revoked (harmless, but satisfies strict RFC compliance).
        payload = jwt.decode(
            token, secret, algorithms=["HS256"], audience="mcp:tools",
            options={"verify_exp": False},
        )
        jti = payload.get("jti")
        exp = payload.get("exp", 0)
        if jti:
            await asyncio.to_thread(identity_mgr.save_revoked_token, jti, exp)
    except jwt.PyJWTError:
        # Unknown or malformed token — per RFC 7009 §2.2, return 200 silently.
        pass
    except Exception:
        logger.exception("Failed to revoke token")
        return JSONResponse({"error": "server_error"}, status_code=503)

    return JSONResponse({}, status_code=200)
