# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import asyncio
from urllib.parse import urlparse
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import oauth, identity_mgr, HAS_GITHUB_AUTH, HAS_OIDC_AUTH, templates, ALLOWED_DOMAINS

logger = logging.getLogger(__name__)
from core.auth import claim_groups, groups_claim_name

async def require_auth(request: Request):
    from core.auth import get_current_user
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url='/login')
    return user

router = APIRouter()


DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"


def _safe_post_login_redirect(url: str, current_host: str) -> str:
    """Return url only if it's on current_host; fall back to '/'.

    Prevents open-redirect attacks when the HOST header is spoofable in the
    deployment — the stored post_login_redirect could otherwise point off-domain.
    """
    if not url:
        return "/"
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            return url  # relative path — inherently on-host
        if parsed.netloc == current_host:
            return url
    except Exception:
        pass
    return "/"

def is_domain_allowed(email: str) -> bool:
    if not ALLOWED_DOMAINS:
        return True
    if not email:
        return False
    domain = email.split('@')[-1].lower()
    return domain in ALLOWED_DOMAINS

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    flash_msg = request.session.pop("flash_msg", None)
    return templates.TemplateResponse(
        request=request,
        name="login.html", 
        context={
            "request": request,
            "has_github": HAS_GITHUB_AUTH,
            "has_oidc": HAS_OIDC_AUTH,
            "dev_mode": DEV_MODE,
            "flash_msg": flash_msg
        }
    )

@router.get("/login/dev")
async def login_dev(request: Request):
    if DEV_MODE:
        user = {
            "sub": "dev-user-id",
            "name": "Dev User",
            "email": "dev-user@local.host"
        }
        request.session['user'] = user
        try:
            await asyncio.to_thread(identity_mgr.upsert_user, user['sub'], user)
        except Exception as e:
            print(f"Warning: Failed to upsert mock user in etcd: {e}")
    next_url = _safe_post_login_redirect(
        request.session.pop("post_login_redirect", "/"),
        request.headers.get("host", "localhost"),
    )
    return RedirectResponse(url=next_url)

@router.get("/login/oidc")
async def login_oidc(request: Request):
    redirect_uri = request.url_for('auth_callback')
    return await oauth.oidc.authorize_redirect(request, redirect_uri)

@router.get("/auth/callback")
async def auth_callback(request: Request):
    token = await oauth.oidc.authorize_access_token(request)
    user = token.get('userinfo')
    if user:
        email = user.get('email')
        if not is_domain_allowed(email):
            request.session["flash_msg"] = f"Domain '{email.split('@')[-1]}' is not authorized."
            return RedirectResponse(url='/login')

        # Ensure name is not None for UI display
        if not user.get('name'):
            user['name'] = user.get('email') or user.get('preferred_username') or user.get('sub')

        # Group membership travels with the etcd record; `group:` policy rules read it.
        # Deliberately NOT in the session: Starlette sessions are a signed cookie with a
        # browser 4 KB budget, and a large IdP claim (100+ groups) would drop the cookie
        # and lock the user out. Nothing renders groups from the session.
        profile = {**user, "groups": claim_groups(user)}
        if not profile["groups"]:
            logger.info(
                "Login for %s produced no groups from claim %r; group: rules fall back "
                "to /config/framework/principal_groups.",
                user.get("email"), groups_claim_name(),
            )

        # The raw claim also stays out of the cookie: only the normalized copy on the
        # record is used, and a 200-group claim would blow the cookie budget.
        request.session['user'] = {
            key: value for key, value in user.items() if key != groups_claim_name()
        }
        # Upsert user to etcd
        await asyncio.to_thread(identity_mgr.upsert_user, user['sub'], profile)
    next_url = _safe_post_login_redirect(
        request.session.pop("post_login_redirect", "/"),
        request.headers.get("host", "localhost"),
    )
    return RedirectResponse(url=next_url)

@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    response = RedirectResponse(url='/login')
    response.delete_cookie("session") # Just in case, ensure the cookie is cleared
    return response

@router.get("/login/github")
async def login_github(request: Request):
    redirect_uri = request.url_for('auth_github_callback')
    return await oauth.github.authorize_redirect(request, redirect_uri)

@router.get("/auth/github/callback")
async def auth_github_callback(request: Request):
    token = await oauth.github.authorize_access_token(request)
    resp = await oauth.github.get('user', token=token)
    userinfo = resp.json()
    if userinfo:
        # Normalize Identity: ensure consistent string format for IdentityManager
        userinfo['sub'] = f"github|{userinfo['id']}"
        
        # Ensure name is not None for UI display
        if not userinfo.get('name'):
            userinfo['name'] = userinfo.get('login')
            
        # Some GitHub accounts might not have a public email in the basic user info
        if not userinfo.get('email'):
            email_resp = await oauth.github.get('user/emails', token=token)
            emails = email_resp.json()
            primary_email = next((email['email'] for email in emails if email['primary']), None)
            if primary_email:
                userinfo['email'] = primary_email

        email = userinfo.get('email')
        if not is_domain_allowed(email):
            domain_str = email.split('@')[-1] if email else "unknown"
            request.session["flash_msg"] = f"Domain '{domain_str}' is not authorized."
            return RedirectResponse(url='/login')

        # Sourced from the same configured claim; GitHub's default payload carries no
        # groups, so this is `[]` unless the deployment maps one. Kept out of the
        # session cookie for the same reason as the OIDC callback above.
        profile = {**userinfo, "groups": claim_groups(userinfo)}

        request.session['user'] = {
            key: value for key, value in userinfo.items() if key != groups_claim_name()
        }
        # Upsert user to etcd
        await asyncio.to_thread(identity_mgr.upsert_user, userinfo['sub'], profile)
    next_url = _safe_post_login_redirect(
        request.session.pop("post_login_redirect", "/"),
        request.headers.get("host", "localhost"),
    )
    return RedirectResponse(url=next_url)