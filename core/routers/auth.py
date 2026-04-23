import os
import asyncio
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import oauth, identity_mgr, HAS_GITHUB_AUTH, HAS_OIDC_AUTH, templates

router = APIRouter()

DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html", 
        context={
            "request": request,
            "has_github": HAS_GITHUB_AUTH,
            "has_oidc": HAS_OIDC_AUTH,
            "dev_mode": DEV_MODE
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
    return RedirectResponse(url='/')

@router.get("/login/oidc")
async def login_oidc(request: Request):
    redirect_uri = request.url_for('auth_callback')
    return await oauth.oidc.authorize_redirect(request, redirect_uri)

@router.get("/auth/callback")
async def auth_callback(request: Request):
    token = await oauth.oidc.authorize_access_token(request)
    user = token.get('userinfo')
    if user:
        # Ensure name is not None for UI display
        if not user.get('name'):
            user['name'] = user.get('email') or user.get('preferred_username') or user.get('sub')
            
        request.session['user'] = user
        # Upsert user to etcd
        await asyncio.to_thread(identity_mgr.upsert_user, user['sub'], dict(user))
    return RedirectResponse(url='/')

@router.get("/logout")
async def logout(request: Request):
    request.session.pop('user', None)
    return RedirectResponse(url='/')

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

        request.session['user'] = userinfo
        # Upsert user to etcd
        await asyncio.to_thread(identity_mgr.upsert_user, userinfo['sub'], dict(userinfo))
    return RedirectResponse(url='/')