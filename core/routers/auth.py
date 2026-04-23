import os
import asyncio
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import oauth, identity_mgr, HAS_GITHUB_AUTH, HAS_OIDC_AUTH

router = APIRouter()

DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"

@router.get("/")
async def homepage(request: Request):
    user = request.session.get('user')
    if user:
        return RedirectResponse(url='/catalog')
        
    links = []
    if DEV_MODE:
        links.append('<a href="/login">Login (Dev Mode)</a>')
    else:
        if HAS_OIDC_AUTH:
            links.append('<a href="/login">Login with OIDC</a>')
        if HAS_GITHUB_AUTH:
            links.append('<a href="/login/github">Login with GitHub</a>')
            
    if not links:
        return HTMLResponse('No authentication methods configured.')
        
    html_content = "<br><br>".join(links)
    return HTMLResponse(f'<div>{html_content}</div>')

@router.get("/login")
async def login(request: Request):
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
        return RedirectResponse(url='/catalog')
        
    redirect_uri = request.url_for('auth_callback')
    return await oauth.oidc.authorize_redirect(request, redirect_uri)

@router.get("/auth/callback")
async def auth_callback(request: Request):
    token = await oauth.oidc.authorize_access_token(request)
    user = token.get('userinfo')
    if user:
        request.session['user'] = user
        # Upsert user to etcd
        await asyncio.to_thread(identity_mgr.upsert_user, user['sub'], dict(user))
    return RedirectResponse(url='/catalog')

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
    return RedirectResponse(url='/catalog')