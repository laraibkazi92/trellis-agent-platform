import asyncio
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from core.dependencies import oauth, identity_mgr

router = APIRouter()

@router.get("/")
async def homepage(request: Request):
    user = request.session.get('user')
    if user:
        return RedirectResponse(url='/catalog')
    return HTMLResponse('<a href="/login">Login with OIDC</a>')

@router.get("/login")
async def login(request: Request):
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