import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from core.auth import IdentityManager
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Marketplace UI")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "super-secret-key"))

# Templates
templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
os.makedirs(templates_dir, exist_ok=True)
templates = Jinja2Templates(directory=templates_dir)

# OAuth setup
oauth = OAuth()
oauth.register(
    name='oidc',
    client_id=os.getenv('OIDC_CLIENT_ID', 'default_id'),
    client_secret=os.getenv('OIDC_CLIENT_SECRET', 'default_secret'),
    server_metadata_url=os.getenv('OIDC_METADATA_URL', 'https://dev-000000.oidc.com/.well-known/openid-configuration'),
    client_kwargs={'scope': 'openid profile email'}
)

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)

@app.get("/")
async def homepage(request: Request):
    user = request.session.get('user')
    if user:
        return RedirectResponse(url='/catalog')
    return HTMLResponse('<a href="/login">Login with OIDC</a>')

@app.get("/login")
async def login(request: Request):
    redirect_uri = request.url_for('auth_callback')
    return await oauth.oidc.authorize_redirect(request, redirect_uri)

@app.get("/auth/callback")
async def auth_callback(request: Request):
    token = await oauth.oidc.authorize_access_token(request)
    user = token.get('userinfo')
    if user:
        request.session['user'] = user
        # Upsert user to etcd
        identity_mgr.upsert_user(user['sub'], dict(user))
    return RedirectResponse(url='/catalog')

@app.get("/logout")
async def logout(request: Request):
    request.session.pop('user', None)
    return RedirectResponse(url='/')
