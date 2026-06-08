import os
import re
from fastapi.templating import Jinja2Templates
from authlib.integrations.starlette_client import OAuth
from core.auth import IdentityManager
from dotenv import load_dotenv

load_dotenv()

# Templates
templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
os.makedirs(templates_dir, exist_ok=True)

def admin_context(request):
    from core.auth import is_admin
    return {"is_admin": is_admin(request)}

def _validate_hex_color(color: str, default: str) -> str:
    color = color.strip()
    if re.match(r"^#(?:[0-9a-fA-F]{3}){1,2}$", color):
        return color
    return default

def whitelabel_context(request):
    return {
        "app_name": os.getenv("APP_NAME", "Trellis").strip(),
        "app_favicon_url": os.getenv("APP_FAVICON_URL", "").strip(),
        "app_logo_url": os.getenv("APP_LOGO_URL", "").strip(),
        "app_login_logo_url": os.getenv("APP_LOGIN_LOGO_URL", "").strip(),
        "app_login_title": os.getenv("APP_LOGIN_TITLE", "Welcome Back").strip(),
        "app_login_subtitle": os.getenv("APP_LOGIN_SUBTITLE", "Sign in to your enterprise workspace").strip(),
        "app_login_disclaimer": os.getenv("APP_LOGIN_DISCLAIMER", "This system is for authorized use only. All activities are monitored and logged for security and compliance purposes.").strip(),
        "app_accent_color": _validate_hex_color(os.getenv("APP_ACCENT_COLOR", "#0055FF"), "#0055FF"),
        "app_accent_color_dark": _validate_hex_color(os.getenv("APP_ACCENT_COLOR_DARK", "#3377FF"), "#3377FF"),
    }

import secrets
from typing import Optional
from fastapi import Request
from fastapi.responses import RedirectResponse
from fastapi.routing import APIRoute

def csrf_context(request: Request):
    csrf_token = request.session.get("csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_hex(32)
        request.session["csrf_token"] = csrf_token
    return {"csrf_token": csrf_token}

class CSRFRoute(APIRoute):
    def get_route_handler(self):
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request):
            if request.method == "POST":
                content_type = request.headers.get("content-type", "")
                if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
                    form = await request.form()
                    token = form.get("csrf_token")
                    session_token = request.session.get("csrf_token")
                    if not token or not session_token or token != session_token:
                        request.session["flash_msg"] = "Invalid CSRF token. Please refresh and try again."
                        return RedirectResponse(url=request.headers.get("referer", "/"), status_code=303)
            
            return await original_route_handler(request)
        return custom_route_handler

templates = Jinja2Templates(directory=templates_dir, context_processors=[admin_context, whitelabel_context, csrf_context])

# OAuth setup
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET")
OIDC_METADATA_URL = os.getenv("OIDC_METADATA_URL")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

oauth = OAuth()

HAS_OIDC_AUTH = bool(OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_METADATA_URL)
if HAS_OIDC_AUTH:
    oauth.register(
        name='oidc',
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=OIDC_METADATA_URL,
        client_kwargs={'scope': 'openid profile email'}
    )

HAS_GITHUB_AUTH = bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)
if HAS_GITHUB_AUTH:
    oauth.register(
        name='github',
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        client_kwargs={
            'scope': 'user:email',
            'verify': '/etc/ssl/certs/ca-certificates.crt'
        }
    )

ALLOWED_DOMAINS = [d.strip().lower() for d in os.getenv("ALLOWED_DOMAINS", "").split(",") if d.strip()]

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)