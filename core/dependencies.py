# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
import re
import json
import time
import asyncio
from fastapi.templating import Jinja2Templates
from authlib.integrations.starlette_client import OAuth
from core.auth import get_identity_manager
from core.llm_providers import provider_ui_specs
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

# Branding is edited primarily in the Admin UI (Admin Dashboard -> Branding) and stored in
# etcd; the APP_* env vars below are only the shipped defaults. The context processor runs on
# every render, so values are served from a short-lived cache and refreshed out of band --
# a page render must never block on etcd (same rationale as core/rules_engine.py's overrides).
_BRANDING_ENV_DEFAULTS = {
    "name": ("APP_NAME", "Trellis"),
    "favicon_url": ("APP_FAVICON_URL", ""),
    "logo_url": ("APP_LOGO_URL", ""),
    "login_logo_url": ("APP_LOGIN_LOGO_URL", ""),
    "login_title": ("APP_LOGIN_TITLE", "Welcome Back"),
    "login_subtitle": ("APP_LOGIN_SUBTITLE", "Sign in to your workspace"),
    "login_disclaimer": (
        "APP_LOGIN_DISCLAIMER",
        "This system is for authorized use only. All activities are monitored and logged for security and compliance purposes.",
    ),
    "accent_color": ("APP_ACCENT_COLOR", "#0055FF"),
    "accent_color_dark": ("APP_ACCENT_COLOR_DARK", "#3377FF"),
}
_BRANDING_CACHE_TTL_SECONDS = 30.0
_branding_cache: dict = {}
_branding_cached_at: float = 0.0
_branding_refresh_in_flight: bool = False


def _env_branding_defaults() -> dict:
    return {
        key: os.getenv(env_var, default).strip()
        for key, (env_var, default) in _BRANDING_ENV_DEFAULTS.items()
    }


def _refresh_branding_sync() -> None:
    """Runs in a thread-pool worker via loop.run_in_executor -- never awaited directly."""
    global _branding_cache, _branding_cached_at, _branding_refresh_in_flight
    values = _env_branding_defaults()
    try:
        for key in values:
            override = identity_mgr.get_branding(key)
            if override:
                values[key] = override
    except Exception:
        # etcd unavailable or not seeded yet -- ship the env defaults.
        values = _env_branding_defaults()
    _branding_cache = values
    _branding_cached_at = time.monotonic()
    _branding_refresh_in_flight = False


def _branding_values() -> dict:
    """Resolve branding as: etcd override (Admin UI) > APP_* env default. Serves the
    last-known cache immediately and, if it is stale, schedules a background refresh for
    the next render instead of waiting on etcd here."""
    global _branding_refresh_in_flight

    now = time.monotonic()
    if _branding_cache and (now - _branding_cached_at) < _BRANDING_CACHE_TTL_SECONDS:
        return _branding_cache

    if not _branding_refresh_in_flight:
        _branding_refresh_in_flight = True
        try:
            asyncio.get_running_loop().run_in_executor(None, _refresh_branding_sync)
        except RuntimeError:
            # No running loop (e.g. sync render/test) -- skip this refresh cycle rather
            # than block; the next render from an async context will pick it up.
            _branding_refresh_in_flight = False

    return _branding_cache or _env_branding_defaults()


def whitelabel_context(request):
    values = _branding_values()
    return {
        "app_name": values["name"],
        "app_favicon_url": values["favicon_url"],
        "app_logo_url": values["logo_url"],
        "app_login_logo_url": values["login_logo_url"],
        "app_login_title": values["login_title"],
        "app_login_subtitle": values["login_subtitle"],
        "app_login_disclaimer": values["login_disclaimer"],
        "app_accent_color": _validate_hex_color(values["accent_color"], "#0055FF"),
        "app_accent_color_dark": _validate_hex_color(values["accent_color_dark"], "#3377FF"),
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

# Single injection point for the LLM provider registry: every template rendered through
# `templates` gets `llm_providers` (server-side <option>s) and `llm_providers_json`
# (inline-JS payload). The specs are pure and static, so they are computed once at import
# and add no etcd read / SDK import to any render. Per-provider `configured` state is
# deliberately NOT here -- it needs etcd; only /admin/llm-providers fetches the store.
_LLM_PROVIDER_UI_SPECS = provider_ui_specs()
_LLM_PROVIDERS_JSON = json.dumps(_LLM_PROVIDER_UI_SPECS)


def llm_providers_context(request):
    return {"llm_providers": _LLM_PROVIDER_UI_SPECS, "llm_providers_json": _LLM_PROVIDERS_JSON}


templates = Jinja2Templates(directory=templates_dir, context_processors=[admin_context, whitelabel_context, csrf_context, llm_providers_context])

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

identity_mgr = get_identity_manager()