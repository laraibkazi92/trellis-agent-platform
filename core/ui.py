# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

from core.devmode import configure_cors, enforce_dev_mode_safety

load_dotenv()

DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-secret-key" if DEV_MODE else None)
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET")
OIDC_METADATA_URL = os.getenv("OIDC_METADATA_URL")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
ADMIN_USERS_ENV = os.getenv("ADMIN_USERS")

if not DEV_MODE:
    missing = []
    if not SESSION_SECRET:
        missing.append("SESSION_SECRET")
    if not ADMIN_USERS_ENV:
        missing.append("ADMIN_USERS")
    
    has_oidc = all([OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_METADATA_URL])
    has_github = all([GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET])
    
    if not (has_oidc or has_github):
        missing.append("Authentication Provider (GitHub or OIDC variables)")
    
    if missing:
        raise ValueError(f"Missing required environment variables for UI: {', '.join(missing)}")

# Warn if this is an unauthenticated DEV_MODE instance (see core/devmode.py).
enforce_dev_mode_safety("ui")

from core.routers import auth, marketplace, profile, admin, configuration, docs, status, workflows, api, reports, mcp_oauth

app = FastAPI(title="Marketplace UI", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

configure_cors(app)

app.include_router(auth.router)
app.include_router(marketplace.router)
app.include_router(profile.router)
app.include_router(admin.router)
app.include_router(configuration.router)
app.include_router(docs.router)
app.include_router(status.router)
app.include_router(workflows.router)
app.include_router(api.router)
app.include_router(reports.router)
app.include_router(mcp_oauth.router)