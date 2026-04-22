import os
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

load_dotenv()

DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-secret-key" if DEV_MODE else None)
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET")
OIDC_METADATA_URL = os.getenv("OIDC_METADATA_URL")
ADMIN_USERS_ENV = os.getenv("ADMIN_USERS")

if not DEV_MODE and not all([SESSION_SECRET, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_METADATA_URL, ADMIN_USERS_ENV]):
    raise ValueError("Missing required environment variables for UI (SESSION_SECRET, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_METADATA_URL, ADMIN_USERS).")

from core.routers import auth, marketplace, keys, admin

app = FastAPI(title="Marketplace UI")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

app.include_router(auth.router)
app.include_router(marketplace.router)
app.include_router(keys.router)
app.include_router(admin.router)