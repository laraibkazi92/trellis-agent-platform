import os
from fastapi.templating import Jinja2Templates
from authlib.integrations.starlette_client import OAuth
from core.auth import IdentityManager
from dotenv import load_dotenv

load_dotenv()

# Templates
templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
os.makedirs(templates_dir, exist_ok=True)
templates = Jinja2Templates(directory=templates_dir)

# OAuth setup
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET")
OIDC_METADATA_URL = os.getenv("OIDC_METADATA_URL")

oauth = OAuth()
if OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_METADATA_URL:
    oauth.register(
        name='oidc',
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=OIDC_METADATA_URL,
        client_kwargs={'scope': 'openid profile email'}
    )

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)