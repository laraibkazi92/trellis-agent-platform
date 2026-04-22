import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from core.auth import IdentityManager
from core.discovery import discover_agents, discover_tools
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

@app.get("/catalog", response_class=HTMLResponse)
async def catalog(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_users = os.getenv("ADMIN_USERS", "").split(",")
    is_admin = user.get("email") in admin_users
    
    agents = discover_agents()
    tools = discover_tools()
    
    return templates.TemplateResponse("catalog.html", {
        "request": request,
        "user": user,
        "agents": agents,
        "tools": tools,
        "is_admin": is_admin
    })

from fastapi import Form

@app.get("/keys", response_class=HTMLResponse)
async def keys_page(request: Request):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
    
    keys = identity_mgr.list_keys(user['sub'])
    return templates.TemplateResponse("keys.html", {
        "request": request,
        "keys": keys
    })

@app.post("/keys/generate")
async def generate_key(request: Request, key_name: str = Form(...)):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    identity_mgr.create_key(user['sub'], key_name)
    return RedirectResponse(url='/keys', status_code=303)

@app.post("/keys/revoke")
async def revoke_key(request: Request, api_key: str = Form(...)):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    # Verify the key belongs to the user before deleting
    key_user_id = identity_mgr.validate_key(api_key)
    if key_user_id == user['sub']:
        identity_mgr.delete_key(api_key)
        
    return RedirectResponse(url='/keys', status_code=303)

@app.get("/editor/{agent_name}", response_class=HTMLResponse)
async def editor_page(request: Request, agent_name: str):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_users = os.getenv("ADMIN_USERS", "").split(",")
    if user.get("email") not in admin_users:
        return HTMLResponse("Unauthorized", status_code=403)
        
    agents_dir = os.path.join(os.path.dirname(__file__), "..", "agents")
    skills_path = os.path.join(agents_dir, agent_name, "skills.md")
    
    skills_content = ""
    if os.path.exists(skills_path):
        with open(skills_path, "r") as f:
            skills_content = f.read()
            
    return templates.TemplateResponse("editor.html", {
        "request": request,
        "agent_name": agent_name,
        "skills_content": skills_content
    })

@app.post("/editor/{agent_name}")
async def save_skills(request: Request, agent_name: str, skills_content: str = Form(...)):
    user = request.session.get('user')
    if not user:
        return RedirectResponse(url='/login')
        
    admin_users = os.getenv("ADMIN_USERS", "").split(",")
    if user.get("email") not in admin_users:
        return HTMLResponse("Unauthorized", status_code=403)
        
    agents_dir = os.path.join(os.path.dirname(__file__), "..", "agents")
    agent_dir = os.path.join(agents_dir, agent_name)
    
    if not os.path.exists(agent_dir):
        return HTMLResponse("Agent not found", status_code=404)
        
    skills_path = os.path.join(agent_dir, "skills.md")
    with open(skills_path, "w") as f:
        f.write(skills_content)
        
    return RedirectResponse(url='/catalog', status_code=303)
