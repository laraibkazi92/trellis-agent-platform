import sys
import os
import base64
import tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Create a temporary directory for tools
temp_tools_dir = tempfile.mkdtemp()
os.environ["TOOLS_DIR"] = temp_tools_dir

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
# We must set DEV_MODE so it bypasses auth
os.environ["DEV_MODE"] = "true"

from fastapi.testclient import TestClient
from app.main import app, get_db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.models import Base

# We must set DEV_MODE so it bypasses auth
os.environ["DEV_MODE"] = "true"

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

def test_create_agent():
    response = client.post(
        "/marketplace/agents",
        json={
            "name": "test-agent-create",
            "model_provider": "openai",
            "model_name": "gpt-4",
            "system_prompt": "You are a test agent."
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["name"] == "test-agent-create"
    assert "id" in data

def test_list_agents():
    client.post(
        "/marketplace/agents",
        json={
            "name": "test-agent-list",
            "model_provider": "openai",
            "model_name": "gpt-4",
        },
    )
    response = client.get("/marketplace/agents")
    assert response.status_code == 200
    data = response.json()
    assert "agents" in data
    assert len(data["agents"]) > 0
    names = [a["name"] for a in data["agents"]]
    assert "test-agent-list" in names

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_agent_health_404():
    response = client.get("/agents/999/health")
    assert response.status_code == 404

def test_tool_path_traversal():
    # Create tool first
    response = client.post(
        "/marketplace/tools",
        json={
            "name": "test-traversal-tool",
            "tool_directory": "tools/test/traversal",
            "entry_point_module": "main",
            "entry_point_function": "run"
        }
    )
    assert response.status_code == 200
    tool_id = response.json()["id"]

    # Try deploying file with path traversal
    file_content = base64.b64encode(b"print('hello')").decode('utf-8')
    deploy_res = client.post(
        f"/marketplace/tools/{tool_id}/deploy",
        json={
            "files": [
                {"path": "../../../etc/passwd", "content": file_content, "size": 15}
            ]
        }
    )
    assert deploy_res.status_code == 400

def test_tool_dangerous_imports():
    response = client.post(
        "/marketplace/tools",
        json={
            "name": "test-dangerous-tool",
            "tool_directory": "tools/test/dangerous",
            "entry_point_module": "main",
            "entry_point_function": "run"
        }
    )
    assert response.status_code == 200
    tool_id = response.json()["id"]

    file_content = base64.b64encode(b"import subprocess\nsubprocess.run('ls')").decode('utf-8')
    deploy_res = client.post(
        f"/marketplace/tools/{tool_id}/deploy",
        json={
            "files": [
                {"path": "main.py", "content": file_content, "size": len(file_content)}
            ]
        }
    )
    assert deploy_res.status_code == 400
    assert "Dangerous import" in deploy_res.json()["detail"]
