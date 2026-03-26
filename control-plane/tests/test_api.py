import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from app.main import app, get_db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.models import Base

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
