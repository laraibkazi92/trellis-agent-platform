from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List
import httpx

from . import models, schemas, database, etcd_client
from .database import engine

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Control Plane API")

# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/agents/register")
def register_agent(agent_data: schemas.AgentRegister, db: Session = Depends(get_db)):
    agent = db.query(models.Agent).filter(models.Agent.name == agent_data.agent_name).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found in registry")
    
    # Update agent info based on registration
    agent.status = "active"
    agent.docker_container_name = agent_data.docker_container_name
    db.commit()
    
    return {
        "agent_id": agent.id,
        "status": "registered",
        "config_url": f"/agents/{agent.id}/config"
    }

@app.get("/agents/{agent_id}/config")
def get_agent_config(agent_id: int, db: Session = Depends(get_db)):
    agent = db.query(models.Agent).filter(models.Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    tool_links = db.query(models.AgentToolLink).filter(models.AgentToolLink.agent_id == agent.id).all()
    assigned_tools = []
    for link in tool_links:
        tool = db.query(models.Tool).filter(models.Tool.id == link.tool_id).first()
        if tool:
            assigned_tools.append({
                "tool_id": tool.id,
                "name": tool.name,
                "tool_directory": tool.tool_directory,
                "entry_point_module": tool.entry_point_module,
                "entry_point_function": tool.entry_point_function,
                "etcd_secret_key": tool.etcd_secret_key,
                "etcd_secret_key_reference": tool.etcd_secret_key_reference
            })

    return {
        "agent": {
            "id": agent.id,
            "name": agent.name,
            "model_provider": agent.model_provider,
            "model_name": agent.model_name,
            "system_prompt": agent.system_prompt
        },
        "all_tools_mcp_server": {
            "url": "http://all-tools-mcp-server:8000/mcp",
            "mcp_type": "http"
        },
        "assigned_tools": assigned_tools,
        "model_provider": {
            "api_key_etcd_path": f"providers/{agent.model_provider}/api_key"
        }
    }

@app.get("/marketplace/agents")
def list_marketplace_agents(db: Session = Depends(get_db)):
    agents = db.query(models.Agent).all()
    result = []
    for a in agents:
        tool_count = db.query(models.AgentToolLink).filter(models.AgentToolLink.agent_id == a.id).count()
        result.append({
            "id": a.id,
            "name": a.name,
            "model_provider": a.model_provider,
            "model_name": a.model_name,
            "status": a.status,
            "tool_count": tool_count,
            "tags": []
        })
    return {"agents": result}

@app.post("/marketplace/agents", response_model=schemas.Agent)
def create_agent(agent_data: schemas.AgentCreate, db: Session = Depends(get_db)):
    db_agent = models.Agent(
        name=agent_data.name,
        model_provider=agent_data.model_provider,
        model_name=agent_data.model_name,
        system_prompt=agent_data.system_prompt,
        docker_container_name=agent_data.docker_container_name,
        status=agent_data.status
    )
    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)

    for tid in agent_data.assigned_tool_ids:
        link = models.AgentToolLink(agent_id=db_agent.id, tool_id=tid)
        db.add(link)
    db.commit()

    return db_agent

@app.get("/marketplace/tools")
def list_marketplace_tools(db: Session = Depends(get_db)):
    tools = db.query(models.Tool).filter(models.Tool.is_active == True).all()
    return {"tools": tools}

@app.post("/marketplace/credentials")
def create_credential(cred: schemas.CredentialCreate):
    etcd_client.set_etcd_secret(cred.path, cred.value)
    return {"status": "created", "path": cred.path}

@app.get("/marketplace/credentials")
def list_credentials(prefix: str = ""):
    keys = etcd_client.list_etcd_secrets(prefix)
    return {"credentials": keys}

@app.post("/v1/chat/completions")
async def chat_completions(request: Request, db: Session = Depends(get_db)):
    request_data = await request.json()
    model_name = request_data.get("model")

    agent = db.query(models.Agent).filter(models.Agent.name == model_name).first()
    if not agent or not agent.docker_container_name:
        raise HTTPException(status_code=404, detail="Agent not found or not registered")

    agent_url = f"http://{agent.docker_container_name}:{agent.port_openai}/v1/chat/completions"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(agent_url, json=request_data, timeout=300.0)
            return response.json()
        except Exception as e:
            raise HTTPException(status_code=502, detail=str(e))
