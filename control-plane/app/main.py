from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
import httpx
import base64
import os
import logging
from pathlib import Path

from fastapi.security import APIKeyHeader

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def verify_api_key(api_key: str = Depends(api_key_header)):
    expected_api_key = os.environ.get("CONTROL_PLANE_API_KEY")
    if not expected_api_key:
        # If no key is configured, allow all requests (for backward compatibility/easy dev)
        # But log a warning in a production-like environment
        return
    if api_key != expected_api_key:
        raise HTTPException(status_code=403, detail="Invalid or missing API Key")

from . import models, schemas, database, etcd_client
from .database import engine

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Control Plane API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.post("/agents/register", dependencies=[Depends(verify_api_key)])
def register_agent(agent_data: schemas.AgentRegister, db: Session = Depends(get_db)):
    agent = db.query(models.Agent).filter(models.Agent.name == agent_data.agent_name).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found in registry")
    
    # Update agent info based on registration
    agent.status = "active"
    agent.docker_container_name = agent_data.docker_container_name
    
    # Create or update deployment status
    deployment = db.query(models.Deployment).filter(models.Deployment.agent_id == agent.id).first()
    if not deployment:
        deployment = models.Deployment(agent_id=agent.id)
        db.add(deployment)
    
    deployment.container_url = agent_data.container_url
    deployment.docker_status = "running"
    
    db.commit()
    
    return {
        "agent_id": agent.id,
        "status": "registered",
        "config_url": f"/agents/{agent.id}/config"
    }

@app.get("/agents/{agent_id}/config", dependencies=[Depends(verify_api_key)])
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

@app.get("/marketplace/agents", dependencies=[Depends(verify_api_key)])
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

@app.post("/marketplace/agents", response_model=schemas.Agent, dependencies=[Depends(verify_api_key)])
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

def deploy_tool_files(tool_id: int, files: List[schemas.ToolFile], db: Session):
    db_tool = db.query(models.Tool).filter(models.Tool.id == tool_id).first()
    if not db_tool:
        raise HTTPException(status_code=404, detail="Tool not found")
        
    tools_dir = os.environ.get("TOOLS_DIR", "/app/tools")
    base_tool_dir = db_tool.tool_directory
    
    # Strip tools/ prefix if it exists to avoid nested tools/tools/
    if base_tool_dir.startswith("tools/"):
        base_tool_dir = base_tool_dir[len("tools/"):]
        
    full_tool_path = (Path(tools_dir) / base_tool_dir).resolve()
    full_tool_path.mkdir(parents=True, exist_ok=True)
    
    for f in files:
        # Prevent path traversal by ensuring the resolved path is within the base tool directory
        requested_path = (full_tool_path / f.path).resolve()
        try:
            requested_path.relative_to(full_tool_path)
        except ValueError:
             logger.warning(f"Prevented path traversal attempt: {f.path}")
             continue
             
        requested_path.parent.mkdir(parents=True, exist_ok=True)
        with open(requested_path, "wb") as file:
            file.write(base64.b64decode(f.content))
        logger.info(f"Deployed file {f.path} for tool {tool_id}")

@app.post("/marketplace/tools", response_model=schemas.Tool, dependencies=[Depends(verify_api_key)])
def create_tool(tool_data: schemas.ToolRegister, db: Session = Depends(get_db)):
    db_tool = models.Tool(
        name=tool_data.name,
        description=tool_data.description,
        tool_directory=tool_data.tool_directory,
        entry_point_module=tool_data.entry_point_module,
        entry_point_function=tool_data.entry_point_function,
        etcd_secret_key=tool_data.etcd_secret_key,
        etcd_secret_key_reference=tool_data.etcd_secret_key_reference,
        is_active=True
    )
    db.add(db_tool)
    db.commit()
    db.refresh(db_tool)
    
    # If files are provided during registration, deploy them
    if tool_data.files:
        deploy_tool_files(db_tool.id, tool_data.files, db)
        
    return db_tool

@app.put("/marketplace/tools/{tool_id}", response_model=schemas.Tool, dependencies=[Depends(verify_api_key)])
def update_tool(tool_id: int, tool_data: schemas.ToolUpdate, db: Session = Depends(get_db)):
    db_tool = db.query(models.Tool).filter(models.Tool.id == tool_id).first()
    if not db_tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    
    for key, value in tool_data.model_dump(exclude_unset=True).items():
        setattr(db_tool, key, value)
    
    db.commit()
    db.refresh(db_tool)
    return db_tool

@app.post("/marketplace/tools/{tool_id}/deploy", dependencies=[Depends(verify_api_key)])
async def deploy_tool_endpoint(tool_id: int, deploy_data: schemas.ToolDeploy, db: Session = Depends(get_db)):
    deploy_tool_files(tool_id, deploy_data.files, db)
    # Trigger All Tools MCP Server to reload tools
    await reload_mcp()
    return {"status": "deployed", "mcp_reloaded": True}

@app.post("/admin/mcp-reload", dependencies=[Depends(verify_api_key)])
async def reload_mcp():
    # Trigger All Tools MCP Server to reload tools
    # We'll call its /reload endpoint
    mcp_url = "http://all-tools-mcp-server:8000/reload"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(mcp_url, timeout=10.0)
            return response.json()
        except Exception as e:
            # Fallback if MCP server doesn't have /reload yet or is unreachable
            return {"status": "error", "message": f"Failed to reload MCP server: {str(e)}"}

@app.put("/marketplace/agents/{agent_id}/tools", dependencies=[Depends(verify_api_key)])
def assign_agent_tools(agent_id: int, tool_data: List[int], db: Session = Depends(get_db)):
    # Remove existing links
    db.query(models.AgentToolLink).filter(models.AgentToolLink.agent_id == agent_id).delete()
    
    # Add new links
    for tid in tool_data:
        link = models.AgentToolLink(agent_id=agent_id, tool_id=tid)
        db.add(link)
    
    db.commit()
    return {"status": "success", "agent_id": agent_id, "tool_count": len(tool_data)}

@app.get("/marketplace/tools", dependencies=[Depends(verify_api_key)])
def list_marketplace_tools(db: Session = Depends(get_db)):
    tools = db.query(models.Tool).filter(models.Tool.is_active == True).all()
    return {"tools": tools}

@app.post("/marketplace/credentials", dependencies=[Depends(verify_api_key)])
def create_credential(cred: schemas.CredentialCreate):
    etcd_client.set_etcd_secret(cred.path, cred.value)
    return {"status": "created", "path": cred.path}

@app.get("/marketplace/credentials", dependencies=[Depends(verify_api_key)])
def list_credentials(prefix: str = ""):
    keys = etcd_client.list_etcd_secrets(prefix)
    return {"credentials": keys}

@app.get("/agents/{agent_id}/health", dependencies=[Depends(verify_api_key)])
async def check_agent_health(agent_id: int, db: Session = Depends(get_db)):
    agent = db.query(models.Agent).filter(models.Agent.id == agent_id).first()
    if not agent or not agent.docker_container_name:
        raise HTTPException(status_code=404, detail="Agent not found or not registered")

    health_url = f"http://{agent.docker_container_name}:{agent.port_openai}/health"
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(health_url, timeout=5.0)
            status = "healthy" if response.status_code == 200 else "unhealthy"
        except Exception:
            status = "unhealthy"

    # Update or create deployment status
    deployment = db.query(models.Deployment).filter(models.Deployment.agent_id == agent_id).first()
    if not deployment:
        deployment = models.Deployment(agent_id=agent_id)
        db.add(deployment)
    
    deployment.health_status = status
    deployment.last_health_check = datetime.utcnow()
    db.commit()
    
    return {"agent_id": agent_id, "status": status, "last_check": deployment.last_health_check}

@app.get("/agents/health", dependencies=[Depends(verify_api_key)])
async def check_all_agents_health(db: Session = Depends(get_db)):
    agents = db.query(models.Agent).filter(models.Agent.status == "active").all()
    results = []
    for agent in agents:
        try:
            health = await check_agent_health(agent.id, db)
            results.append(health)
        except HTTPException:
            continue
    return {"agents": results}

@app.post("/v1/chat/completions", dependencies=[Depends(verify_api_key)])
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
