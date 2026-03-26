from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime

class ToolBase(BaseModel):
    name: str
    description: Optional[str] = None
    tool_directory: str
    entry_point_module: str
    entry_point_function: str
    etcd_secret_key: Optional[str] = None
    etcd_secret_key_reference: bool = False

class ToolCreate(ToolBase):
    pass

class Tool(ToolBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AgentBase(BaseModel):
    name: str
    model_provider: str
    model_name: str
    system_prompt: Optional[str] = None
    docker_container_name: Optional[str] = None
    status: Optional[str] = "inactive"

class AgentCreate(AgentBase):
    assigned_tool_ids: List[int] = []

class Agent(AgentBase):
    id: int
    port_openai: int
    port_mcp: int
    port_a2a: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AgentRegister(BaseModel):
    agent_name: str
    container_url: str
    docker_container_name: str

class ToolFile(BaseModel):
    path: str
    content: str  # base64 encoded
    size: int

class ToolRegister(ToolCreate):
    files: List[ToolFile] = []

class ToolDeploy(BaseModel):
    files: List[ToolFile]

class ToolUpdate(BaseModel):
    description: Optional[str] = None
    etcd_secret_key: Optional[str] = None
    etcd_secret_key_reference: Optional[bool] = None
    is_active: Optional[bool] = None

class CredentialCreate(BaseModel):
    path: str
    value: dict
