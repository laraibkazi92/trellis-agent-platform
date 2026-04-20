from pydantic import BaseModel, Field
from typing import List, Optional

class AgentConfig(BaseModel):
    """Configuration for an Agent, parsed from config.yaml."""
    name: str
    version: str = "0.1.0"
    description: Optional[str] = None
    model: str = "gemini-2.0-flash"
    a2a_access: List[str] = Field(default_factory=list, description="List of other agents this agent can call.")

class ToolConfig(BaseModel):
    """Configuration for a Tool, parsed from tool.yaml."""
    name: str
    version: str = "0.1.0"
    description: str
    runtime: str = Field(..., pattern="^(python|go|ts)$")
    entrypoint: str
