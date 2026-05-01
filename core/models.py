from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any

class AgentConfig(BaseModel):
    """Configuration for an Agent, parsed from config.yaml."""
    name: str
    version: str = "0.1.0"
    author: str = "Unknown"
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    type: Literal['standard', 'background'] = 'standard'
    model: str
    thinking_level: Literal['none', 'low', 'medium', 'high', 'n/a']
    a2a_access: List[str] = Field(default_factory=list, description="List of other agents this agent can call.")
    allowed_tools: List[str] = Field(default_factory=list, description="List of MCP tools this agent is allowed to use.")
    allowed_mcps: List[str] = Field(default_factory=list, description="List of MCP servers this agent is allowed to connect to.")

class MCPToolDefinition(BaseModel):
    name: str
    description: str
    inputSchema: dict

class MCPConfig(BaseModel):
    """Configuration for an external MCP server, parsed from mcp.yaml or DB."""
    name: str
    transport: Literal["stdio", "sse"] = "stdio"
    command: Optional[str] = None
    args: Optional[List[str]] = Field(default_factory=list)
    env: Optional[Dict[str, str]] = Field(default_factory=dict)
    secrets: Optional[List[str]] = Field(default_factory=list, description="List of user secrets required by this MCP.")
    tools: Optional[List[MCPToolDefinition]] = Field(default_factory=list, description="Optional statically defined tools to bypass dynamic discovery.")

class ToolConfig(BaseModel):
    """Configuration for a Tool, parsed from tool.yaml."""
    name: str
    version: str = "0.1.0"
    description: str
    runtime: str = Field(..., pattern="^(python|go|ts|bash)$")
    entrypoint: str
    inputs: Optional[Dict[str, Any]] = None
    outputs: Optional[Dict[str, Any]] = None
    secrets: Optional[List[str]] = Field(default_factory=list)
