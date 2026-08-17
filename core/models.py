from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any, Union
from enum import Enum

class IdentityType(str, Enum):
    USER = "user"
    WORKFLOW = "workflow"
    SYSTEM = "system"

class Identity(BaseModel):
    id: str
    type: IdentityType

    @classmethod
    def from_string(cls, id_str: str) -> "Identity":
        """
        Parses an identity string into an Identity object.
        Handles legacy 'svc_agent_' prefixes by mapping them to IdentityType.WORKFLOW.
        """
        if id_str.startswith("svc_agent_"):
            return cls(id=id_str.replace("svc_agent_", ""), type=IdentityType.WORKFLOW)
        if id_str == "system":
            return cls(id="system", type=IdentityType.SYSTEM)
        return cls(id=id_str, type=IdentityType.USER)

    def to_legacy_string(self) -> str:
        """Returns the legacy string representation (e.g. adding 'svc_agent_' prefix)."""
        if self.type == IdentityType.WORKFLOW:
            return f"svc_agent_{self.id}"
        return self.id

    def get_etcd_path(self, category: str) -> str:
        """Returns the structured etcd path: /identities/{type}/{id}/{category}"""
        return f"/identities/{self.type.value}/{self.id}/{category}"

class AgentConfig(BaseModel):
    """Configuration for an Agent, parsed from config.yaml."""
    name: str
    version: str = "0.1.0"
    author: str = "Unknown"
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    type: Literal['user_agent', 'background_agent', 'background_script'] = 'user_agent'
    model: Optional[str] = None
    thinking_level: Optional[Literal['none', 'low', 'medium', 'high', 'n/a']] = None
    a2a_access: List[str] = Field(default_factory=list, description="List of other agents this agent can call.")
    allowed_tools: List[str] = Field(default_factory=list, description="List of MCP tools this agent is allowed to use.")
    allowed_mcps: List[str] = Field(default_factory=list, description="List of MCP servers this agent is allowed to connect to.")
    agent_memory: bool = Field(default=False, description="Opt this agent into per-agent persistent memory (Hindsight). Requires the admin 'agent_memory_enabled' feature flag to also be on.")

class MCPToolDefinition(BaseModel):
    name: str
    description: str
    inputSchema: dict

class MCPConfig(BaseModel):
    """Configuration for an external MCP server, parsed from mcp.yaml or DB."""
    name: str
    transport: Literal["stdio", "sse", "http", "streamable-http"] = "stdio"
    command: Optional[str] = None
    args: Optional[List[str]] = Field(default_factory=list)
    env: Optional[Dict[str, str]] = Field(default_factory=dict)
    secrets: Optional[Union[List[str], Dict[str, List[str]]]] = Field(default_factory=list, description="List of user secrets required by this MCP.")
    optional_secrets: Optional[List[str]] = Field(default_factory=list, description="Secrets injected when present but not required for the MCP to start.")
    variables: Optional[Union[List[str], Dict[str, List[str]]]] = Field(default_factory=list, description="List of non-sensitive configuration variables required by this MCP.")
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
    secrets: Optional[Union[List[str], Dict[str, List[str]]]] = Field(default_factory=list)
    variables: Optional[Union[List[str], Dict[str, List[str]]]] = Field(default_factory=list)
