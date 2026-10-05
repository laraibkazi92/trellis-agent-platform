# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Literal, Dict, Any, Union
from enum import Enum

# LLM providers core/llm_factory.py can resolve. `openai-compatible` targets any
# OpenAI-compatible endpoint via `base_url`.
ALLOWED_PROVIDERS = ("google", "openai", "anthropic", "ollama", "openai-compatible")


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

class AgentRule(BaseModel):
    """Declarative operational routing rule for a specific agent."""
    description: Optional[str] = Field(
        default=None,
        description="Brief summary of what this rule governs."
    )
    use_when: List[str] = Field(
        default_factory=list,
        description="Positive operational conditions when this agent MUST be selected."
    )
    do_not_use_when: List[str] = Field(
        default_factory=list,
        description="Strict negative boundaries when this agent MUST NOT be selected."
    )
    examples: List[str] = Field(
        default_factory=list,
        description="Representative user queries matching this rule."
    )


class GlobalRule(BaseModel):
    """Central organizational override rule for cross-agent dispute resolution."""
    rule_id: str = Field(
        description="Unique identifier for the global rule (e.g. override-pcap-triage)."
    )
    target_agent: str = Field(
        description="Exact agent name that this rule locks onto."
    )
    description: Optional[str] = Field(
        default=None,
        description="Operational context and justification for the override."
    )
    use_when: List[str] = Field(
        default_factory=list,
        description="Positive operational conditions triggering this global override."
    )
    do_not_use_when: List[str] = Field(
        default_factory=list,
        description="Strict negative boundaries disqualifying this global override."
    )
    examples: List[str] = Field(
        default_factory=list,
        description="Representative user queries matching this override."
    )


class RoutingRulesConfig(BaseModel):
    """Top-level schema for workspace/routing_rules.yaml."""
    version: str = Field(default="1.0")
    global_rules: List[GlobalRule] = Field(default_factory=list)


class RuleEvaluationResult(BaseModel):
    """Structured LLM decision output for rule evaluation."""
    matched_agent: Optional[str] = Field(
        default=None,
        description="Exact name of the matching agent if a rule positively locks onto the query, or null if no rule matches."
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0 reflecting how unambiguously the query matches the rule criteria."
    )
    reasoning: str = Field(
        default="",
        description="Brief explanation of why the rule matched or why no rule applied."
    )


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
    provider: Optional[str] = Field(default=None, description="LLM provider. None infers from the model name prefix (gemini*/claude*/gpt-*/o1*/o3*/o4*/chatgpt*).")
    base_url: Optional[str] = Field(default=None, description="Custom API endpoint. Required for 'openai-compatible', optional for 'ollama'.")
    a2a_access: List[str] = Field(default_factory=list, description="List of other agents this agent can call.")
    allowed_tools: List[str] = Field(default_factory=list, description="List of MCP tools this agent is allowed to use.")
    allowed_mcps: List[str] = Field(default_factory=list, description="List of MCP servers this agent is allowed to connect to.")
    agent_memory: bool = Field(default=False, description="Opt this agent into per-agent persistent memory (Hindsight). Requires the admin 'agent_memory_enabled' feature flag to also be on.")
    external: bool = Field(default=True, description="Available for direct consumption by users, Host API, Gateway MCP, and Supervisor agent.")
    internal: bool = Field(default=True, description="Available to be called by other specialized agents via a2a_access.")
    rules: List[AgentRule] = Field(default_factory=list, description="Declarative routing rules evaluated by the Trellis Rules Engine before semantic search.")

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, value: Optional[str]) -> Optional[str]:
        """Reject unknown providers at config load; empty string counts as unset (inferred)."""
        if value is None:
            return None
        normalized = value.strip().lower()
        if not normalized:
            return None
        if normalized not in ALLOWED_PROVIDERS:
            raise ValueError(
                f"Unknown provider '{value}'. Valid providers: {', '.join(ALLOWED_PROVIDERS)}."
            )
        return normalized

    @field_validator("base_url")
    @classmethod
    def _strip_base_url(cls, value: Optional[str]) -> Optional[str]:
        return (value or "").strip() or None


def coerce_bool_flag(value, default: bool = True) -> bool:
    """Normalize a raw config value (bool, YAML/string, or missing) to a real bool.

    Handles legacy config.yaml values that were YAML-quoted as strings (e.g. "false")
    instead of real booleans, so downstream checks always operate on genuine bools.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "1", "on"):
            return True
        if v in ("false", "no", "0", "off"):
            return False
        return default
    return bool(value)


def is_agent_external(cfg: Optional[dict]) -> bool:
    """True unless the config explicitly sets external: false. Fail-open on missing/malformed values."""
    return coerce_bool_flag((cfg or {}).get("external"), default=True)


def is_agent_internal(cfg: Optional[dict]) -> bool:
    """True unless the config explicitly sets internal: false. Fail-open on missing/malformed values."""
    return coerce_bool_flag((cfg or {}).get("internal"), default=True)


BACKGROUND_AGENT_TYPES = ("background_agent", "background_script")


def is_routable_agent_type(name: str, cfg: Optional[dict]) -> bool:
    """False for the supervisor or a background agent/script; True for an ordinary routable agent.

    Single source of truth for the structural exclusion every agent-listing
    surface (discovery, ranked search, rules-engine eligibility, Gateway
    visibility, Host health reporting) needs to apply before layering on its
    own additional filters (external/internal, disabled, offline, etc.).
    """
    return name != "supervisor" and (cfg or {}).get("type") not in BACKGROUND_AGENT_TYPES

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
    public: bool = Field(default=False, description="Expose all tools from this MCP server publicly.")
    public_tools: List[str] = Field(default_factory=list, description="Whitelist of specific tool names exposed publicly.")
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
    public: bool = Field(default=False, description="Expose this tool directly to external MCP clients and gateway search.")
    inputs: Optional[Dict[str, Any]] = None
    outputs: Optional[Dict[str, Any]] = None
    secrets: Optional[Union[List[str], Dict[str, List[str]]]] = Field(default_factory=list)
    optional_secrets: Optional[List[str]] = Field(default_factory=list, description="Secrets injected when present but not required for the tool to run.")
    variables: Optional[Union[List[str], Dict[str, List[str]]]] = Field(default_factory=list)
    secret_groups: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="UI hint for /configuration: renders a set of optional_secrets as a single card with a selector (e.g. an environment dropdown) instead of flat rows. Each group: {label, select_label, options: [{value, label, fields: [{key, label, type}]}]}.")
    timeout_seconds: Optional[int] = Field(default=None, description="Per-tool subprocess execution timeout in seconds. Overrides the TOOL_EXECUTION_TIMEOUT env default (300s) when set. Timeouts are immediately fatal (never retried).")
    retry_on_transient: bool = Field(default=True, description="Allow automatic retry (up to 3 attempts) when the tool fails fast with a transient network error. Set false for tools with non-idempotent side effects (creates/updates/writes) so a transient failure surfaces to the caller instead of re-executing.")
