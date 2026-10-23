# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import logging
import re

from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Optional, Literal, Dict, Any, Union
from enum import Enum

from core.llm_providers import ALLOWED_PROVIDERS, provider_requires_base_url

logger = logging.getLogger(__name__)

# 15 selectable LLM providers; the registry lives in core/llm_providers.py.
# `openai-compatible` targets any OpenAI-compatible endpoint via `base_url`.


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
    provider: Optional[str] = Field(default=None, description="LLM provider. None infers from the model name prefix: gemini* -> google; claude* -> anthropic; gpt-*/o1*/o3*/o4*/chatgpt* -> openai; plus deepseek*, kimi*, glm*, qwen* -> their providers.")
    base_url: Optional[str] = Field(default=None, description="Custom API endpoint. Required for 'openai-compatible'.")
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

    @model_validator(mode="after")
    def _require_base_url_for_provider(self) -> "AgentConfig":
        """Surface a provider's base_url requirement at config-load time
        instead of failing later inside resolve_model mid-build."""
        if provider_requires_base_url(self.provider) and not self.base_url:
            raise ValueError(
                f"Provider '{self.provider}' requires a base_url pointing at the endpoint."
            )
        return self


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

# An edge name (site / exported tool / exported MCP): `NAME_RE` with `__` banned.
#
# pydantic-core's regex engine has no lookarounds, so "no `__` anywhere" is spelled
# structurally instead of `(?!.*__)`: an underscore may only appear when followed by a
# non-underscore character (or at the very end). That rejects `a__b`, `a__`, `__a`.
_EDGE_REF_NAME_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9-]|_[A-Za-z0-9-])*_?$"


# --- Public reference forms (v0.5.0 L7; documented manifest API) -------------------
# One site / MCP / tool name: `NAME_RE`'s character set and 64-char cap with `__` banned
# structurally (`_` must be followed by an alphanumeric or `-`). The same
# ban is enforced at every write boundary -- the relay's `_check_namespace`, the
# `Remote*Spec` patterns above, `save_mcp_config`, `sync_mcp` -- and it is repeated here
# on purpose: it is what makes each form below a *single* unambiguous statement.
# Without it, `mcp__dc1__mcp__tool` would also match the 3-part central form (server
# `dc1__mcp`), and `dc1__a__b` would read as an edge MCP named `a__b`.
#
# Deliberately stricter than `NAME_RE` in one respect: a segment may not *end* with `_`
# (`a_` is rejected). A trailing underscore is legal for a name on its own, but inside a
# ref it makes the `__` boundary ambiguous -- `a___b` would be "site `a_` + `b`" or
# "site `a` + name `_b`" depending on the split direction. One character per repetition
# (`{0,63}` after the mandatory first character) keeps the length at 1..64; the
# lookahead is a Python-`re` feature, so this form is for the documented refs only --
# pydantic-core (`_EDGE_REF_NAME_PATTERN`) spells the ban without one.
_EDGE_REF_SEGMENT = r"[A-Za-z0-9](?:[A-Za-z0-9-]|_(?=[A-Za-z0-9-])){0,63}"
_EDGE_REF_PAIR = rf"{_EDGE_REF_SEGMENT}__{_EDGE_REF_SEGMENT}"

# `<site>__<tool>`: an edge tool, the registry key `/registry/tools/<site>__<tool>`.
EDGE_TOOL_REF_RE = re.compile(rf"^{_EDGE_REF_PAIR}$")
# `<site>__<mcp>`: an edge MCP server, the registry key `/registry/mcps/<site>__<mcp>`,
# and a valid entry in an agent's `allowed_mcps`.
EDGE_MCP_REF_RE = re.compile(rf"^{_EDGE_REF_PAIR}$")
# `<site>__*`: optional sugar in `allowed_mcps` for every MCP that site currently
# exports. Expanded against discovery at build time; never stored expanded.
EDGE_MCP_WILDCARD_RE = re.compile(rf"^{_EDGE_REF_SEGMENT}__\*$")
# `mcp__<site>__<mcp>__<tool>`: 4 parts -- the agent/gateway name of an edge MCP tool.
EDGE_MCP_TOOL_REF_RE = re.compile(rf"^mcp__{_EDGE_REF_PAIR}__{_EDGE_REF_SEGMENT}$")
# `mcp__<server>__<tool>`: 3 parts -- a central MCP tool. Because a central MCP name
# may not contain `__`, the 4-part name above cannot also read as this form, and a
# 3-part name can never be mistaken for an edge target (see
# `core.discovery.resolve_edge_mcp_target`, which still lets the registry decide).
CENTRAL_MCP_TOOL_REF_RE = re.compile(rf"^mcp__{_EDGE_REF_PAIR}$")


class RemoteMcpSpec(BaseModel):
    """Where a remote (edge-hosted) MCP server actually executes.

    ``site`` is the edge id and the routing key; ``mcp`` is the server's name in
    that edge's exported catalog. Both are written by the edge relay from the
    catalog the edge published, never by a caller or an ``mcp.yaml``.

    Neither may contain ``__`` (see ``_EDGE_REF_NAME_PATTERN``): that separator is what
    makes ``mcp__<site>__<mcp>__<tool>`` split, and the two halves form a registry key.
    """
    site: str = Field(..., pattern=_EDGE_REF_NAME_PATTERN, max_length=64)
    mcp: str = Field(..., pattern=_EDGE_REF_NAME_PATTERN, max_length=64)


class ContainerLimits(BaseModel):
    """cgroup v2 limits for one container.

    ``tmpfs_mb`` is validated against ``memory_mb``: tmpfs pages are charged to
    the container's cgroup, so a tmpfs at or near the memory limit makes the
    first temp file an OOM kill.
    """

    memory_mb: int = Field(default=512, ge=32, le=65536)
    cpus: float = Field(default=1.0, gt=0, le=64)
    pids: int = Field(default=256, ge=16, le=32768)
    tmpfs_mb: int = Field(default=128, ge=1, le=32768)

    @model_validator(mode="after")
    def _tmpfs_bounded(self) -> "ContainerLimits":
        if self.tmpfs_mb * 2 > self.memory_mb:
            raise ValueError("limits.tmpfs_mb must be at most half of limits.memory_mb")
        return self


def mcp_limits() -> "ContainerLimits":
    """Node-based stdio servers need more headroom than a Python tool."""
    return ContainerLimits(memory_mb=2048, cpus=2.0, pids=512, tmpfs_mb=512)



class MCPConfig(BaseModel):
    """Configuration for an external MCP server, parsed from mcp.yaml or DB."""
    name: str
    transport: Literal["stdio", "sse", "http", "streamable-http", "remote"] = "stdio"
    command: Optional[str] = None
    args: Optional[List[str]] = Field(default_factory=list)
    env: Optional[Dict[str, str]] = Field(default_factory=dict)
    public: bool = Field(default=False, description="Expose all tools from this MCP server publicly.")
    public_tools: List[str] = Field(default_factory=list, description="Whitelist of specific tool names exposed publicly.")
    secrets: Optional[Union[List[str], Dict[str, List[str]]]] = Field(default_factory=list, description="List of user secrets required by this MCP.")
    optional_secrets: Optional[List[str]] = Field(default_factory=list, description="Secrets injected when present but not required for the MCP to start.")
    variables: Optional[Union[List[str], Dict[str, List[str]]]] = Field(default_factory=list, description="List of non-sensitive configuration variables required by this MCP.")
    tools: Optional[List[MCPToolDefinition]] = Field(default_factory=list, description="Optional statically defined tools to bypass dynamic discovery.")
    network: str = Field(default="none", description="Network profile for this MCP server's stdio container: 'none' (default), 'internal' or 'internet'. Legacy 'allow' maps to 'internet'. Only stdio servers spawn a process; http/sse transports ignore it.")
    remote: Optional[RemoteMcpSpec] = Field(default=None, description="Set for edge-hosted MCP servers: the site and the server name inside that site's catalog. Written only by the edge relay, never parsed from an mcp.yaml. Remote servers are never connected from central: calls are POSTed to the relay, and their tools come from the static `tools` catalog.")
    container_runtime: Optional[str] = Field(default=None, description="OCI runtime for this server's session container: runsc (default), runsc-variant or runc. None uses CONTAINER_DEFAULT_RUNTIME.")
    limits: ContainerLimits = Field(default_factory=mcp_limits, description="Container limits. Defaults are sized for Node-based stdio servers.")
    session_idle_ttl_minutes: int = Field(default=30, ge=1, le=1440, description="Idle TTL for a warm session container. The edge's proxy.yaml export TTL stays authoritative there.")

    @field_validator("network")
    @classmethod
    def _normalize_network(cls, value: str) -> str:
        return normalize_network_policy(value, "mcp")

class RemoteToolSpec(BaseModel):
    """Where a remote (edge-hosted) tool actually executes.

    ``site`` is both the edge id and the routing key; it is written by the edge
    relay from the catalog the edge published, never by a caller. Neither field may
    contain ``__`` (see ``_EDGE_REF_NAME_PATTERN``): a site is the left half of
    ``<site>__<tool>``, and a tool name is the last segment of an
    ``mcp__<site>__<mcp>__<tool>`` reference.
    """
    site: str = Field(..., pattern=_EDGE_REF_NAME_PATTERN, max_length=64)
    tool: str = Field(..., pattern=_EDGE_REF_NAME_PATTERN, max_length=64)


_WARNED_NETWORK_POLICIES: set[str] = set()


def normalize_network_policy(value: Any, what: str) -> str:
    """Normalize a manifest's network field onto the v0.6 profile enum.

    ``allow`` keeps its old meaning (``internet``); everything else is
    deny-by-default. As a Literal a typo (`network: deny`) raised
    ValidationError, and the loaders drop any config that fails to parse. The
    safer failure is the *most restrictive* profile plus a visible warning --
    note the flip from v0.5, where an unknown value fell back to `allow`.
    Shared by ToolConfig and MCPConfig so the two cannot drift.
    """
    normalized = str(value if value is not None else "").strip().lower()
    aliases = {
        "allow": "internet",
        "internet": "internet",
        "internal": "internal",
        "none": "none",
        "deny": "none",
        "off": "none",
        "": "none",
    }
    if normalized in aliases:
        return aliases[normalized]
    key = f"{what}:{normalized}"
    if key not in _WARNED_NETWORK_POLICIES:
        _WARNED_NETWORK_POLICIES.add(key)
        logger.warning(
            "Invalid %s network policy %r; falling back to 'none'. "
            "Use 'none', 'internal' or 'internet'.",
            what,
            value,
        )
    return "none"


class ToolConfig(BaseModel):
    """Configuration for a Tool, parsed from tool.yaml."""
    name: str
    version: str = "0.1.0"
    description: str
    runtime: str = Field(..., pattern="^(python|go|ts|bash|remote)$")
    entrypoint: str = ""
    remote: Optional[RemoteToolSpec] = Field(default=None, description="Set for edge-hosted tools: the site and the tool name inside that site's catalog. Remote tools have no local entrypoint and no central secrets.")
    public: bool = Field(default=False, description="Expose this tool directly to external MCP clients and gateway search.")
    inputs: Optional[Dict[str, Any]] = None
    outputs: Optional[Dict[str, Any]] = None
    secrets: Optional[Union[List[str], Dict[str, List[str]]]] = Field(default_factory=list)
    optional_secrets: Optional[List[str]] = Field(default_factory=list, description="Secrets injected when present but not required for the tool to run.")
    variables: Optional[Union[List[str], Dict[str, List[str]]]] = Field(default_factory=list)
    secret_groups: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="UI hint for /configuration: renders a set of optional_secrets as a single card with a selector (e.g. an environment dropdown) instead of flat rows. Each group: {label, select_label, options: [{value, label, fields: [{key, label, type}]}]}.")
    timeout_seconds: Optional[int] = Field(default=None, description="Per-tool subprocess execution timeout in seconds. Overrides the TOOL_EXECUTION_TIMEOUT env default (300s) when set. Timeouts are immediately fatal (never retried).")
    retry_on_transient: bool = Field(default=True, description="Allow automatic retry (up to 3 attempts) when the tool fails fast with a transient network error. Set false for tools with non-idempotent side effects (creates/updates/writes) so a transient failure surfaces to the caller instead of re-executing.")
    network: str = Field(default="none", description="Network profile for this tool's container: 'none' (default), 'internal' or 'internet'. Legacy 'allow' maps to 'internet'. Use 'none' for tools that never call external APIs.")
    egress: List[str] = Field(default_factory=list, description="External domains this tool may reach when egress mode is enabled. v1 enforcement is the union across all tools; see docs/deploy.md.")
    container_runtime: Optional[str] = Field(default=None, description="OCI runtime for this tool's container: runsc (default), runsc-variant or runc. None uses CONTAINER_DEFAULT_RUNTIME. `runc` forfeits kernel-syscall isolation and must be justified per tool.")
    limits: ContainerLimits = Field(default_factory=ContainerLimits, description="cgroup v2 limits for one tool container (memory/cpus/pids/tmpfs).")
    output_dirs: List[str] = Field(default_factory=list, description="Subset of [reports, output]. Declaring one grants a read-write mount of that directory for the calling agent only.")
    image: Optional[str] = Field(default=None, description="Reserved. Per-tool images are not implemented in v0.6 and this field is ignored.")

    @field_validator("network")
    @classmethod
    def _normalize_network(cls, value: str) -> str:
        return normalize_network_policy(value, "tool")

    @field_validator("container_runtime")
    @classmethod
    def _validate_runtime(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = str(value).strip()
        if normalized not in {"runsc", "runsc-variant", "runc"}:
            raise ValueError(
                "container_runtime must be one of runsc, runsc-variant, runc"
            )
        return normalized

    @field_validator("output_dirs")
    @classmethod
    def _validate_output_dirs(cls, value: List[str]) -> List[str]:
        normalized = [str(v).strip() for v in value]
        invalid = sorted({v for v in normalized if v not in {"reports", "output"}})
        if invalid:
            raise ValueError(
                f"output_dirs may only contain 'reports' and 'output' (got {invalid})"
            )
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def _validate_remote(self) -> "ToolConfig":
        """A tool is either local (entrypoint required) or remote (pointer only).

        ``rel_path`` is not part of the model; ``load_tool_configs`` keeps it out of
        the parsed config and resolves the directory separately. Remote configs have
        no directory at all, so the runtime tag is what tells the hub which branch of
        ``run_tool`` to take.
        """
        if self.remote is not None:
            if self.runtime != "remote":
                raise ValueError("a tool with `remote` set must use runtime: remote")
            self.entrypoint = ""
        elif self.runtime == "remote":
            raise ValueError("runtime: remote requires a `remote: {site, tool}` block")
        elif not self.entrypoint:
            raise ValueError("entrypoint is required for a non-remote tool")
        return self
