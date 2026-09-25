"""Semantic tool discovery for Direct Tool Gateway Execution (see ``core.gateway.search_tools``).

Mirrors ``core.agent_search``: ranks publicly-whitelisted tools via Gemini embeddings
cached in etcd at sync time (see ``scripts/sync_to_db.py``), falling back to keyword
matching when embeddings are unavailable. Only tools/MCP tools explicitly marked
``public`` are ever considered candidates — internal tools are never returned
regardless of query, per the secure-by-default whitelisting model.
"""
import os
import re
import asyncio
import logging
from typing import List, Dict, Any, Optional

from core.auth import get_identity_manager
from core.embeddings import embed_text, cosine
from core.discovery import is_tool_configured

logger = logging.getLogger(__name__)

DEFAULT_LIMIT = int(os.getenv("TOOL_SEARCH_LIMIT", "8"))

identity_mgr = get_identity_manager()


def _keyword_rank_tools(query: str, candidates: List[Dict]) -> List[Dict]:
    """Fallback ranking: count query-term hits across name/description."""
    terms = [t for t in re.split(r"\W+", query.lower()) if t]

    def score(c: Dict) -> int:
        haystack = f"{c['name']} {c['description']}".lower()
        return sum(1 for t in terms if t in haystack)

    return sorted(candidates, key=lambda c: (-score(c), c["name"].lower()))


def _local_tool_parameters(config: Dict) -> Dict[str, Any]:
    """Local tool.yaml `inputs` are already shaped as {name: {type, description, required}}."""
    parameters = {}
    for key, spec in (config.get("inputs") or {}).items():
        if isinstance(spec, dict):
            parameters[key] = {
                "type": spec.get("type", "any"),
                "description": spec.get("description", ""),
                "required": spec.get("required", False),
            }
        else:
            parameters[key] = {"type": "any", "description": "", "required": False}
    return parameters


def _mcp_tool_parameters(input_schema: Dict) -> Dict[str, Any]:
    """MCP tools describe parameters via a JSON-Schema `inputSchema`."""
    parameters = {}
    properties = (input_schema or {}).get("properties", {})
    required = (input_schema or {}).get("required", [])
    for prop_name, prop_details in properties.items():
        parameters[prop_name] = {
            "type": prop_details.get("type", "string"),
            "description": prop_details.get("description", ""),
            "required": prop_name in required,
        }
    return parameters


def _missing_configuration_labels(status: Dict[str, Any]) -> List[str]:
    """Shape-safe flattening of a readiness status's missing_* fields for display.

    A bare string is a single label (not a character sequence); non-iterable
    values (e.g. a malformed int) degrade to no labels instead of raising, and
    non-string entries are stringified so the join can't fail.
    """
    labels: List[str] = []
    for key in ("missing_secrets", "missing_variables"):
        value = status.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            labels.append(value)
            continue
        try:
            labels.extend(str(m) for m in value)
        except TypeError:
            continue
    return labels


async def search_tools(query: str, limit: int = DEFAULT_LIMIT, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return up to ``limit`` publicly-whitelisted tools most relevant to ``query``.

    Each result is a Tool Card: ``{"name", "description", "parameters", "configured",
    "status", "source"}``. Local tools are included only if their ``tool.yaml`` sets
    ``public: true``. MCP tools are included only if the owning MCP config sets
    ``public: true`` or lists the tool name in ``public_tools``; their returned
    ``name`` is the ``mcp__{server}__{tool}`` form so it can be passed straight to
    ``use_tool`` for execution. Internal (non-whitelisted) tools are never returned,
    regardless of how well they match the query.

    If ``user_id`` is provided, each result's configuration status is resolved via
    ``is_tool_configured``; unconfigured tools get ``configured: False`` and their
    description gains a trailing note naming the missing secrets/variables.

    Pass ``limit <= 0`` to get the full ranked list (mirrors ``search_agents``).
    """
    tool_configs = await asyncio.to_thread(identity_mgr.get_all_tool_configs)
    mcp_configs = await asyncio.to_thread(identity_mgr.get_all_mcp_configs)
    embeddings = await asyncio.to_thread(identity_mgr.get_all_tool_embeddings)
    try:
        health = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "tool")
    except Exception:
        health = {}

    candidates: List[Dict] = []

    for name, config in tool_configs.items():
        # Re-check visibility at query time (not just embedding presence) since a tool
        # may have been demoted to internal after being indexed — embeddings are only
        # pruned on deletion, not on demotion. Strict `is True` (not truthy) since these
        # are unvalidated raw etcd dicts and this is a secure-by-default whitelist: a
        # malformed `public: "false"` must fail closed, not leak the tool.
        if config.get("public") is not True:
            continue
        candidates.append({
            "name": config.get("name", name),
            "description": config.get("description", ""),
            "parameters": _local_tool_parameters(config),
            "status": (health.get(name) or {}).get("status", "Online"),
            "source": "local",
            "_vec": embeddings.get(name),
        })

    for mcp_name, mcp_config in mcp_configs.items():
        mcp_public = mcp_config.get("public") is True
        public_tools_raw = mcp_config.get("public_tools", [])
        public_tools = set(public_tools_raw) if isinstance(public_tools_raw, list) else set()
        for t in mcp_config.get("tools", []) or []:
            tool_name = t.get("name", "")
            if not tool_name or not (mcp_public or tool_name in public_tools):
                continue
            prefixed_name = f"mcp__{mcp_name}__{tool_name}"
            candidates.append({
                "name": prefixed_name,
                "description": t.get("description", ""),
                "parameters": _mcp_tool_parameters(t.get("inputSchema", {})),
                "status": "Online",
                "source": mcp_name,
                # No embedding is ever indexed for individual MCP tools today (see
                # scripts/sync_to_db.py) — this is always None, falling back to
                # cosine(_, None) == 0.0 under embedding ranking (or the keyword fallback
                # otherwise). Keyed by the prefixed name so that if/when MCP tool
                # embeddings are added later, this lookup is already correct rather than
                # colliding with an unrelated local tool of the same bare name.
                "_vec": embeddings.get(prefixed_name),
            })

    if not candidates:
        return []

    query_vec = await asyncio.to_thread(embed_text, query, "retrieval_query")
    if query_vec:
        ranked = sorted(candidates, key=lambda c: cosine(query_vec, c.get("_vec")), reverse=True)
    else:
        logger.warning("Embeddings unavailable; using keyword fallback for tool search.")
        ranked = _keyword_rank_tools(query, candidates)

    selected = ranked if limit is None or limit <= 0 else ranked[:limit]

    statuses = [None] * len(selected)
    if user_id is not None:
        statuses = await asyncio.gather(
            *(is_tool_configured(c["name"], user_id) for c in selected),
            return_exceptions=True,
        )

    results = []
    for c, status in zip(selected, statuses):
        description = c["description"]
        configured = True
        if isinstance(status, BaseException):
            logger.warning("Configuration check failed for tool %r: %s", c["name"], status)
        elif status is not None:
            if not isinstance(status, dict):
                logger.warning("Malformed configuration status for tool %r: %r", c["name"], status)
            else:
                configured = bool(status.get("configured"))
                if not configured:
                    missing = _missing_configuration_labels(status)
                    missing_text = ", ".join(missing) if missing else "required configuration"
                    description = f"{description}\n\n[Missing configuration: {missing_text}. Configure at /configuration]"
        results.append({
            "name": c["name"],
            "description": description,
            "parameters": c["parameters"],
            "configured": configured,
            "status": c["status"],
            "source": c["source"],
        })
    return results


async def is_tool_publicly_whitelisted(tool_name: str, identity_manager: Optional[Any] = None) -> bool:
    """Authorization Guard for `use_tool`: check `public`/`public_tools` directly against
    the tool's/MCP's own registry config, independent of `search_tools`.

    Fails closed on anything unexpected (unknown tool, malformed `mcp__` name, non-`True`
    `public` value, non-list `public_tools`) — mirrors the secure-by-default checks
    already applied in `is_tool_configured`/`search_tools`.
    """
    mgr = identity_manager or identity_mgr
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) != 3:
            return False
        _, server_name, sub_tool_name = parts
        config = await asyncio.to_thread(mgr.get_mcp_config, server_name)
        if not config:
            return False
        public_tools_raw = config.get("public_tools", [])
        public_tools = set(public_tools_raw) if isinstance(public_tools_raw, list) else set()
        return config.get("public") is True or sub_tool_name in public_tools

    config = await asyncio.to_thread(mgr.get_tool_config, tool_name)
    if not config:
        return False
    return config.get("public") is True


async def execute_whitelisted_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    user_id: Optional[str],
    *,
    identity_manager=None,
    is_configured=is_tool_configured,
    get_hub_client_fn=None,
    get_external_mcp_client_fn=None,
) -> Any:
    """Shared use_tool execution flow: whitelist check -> configuration check -> dispatch -> output extraction.

    Returns the raw structured tool output, or a 'SYSTEM: ...' error string. Callers inject
    their own module-level seams (`is_configured`, hub/external client getters) so existing
    monkeypatch targets keep working; `identity_manager` defaults to this module's
    `identity_mgr` (the `is_configured` default binds this module's name at def time).
    """
    mgr = identity_manager or identity_mgr

    try:
        whitelisted = await is_tool_publicly_whitelisted(tool_name, mgr)
    except Exception as e:
        logger.error("Error checking tool access for %r: %s", tool_name, e, exc_info=True)
        return f"SYSTEM: Error checking tool access for '{tool_name}'. Please try again later."
    if not whitelisted:
        return f"SYSTEM: Access denied. Tool '{tool_name}' is internal and not exposed for direct execution."

    try:
        status = await is_configured(tool_name, user_id)
    except Exception as e:
        logger.error("Error checking configuration for tool %r: %s", tool_name, e, exc_info=True)
        return f"SYSTEM: Error checking configuration for tool '{tool_name}'. Please try again later."
    if not isinstance(status, dict):
        logger.error("Malformed configuration status for tool %r: %r", tool_name, status)
        return f"SYSTEM: Error checking configuration for tool '{tool_name}'. Please try again later."
    if not status.get("configured"):
        missing = _missing_configuration_labels(status)
        missing_text = ", ".join(missing) if missing else "required configuration"
        return f"SYSTEM: Tool '{tool_name}' requires configuration before it can be used. Missing: {missing_text}. Configure at /configuration"

    try:
        if tool_name.startswith("mcp__"):
            _, server_name, sub_tool_name = tool_name.split("__", 2)
            client = await get_external_mcp_client_fn(server_name, user_id)
            result = await client.call_tool(sub_tool_name, arguments, raise_on_error=False)
        else:
            client = await get_hub_client_fn()
            result = await client.call_tool(tool_name, {**arguments, "__user_id": user_id}, raise_on_error=False)
    except Exception as e:
        logger.error("Error executing tool %r: %s", tool_name, e, exc_info=True)
        return f"SYSTEM: Error executing tool '{tool_name}'. Please try again later."

    try:
        return extract_tool_output(result)
    except Exception as e:
        logger.error("Error extracting output for tool %r: %s", tool_name, e, exc_info=True)
        return f"SYSTEM: Error executing tool '{tool_name}'. Please try again later."


def extract_tool_output(result: Any) -> Any:
    """Unwrap a fastmcp `CallToolResult` into the raw structured value a direct caller
    expects, preserving full stdout/JSON/error codes rather than pydantic-ai's
    agent-facing `.content` (a list of MCP content blocks).
    """
    if result.data is not None:
        return result.data
    if result.structured_content is not None:
        return result.structured_content
    texts = [c.text for c in (result.content or []) if hasattr(c, "text")]
    if texts:
        return "\n".join(texts)
    return None
