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

from core.auth import IdentityManager
from core.embeddings import embed_text, cosine
from core.discovery import is_tool_configured

logger = logging.getLogger(__name__)

DEFAULT_LIMIT = int(os.getenv("TOOL_SEARCH_LIMIT", "8"))

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379)),
)


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
        statuses = await asyncio.gather(*(is_tool_configured(c["name"], user_id) for c in selected))

    results = []
    for c, status in zip(selected, statuses):
        description = c["description"]
        configured = True
        if status is not None:
            configured = status["configured"]
            if not configured:
                missing = status["missing_secrets"] + status["missing_variables"]
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
