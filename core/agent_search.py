"""Semantic agent discovery shared by the gateway MCP and the Supervisor agent.

Both the public ``search_agents`` gateway tool and the Supervisor's internal routing
tool call :func:`search_agents` so there is a single retrieval mechanism. This keeps
context small at scale: instead of dumping every agent, we return only the top matches
for a query.

Ranking uses Gemini embeddings (cached per-agent in etcd, see ``scripts/sync_to_db.py``).
If embeddings are unavailable we fall back to simple keyword matching so the framework
still works without an API key.
"""
import os
import re
import asyncio
import logging
from typing import List, Dict

from core.auth import IdentityManager
from core.embeddings import embed_text, cosine

logger = logging.getLogger(__name__)

DEFAULT_LIMIT = int(os.getenv("AGENT_SEARCH_LIMIT", "8"))

_BACKGROUND_TYPES = ("background_agent", "background_script")

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379)),
)


def _keyword_rank(query: str, candidates: List[Dict]) -> List[Dict]:
    """Fallback ranking: count query-term hits across name/description/tags."""
    terms = [t for t in re.split(r"\W+", query.lower()) if t]

    def score(c: Dict) -> int:
        haystack = f"{c['name']} {c['description']} {' '.join(c.get('tags', []))}".lower()
        return sum(1 for t in terms if t in haystack)

    return sorted(candidates, key=lambda c: (-score(c), c["name"].lower()))


async def search_agents(query: str, limit: int = DEFAULT_LIMIT, include_disabled: bool = False) -> List[Dict]:
    """Return up to ``limit`` agents most relevant to ``query``.

    Each result is ``{"name", "description", "status"}``. Background agents/scripts and
    the supervisor are always excluded. Disabled agents are excluded unless
    ``include_disabled`` is True (the Supervisor passes True so it can still manage them).
    Pass ``limit <= 0`` to get the full ranked list (used by callers that apply their own
    visibility filter on top of the ranking).
    """
    configs = await asyncio.to_thread(identity_mgr.get_all_agent_configs)
    embeddings = await asyncio.to_thread(identity_mgr.get_all_agent_embeddings)
    disabled = set(await asyncio.to_thread(identity_mgr.get_disabled_standard_agents))
    try:
        health = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "agent")
    except Exception:
        health = {}

    candidates: List[Dict] = []
    for name, cfg in configs.items():
        if name == "supervisor":
            continue
        if cfg.get("type") in _BACKGROUND_TYPES:
            continue

        is_disabled = name in disabled
        if is_disabled and not include_disabled:
            continue

        if is_disabled:
            status = "disabled"
        else:
            status = (health.get(name) or {}).get("status", "Online")

        candidates.append({
            "name": cfg.get("name", name),
            "description": cfg.get("description", ""),
            "status": status,
            "tags": cfg.get("tags", []),
            "_vec": embeddings.get(name),
        })

    if not candidates:
        return []

    query_vec = await asyncio.to_thread(embed_text, query, "retrieval_query")
    if query_vec:
        ranked = sorted(
            candidates,
            key=lambda c: cosine(query_vec, c.get("_vec")),
            reverse=True,
        )
    else:
        logger.warning("Embeddings unavailable; using keyword fallback for agent search.")
        ranked = _keyword_rank(query, candidates)

    selected = ranked if limit is None or limit <= 0 else ranked[:limit]
    return [
        {"name": c["name"], "description": c["description"], "status": c["status"]}
        for c in selected
    ]
