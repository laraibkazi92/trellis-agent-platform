"""Semantic agent discovery shared by the gateway MCP and the Supervisor agent.

Both the public ``search_agents`` gateway tool and the Supervisor's internal routing
tool call :func:`search_agents` so there is a single retrieval mechanism. This keeps
context small at scale: instead of dumping every agent, we return only the top matches
for a query.

The Trellis Rules Engine (``core/rules_engine.py``) is evaluated first: if an eligible
agent's declarative rules (or a central ``routing_rules.yaml`` override) lock
deterministically onto the query, that agent short-circuits ranking entirely. Only when
no rule fires -- no rules configured, no confident match, or a rules-engine failure --
do we fall through to embedding-based ranking.

Ranking uses Gemini embeddings (cached per-agent in etcd, see ``scripts/sync_to_db.py``).
If embeddings are unavailable we fall back to simple keyword matching so the framework
still works without an API key.
"""
import os
import re
import asyncio
import logging
from typing import List, Dict, Optional, Set

from core.auth import IdentityManager, user_id_var
from core.discovery import discover_agents
from core.embeddings import embed_text, cosine
from core.models import is_agent_external
from core.rules_engine import evaluate_rules, filter_eligible_agents

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


def _build_candidates(
    configs: Dict[str, Dict],
    embeddings: Dict[str, List[float]],
    disabled: Set[str],
    health: Dict[str, Dict],
    include_disabled: bool,
) -> List[Dict]:
    """Build the ranked-search candidate pool (supervisor/background/internal excluded)."""
    candidates: List[Dict] = []
    for name, cfg in configs.items():
        if name == "supervisor":
            continue
        if cfg.get("type") in _BACKGROUND_TYPES:
            continue
        if not is_agent_external(cfg):
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
    return candidates


async def _rank_candidates(query: str, candidates: List[Dict]) -> List[Dict]:
    """Rank ``candidates`` by embedding cosine similarity, falling back to keyword match."""
    if not candidates:
        return []
    query_vec = await asyncio.to_thread(embed_text, query, "retrieval_query")
    if query_vec:
        return sorted(candidates, key=lambda c: cosine(query_vec, c.get("_vec")), reverse=True)
    logger.warning("Embeddings unavailable; using keyword fallback for agent search.")
    return _keyword_rank(query, candidates)


async def _resolve_rule_lock(
    query: str,
    configs: Dict[str, Dict],
    health: Dict[str, Dict],
    disabled: Set[str],
) -> Optional[Dict]:
    """Evaluate the Trellis Rules Engine and return a locked ``{name, description, status}``
    dict, or ``None`` if no rule fires.

    Fully self-contained and fail-open: any error anywhere in this path (etcd fetch,
    bulk configuration-readiness resolution, or LLM evaluation) results in ``None``, so
    ``search_agents`` falls through to vector semantic search exactly as if no rules
    existed. Rule evaluation must never crash query routing.
    """
    try:
        routing_rules_doc = await asyncio.to_thread(identity_mgr.get_routing_rules)
        global_rules = (routing_rules_doc or {}).get("global_rules", [])

        # Cheap pre-check against configs already fetched by the caller, before paying
        # for the bulk discover_agents() configuration-readiness resolve below -- the
        # common case (no rules authored anywhere) should never pay that cost.
        if not global_rules and not any(cfg.get("rules") for cfg in configs.values()):
            return None

        discovered = await discover_agents(user_id=user_id_var.get())
        configured_agents = {a["name"]: a.get("is_configured", True) for a in discovered}

        eligible_agents = filter_eligible_agents(configs, health, disabled, configured_agents)
        rule_result = await evaluate_rules(query, global_rules, eligible_agents)
        if not rule_result or not rule_result.matched_agent:
            return None

        matched_cfg = eligible_agents.get(rule_result.matched_agent, {})
        return {
            "name": rule_result.matched_agent,
            "description": matched_cfg.get("description", ""),
            "status": (health.get(rule_result.matched_agent) or {}).get("status", "Online"),
        }
    except Exception as e:
        logger.warning(f"[RulesEngine] Unexpected error resolving rule lock ({e}); failing open to semantic search")
        return None


async def search_agents(query: str, limit: int = DEFAULT_LIMIT, include_disabled: bool = False) -> List[Dict]:
    """Return up to ``limit`` agents most relevant to ``query``.

    Each result is ``{"name", "description", "status"}``. Background agents/scripts and
    the supervisor are always excluded. Disabled agents are excluded unless
    ``include_disabled`` is True (the Supervisor passes True so it can still manage them).
    Agents with ``external: False`` (internal-only agents) are always excluded.
    Pass ``limit <= 0`` to get the full ranked list (used by callers that apply their own
    visibility filter on top of the ranking) -- *unless* a rule locks (see below), in which
    case ``limit <= 0`` is treated the same as ``limit == 1`` and only the locked agent is
    returned; callers relying on the "full list" idiom to backfill from visibility-filtered
    alternates should pass an explicit ``limit > 1`` instead if that matters for them.

    Before ranking, the Trellis Rules Engine is evaluated (see
    ``__spec_docs/rules_engine_spec.md``). If a rule deterministically locks onto an
    eligible agent, that agent is placed first with no embedding call required; when
    ``limit`` allows more than one result, remaining slots are filled with the ranked
    semantic fallback (excluding the locked agent).
    """
    configs = await asyncio.to_thread(identity_mgr.get_all_agent_configs)
    embeddings = await asyncio.to_thread(identity_mgr.get_all_agent_embeddings)
    disabled = set(await asyncio.to_thread(identity_mgr.get_disabled_standard_agents))
    try:
        health = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "agent")
    except Exception:
        health = {}

    candidates = _build_candidates(configs, embeddings, disabled, health, include_disabled)
    if not candidates:
        return []

    locked = await _resolve_rule_lock(query, configs, health, disabled)
    if locked:
        if limit is None or limit <= 1:
            return [locked]
        remaining = [c for c in candidates if c["name"] != locked["name"]]
        ranked = await _rank_candidates(query, remaining)
        fill = ranked[: max(limit - 1, 0)]
        return [locked] + [
            {"name": c["name"], "description": c["description"], "status": c["status"]}
            for c in fill
        ]

    ranked = await _rank_candidates(query, candidates)
    selected = ranked if limit is None or limit <= 0 else ranked[:limit]
    return [
        {"name": c["name"], "description": c["description"], "status": c["status"]}
        for c in selected
    ]
