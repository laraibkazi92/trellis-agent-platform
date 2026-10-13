# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

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
import re
import asyncio
import logging
from typing import List, Dict, Optional, Set, Tuple

from core.auth import get_identity_manager, user_id_var
from core.discovery import is_agent_configured
from core.embeddings import embed_text, cosine
from core.health import evaluate_health_status
from core.models import is_agent_external, is_routable_agent_type
from core.rules_engine import evaluate_rules, filter_eligible_agents
from core.tunables import resolve as resolve_tunable

logger = logging.getLogger(__name__)

identity_mgr = get_identity_manager()


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
        if not is_routable_agent_type(name, cfg):
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
) -> Tuple[Optional[Dict], Optional[Dict]]:
    """Evaluate the Trellis Rules Engine and return ``(locked, unavailable_note)``.

    ``locked`` is a ``{name, description, status}`` dict when a confident rule match is
    also currently available (Half-Open counts as available, per Phase B); it's
    ``None`` whenever no lock should be honored. ``unavailable_note`` is a ``{name,
    reason, reason_status}`` dict when a confident rule match exists but the matched
    agent is currently offline or unconfigured -- the two are mutually exclusive, and
    both are ``None`` when no rule fires at all.

    Per Phase E of the Trellis Rules Engine hardening plan (items E2/E3),
    ``filter_eligible_agents``
    no longer considers health or configuration-readiness -- the LLM decider reasons
    purely on declarative rule content, blind to availability. Availability is checked
    here, only *after* a confident match, using the same Phase B/C unified evaluators
    used everywhere else. Administratively disabled agents are excluded from
    eligibility entirely (silent, no note) and never reach this availability check.

    Fully self-contained and fail-open: any error anywhere in this path (etcd fetch,
    bulk configuration-readiness resolution, or LLM evaluation) results in
    ``(None, None)``, so ``search_agents`` falls through to vector semantic search
    exactly as if no rules existed. Rule evaluation must never crash query routing.
    """
    try:
        routing_rules_doc = await asyncio.to_thread(identity_mgr.get_routing_rules)
        global_rules = (routing_rules_doc or {}).get("global_rules", [])

        # Cheap pre-check against configs already fetched by the caller -- the
        # common case (no rules authored anywhere) should never pay any evaluation cost.
        if not global_rules and not any(cfg.get("rules") for cfg in configs.values()):
            return None, None

        eligible_agents = filter_eligible_agents(configs, disabled)
        rule_result = await evaluate_rules(query, global_rules, eligible_agents)
        if not rule_result or not rule_result.matched_agent:
            return None, None

        matched_name = rule_result.matched_agent
        matched_cfg = eligible_agents.get(matched_name, {})

        # Evaluated (cooldown-aware), not raw -- a past-cooldown "Half-Open" agent
        # counts as available (Phase B decision) and must be locked, not routed into
        # the unavailable-note path.
        evaluated = evaluate_health_status(health.get(matched_name) or {})
        evaluated_status = evaluated.get("status", "Online")
        if evaluated_status == "Offline":
            return None, {"name": matched_name, "reason": "offline", "reason_status": "Offline"}

        # Configuration readiness is checked ONLY after a confident match occurs and
        # the matched agent is not offline. Targeted single-agent evaluation via
        # is_agent_configured avoids a whole-catalog discover_agents scan.
        status_dict = await is_agent_configured(matched_name, user_id=user_id_var.get())
        if status_dict.get("configured") is False:
            return None, {"name": matched_name, "reason": "not configured", "reason_status": "Unconfigured"}

        return {
            "name": matched_name,
            "description": matched_cfg.get("description", ""),
            "status": evaluated_status,
        }, None
    except Exception as e:
        logger.warning(f"[RulesEngine] Unexpected error resolving rule lock ({e}); failing open to semantic search")
        return None, None


async def search_agents(query: str, limit: Optional[int] = None, include_disabled: bool = False) -> List[Dict]:
    """Return up to ``limit`` agents most relevant to ``query``.

    Each result is ``{"name", "description", "status"}``. Background agents/scripts and
    the supervisor are always excluded. Disabled agents are excluded unless
    ``include_disabled`` is True (the Supervisor passes True so it can still manage them).
    Agents with ``external: False`` (internal-only agents) are always excluded.
    Pass ``limit <= 0`` to get the full ranked list when no rule locks.
    ``limit=None`` (the default) resolves to the admin-tunable ``agent_search_limit``
    (env ``AGENT_SEARCH_LIMIT``, default 8).

    Before ranking, the Trellis Rules Engine is evaluated (see ``docs/rules_engine.md``).
    A confident rule match that is also currently available (Half-Open counts as
    available, per Phase B) short-circuits ranking entirely: it returns **exactly one**
    result, unconditionally -- regardless of ``limit``, including ``limit <= 0``. A
    rules-engine lock is meant to be deterministic and authoritative, not diluted or
    truncated by the caller (see rules_engine_hardening_plan.md §5, Phase E, E1).

    If the rules engine confidently matches an agent that turns out to be offline or
    unconfigured, the lock is *not* honored -- instead the query falls through to the
    normal ranked semantic fallback (governed by ``limit`` as usual), with an extra
    leading "unavailable match" note describing what was skipped. This note is
    additional, not counted against ``limit``: a caller requesting ``limit=5`` still
    gets 5 ranked alternatives, plus the note, when this happens. The note item also
    carries ``unavailable_match: True`` (absent on every other result) so a caller that
    re-decorates results by agent name (e.g. the Gateway MCP tool) can recognize it and
    leave its crafted, self-contained description untouched -- it's still fully
    readable by a caller that only looks at ``description``, ignoring this flag.
    """
    if limit is None:
        limit = resolve_tunable("agent_search_limit")
    configs = await asyncio.to_thread(identity_mgr.get_all_agent_configs)
    disabled = set(await asyncio.to_thread(identity_mgr.get_disabled_standard_agents))
    try:
        health = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "agent")
    except Exception:
        health = {}

    # Quick check: are there any external routable candidates?
    has_routable = any(
        is_routable_agent_type(name, cfg) and is_agent_external(cfg) and (include_disabled or name not in disabled)
        for name, cfg in configs.items()
    )
    if not has_routable:
        return []

    locked, unavailable_note = await _resolve_rule_lock(query, configs, health, disabled)
    if locked:
        return [locked]

    # Defer embeddings fetch until semantic fallback is actually needed
    embeddings = await asyncio.to_thread(identity_mgr.get_all_agent_embeddings)
    candidates = _build_candidates(configs, embeddings, disabled, health, include_disabled)

    if unavailable_note:
        # The unavailable matched agent should not appear in the ranked fallback alternatives
        # beneath the note that explicitly announces it is unavailable and shows next-best alternatives.
        candidates = [c for c in candidates if c["name"] != unavailable_note["name"]]

    ranked = await _rank_candidates(query, candidates)
    selected = ranked if limit <= 0 else ranked[:limit]
    results = [
        {"name": c["name"], "description": c["description"], "status": c["status"]}
        for c in selected
    ]

    if unavailable_note:
        name = unavailable_note["name"]
        reason = unavailable_note["reason"]
        results.insert(0, {
            "name": name,
            "description": (
                f"The routing policy identified '{name}' as the best match for this "
                f"query, but it is currently {reason}. Showing next-best alternatives below."
            ),
            "status": unavailable_note["reason_status"],
            # Lets a caller that also re-decorates results (e.g. the Gateway MCP tool,
            # see core/gateway.py:search_agents) recognize this item as the crafted,
            # self-contained routing-policy note and leave its description untouched,
            # rather than silently overwriting it with the same agent's own catalog
            # description just because the name happens to still resolve there.
            "unavailable_match": True,
        })
    return results
