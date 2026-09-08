"""Trellis Rules Engine: deterministic, declarative routing evaluated before
semantic vector search (see ``__spec_docs/rules_engine_spec.md``).

Phase 2 scope: readiness gating (:func:`filter_eligible_agents`) and prompt
catalog compilation (:func:`compile_rules_prompt`, :func:`has_active_rules`).
Phase 3 scope: the single-pass LLM structured decider (:func:`evaluate_rules`),
with strict timeout, confidence threshold enforcement, query memoization, and
fail-open guarantees. ``search_agents`` wiring lands in Phase 4.
"""
import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Dict, List, Optional, Set

from cachetools import TTLCache
from pydantic_ai import Agent
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings

from core.models import RuleEvaluationResult, is_agent_external

logger = logging.getLogger(__name__)

_BACKGROUND_TYPES = ("background_agent", "background_script")

# Single-slot compiled-prompt cache. Keyed by a content hash of the exact
# global/agent rule data that would go into the prompt, so any change to the
# eligible rule set (a rule edited, an agent losing/gaining eligibility)
# invalidates it immediately; the TTL only bounds staleness for
# back-to-back identical calls within the window (avoids re-formatting the
# same catalog string on every query in a hot loop).
_PROMPT_CACHE_TTL_SECONDS = 30.0
_cached_catalog_hash: Optional[str] = None
_cached_prompt: Optional[str] = None
_cached_expires_at: float = 0.0


def filter_eligible_agents(
    configs: Dict[str, Dict],
    health: Dict[str, Dict],
    disabled_agents: Set[str],
    configured_agents: Dict[str, bool],
) -> Dict[str, Dict]:
    """Return the subset of ``configs`` whose declarative rules may be evaluated.

    Excludes the supervisor, background agents/scripts, internal-only agents
    (``external: False``), disabled agents, offline agents, and agents known
    to be unconfigured (missing required secrets/variables) -- this prevents
    "black hole" routing onto an agent that can't actually service the query.
    Agents with no declared ``rules`` are dropped too, since they have
    nothing to contribute to rule evaluation.
    """
    eligible: Dict[str, Dict] = {}
    for name, cfg in configs.items():
        if name == "supervisor":
            continue
        if cfg.get("type") in _BACKGROUND_TYPES:
            continue
        if not is_agent_external(cfg):
            continue
        if name in disabled_agents:
            continue
        if (health.get(name) or {}).get("status") == "Offline":
            continue
        if configured_agents.get(name) is False:
            continue
        if not cfg.get("rules"):
            continue
        eligible[name] = cfg
    return eligible


def has_active_rules(global_rules: List[Dict], eligible_agents: Dict[str, Dict]) -> bool:
    """Fast boolean check to short-circuit rule evaluation when nothing is configured.

    True when there is at least one global override, or at least one eligible
    agent carries a non-empty ``rules`` list -- a pure global-override-only
    deployment (zero agent-level rules) must still enter evaluation.
    """
    if global_rules:
        return True
    return any(cfg.get("rules") for cfg in eligible_agents.values())


def _format_bullet_list(label: str, items: List[str], indent: str, quote: bool = False) -> List[str]:
    if not items:
        return []
    lines = [f"{indent}{label}:"]
    for item in items:
        lines.append(f'{indent}  * "{item}"' if quote else f"{indent}  * {item}")
    return lines


def _format_global_rule(rule: Dict) -> List[str]:
    lines = [f"- Override ID: {rule.get('rule_id', '')}"]
    lines.append(f"  Target Agent: {rule.get('target_agent', '')}")
    lines.extend(_format_bullet_list("Use When", rule.get("use_when", []), "  "))
    lines.extend(_format_bullet_list("Do Not Use When", rule.get("do_not_use_when", []), "  "))
    lines.extend(_format_bullet_list("Examples", rule.get("examples", []), "  ", quote=True))
    return lines


def _format_agent_rule(rule: Dict) -> List[str]:
    lines = [f"  - Description: {rule.get('description', '')}"]
    lines.extend(_format_bullet_list("Use When", rule.get("use_when", []), "    "))
    lines.extend(_format_bullet_list("Do Not Use When", rule.get("do_not_use_when", []), "    "))
    lines.extend(_format_bullet_list("Examples", rule.get("examples", []), "    ", quote=True))
    return lines


def _format_agent_block(name: str, cfg: Dict) -> List[str]:
    lines = [f"Agent: {cfg.get('name', name)}"]
    lines.append(f"Description: {cfg.get('description') or ''}")
    lines.append("Rules:")
    for rule in cfg.get("rules", []):
        lines.extend(_format_agent_rule(rule))
    return lines


def _build_rules_prompt(global_rules: List[Dict], eligible_agents: Dict[str, Dict]) -> str:
    sections: List[str] = []

    if global_rules:
        block = ["=== GLOBAL OVERRIDES (HIGHEST PRIORITY) ==="]
        for i, rule in enumerate(global_rules):
            block.extend(_format_global_rule(rule))
            if i < len(global_rules) - 1:
                block.append("")
        sections.append("\n".join(block))

    if eligible_agents:
        block = ["=== ELIGIBLE AGENT RULES ==="]
        names = sorted(eligible_agents.keys())
        for i, name in enumerate(names):
            block.extend(_format_agent_block(name, eligible_agents[name]))
            if i < len(names) - 1:
                block.append("")
        sections.append("\n".join(block))

    return "\n\n".join(sections)


def _catalog_hash(global_rules: List[Dict], eligible_agents: Dict[str, Dict]) -> str:
    payload = {
        "global_rules": global_rules,
        "agents": {
            name: {"description": cfg.get("description", ""), "rules": cfg.get("rules", [])}
            for name, cfg in eligible_agents.items()
        },
    }
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compile_rules_prompt(global_rules: List[Dict], eligible_agents: Dict[str, Dict]) -> str:
    """Compile global overrides and eligible agent rules into the LLM catalog context.

    Global overrides render first under ``=== GLOBAL OVERRIDES (HIGHEST PRIORITY) ===``,
    followed by per-agent rules under ``=== ELIGIBLE AGENT RULES ===`` (sections are
    omitted entirely when empty). Results are cached in-process (see module docstring).
    """
    global _cached_catalog_hash, _cached_prompt, _cached_expires_at

    cache_key = _catalog_hash(global_rules, eligible_agents)
    now = time.monotonic()
    if _cached_catalog_hash == cache_key and _cached_prompt is not None and now < _cached_expires_at:
        return _cached_prompt

    prompt = _build_rules_prompt(global_rules, eligible_agents)
    _cached_catalog_hash = cache_key
    _cached_prompt = prompt
    _cached_expires_at = now + _PROMPT_CACHE_TTL_SECONDS
    return prompt


# --- Phase 3: LLM structured evaluation ---

RULES_CONFIDENCE_THRESHOLD = float(os.getenv("RULES_CONFIDENCE_THRESHOLD", "0.8"))
RULES_EVALUATION_TIMEOUT = float(os.getenv("RULES_EVALUATION_TIMEOUT", "2.5"))
RULES_EVALUATION_MODEL = os.getenv("RULES_EVALUATION_MODEL", "gemini-2.5-flash")

# Exact-match query result cache: avoids re-invoking the LLM for a repeated
# identical query. Keyed on (query, catalog_hash) rather than query alone so a
# rule-set change (an agent's rules edited, an agent losing/gaining
# eligibility) can never serve a stale positive/negative decision.
_QUERY_CACHE_TTL_SECONDS = 60.0
_QUERY_CACHE_MAXSIZE = 256
_query_result_cache: TTLCache = TTLCache(maxsize=_QUERY_CACHE_MAXSIZE, ttl=_QUERY_CACHE_TTL_SECONDS)

_SYSTEM_PROMPT = """You are the deterministic Routing Rules Evaluator for the Trellis Agent Platform.
Your sole job is to evaluate an incoming user query against a catalog of strict routing rules and determine if the query explicitly locks onto an agent.

EVALUATION PRINCIPLES:
1. Global Overrides take strict precedence over Agent-Level Rules.
2. Negative boundaries ("do_not_use_when") strictly disqualify an agent, even if positive "use_when" conditions or examples seem to match.
3. Specificity is required. If a query is general, ambiguous, spans multiple domains without a global override, or does not clearly meet the "use_when" criteria, you MUST return matched_agent = null with low confidence. Do NOT guess or extrapolate.
4. Only return matched_agent if you are highly confident (>= 0.8) that the query unambiguously matches the positive criteria and violates none of the negative boundaries.
5. You must choose ONLY from the eligible agents listed below. Never invent agent names."""


def _build_user_prompt(catalog: str, query: str) -> str:
    return (
        f"[CATALOG]\n{catalog}\n\n"
        f"[USER QUERY]\n\"{query}\"\n\n"
        "Respond ONLY with valid JSON conforming to the RuleEvaluationResult schema."
    )


def _build_evaluation_agent() -> Agent:
    """Construct a fresh single-pass structured-decider Agent for one evaluation call.

    Not module-cached: construction is cheap (no network I/O), and a fresh instance
    keeps this function trivially mockable in tests via ``monkeypatch.setattr(Agent)``.
    """
    model = GoogleModel(RULES_EVALUATION_MODEL)
    model_settings = GoogleModelSettings(
        google_thinking_config={"thinking_budget": 0, "include_thoughts": False}
    )
    return Agent(
        model,
        output_type=RuleEvaluationResult,
        system_prompt=_SYSTEM_PROMPT,
        model_settings=model_settings,
        retries=1,
    )


async def evaluate_rules(
    query: str,
    global_rules: List[Dict],
    eligible_agents: Dict[str, Dict],
) -> Optional[RuleEvaluationResult]:
    """Evaluate ``query`` against the compiled rule catalog via a single-pass LLM call.

    Returns a :class:`RuleEvaluationResult` only when the LLM locked onto an eligible
    agent with confidence >= :data:`RULES_CONFIDENCE_THRESHOLD`. Returns ``None`` in
    every other case -- no active rules, no rule match, a match on an ineligible/unknown
    agent, below-threshold confidence, or any failure (timeout, API error, validation
    error) -- so the caller can fall open to vector semantic search unconditionally.
    This function must never raise.
    """
    if not has_active_rules(global_rules, eligible_agents):
        return None

    try:
        catalog_hash = _catalog_hash(global_rules, eligible_agents)
        cache_key = (query, catalog_hash)
        if cache_key in _query_result_cache:
            return _query_result_cache[cache_key]

        catalog = compile_rules_prompt(global_rules, eligible_agents)
        user_prompt = _build_user_prompt(catalog, query)

        agent = _build_evaluation_agent()
        run_result = await asyncio.wait_for(agent.run(user_prompt), timeout=RULES_EVALUATION_TIMEOUT)
        result = run_result.output
    except asyncio.TimeoutError:
        logger.warning(
            f"[RulesEngine] Evaluation timed out after {RULES_EVALUATION_TIMEOUT}s; failing open to semantic search"
        )
        return None
    except Exception as e:
        logger.warning(f"[RulesEngine] Evaluation failed with error {e}; failing open to semantic search")
        return None

    final: Optional[RuleEvaluationResult] = None
    if result.matched_agent is None:
        logger.debug("[RulesEngine] No rule matched; falling open to semantic search")
    elif result.matched_agent not in eligible_agents:
        logger.warning(
            f"[RulesEngine] Matched agent '{result.matched_agent}' is not an eligible agent; failing open to semantic search"
        )
    elif result.confidence < RULES_CONFIDENCE_THRESHOLD:
        logger.debug(
            f"[RulesEngine] Match confidence {result.confidence} below threshold {RULES_CONFIDENCE_THRESHOLD}; falling open to semantic search"
        )
    else:
        logger.info(f"[RulesEngine] Matched rule for agent: {result.matched_agent} (confidence: {result.confidence})")
        final = result

    _query_result_cache[cache_key] = final
    return final
