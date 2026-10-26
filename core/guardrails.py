# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Declarative guardrails (v1: regex only).

Patterns are admin-authored, so there is no runtime timeout for catastrophic
backtracking (ReDoS) -- and because ``re`` holds the GIL, a pathological pattern
stalls the whole process, not just the evaluating thread. Keep patterns simple.
A malformed rule is skipped and logged (fail-open).

Known v1 gaps: streaming replies are checked on the final assembled output only;
supervisor-delegated sub-agent turns are not evaluated (only the orchestrating
agent's rules apply), and ``background_script`` runs are input-checked only --
their stdout is not.
"""
import logging
import re
import threading
import time
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_PREVIEW_CHARS = 120
REDACTION_MARKER = "[REDACTED]"
FRAMEWORK_CACHE_TTL_SECONDS = 30.0
FRAMEWORK_CACHE_ERROR_TTL_SECONDS = 5.0

DIRECTIONS = ("on_input", "on_output")
_VALID_ACTIONS = ("block", "redact")

GuardrailResult = Tuple[str, str, List[Dict[str, Any]]]

_framework_cache: Optional[Dict[str, List[Dict[str, Any]]]] = None
_framework_cache_expiry: float = 0.0
_framework_cache_generation = 0
_framework_cache_lock = threading.Lock()


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


@lru_cache(maxsize=512)
def _compile_pattern(pattern: str) -> Optional[re.Pattern]:
    """Compile one regex; a bad pattern is logged once and cached as ``None``."""
    try:
        return re.compile(pattern)
    except (re.error, RecursionError) as e:
        logger.error("Ignoring invalid guardrail regex %r: %s", pattern, e)
        return None


def _preview(value: str) -> str:
    return (value or "")[:MAX_PREVIEW_CHARS]


def _redact_all(pattern: "re.Pattern", text: str) -> Tuple[str, Optional[str], int]:
    """Replace every match, returning the redacted text, first match and count."""
    first: List[str] = []

    def _replace(match: "re.Match") -> str:
        if not first:
            first.append(match.group(0))
        return REDACTION_MARKER

    redacted, count = pattern.subn(_replace, text)
    return redacted, (first[0] if first else None), count


def _rule_name(rule: Dict[str, Any], fallback: str) -> str:
    name = rule.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return fallback


def _normalize_patterns(raw: Any) -> Optional[List[str]]:
    """Accept a single string or a list of strings; anything else is malformed."""
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list) and all(isinstance(p, str) for p in raw):
        return raw
    return None


def _log_decision(direction: str, action: str, hits: List[Dict[str, Any]]) -> None:
    """One bounded line per decision that fired (never the full payload)."""
    if not hits:
        return
    summary = ", ".join(f"{hit.get('rule')}={hit.get('preview')!r}" for hit in hits)
    logger.info("guardrail %s decision=%s hits=[%s]", direction, action, summary)


def _evaluate(text: str, rules: List[Dict[str, Any]], direction: str) -> GuardrailResult:
    text = text if isinstance(text, str) else ("" if text is None else str(text))
    original_len = len(text)
    hits: List[Dict[str, Any]] = []
    if not isinstance(rules, list) or not rules:
        return "allow", text, hits

    action = "allow"
    for rule in rules:
        if not isinstance(rule, dict):
            logger.error("Skipping guardrail rule that is not an object: %r", rule)
            continue

        rule_type = rule.get("type")

        if rule_type == "max_chars":
            value = rule.get("value")
            if not _is_number(value) or value < 0:
                logger.error("Skipping guardrail rule with invalid max_chars value: %r", rule)
                continue
            limit = int(value)
            if len(text) <= limit:
                continue
            name = _rule_name(rule, "max_chars")
            hits.append({
                "rule": name,
                "type": "max_chars",
                "preview": _preview(f"{len(text)}>{limit}"),
            })
            if direction == "input":
                _log_decision(direction, "block", hits)
                return "block", text, hits
            # Count characters dropped from the original input, not from the
            # already-truncated text (two stacked caps would otherwise under-report).
            removed = max(0, original_len - limit)
            label = "char" if removed == 1 else "chars"
            text = text[:limit] + f"… [truncated {removed} {label}]"
            action = "redact"
            continue

        if rule_type == "deny_patterns":
            name = _rule_name(rule, "deny_patterns")
            rule_action = rule.get("action")
            rule_action = "block" if rule_action is None else rule_action
            if not isinstance(rule_action, str):
                logger.error("Skipping guardrail rule %r: invalid action %r", name, rule_action)
                continue
            rule_action = rule_action.strip().lower()
            if rule_action not in _VALID_ACTIONS:
                logger.error("Skipping guardrail rule %r: unknown action %r", name, rule_action)
                continue

            patterns = _normalize_patterns(rule.get("patterns"))
            if patterns is None:
                logger.error("Skipping guardrail rule %r: invalid patterns", name)
                continue
            compiled = [_compile_pattern(p) for p in patterns]
            if any(c is None for c in compiled):
                # One bad pattern makes the whole rule unreliable: skip it fail-open.
                logger.error("Skipping guardrail rule %r: one or more patterns are invalid", name)
                continue

            if rule_action == "block":
                for pattern in compiled:
                    match = pattern.search(text)
                    if match:
                        hits.append({
                            "rule": name,
                            "type": "deny_patterns",
                            "preview": _preview(match.group(0)),
                        })
                        _log_decision(direction, "block", hits)
                        return "block", text, hits
                continue

            redact_hit: Optional[str] = None
            for pattern in compiled:
                text, first, replaced = _redact_all(pattern, text)
                if not replaced:
                    continue
                if redact_hit is None:
                    redact_hit = first
                action = "redact"
            if redact_hit is not None:
                hits.append({
                    "rule": name,
                    "type": "deny_patterns",
                    "preview": _preview(redact_hit),
                })
            continue

        logger.error("Skipping guardrail rule with unknown type %r", rule_type)

    _log_decision(direction, action, hits)
    return action, text, hits


def evaluate_input(prompt: str, rules: List[Dict[str, Any]]) -> GuardrailResult:
    """Check user/agent input; over-limit ``max_chars`` blocks instead of truncating."""
    return _evaluate(prompt, rules, "input")


def evaluate_output(text: str, rules: List[Dict[str, Any]]) -> GuardrailResult:
    """Check agent output; over-limit ``max_chars`` truncates and reports ``redact``."""
    return _evaluate(text, rules, "output")


def _direction_rules(container: Any, direction: str) -> List[Dict[str, Any]]:
    """Rules for one direction, preferring a nested ``guardrails`` block.

    An empty list counts as "unset" so a nested empty block does not shadow rules
    written at the top level (both shapes are accepted).
    """
    if not isinstance(container, dict):
        return []
    sources = []
    nested = container.get("guardrails")
    if isinstance(nested, dict):
        sources.append(nested)
    sources.append(container)
    for source in sources:
        value = source.get(direction)
        if isinstance(value, list) and value:
            return [dict(rule) for rule in value if isinstance(rule, dict)]
    return []


def merge_rules(
    agent_config: Dict[str, Any],
    framework_defaults: Optional[Dict[str, Any]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Per-direction union: framework rules first, then agent rules."""
    if framework_defaults is None:
        framework_defaults = get_framework_guardrails()
    merged: Dict[str, List[Dict[str, Any]]] = {}
    for direction in DIRECTIONS:
        merged[direction] = (
            _direction_rules(framework_defaults, direction)
            + _direction_rules(agent_config, direction)
        )
    return merged


def _normalize_framework(raw: Any) -> Dict[str, List[Dict[str, Any]]]:
    if not isinstance(raw, dict):
        return {}
    normalized: Dict[str, List[Dict[str, Any]]] = {}
    for direction in DIRECTIONS:
        rules = _direction_rules(raw, direction)
        if rules:
            normalized[direction] = rules
    return normalized


def get_framework_guardrails() -> Dict[str, List[Dict[str, Any]]]:
    """Cached framework-wide rules (30s TTL); any read failure keeps the old cache."""
    global _framework_cache, _framework_cache_expiry
    with _framework_cache_lock:
        if _framework_cache is not None and time.monotonic() < _framework_cache_expiry:
            return _framework_cache
        generation = _framework_cache_generation

    try:
        from core.auth import get_identity_manager

        normalized = _normalize_framework(
            get_identity_manager().get_guardrails_defaults()
        )
    except Exception as e:
        logger.warning("Failed to read framework guardrails: %s", e)
        with _framework_cache_lock:
            # Short negative window: without it a cold/expired cache would retry the
            # full @retry_etcd budget (~18s) on every input AND output check.
            if _framework_cache is None:
                _framework_cache = {}
            _framework_cache_expiry = time.monotonic() + FRAMEWORK_CACHE_ERROR_TTL_SECONDS
            return _framework_cache

    with _framework_cache_lock:
        # A reset that landed mid-read must not be shadowed by this stale value.
        if _framework_cache_generation == generation:
            _framework_cache = normalized
            _framework_cache_expiry = time.monotonic() + FRAMEWORK_CACHE_TTL_SECONDS
    return normalized


def set_framework_guardrails(rules: Dict[str, Any]) -> None:
    """Persist framework-wide rules, then drop the cache so the next read sees them."""
    from core.auth import get_identity_manager

    get_identity_manager().set_guardrails_defaults(rules)
    reset_framework_guardrails_cache()


def reset_framework_guardrails_cache() -> None:
    """Drop the cached framework rules so the next read goes back to etcd."""
    global _framework_cache, _framework_cache_expiry, _framework_cache_generation
    with _framework_cache_lock:
        _framework_cache_generation += 1
        _framework_cache = None
        _framework_cache_expiry = 0.0


def _evaluate_agent(text: str, agent_config: Dict[str, Any], direction: str) -> GuardrailResult:
    try:
        rules = merge_rules(agent_config or {}).get(direction, [])
        return _evaluate(text, rules, "input" if direction == "on_input" else "output")
    except Exception:
        logger.exception("Guardrail evaluation failed (%s); allowing text through", direction)
        return "allow", text, []


def evaluate_agent_input(prompt: str, agent_config: Dict[str, Any]) -> GuardrailResult:
    """Merge the agent's rules with the framework defaults, then check input."""
    return _evaluate_agent(prompt, agent_config, "on_input")


def evaluate_agent_output(text: str, agent_config: Dict[str, Any]) -> GuardrailResult:
    """Merge the agent's rules with the framework defaults, then check output."""
    return _evaluate_agent(text, agent_config, "on_output")


def hit_counts(hits: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count hits per rule name."""
    counts: Dict[str, int] = {}
    for hit in hits or []:
        if not isinstance(hit, dict):
            continue
        name = hit.get("rule")
        if isinstance(name, str) and name:
            counts[name] = counts.get(name, 0) + 1
    return counts
