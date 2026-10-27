# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The ONE tool-authorization decision in the framework.

Every enforcement point (hub, edge relay, host-before-runner, agent-factory bound
tools) asks :func:`authorize` and applies the answer with :func:`enforce`. There is
one mode switch for the whole framework (:func:`tool_access_mode`), one policy
document, and one fail-closed rule for reading it.

Sync vs. async
--------------

Deciding a call needs one registry read (:func:`policy_snapshot`), which is blocking
and has no deadline of its own. Every enforcement point runs on the asyncio event
loop of a request-handling process, so they MUST use the ``*_async`` variants
(:func:`authorize_async`, :func:`authorize_claims_async`, :func:`enforce_async`):
those hop to a worker thread for the read and the shadow-ring write and then decide
in-process, so one slow registry never stalls unrelated coroutines. The sync
:func:`authorize` / :func:`enforce` remain for genuinely synchronous callers only --
a worker thread such as the ``search_tools`` card filter (already inside
``asyncio.to_thread``) -- and for tests.

Two independent halves decide one call
---------------------------------------

1. **The agent allowlist** -- resolved from the agent record by
   :mod:`core.allowlist` (``allowed_tools`` / ``allowed_mcps`` / edge forms /
   ``<site>__*`` wildcards / console names). This half is *always* enforced; it is
   the agent's own manifest and no mode switch relaxes it.
2. **Group rules** -- from the workspace policy document. A target matched by at
   least one rule is usable ONLY by a caller whose token groups intersect one of
   those rules' group sets. A target no rule matches is governed by the allowlist
   alone. Rules are allow-lists of groups: no priorities, no deny-overrides, no
   special "everyone" group (an empty ``groups`` list is a validation error, so a
   rule can never accidentally grant everybody).

``public=True`` means "this caller has no agent record" -- the front door (a
gateway client, a directly-exposed tool). It replaces half 1 with the tool's own
published exposure and leaves half 2 unchanged.

Note what ``public`` cannot express: "this token names an agent that has no record"
(the agent was deleted, or the token was minted for a typo'd name) is
indistinguishable here from "this caller sits at the front door", because both hand
the evaluator ``agent`` with no allowlist. The front door is a reserved *identity*,
not a missing record, and telling the two apart needs a caller-supplied flag at the
mint sites (a Phase 5 follow-up): until then a token for an unregistered agent is
granted exactly what a public tool grants, and nothing more.

The policy document (``workspace/policies/tool_access.yaml``, synced to etcd)
---------------------------------------------------------------------------

Accepted shape -- anything else is invalid, and an invalid or unreadable policy
denies every call that group rules could have decided:

.. code-block:: yaml

    rules:
      - name: platform-ops                  # optional label, unique
        targets: [text_stats]               # one pattern, or a list; `target:` also
        groups: [platform-ops]              # one or more group names, non-empty

    # `target` / `targets` patterns are shell globs (``fnmatch``) matched against the
    # reference the enforcement point passes:
    #   text_stats                          a framework/hub tool
    #   mcp__coralogix__list_alerts         a central MCP tool
    #   dc1__node_ssh                       an edge tool
    #   mcp__dc1__devops-cli__kubectl       an edge MCP tool
    #   execute                             the console `execute` tool -- the ONLY
    #                                       console tool rules cover
    #   coralogix, dc1__devops-cli          an MCP *session* (session=True)
    #
    # A rule naming any other console tool (``read_file``, ``write_file``,
    # ``edit_file``, ``ls``, ``glob``, ``grep``) validates but decides nothing: those
    # tools are not routed through this evaluator at all, and they stay constrained by
    # the agent's console allowlist alone. The policy load warns about such a rule
    # (see :func:`policy_warnings`) instead of rejecting the file.

Validation rejects: unknown top-level keys (``rules`` is the only one), a missing
or non-list ``rules``, unknown rule keys (``name``/``target``/``targets``/
``groups`` only), empty or non-string entries, two rules with the same name, and
two rules with the same targets+groups.

Mode
----

``TOOL_ACCESS_MODE`` (default ``enforce``) is the only switch:

* ``enforce`` -- decisions are final.
* ``shadow``  -- a denial of the *group-rule* half is logged and pushed onto the
  shadow ring, then allowed.
* ``off``     -- the group-rule half is skipped entirely.

Both relaxed modes leave the allowlist half alone: it is always enforced (that is
``ENFORCE_AGENT_TOKENS``' business, not this switch), so neither mode can execute a
call outside the agent's manifest. An invalid value logs an error and behaves as
``enforce``.

Reading the policy
------------------

The snapshot is cached for :data:`POLICY_TTL_S` and invalidated by an etcd watch
(:func:`install_watch`, called once at startup by every enforcing process), so a
policy edit lands in every process within a couple of seconds without a restart.
A read error or an invalid document is *not* cached as good: it denies with
``policy_unavailable``. An absent registry key is different from an error -- it
means "no group rules", so the allowlist alone decides.
"""

import asyncio
import fnmatch
import json
import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple

from core.allowlist import CONSOLE_TOOLS, EffectiveAllowlist, permits_mcp_session, permits_tool

logger = logging.getLogger(__name__)

# Registry key the workspace file is synced to (scripts/sync_to_db.py).
POLICY_PATH = "/registry/tool_access"
# Shadow-denial ring shared between processes so the admin page (its own process)
# can show what a shadow window would have denied.
SHADOW_DENIAL_PATH = "/registry/tool_access_denials"

MODE_ENV = "TOOL_ACCESS_MODE"
MODES = ("off", "shadow", "enforce")
DEFAULT_MODE = "enforce"
MODES_HELP = "off, shadow, enforce"

# Denial reasons -- stable machine strings, safe to branch on / show in a UI.
REASON_NOT_IN_ALLOWLIST = "not_in_allowlist"
REASON_GROUP_DENIED = "group_denied"
REASON_UNKNOWN_TARGET = "unknown_target"
REASON_POLICY_UNAVAILABLE = "policy_unavailable"

# Allow reasons -- informational only (``Decision.allowed`` is the verdict).
REASON_ALLOWLIST = "allowlist"
REASON_PUBLIC = "public"
REASON_GROUP_MATCH = "group_match"
REASON_MODE_OFF = "mode_off"
REASON_SHADOW = "shadow"

# Denial reasons produced by the group-rule half. ``off`` relaxes exactly these:
# everything else (allowlist, unusable reference) is enforced in every mode.
GROUP_HALF_REASONS = frozenset({REASON_GROUP_DENIED, REASON_POLICY_UNAVAILABLE})

POLICY_TTL_S = 30.0
# Negative window: a failed read must not turn every tool call into a full etcd
# retry budget. Denials are the same either way -- this is a load guard, not a
# fail-open window.
POLICY_ERROR_TTL_S = 5.0
SHADOW_RING_CAP = 50
# One shared-ring write per second per process: a deny-everything policy must not
# make every tool call an etcd write.
_SHADOW_PERSIST_MIN_INTERVAL_S = 1.0


# --------------------------------------------------------------------------- #
# the decision
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Decision:
    """One authorization verdict.

    ``allowed`` is the verdict, ``reason`` a stable machine string (see the
    ``REASON_*`` constants), ``rule`` the matching group rule's label when one
    decided the call, and ``message`` a human explanation naming the agent and the
    target -- never a user, an email or an argument.
    """

    allowed: bool
    reason: str
    rule: Optional[str] = None
    message: str = ""


def allow(
    reason: str = REASON_ALLOWLIST, *, rule: Optional[str] = None, message: str = ""
) -> Decision:
    """An allowing decision (``allowlist`` unless a group rule admitted the call)."""
    return Decision(True, reason, rule, message)


def deny(reason: str, message: str, *, rule: Optional[str] = None) -> Decision:
    """A denying decision; ``reason`` must be one of the ``REASON_*`` denials."""
    return Decision(False, reason, rule, message)


# --------------------------------------------------------------------------- #
# the policy document
# --------------------------------------------------------------------------- #


class PolicyInvalid(ValueError):
    """A policy document that fails :func:`validate_policy`."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class GroupRule:
    """One rule: ``targets`` patterns, usable only by users in ``groups``."""

    targets: Tuple[str, ...]
    groups: frozenset
    name: Optional[str] = None

    @property
    def label(self) -> str:
        """Stable identifier for logs and the shadow ring."""
        return self.name or "|".join(self.targets)

    def matches(self, target: str) -> bool:
        """Exact or glob match against one tool reference."""
        return any(fnmatch.fnmatchcase(target, pattern) for pattern in self.targets)


@dataclass(frozen=True)
class PolicySnapshot:
    """One loaded policy plus how it was obtained."""

    rules: Tuple[GroupRule, ...] = ()
    version: str = ""
    loaded_at: float = 0.0
    error: Optional[str] = None
    # Non-fatal load warnings (see :func:`policy_warnings`): the document is usable,
    # but some rule decides nothing. Surfaced by the sync output and the admin page.
    warnings: Tuple[str, ...] = ()

    @property
    def available(self) -> bool:
        """False when the document could not be read or failed validation."""
        return self.error is None


_TOP_LEVEL_KEYS = {"rules"}
_RULE_KEYS = {"name", "target", "targets", "groups"}

# The only console tool the evaluator is asked about. The file tools are reachable
# through the agent's console allowlist alone, so a rule naming one is inert.
ENFORCED_CONSOLE_TOOLS = frozenset({"execute"})

_warned_policy_lines: set = set()
_warned_policy_lock = threading.Lock()


def _warn_once(message: str) -> None:
    """Log a load warning once per process (a policy reloads every TTL)."""
    with _warned_policy_lock:
        if message in _warned_policy_lines:
            return
        _warned_policy_lines.add(message)
    logger.warning("tool_access: %s", message)


def _patterns(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _console_target_warning(location: str, name: str) -> str:
    """The one sentence for an inert console rule target."""
    return (
        f"{location}: console tool '{name}' is not covered by tool-access rules; "
        "only 'execute' is enforced"
    )


def policy_warnings(policy: Any) -> List[str]:
    """Non-fatal problems in a policy document: ``[]`` when there are none.

    The one case today is a rule naming a console tool other than ``execute``. Only
    ``execute`` goes through this evaluator (``core/console_backend.py``), so
    ``read_file``/``write_file``/``edit_file``/``ls``/``glob``/``grep`` rules match
    nothing: they are advertised as targets but are inert, and the file tools remain
    constrained by the console allowlist. Refusing the file would be wrong (the rule
    is legal, it just does nothing), so it is a loud warning instead.
    """
    rules = policy.get("rules") if isinstance(policy, Mapping) else None
    if not isinstance(rules, list):
        return []
    warnings: List[str] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, Mapping):
            continue
        patterns = _patterns(rule.get("targets")) + _patterns(rule.get("target"))
        for pattern in patterns:
            if not isinstance(pattern, str):
                continue
            name = pattern.strip()
            if name not in CONSOLE_TOOLS or name in ENFORCED_CONSOLE_TOOLS:
                continue
            message = _console_target_warning(f"rules[{index}]", name)
            if message not in warnings:
                warnings.append(message)
    return warnings


def validate_policy(policy: Any) -> List[str]:
    """Human-readable schema errors; ``[]`` means the policy is usable.

    Every :func:`policy_warnings` entry is also logged here (once per process), so a
    rule that can never match is loud on load rather than silently inert. Warnings
    are NOT errors: the document stays usable and the sync still publishes it.
    """
    if not isinstance(policy, Mapping):
        return ["policy must be a mapping with a 'rules:' list"]

    errors: List[str] = []
    unknown = set(policy) - _TOP_LEVEL_KEYS
    if unknown:
        errors.append(f"unknown policy fields: {', '.join(sorted(map(str, unknown)))}")

    rules = policy.get("rules")
    if not isinstance(rules, list):
        errors.append("'rules' must be a list (use `rules: []` for no group rules)")
        return errors

    seen_names: set = set()
    seen_shapes: set = set()
    for index, rule in enumerate(rules):
        prefix = f"rules[{index}]"
        if not isinstance(rule, Mapping):
            errors.append(f"{prefix} must be a mapping")
            continue
        unknown_rule = set(rule) - _RULE_KEYS
        if unknown_rule:
            errors.append(
                f"{prefix} has unknown fields: {', '.join(sorted(map(str, unknown_rule)))}"
            )

        name = rule.get("name")
        if name is not None:
            if not isinstance(name, str) or not name.strip():
                errors.append(f"{prefix}.name must be a non-empty string")
            elif name.strip() in seen_names:
                errors.append(f"{prefix}.name duplicates rule name '{name.strip()}'")
            else:
                seen_names.add(name.strip())

        patterns = _patterns(rule.get("targets")) + _patterns(rule.get("target"))
        if not patterns:
            errors.append(f"{prefix} needs 'targets' (or 'target') with at least one pattern")
        elif any(not isinstance(p, str) or not p.strip() for p in patterns):
            errors.append(f"{prefix}.targets must contain non-empty strings")

        groups = rule.get("groups")
        if not isinstance(groups, list):
            errors.append(f"{prefix}.groups must be a list of group names")
        elif not groups:
            # An empty group set would grant nobody, but it is far more likely a
            # mistake than an intent -- refuse it instead of shipping a silent no-op.
            errors.append(f"{prefix}.groups must name at least one group")
        elif any(not isinstance(g, str) or not g.strip() for g in groups):
            errors.append(f"{prefix}.groups must contain non-empty strings")

        if patterns and isinstance(groups, list):
            shape = (
                tuple(sorted({p.strip() for p in patterns if isinstance(p, str)})),
                tuple(sorted({g.strip() for g in groups if isinstance(g, str)})),
            )
            if shape in seen_shapes:
                errors.append(
                    f"{prefix} duplicates an earlier rule (same targets and groups): "
                    f"{', '.join(shape[0])}"
                )
            seen_shapes.add(shape)
    for message in policy_warnings(policy):
        _warn_once(message)
    return errors


def parse_rules(rules: Iterable[Mapping[str, Any]]) -> Tuple[GroupRule, ...]:
    """Normalize validated rule mappings into :class:`GroupRule` objects.

    Also the second place a load warning can come from: a parsed rule whose target is
    an unenforced console tool is reported here (once per process, deduped with
    :func:`validate_policy`) so a caller that parses without validating still hears
    about a rule that can never match.
    """
    parsed: List[GroupRule] = []
    for rule in rules:
        patterns = _patterns(rule.get("targets")) + _patterns(rule.get("target"))
        name = rule.get("name")
        parsed_rule = GroupRule(
            targets=tuple(p.strip() for p in patterns if isinstance(p, str) and p.strip()),
            groups=frozenset(
                g.strip()
                for g in (rule.get("groups") or ())
                if isinstance(g, str) and g.strip()
            ),
            name=name.strip() if isinstance(name, str) and name.strip() else None,
        )
        for target in parsed_rule.targets:
            if target in CONSOLE_TOOLS and target not in ENFORCED_CONSOLE_TOOLS:
                _warn_once(_console_target_warning(f"rule '{parsed_rule.label}'", target))
        parsed.append(parsed_rule)
    return tuple(parsed)


# --- snapshot cache --------------------------------------------------------- #

_snapshot: Optional[PolicySnapshot] = None
_snapshot_expiry: float = 0.0
_snapshot_generation = 0
_snapshot_lock = threading.Lock()


def _client():
    """The etcd handle every policy read/write and the watch go through.

    One seam, so a test (or an embedded deployment) can replace the registry without
    a network: ``monkeypatch.setattr(tool_access, "_client", lambda: fake)``.
    """
    from core.auth import get_identity_manager

    return get_identity_manager().client


def _read_document() -> Tuple[Any, str]:
    """``(document, version)`` from the registry; ``document`` is None when absent."""
    value, metadata = _client().get(POLICY_PATH)
    if not value:
        return None, ""
    version = str(getattr(metadata, "mod_revision", "") or "")
    return json.loads(value.decode("utf-8")), version


def _load() -> PolicySnapshot:
    """Read and validate one snapshot. Raises ``PolicyInvalid`` / registry errors."""
    document, version = _read_document()
    if document is None:
        # An absent key is a legitimate state (nothing configured yet): no rules, so
        # the allowlist alone decides. It is NOT the same as an unreadable document.
        return PolicySnapshot((), version or "absent", time.monotonic())
    errors = validate_policy(document)
    if errors:
        raise PolicyInvalid(errors)
    return PolicySnapshot(
        parse_rules(document["rules"]),
        version,
        time.monotonic(),
        warnings=tuple(policy_warnings(document)),
    )


def _load_or_error() -> PolicySnapshot:
    try:
        return _load()
    except PolicyInvalid as exc:
        logger.error(
            "tool_access: invalid policy at %s (failing closed): %s",
            POLICY_PATH,
            "; ".join(exc.errors),
        )
        return PolicySnapshot(
            error=f"invalid policy document: {'; '.join(exc.errors[:3])}"
        )
    except Exception as exc:  # registry error, bad JSON, undecodable bytes, ...
        logger.warning("tool_access: failed to read %s (failing closed): %s", POLICY_PATH, exc)
        return PolicySnapshot(error=f"policy read failed: {exc}")


def policy_snapshot() -> PolicySnapshot:
    """The current policy snapshot, re-read when older than :data:`POLICY_TTL_S`."""
    global _snapshot, _snapshot_expiry, _snapshot_generation
    for _attempt in (0, 1):
        with _snapshot_lock:
            snapshot = _snapshot
            if snapshot is not None and time.monotonic() < _snapshot_expiry:
                return snapshot
            generation = _snapshot_generation

        fresh = _load_or_error()
        with _snapshot_lock:
            if _snapshot_generation != generation:
                # A reset (policy edit) landed mid-read: this caller's document may
                # predate the edit. Drop it and read again instead of caching it.
                continue
            _snapshot = fresh
            _snapshot_expiry = time.monotonic() + (
                POLICY_TTL_S if fresh.available else POLICY_ERROR_TTL_S
            )
            return fresh
    return fresh


def reset_snapshot() -> None:
    """Invalidate the cached snapshot; the next read goes to the registry."""
    global _snapshot, _snapshot_expiry, _snapshot_generation
    with _snapshot_lock:
        _snapshot_generation += 1
        _snapshot = None
        _snapshot_expiry = 0.0


def group_rules() -> Tuple[GroupRule, ...]:
    """The loaded group rules (empty when the policy is absent or unusable)."""
    return policy_snapshot().rules


def publish_policy(document: Any, *, client: Any = None) -> None:
    """Validate and write the policy document to the registry.

    Raises :class:`PolicyInvalid` (writing nothing) when the document is malformed,
    so a bad file never replaces a good policy. Used by the workspace sync.
    """
    errors = validate_policy(document)
    if errors:
        raise PolicyInvalid(errors)
    writer = client if client is not None else _client()
    writer.put(POLICY_PATH, json.dumps(document))
    reset_snapshot()


# --- the watch -------------------------------------------------------------- #

_watch_ids: Optional[List[Any]] = None
_watch_lock = threading.Lock()


def _event_keys(event: Any) -> List[str]:
    """Best-effort key list off one etcd watch response (empty when unreadable)."""
    keys: List[str] = []
    for raw in getattr(event, "events", None) or ():
        key = getattr(getattr(raw, "kv", None), "key", None) or getattr(raw, "key", None)
        if isinstance(key, bytes):
            keys.append(key.decode("utf-8", "replace"))
        elif isinstance(key, str):
            keys.append(key)
    return keys


def _on_policy_change(event: Any = None) -> None:
    """etcd watch callback (sync): drop the snapshot for a real policy change.

    The shadow-denial ring lives under a key sharing this prefix, and entries are
    written while a shadow window is failing calls -- so the key is filtered here
    rather than letting every ring write invalidate the policy cache.
    """
    keys = _event_keys(event)
    if keys and POLICY_PATH not in keys:
        return
    reset_snapshot()


def install_watch() -> None:
    """Install the policy watch (idempotent, once per process).

    Every process that enforces must call this at startup: a process whose only
    reader is its own cache would otherwise keep the document it first loaded.
    """
    global _watch_ids
    with _watch_lock:
        if _watch_ids is not None:
            return
        client = _client()
        exact = getattr(client, "add_watch_callback", None)
        try:
            if callable(exact):
                _watch_ids = [exact(POLICY_PATH, _on_policy_change)]
            else:
                _watch_ids = [client.add_watch_prefix_callback(POLICY_PATH, _on_policy_change)]
        except Exception:
            _watch_ids = None
            raise
    mode = tool_access_mode()
    logger.info("tool_access: watch installed on %s; mode=%s", POLICY_PATH, mode)


def cancel_watch() -> None:
    """Cancel the policy watch and clear the sentinel (idempotent)."""
    global _watch_ids
    with _watch_lock:
        watch_ids, _watch_ids = _watch_ids, None
    if not watch_ids:
        return
    client = _client()
    for watch_id in watch_ids:
        client.cancel_watch(watch_id)


# --------------------------------------------------------------------------- #
# the mode switch
# --------------------------------------------------------------------------- #

_mode_lock = threading.Lock()
_mode_cache: Tuple[Optional[str], str] = (None, DEFAULT_MODE)


def tool_access_mode() -> str:
    """``TOOL_ACCESS_MODE`` -- one switch for the whole framework.

    Default ``enforce``. An unrecognized value logs an error (once per distinct
    value) and behaves as ``enforce``: a typo must never widen access. ``off`` logs
    a one-time warning the first time a process resolves it, so a stack running
    without group rules is never silent about it.
    """
    global _mode_cache
    raw = (os.getenv(MODE_ENV) or "").strip().lower()
    with _mode_lock:
        seen, value = _mode_cache
        if seen == raw:
            return value
        if not raw:
            value = DEFAULT_MODE
        elif raw in MODES:
            value = raw
        else:
            logger.error(
                "tool_access: unrecognized %s=%r; failing closed to %r (valid: %s)",
                MODE_ENV,
                raw,
                DEFAULT_MODE,
                MODES_HELP,
            )
            value = DEFAULT_MODE
        _mode_cache = (raw, value)
    if value == "off":
        logger.warning(
            "tool_access: %s=off -- group rules are NOT enforced; every agent keeps "
            "only its own allowlist",
            MODE_ENV,
        )
    return value


def enforce(
    decision: Decision,
    mode: Optional[str] = None,
    *,
    agent: Optional[str] = None,
    groups: Sequence[str] = (),
    target: Optional[str] = None,
    surface: Optional[str] = None,
) -> Decision:
    """Apply the mode to a decision.

    Both relaxed modes touch :data:`GROUP_HALF_REASONS` only -- the allowlist half
    is enforced in every mode (:data:`ENFORCE_AGENT_TOKENS` governs that, not this
    switch), so a shadow window can never execute a call outside the agent's
    manifest. ``off`` allows a group-rule denial silently; ``shadow`` allows it and
    records it (the ring entry and the log line carry
    ``agent``/``target``/``groups``/``surface``); ``enforce`` returns the decision
    unchanged.

    **Synchronous** (the ``shadow`` ring write is a throttled blocking registry
    call). Event-loop callers must use :func:`enforce_async`.
    """
    resolved = mode or tool_access_mode()
    if decision.allowed or decision.reason not in GROUP_HALF_REASONS:
        return decision

    if resolved == "off":
        return Decision(True, REASON_MODE_OFF, decision.rule, decision.message)

    if resolved == "shadow":
        record_shadow_denial(
            decision, agent=agent, groups=groups, target=target, surface=surface
        )
        return Decision(True, REASON_SHADOW, decision.rule, decision.message)

    return decision


async def enforce_async(
    decision: Decision,
    mode: Optional[str] = None,
    *,
    agent: Optional[str] = None,
    groups: Sequence[str] = (),
    target: Optional[str] = None,
    surface: Optional[str] = None,
) -> Decision:
    """:func:`enforce` without blocking the event loop.

    Identical semantics; the only difference is that the ``shadow`` ring write (a
    throttled registry read-modify-write) runs in a worker thread instead of on the
    loop. Event-loop callers must use this one.
    """
    resolved = mode or tool_access_mode()
    if decision.allowed or decision.reason not in GROUP_HALF_REASONS:
        return decision

    if resolved == "off":
        return Decision(True, REASON_MODE_OFF, decision.rule, decision.message)

    if resolved == "shadow":
        await asyncio.to_thread(
            record_shadow_denial,
            decision,
            agent=agent,
            groups=groups,
            target=target,
            surface=surface,
        )
        return Decision(True, REASON_SHADOW, decision.rule, decision.message)

    return decision


# --------------------------------------------------------------------------- #
# the evaluator
# --------------------------------------------------------------------------- #


def _session_reference(target: str) -> Optional[Tuple[str, Optional[str]]]:
    """``(server, site)`` for an MCP session target, ``None`` when unusable.

    Accepts ``<server>``, ``<site>__<mcp>`` and their ``mcp__``-prefixed spellings.
    """
    reference = target[len("mcp__"):] if target.startswith("mcp__") else target
    parts = reference.split("__")
    if len(parts) == 1 and parts[0]:
        return parts[0], None
    if len(parts) == 2 and all(parts):
        return parts[1], parts[0]
    return None


def session_reference(target: str) -> Optional[Tuple[str, Optional[str]]]:
    """``(server, site)`` for an MCP-session target, or ``None`` when unusable.

    The same grammar the evaluator uses, so a caller resolving a session's exposure
    splits the reference exactly as the decision will.
    """
    return _session_reference(target)


def _allowlist_grants(
    allowed: Optional[EffectiveAllowlist], target: str, session: bool
) -> bool:
    if allowed is None:
        return False
    if not session:
        return permits_tool(allowed, target)
    reference = _session_reference(target)
    if reference is None:
        return False
    server, site = reference
    return permits_mcp_session(allowed, server, site=site)


def authorize(
    *,
    agent: Optional[str],
    groups: Sequence[str],
    target: str,
    allowed: Optional[EffectiveAllowlist],
    public: bool = False,
    surface: str = "tool",
    session: bool = False,
) -> Decision:
    """Decide one call. Mode-independent -- apply the answer with :func:`enforce`.

    ``agent`` is the agent the verified token names (``None`` for a caller with no
    agent record), ``groups`` its token groups, ``target`` the reference the
    enforcement point is about to use, ``allowed`` the agent's resolved allowlist
    and ``public`` the front-door flag (no agent record: the tool's own exposure
    replaces the allowlist part). Pass ``session=True`` to authorize opening an MCP
    session, where ``target`` is the server reference. ``surface`` names the
    enforcement point (``hub``, ``relay``, ``host``, ``bound_tool``, ``runner``) and
    is echoed in every denial message, so the same refusal is attributable wherever
    it is logged.

    **Synchronous**: this blocks the calling thread on one registry read (cached for
    :data:`POLICY_TTL_S`). Async callers -- every enforcement point on an event loop
    -- must use :func:`authorize_async`; this form is for a caller that is already
    in a worker thread and for tests.
    """
    return _decide(
        policy_snapshot(),
        agent=agent,
        groups=groups,
        target=target,
        allowed=allowed,
        public=public,
        surface=surface,
        session=session,
    )


async def authorize_async(
    *,
    agent: Optional[str],
    groups: Sequence[str],
    target: str,
    allowed: Optional[EffectiveAllowlist],
    public: bool = False,
    surface: str = "tool",
    session: bool = False,
) -> Decision:
    """:func:`authorize` without blocking the event loop.

    The registry read happens in a worker thread; the decision itself is pure. Every
    enforcement point on an event loop (hub, relay, host-before-runner, bound tools)
    must use this, not the sync form.
    """
    snapshot = await asyncio.to_thread(policy_snapshot)
    return _decide(
        snapshot,
        agent=agent,
        groups=groups,
        target=target,
        allowed=allowed,
        public=public,
        surface=surface,
        session=session,
    )


def _decide(
    snapshot: PolicySnapshot,
    *,
    agent: Optional[str],
    groups: Sequence[str],
    target: str,
    allowed: Optional[EffectiveAllowlist],
    public: bool = False,
    surface: str = "tool",
    session: bool = False,
) -> Decision:
    """The decision itself: one already-loaded snapshot in, one verdict out, no I/O."""
    reference = (target or "").strip()
    where = f" [{surface}]" if surface else ""
    who = f"agent '{agent}'" if agent else "caller with no agent record"
    if not reference:
        return deny(REASON_UNKNOWN_TARGET, f"access_denied{where}: empty tool reference")

    if session and _session_reference(reference) is None:
        return deny(
            REASON_UNKNOWN_TARGET,
            f"access_denied{where}: {reference!r} is not an MCP server reference",
        )

    # 1. The allowlist half -- always enforced, in every mode.
    # `public` is the front door: the caller has no agent record, so the target's own
    # published exposure stands in for the allowlist. It cannot express "this token
    # names an agent that has no record" -- see the module docstring's Phase 5 note.
    if public:
        base = allow(REASON_PUBLIC, message=f"'{reference}' is publicly exposed")
    elif _allowlist_grants(allowed, reference, session):
        base = allow(REASON_ALLOWLIST)
    else:
        return deny(
            REASON_NOT_IN_ALLOWLIST,
            f"access_denied{where}: {who} is not allowed to use '{reference}'",
        )

    # 2. The group-rule half -- one policy read, never a stale one.
    if not snapshot.available:
        return deny(
            REASON_POLICY_UNAVAILABLE,
            f"access_denied{where}: '{reference}' cannot be authorized -- the "
            f"tool-access policy is unavailable ({snapshot.error})",
        )

    matching = tuple(rule for rule in snapshot.rules if rule.matches(reference))
    if not matching:
        # No rule constrains this target: the allowlist (or the public front door)
        # decides alone.
        return base

    held = {str(group).strip() for group in groups or () if str(group).strip()}
    for rule in matching:
        if rule.groups & held:
            return allow(
                REASON_GROUP_MATCH,
                rule=rule.label,
                message=f"'{reference}' allowed by group rule '{rule.label}'",
            )

    labels = ", ".join(rule.label for rule in matching)
    return deny(
        REASON_GROUP_DENIED,
        f"access_denied{where}: {who} is in none of the groups that may use "
        f"'{reference}' (rule: {labels})",
        rule=labels,
    )


def authorize_claims(
    claims: Optional[Any],
    *,
    target: str,
    allowed: Optional[EffectiveAllowlist],
    public: bool = False,
    surface: str = "tool",
    session: bool = False,
) -> Decision:
    """:func:`authorize` for a verified token's claims -- the one-liner for a caller.

    ``claims`` is an :class:`core.agent_token.Claims` (duck-typed) or ``None`` when
    no token verified: the agent and its groups come from the token only, never from
    a request body. Enforcement points should prefer this over spelling out
    ``claims.agent`` / ``claims.groups`` at every site. Synchronous -- event-loop
    callers use :func:`authorize_claims_async`.
    """
    return authorize_claims_decision(
        policy_snapshot(), claims, target=target, allowed=allowed, public=public,
        surface=surface, session=session,
    )


async def authorize_claims_async(
    claims: Optional[Any],
    *,
    target: str,
    allowed: Optional[EffectiveAllowlist],
    public: bool = False,
    surface: str = "tool",
    session: bool = False,
) -> Decision:
    """:func:`authorize_claims` without blocking the event loop."""
    snapshot = await asyncio.to_thread(policy_snapshot)
    return authorize_claims_decision(
        snapshot, claims, target=target, allowed=allowed, public=public,
        surface=surface, session=session,
    )


def authorize_claims_decision(
    snapshot: PolicySnapshot,
    claims: Optional[Any],
    *,
    target: str,
    allowed: Optional[EffectiveAllowlist],
    public: bool = False,
    surface: str = "tool",
    session: bool = False,
) -> Decision:
    """The pure half of :func:`authorize_claims`: claims + snapshot, no I/O."""
    return _decide(
        snapshot,
        agent=getattr(claims, "agent", None),
        groups=getattr(claims, "groups", ()) or (),
        target=target,
        allowed=allowed,
        public=public,
        surface=surface,
        session=session,
    )


# --------------------------------------------------------------------------- #
# shadow-denial ring (diagnostics for the read-only admin page)
# --------------------------------------------------------------------------- #

_shadow_ring: "deque[dict]" = deque(maxlen=SHADOW_RING_CAP)
_shadow_lock = threading.Lock()
_last_shadow_persist = 0.0


def _persist_shadow_denial(entry: Mapping[str, Any]) -> None:
    """Best-effort copy into the shared ring; never raises, throttled per process.

    Read-modify-write, not a CAS: this is a diagnostic ring, and a lost sample from
    two processes denying in the same second costs nothing (the log line is the
    authoritative record).
    """
    global _last_shadow_persist
    now = time.monotonic()
    with _shadow_lock:
        if now - _last_shadow_persist < _SHADOW_PERSIST_MIN_INTERVAL_S:
            return
        _last_shadow_persist = now
    try:
        client = _client()
        value, _metadata = client.get(SHADOW_DENIAL_PATH)
        denials: List[Any] = []
        if value:
            try:
                document = json.loads(value.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                document = {}
            raw = document.get("denials") if isinstance(document, dict) else None
            denials = list(raw) if isinstance(raw, list) else []
        denials.insert(0, dict(entry))
        client.put(SHADOW_DENIAL_PATH, json.dumps({"denials": denials[:SHADOW_RING_CAP]}))
    except Exception as exc:  # a diagnostic must never break the call path
        logger.debug("tool_access: could not persist shadow denial: %s", exc)


def record_shadow_denial(
    decision: Decision,
    *,
    agent: Optional[str] = None,
    groups: Sequence[str] = (),
    target: Optional[str] = None,
    surface: Optional[str] = None,
) -> dict:
    """Log and ring one would-be denial (``shadow`` mode). Returns the entry.

    Entries carry the agent, target, reason, matched rule, the caller's groups and
    the surface -- never a user id, an email, or tool arguments.
    """
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent": agent,
        "target": target,
        "reason": decision.reason,
        "rule": decision.rule,
        "groups": sorted({str(group) for group in groups or () if str(group).strip()}),
        "surface": surface,
        "mode": "shadow",
    }
    with _shadow_lock:
        _shadow_ring.append(entry)
    logger.warning(
        "tool_access: would deny agent=%s target=%s reason=%s rule=%s surface=%s "
        "groups=%s",
        agent or "-",
        target or "-",
        decision.reason,
        decision.rule or "-",
        surface or "-",
        ",".join(entry["groups"]) or "-",
    )
    _persist_shadow_denial(entry)
    return entry


def recent_shadow_denials(limit: int = SHADOW_RING_CAP) -> List[dict]:
    """Recent would-be denials, newest first: the shared ring, else this process.

    The admin page runs in its own process, so the shared ring is what it reads;
    the in-process fallback keeps the view useful when etcd is unreadable.
    """
    try:
        value, _metadata = _client().get(SHADOW_DENIAL_PATH)
        if value:
            document = json.loads(value.decode("utf-8"))
            denials = document.get("denials") if isinstance(document, dict) else None
            if isinstance(denials, list):
                entries = [dict(entry) for entry in denials if isinstance(entry, dict)]
                if entries:
                    return entries[:limit]
    except Exception as exc:
        logger.debug("tool_access: could not read the shared shadow ring: %s", exc)
    with _shadow_lock:
        return [dict(entry) for entry in reversed(_shadow_ring)][:limit]


def clear_shadow_denials() -> None:
    """Empty the shared and in-process rings (best effort)."""
    global _last_shadow_persist
    with _shadow_lock:
        _shadow_ring.clear()
        _last_shadow_persist = 0.0
    try:
        _client().put(SHADOW_DENIAL_PATH, json.dumps({"denials": []}))
    except Exception as exc:
        logger.debug("tool_access: could not clear the shared shadow ring: %s", exc)
