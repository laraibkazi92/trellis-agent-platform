# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
import asyncio
import random
from pathlib import Path
from typing import Dict, Any, Optional, List
from taskiq_redis import ListQueueBroker
from pydantic_ai import Agent

from core.auth import agent_token_var, user_id_var
from core.agent_token import mint_for_run, refresh
from core.models import Identity, IdentityType
from core.execution.client import RunnerCallError, RunnerClient, RunnerUnavailable
from core.execution.contract import WORKFLOW_RUNTIMES, ExecRequest
from core.execution.spec import RESTRICTED_ENV_VARS
from core.tunables import resolve as resolve_tunable
from core.agent_factory import (
    build_agent,
    get_identity_manager,
    get_health_monitor,
    get_hub_client,
    install_llm_key_watch,
    install_llm_defaults_watch,
)
from core.llm_defaults import provider_for_config, warm_defaults_cache
from core.llm_factory import warm_key_cache

# Entrypoint interpreters a workflow container can start, defined once in
# ``core.execution.contract`` (the wire Literal) and imported here so the worker's
# config check and the runner's argv map can never drift apart. `exec` runs the file
# as given (a shebang script or a binary), which is what the pre-container worker did
# for any runtime it did not recognize.


def _workflow_runtime(config_data: Dict[str, Any]) -> str:
    """The workflow's runtime, mapped onto what the runner can start.

    v0.7's worker ran an unrecognized `runtime:` as a bare executable; keep that
    (as `exec`) instead of turning a working pipeline into a failure, but say so.
    """
    raw = str(config_data.get("runtime") or "python").strip().lower()
    if raw in WORKFLOW_RUNTIMES:
        return raw
    print(
        f"Workflow {config_data.get('name')!r} declares runtime {raw!r}, which is not "
        f"one of {', '.join(WORKFLOW_RUNTIMES)}; running its entrypoint directly (exec)."
    )
    return "exec"


def _truncate_output(text: Optional[str], max_chars: Optional[int] = None) -> str:
    if max_chars is None:
        max_chars = resolve_tunable("max_run_output_chars")
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    half = max(1, (max_chars - 100) // 2)
    omitted = max(0, len(text) - (half * 2))
    return f"{text[:half]}\n\n[... Truncated {omitted} characters ...]\n\n{text[-half:]}"


# A pipeline that outruns the runner's per-stream cap (8 MiB stdout) used to come back
# as a silently halved report. Pick up where `_truncate_output` leaves off: no length is
# known here (the runner cut the stream), so say what happened instead of a count.
WORKFLOW_OUTPUT_TRUNCATION_MARKER = (
    "\n\n[... Truncated output: the runner's per-stream limit was reached ...]"
)


async def _record_run_state(identity_mgr, agent_name: str, task_id: str, state: str, metadata: Dict[str, Any]) -> bool:
    """Persist a workflow run's state, logging (never raising) on failure.

    Returns True when the transition was accepted. False means the terminal-state
    guard rejected it (or the write failed) — callers must not record a matching
    event in that case.
    """
    try:
        return bool(
            await asyncio.to_thread(
                identity_mgr.record_agent_run_state,
                agent_name,
                task_id,
                state,
                metadata,
            )
        )
    except Exception as err:
        print(f"Failed to record {state} state for {agent_name} run {task_id}: {err}")
        return False


async def _append_run_event(identity_mgr, agent_name: str, task_id: str, event_type: str, payload: Optional[Dict[str, Any]] = None) -> None:
    """Append one run event, logging (never raising) on failure."""
    if task_id == "unknown":
        return
    try:
        await asyncio.to_thread(identity_mgr.append_run_event, agent_name, task_id, event_type, payload)
    except Exception as err:
        print(f"Failed to append {event_type} event for {agent_name} run {task_id}: {err}")


async def _write_heartbeat(identity_mgr, agent_name: str, task_id: str) -> None:
    """Refresh a run's heartbeat, logging (never raising) on failure."""
    if task_id == "unknown":
        return
    try:
        await asyncio.to_thread(identity_mgr.record_run_heartbeat, agent_name, task_id)
    except Exception as err:
        print(f"Failed to write heartbeat for {agent_name} run {task_id}: {err}")


async def _abort_if_cancelled(identity_mgr, agent_name: str, task_id: str) -> bool:
    """True when the run must not start (cancelled, or already finalized by the reaper).

    A `pending` run that was reaped to `failed`/`completed` must not execute: its task
    may still be sitting in the queue, and running it would duplicate the retry.
    """
    run_record = await asyncio.to_thread(identity_mgr.get_agent_run, agent_name, task_id)
    state = (run_record or {}).get("state")
    if state == "cancelled":
        print(f"Task {task_id} for {agent_name} was cancelled before processing. Aborting.")
        await _append_run_event(identity_mgr, agent_name, task_id, "run_cancelled", {"reason": "cancelled_before_start"})
        return True
    if state in ("failed", "completed"):
        print(f"Task {task_id} for {agent_name} was already finalized ({state}). Skipping execution.")
        return True
    return False


async def _check_input_guardrails(
    identity_mgr,
    agent_name: str,
    task_id: str,
    user_id: str,
    prompt: str,
    config_data: Dict[str, Any],
) -> tuple[bool, str]:
    """Run the input guardrail over a run's prompt; returns ``(blocked, prompt)``.

    Shared by the agent and script paths so both record the same state and event on a
    hit. Fail-open: any evaluation failure leaves the prompt untouched, and only an
    explicit "block" stops the run. Callers decide what "stopped" means (no LLM call
    for an agent, no runner container for a script).
    """
    input_action, checked_prompt, input_hits = "allow", prompt, []
    try:
        from core import guardrails
        input_action, checked_prompt, input_hits = await asyncio.to_thread(
            guardrails.evaluate_agent_input, prompt, config_data)
    except Exception as err:
        print(f"Guardrail input evaluation failed for {agent_name} run {task_id}: {err}")
        input_action, checked_prompt, input_hits = "allow", prompt, []

    input_hit_counts: Dict[str, int] = {}
    if input_hits:
        try:
            from core import guardrails
            input_hit_counts = dict(await asyncio.to_thread(guardrails.hit_counts, input_hits))
        except Exception as err:
            print(f"Failed to count guardrail hits for {agent_name} run {task_id}: {err}")
        try:
            await asyncio.to_thread(
                identity_mgr.record_guardrail_hits, agent_name, input_hit_counts)
        except Exception as err:
            print(f"Failed to record guardrail hits for {agent_name} run {task_id}: {err}")

    if input_action != "block":
        return False, checked_prompt

    failed = await _record_run_state(
        identity_mgr,
        agent_name,
        task_id,
        "failed",
        {
            "prompt": _truncate_output(prompt, max_chars=8192),
            "user_id": user_id,
            "error": "guardrail blocked input",
            "guardrail_hits": input_hit_counts,
        },
    )
    if failed:
        await _append_run_event(
            identity_mgr, agent_name, task_id, "run_failed",
            {"error_type": "GuardrailBlocked", "error_chars": 0},
        )
    return True, prompt


async def enqueue_workflow_run(
    name: str,
    config: Dict,
    xml_payload: str,
    attempt: int = 1,
    prior_run_id: Optional[str] = None,
) -> str:
    """Dispatch a workflow (script or agent) and record its initial pending state.

    Returns the task id. Retries pass ``attempt``/``prior_run_id`` so the new run
    record carries the chain; a first enqueue keeps the original metadata shape.
    """
    identity_mgr = get_identity_manager()
    agent_identity = Identity(id=name, type=IdentityType.WORKFLOW)

    if config.get("type") == "background_script":
        task = await run_background_script.kiq(
            agent_name=name,
            prompt=xml_payload,
            user_id=agent_identity.to_legacy_string(),
        )
    else:
        task = await run_background_agent.kiq(
            agent_name=name,
            prompt=xml_payload,
            user_id=agent_identity.to_legacy_string(),
        )

    pending_metadata = {"prompt": xml_payload, "user_id": agent_identity.to_legacy_string()}
    if attempt != 1 or prior_run_id is not None:
        pending_metadata["attempt"] = attempt
        if prior_run_id is not None:
            pending_metadata["prior_run_id"] = prior_run_id

    try:
        await asyncio.to_thread(
            identity_mgr.record_agent_run_state,
            name,
            task.task_id,
            "pending",
            pending_metadata,
        )
    except Exception as e:
        print(f"Failed to record pending state for {name}: {e}")

    await _append_run_event(identity_mgr, name, task.task_id, "run_enqueued", {"user_id": agent_identity.to_legacy_string()})
    return task.task_id


# How often a running background task re-reads its run record to notice a cancellation.
# Module-level so tests can shorten it without patching asyncio.sleep process-wide.
CANCELLATION_POLL_INTERVAL_S = 15.0


# --- runner capacity (v0.7.2 R4) ------------------------------------------- #
# A saturated runner pool answers 429 (`capacity_exhausted`, retryable) instead of
# queueing, so a workflow that asks for the last slot used to fail one run per
# saturation. Waiting is bounded by `workflow_slot_wait` and grows the retry interval,
# so a long saturation does not hammer the socket; every waited second is charged
# against the run's own deadline (see `_exec_with_slot_wait`).
SLOT_WAIT_INITIAL_S = 1.0
SLOT_WAIT_MAX_S = 30.0
# +/- fraction per step: several workflows can hit one saturation together, and a
# fixed interval would wake all of them on the same tick. A step is the capped
# backoff plus/minus this fraction, so the ceiling is SLOT_WAIT_MAX_S * (1 + jitter).
SLOT_WAIT_JITTER = 0.25
# Never re-attempt with an unusable budget: a retry carrying a second of deadline
# makes the runner create a container only to kill it, and the run then fails as
# `timeout` instead of `runner_capacity`. Half of a short deadline is accepted, so a
# deliberately small WORKFLOW_RUN_TIMEOUT in a test or a demo still gets one retry.
SLOT_WAIT_MIN_DEADLINE_S = 5.0
# How long to let a detected cancel finish stopping its container before the worker
# stops waiting for it. The stop is a small HTTP call with its own 30 s timeout.
STOP_OUTCOME_WAIT_S = 30.0


def _slot_wait_step(backoff: float) -> float:
    """One jittered retry step (``backoff`` itself is capped by the caller)."""
    return backoff * (1.0 + random.uniform(-SLOT_WAIT_JITTER, SLOT_WAIT_JITTER))


async def _slot_wait_sleep(seconds: float) -> None:
    """The retry wait itself. Module-level so tests can drive it without real time."""
    await asyncio.sleep(seconds)


async def _settle_cancel_monitor(monitor: "asyncio.Task", *, detected: bool = False) -> None:
    """Tear the cancellation poller down without losing the stop it is performing.

    The poller's stop call is what ends the container, and that container ending is
    what makes the in-flight ``exec()`` return -- so the main coroutine routinely
    resumes while the poller is still inside ``stop_run``. Cancelling it there would
    discard the outcome the run event is about to report (``container_stopped`` and
    the count). When a cancel was detected, the poller is therefore *awaited* (bounded
    by the stop call's own 30 s timeout) instead of cancelled; in every other case
    there is nothing to wait for and it is cancelled outright.
    """
    if detected and not monitor.done():
        try:
            await asyncio.wait_for(asyncio.shield(monitor), timeout=STOP_OUTCOME_WAIT_S)
        except (asyncio.TimeoutError, Exception):  # incl. the poller's own errors
            pass
        return
    monitor.cancel()
    try:
        await monitor
    except asyncio.CancelledError:
        pass
    except Exception:  # the poller swallows its own errors; a race can still leak one
        pass


class _RunCancelled(Exception):
    """The run was cancelled while it was waiting for a runner slot (never started)."""


async def _exec_with_slot_wait(
    runner: RunnerClient,
    request: ExecRequest,
    *,
    identity_mgr,
    agent_name: str,
    task_id: str,
    cancelled=None,
):
    """``runner.exec`` a workflow run, waiting out a saturated runner pool.

    Two ceilings apply and the earlier one wins:

    * ``workflow_slot_wait`` -- how long the worker is willing to wait at all;
    * the run's own deadline (``workflow_run_timeout``) -- every second spent waiting
      is removed from the ``deadline_ms`` sent with the retry, so a run that queued for
      minutes cannot then also get its full runtime on top.

    ``run_waiting`` is recorded once, on the first 429, with the runner's own limits
    (the message names them; no secret is ever in it); ``run_slot_acquired`` records
    the total wait once the run actually starts -- an operator must be able to tell
    "queued" from "slow". Any other error is re-raised untouched.

    ``workflow_slot_wait=0`` disables the wait entirely: the first 429 is re-raised
    untouched, exactly as before v0.7.2 (no event, same error code and message).

    ``cancelled`` is the poller's flag: a run cancelled while it was still queued must
    not start a container, so the wait ends with :class:`_RunCancelled` instead.
    """
    deadline_s = request.deadline_ms / 1000.0
    slot_wait_s = max(0.0, float(resolve_tunable("workflow_slot_wait")))
    min_deadline_s = min(SLOT_WAIT_MIN_DEADLINE_S, deadline_s / 2.0)
    waited = 0.0
    backoff = SLOT_WAIT_INITIAL_S
    announced = False

    while True:
        if cancelled is not None and cancelled():
            raise _RunCancelled()
        attempt = request
        if waited:
            attempt = request.model_copy(
                update={
                    "deadline_ms": max(1, request.deadline_ms - int(waited * 1000)),
                    # A queued run outlives the token minted for it when the wait is
                    # longer than the token's TTL, and every attempt re-verifies.
                    "agent_token": refresh(agent_token_var.get()),
                }
            )
        try:
            result = await runner.exec(attempt)
        except RunnerCallError as err:
            if err.code != "capacity_exhausted" or slot_wait_s <= 0:
                raise
            if not announced:
                announced = True
                await _append_run_event(
                    identity_mgr,
                    agent_name,
                    task_id,
                    "run_waiting",
                    {
                        "workflow": agent_name,
                        "reason": err.code,
                        "detail": str(err.message)[:512],
                        "slot_wait_s": round(slot_wait_s, 1),
                        "deadline_ms": attempt.deadline_ms,
                    },
                )
            headroom = min(slot_wait_s - waited, deadline_s - waited)
            if headroom <= 0:
                # A cancel can land between the 429 and this check; it wins, so a run
                # the operator cancelled is never recorded as a capacity failure.
                if cancelled is not None and cancelled():
                    raise _RunCancelled() from err
                raise RuntimeError(
                    f"runner_capacity: no free runner container slot for workflow "
                    f"{agent_name!r} after waiting {waited:.1f}s "
                    f"(WORKFLOW_SLOT_WAIT_S={slot_wait_s:.1f}, "
                    f"WORKFLOW_RUN_TIMEOUT={deadline_s:.0f})"
                ) from err
            step = min(_slot_wait_step(backoff), headroom)
            await _slot_wait_sleep(step)
            waited += step
            backoff = min(backoff * 2, SLOT_WAIT_MAX_S)
            # Checked before the next attempt, not after it: an attempt whose deadline
            # is nearly spent starts a container the runner kills immediately, and the
            # run would then fail as `timeout` rather than `runner_capacity`.
            if deadline_s - waited < min_deadline_s:
                if cancelled is not None and cancelled():
                    raise _RunCancelled()
                raise RuntimeError(
                    f"runner_capacity: no free runner container slot for workflow "
                    f"{agent_name!r} after waiting {waited:.1f}s: only "
                    f"{max(0.0, deadline_s - waited):.1f}s of the run's "
                    f"{deadline_s:.0f}s deadline would be left, not enough to run it "
                    f"(WORKFLOW_SLOT_WAIT_S={slot_wait_s:.1f})"
                ) from err
            continue
        if waited:
            await _append_run_event(
                identity_mgr,
                agent_name,
                task_id,
                "run_slot_acquired",
                {
                    "workflow": agent_name,
                    "waited_s": round(waited, 1),
                    "deadline_ms": attempt.deadline_ms,
                },
            )
        return result


# Redis broker configuration
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
broker = ListQueueBroker(redis_url, socket_timeout=None)

from taskiq import TaskiqEvents, TaskiqScheduler, Context, TaskiqDepends
from taskiq.schedule_sources import LabelScheduleSource


@broker.on_event(TaskiqEvents.WORKER_STARTUP)
def _install_llm_key_watch_on_startup(state) -> None:
    """Register the LLM-key etcd watch in the worker process (idempotent).

    The taskiq worker is a separate process from the Host with its own agent
    cache, so it needs its own watch registered at startup. This hook is sync and
    runs during startup (no event loop to hand off to), so the cache warms are called
    directly rather than via asyncio.to_thread.
    """
    install_llm_key_watch()
    install_llm_defaults_watch()
    warm_key_cache()
    warm_defaults_cache()
    # The worker is its own process, so the tool-access policy watch must be
    # registered here too. A failure must never block worker startup.
    try:
        from core import tool_access

        tool_access.install_watch()
    except Exception as e:
        print(f"Failed to install the tool-access watch: {e}")

scheduler = TaskiqScheduler(
    broker=broker,
    sources=[LabelScheduleSource(broker)],
)

# We use a single heartbeat task that runs every minute to check ETCD for dynamic cron jobs
import time
from datetime import datetime, timedelta, timezone
import pycron

@broker.task(schedule=[{"cron": "* * * * *"}])
async def dynamic_cron_heartbeat():
    """Runs every minute to trigger any dynamic background agents that have matching cron expressions."""
    
    identity_mgr = get_identity_manager()
    agent_names = await asyncio.to_thread(identity_mgr.list_agents)
    disabled_workflows = await asyncio.to_thread(identity_mgr.get_disabled_workflows)
    
    now = datetime.now()
    
    for name in agent_names:
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if not config_data or config_data.get("type") not in ("background_agent", "background_script"):
            continue

        # Periodic pruning of historical workflow runs (runs once per hour at minute 0).
        # Before the disabled check: a disabled workflow accumulates runs too, and the
        # reaper's full-history scan would otherwise read them forever.
        if now.minute == 0:
            try:
                await asyncio.to_thread(identity_mgr.prune_agent_runs, name, 100)
            except Exception as e:
                print(f"Failed to periodically prune runs for {name}: {e}")

        if name in disabled_workflows:
            continue

        trigger = config_data.get("trigger")
        if trigger and trigger.get("type") == "cron":
            expr_data = trigger.get("expression")
            expressions = expr_data if isinstance(expr_data, list) else [expr_data]
            
            for expr in expressions:
                if expr and pycron.is_now(expr, now):
                    print(f"Triggering background workflow {name} via cron: {expr}")
                    # System prompt for cron runs
                    xml_payload = f"<event_payload><![CDATA[\nScheduled execution triggered at {now.isoformat()}\n]]></event_payload>"

                    await enqueue_workflow_run(name, config_data, xml_payload)
                    break


def _utcnow() -> datetime:
    """Now, timezone-aware in UTC (tests monkeypatch this)."""
    return datetime.now(timezone.utc)


def _parse_iso(value: Any) -> Optional[datetime]:
    """Parse an ISO string or datetime into an aware UTC datetime; None on junk."""
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).strip())
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _attempt_of(metadata: Any) -> int:
    """The run's attempt number from its metadata; 1 when absent or malformed."""
    try:
        return max(1, int((metadata or {}).get("attempt", 1)))
    except (AttributeError, TypeError, ValueError):
        return 1


def _orphan_reason(
    state: Optional[str],
    heartbeat: Any,
    updated: Optional[datetime],
    now: datetime,
) -> Optional[Dict[str, Any]]:
    """Why a run looks abandoned, or None while it is still healthy.

    Only `pending` and `processing` can be orphaned. A processing run with a
    heartbeat is judged on the heartbeat; one without (a pre-heartbeat run) falls
    back to `updated`. Unparseable/missing timestamps never orphan.
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    if state == "processing":
        if heartbeat:
            hb = _parse_iso(heartbeat)
            if hb is None:
                return None
            age = int((now - hb).total_seconds())
            if age > resolve_tunable("reaper_stale_heartbeat_s"):
                return {"reason": "stale_heartbeat", "heartbeat_age_s": age, "fallback": False}
            return None
        if updated is None:
            return None
        age = int((now - updated).total_seconds())
        if age > resolve_tunable("reaper_stale_processing_s"):
            return {"reason": "stale_heartbeat", "heartbeat_age_s": None, "fallback": True}
        return None

    if state == "pending":
        if updated is None:
            return None
        age = int((now - updated).total_seconds())
        if age > resolve_tunable("reaper_stale_pending_s"):
            return {"reason": "stale_pending", "heartbeat_age_s": None, "fallback": False}
    return None


def _retry_policy(config: Optional[Dict[str, Any]]) -> tuple[int, int]:
    """(max_attempts, backoff_s) from config['retries']; (1, 60) when absent/malformed."""
    retries = (config or {}).get("retries")
    if not isinstance(retries, dict):
        return (1, 60)
    try:
        max_attempts = int(retries.get("max_attempts") or 1)
        backoff_s = int(retries.get("backoff_s") or 60)
    except (TypeError, ValueError):
        return (1, 60)
    return (max(1, max_attempts), max(0, backoff_s))


async def _reap_agent(identity_mgr, name: str, config: Dict, now: datetime) -> Dict[str, int]:
    """Fail one workflow's orphaned runs and enqueue the retries that are due."""
    stats = {"scanned": 0, "orphaned": 0, "retried": 0, "errors": 0}
    max_attempts, backoff_s = _retry_policy(config)

    try:
        # No limit: the default view is newest-first, and a stuck run is by
        # definition old. The per-agent retention (hourly prune to 100) bounds this.
        runs = await asyncio.to_thread(identity_mgr.get_agent_runs, name)
    except Exception as err:
        print(f"Failed to scan runs for {name}: {err}")
        stats["errors"] += 1
        return stats

    scan_cap = resolve_tunable("reaper_scan_per_agent")
    snapshots = [run for run in runs or [] if isinstance(run, dict) and run.get("run_id")]
    stats["scanned"] = len(snapshots)
    active = [run for run in snapshots if run.get("state") in ("pending", "processing")][:scan_cap]

    def _retry_is_due(run: Dict[str, Any]) -> bool:
        metadata = run.get("metadata")
        if run.get("state") != "failed" or not isinstance(metadata, dict):
            return False
        if metadata.get("retried_run_id") or metadata.get("retry_abandoned"):
            return False
        retry_at = _parse_iso(metadata.get("retry_at"))
        return retry_at is not None and retry_at <= now

    # Filter before capping so due retries are never starved by newer failures.
    retry_due = [run for run in snapshots if _retry_is_due(run)][:scan_cap]

    for run in active:
        run_id = run.get("run_id")
        try:
            fresh = await asyncio.to_thread(identity_mgr.get_agent_run, name, run_id)
        except Exception as err:
            print(f"Failed to re-read run {run_id} for {name}: {err}")
            stats["errors"] += 1
            continue
        if not fresh:
            continue

        state = fresh.get("state")
        if state not in ("pending", "processing"):
            continue

        heartbeat = None
        if state == "processing":
            try:
                heartbeat = await asyncio.to_thread(identity_mgr.get_run_heartbeat, name, run_id)
            except Exception as err:
                print(f"Failed to read heartbeat for {name} run {run_id}: {err}")
                stats["errors"] += 1
                continue

        updated = _parse_iso(fresh.get("updated_at") or fresh.get("timestamp"))
        orphan = _orphan_reason(state, heartbeat, updated, now)
        if not orphan:
            continue

        attempt = _attempt_of(fresh.get("metadata"))
        existing_metadata = fresh.get("metadata")
        if not isinstance(existing_metadata, dict):
            existing_metadata = {}
        metadata = {
            **existing_metadata,
            "orphaned": True,
            "orphan_reason": orphan["reason"],
            "orphaned_at": now.isoformat(),
            "heartbeat_age_s": orphan["heartbeat_age_s"],
            "attempt": attempt,
        }
        accepted = await _record_run_state(identity_mgr, name, run_id, "failed", metadata)
        if not accepted:
            # Terminal-state guard won (cancelled/completed meanwhile): never rewrite.
            continue
        stats["orphaned"] += 1
        await _append_run_event(
            identity_mgr,
            name,
            run_id,
            "run_orphaned",
            {
                "reason": orphan["reason"],
                "heartbeat_age_s": orphan["heartbeat_age_s"],
                "fallback": orphan.get("fallback", False),
                "attempt": attempt,
            },
        )

        if attempt < max_attempts:
            retry_at = (now + timedelta(seconds=backoff_s)).isoformat()
            try:
                await asyncio.to_thread(identity_mgr.mark_run_retry_due, name, run_id, retry_at)
            except Exception as err:
                print(f"Failed to schedule retry for {name} run {run_id}: {err}")
                stats["errors"] += 1
    # Second look: failed runs whose retry window has opened get re-enqueued once.
    for snapshot in retry_due:
        run_id = snapshot.get("run_id")
        try:
            fresh = await asyncio.to_thread(identity_mgr.get_agent_run, name, run_id)
        except Exception as err:
            print(f"Failed to re-read run {run_id} for {name}: {err}")
            stats["errors"] += 1
            continue
        if not fresh or fresh.get("state") != "failed":
            continue
        metadata = fresh.get("metadata")
        if not isinstance(metadata, dict):
            continue
        retry_at = _parse_iso(metadata.get("retry_at"))
        if retry_at is None or retry_at > now:
            continue
        if metadata.get("retried_run_id") or metadata.get("retry_abandoned"):
            continue
        attempt = _attempt_of(metadata)
        if attempt >= max_attempts:
            # The cap can be lowered after a retry was scheduled; clear the stale
            # deadline so this run leaves the due list instead of being re-read forever.
            try:
                await asyncio.to_thread(
                    identity_mgr.clear_run_retry, name, run_id, "attempts_exhausted"
                )
            except Exception as err:
                print(f"Failed to abandon retry for {name} run {run_id}: {err}")
                stats["errors"] += 1
            continue

        try:
            claimed = bool(await asyncio.to_thread(identity_mgr.claim_run_retry, name, run_id))
        except Exception as err:
            print(f"Failed to claim retry for {name} run {run_id}: {err}")
            stats["errors"] += 1
            continue
        if not claimed:
            continue

        try:
            # The stored prompt is the worker's copy for processing-path orphans
            # (truncated to 8 KiB), so very large trigger payloads retry truncated.
            new_run_id = await enqueue_workflow_run(
                name,
                config,
                metadata.get("prompt") or "",
                attempt=attempt + 1,
                prior_run_id=run_id,
            )
        except Exception as err:
            # Deliberate at-most-once: the claim stays, so a broken queue is not
            # hammered every two minutes.
            print(f"Failed to enqueue retry for {name} run {run_id}: {err}")
            stats["errors"] += 1
            continue

        try:
            await asyncio.to_thread(identity_mgr.complete_run_retry, name, run_id, new_run_id)
        except Exception as err:
            print(f"Failed to complete retry for {name} run {run_id}: {err}")
            stats["errors"] += 1

        await _append_run_event(
            identity_mgr, name, run_id, "run_retried",
            {"new_run_id": new_run_id, "attempt": attempt + 1},
        )
        await _append_run_event(
            identity_mgr, name, new_run_id, "run_retried",
            {"prior_run_id": run_id, "attempt": attempt + 1},
        )
        stats["retried"] += 1

    return stats


@broker.task(schedule=[{"cron": "*/2 * * * *"}])
async def reap_orphaned_runs() -> Dict[str, int]:
    """Every two minutes: fail runs whose worker died, retry failed runs that are due.

    Disabled workflows are still swept — cleanup must happen for them too.
    """
    totals = {"scanned": 0, "orphaned": 0, "retried": 0, "errors": 0}
    now = _utcnow()
    try:
        identity_mgr = get_identity_manager()
        names = await asyncio.to_thread(identity_mgr.list_agents)
    except Exception as err:
        print(f"Failed to list agents for run reaping: {err}")
        totals["errors"] += 1
        return totals

    for name in names or []:
        try:
            config = await asyncio.to_thread(identity_mgr.get_agent_config, name)
            if not config or config.get("type") not in ("background_agent", "background_script"):
                continue
            stats = await _reap_agent(identity_mgr, name, config, now)
        except Exception as err:
            print(f"Failed to reap runs for {name}: {err}")
            totals["errors"] += 1
            continue
        for key in totals:
            totals[key] += stats.get(key, 0)

    return totals


@broker.task
async def run_background_script(
    agent_name: str,
    prompt: str,
    user_id: str,
    context: Context = TaskiqDepends(),
) -> str:
    """Executes a script in the background as a Taskiq task.

    Since v0.7.1 the pipeline runs as ONE runner container per run (mounts: the
    workflow's own tree, ``shared/`` and only the tool suites its ``allowed_tools``
    names -- all read-only -- plus ``output/<name>`` and ``reports/<name>``
    read-write and a ``/tmp`` tmpfs). What still happens here in the worker: the
    guardrail evaluation on the input (a blocked run never creates a container), the
    config/registry lookups, the run record/event writes and the heartbeat.
    """
    token = user_id_var.set(user_id)
    task_id = context.message.task_id if (context and context.message) else "unknown"
    # Background runs act as `svc_agent_<name>`; the token carries the agent name so
    # every enforcement point maps it back to the agent record. Service identity: NO
    # email and NO groups, deliberately -- a background run must not inherit the
    # groups of the user who triggered it (the fail-closed contract for workflows).
    mint_for_run(agent_name, user_id, run_id=task_id)
    try:
        identity_mgr = get_identity_manager()
        
        try:
            # Check for cancellation before processing
            if await _abort_if_cancelled(identity_mgr, agent_name, task_id):
                return "Cancelled before execution."

            started = await _record_run_state(
                identity_mgr,
                agent_name,
                task_id,
                "processing",
                {"prompt": _truncate_output(prompt, max_chars=8192), "user_id": user_id}
            )
            if started:
                await _append_run_event(identity_mgr, agent_name, task_id, "run_started", {"user_id": user_id})
                await _write_heartbeat(identity_mgr, agent_name, task_id)
        except Exception as err:
            print(f"Failed to record processing state for {agent_name} run {task_id}: {err}")
            
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
        if not config_data:
            raise ValueError(f"Workflow '{agent_name}' configuration not found in etcd.")
            
        disabled_workflows = await asyncio.to_thread(identity_mgr.get_disabled_workflows)
        if agent_name in disabled_workflows:
            raise ValueError(f"Workflow '{agent_name}' is currently disabled.")

        # Same input guardrail the agent path applies, over the rendered prompt (the
        # event payload that becomes the script's stdin). A hit fails the run before
        # a container is created; an empty prompt has nothing to check.
        if prompt:
            blocked, prompt = await _check_input_guardrails(
                identity_mgr, agent_name, task_id, user_id, prompt, config_data)
            if blocked:
                return "SYSTEM: Input blocked by guardrail policy."

        # Config sanity checks, before anything is created. The container's own
        # working directory is workspace/workflows/<name>, so the entrypoint is a path
        # *inside* that tree -- never a path on this worker's filesystem.
        base_dir = Path(__file__).parent.parent
        rel_path = config_data.get("rel_path")
        if not rel_path:
            raise ValueError(f"Workflow '{agent_name}' is missing rel_path configuration.")
            
        script_dir = (base_dir / rel_path).resolve()
        if not script_dir.is_relative_to(base_dir):
            raise ValueError(f"Invalid rel_path '{rel_path}': escapes base directory.")
        entrypoint = config_data.get("entrypoint")
        if not entrypoint:
            raise ValueError(f"Workflow '{agent_name}' is missing entrypoint configuration.")
            
        entrypoint_path = (script_dir / entrypoint).resolve()
        
        if not entrypoint_path.is_relative_to(script_dir) or not entrypoint_path.is_file():
            raise ValueError(f"Invalid entrypoint {entrypoint_path}")

        # Pass the entrypoint the way the runner expects it: a plain relative path
        # inside the workflow directory. Normalizing here keeps a config written as
        # "./pipeline.py" (or "scripts/run.py") working, and the check above already
        # proved the resolved file really is inside the workflow's tree.
        entrypoint_relative = entrypoint_path.relative_to(script_dir).as_posix()

        from core.discovery import get_agent_required_secrets, get_agent_required_variables

        # Declared keys ONLY. The container no longer inherits this worker's
        # environment (v0.7.1 Phase 6), so a secret the workflow never declared is
        # absent -- and so is every framework secret the worker itself holds.
        env: Dict[str, str] = {}

        # Scoped Secret Injection (Aggregated from config + allowed tools/mcps)
        secret_keys = await get_agent_required_secrets(config_data, strict=True)
        if secret_keys:
            secrets = await asyncio.to_thread(identity_mgr.get_resolved_config, user_id, "secrets", keys=secret_keys)
            safe_secrets = {str(k): str(v) for k, v in secrets.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
            env.update(safe_secrets)
            
        # Scoped Variable Injection (Aggregated from config + allowed tools/mcps)
        variable_keys = await get_agent_required_variables(config_data, strict=True)
        if variable_keys:
            variables = await asyncio.to_thread(identity_mgr.get_resolved_config, user_id, "variables", keys=variable_keys)
            safe_vars = {str(k): str(v) for k, v in variables.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
            env.update(safe_vars)

        # The workflow's own name, so a pipeline -- and any tool it launches with its
        # own environment -- can address reports/<name>/ (mounted read-write). A
        # workflow container carries no agent token, so the name travels in the
        # environment; nothing in the framework reads it back.
        env["TRELLIS_AGENT_NAME"] = agent_name

        # One pipeline, one container: the runner derives image, mounts, user and
        # limits from its own workspace view. `target` is the workflow NAME (the
        # runner resolves workspace/workflows/<name>), `env` is the declared set
        # above, `tools` is both the mount list and the token's allowlist, and
        # `limits` stays partial so unnamed knobs keep the workflow defaults instead
        # of a single tool's.
        request = ExecRequest(
            kind="workflow",
            target=agent_name,
            entrypoint=entrypoint_relative,
            runtime=_workflow_runtime(config_data),
            args=[],
            tools=list(config_data.get("allowed_tools") or []),
            env=env,
            network=config_data.get("network"),
            limits=config_data.get("limits"),
            # The runner prefixes the environment preamble line; this is the
            # pipeline's own stdin, byte for byte.
            input=prompt or "",
            agent_token=refresh(agent_token_var.get()),
            deadline_ms=max(1, int(resolve_tunable("workflow_run_timeout") * 1000)),
        )

        cancelled_by_poller = False
        # Why the poller stopped the run: a cancel while a container ran is
        # `cancelled_mid_run`; a cancel while it was still queued for a slot never
        # created one (`cancelled_while_waiting`).
        cancellation_reason = "cancelled_mid_run"
        # What the stop attempt achieved, keyed exactly as the run event reports it.
        stop_outcome: Dict[str, Any] = {"container_stopped": False}

        async def _stop_container(runner, reason: str) -> Dict[str, Any]:
            """Stop this run's container; returns the outcome and never raises.

            A stop failure must not mask the run's real outcome (a cancel, a timeout)
            and must not escape the poller task: the run record says the container
            could not be stopped, with the reason, and the run ends the normal way.

            ``container_stopped`` follows the count the runner reports, not the call
            succeeding: a run with no ``trellis.run`` label (token verification off) or
            one whose container already exited reports 0, and claiming it was stopped
            would be the one thing this event must not do.
            """
            if task_id == "unknown":
                return {"container_stopped": False, "stop_error": "no run id"}
            try:
                stopped = await runner.stop_run(task_id)
            except asyncio.CancelledError:
                raise
            except Exception as err:
                print(
                    f"Task {task_id} for {agent_name}: could not stop the workflow "
                    f"container ({reason}): {err}"
                )
                return {"container_stopped": False, "stop_error": str(err)[:512]}
            count = int(getattr(stopped, "stopped", 0) or 0)
            detail = str(getattr(stopped, "detail", "") or "")
            outcome: Dict[str, Any] = {
                "container_stopped": count > 0,
                "containers_stopped": count,
            }
            if count == 0:
                outcome["stop_detail"] = detail or (
                    "no container was left for this run: it already exited, or it "
                    "never carried a run label (token verification off)"
                )
            elif detail:
                outcome["stop_detail"] = detail
            return outcome

        async def _poll_for_cancellation(
            runner,
            check_interval: float = CANCELLATION_POLL_INTERVAL_S,
        ):
            nonlocal cancelled_by_poller
            if task_id == "unknown":
                return
            while True:
                try:
                    await _write_heartbeat(identity_mgr, agent_name, task_id)
                    rec = await asyncio.to_thread(identity_mgr.get_agent_run, agent_name, task_id)
                    if rec and rec.get("state") == "cancelled":
                        # Flag FIRST: the exec() in flight is about to lose its
                        # container, and that failure IS the cancellation taking
                        # effect -- not a run error.
                        cancelled_by_poller = True
                        print(
                            f"Task {task_id} for {agent_name} cancelled mid-execution; "
                            "stopping its workflow container."
                        )
                        stop_outcome.update(
                            await _stop_container(runner, "cancelled_mid_run")
                        )
                        return
                except Exception:
                    pass
                await asyncio.sleep(check_interval)

        async def _record_cancelled() -> str:
            await _append_run_event(
                identity_mgr, agent_name, task_id, "run_cancelled",
                {"reason": cancellation_reason, **stop_outcome},
            )
            return "Cancelled."

        # One client for the exec call AND the poller: the poller is the only party
        # that can notice a cancel while the container runs, so it must be able to
        # stop that container (v0.7.2 R3).
        async with RunnerClient() as runner:
            cancel_monitor = asyncio.create_task(_poll_for_cancellation(runner))
            try:
                result = await _exec_with_slot_wait(
                    runner,
                    request,
                    identity_mgr=identity_mgr,
                    agent_name=agent_name,
                    task_id=task_id,
                    cancelled=lambda: cancelled_by_poller,
                )
            except _RunCancelled:
                # Cancelled while it was still queued for a slot: no container ever
                # ran, so the cancelled path below has nothing to stop.
                cancellation_reason = "cancelled_while_waiting"
                result = None
            except RunnerCallError as err:
                if not cancelled_by_poller:
                    if err.code == "timeout":
                        # The worker's own wait ran out. Left alone the container
                        # would keep running to the runner's deadline, so end it here
                        # and record why; the run still fails with the timeout. (The
                        # poller may stop the same run concurrently -- /v1/stop is
                        # idempotent, and the last writer's outcome is the truth.)
                        await _append_run_event(
                            identity_mgr, agent_name, task_id, "run_container_stopped",
                            {
                                "reason": "deadline_exceeded",
                                **(await _stop_container(runner, "deadline_exceeded")),
                            },
                        )
                    raise RuntimeError(
                        f"Workflow container failed ({err.code}): {err.message}"
                    ) from err
                result = None
            except RunnerUnavailable as err:
                if not cancelled_by_poller:
                    raise RuntimeError(f"Runner is unreachable: {err}") from err
                result = None
            finally:
                await _settle_cancel_monitor(
                    cancel_monitor, detected=cancelled_by_poller
                )

        if cancelled_by_poller:
            return await _record_cancelled()

        output_str = result.stdout or ""
        if result.stderr:
            output_str += "\n" + result.stderr
        truncated = bool(
            getattr(result, "stdout_truncated", False)
            or getattr(result, "stderr_truncated", False)
        )
        if truncated:
            output_str += WORKFLOW_OUTPUT_TRUNCATION_MARKER

        if result.exit_code != 0:
            raise RuntimeError(f"Script exited with status {result.exit_code}:\n{output_str}")

        if truncated:
            # Visible in the run record, not just in the text: an operator reading the
            # Workflows list must not believe a cut-off report is the whole output.
            await _append_run_event(
                identity_mgr, agent_name, task_id, "run_output_truncated",
                {
                    "stdout_truncated": bool(getattr(result, "stdout_truncated", False)),
                    "stderr_truncated": bool(getattr(result, "stderr_truncated", False)),
                    "output_chars": len(output_str),
                },
            )

        completed = await _record_run_state(
            identity_mgr,
            agent_name,
            task_id,
            "completed",
            {
                "prompt": _truncate_output(prompt, max_chars=8192),
                "user_id": user_id,
                "output": _truncate_output(output_str.strip()),
                "output_truncated": truncated,
            }
        )

        if completed:
            await _append_run_event(identity_mgr, agent_name, task_id, "run_completed", {"output_chars": len(output_str or "")})

        return output_str.strip()

    except Exception as e:
        print(f"Error running background script '{agent_name}': {e}")
        failed = await _record_run_state(
            identity_mgr,
            agent_name,
            task_id,
            "failed",
            {
                "prompt": _truncate_output(prompt, max_chars=8192),
                "user_id": user_id,
                "error": str(e)[:resolve_tunable("max_run_error_chars")]
            }
        )
        if failed:
            await _append_run_event(
                identity_mgr, agent_name, task_id, "run_failed",
                {"error_type": type(e).__name__, "error_chars": len(str(e))},
            )
        raise
    finally:
        user_id_var.reset(token)


@broker.task
async def run_background_agent(
    agent_name: str,
    prompt: str,
    user_id: str,
    context: Context = TaskiqDepends(),
) -> str:
    """Executes an agent in the background as a Taskiq task."""
    # Set context variables for thread/async safety with robust try...finally cleanup
    token = user_id_var.set(user_id)
    task_id = context.message.task_id if (context and context.message) else "unknown"
    t0 = time.monotonic()
    config_data: Optional[Dict] = None
    # Background runs act as `svc_agent_<name>`; the token carries the agent name so
    # every enforcement point maps it back to the agent record. Service identity: NO
    # email and NO groups, deliberately (see run_background_script).
    mint_for_run(agent_name, user_id, run_id=task_id)
    try:
        identity_mgr = get_identity_manager()
        
        # Record processing state
        try:
            # Check for cancellation before processing
            if await _abort_if_cancelled(identity_mgr, agent_name, task_id):
                return "Cancelled before execution."

            started = await _record_run_state(
                identity_mgr,
                agent_name,
                task_id,
                "processing",
                {"prompt": _truncate_output(prompt, max_chars=8192), "user_id": user_id}
            )
            if started:
                await _append_run_event(identity_mgr, agent_name, task_id, "run_started", {"user_id": user_id})
                await _write_heartbeat(identity_mgr, agent_name, task_id)
        except Exception as err:
            print(f"Failed to record processing state for {agent_name} run {task_id}: {err}")
            
        # 1. Fetch agent configuration
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
        if not config_data:
            raise ValueError(f"Agent '{agent_name}' configuration not found in etcd.")
            
        # Check if agent is disabled
        disabled_workflows = await asyncio.to_thread(identity_mgr.get_disabled_workflows)
        if agent_name in disabled_workflows:
            raise ValueError(f"Agent '{agent_name}' is currently disabled.")

        # 2. Guardrail check on the input. Fail-open: any evaluation failure leaves the
        # prompt untouched, and only an explicit "block" stops the run before the LLM call.
        blocked, prompt = await _check_input_guardrails(
            identity_mgr, agent_name, task_id, user_id, prompt, config_data)
        if blocked:
            return "SYSTEM: Input blocked by guardrail policy."

        # 3. Build the PydanticAI Agent with full parity (Hub, MCP, A2A)
        agent = await build_agent(agent_name)

        # 4. Execute the run with a concurrent cancellation monitor
        async def _poll_for_agent_cancellation(
            agent_task_ref, check_interval: float = CANCELLATION_POLL_INTERVAL_S
        ):
            if task_id == "unknown":
                return
            while True:
                try:
                    await _write_heartbeat(identity_mgr, agent_name, task_id)
                    rec = await asyncio.to_thread(identity_mgr.get_agent_run, agent_name, task_id)
                    if rec and rec.get("state") == "cancelled":
                        print(f"Task {task_id} for {agent_name} cancelled mid-execution. Cancelling agent task.")
                        agent_task_ref.cancel()
                        return
                except Exception:
                    pass
                await asyncio.sleep(check_interval)

        agent_run_task = asyncio.create_task(agent.run(prompt))
        cancel_monitor = asyncio.create_task(_poll_for_agent_cancellation(agent_run_task))
        try:
            result = await agent_run_task
        except asyncio.CancelledError:
            print(f"Task {task_id} for {agent_name} agent execution was cancelled.")
            await _append_run_event(identity_mgr, agent_name, task_id, "run_cancelled", {"reason": "cancelled_mid_run"})
            return "Cancelled."
        finally:
            cancel_monitor.cancel()
            try:
                await cancel_monitor
            except asyncio.CancelledError:
                pass

        # Measure the model call before memory/usage bookkeeping so latency reflects
        # the run itself, not etcd retries from the side effects.
        total_ms = (time.monotonic() - t0) * 1000

        # Guardrail check on the model output. Fail-open: an evaluation failure leaves
        # the text untouched; only an explicit "block"/"redact" rewrites it. Runs before
        # memory retention so a withheld output is never retained.
        result_output = str(result.output or "")
        output_action, safe_output, output_hits = "allow", result_output, []
        try:
            from core import guardrails
            output_action, safe_output, output_hits = await asyncio.to_thread(
                guardrails.evaluate_agent_output, result_output, config_data)
        except Exception as err:
            print(f"Guardrail output evaluation failed for {agent_name} run {task_id}: {err}")
            output_action, safe_output, output_hits = "allow", result_output, []

        output_hit_counts: Dict[str, int] = {}
        if output_hits:
            try:
                from core import guardrails
                output_hit_counts = dict(await asyncio.to_thread(guardrails.hit_counts, output_hits))
            except Exception as err:
                print(f"Failed to count guardrail hits for {agent_name} run {task_id}: {err}")
            try:
                await asyncio.to_thread(
                    identity_mgr.record_guardrail_hits, agent_name, output_hit_counts)
            except Exception as err:
                print(f"Failed to record guardrail hits for {agent_name} run {task_id}: {err}")

        if output_action == "block":
            safe_output = "SYSTEM: Response blocked by guardrail policy. The agent output was withheld."
        elif not isinstance(safe_output, str):
            safe_output = result_output

        # Agent memory: retain this exchange (awaited so it completes within the worker
        # task lifetime; gated by feature flag + agent config, and fail-open internally).
        from core.memory import get_memory_manager
        memory_mgr = get_memory_manager()
        if await asyncio.to_thread(memory_mgr.active_for, config_data):
            bank = await asyncio.to_thread(memory_mgr.bank_for, agent_name, user_id)
            await memory_mgr.retain(bank=bank, user_msg=prompt, agent_output=safe_output)

        # Log usage
        usage_data = {}
        if hasattr(result, 'usage'):
            usage = result.usage
            if callable(usage):
                usage = usage()
            if usage:
                usage_data = {
                    "request_tokens": usage.input_tokens or 0,
                    "response_tokens": usage.output_tokens or 0,
                    "total_tokens": (usage.input_tokens or 0) + (usage.output_tokens or 0)
                }
                try:
                    await asyncio.to_thread(
                        identity_mgr.record_usage, 
                        user_id, 
                        usage.input_tokens or 0, 
                        usage.output_tokens or 0
                    )
                    # Support metric recording per-agent for observability
                    await asyncio.to_thread(
                        identity_mgr.record_agent_usage,
                        user_id,
                        agent_name,
                        usage.input_tokens or 0,
                        usage.output_tokens or 0
                    )
                except Exception as e:
                    print(f"Failed to record token usage for {user_id}: {e}")
                    
        # Record end-to-end latency next to the terminal state write. Metrics are
        # strictly best-effort: a failure here must never fail the run.
        provider = None
        try:
            provider = await asyncio.to_thread(provider_for_config, config_data)
        except Exception as e:
            print(f"Failed to resolve provider for {agent_name} run {task_id}: {e}")
        try:
            await asyncio.to_thread(
                identity_mgr.record_agent_latency,
                user_id,
                agent_name,
                provider,
                None,
                total_ms,
                True,
            )
        except Exception as e:
            print(f"Failed to record latency for {agent_name} run {task_id}: {e}")

        # Record completed state (auth.py state machine guards against overwriting cancelled)
        completed = await _record_run_state(
            identity_mgr,
            agent_name,
            task_id,
            "completed",
            {
                "prompt": _truncate_output(prompt, max_chars=8192),
                "user_id": user_id,
                "output": _truncate_output(safe_output),
                "usage": usage_data,
                "latency_ms": int(round(total_ms))
            }
        )

        if completed:
            await _append_run_event(
                identity_mgr,
                agent_name,
                task_id,
                "run_completed",
                {"output_chars": len(safe_output)},
            )

        return safe_output

    except Exception as e:
        print(f"Error running background agent '{agent_name}': {e}")
        # Latency metric for the failed run; print-only so metrics never mask the error.
        provider = None
        if config_data:
            try:
                provider = await asyncio.to_thread(provider_for_config, config_data)
            except Exception:
                provider = None
        try:
            await asyncio.to_thread(
                identity_mgr.record_agent_latency,
                user_id,
                agent_name,
                provider,
                None,
                (time.monotonic() - t0) * 1000,
                False,
            )
        except Exception as latency_err:
            print(f"Failed to record latency for {agent_name} run {task_id}: {latency_err}")
        # Record failed state (auth.py state machine guards against overwriting cancelled)
        failed = await _record_run_state(
            identity_mgr,
            agent_name,
            task_id,
            "failed",
            {
                "prompt": _truncate_output(prompt, max_chars=8192),
                "user_id": user_id,
                "error": str(e)[:resolve_tunable("max_run_error_chars")]
            }
        )
        if failed:
            await _append_run_event(
                identity_mgr, agent_name, task_id, "run_failed",
                {"error_type": type(e).__name__, "error_chars": len(str(e))},
            )
        raise
    finally:
        # Guarantee ContextVar state cleanup
        user_id_var.reset(token)
