# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
import asyncio
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List
from taskiq_redis import ListQueueBroker
from pydantic_ai import Agent

from core.auth import user_id_var
from core.agent_token import mint_for_run
from core.models import Identity, IdentityType
from core.env_sanitize import sanitized_env
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

RESTRICTED_ENV_VARS = {"PATH", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV", "HOSTALIASES"}


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
    # The worker is its own process, so the tool-authorization policy watch must be
    # registered here too. A failure must never block worker startup.
    try:
        from core.tool_authz import install_tool_authz_watch

        install_tool_authz_watch()
    except Exception as e:
        print(f"Failed to install tool-authorization watch: {e}")

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
    """Executes a script in the background as a Taskiq task."""
    token = user_id_var.set(user_id)
    task_id = context.message.task_id if (context and context.message) else "unknown"
    # Background runs act as `svc_agent_<name>`; the token carries the agent name so
    # every enforcement point maps it back to the agent record.
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
        
        # Prepare execution environment
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
        
        if not str(entrypoint_path).startswith(str(script_dir)) or not entrypoint_path.is_file():
            raise ValueError(f"Invalid entrypoint {entrypoint_path}")

        runtime = config_data.get("runtime", "python")
        if runtime == "python":
            import sys
            cmd = [sys.executable, str(entrypoint_path)]
        elif runtime == "node":
            cmd = ["node", str(entrypoint_path)]
        elif runtime == "bash":
            cmd = ["bash", str(entrypoint_path)]
        else:
            cmd = [str(entrypoint_path)]

        env = sanitized_env()
        from core.discovery import get_agent_required_secrets, get_agent_required_variables
        
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

        # v0.6: no framework loopback credentials are injected into executed
        # scripts. A script that needs the API must be given a declared secret.

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(script_dir),
            env=env
        )

        cancelled_by_poller = False

        async def _poll_for_cancellation(proc, check_interval: int = 15):
            nonlocal cancelled_by_poller
            if task_id == "unknown":
                return
            while True:
                try:
                    await _write_heartbeat(identity_mgr, agent_name, task_id)
                    rec = await asyncio.to_thread(identity_mgr.get_agent_run, agent_name, task_id)
                    if rec and rec.get("state") == "cancelled":
                        print(f"Task {task_id} for {agent_name} cancelled mid-execution. Killing subprocess.")
                        try:
                            proc.kill()
                        except (ProcessLookupError, PermissionError, OSError):
                            pass
                        cancelled_by_poller = True
                        return
                except Exception:
                    pass
                await asyncio.sleep(check_interval)

        cancel_monitor = asyncio.create_task(_poll_for_cancellation(process))
        input_data = prompt.encode() if prompt else b""
        try:
            stdout, stderr = await process.communicate(input=input_data)
        finally:
            cancel_monitor.cancel()
            try:
                await cancel_monitor
            except asyncio.CancelledError:
                pass

        output_str = ""
        if stdout:
            output_str += stdout.decode()
        if stderr:
            output_str += "\n" + stderr.decode()

        if process.returncode != 0:
            if cancelled_by_poller:
                await _append_run_event(identity_mgr, agent_name, task_id, "run_cancelled", {"reason": "cancelled_mid_run"})
                return "Cancelled."
            raise RuntimeError(f"Script exited with status {process.returncode}:\n{output_str}")

        completed = await _record_run_state(
            identity_mgr,
            agent_name,
            task_id,
            "completed",
            {
                "prompt": _truncate_output(prompt, max_chars=8192),
                "user_id": user_id,
                "output": _truncate_output(output_str.strip())
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
    # every enforcement point maps it back to the agent record.
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

        if input_action == "block":
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
            return "SYSTEM: Input blocked by guardrail policy."

        prompt = checked_prompt

        # 3. Build the PydanticAI Agent with full parity (Hub, MCP, A2A)
        agent = await build_agent(agent_name)

        # 4. Execute the run with a concurrent cancellation monitor
        async def _poll_for_agent_cancellation(agent_task_ref, check_interval: int = 15):
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
