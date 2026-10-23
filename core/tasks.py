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
from core.llm_defaults import warm_defaults_cache
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


async def _record_run_state(identity_mgr, agent_name: str, task_id: str, state: str, metadata: Dict[str, Any]) -> None:
    """Persist a workflow run's state, logging (never raising) on failure."""
    try:
        await asyncio.to_thread(
            identity_mgr.record_agent_run_state,
            agent_name,
            task_id,
            state,
            metadata,
        )
    except Exception as err:
        print(f"Failed to record {state} state for {agent_name} run {task_id}: {err}")


async def _abort_if_cancelled(identity_mgr, agent_name: str, task_id: str) -> bool:
    """True if the run was cancelled before processing began."""
    run_record = await asyncio.to_thread(identity_mgr.get_agent_run, agent_name, task_id)
    if run_record and run_record.get("state") == "cancelled":
        print(f"Task {task_id} for {agent_name} was cancelled before processing. Aborting.")
        return True
    return False


async def enqueue_workflow_run(name: str, config: Dict, xml_payload: str) -> None:
    """Dispatch a workflow (script or agent) and record its initial pending state."""
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

    try:
        await asyncio.to_thread(
            identity_mgr.record_agent_run_state,
            name,
            task.task_id,
            "pending",
            {"prompt": xml_payload, "user_id": agent_identity.to_legacy_string()},
        )
    except Exception as e:
        print(f"Failed to record pending state for {name}: {e}")

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

scheduler = TaskiqScheduler(
    broker=broker,
    sources=[LabelScheduleSource(broker)],
)

# We use a single heartbeat task that runs every minute to check ETCD for dynamic cron jobs
import time
from datetime import datetime
import pycron

@broker.task(schedule=[{"cron": "* * * * *"}])
async def dynamic_cron_heartbeat():
    """Runs every minute to trigger any dynamic background agents that have matching cron expressions."""
    
    identity_mgr = get_identity_manager()
    agent_names = await asyncio.to_thread(identity_mgr.list_agents)
    disabled_workflows = await asyncio.to_thread(identity_mgr.get_disabled_workflows)
    
    now = datetime.now()
    
    for name in agent_names:
        if name in disabled_workflows:
            continue
            
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if not config_data or config_data.get("type") not in ("background_agent", "background_script"):
            continue

        # Periodic pruning of historical workflow runs (runs once per hour at minute 0)
        if now.minute == 0:
            try:
                await asyncio.to_thread(identity_mgr.prune_agent_runs, name, 100)
            except Exception as e:
                print(f"Failed to periodically prune runs for {name}: {e}")

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

            await _record_run_state(
                identity_mgr,
                agent_name,
                task_id,
                "processing",
                {"prompt": _truncate_output(prompt, max_chars=8192), "user_id": user_id}
            )
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
                return "Cancelled."
            raise RuntimeError(f"Script exited with status {process.returncode}:\n{output_str}")

        await _record_run_state(
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

        return output_str.strip()

    except Exception as e:
        print(f"Error running background script '{agent_name}': {e}")
        await _record_run_state(
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

            await _record_run_state(
                identity_mgr,
                agent_name,
                task_id,
                "processing",
                {"prompt": _truncate_output(prompt, max_chars=8192), "user_id": user_id}
            )
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
        
        # 2. Build the PydanticAI Agent with full parity (Hub, MCP, A2A)
        agent = await build_agent(agent_name)

        # 3. Execute the run with a concurrent cancellation monitor
        async def _poll_for_agent_cancellation(agent_task_ref, check_interval: int = 15):
            if task_id == "unknown":
                return
            while True:
                try:
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
            return "Cancelled."
        finally:
            cancel_monitor.cancel()
            try:
                await cancel_monitor
            except asyncio.CancelledError:
                pass

        # Agent memory: retain this exchange (awaited so it completes within the worker
        # task lifetime; gated by feature flag + agent config, and fail-open internally).
        from core.memory import get_memory_manager
        memory_mgr = get_memory_manager()
        if await asyncio.to_thread(memory_mgr.active_for, config_data):
            bank = await asyncio.to_thread(memory_mgr.bank_for, agent_name, user_id)
            await memory_mgr.retain(bank=bank, user_msg=prompt, agent_output=result.output)

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
                    
        # Record completed state (auth.py state machine guards against overwriting cancelled)
        await _record_run_state(
            identity_mgr,
            agent_name,
            task_id,
            "completed",
            {
                "prompt": _truncate_output(prompt, max_chars=8192),
                "user_id": user_id,
                "output": _truncate_output(str(result.output) if result.output else ""),
                "usage": usage_data
            }
        )

        return result.output

    except Exception as e:
        print(f"Error running background agent '{agent_name}': {e}")
        # Record failed state (auth.py state machine guards against overwriting cancelled)
        await _record_run_state(
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
        raise
    finally:
        # Guarantee ContextVar state cleanup
        user_id_var.reset(token)
