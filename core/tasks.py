import os
import asyncio
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List
from taskiq_redis import ListQueueBroker
from pydantic_ai import Agent

from core.auth import user_id_var
from core.agent_factory import (
    build_agent,
    get_identity_manager,
    get_health_monitor,
    get_hub_client,
)

RESTRICTED_ENV_VARS = {"PATH", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV", "HOSTALIASES"}

# Redis broker configuration
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
broker = ListQueueBroker(redis_url)

from taskiq import TaskiqScheduler, Context, TaskiqDepends
from taskiq.schedule_sources import LabelScheduleSource

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
    disabled_agents = identity_mgr.get_disabled_agents()
    
    now = datetime.now()
    
    for name in agent_names:
        if name in disabled_agents:
            continue
            
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        if not config_data or config_data.get("type") not in ("background_agent", "background_script"):
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
                    
                    agent_identity = Identity(id=name, type=IdentityType.WORKFLOW)
                    
                    if config_data.get("type") == "background_script":
                        task = await run_background_script.kiq(
                            agent_name=name,
                            prompt=xml_payload,
                            user_id=agent_identity.to_legacy_string()
                        )
                    else:
                        task = await run_background_agent.kiq(
                            agent_name=name,
                            prompt=xml_payload,
                            user_id=agent_identity.to_legacy_string()
                        )
                    try:
                        await asyncio.to_thread(
                            identity_mgr.record_agent_run_state,
                            name,
                            task.task_id,
                            "pending",
                            {"prompt": xml_payload, "user_id": agent_identity.to_legacy_string()}
                        )
                    except Exception as e:
                        print(f"Failed to record pending state for {name}: {e}")
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
    try:
        identity_mgr = get_identity_manager()
        
        try:
            # Check for cancellation before processing
            runs = await asyncio.to_thread(identity_mgr.get_agent_runs, agent_name)
            run_record = next((r for r in runs if r.get("run_id") == task_id), None)
            
            if run_record and run_record.get("state") == "cancelled":
                print(f"Task {task_id} for {agent_name} was cancelled before processing. Aborting.")
                return "Cancelled before execution."

            await asyncio.to_thread(
                identity_mgr.record_agent_run_state,
                agent_name,
                task_id,
                "processing",
                {"prompt": prompt, "user_id": user_id}
            )
        except Exception as err:
            print(f"Failed to record processing state for {agent_name} run {task_id}: {err}")
            
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
        if not config_data:
            raise ValueError(f"Workflow '{agent_name}' configuration not found in etcd.")
            
        disabled_agents = identity_mgr.get_disabled_agents()
        if agent_name in disabled_agents:
            raise ValueError(f"Workflow '{agent_name}' is currently disabled.")
        
        # Prepare execution environment
        base_dir = Path(__file__).parent.parent
        rel_path = config_data.get("rel_path")
        if not rel_path:
            raise ValueError(f"Workflow '{agent_name}' is missing rel_path configuration.")
            
        script_dir = (base_dir / rel_path).resolve()
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

        env = os.environ.copy()
        from core.discovery import get_agent_required_secrets, get_agent_required_variables
        
        # Scoped Secret Injection (Aggregated from config + allowed tools/mcps)
        secret_keys = await get_agent_required_secrets(config_data)
        if secret_keys:
            secrets = identity_mgr.get_resolved_config(user_id, "secrets", keys=secret_keys)
            safe_secrets = {str(k): str(v) for k, v in secrets.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
            env.update(safe_secrets)
            
        # Scoped Variable Injection (Aggregated from config + allowed tools/mcps)
        variable_keys = await get_agent_required_variables(config_data)
        if variable_keys:
            variables = identity_mgr.get_resolved_config(user_id, "variables", keys=variable_keys)
            safe_vars = {str(k): str(v) for k, v in variables.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
            env.update(safe_vars)

        env["FRAMEWORK_EXECUTION_TOKEN"] = identity_mgr.generate_execution_token(user_id)
        framework_url = identity_mgr.get_config("HOST_URL", os.getenv("HOST_URL", "http://localhost:8000"))
        env["FRAMEWORK_API_URL"] = framework_url

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(script_dir),
            env=env
        )

        input_data = prompt.encode() if prompt else b""
        stdout, stderr = await process.communicate(input=input_data)
        
        output_str = ""
        if stdout:
            output_str += stdout.decode()
        if stderr:
            output_str += "\n" + stderr.decode()

        if process.returncode != 0:
            raise RuntimeError(f"Script exited with status {process.returncode}:\n{output_str}")

        try:
            await asyncio.to_thread(
                identity_mgr.record_agent_run_state,
                agent_name,
                task_id,
                "completed",
                {
                    "prompt": prompt,
                    "user_id": user_id,
                    "output": output_str.strip()
                }
            )
        except Exception as err:
            print(f"Failed to record completed state for {agent_name} run {task_id}: {err}")
                    
        return output_str.strip()
        
    except Exception as e:
        print(f"Error running background script '{agent_name}': {e}")
        try:
            await asyncio.to_thread(
                identity_mgr.record_agent_run_state,
                agent_name,
                task_id,
                "failed",
                {
                    "prompt": prompt,
                    "user_id": user_id,
                    "error": str(e)
                }
            )
        except Exception as err:
            print(f"Failed to record failed state for {agent_name} run {task_id}: {err}")
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
    try:
        identity_mgr = get_identity_manager()
        
        # Record processing state
        try:
            # Check for cancellation before processing
            runs = await asyncio.to_thread(identity_mgr.get_agent_runs, agent_name)
            run_record = next((r for r in runs if r.get("run_id") == task_id), None)
            
            if run_record and run_record.get("state") == "cancelled":
                print(f"Task {task_id} for {agent_name} was cancelled before processing. Aborting.")
                return "Cancelled before execution."

            await asyncio.to_thread(
                identity_mgr.record_agent_run_state,
                agent_name,
                task_id,
                "processing",
                {"prompt": prompt, "user_id": user_id}
            )
        except Exception as err:
            print(f"Failed to record processing state for {agent_name} run {task_id}: {err}")
            
        # 1. Fetch agent configuration
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
        if not config_data:
            raise ValueError(f"Agent '{agent_name}' configuration not found in etcd.")
            
        # Check if agent is disabled
        disabled_agents = identity_mgr.get_disabled_agents()
        if agent_name in disabled_agents:
            raise ValueError(f"Agent '{agent_name}' is currently disabled.")
        
        # 2. Build the PydanticAI Agent with full parity (Hub, MCP, A2A)
        agent = await build_agent(agent_name)
        
        # 3. Execute the run
        result = await agent.run(prompt)
        
        # Log usage
        usage_data = {}
        if hasattr(result, 'usage'):
            usage = result.usage
            if callable(usage):
                usage = usage()
            if usage:
                usage_data = {
                    "request_tokens": usage.request_tokens or 0,
                    "response_tokens": usage.response_tokens or 0,
                    "total_tokens": (usage.request_tokens or 0) + (usage.response_tokens or 0)
                }
                try:
                    await asyncio.to_thread(
                        identity_mgr.record_usage, 
                        user_id, 
                        usage.request_tokens or 0, 
                        usage.response_tokens or 0
                    )
                    # Support metric recording per-agent for observability
                    await asyncio.to_thread(
                        identity_mgr.record_agent_usage,
                        user_id,
                        agent_name,
                        usage.request_tokens or 0,
                        usage.response_tokens or 0
                    )
                except Exception as e:
                    print(f"Failed to record token usage for {user_id}: {e}")
                    
        # Record completed state
        try:
            await asyncio.to_thread(
                identity_mgr.record_agent_run_state,
                agent_name,
                task_id,
                "completed",
                {
                    "prompt": prompt,
                    "user_id": user_id,
                    "output": result.output,
                    "usage": usage_data
                }
            )
        except Exception as err:
            print(f"Failed to record completed state for {agent_name} run {task_id}: {err}")
                    
        return result.output
        
    except Exception as e:
        print(f"Error running background agent '{agent_name}': {e}")
        # Record failed state
        try:
            await asyncio.to_thread(
                identity_mgr.record_agent_run_state,
                agent_name,
                task_id,
                "failed",
                {
                    "prompt": prompt,
                    "user_id": user_id,
                    "error": str(e)
                }
            )
        except Exception as err:
            print(f"Failed to record failed state for {agent_name} run {task_id}: {err}")
        raise
    finally:
        # Guarantee ContextVar state cleanup
        user_id_var.reset(token)
