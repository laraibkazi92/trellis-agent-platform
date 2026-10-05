# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import sys
import json
import os
import subprocess
import asyncio
import logging
import shutil
import stamina
from pathlib import Path
import typing
from typing import Dict, Any, Optional
from fastmcp import FastMCP
from core.models import ToolConfig
from core.auth import get_identity_manager
from core.devmode import enforce_dev_mode_safety

from core.health import HealthMonitor

# Initialize FastMCP server with host and port
mcp = FastMCP("Polyglot Tool Hub")

BASE_DIR = Path(__file__).parent.parent

identity_mgr = get_identity_manager()
health_monitor = HealthMonitor(identity_mgr)

logger = logging.getLogger(__name__)

_background_tasks: set[asyncio.Task] = set()

def _spawn_background(coro, name: str) -> asyncio.Task:
    task = asyncio.create_task(coro, name=name)
    _background_tasks.add(task)
    def _done(t: asyncio.Task):
        _background_tasks.discard(t)
        if not t.cancelled() and t.exception() is not None:
            logger.error("Background task %s failed: %s", name, t.exception())
    task.add_done_callback(_done)
    return task

async def _drain_background_tasks(timeout: float = 5.0) -> None:
    pending = {t for t in _background_tasks if not t.done()}
    if not pending:
        return
    _, still_pending = await asyncio.wait(pending, timeout=timeout)
    for task in still_pending:
        task.cancel()
    if still_pending:
        logger.warning("Cancelled %d background task(s) that did not finish within %.1fs", len(still_pending), timeout)

class _LifespanDrainWrapper:
    """Delegates ASGI calls to the wrapped app, draining background tasks on shutdown.

    Relies on the wrapped Starlette lifespan calling ``receive()`` again for the
    shutdown message; the drain runs before that message is forwarded, so tasks
    finish while the app's session manager is still alive.
    """

    def __init__(self, app):
        self._app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "lifespan":
            await self._app(scope, receive, send)
            return

        async def receive_and_drain():
            message = await receive()
            if message["type"] == "lifespan.shutdown":
                await _drain_background_tasks()
            return message

        await self._app(scope, receive_and_drain, send)

RESTRICTED_ENV_VARS = {"PATH", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV", "HOSTALIASES"}

def load_tool_configs() -> Dict[str, tuple[ToolConfig, Path]]:
    """Fetches tool configurations from etcd."""
    configs = {}
    try:
        tool_names = identity_mgr.list_tools()
        for name in tool_names:
            data = identity_mgr.get_tool_config(name)
            if data and "rel_path" in data:
                try:
                    rel_path = data.pop("rel_path")
                    config = ToolConfig(**data)
                    tool_dir = (BASE_DIR / rel_path).resolve()
                    if not str(tool_dir).startswith(str(BASE_DIR.resolve())):
                        logger.error(f"Error: Tool directory {tool_dir} is outside BASE_DIR {BASE_DIR}")
                        continue
                    configs[config.name] = (config, tool_dir)
                except Exception as e:
                    logger.error(f"Error loading tool {name}: {e}")
    except Exception as e:
        logger.error(f"Error loading tools from etcd: {e}")
    return configs

class TransientToolError(Exception):
    pass

@stamina.retry(on=TransientToolError, attempts=3)
async def _run_tool_attempt(config: ToolConfig, tool_dir: Path, arguments: Dict[str, Any], user_id: Optional[str]) -> Dict[str, Any]:
    """Executes a tool as a subprocess and handles JSON stdin/stdout."""
    entrypoint_path = (tool_dir / config.entrypoint).resolve()
    if not str(entrypoint_path).startswith(str(tool_dir)):
        return {"error": f"Entrypoint resolves outside tool directory"}
    if not entrypoint_path.is_file():
        return {"error": f"Entrypoint does not exist or is not a file"}

    cmd = []
    if config.runtime == "python":
        cmd = [sys.executable, str(entrypoint_path)]
    elif config.runtime == "go":
        bin_path = tool_dir / ".bin" / config.name
        cmd = [str(bin_path)]
    elif config.runtime == "ts":
        cmd = ["npx", "tsx", str(entrypoint_path)]
    elif config.runtime == "bash":
        cmd = ["bash", str(entrypoint_path)]
    else:
        return {"error": f"Unsupported runtime: {config.runtime}"}

    if not shutil.which("bwrap"):
        raise RuntimeError("bwrap not found on system. Sandboxing is required.")

    bwrap_cmd = [
        "bwrap",
        "--ro-bind", "/", "/",
        "--bind", "/app/workspace", "/app/workspace",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent"
    ]
    cmd = bwrap_cmd + cmd

    try:
        env = os.environ.copy()

        # A CLI binary dropped into this tool's own bin/ on the host becomes
        # available to it automatically — workspace/ is already bind-mounted
        # into this container, so this needs no docker-compose volume mount
        # and no image rebuild. Scoped per-tool (rather than one shared
        # directory) so different tools' binaries can't collide by name.
        tool_bin = str((tool_dir / "bin").resolve())
        env["PATH"] = f"{tool_bin}{os.pathsep}{env.get('PATH', '')}"

        if user_id:
            from core.discovery import _resolve_requirements
            is_background = user_id.startswith("svc_agent_")
            
            # Scoped Secret Injection
            secret_keys = _resolve_requirements(config.secrets, is_background)
            if secret_keys:
                secrets = await asyncio.to_thread(identity_mgr.get_resolved_config, user_id, "secrets", keys=secret_keys)
                safe_secrets = {str(k): str(v) for k, v in secrets.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
                env.update(safe_secrets)

            # Scoped Optional Secret Injection (absence does not block tool execution)
            optional_secret_keys = _resolve_requirements(getattr(config, "optional_secrets", None), is_background)
            if optional_secret_keys:
                optional_secrets = await asyncio.to_thread(identity_mgr.get_resolved_config, user_id, "secrets", keys=optional_secret_keys)
                safe_optional_secrets = {str(k): str(v) for k, v in optional_secrets.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
                env.update(safe_optional_secrets)

            # Scoped Variable Injection
            variable_keys = _resolve_requirements(config.variables, is_background)
            if variable_keys:
                variables = await asyncio.to_thread(identity_mgr.get_resolved_config, user_id, "variables", keys=variable_keys)
                safe_vars = {str(k): str(v) for k, v in variables.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
                env.update(safe_vars)

            # Auto-inject framework loopback capabilities
            env["FRAMEWORK_EXECUTION_TOKEN"] = await asyncio.to_thread(identity_mgr.generate_execution_token, user_id)
            framework_url = await asyncio.to_thread(identity_mgr.get_config, "HOST_URL", os.getenv("HOST_URL", "http://localhost:8000"))
            env["FRAMEWORK_API_URL"] = framework_url

            # Auto-inject user identity (email)
            if os.getenv("DEV_MODE", "false").lower() == "true":
                env["TRELLIS_USER_EMAIL"] = os.getenv("DEV_USER_EMAIL", "dev-user@local.host")
            else:
                user_profile = await asyncio.to_thread(identity_mgr.get_user, user_id)
                if user_profile and user_profile.get("email"):
                    env["TRELLIS_USER_EMAIL"] = user_profile["email"]

        input_json = json.dumps(arguments).encode()
        try:
            env_timeout = float(os.getenv("TOOL_EXECUTION_TIMEOUT", "300"))
        except (TypeError, ValueError):
            env_timeout = 300.0
        timeout = config.timeout_seconds if getattr(config, "timeout_seconds", None) else env_timeout

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(tool_dir),
            env=env
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(input=input_json), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                await process.wait()
            except Exception:
                pass
            error_msg = f"Tool execution timed out after {timeout:.0f}s."
            await asyncio.to_thread(health_monitor.record_event, "tool", config.name, False, error_msg)
            return {"error": error_msg}
        except asyncio.CancelledError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                await process.wait()
            except Exception:
                pass
            raise

        if stderr:
            stderr_text = stderr.decode().strip()
            if len(stderr_text) > 2048:
                logger.warning(f"Tool {config.name} stderr ({len(stderr_text)} chars): {stderr_text[:2048]}... [truncated]")
            else:
                logger.warning(f"Tool {config.name} stderr: {stderr_text}")

        if process.returncode != 0:
            stderr_str = stderr.decode().strip()
            error_msg = f"Tool exited with code {process.returncode}: {stderr_str}"
            await asyncio.to_thread(health_monitor.record_event, "tool", config.name, False, error_msg)
            config_retry = getattr(config, "retry_on_transient", True)
            
            # Identify common transient network errors in stderr
            transient_keywords = ["timeout", "connection refused", "econnrefused", "eof", "network is unreachable", "temporary failure"]
            if config_retry and any(keyword in stderr_str.lower() for keyword in transient_keywords):
                raise TransientToolError(error_msg)
                
            return {
                "error": error_msg,
                "stderr": stderr_str
            }

        try:
            result = json.loads(stdout.decode())
            # Global Safety Net: Safely truncate tool outputs exceeding 24k tokens (96,000 characters)
            stringified = json.dumps(result)
            if len(stringified) > 96000:
                logger.warning(f"Warning: Tool {config.name} output size ({len(stringified)} chars) exceeded safety limit of 96000 chars. Truncating...")
                result = {
                    "error": f"Global Safety Net: The tool '{config.name}' output exceeded the 24k token limit (96,000 characters). Output was safely truncated to prevent model context crashes.",
                    "partial_data_preview": stringified[:90000] + "... [TRUNCATED DUE TO SAFETY LIMITS]"
                }
            # A valid JSON output with an 'error' key is considered a User-Scoped Failure,
            # which does NOT trip the global circuit breaker. We count it as a success for global health.
            await asyncio.to_thread(health_monitor.record_event, "tool", config.name, True)
            return result
        except json.JSONDecodeError:
            error_msg = f"Output was not valid JSON: {stdout.decode().strip()}"
            await asyncio.to_thread(health_monitor.record_event, "tool", config.name, False, error_msg)
            return {"output": stdout.decode().strip(), "warning": error_msg}

    except TransientToolError:
        raise
    except Exception as e:
        error_msg = f"Failed to execute tool: {str(e)}"
        await asyncio.to_thread(health_monitor.record_event, "tool", config.name, False, error_msg)
        return {"error": error_msg}

async def run_tool(config: ToolConfig, tool_dir: Path, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Executes a tool as a subprocess and handles JSON stdin/stdout."""
    # stamina re-invokes with the same dict — never mutate the caller's arguments.
    arguments = dict(arguments)
    user_id = arguments.pop("__user_id", None)
    if user_id and user_id.startswith("svc_agent_"):
        arguments["__agent_name"] = user_id[len("svc_agent_"):]
    try:
        return await _run_tool_attempt(config, tool_dir, arguments, user_id)
    finally:
        # Usage is recorded once per invocation, not once per stamina retry attempt.
        if user_id:
            _spawn_background(
                asyncio.to_thread(identity_mgr.record_tool_usage, user_id, config.name),
                f"record_tool_usage:{config.name}",
            )

def register_tools():
    """Dynamically registers tools with the FastMCP server and pre-compiles Go tools."""
    configs = load_tool_configs()
    
    for name, (config, tool_dir) in configs.items():
        if config.runtime == "go":
            entrypoint_path = (tool_dir / config.entrypoint).resolve()
            if not str(entrypoint_path).startswith(str(tool_dir)) or not entrypoint_path.is_file():
                logger.error(f"Skipping compilation of Go tool {name}: invalid entrypoint {config.entrypoint}")
                continue
            
            logger.info(f"Pre-compiling Go tool: {name}")
            bin_dir = tool_dir / ".bin"
            bin_dir.mkdir(exist_ok=True)
            bin_path = bin_dir / config.name
            try:
                subprocess.run(["go", "build", "-o", str(bin_path), config.entrypoint], cwd=str(tool_dir), check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to compile Go tool {name}: {e}")
                continue

        # Use a closure to capture the current config and tool_dir
        def create_handler(c, d):
            import inspect
            
            sig_parts = []
            annotations = {}
            params = []
            
            if c.inputs:
                for input_name, input_def in c.inputs.items():
                    input_type = input_def.get("type", "string")
                    py_type = str
                    if input_type == "string":
                        # Historical: 'string' maps to Any (not str) so the handler's str()-coercion
                        # below is the single place stringification happens; unknown types also
                        # fall through to the str default.
                        py_type = Any
                    elif input_type == "integer": py_type = int
                    elif input_type == "boolean": py_type = bool
                    elif input_type == "array": py_type = list
                    elif input_type == "object": py_type = dict
                    
                    is_req = input_def.get("required", False)
                    default = inspect.Parameter.empty if is_req else None
                    
                    params.append(
                        inspect.Parameter(
                            input_name, 
                            inspect.Parameter.POSITIONAL_OR_KEYWORD, 
                            annotation=py_type, 
                            default=default
                        )
                    )
                    annotations[input_name] = py_type

            # Add __user_id
            params.append(
                inspect.Parameter(
                    "__user_id",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=typing.Optional[str],
                    default=None
                )
            )
            annotations["__user_id"] = typing.Optional[str]
            
            async def handler(**kwargs):
                filtered_kwargs = {}
                for k, v in kwargs.items():
                    if v is not None:
                        # Ensure we stringify string inputs properly 
                        if c.inputs and k in c.inputs:
                            if c.inputs[k].get("type", "string") == "string" and not isinstance(v, str):
                                filtered_kwargs[k] = str(v)
                            else:
                                filtered_kwargs[k] = v
                        else:
                            filtered_kwargs[k] = v
                            
                try:
                    return await run_tool(c, d, filtered_kwargs)
                except TransientToolError as e:
                    return {"error": f"Tool failed after retries: {str(e)}"}
            
            handler.__signature__ = inspect.Signature(params)
            handler.__annotations__ = annotations
            handler.__name__ = c.name.replace('-', '_')
            handler.__doc__ = c.description
            
            return handler

        mcp.tool(name=name, description=config.description)(create_handler(config, tool_dir))
        logger.info(f"Registered tool: {name}")

if __name__ == "__main__":
    # Startup gate: refuse to serve an unauthenticated DEV_MODE instance on a
    # remotely reachable bind host (see core/devmode.py).
    enforce_dev_mode_safety("hub")
    register_tools()
    import uvicorn
    app = _LifespanDrainWrapper(mcp.http_app(host_origin_protection=False))
    uvicorn.run(app, host=os.getenv("BIND_HOST", "0.0.0.0"), port=8001)
