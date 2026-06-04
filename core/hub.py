import sys
import json
import os
import subprocess
import asyncio
import shutil
import stamina
from pathlib import Path
import typing
from typing import Dict, Any, Optional
from fastmcp import FastMCP
from core.models import ToolConfig
from core.auth import IdentityManager

from core.health import HealthMonitor

# Initialize FastMCP server with host and port
mcp = FastMCP("Polyglot Tool Hub")

BASE_DIR = Path(__file__).parent.parent

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)
health_monitor = HealthMonitor(identity_mgr)

RESTRICTED_ENV_VARS = {"PATH", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV", "HOSTALIASES"}

def load_tool_configs() -> Dict[str, tuple[ToolConfig, Path]]:
    """Fetches tool configurations from etcd."""
    configs = {}
    try:
        tool_names = identity_mgr.list_tools()
        for name in tool_names:
            data = identity_mgr.get_tool_config(name)
            if data and "rel_path" in data:
                rel_path = data.pop("rel_path")
                config = ToolConfig(**data)
                tool_dir = (BASE_DIR / rel_path).resolve()
                if not str(tool_dir).startswith(str(BASE_DIR.resolve())):
                    print(f"Error: Tool directory {tool_dir} is outside BASE_DIR {BASE_DIR}")
                    continue
                configs[config.name] = (config, tool_dir)
    except Exception as e:
        print(f"Error loading tools from etcd: {e}")
    return configs

class TransientToolError(Exception):
    pass

@stamina.retry(on=TransientToolError, attempts=3)
async def run_tool(config: ToolConfig, tool_dir: Path, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Executes a tool as a subprocess and handles JSON stdin/stdout."""
    user_id = arguments.pop("__user_id", None)
    if user_id:
        asyncio.create_task(asyncio.to_thread(identity_mgr.record_tool_usage, user_id, config.name))
    
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
        if user_id:
            secrets = identity_mgr.get_resolved_secrets(user_id)
            if secrets:
                safe_secrets = {str(k): str(v) for k, v in secrets.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
                env.update(safe_secrets)
            
            variables = identity_mgr.get_resolved_variables(user_id)
            if variables:
                safe_vars = {str(k): str(v) for k, v in variables.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
                env.update(safe_vars)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(tool_dir),
            env=env
        )

        input_json = json.dumps(arguments).encode()
        stdout, stderr = await process.communicate(input=input_json)

        if stderr:
            print(f"Tool {config.name} stderr: {stderr.decode().strip()}")

        if process.returncode != 0:
            stderr_str = stderr.decode().strip()
            error_msg = f"Tool exited with code {process.returncode}: {stderr_str}"
            health_monitor.record_event("tool", config.name, is_success=False, error_details=error_msg)
            
            # Identify common transient network errors in stderr
            transient_keywords = ["timeout", "connection refused", "econnrefused", "eof", "network is unreachable", "temporary failure"]
            if any(keyword in stderr_str.lower() for keyword in transient_keywords):
                raise TransientToolError(error_msg)
                
            return {
                "error": error_msg,
                "stderr": stderr_str
            }

        try:
            result = json.loads(stdout.decode())
            # A valid JSON output with an 'error' key is considered a User-Scoped Failure,
            # which does NOT trip the global circuit breaker. We count it as a success for global health.
            health_monitor.record_event("tool", config.name, is_success=True)
            return result
        except json.JSONDecodeError:
            error_msg = f"Output was not valid JSON: {stdout.decode().strip()}"
            health_monitor.record_event("tool", config.name, is_success=False, error_details=error_msg)
            return {"output": stdout.decode().strip(), "warning": error_msg}

    except asyncio.TimeoutError:
        error_msg = "Tool execution timed out."
        health_monitor.record_event("tool", config.name, is_success=False, error_details=error_msg)
        raise TransientToolError(error_msg)
    except TransientToolError:
        raise
    except Exception as e:
        error_msg = f"Failed to execute tool: {str(e)}"
        health_monitor.record_event("tool", config.name, is_success=False, error_details=error_msg)
        return {"error": error_msg}

def register_tools():
    """Dynamically registers tools with the FastMCP server and pre-compiles Go tools."""
    configs = load_tool_configs()
    
    for name, (config, tool_dir) in configs.items():
        if config.runtime == "go":
            entrypoint_path = (tool_dir / config.entrypoint).resolve()
            if not str(entrypoint_path).startswith(str(tool_dir)) or not entrypoint_path.is_file():
                print(f"Skipping compilation of Go tool {name}: invalid entrypoint {config.entrypoint}")
                continue
            
            print(f"Pre-compiling Go tool: {name}")
            bin_dir = tool_dir / ".bin"
            bin_dir.mkdir(exist_ok=True)
            bin_path = bin_dir / config.name
            try:
                subprocess.run(["go", "build", "-o", str(bin_path), config.entrypoint], cwd=str(tool_dir), check=True)
            except subprocess.CalledProcessError as e:
                print(f"Failed to compile Go tool {name}: {e}")
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
        print(f"Registered tool: {name}")

if __name__ == "__main__":
    register_tools()
    import uvicorn
    app = mcp.http_app()
    uvicorn.run(app, host="0.0.0.0", port=8001)
