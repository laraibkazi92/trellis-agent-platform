import sys
import json
import os
import subprocess
import asyncio
import shutil
from pathlib import Path
from typing import Dict, Any
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

async def run_tool(config: ToolConfig, tool_dir: Path, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Executes a tool as a subprocess and handles JSON stdin/stdout."""
    user_id = arguments.pop("__user_id", None)
    
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
            secrets = identity_mgr.get_user_secrets(user_id)
            if secrets:
                safe_secrets = {str(k): str(v) for k, v in secrets.items() if str(k).upper() not in RESTRICTED_ENV_VARS}
                env.update(safe_secrets)

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
            error_msg = f"Tool exited with code {process.returncode}: {stderr.decode().strip()}"
            health_monitor.record_event("tool", config.name, is_success=False, error_details=error_msg)
            return {
                "error": error_msg,
                "stderr": stderr.decode().strip()
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
        return {"error": error_msg}
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
            sig_parts = []
            string_fields = []
            if c.inputs:
                for input_name, input_def in c.inputs.items():
                    input_type = input_def.get("type", "string")
                    type_str = "str"
                    if input_type == "string":
                        type_str = "typing.Any"
                        string_fields.append(input_name)
                    elif input_type == "integer": type_str = "int"
                    elif input_type == "boolean": type_str = "bool"
                    elif input_type == "array": type_str = "list"
                    elif input_type == "object": type_str = "dict"
                    
                    is_req = input_def.get("required", False)
                    if is_req:
                        sig_parts.append(f"{input_name}: {type_str}")
                    else:
                        sig_parts.append(f"{input_name}: {type_str} = None")
            
            sig_parts.append("__user_id: typing.Optional[str] = None")
            sig = ", ".join(sig_parts)
            fn_name = f"handler_{c.name.replace('-', '_')}"
            
            code = f'''
import typing

async def {fn_name}({sig}):
    kwargs = locals()
    filtered_kwargs = {{}}
    for k, v in kwargs.items():
        if v is not None:
            if k in {string_fields} and not isinstance(v, str):
                filtered_kwargs[k] = str(v)
            else:
                filtered_kwargs[k] = v
    return await run_tool(c, d, filtered_kwargs)
'''
            loc = {'run_tool': run_tool, 'c': c, 'd': d}
            exec(code, loc, loc)
            handler = loc[fn_name]
            handler.__name__ = c.name
            handler.__doc__ = c.description
            return handler

        mcp.tool(name=name, description=config.description)(create_handler(config, tool_dir))
        print(f"Registered tool: {name}")

if __name__ == "__main__":
    register_tools()
    import uvicorn
    app = mcp.http_app()
    uvicorn.run(app, host="0.0.0.0", port=8001)
