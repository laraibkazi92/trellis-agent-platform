import sys
import json
import os
import subprocess
import asyncio
from pathlib import Path
from typing import Dict, Any
from fastmcp import FastMCP
from core.models import ToolConfig
from core.auth import IdentityManager

# Initialize FastMCP server with host and port
mcp = FastMCP("Polyglot Tool Hub")

BASE_DIR = Path(__file__).parent.parent

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)

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
                tool_dir = BASE_DIR / rel_path
                configs[config.name] = (config, tool_dir)
    except Exception as e:
        print(f"Error loading tools from etcd: {e}")
    return configs

async def run_tool(config: ToolConfig, tool_dir: Path, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Executes a tool as a subprocess and handles JSON stdin/stdout."""
    cmd = []
    if config.runtime == "python":
        cmd = [sys.executable, str(tool_dir / config.entrypoint)]
    elif config.runtime == "go":
        bin_path = tool_dir / ".bin" / config.name
        cmd = [str(bin_path)]
    elif config.runtime == "ts":
        cmd = ["npx", "tsx", str(tool_dir / config.entrypoint)]
    else:
        return {"error": f"Unsupported runtime: {config.runtime}"}

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(tool_dir)
        )

        input_json = json.dumps(arguments).encode()
        stdout, stderr = await process.communicate(input=input_json)

        if process.returncode != 0:
            return {
                "error": f"Tool exited with code {process.returncode}",
                "stderr": stderr.decode().strip()
            }

        try:
            return json.loads(stdout.decode())
        except json.JSONDecodeError:
            return {"output": stdout.decode().strip(), "warning": "Output was not valid JSON"}

    except Exception as e:
        return {"error": f"Failed to execute tool: {str(e)}"}

def register_tools():
    """Dynamically registers tools with the FastMCP server and pre-compiles Go tools."""
    configs = load_tool_configs()
    
    for name, (config, tool_dir) in configs.items():
        if config.runtime == "go":
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
