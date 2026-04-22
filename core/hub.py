import sys
import json
import os
import subprocess
import asyncio
from pathlib import Path
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP
from core.models import ToolConfig
from core.auth import IdentityManager

# Initialize FastMCP server with host and port
mcp = FastMCP("Polyglot Tool Hub", host="0.0.0.0", port=8001)

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
            async def handler(arguments: Dict[str, Any] = {}):
                return await run_tool(c, d, arguments)
            return handler

        mcp.tool(name=name, description=config.description)(create_handler(config, tool_dir))
        print(f"Registered tool: {name}")

if __name__ == "__main__":
    register_tools()
    mcp.run(transport="sse")
