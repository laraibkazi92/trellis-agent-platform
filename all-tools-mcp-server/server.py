import os
import sys
import json
import inspect
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Callable
from pydantic_settings import BaseSettings, SettingsConfigDict
from mcp.server.fastmcp import FastMCP, Context
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.security import APIKeyHeader
import etcd3gw
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import uvicorn
import subprocess

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    tools_dir: str = "/app/tools"
    etcd_endpoint: str = "http://etcd:2379"
    database_url: str = "postgresql+asyncpg://user:password@postgres:5432/agent_registry"
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()

# Configuration
TOOLS_DIR = settings.tools_dir
ETCD_ENDPOINT = settings.etcd_endpoint
DATABASE_URL = settings.database_url

# Initialize database engine globally with connection pooling settings
engine = create_async_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5, max_overflow=10)

# Initialize global MCP server reference
current_mcp = FastMCP("all-tools-mcp-server")

import contextvars
agent_token_var = contextvars.ContextVar("agent_token", default=None)

async def check_tool_assignment(token: str | None, tool_name: str) -> bool:
    if not token:
        return False
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("""
                SELECT 1 FROM agent_tool_links atl
                JOIN agents a ON a.id = atl.agent_id
                JOIN tools t ON t.id = atl.tool_id
                WHERE a.agent_token = :token AND t.name = :tool_name
            """), {"token": token, "tool_name": tool_name})
            row = result.fetchone()
            return bool(row)
    except Exception as e:
        logger.error(f"Error checking tool assignment: {e}")
        return False

def get_etcd_secret(key: str) -> dict:
    """Retrieve credentials from etcd"""
    try:
        host_port = ETCD_ENDPOINT.replace("http://", "").replace("https://", "")
        host, port = host_port.split(":") if ":" in host_port else (host_port, "2379")
        client = etcd3gw.client(host=host, port=int(port))
        results = client.get(key)
        if not results or len(results) == 0:
            return {}
        value = results[0]
        if isinstance(value, tuple):
            value = value[0]
        return json.loads(value.decode() if isinstance(value, bytes) else value)
    except Exception as e:
        logger.error(f"Error fetching etcd secret {key}: {e}")
        return {}

def get_tool_info(tool_dir: str, module_name: str, function_name: str) -> dict:
    """Get tool signature and docstring out-of-process to avoid direct imports."""
    base_path = Path(TOOLS_DIR)
    rel_path = tool_dir
    if rel_path.startswith("tools/"):
        rel_path = rel_path[len("tools/"):]
    
    full_tool_path = base_path / rel_path
    
    if not full_tool_path.exists():
        # Fallback for local dev/testing
        root_dir = Path(__file__).parent.parent
        full_tool_path = root_dir / tool_dir
        if not full_tool_path.exists():
            raise FileNotFoundError(f"Tool directory not found: {full_tool_path}")

    venv_python = full_tool_path / "venv" / "bin" / "python"
    if not venv_python.exists():
        venv_python = Path(sys.executable)

    tool_runner_path = Path(__file__).parent / "tool_runner.py"

    process = subprocess.Popen(
        [str(venv_python), str(tool_runner_path), "info", str(full_tool_path), module_name, function_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(full_tool_path)
    )
    stdout, stderr = process.communicate()
    
    if process.returncode != 0:
        raise Exception(f"Failed to get tool info: {stderr}")
        
    try:
        info = json.loads(stdout)
        if "error" in info:
            raise Exception(info["error"])
        return info
    except json.JSONDecodeError:
        raise Exception(f"Failed to parse tool info output: {stdout}")

def create_mcp_wrapper(tool_name: str, description: str, secret_key: str | None, tool_dir: str, module_name: str, function_name: str):
    """Creates a wrapper for the tool function that executes it in a subprocess"""
    info = get_tool_info(tool_dir, module_name, function_name)
    
    # Reconstruct inspect.Signature
    parameters = []
    has_credentials_param = False
    
    for p in info["params"]:
        name = p["name"]
        
        # We skip adding credentials to the signature, since the MCP client shouldn't supply it
        if name == "credentials":
            has_credentials_param = True
            continue
            
        annotation = p["annotation"]
        if annotation == "Any":
            annotation = inspect.Parameter.empty
            
        default = inspect.Parameter.empty if p["default"] == "__EMPTY__" else p["default"]
        
        # Kind mapping (string to enum)
        kind_str = p["kind"].split(".")[-1]
        kind = getattr(inspect.Parameter, kind_str, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        
        parameters.append(inspect.Parameter(
            name=name,
            kind=kind,
            default=default,
            annotation=annotation
        ))
        
    new_sig = inspect.Signature(parameters)
    
    base_path = Path(TOOLS_DIR)
    rel_path = tool_dir
    if rel_path.startswith("tools/"):
        rel_path = rel_path[len("tools/"):]
    full_tool_path = base_path / rel_path
    
    venv_python = full_tool_path / "venv" / "bin" / "python"
    if not venv_python.exists():
        # Fallback for local testing or tools without requirements
        venv_python = Path(sys.executable)
        
    tool_runner_path = Path(__file__).parent / "tool_runner.py"
        
    async def mcp_tool_wrapper(**kwargs) -> str:
        # Check authorization using ContextVar
        token = agent_token_var.get()
        if not await check_tool_assignment(token, tool_name):
            raise Exception(f"Unauthorized: Agent does not have permission to execute tool '{tool_name}'")
            
        credentials = get_etcd_secret(secret_key) if secret_key else {}
        if has_credentials_param:
            kwargs['credentials'] = credentials
            
        process = await asyncio.create_subprocess_exec(
            str(venv_python), str(tool_runner_path), "run", str(full_tool_path), module_name, function_name,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(full_tool_path)
        )
        
        stdout, stderr = await process.communicate(input=json.dumps(kwargs).encode())
        
        if process.returncode != 0:
            raise Exception(f"Tool execution failed: {stderr.decode()}")
            
        try:
            output = json.loads(stdout.decode())
            if "error" in output:
                raise Exception(output["error"])
            return str(output.get("result", ""))
        except json.JSONDecodeError:
            raise Exception(f"Failed to parse tool output: {stdout.decode()}")
    
    mcp_tool_wrapper.__signature__ = new_sig
    mcp_tool_wrapper.__name__ = tool_name
    mcp_tool_wrapper.__doc__ = description or info.get("doc", "")
    
    return mcp_tool_wrapper

async def register_tools(max_retries: int = 5, retry_delay: int = 5):
    """Query database and load all active tools with retry logic"""
    new_mcp = FastMCP("all-tools-mcp-server")
    
    for attempt in range(max_retries):
        try:
            async with engine.connect() as conn:
                result = await conn.execute(text("""
                    SELECT name, description, tool_directory, entry_point_module,
                           entry_point_function, etcd_secret_key
                    FROM tools
                    WHERE is_active = true
                """))
                
                rows = result.fetchall()
                for row in rows:
                    tool_name, description, tool_dir, module_name, func_name, secret_key = row
                    try:
                        wrapper = create_mcp_wrapper(tool_name, description, secret_key, tool_dir, module_name, func_name)
                        new_mcp.add_tool(wrapper)
                        logger.info(f"Registered tool: {tool_name}")
                    except Exception as e:
                        logger.error(f"Failed to register tool {tool_name}: {e}")
                
                global current_mcp
                current_mcp = new_mcp
                return
        except Exception as e:
            logger.warning(f"Database connection attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            else:
                logger.error("Final database connection attempt failed. Starting server without tools.")

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def verify_api_key(api_key: str = Depends(api_key_header)):
    expected_api_key = os.environ.get("CONTROL_PLANE_API_KEY")
    if expected_api_key and api_key != expected_api_key:
        raise HTTPException(status_code=403, detail="Invalid or missing API Key")

# We'll use a standard FastAPI app to host the MCP and the reload endpoint
app = FastAPI()

@app.post("/reload", dependencies=[Depends(verify_api_key)])
async def reload_server():
    """Dynamically reloads tools from database without restarting the process"""
    logger.info("Reloading tools...")
    await register_tools()
    return {"status": "success", "message": "Tools reloaded successfully"}


class AgentTokenMiddleware:
    def __init__(self, app):
        self.app = app
        
    async def __call__(self, scope, receive, send):
        if scope['type'] in ('http', 'websocket'):
            headers = dict(scope.get('headers', []))
            token = headers.get(b'x-agent-token', b'').decode()
            if token:
                # Setting ContextVar in middleware ensures it propagates to all downstream async tasks
                agent_token_var.set(token)
        await self.app(scope, receive, send)

# Mount the MCP server's app proxy with the contextvar middleware applied
app.mount("/mcp", AgentTokenMiddleware(current_mcp.app))

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(register_tools())
    uvicorn.run(app, host="0.0.0.0", port=8000)
