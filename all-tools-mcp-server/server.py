import os
import sys
import importlib.util
import json
import inspect
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Callable
from pydantic_settings import BaseSettings, SettingsConfigDict
from mcp.server.fastmcp import FastMCP
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.security import APIKeyHeader
import etcd3gw
from sqlalchemy import create_engine, text
import uvicorn

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    tools_dir: str = "/app/tools"
    etcd_endpoint: str = "http://etcd:2379"
    database_url: str = "postgresql://user:password@postgres:5432/agent_registry"
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()

# Configuration
TOOLS_DIR = settings.tools_dir
ETCD_ENDPOINT = settings.etcd_endpoint
DATABASE_URL = settings.database_url

# Initialize database engine globally with connection pooling settings
engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5, max_overflow=10)

# Initialize global MCP server reference
current_mcp = FastMCP("all-tools-mcp-server")

import contextvars
agent_token_var = contextvars.ContextVar("agent_token", default=None)

def check_tool_assignment(token: str | None, tool_name: str) -> bool:
    if not token:
        return False
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT 1 FROM agent_tool_links atl
                JOIN agents a ON a.id = atl.agent_id
                JOIN tools t ON t.id = atl.tool_id
                WHERE a.agent_token = :token AND t.name = :tool_name
            """), {"token": token, "tool_name": tool_name}).fetchone()
            return bool(result)
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

def load_tool_function(tool_dir: str, module_name: str, function_name: str):
    """Dynamically load a tool function from its directory"""
    base_path = Path(TOOLS_DIR)
    
    rel_path = tool_dir
    if rel_path.startswith("tools/"):
        rel_path = rel_path[len("tools/"):]
    
    full_tool_path = base_path / rel_path
    tool_path = full_tool_path / f"{module_name}.py"
    
    if not tool_path.exists():
        # Fallback for local dev/testing
        root_dir = Path(__file__).parent.parent
        full_tool_path = root_dir / tool_dir
        tool_path = full_tool_path / f"{module_name}.py"
        if not tool_path.exists():
            raise FileNotFoundError(f"Tool file not found: {tool_path}")

    # Add venv site-packages to sys.path to allow inspecting signatures
    venv_site_packages = list(full_tool_path.glob("venv/lib/python*/site-packages"))
    if venv_site_packages:
        sys.path.insert(0, str(venv_site_packages[0]))
    
    sys.path.insert(0, str(full_tool_path))

    # If module already exists, try to reload it safely to avoid memory leaks
    if module_name in sys.modules:
        module = sys.modules[module_name]
        # Only reload if the module has a __file__ attribute matching our tool path
        if getattr(module, '__file__', None) == str(tool_path):
            importlib.reload(module)
            sys.path.pop(0)
            if venv_site_packages:
                sys.path.pop(0)
            return getattr(module, function_name)
            
    spec = importlib.util.spec_from_file_location(module_name, tool_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load spec for {tool_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    sys.path.pop(0)
    if venv_site_packages:
        sys.path.pop(0)

    return getattr(module, function_name)

def create_mcp_wrapper(tool_name: str, description: str, tool_func: Callable, secret_key: str | None, tool_dir: str, module_name: str, function_name: str):
    """Creates a wrapper for the tool function that executes it in a subprocess"""
    sig = inspect.signature(tool_func)
    params = list(sig.parameters.values())
    
    new_params = [p for p in params if p.name != 'credentials']
    new_sig = sig.replace(parameters=new_params)
    
    base_path = Path(TOOLS_DIR)
    rel_path = tool_dir
    if rel_path.startswith("tools/"):
        rel_path = rel_path[len("tools/"):]
    full_tool_path = base_path / rel_path
    
    venv_python = full_tool_path / "venv" / "bin" / "python"
    if not venv_python.exists():
        # Fallback for local testing or tools without requirements
        venv_python = Path(sys.executable)
        
    async def mcp_tool_wrapper(**kwargs) -> str:
        token = agent_token_var.get()
        if not check_tool_assignment(token, tool_name):
            raise Exception(f"Unauthorized: Agent does not have permission to execute tool '{tool_name}'")
            
        credentials = get_etcd_secret(secret_key) if secret_key else {}
        if 'credentials' in [p.name for p in params]:
            kwargs['credentials'] = credentials
            
        import subprocess
        
        # We write a tiny wrapper script to execute the function and handle sync/async
        script = f"""
import sys, json, asyncio
sys.path.insert(0, '{full_tool_path}')
try:
    from {module_name} import {function_name}
except ImportError as e:
    print(json.dumps({{"error": f"Import error: {{e}}" }}))
    sys.exit(1)

kwargs = json.loads(sys.stdin.read())

async def run():
    try:
        if asyncio.iscoroutinefunction({function_name}):
            res = await {function_name}(**kwargs)
        else:
            res = {function_name}(**kwargs)
        print(json.dumps({{"result": res}}))
    except Exception as e:
        print(json.dumps({{"error": str(e)}}))

asyncio.run(run())
"""
        process = await asyncio.create_subprocess_exec(
            str(venv_python), "-c", script,
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
            raise Exception(f"Failed to parse tool output: {stdout}")
    
    mcp_tool_wrapper.__signature__ = new_sig
    mcp_tool_wrapper.__name__ = tool_name
    mcp_tool_wrapper.__doc__ = description
    
    return mcp_tool_wrapper

def register_tools(max_retries: int = 5, retry_delay: int = 5):
    """Query database and load all active tools with retry logic"""
    new_mcp = FastMCP("all-tools-mcp-server")
    
    for attempt in range(max_retries):
        try:
            with engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT name, description, tool_directory, entry_point_module,
                           entry_point_function, etcd_secret_key
                    FROM tools
                    WHERE is_active = true
                """))
                
                for row in result:
                    tool_name, description, tool_dir, module_name, func_name, secret_key = row
                    try:
                        tool_func = load_tool_function(tool_dir, module_name, func_name)
                        wrapper = create_mcp_wrapper(tool_name, description, tool_func, secret_key, tool_dir, module_name, func_name)
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
                import time
                time.sleep(retry_delay)
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
def reload_server():
    """Dynamically reloads tools from database without restarting the process"""
    logger.info("Reloading tools...")
    register_tools()
    return {"status": "success", "message": "Tools reloaded successfully"}

async def mcp_proxy(scope, receive, send):
    if scope['type'] == 'http':
        headers = dict(scope.get('headers', []))
        token = headers.get(b'x-agent-token', b'').decode()
        agent_token_var.set(token)
    elif scope['type'] == 'websocket':
        headers = dict(scope.get('headers', []))
        token = headers.get(b'x-agent-token', b'').decode()
        agent_token_var.set(token)
        
    await current_mcp.app(scope, receive, send)

# Mount the MCP server's app proxy
app.mount("/mcp", mcp_proxy)

if __name__ == "__main__":
    register_tools()
    uvicorn.run(app, host="0.0.0.0", port=8000)
