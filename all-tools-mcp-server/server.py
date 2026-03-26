import os
import sys
import importlib.util
import json
import inspect
from pathlib import Path
from typing import Dict, Any, List, Callable
from mcp.server.fastmcp import FastMCP
import etcd3gw
from sqlalchemy import create_engine, text

# Configuration
TOOLS_DIR = os.environ.get("TOOLS_DIR", "/app/tools")
ETCD_ENDPOINT = os.environ.get("ETCD_ENDPOINT", "http://etcd:2379")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@postgres:5432/agent_registry")

# Initialize MCP server
mcp = FastMCP("all-tools-mcp-server")

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
        print(f"Error fetching etcd secret {key}: {e}")
        return {}

def load_tool_function(tool_dir: str, module_name: str, function_name: str):
    """Dynamically load a tool function from its directory"""
    # Normalize paths
    base_path = Path(TOOLS_DIR)
    
    # Handle relative paths from DB
    rel_path = tool_dir
    if rel_path.startswith("tools/"):
        rel_path = rel_path[len("tools/"):]
    
    tool_path = base_path / rel_path / f"{module_name}.py"
    
    if not tool_path.exists():
        # Fallback for local dev/testing
        root_dir = Path(__file__).parent.parent
        tool_path = root_dir / tool_dir / f"{module_name}.py"
        if not tool_path.exists():
            raise FileNotFoundError(f"Tool file not found: {tool_path}")

    spec = importlib.util.spec_from_file_location(module_name, tool_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load spec for {tool_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    return getattr(module, function_name)

def create_mcp_wrapper(tool_name: str, description: str, tool_func: Callable, secret_key: str | None):
    """
    Creates a wrapper for the tool function that injects credentials
    and preserves type hints for the other arguments.
    """
    sig = inspect.signature(tool_func)
    params = list(sig.parameters.values())
    
    # Filter out 'credentials' parameter if it exists
    new_params = [p for p in params if p.name != 'credentials']
    new_sig = sig.replace(parameters=new_params)
    
    async def mcp_tool_wrapper(**kwargs) -> str:
        credentials = get_etcd_secret(secret_key) if secret_key else {}
        # Inject credentials into kwargs if tool expects it
        if 'credentials' in [p.name for p in params]:
            kwargs['credentials'] = credentials
        
        if inspect.iscoroutinefunction(tool_func):
            result = await tool_func(**kwargs)
        else:
            result = tool_func(**kwargs)
        return str(result)
    
    mcp_tool_wrapper.__signature__ = new_sig
    mcp_tool_wrapper.__name__ = tool_name
    mcp_tool_wrapper.__doc__ = description
    
    return mcp_tool_wrapper

def register_tools():
    """Query database and load all active tools"""
    try:
        engine = create_engine(DATABASE_URL)
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
                    wrapper = create_mcp_wrapper(tool_name, description, tool_func, secret_key)
                    mcp.add_tool(wrapper)
                    print(f"Registered tool: {tool_name}")
                except Exception as e:
                    print(f"Failed to register tool {tool_name}: {e}")
    except Exception as e:
        print(f"Database connection failed during tool registration: {e}")

if __name__ == "__main__":
    register_tools()
    # Run MCP server on port 8000 (standard for our architecture)
    import uvicorn
    # FastMCP uses its own internal server, but we can also use mcp.run()
    # If transport="http", it uses an internal FastAPI app.
    mcp.run(transport="http")

