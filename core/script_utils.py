import os
import json
import subprocess
from pathlib import Path
from core.agent_factory import get_identity_manager

def run_local_tool(tool_name: str, kwargs: dict) -> dict:
    """
    Executes a framework tool locally by looking up its configuration from the framework registry.
    """
    try:
        identity_mgr = get_identity_manager()
        tool_config = identity_mgr.get_tool_config(tool_name)
        
        if not tool_config:
            return {"success": False, "error": f"Tool '{tool_name}' not found in registry."}
            
        rel_path = tool_config.get("rel_path")
        if not rel_path:
            return {"success": False, "error": f"Tool '{tool_name}' missing rel_path configuration."}
            
        base_dir = Path(__file__).parent.parent
        tool_dir = (base_dir / rel_path).resolve()
        if not tool_dir.is_relative_to(base_dir):
            return {"success": False, "error": f"Tool '{tool_name}' has invalid path: escapes base directory."}

        entrypoint = tool_config.get("entrypoint")
        runtime = tool_config.get("runtime", "python")

        if not entrypoint:
            return {"success": False, "error": f"Tool '{tool_name}' missing entrypoint."}

        entrypoint_path = (tool_dir / entrypoint).resolve()
        if not entrypoint_path.is_relative_to(tool_dir) or not entrypoint_path.is_file():
            return {"success": False, "error": f"Tool entrypoint not found or outside tool directory."}
            
        if runtime == "python":
            cmd = ["python", str(entrypoint_path)]
        elif runtime == "node":
            cmd = ["node", str(entrypoint_path)]
        elif runtime == "bash":
            cmd = ["bash", str(entrypoint_path)]
        else:
            cmd = [str(entrypoint_path)]
            
        input_json = json.dumps(kwargs).encode('utf-8')
        env = os.environ.copy()
        
        process = subprocess.run(
            cmd,
            input=input_json,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(tool_dir),
            timeout=120
        )
        
        if process.returncode != 0:
            return {"success": False, "error": f"Tool failed with exit code {process.returncode}: {process.stderr.decode()}"}
            
        stdout_str = process.stdout.decode().strip()
        try:
            return json.loads(stdout_str)
        except json.JSONDecodeError:
            return {"success": False, "error": f"Tool did not output valid JSON. Output: {stdout_str}"}
            
    except Exception as e:
        return {"success": False, "error": str(e)}
