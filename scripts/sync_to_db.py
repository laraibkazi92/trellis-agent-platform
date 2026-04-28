import os
import sys

# Protocol Buffers implementation fix for etcd3
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

import yaml
from pathlib import Path

# Add the parent directory to sys.path to import core
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth import IdentityManager

BASE_DIR = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
TOOLS_DIR = BASE_DIR / "tools"
SUPERVISOR_DIR = BASE_DIR / "core" / "assets" / "supervisor"
MCPS_DIR = BASE_DIR / "mcps"

def sync_agent(identity_mgr, agent_dir, name=None):
    if not name:
        name = agent_dir.name
        
    config_path = agent_dir / "config.yaml"
    skills_path = agent_dir / "skills.md"
    
    if config_path.exists():
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
            
        if not config.get("name"):
            config["name"] = name
        
        if "allowed_tools" not in config:
            config["allowed_tools"] = []
            
        identity_mgr.save_agent_config(name, config)
        print(f"  Saved config for agent: {name}")
        
    if skills_path.exists():
        with open(skills_path, "r") as f:
            skills = f.read()
        identity_mgr.save_agent_skills(name, skills)
        print(f"  Saved skills for agent: {name}")

def main():
    identity_mgr = IdentityManager(
        host=os.getenv("ETCD_HOST", "127.0.0.1"),
        port=int(os.getenv("ETCD_PORT", 2379))
    )
    
    print("Syncing agents to etcd...")
    if AGENTS_DIR.exists():
        for agent_dir in AGENTS_DIR.iterdir():
            if not agent_dir.is_dir() or agent_dir.name == "supervisor":
                continue
            sync_agent(identity_mgr, agent_dir)
    
    print("\nSyncing supervisor to etcd...")
    if SUPERVISOR_DIR.exists():
        sync_agent(identity_mgr, SUPERVISOR_DIR, name="supervisor")

    print("\nSyncing tools to etcd...")
    if TOOLS_DIR.exists():
        for tool_yaml in TOOLS_DIR.glob("**/tool.yaml"):
            tool_dir = tool_yaml.parent
            with open(tool_yaml, "r") as f:
                data = yaml.safe_load(f)
                
            # Support both single tool and list of tools
            tool_configs = data if isinstance(data, list) else [data]
            
            for config in tool_configs:
                if not config.get("name"):
                    config["name"] = tool_dir.name
                    
                # Add relative path so Hub knows where to execute it
                rel_path = tool_dir.relative_to(BASE_DIR)
                config["rel_path"] = str(rel_path)
                
                identity_mgr.save_tool_config(config["name"], config)
                print(f"  Saved config for tool: {config['name']}")

    print("\nSyncing MCPs to etcd...")
    if MCPS_DIR.exists():
        for mcp_yaml in MCPS_DIR.glob("**/mcp.yaml"):
            mcp_dir = mcp_yaml.parent
            with open(mcp_yaml, "r") as f:
                data = yaml.safe_load(f)
                
            mcp_configs = data if isinstance(data, list) else [data]
            
            for config in mcp_configs:
                if not config.get("name"):
                    config["name"] = mcp_dir.name
                
                identity_mgr.save_mcp_config(config["name"], config)
                print(f"  Saved config for MCP: {config['name']}")

    print("\nSync complete.")

if __name__ == "__main__":
    main()
