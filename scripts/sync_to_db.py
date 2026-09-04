import os
import sys


import yaml
from pathlib import Path

# Add the parent directory to sys.path to import core
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth import IdentityManager
from core.embeddings import embed_text

BASE_DIR = Path(__file__).parent.parent
WORKSPACE_DIR = BASE_DIR / "workspace"

AGENTS_DIR = WORKSPACE_DIR / "agents"
WORKFLOWS_DIR = WORKSPACE_DIR / "workflows"
TOOLS_DIR = WORKSPACE_DIR / "tools"
MCPS_DIR = WORKSPACE_DIR / "mcps"

# Supervisor is an internal core agent
SUPERVISOR_DIR = BASE_DIR / "core" / "assets" / "supervisor"

def sync_agent(identity_mgr, agent_dir, name=None, default_type=None):
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
            
        if not config.get("type") and default_type:
            config["type"] = default_type

        config["external"] = config.get("external", True)
        config["internal"] = config.get("internal", True)

        # For script types, we need the rel_path so the engine knows where to run it
        try:
            rel_path = agent_dir.relative_to(BASE_DIR)
            config["rel_path"] = str(rel_path)
        except ValueError:
            # If agent_dir is outside BASE_DIR, just use the absolute path or ignore
            pass
            
        identity_mgr.save_agent_config(name, config)
        print(f"  Saved config for agent: {name} (Type: {config.get('type')})")

        # Index the agent for semantic search. Skipped for background agents/scripts
        # and the supervisor, which are never returned by search_agents.
        if config.get("type") not in ("background_agent", "background_script") and name != "supervisor":
            parts = [config.get("name", name), config.get("description", "")]
            tags = config.get("tags") or []
            if tags:
                parts.append(" ".join(str(t) for t in tags))
            vector = embed_text("\n".join(p for p in parts if p), task_type="retrieval_document")
            if vector:
                identity_mgr.save_agent_embedding(name, vector)
                print(f"  Indexed embedding for agent: {name}")
            else:
                print(f"  Skipped embedding for agent: {name} (embeddings unavailable)")

    if skills_path.exists():
        with open(skills_path, "r") as f:
            skills = f.read()
        identity_mgr.save_agent_skills(name, skills)
        print(f"  Saved skills for agent: {name}")
        
    return name

def main():
    identity_mgr = IdentityManager(
        host=os.getenv("ETCD_HOST", "127.0.0.1"),
        port=int(os.getenv("ETCD_PORT", 2379))
    )
    
    # 1. Fetch current items from etcd
    existing_agents = set(identity_mgr._get_all_configs_by_prefix("/registry/agents/").keys())
    existing_tools = set(identity_mgr._get_all_configs_by_prefix("/registry/tools/").keys())
    existing_mcps = set(identity_mgr._get_all_configs_by_prefix("/registry/mcps/").keys())
    
    seen_agents = set()
    seen_tools = set()
    seen_mcps = set()
    
    print("Syncing agents to etcd...")
    if AGENTS_DIR.exists():
        for agent_dir in AGENTS_DIR.iterdir():
            if not agent_dir.is_dir() or agent_dir.name == "supervisor":
                continue
            name = sync_agent(identity_mgr, agent_dir, default_type="user_agent")
            if name:
                seen_agents.add(name)
                
    print("\nSyncing workflows to etcd...")
    if WORKFLOWS_DIR.exists():
        for agent_dir in WORKFLOWS_DIR.iterdir():
            if not agent_dir.is_dir():
                continue
            name = sync_agent(identity_mgr, agent_dir, default_type="background_agent")
            if name:
                seen_agents.add(name)
    
    print("\nSyncing supervisor to etcd...")
    if SUPERVISOR_DIR.exists():
        name = sync_agent(identity_mgr, SUPERVISOR_DIR, name="supervisor", default_type="user_agent")
        if name:
            seen_agents.add(name)

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
                
                name = config["name"]
                identity_mgr.save_tool_config(name, config)
                seen_tools.add(name)
                print(f"  Saved config for tool: {name}")

                # Index the embedding only for tools exposed publicly via the gateway.
                if config.get("public"):
                    inputs = config.get("inputs") or {}
                    input_keys = ", ".join(
                        f"{key}:{spec.get('type', 'any')}" if isinstance(spec, dict) else str(key)
                        for key, spec in inputs.items()
                    )
                    parts = [name, config.get("description", ""), input_keys]
                    vector = embed_text("\n".join(p for p in parts if p), task_type="retrieval_document")
                    if vector:
                        identity_mgr.save_tool_embedding(name, vector)
                        print(f"  Indexed embedding for tool: {name}")
                    else:
                        print(f"  Skipped embedding for tool: {name} (embeddings unavailable)")

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
                
                name = config["name"]
                identity_mgr.save_mcp_config(name, config)
                seen_mcps.add(name)
                print(f"  Saved config for MCP: {name}")

    # 2. Prune obsolete items
    print("\nPruning obsolete entries from etcd...")
    
    for agent in existing_agents - seen_agents:
        print(f"  Deleting obsolete agent: {agent}")
        identity_mgr.client.delete(f"/registry/agents/{agent}/config")
        identity_mgr.client.delete(f"/registry/agents/{agent}/skills")
        identity_mgr.client.delete(f"/registry/agents/{agent}/embedding")
        
    for tool in existing_tools - seen_tools:
        print(f"  Deleting obsolete tool: {tool}")
        identity_mgr.client.delete(f"/registry/tools/{tool}/config")
        identity_mgr.client.delete(f"/registry/tools/{tool}/embedding")
        
    for mcp in existing_mcps - seen_mcps:
        print(f"  Deleting obsolete MCP: {mcp}")
        identity_mgr.client.delete(f"/registry/mcps/{mcp}/config")

    print("\nSync complete.")

if __name__ == "__main__":
    main()
