import os
import yaml
from pathlib import Path
from typing import List, Dict

BASE_DIR = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
TOOLS_DIR = BASE_DIR / "tools"

def discover_agents() -> List[Dict]:
    """Scan agents directory for agent configs and skills."""
    agents = []
    if not AGENTS_DIR.exists():
        return agents
        
    for agent_dir in AGENTS_DIR.iterdir():
        if agent_dir.is_dir() and (agent_dir / "config.yaml").exists():
            with open(agent_dir / "config.yaml", 'r') as f:
                config = yaml.safe_load(f)
                
            skills_content = ""
            if (agent_dir / "skills.md").exists():
                with open(agent_dir / "skills.md", 'r') as f:
                    skills_content = f.read()
                    
            agents.append({
                "name": config.get("name", agent_dir.name),
                "description": config.get("description", ""),
                "capabilities": config.get("capabilities", []),
                "skills": skills_content,
                "path": str(agent_dir)
            })
    return agents

def discover_tools() -> List[Dict]:
    """Scan tools directory for tool configs."""
    tools = []
    if not TOOLS_DIR.exists():
        return tools
        
    for tool_yaml in TOOLS_DIR.glob("**/tool.yaml"):
        with open(tool_yaml, 'r') as f:
            config = yaml.safe_load(f)
            tools.append({
                "name": config.get("name", tool_yaml.parent.name),
                "description": config.get("description", ""),
                "runtime": config.get("runtime", "unknown"),
                "path": str(tool_yaml.parent)
            })
    return tools
