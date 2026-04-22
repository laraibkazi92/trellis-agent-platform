import os
import yaml
import aiofiles
import asyncio
from pathlib import Path
from typing import List, Dict

BASE_DIR = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
TOOLS_DIR = BASE_DIR / "tools"

async def discover_agents() -> List[Dict]:
    """Scan agents directory for agent configs and skills."""
    agents = []
    if not await asyncio.to_thread(AGENTS_DIR.exists):
        return agents
        
    for agent_dir in await asyncio.to_thread(lambda: list(AGENTS_DIR.iterdir())):
        is_dir = await asyncio.to_thread(agent_dir.is_dir)
        config_exists = await asyncio.to_thread((agent_dir / "config.yaml").exists)
        
        if is_dir and config_exists:
            async with aiofiles.open(agent_dir / "config.yaml", 'r') as f:
                content = await f.read()
                config = yaml.safe_load(content)
                
            skills_content = ""
            skills_exists = await asyncio.to_thread((agent_dir / "skills.md").exists)
            if skills_exists:
                async with aiofiles.open(agent_dir / "skills.md", 'r') as f:
                    skills_content = await f.read()
                    
            agents.append({
                "name": config.get("name", agent_dir.name),
                "description": config.get("description", ""),
                "capabilities": config.get("capabilities", []),
                "skills": skills_content,
                "path": str(agent_dir)
            })
    return agents

async def discover_tools() -> List[Dict]:
    """Scan tools directory for tool configs."""
    tools = []
    if not await asyncio.to_thread(TOOLS_DIR.exists):
        return tools
        
    for tool_yaml in await asyncio.to_thread(lambda: list(TOOLS_DIR.glob("**/tool.yaml"))):
        async with aiofiles.open(tool_yaml, 'r') as f:
            content = await f.read()
            config = yaml.safe_load(content)
            tools.append({
                "name": config.get("name", tool_yaml.parent.name),
                "description": config.get("description", ""),
                "runtime": config.get("runtime", "unknown"),
                "path": str(tool_yaml.parent)
            })
    return tools
