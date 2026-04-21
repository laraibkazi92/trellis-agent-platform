import os
import yaml
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.gemini import GeminiModel
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from core.models import AgentConfig

app = FastAPI(title="Universal Agent Host")

# Setup directories
BASE_DIR = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
HUB_PATH = BASE_DIR / "core" / "hub.py"

class ChatRequest(BaseModel):
    model: str
    messages: List[Dict[str, str]]

class AgentManager:
    def __init__(self):
        self.agents: Dict[str, Agent] = {}
        self.configs: Dict[str, AgentConfig] = {}
        self.mcp_session: Optional[ClientSession] = None
        self._mcp_cleanup = None

    async def start(self):
        """Initializes agents and connects to the Tool Hub."""
        await self.load_agents()
        await self.connect_to_hub()
        self.inject_a2a_tools()

    async def load_agents(self):
        """Scans the agents directory and initializes PydanticAI agents."""
        if not AGENTS_DIR.exists():
            print(f"Agents directory not found at {AGENTS_DIR}")
            return

        for agent_dir in AGENTS_DIR.iterdir():
            if agent_dir.is_dir():
                config_path = agent_dir / "config.yaml"
                skills_path = agent_dir / "skills.md"
                if config_path.exists() and skills_path.exists():
                    try:
                        with open(config_path, 'r') as f:
                            config_data = yaml.safe_load(f)
                            config = AgentConfig(**config_data)
                        
                        with open(skills_path, 'r') as f:
                            system_prompt = f.read()
                        
                        self.configs[config.name] = config
                        
                        # Initialize PydanticAI Agent
                        # Use GEMINI_API_KEY from env
                        api_key = os.getenv("GEMINI_API_KEY")
                        model = GeminiModel(config.model, api_key=api_key)
                        agent = Agent(
                            model,
                            system_prompt=system_prompt,
                            name=config.name,
                            retries=3
                        )
                        self.agents[config.name] = agent
                        print(f"Loaded agent: {config.name}")
                    except Exception as e:
                        print(f"Error loading agent at {agent_dir}: {e}")

    async def connect_to_hub(self):
        """Connects to the Polyglot Tool Hub via MCP stdio."""
        print("Connecting to Polyglot Tool Hub...")
        server_params = StdioServerParameters(
            command="python",
            args=[str(HUB_PATH)],
            env={**os.environ, "PYTHONPATH": str(BASE_DIR)}
        )
        
        # We need to keep the connection alive. 
        # In a real production app, we might use a background task or SSE.
        # For this refactor, we'll use a simplified approach where the Host
        # manages the Hub lifecycle for now.
        
        self._mcp_cleanup = stdio_client(server_params)
        read, write = await self._mcp_cleanup.__aenter__()
        self.mcp_session = ClientSession(read, write)
        await self.mcp_session.__aenter__()
        await self.mcp_session.initialize()
        
        # Discover and register tools to all agents
        tools_result = await self.mcp_session.list_tools()
        for tool in tools_result.tools:
            print(f"Injecting MCP tool '{tool.name}' into all agents")
            for agent_name, agent in self.agents.items():
                self._register_mcp_tool(agent, tool)

    def _register_mcp_tool(self, agent: Agent, mcp_tool: Any):
        """Helper to register an MCP tool to a PydanticAI agent."""
        
        # Define a wrapper that calls the MCP tool
        async def tool_wrapper(ctx: RunContext[None], arguments: Dict[str, Any]) -> Any:
            result = await self.mcp_session.call_tool(mcp_tool.name, arguments)
            return result.content

        # Register with PydanticAI
        # Note: We use a simplified schema for now as Phase 2 used generic 'arguments'
        agent.tool(name=mcp_tool.name, description=mcp_tool.description)(tool_wrapper)

    def inject_a2a_tools(self):
        """Injects call_{other_agent} tools based on a2a_access configuration."""
        for name, config in self.configs.items():
            agent = self.agents[name]
            for target_agent_name in config.a2a_access:
                if target_agent_name in self.agents:
                    print(f"Injecting A2A tool 'call_{target_agent_name}' into agent '{name}'")
                    self._register_a2a_tool(agent, target_agent_name)

    def _register_a2a_tool(self, agent: Agent, target_agent_name: str):
        """Helper to register an A2A tool."""
        
        async def a2a_tool_wrapper(ctx: RunContext[None], prompt: str) -> str:
            target_agent = self.agents[target_agent_name]
            result = await target_agent.run(prompt)
            return result.data

        tool_name = f"call_{target_agent_name}"
        description = f"Call the {target_agent_name} agent with a prompt and get a response."
        agent.tool(name=tool_name, description=description)(a2a_tool_wrapper)

    async def stop(self):
        if self.mcp_session:
            await self.mcp_session.__aexit__(None, None, None)
        if self._mcp_cleanup:
            await self._mcp_cleanup.__aexit__(None, None, None)

manager = AgentManager()

@app.on_event("startup")
async def startup_event():
    await manager.start()

@app.on_event("shutdown")
async def shutdown_event():
    await manager.stop()

@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    if request.model not in manager.agents:
        raise HTTPException(status_code=404, detail=f"Agent '{request.model}' not found")
    
    agent = manager.agents[request.model]
    
    # Simple conversion of messages to a single prompt for now
    # PydanticAI supports message history, but for simplicity in this V2 phase:
    prompt = request.messages[-1]["content"]
    
    try:
        result = await agent.run(prompt)
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": result.data
                    }
                }
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
