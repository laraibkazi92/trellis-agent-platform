import os
import yaml
import aiofiles
import asyncio
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from core.auth import AuthMiddleware, IdentityManager, user_id_var

from pydantic import BaseModel
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings
from pydantic_ai.messages import ModelRequest, ModelResponse, UserPromptPart, TextPart
from fastmcp import Client as FastMCPClient
from core.models import AgentConfig
from core.health import HealthMonitor

app = FastAPI(title="Universal Agent Host")

# CORS Setup
DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"
cors_origins_str = os.getenv("CORS_ALLOWED_ORIGINS", "")
if DEV_MODE:
    allow_origins = ["*"]
else:
    allow_origins = [origin.strip() for origin in cors_origins_str.split(",")] if cors_origins_str else []

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

identity_mgr = IdentityManager(
    host=os.getenv("ETCD_HOST", "127.0.0.1"),
    port=int(os.getenv("ETCD_PORT", 2379))
)
app.add_middleware(AuthMiddleware, identity_mgr=identity_mgr)
health_monitor = HealthMonitor(identity_mgr)


# Setup directories
BASE_DIR = Path(__file__).parent.parent
AGENTS_DIR = BASE_DIR / "agents"
INTERNAL_ASSETS_DIR = BASE_DIR / "core" / "assets"
DEFAULT_HUB_URL = os.getenv("HUB_URL", "http://localhost:8001/mcp")

GEMINI_2_5_PRO_MODELS = {"gemini-2.5-pro"}
GEMINI_2_5_FLASH_MODELS = {"gemini-2.5-flash"}
LITE_MODELS = {"gemini-3.1-flash-lite-preview", "gemini-2.5-flash-lite"}
GEMINI_3_MODELS = {"gemini-3.1-pro-preview", "gemini-3-flash-preview"}

GEMINI_2_5_PRO_BUDGETS = {"low": 1024, "medium": 8192, "high": 16384}
GEMINI_2_5_FLASH_BUDGETS = {"low": 1024, "medium": 4096, "high": 8192}

# Maintain a set of background tasks to prevent garbage collection
background_tasks = set()

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str
    messages: List[ChatMessage]

def _inject_secrets(env: Optional[Dict[str, str]], secrets: Optional[List[str]], user_secrets: Dict[str, str]) -> Dict[str, str]:
    """Inject user secrets into the environment dict, supporting string interpolation."""
    env_copy = env.copy() if env else {}
    for req_secret in (secrets or []):
        val = user_secrets.get(req_secret)
        if val:
            interpolated = False
            for k, v in env_copy.items():
                if isinstance(v, str) and f"{{{req_secret}}}" in v:
                    env_copy[k] = v.replace(f"{{{req_secret}}}", val)
                    interpolated = True
            if not interpolated:
                env_copy[req_secret] = val
    return env_copy

class AgentManager:
    def __init__(self):
        self.agents: Dict[str, Agent] = {}
        self.configs: Dict[str, AgentConfig] = {}
        self.mcp_client: Optional[FastMCPClient] = None
        self._mcp_tools_cache = []
        self._external_mcp_tools_cache = {}  # mcp_name -> list of tools
        self._user_mcp_pools: Dict[tuple[str, str], FastMCPClient] = {}  # (user_id, mcp_name) -> FastMCPClient
        self._lock = asyncio.Lock()

    async def start(self):
        """Initializes agents and connects to the Tool Hub."""
        print("Starting Agent Manager...")
        await self._init_supervisor()
        await self.load_agents()
        await self.connect_to_hub()
        await self.discover_mcps()
        await self.inject_a2a_tools()
        print("Agent Manager started successfully.")

    async def _init_supervisor(self):
        """Loads the internal Supervisor agent from etcd or falls back to filesystem."""
        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, "supervisor")
        system_prompt = await asyncio.to_thread(identity_mgr.get_agent_skills, "supervisor")
        
        if not config_data or not system_prompt:
            print("Internal supervisor configuration not found in etcd. Loading from filesystem...")
            supervisor_dir = INTERNAL_ASSETS_DIR / "supervisor"
            config_path = supervisor_dir / "config.yaml"
            skills_path = supervisor_dir / "skills.md"
            
            if not config_path.exists() or not skills_path.exists():
                print("Critical: Supervisor assets missing from filesystem!")
                return
                
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f)
            with open(skills_path, "r") as f:
                system_prompt = f.read()
                
            config_data['a2a_access'] = []
            if "allowed_tools" not in config_data:
                config_data["allowed_tools"] = []
                
            await asyncio.to_thread(identity_mgr.save_agent_config, "supervisor", config_data)
            await asyncio.to_thread(identity_mgr.save_agent_skills, "supervisor", system_prompt)
            print("Supervisor configuration populated to etcd from filesystem.")

        try:
            # clear a2a_access as it's injected dynamically
            config_data['a2a_access'] = []
            config = AgentConfig(**config_data)
            
            self.configs[config.name] = config
            
            model = GoogleModel(config.model)
            model_settings = self._get_model_settings(config.model, config.thinking_level)
            
            agent = Agent(
                model,
                system_prompt=system_prompt,
                name=config.name,
                model_settings=model_settings,
                retries=3
            )
            
            # Inject administrative tools
            self._register_admin_tools(agent)

            async with self._lock:
                self.agents[config.name] = agent
            print(f"Successfully loaded internal agent: {config.name}")
        except Exception as e:
            print(f"Error loading internal supervisor: {e}")

    def _get_model_settings(self, model_name: str, thinking_level: str) -> Optional[GoogleModelSettings]:
        """Translates UI thinking_level into PydanticAI GoogleModelSettings."""
        if not thinking_level or thinking_level in ("none", "n/a"):
            return None

        if model_name in LITE_MODELS:
            return None

        if model_name in GEMINI_2_5_PRO_MODELS:
            budget = GEMINI_2_5_PRO_BUDGETS.get(thinking_level.lower(), 8192) # fallback to medium
            return GoogleModelSettings(
                google_thinking_config={"thinking_budget": budget, "include_thoughts": False}
            )
            
        elif model_name in GEMINI_2_5_FLASH_MODELS:
            budget = GEMINI_2_5_FLASH_BUDGETS.get(thinking_level.lower(), 4096) # fallback to medium
            return GoogleModelSettings(
                google_thinking_config={"thinking_budget": budget, "include_thoughts": False}
            )
            
        elif model_name in GEMINI_3_MODELS:
            # Gemini 3.x uses thinking_level parameter directly
            return GoogleModelSettings(
                google_thinking_config={"thinking_level": thinking_level.lower(), "include_thoughts": False}
            )

        return None

    def _register_admin_tools(self, agent: Agent):
        """Registers framework management tools specifically for the Supervisor."""

        @agent.tool_plain(name="list_agents", description="List all available specialized agents.")
        def list_agents() -> List[Dict[str, str]]:
            disabled = identity_mgr.get_disabled_agents()
            agents_info = []
            for name, config in self.configs.items():
                if name == "supervisor": continue
                status = "disabled" if name in disabled else "active"
                agents_info.append({"name": name, "description": config.description or "No description", "status": status})
            return agents_info

        @agent.tool_plain(name="manage_agent", description="Enable, disable or reload an agent.")
        async def manage_agent(name: str, action: str) -> str:
            if action == "disable":
                disabled = identity_mgr.get_disabled_agents()
                if name not in disabled:
                    disabled.append(name)
                    identity_mgr.set_disabled_agents(disabled)
                    async with self._lock:
                        if name in self.agents:
                            del self.agents[name]
                        # Don't delete from configs to keep knowledge of it
                return f"Agent {name} disabled."
            elif action == "enable":
                disabled = identity_mgr.get_disabled_agents()
                if name in disabled:
                    disabled.remove(name)
                    identity_mgr.set_disabled_agents(disabled)
                    await self._load_agent_from_registry(name)
                    await self._reinject_tools_for_agent(name)
                return f"Agent {name} enabled."
            elif action == "reload":
                await self._load_agent_from_registry(name)
                await self._reinject_tools_for_agent(name)
                return f"Agent {name} reloaded."
            return "Invalid action."

        @agent.tool_plain(name="get_framework_status", description="Get MCP Hub connection status and tool count.")
        def get_framework_status() -> Dict[str, Any]:
            hub_url = identity_mgr.get_config("HUB_URL", DEFAULT_HUB_URL)
            return {
                "hub_url": hub_url,
                "connected": self.mcp_client is not None,
                "tool_count": len(self._mcp_tools_cache),
                "external_mcps": list(self._external_mcp_tools_cache.keys())
            }

        @agent.tool_plain(name="update_mcp_config", description="Update the Polyglot Tool Hub URL and reconnect.")
        async def update_mcp_config(hub_url: str) -> str:
            parsed = urlparse(hub_url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                return f"Error: Invalid URL format '{hub_url}'. Must be a valid HTTP/HTTPS URL."
            
            identity_mgr.set_config("HUB_URL", hub_url)
            try:
                await self.connect_to_hub()
                return f"Successfully updated and connected to {hub_url}."
            except Exception as e:
                return f"Updated config, but connection failed: {e}"

    async def _reinject_tools_for_agent(self, name: str):
        """Helper to inject MCP tools into a specific agent if active."""
        async with self._lock:
            if name in self.agents:
                agent_config = self.configs.get(name)
                if not agent_config:
                    return
                
                allowed_tools = agent_config.allowed_tools if agent_config else []
                allowed_mcps = agent_config.allowed_mcps if agent_config else []
                
                if self.mcp_client:
                    for tool in self._mcp_tools_cache:
                        if tool.name in allowed_tools:
                            self._register_mcp_tool(self.agents[name], tool)
                
                for mcp_name, tools in self._external_mcp_tools_cache.items():
                    if mcp_name in allowed_mcps:
                        for tool in tools:
                            self._register_external_mcp_tool(self.agents[name], mcp_name, tool)
                    else:
                        for tool in tools:
                            if tool.name in allowed_tools:
                                self._register_external_mcp_tool(self.agents[name], mcp_name, tool)

    async def _load_agent_from_registry(self, name: str):
        """Loads a single agent from etcd."""
        if name == "supervisor":
            return # Ignore supervisor in public agents directory

        config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
        system_prompt = await asyncio.to_thread(identity_mgr.get_agent_skills, name)
        
        if not config_data or not system_prompt:
            return

        try:
            config = AgentConfig(**config_data)
            
            model = GoogleModel(config.model)
            model_settings = self._get_model_settings(config.model, config.thinking_level)
            
            agent = Agent(
                model,
                system_prompt=system_prompt,
                name=config.name,
                model_settings=model_settings,
                retries=3
            )
            async with self._lock:
                self.configs[config.name] = config
                self.agents[config.name] = agent
            print(f"Successfully loaded agent: {config.name}")
        except Exception as e:
            print(f"Error loading agent {name}: {e}")

    async def load_agents(self):
        """Scans the etcd registry and initializes PydanticAI agents."""
        print(f"Loading agents from etcd...")
        agent_names = await asyncio.to_thread(identity_mgr.list_agents)

        disabled_agents = identity_mgr.get_disabled_agents()

        for name in agent_names:
            if name in disabled_agents:
                print(f"Skipping disabled agent: {name}")
                continue
            await self._load_agent_from_registry(name)

    async def discover_mcps(self):
        """Iterates over registered MCPs and temporarily connects to discover their tools."""
        print("Discovering external MCPs...")
        mcp_names = await asyncio.to_thread(identity_mgr.list_mcps)
        
        # Avoid overriding the entire dict if not needed, just in case
        for name in mcp_names:
            config_data = await asyncio.to_thread(identity_mgr.get_mcp_config, name)
            if not config_data:
                continue
            
            try:
                from core.models import MCPConfig
                from fastmcp.client import StdioTransport, SSETransport
                config = MCPConfig(**config_data)
                
                if config.tools:
                    tools = config.tools
                    self._external_mcp_tools_cache[name] = tools
                    print(f"Loaded {len(tools)} static tools for MCP '{name}'")
                    
                    # Register to agents
                    async with self._lock:
                        for agent_name, agent in self.agents.items():
                            if agent_name == "supervisor":
                                continue
                            agent_config = self.configs.get(agent_name)
                            if not agent_config:
                                continue
                            
                            allowed_mcps = agent_config.allowed_mcps or []
                            allowed_tools = agent_config.allowed_tools or []
                            
                            if name in allowed_mcps:
                                # Agent is allowed to use all tools from this MCP
                                for tool in tools:
                                    print(f"Injecting external MCP tool '{tool.name}' (from '{name}') into agent '{agent_name}'")
                                    self._register_external_mcp_tool(agent, name, tool)
                            else:
                                # Check if specific tools from this MCP are allowed
                                for tool in tools:
                                    if tool.name in allowed_tools:
                                        print(f"Injecting external MCP tool '{tool.name}' (from '{name}') into agent '{agent_name}'")
                                        self._register_external_mcp_tool(agent, name, tool)
                    continue

                transport = None
                if config.transport == "stdio":
                    if not config.command:
                        print(f"Skipping MCP '{name}' (stdio missing command)")
                        continue
                    transport = StdioTransport(
                        command=config.command,
                        args=config.args or [],
                        env=config.env or {},
                        keep_alive=False
                    )
                elif config.transport == "sse":
                    if not config.command:
                        print(f"Skipping MCP '{name}' (sse missing url)")
                        continue
                    transport = SSETransport(url=config.command, headers=config.env or {})
                else:
                    print(f"Skipping MCP '{name}' (unknown transport {config.transport})")
                    continue
                
                client = FastMCPClient(transport)
                async with client:
                    tools = await client.list_tools()
                    self._external_mcp_tools_cache[name] = tools
                    print(f"Successfully discovered {len(tools)} tools from MCP '{name}'")
                    
                    # Register to agents
                    async with self._lock:
                        for agent_name, agent in self.agents.items():
                            if agent_name == "supervisor":
                                continue
                            agent_config = self.configs.get(agent_name)
                            if not agent_config:
                                continue
                            
                            allowed_mcps = agent_config.allowed_mcps or []
                            allowed_tools = agent_config.allowed_tools or []
                            
                            if name in allowed_mcps:
                                # Agent is allowed to use all tools from this MCP
                                for tool in tools:
                                    print(f"Injecting external MCP tool '{tool.name}' (from '{name}') into agent '{agent_name}'")
                                    self._register_external_mcp_tool(agent, name, tool)
                            else:
                                # Check if specific tools from this MCP are allowed
                                for tool in tools:
                                    if tool.name in allowed_tools:
                                        print(f"Injecting external MCP tool '{tool.name}' (from '{name}') into agent '{agent_name}'")
                                        self._register_external_mcp_tool(agent, name, tool)
                                        
            except Exception as e:
                print(f"Failed to discover tools for MCP '{name}': {e}")

    async def connect_to_hub(self, max_retries: int = 5, retry_delay: int = 2):
        """Connects to the Polyglot Tool Hub via MCP SSE and registers tools."""
        hub_url = identity_mgr.get_config("HUB_URL", DEFAULT_HUB_URL)
        
        for attempt in range(max_retries):
            print(f"Connecting to Polyglot Tool Hub at {hub_url} (attempt {attempt + 1}/{max_retries})...")
            try:
                await self._establish_mcp_connection(hub_url)
                # Discover and register tools to specialized agents ONLY
                tools = await self.mcp_client.list_tools()
                self._mcp_tools_cache = tools
                
                async with self._lock:
                    for tool in self._mcp_tools_cache:
                        print(f"Evaluating MCP tool '{tool.name}' for specialized agents")
                        # Using a safe copy to iterate
                        agent_items = list(self.agents.items())
                        for agent_name, agent in agent_items:
                            if agent_name == "supervisor":
                                continue # Supervisor does not get business logic tools
                            agent_config = self.configs.get(agent_name)
                            allowed_tools = agent_config.allowed_tools if agent_config else []
                            if tool.name in allowed_tools:
                                print(f"Injecting MCP tool '{tool.name}' into agent '{agent_name}'")
                                self._register_mcp_tool(agent, tool)
                print("Successfully connected to Tool Hub and registered tools.")
                return
            except Exception as e:
                print(f"Attempt {attempt + 1} failed to connect to Tool Hub: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                else:
                    print("Max retries reached. Tools will be unavailable until connection is established.")

    async def _establish_mcp_connection(self, hub_url: str):
        """Creates the connection and FastMCPClient."""
        if self.mcp_client:
            try:
                await self.stop()
            except Exception:
                pass
        
        self.mcp_client = FastMCPClient(hub_url)
        await self.mcp_client.__aenter__()

    async def _execute_mcp_tool_with_retry(self, mcp_tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Executes an MCP tool, retrying the connection if it fails."""
        arguments["__user_id"] = user_id_var.get()
        max_retries = 2
        for attempt in range(max_retries):
            try:
                if not self.mcp_client:
                    hub_url = identity_mgr.get_config("HUB_URL", DEFAULT_HUB_URL)
                    await self._establish_mcp_connection(hub_url)
                result = await self.mcp_client.call_tool(mcp_tool_name, arguments)
                return result.content
            except Exception as e:
                print(f"MCP Tool error on attempt {attempt + 1}: {e}")
                self.mcp_client = None # Force reconnect
                if attempt == max_retries - 1:
                    raise Exception(f"Failed to execute MCP tool '{mcp_tool_name}' after {max_retries} attempts: {e}")

    async def _execute_external_mcp_tool(self, mcp_name: str, tool_name: str, arguments: Dict[str, Any]) -> Any:
        user_id = user_id_var.get()
        if not user_id:
            raise Exception("No user_id found in context")

        # 1. Fetch user secrets
        user_secrets = await asyncio.to_thread(identity_mgr.get_user_secrets, user_id)
        
        # 2. Get MCP config
        config_data = await asyncio.to_thread(identity_mgr.get_mcp_config, mcp_name)
        if not config_data:
            raise Exception(f"MCP config '{mcp_name}' not found")
            
        from core.models import MCPConfig
        from fastmcp.client import StdioTransport, SSETransport
        config = MCPConfig(**config_data)

        pool_key = (user_id, mcp_name)
        
        # 3. Check connection pool
        client = None
        async with self._lock:
            client = self._user_mcp_pools.get(pool_key)
            if not client:
                transport = None
                
                env = _inject_secrets(config.env, config.secrets, user_secrets)
                        
                if config.transport == "stdio":
                    if not config.command:
                        raise Exception(f"MCP '{mcp_name}' stdio missing command")
                    
                    # Merge with os.environ so PATH etc is available
                    full_env = os.environ.copy()
                    full_env.update(env)

                    transport = StdioTransport(
                        command=config.command,
                        args=config.args or [],
                        env=full_env,
                        keep_alive=True  # Important: keep alive for pooling
                    )
                elif config.transport == "sse":
                    if not config.command:
                        raise Exception(f"MCP '{mcp_name}' sse missing url")
                    transport = SSETransport(url=config.command, headers=env)
                else:
                    raise Exception(f"Unknown transport {config.transport}")
                    
                client = FastMCPClient(transport)
                await client.__aenter__()
                self._user_mcp_pools[pool_key] = client

        # 4. Execute tool
        try:
            result = await client.call_tool(tool_name, arguments)
            return result.content
        except Exception as e:
            print(f"External MCP Tool error: {e}")
            async with self._lock:
                if pool_key in self._user_mcp_pools:
                    try:
                        await self._user_mcp_pools[pool_key].__aexit__(None, None, None)
                    except Exception:
                        pass
                    del self._user_mcp_pools[pool_key]
            raise Exception(f"Failed to execute external MCP tool '{tool_name}': {e}")

    def _register_external_mcp_tool(self, agent: Agent, mcp_name: str, mcp_tool: Any):
        """Helper to register an external MCP tool to a PydanticAI agent."""
        import copy
        
        safe_mcp_tool = mcp_tool
        if hasattr(mcp_tool, "inputSchema") and isinstance(mcp_tool.inputSchema, dict):
            if hasattr(mcp_tool, "model_copy"):
                safe_mcp_tool = mcp_tool.model_copy(deep=True)
            else:
                safe_mcp_tool = copy.copy(mcp_tool)
                safe_mcp_tool.inputSchema = copy.deepcopy(mcp_tool.inputSchema)
        
        async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
            # Check tool health before execution
            status = health_monitor.get_status("tool", safe_mcp_tool.name)
            if status.get("status") == "Offline":
                return f"SYSTEM: This tool is currently offline due to technical failures. Inform the user you cannot perform this action right now."

            return await self._execute_external_mcp_tool(mcp_name, safe_mcp_tool.name, kwargs)

        agent.tool(name=safe_mcp_tool.name, description=safe_mcp_tool.description)(tool_wrapper)

    def _register_mcp_tool(self, agent: Agent, mcp_tool: Any):
        """Helper to register an MCP tool to a PydanticAI agent."""
        import copy
        
        # Strip __user_id from the schema to prevent context waste and hallucinations
        # Create a deep copy to avoid modifying the shared original schema
        safe_mcp_tool = mcp_tool
        if hasattr(mcp_tool, "inputSchema") and isinstance(mcp_tool.inputSchema, dict):
            if hasattr(mcp_tool, "model_copy"):
                safe_mcp_tool = mcp_tool.model_copy(deep=True)
            else:
                safe_mcp_tool = copy.copy(mcp_tool)
                safe_mcp_tool.inputSchema = copy.deepcopy(mcp_tool.inputSchema)
                
            props = safe_mcp_tool.inputSchema.get("properties", {})
            if "__user_id" in props:
                del props["__user_id"]
            reqs = safe_mcp_tool.inputSchema.get("required", [])
            if "__user_id" in reqs:
                reqs.remove("__user_id")
        
        # Define a wrapper that calls the MCP tool
        async def tool_wrapper(ctx: RunContext[None], **kwargs: Any) -> Any:
            # Check tool health before execution
            status = health_monitor.get_status("tool", safe_mcp_tool.name)
            if status.get("status") == "Offline":
                return f"SYSTEM: This tool is currently offline due to technical failures. Inform the user you cannot perform this action right now."

            return await self._execute_mcp_tool_with_retry(safe_mcp_tool.name, kwargs)

        # Register with PydanticAI
        agent.tool(name=safe_mcp_tool.name, description=safe_mcp_tool.description)(tool_wrapper)

    async def inject_a2a_tools(self):
        """Injects call_{other_agent} tools based on a2a_access configuration and globally for supervisor."""
        
        async with self._lock:
            agent_names = list(self.agents.keys())
            # Supervisor gets access to ALL agents
            if "supervisor" in self.agents:
                supervisor = self.agents["supervisor"]
                for target_name in agent_names:
                    if target_name != "supervisor":
                        self._register_a2a_tool(supervisor, target_name)
                        
            # Other agents get a2a according to their config
            for name, config in self.configs.items():
                if name not in self.agents or name == "supervisor":
                    continue
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
            return result.output

        tool_name = f"call_{target_agent_name}"
        description = f"Call the {target_agent_name} agent with a prompt and get a response."
        agent.tool(name=tool_name, description=description)(a2a_tool_wrapper)

    async def stop(self):
        if self.mcp_client:
            await self.mcp_client.__aexit__(None, None, None)
            self.mcp_client = None
            
        async with self._lock:
            for pool_key, client in list(self._user_mcp_pools.items()):
                try:
                    await client.__aexit__(None, None, None)
                except Exception:
                    pass
            self._user_mcp_pools.clear()

manager = AgentManager()

@app.on_event("startup")
async def startup_event():
    await manager.start()

@app.on_event("shutdown")
async def shutdown_event():
    await manager.stop()

@app.on_event("startup")
async def log_startup():
    print("FastAPI startup event triggered.")

@app.get("/health")
async def health():
    disabled = identity_mgr.get_disabled_agents()
    agents_status = {}
    
    for agent_name, agent_config in manager.configs.items():
        if agent_name == "supervisor" or agent_name in disabled:
            continue
            
        offline_tools = []
        for tool_name in agent_config.allowed_tools:
            tool_status = health_monitor.get_status("tool", tool_name)
            if tool_status.get("status") == "Offline":
                offline_tools.append(tool_name)
                
        agent_global_status = health_monitor.get_status("agent", agent_name)
        if agent_global_status.get("status") == "Offline":
            status_str = "Offline"
        elif offline_tools:
            status_str = "Degraded"
        else:
            status_str = "Online"
            
        agents_status[agent_name] = {
            "status": status_str,
            "offline_tools": offline_tools,
            "agent_error": agent_global_status.get("last_error")
        }

    return {
        "status": "healthy",
        "agents": agents_status,
        "agents_disabled": disabled,
        "hub_connected": manager.mcp_client is not None,
        "hub_url": identity_mgr.get_config("HUB_URL", DEFAULT_HUB_URL)
    }

@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    if not request.messages:
        raise HTTPException(status_code=400, detail="Messages array cannot be empty")

    if request.messages[-1].role != "user":
        raise HTTPException(status_code=400, detail="The last message must be from the 'user' role")

    if request.model not in manager.agents:
        raise HTTPException(status_code=404, detail=f"Agent '{request.model}' not found or disabled")
        
    if manager.configs[request.model].type == "background":
        raise HTTPException(status_code=403, detail=f"Agent '{request.model}' is a background agent and cannot be called directly via Chat API.")
    
    # Check if agent is Offline
    agent_status = health_monitor.get_status("agent", request.model)
    if agent_status.get("status") == "Offline":
        raise HTTPException(status_code=503, detail=f"Agent '{request.model}' is currently offline due to failures.")

    agent = manager.agents[request.model]
    
    # Map OpenAI-style messages to PydanticAI message history
    history = []
    for msg in request.messages[:-1]:
        if msg.role == "user":
            history.append(ModelRequest(parts=[UserPromptPart(content=msg.content)]))
        elif msg.role == "assistant":
            history.append(ModelResponse(parts=[TextPart(content=msg.content)]))
        elif msg.role == "system":
            # Silently convert system prompts to user context to prevent overriding agent skills
            system_content = f"[System Note]: {msg.content}"
            history.append(ModelRequest(parts=[UserPromptPart(content=system_content)]))
    
    prompt = request.messages[-1].content
    
    try:
        result = await agent.run(prompt, message_history=history)
        health_monitor.record_event("agent", request.model, is_success=True)
        
        # Record usage in background
        user_id = user_id_var.get()
        if user_id and hasattr(result, 'usage'):
            usage = result.usage()
            if usage:
                async def safe_record_usage(uid, req_tok, res_tok):
                    try:
                        await asyncio.to_thread(identity_mgr.record_usage, uid, req_tok, res_tok)
                    except Exception as e:
                        print(f"Failed to record token usage for {uid}: {e}")
                        
                task = asyncio.create_task(
                    safe_record_usage(
                        user_id,
                        usage.request_tokens or 0,
                        usage.response_tokens or 0
                    )
                )
                background_tasks.add(task)
                task.add_done_callback(background_tasks.discard)

        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": result.output
                    }
                }
            ]
        }
    except Exception as e:
        health_monitor.record_event("agent", request.model, is_success=False, error_details=str(e))
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
