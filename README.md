# Trellis: Agent Platform

A scalable, multi-agent orchestration framework built with FastAPI, PydanticAI, FastMCP, and etcd. It provides an OpenAI-compatible gateway, dynamic tool execution, and an external MCP gateway for seamless integration with clients like Claude Desktop.

## Architecture Overview

The framework relies on a microservice architecture with `etcd` acting as the central state and configuration registry:

- **Universal Agent Host (`core/host.py` - Port 8000)**: FastAPI application that orchestrates LLM agents via PydanticAI.
- **Polyglot Tool Hub (`core/hub.py` - Port 8001)**: FastMCP server that dynamically discovers and executes tools written in Python, TypeScript, or Go. Communicates with the Host over HTTP (SSE Transport).
- **Gateway MCP (`core/gateway.py` - Port 8002)**: External bridge allowing MCP clients to interact with the entire agent fleet via the `/mcp` endpoint.
- **Dashboard UI (`core/ui.py` - Port 8080)**: Web interface for managing Agents, Tools, API Keys, and Tool Secrets.
- **State Registry (`etcd` - Port 2379)**: Central database for users, authentication keys, agent configs, and tool secrets.

## Core Concepts & Terminology

- **Agents**: Defined in `workspace/agents/` with a `config.yaml` and specialized `skills.md`.
- **Tools**: Polyglot standalone scripts defined in `workspace/tools/` using `tool.yaml` configurations.
- **API Keys**: Inbound authentication tokens used to access the framework via API or MCP endpoints.
- **Tool Secrets**: Outbound, third-party credentials (e.g., Issues, Support, OpenAI) securely stored for use by Agents and Tools.

## Quick Start

### 1. Prerequisites
- Docker and Docker Compose
- LLM API Keys (e.g., `GEMINI_API_KEY`, `OPENAI_API_KEY`) set in your environment.

### 2. Run the Stack
Start the framework services (Host, Hub, Gateway, UI, and etcd) using Docker Compose:
```bash
docker compose up -d --build
```

### 3. Sync Filesystem to Registry
The framework uses etcd for state. When you modify or add new agents/tools on the filesystem, sync them to the database:
```bash
docker compose up -d --build
```

### 4. Dashboard UI
Navigate to **http://localhost:8080** to access the Dashboard UI. Here you can review active agents, tools, and configure your API Keys and Tool Secrets.

### 5. API Usage
All `/v1/` endpoints, `/mcp`, and `/sse` require `Bearer` token authentication (unless `DEV_MODE=true` is set).

```bash
# Target a specific agent
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "model": "troubleshooting-agent",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Auto-route — omit model or pass "auto" to let the supervisor pick
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "model": "auto",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### 6. Connecting via MCP
To expose the agent fleet to an external MCP client (like Claude Desktop), use:
```bash
# Example for Claude Desktop configuration
claude mcp add --transport http trellis http://localhost:8002/mcp --header "Authorization: Bearer YOUR_API_KEY"
```

## Directory Structure

- `core/`: Framework logic, auth, routers, and host/hub/gateway/ui services.
- `data/`: Persistent runtime data.
- `docs/`: Developer guides for agents, tools, workflows, and MCP.
- `gateway/`: Nginx gateway configuration.
- `scripts/`: Operational scripts like `sync_to_db.py`.
- `templates/`: HTML templates for the Dashboard UI.
- `tests/`: Test suite.
- `workspace/`: Agent, tool, and workflow content — `agents/`, `tools/`, `mcps/`, `workflows/`, and `shared/`.

## Development Workflow

1. Scaffold new agents/tools inside their respective directories. See [Building Agents](docs/agents.md) and [Building Tools](docs/tools.md).
2. Tools should use `stdin` for JSON arguments and `stdout` for JSON results. See [Building Tools](docs/tools.md).
3. Agents are defined with configurations and skills. See [Building Agents](docs/agents.md).
4. Run `docker compose up -d --build` to push changes to etcd.
5. Manage third-party credentials via the **Tool Secrets** UI.

## License

This project is licensed under the [Apache-2.0](LICENSE).
