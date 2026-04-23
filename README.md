# trellis-agent-platform v2

A simplified, filesystem-driven multi-agent framework built with FastAPI, PydanticAI, and the Model Context Protocol (MCP).

## Architecture Overview

The V2 architecture follows a "Filesystem-as-Source-of-Truth" model, removing the need for a database and complex control plane.

- **Universal Agent Host (`core/host.py`)**: FastAPI application that manages agents and provides an OpenAI-compatible gateway.
- **Polyglot Tool Hub (`core/hub.py`)**: Internal MCP server that dynamically discovers and executes tools in Python, TypeScript, or Go via `tool.yaml`. Communicates with the Host over HTTP (SSE Transport).
- **Gateway MCP (`core/gateway.py`)**: External bridge allowing MCP clients (like Claude Desktop or MCP Inspector) to interact with the entire agent fleet.
- **Agents**: Defined in `/agents` with `skills.md` and `config.yaml`.
- **Tools**: Defined in `/tools` with a `tool.yaml` and a runtime script.

## Quick Start

### 1. Prerequisites
- Docker and Docker Compose
- Gemini API Key (set as `GEMINI_API_KEY` in environment)

### 2. Run with Docker
```bash
docker-compose up --build
```
This starts the Host (8000), standalone Hub, and Gateway services.

### 3. Usage
Send a request to the Host's chat completions endpoint:
```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "supervisor",
    "messages": [{"role": "user", "content": "Say hello using the echo tool"}]
  }'
```

### 4. Connecting via MCP
To use the entire agent fleet from an MCP client (like Claude Desktop), use the following command:
```bash
claude mcp add --transport http trellis http://localhost:8002/mcp --header "Authorization: Bearer YOUR_API_KEY"
```

## Directory Structure
- `core/`: Framework logic (Host, Hub, Gateway, Models).
- `agents/`: Directory-based agent definitions.
- `tools/`: Polyglot tool definitions.
- `__spec_docs/`: Architectural specifications.
- `docker-compose.yml`: Simplified service orchestration.
- `requirements.txt`: Minimal dependencies.

## License
MIT
