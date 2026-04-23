# trellis-agent-platform: LLM Agent Context & Dev Guide

## 🏗 Architecture & Stack
- **Stack**: Python 3.12, FastAPI, PydanticAI (LLM routing), FastMCP (Tooling), etcd3 (State/Registry).
- **`core/host.py`** (Port 8000): Universal Agent Host. FastAPI + PydanticAI. Orchestrates LLM agents.
- **`core/hub.py`** (Port 8001): Polyglot Tool Hub. FastMCP server executing local tools (Python, Go, TS).
- **`core/gateway.py`** (Port 8002): External MCP Gateway. Exposes agents to external MCP clients.
- **`core/ui.py`** (Port 8080): Dashboard UI.
- **`etcd`** (Port 2379): Central registry for users, API keys, agent configs, and framework state.

## 📂 Key Directories
- `core/`: Service implementations, routers, and auth (`core/auth.py` -> `IdentityManager`).
- `agents/`: Agent definitions (each requires `config.yaml` and `skills.md`).
- `tools/`: Polyglot scripts mapped to internal MCP tools.

## 💻 Development Workflow
- **Start/Rebuild**: `docker compose up -d --build`
- **Logs**: `docker compose logs -f [host|hub|gateway|ui]`
- **DB/Config access**: Use `IdentityManager` in `core/auth.py` for all etcd operations (has built-in retries).

## ⚠️ Critical Gotchas & Rules
- **FastMCP API**: `FastMCP()` constructor no longer accepts `host` or `port`. Pass them to the ASGI server (e.g., `uvicorn.run(...)`) or `run_http_async()`.
- **Auth**: Endpoints under `/v1/chat/completions`, `/sse`, `/messages`, `/mcp` require Bearer tokens unless `DEV_MODE=true` is set.
