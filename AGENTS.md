# Trellis: LLM Agent Context & Dev Guide

## 🏗 Architecture & Stack
- **Stack**: Python 3.12, FastAPI, PydanticAI (LLM routing), FastMCP (Tooling), etcd3 (State/Registry).
- **`core/host.py`** (Port 8000): Universal Agent Host. FastAPI + PydanticAI. Orchestrates LLM agents.
- **`core/hub.py`** (Port 8001): Polyglot Tool Hub. FastMCP server executing local tools (Python, Go, TS).
- **`core/gateway.py`** (Port 8002): External MCP Gateway. Exposes agents to external MCP clients via the `/mcp` endpoint.
- **`core/ui.py`** (Port 8080): Dashboard UI.
- **`etcd`** (Port 2379): Central registry for users, API keys, agent configs, and framework state.


## 🤖 Agent Types
- **`user_agent`**: Interactive, user-facing agents that engage in conversational workflows.
- **`background_agent`**: Autonomous agents that run asynchronously (e.g., triggered by cron or webhooks) to perform background tasks.
- **`background_script`**: Lightweight, standalone scripts executing specific procedural tasks in the background.

## 📂 Key Directories
- `core/`: Service implementations, routers, and auth (`core/auth.py` -> `IdentityManager`).
- `agents/`: User-facing agent definitions (`user_agent`) (requires `config.yaml` and `skills.md`).
- `workspace/workflows/`: Background workflows containing `background_agent` and `background_script` definitions.
- `tools/`: Tool logic. Each directory requires a `tool.yaml` (list of tool objects) and entrypoint wrappers.
- `scripts/`: Operational utilities (e.g., `sync_to_db.py`).

## 💻 Development Workflow
- **Start/Rebuild**: `docker compose up -d --build`
- **Registry Sync**: Use `python scripts/sync_to_db.py` to push filesystem changes to `etcd`.
- **Scaling**: Use the `agent-builder` agent to scaffold new agents/tools from external sources.
- **DB/Config access**: Use `IdentityManager` in `core/auth.py` for all etcd operations.

## ⚠️ Critical Gotchas & Rules
- **Tool Protocol**: Tools MUST use `stdin` for JSON arguments and `stdout` for JSON results. Use wrappers for existing scripts.
- **Flat over Nested**: Tools should live as standalone scripts in their directory. Avoid `src/`, `main.py`, or complex package structures within a tool directory.
- **Shared Logic (Tool level)**: If logic must be shared across multiple scripts in a tool suite, use a simple `lib/` directory within that tool's folder.
- **Shared Logic (Workspace level)**: If logic must be shared across multiple completely separate tool suites (e.g. `tickets` and `issues-service`), extract it to `workspace/shared/` and dynamically insert the workspace root into `sys.path`.
- **Drop-in Ready**: A tool directory should be self-contained and movable with minimal changes.
- **Multi-Tool Support**: A single directory can host multiple tools; `tool.yaml` should be a list of configurations.
- **Logical Porting**: When porting external skills (e.g. from Claude Code), preserve all business logic/formatting but translate shell commands into framework tool calls.
- **Auth**: Endpoints under `/v1/chat/completions`, `/mcp`, `/sse`, and `/messages` require Bearer tokens unless `DEV_MODE=true` is set. Note that `/sse` and `/messages` are typically sub-paths of `/mcp`.

## 🎨 UI/UX & Frontend Design Patterns
- **Terminology**: 
  - `API Keys`: Inbound authentication tokens (accessing the framework).
  - `Tool Secrets`: Outbound credentials for 3rd-party integrations (e.g., Issues, Support).
- **Notifications**: Use auto-dismissible toasts for success/error flashes (see `templates/base.html` for the `setTimeout` pattern).
- **Navigation & Modals**: For deep-linking to specific items (like a tool details modal), use query parameters (e.g., `?tool=name`). Parse this on `DOMContentLoaded`, trigger the modal/filter, and use `window.history.replaceState` to strip the parameter to prevent loop issues on refresh.
- **Tooltips**: Avoid native browser `title` attributes. Use Tailwind CSS utility classes (e.g., `group`, `group-hover:block`, `absolute`) for clean, floating tooltips.
