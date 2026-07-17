# Trellis: LLM Agent Context & Dev Guide

## 🏗 Architecture & Stack
- **Stack**: Python 3.12, FastAPI, PydanticAI (LLM routing), FastMCP (Tooling), etcd-sdk-python (State/Registry).
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
- **Registry Sync**: The registry is synchronized automatically when you rebuild and start the containers via `docker compose up -d --build`. You do not need to run manual sync scripts.
- **DB/Config access**: Use `IdentityManager` in `core/auth.py` for all etcd operations.

## 📚 Developer Docs
Full guides for consuming and building each framework component:
- `docs/agents.md` — consuming agents via REST/MCP, building agent configs and skill prompts
- `docs/tools.md` — wiring tools to agents, building tools with the stdin/stdout protocol
- `docs/workflows.md` — triggering/monitoring workflows, building script and agent workflows
- `docs/mcp.md` — registering external MCP servers

## ⚠️ Critical Gotchas & Rules
- **Tool Protocol**: Tools MUST use `stdin` for JSON arguments and `stdout` for JSON results. Use wrappers for existing scripts.
- **Flat over Nested**: Tools should live as standalone scripts in their directory. Avoid `src/`, `main.py`, or complex package structures within a tool directory.
- **Shared Logic (Tool level)**: If logic must be shared across multiple scripts in a tool suite, use a simple `lib/` directory within that tool's folder.
- **Shared Logic (Workspace level)**: If logic must be shared across multiple completely separate tool suites (e.g. `tickets` and `issues-service`), extract it to `workspace/shared/` and dynamically insert the workspace root into `sys.path`.
- **Drop-in Ready**: A tool directory should be self-contained and movable with minimal changes.
- **Multi-Tool Support**: A single directory can host multiple tools; `tool.yaml` should be a list of configurations.
- **Logical Porting**: When porting external skills (e.g. from Claude Code), preserve all business logic/formatting but translate shell commands into framework tool calls.
- **Auth**: All `/v1/` endpoints, `/mcp`, `/sse`, and `/messages` require Bearer tokens unless `DEV_MODE=true` is set. Note that `/sse` and `/messages` are typically sub-paths of `/mcp`.
- **Agent Memory**: Backed by Hindsight (`core/memory.py`), wired at the framework level — recall via a dynamic instruction in `build_agent`, retain at the two `agent.run` sites (`host.py`, `tasks.py`). Banks are keyed by agent name (per-agent, shared across users). Gated by the admin `agent_memory_enabled` feature flag AND per-agent `agent_memory: true`. All ops are fail-open. Visibility: the `hindsight` container exposes the Control Plane web UI on **port 9999** (browse banks/memories/entity graphs by agent name); the API is on 8888. CLI: `hindsight configure --api-url http://localhost:8888` then `hindsight bank list`.

## 🎨 UI/UX & Frontend Design Patterns
- **Terminology**: 
  - `API Keys`: Inbound authentication tokens (accessing the framework).
  - `Tool Secrets`: Outbound credentials for 3rd-party integrations (e.g., Issues, Support).
- **Notifications**: Use auto-dismissible toasts for success/error flashes (see `templates/base.html` for the `setTimeout` pattern).
- **Navigation & Modals**: For deep-linking to specific items (like a tool details modal), use query parameters (e.g., `?tool=name`). Parse this on `DOMContentLoaded`, trigger the modal/filter, and use `window.history.replaceState` to strip the parameter to prevent loop issues on refresh.
- **Tooltips**: Avoid native browser `title` attributes. Use Tailwind CSS utility classes (e.g., `group`, `group-hover:block`, `absolute`) for clean, floating tooltips.

## Architecture Decisions: 3rd-Party Tool Authentication
Trellis intentionally uses **Personal Access Tokens (PATs)** and manually provided API keys (via `IdentityManager` Scoped Secret Injection) rather than implementing a centralized OAuth gateway (like `open-connector`) or a native OAuth2 flow. 

**Reasoning:**
1. **SDK Compatibility:** External gateways (like `open-connector`) often enforce routing all tool traffic through a local proxy to hide credentials. This breaks standard Python/TS SDKs (e.g., `octokit`, `slack-sdk`) used by Trellis standalone tools. Trellis injects raw tokens directly so developers can write standard, idiomatic code.
2. **Maintenance Overhead:** Implementing user-level OAuth natively requires registering and maintaining global Developer Applications (Client IDs & Secrets) for *every single SaaS provider* (GitHub, Slack, Issues, etc.). This introduces an unsustainable configuration burden.
3. **SSO Limitations:** While Trellis uses OIDC for user authentication (SSO), OIDC cannot broker API access tokens for 3rd-party APIs. 
4. **Simplicity:** The PAT model keeps the framework infrastructure lean. While it requires users to manually generate and provide their tokens initially, it guarantees that tools remain simple, stateless, and fully compatible with existing libraries. For organization-wide access without user friction, Trellis supports injecting global Service Account (Bot) tokens into the environment instead.
