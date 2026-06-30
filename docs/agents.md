# Agents: Consuming & Building

Agents are the core compute units of Trellis. Each agent combines an LLM model with a system prompt and a set of tools to create a specialized AI assistant.

---

## Consuming Agents

### Via REST API (OpenAI-compatible)

The Universal Agent Host (`core/host.py`, port 8000) exposes an OpenAI-compatible chat completions endpoint. Specify the agent by name in the `model` field. Omitting `model` (or passing `"auto"`) routes the request through the supervisor, which picks the best agent automatically.

```bash
# Target a specific agent
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "model": "troubleshooting-agent",
    "messages": [{"role": "user", "content": "Check status of tenant acme-corp"}]
  }'

# Let the framework auto-route (model defaults to "auto")
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "model": "auto",
    "messages": [{"role": "user", "content": "Check status of tenant acme-corp"}]
  }'
```

**Auth**: Bearer token required. Generate API keys in the Dashboard UI under **API Keys**. Disable auth with `DEV_MODE=true` for local development only.

**Streaming**: Add `"stream": true` to the request body to receive SSE-streamed tokens.

### Via MCP Gateway

The Gateway MCP (`core/gateway.py`, port 8002) exposes your entire agent fleet as MCP tools, compatible with any MCP client (Claude Desktop, Claude Code, etc.).

```bash
# Connect Claude Code to the framework
claude mcp add --transport http trellis http://localhost:8002/mcp \
  --header "Authorization: Bearer YOUR_API_KEY"
```

The gateway exposes two tools (it does **not** create one tool per agent, so it scales to large fleets):

- **`search_agents(query, limit)`** — semantic search over the fleet; returns a ranked shortlist of relevant agents (`name`, `description`). Use this to discover who can handle a task.
- **`use_agent(agent_name, prompt)`** — run a specific agent.

Typical flow: call `search_agents` to find the right agent, then `use_agent` to run it. To let the framework decide, call `use_agent("supervisor", prompt)` — the supervisor searches the fleet and delegates to the best-matching agent(s).

### Listing Available Agents

```bash
curl http://localhost:8000/agents \
  -H "Authorization: Bearer YOUR_API_KEY"
```

Or view all agents in the Dashboard UI at **http://localhost:8080**.

---

## Building Agents

### Directory Structure

Each agent lives in its own subdirectory under `workspace/agents/`:

```text
workspace/agents/
└── my-agent/
    ├── config.yaml    # Identity, model, tool access
    └── skills.md      # System prompt and behavioral instructions
```

Both files are required. After creating them, restart the containers (`docker compose up -d --build`) to register the agent.

---

### `config.yaml` — All Fields

```yaml
name: my-agent                    # Required. Unique snake-case identifier. Used in API routing.
version: 0.1.0                    # Required. Semantic version string.
author: user@example.com          # Required. Creator email or name.
description: "Does X and Y."      # Required. Shown in the UI. LLM uses this for routing decisions.
model: gemini-3-flash-preview     # Required. LLM model identifier (see supported models below).
thinking_level: medium            # Required. One of: none, low, medium, high.
allowed_tools:                    # Required. Tool names this agent may call. Use [] for no tools.
  - get_system_time
  - tl_issues_fetch
allowed_mcps:                     # Optional. External MCP server names to connect.
  - logs
a2a_access:                       # Optional. Other agent names this agent may delegate to.
  - troubleshooting-agent
tags:                             # Optional. Labels for UI filtering and discovery.
  - support
  - tickets
agent_memory: false               # Optional. Opt into per-agent persistent memory (Hindsight).
```

**`agent_memory`**: When `true`, the framework automatically recalls relevant context from
past interactions before each run and retains the exchange afterward — no skill-prompt or
tool changes required. This only takes effect if an admin has turned on the global
**Agent Memory** feature flag (Admin Dashboard → Feature Flags); otherwise it is a no-op.
Can also be toggled per-agent in the agent editor UI. The LLM/embedding model Hindsight
uses for extraction is configured via `HINDSIGHT_LLM_*` env vars (see `.env.example`),
independent of the agent's own `model`.

> ⚠️ **Scope:** Memory is keyed by agent name and **shared across all users** of that agent.
> The agent builds institutional knowledge over time, but one user's context can surface in
> another user's session. Do not enable it for agents handling user-private data unless that
> sharing is acceptable.

**`thinking_level`**: Controls reasoning depth and token cost. `none` is fastest; `high` enables deep chain-of-thought. Match to task complexity.

**`allowed_tools`**: Must exactly match the `name` field in each tool's `tool.yaml`. The hub exposes only listed tools to this agent.

**`allowed_mcps`**: Must exactly match the `name` in each `mcp.yaml`. All tools from that MCP server become available to the agent. Tool names are prefixed `mcp__{mcp_name}__{tool_name}` internally.

**`a2a_access`**: Enables Agent-to-Agent delegation. The agent can call listed agents as sub-tasks (as if calling a tool). Keep this list small and intentional — the supervisor does not use `a2a_access`; it discovers and delegates dynamically via `search_agents` + `delegate`.

**Supported models** (examples):
- `gemini-3-flash-preview` — fast, cost-efficient
- `gemini-3.1-pro-preview` — more capable reasoning
- `claude-sonnet-4-6` — Anthropic Sonnet
- `claude-opus-4-8` — Anthropic Opus

---

### `skills.md` — Writing Effective System Prompts

The `skills.md` file is passed directly to the LLM as the system prompt. It defines the agent's role, behavior, tool usage guidance, and constraints.

**Recommended structure:**

```markdown
# My Agent

You are a [role] responsible for [primary objective].

## Tools

### `tool_name`
Use this tool when [condition]. Always pass [required fields].

## Output Format

[Describe expected response structure — JSON, Markdown tables, bullet lists, etc.]

## Constraints

- Do not [forbidden action 1].
- Do not [forbidden action 2].
- If you cannot complete a task, say so clearly rather than guessing.
```

**Best practices:**
1. **Be specific about tool usage** — explain *when* to call each tool, not just that it exists.
2. **Provide output templates** — LLMs follow formatting examples more reliably than prose descriptions.
3. **Set hard constraints** — prevents hallucination of data (e.g., "Do not invent Issues ticket IDs").
4. **Keep it focused** — one agent, one responsibility. Narrow scope = better accuracy.

---

### Sync to Registry

After creating or editing agent files, push changes to etcd:

```bash
docker compose up -d --build
```

Confirm the output shows your agent:
```
Saved config for agent: my-agent
Saved skills for agent: my-agent
```

Changes take effect on the next request — the host watches etcd for config changes and evicts the cached agent instance automatically, so no restart is needed.
