# Agents: Consuming & Building

Agents are the core compute units of Trellis. Each agent combines an LLM model with a system prompt and a set of tools to create a specialized AI assistant.

---

## Consuming Agents

### Via REST API (OpenAI-compatible)

The Universal Agent Host (`core/host.py`, port 8000) exposes an OpenAI-compatible chat completions endpoint. Specify the agent by name in the `model` field.

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "model": "troubleshooting-agent",
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

Each agent becomes an MCP tool named after it. The **supervisor** agent is a special meta-agent that can inspect the fleet and route to any other agent.

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

Both files are required. After creating them, run `python scripts/sync_to_db.py` to register the agent.

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
```

**`thinking_level`**: Controls reasoning depth and token cost. `none` is fastest; `high` enables deep chain-of-thought. Match to task complexity.

**`allowed_tools`**: Must exactly match the `name` field in each tool's `tool.yaml`. The hub exposes only listed tools to this agent.

**`allowed_mcps`**: Must exactly match the `name` in each `mcp.yaml`. All tools from that MCP server become available to the agent. Tool names are prefixed `mcp__{mcp_name}__{tool_name}` internally.

**`a2a_access`**: Enables Agent-to-Agent delegation. The agent can call listed agents as sub-tasks (as if calling a tool). The supervisor agent has access to all agents by default.

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
python scripts/sync_to_db.py
```

Confirm the output shows your agent:
```
Saved config for agent: my-agent
Saved skills for agent: my-agent
```

Changes take effect immediately on the next request — the host reloads from etcd per request, so no restart is needed.
