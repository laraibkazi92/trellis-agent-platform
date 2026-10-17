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

**Streaming**: Add `"stream": true` to the request body to receive newline-delimited JSON (NDJSON) progress events: `{"status": "processing"}` heartbeat lines (at least one every 5 s), `{"status": "tool_call", "tool": "<name>"}` whenever the agent calls a tool, and a final line with either the full response (`{"choices": [{"message": {"role": "assistant", "content": "..."}}]}`) or `{"error": "..."}`. The response text arrives in one piece at the end — individual tokens are not streamed.

### Via MCP Gateway

The Gateway MCP (`core/gateway.py`, port 8002) exposes your entire agent fleet as MCP tools, compatible with any MCP client (Claude Desktop, Claude Code, etc.).

```bash
# Connect Claude Code to the framework
claude mcp add --transport http trellis http://localhost:8002/mcp \
  --header "Authorization: Bearer YOUR_API_KEY"
```

The gateway exposes four tools (it does **not** create one tool per agent, so it scales to large fleets):

- **`search_agents(query, limit)`** — semantic search over the fleet; returns a ranked shortlist of relevant agents (`name`, `description`, `configured`). Use this to discover who can handle a task.
- **`use_agent(agent_name, prompt)`** — run a specific agent.
- **`search_tools(query, limit)`** — ranked search over deterministic tools exposed for direct execution; returns Tool Cards (`name`, `description`, `parameters`, `configured`, `status`, `source`).
- **`use_tool(tool_name, arguments)`** — execute one of those tools directly and return its raw structured output, bypassing any agent hop.

Typical flow: call `search_agents` to find the right agent, then `use_agent` to run it. To let the framework decide, call `use_agent("supervisor", prompt)` — the supervisor searches the fleet and delegates to the best-matching agent(s). For a single deterministic operation (a CLI lookup, a status check), `search_tools` + `use_tool` skips the agent entirely; tools opt in via `public: true` in their `tool.yaml` (see the [Tools guide](tools.md)).

### Listing Available Agents

There is no agent-listing REST endpoint on the host. Use either:

- The **Dashboard UI** at http://localhost:8080 (**Agents** page), or
- The Gateway MCP's `search_agents` tool, which returns each agent's `name`, `description`, and `configured` flag.

The host's `GET /health` endpoint also reports the operational status of every routable agent.

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
type: user_agent                  # Optional. Defaults to user_agent here; background_agent /
                                  #   background_script configs belong in workspace/workflows/.
model: gemini-3-flash-preview     # Optional. LLM model identifier. Blank (with a blank
                                  #   provider) inherits the framework default; a blank model
                                  #   on a configured provider resolves to that provider's
                                  #   registry default. See "Framework LLM defaults" below.
thinking_level: medium            # Required. One of: none, low, medium, high, n/a (n/a behaves
                                  #   like none; the dashboard editors apply it automatically for
                                  #   models without thinking support).
provider: google                  # Optional. One of the 15 provider ids in the table
                                  #   below. Blank (with a blank model) inherits the framework
                                  #   default. Omitted/empty infers from the model name
                                  #   prefix (gemini* → google, claude* → anthropic,
                                  #   gpt-*/o1*/o3*/o4*/chatgpt* → openai, deepseek* →
                                  #   deepseek, kimi* → moonshotai, glm* → zai, qwen* →
                                  #   alibaba); anything else fails at build time with a
                                  #   config error. Vendor-prefixed ids (containing "/")
                                  #   always require an explicit provider.
base_url: http://localhost:11434/v1  # Optional. Custom API endpoint. Required for
                                  #   openai-compatible; rejected by providers that do
                                  #   not accept an endpoint.
external: true                    # Optional (default true). Set false to hide this agent from
                                  #   the gateway, semantic search, and auto-routing (internal-only
                                  #   worker subagent).
internal: true                    # Optional (default true). Set false to bar other agents from
                                  #   delegating to it via a2a_access.
allowed_tools:                    # Required. Tool names this agent may call. Use [] for no tools.
  - get_system_time
  - fetch_issues
allowed_mcps:                     # Optional. External MCP server names to connect.
  - logs
a2a_access:                       # Optional. Other agent names this agent may delegate to.
  - troubleshooting-agent
tags:                             # Optional. Labels for UI filtering and discovery.
  - support
  - tickets
agent_memory: false               # Optional. Opt into per-agent persistent memory (Hindsight).
rules:                            # Optional. Deterministic routing rules — see rules_engine.md.
  - use_when:
      - "User asks about X"
    do_not_use_when:
      - "User asks about Y"
```

**`agent_memory`**: When `true`, the framework automatically recalls relevant context from
past interactions before each run and retains the exchange afterward — no skill-prompt or
tool changes required. This only takes effect if an admin has turned on the global
**Agent Memory** feature flag (Admin Dashboard → Feature Flags); otherwise it is a no-op.
Can also be toggled per-agent in the agent editor UI. The LLM/embedding model Hindsight
uses for extraction is configured via `HINDSIGHT_LLM_*` env vars (see `.env.example`),
independent of the agent's own `model`.

> ⚠️ **Scope:** Memory is keyed by agent name and **shared across all users** of that agent by default.
> The agent builds institutional knowledge over time, but one user's context can surface in
> another user's session. An admin can flip the **Per-User Memory Isolation** flag
> (Admin Dashboard → Feature Flags) to key banks as `agent:userid` instead — each user then
> gets a fresh private bank, and background/workflow runs key by their workflow identity
> (e.g. `agent:svc_agent_<name>`, `agent:webhook`), never into any user's bank. Existing
> shared banks are **not** migrated. Do not enable memory for agents handling user-private
> data unless isolation is on or that sharing is acceptable.

**`thinking_level`**: Controls reasoning depth and token cost. `none` is fastest; `high` enables deep chain-of-thought. Match to task complexity.

**`provider` / `base_url`**: Which LLM vendor serves `model`. Provider credentials are configured in **Admin → LLM Providers** — one card per provider, stored Fernet-encrypted in etcd, never read from the environment. Fifteen providers are selectable:

| `provider` | Label | Key name(s) | Keyless | Base URL | `thinking_level` |
| --- | --- | --- | --- | --- | --- |
| `google` | Google (Gemini) | `GEMINI_API_KEY`, `GOOGLE_API_KEY` | — | optional | Gemini budgets / levels |
| `openai` | OpenAI | `OPENAI_API_KEY` | — | optional | reasoning effort |
| `anthropic` | Anthropic | `ANTHROPIC_API_KEY` | — | optional | reasoning effort |
| `deepseek` | DeepSeek | `DEEPSEEK_API_KEY` | — | not supported | — |
| `fireworks` | Fireworks AI | `FIREWORKS_API_KEY` | — | not supported | — |
| `together` | Together AI | `TOGETHER_API_KEY` | — | not supported | — |
| `moonshotai` | Moonshot AI (Kimi) | `MOONSHOTAI_API_KEY` | — | not supported | — |
| `vercel` | Vercel AI Gateway | `VERCEL_AI_GATEWAY_API_KEY` | — | not supported | reasoning effort |
| `zai` | Z.AI (GLM) | `ZAI_API_KEY` | — | not supported | — |
| `openrouter` | OpenRouter | `OPENROUTER_API_KEY` | — | not supported | — |
| `alibaba` | Alibaba (DashScope/Qwen) | `DASHSCOPE_API_KEY`, `ALIBABA_API_KEY` | — | optional | — |
| `ollama` | Ollama (local) | — | ✅ | optional (defaults to `http://localhost:11434`) | — |
| `litellm` | LiteLLM | `LITELLM_API_KEY` (optional) | ✅ | optional (defaults to `http://localhost:4000`) | — |
| `huggingface` | Hugging Face | `HF_TOKEN` | — | not supported | — |
| `openai-compatible` | OpenAI-compatible endpoint | `OPENAI_COMPATIBLE_API_KEY`, `OPENAI_API_KEY` (optional) | ✅ | **required** | — |

Notes:

- `provider` is optional: when unset, it is inferred from the model prefix (`gemini`, `claude`, `gpt-`/`o1`/`o3`/`o4`/`chatgpt`, `deepseek`, `kimi`, `glm`, `qwen`). Vendor-prefixed model ids (anything containing `/`, e.g. `openai/gpt-5`) are always ambiguous and require an explicit provider.
- `openai` runs through the chat-completions API (`openai-chat`), not the Responses API.
- `openai-compatible` points `base_url` at any OpenAI-compatible endpoint (vLLM, LiteLLM, Ollama's `/v1`, …) and is the only provider that **requires** one.
- `ollama` is keyless and local; its endpoint defaults to `http://localhost:11434` and is always passed explicitly. It can be set per agent or globally on the LLM Providers page (`OLLAMA_BASE_URL`).
- `openrouter` model ids must be vendor-prefixed (e.g. `openai/gpt-5`); unprefixed ids are rejected.
- `litellm` routes to sub-providers (`openai/…`, `anthropic/…`) whose own keys LiteLLM resolves from its own environment — the documented exception to the "keys live in etcd, not the env" rule. `LITELLM_API_KEY` itself is the gateway credential and is optional. With no endpoint set it defaults to `http://localhost:4000`, so set `base_url` when your LiteLLM proxy lives elsewhere (e.g. another container — `localhost` is only reachable inside the same network namespace).
- `thinking_level` maps per provider: Gemini uses token budgets or thinking levels, Anthropic maps to `anthropic_effort`, `openai` and `vercel` map to `openai_reasoning_effort`; every other provider takes no reasoning setting and runs with the model's own defaults.

Both fields can also be set in the admin agent editor.

**`allowed_tools`**: Must exactly match the `name` field in each tool's `tool.yaml`. The hub exposes only listed tools to this agent. Built-in console tools (`ls`, `read_file`, `write_file`, `edit_file`, `glob`, `grep`, `execute`) can also be listed. Long-lived background shells (`run_in_background`, `read_output`, `kill_shell`, `list_shells`) are **not** available: their spawn path cannot be env-sanitized, so they are disabled to keep the host's bootstrap secrets out of agent-run commands.

**`allowed_mcps`**: Must exactly match the `name` in each `mcp.yaml`. All tools from that MCP server become available to the agent. Tool names are prefixed `mcp__{mcp_name}__{tool_name}` internally.

**`a2a_access`**: Enables Agent-to-Agent delegation. The agent can call listed agents as sub-tasks (as if calling a tool). Targets must be `internal: true` (the default) — delegation to agents marked `internal: false` is skipped at build time with a warning. Keep this list small and intentional — the supervisor does not use `a2a_access`; it discovers and delegates dynamically via `search_agents` + `delegate`.

**`rules`**: Optional declarative routing rules evaluated before semantic search — lock matching queries onto this agent deterministically. See the [Rules Engine guide](rules_engine.md) for the full field reference and authoring guidance.

---

### Framework LLM defaults

An admin can set **one org-wide default provider + model** (and an optional `base_url`) in
**Admin → LLM Providers → Framework defaults**. An agent — or a background workflow — that
leaves **both `provider` and `model` blank** inherits that pair instead of failing.

The default is applied at build time and is **never written into your YAML**. The agent editor
shows a read-only hint under the model field while the model is blank — `Inherits framework
default: <Provider> / <model>` when the framework default applies, or `Uses <Provider> default:
<model>` when a pinned provider falls back to its own registry default — and nothing is
prefilled, so "inherit" survives every edit and the agent keeps tracking the org default as it
changes.

Resolution priority, highest first:

| Case | `provider` | `model` | Effective provider | Effective model | Effective `base_url` |
| --- | --- | --- | --- | --- | --- |
| A — explicit | set | set | as configured | as configured | as configured |
| B — provider only | set | blank | as configured | the framework model **when the framework provider matches**, otherwise the provider's registry default | the framework `base_url` when the framework provider matches, otherwise as configured |
| C — model only | blank | set | inferred from the model name (fails if unknown or ambiguous) | as configured | as configured |
| D — both blank | blank | blank | framework default provider | framework default model | the agent's `base_url`, else the framework default's (dropped if the provider takes none) |
| E — legacy fallback | blank | blank, framework default unset or invalid | `google` | `gemini-2.5-flash` | as configured |

Notes:

- **Case B inherits the framework `base_url` only when the framework provider is the same
  provider.** A different provider inherits just the registry default model — never the org's
  endpoint, which would otherwise point one vendor's key at another vendor's gateway.
- **Every provider has a registry default model** (e.g. `deepseek` → `deepseek-chat`,
  `openai` → `gpt-5-mini`), so `provider` set + `model` blank is a valid configuration.
- **To opt out of inheritance, set both `provider` and `model`.** A fully-specified pair is
  used verbatim and never consults the framework default.
- **`openai-compatible` is the exception:** it has no registry default, so it always needs an
  explicit `model` *and* an explicit `base_url`. Its config validator rejects a pinned
  `openai-compatible` provider with no `base_url` before resolution runs, so case B cannot apply
  to it — to inherit an org-wide endpoint, leave `provider` blank as well (case D).

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
3. **Set hard constraints** — prevents hallucination of data (e.g., "Do not invent issue IDs").
4. **Keep it focused** — one agent, one responsibility. Narrow scope = better accuracy.

---

### Sync to Registry

After creating or editing agent files, push changes to etcd:

```bash
docker compose up -d --build
```

Confirm the output shows your agent:
```
Saved config for agent: my-agent (Type: user_agent)
Saved skills for agent: my-agent
```

Changes take effect on the next request — the host watches etcd for config changes and evicts the cached agent instance automatically, so no restart is needed.
