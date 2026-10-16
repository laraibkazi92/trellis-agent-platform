<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="branding/trellis-logo/svg/trellis-horizontal-on-dark.svg">
    <img src="branding/trellis-logo/masters/trellis-horizontal.svg" alt="Trellis" width="460">
  </picture>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-123B2E" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/python-3.12-123B2E?logo=python&logoColor=white" alt="Python 3.12">
  <img src="https://img.shields.io/badge/docker--compose-123B2E?logo=docker&logoColor=white" alt="Docker Compose">
</p>

Trellis runs a fleet of LLM agents behind one OpenAI-compatible API. Each agent is a config file plus a skills prompt; tools are standalone scripts in Python, TypeScript, Go, or Bash, executed in a sandbox. Call agents over REST or from MCP clients like Claude Desktop. A dashboard manages users, API keys, and credentials; etcd holds all framework state.

## Who is this for?

- **Org operators** (deploy and host the framework) - start with [docs/deploy.md](docs/deploy.md).
- **Content authors** (build agents, tools, workflows, and MCP servers) - see [docs/agents.md](docs/agents.md), [docs/tools.md](docs/tools.md), [docs/workflows.md](docs/workflows.md), and [docs/mcp.md](docs/mcp.md).
- **Framework contributors** (work on the engine itself) - see [CONTRIBUTING.md](CONTRIBUTING.md).

## Architecture

| Service | Port | What it does |
| --- | --- | --- |
| Agent host (`core/host.py`) | 8000 | FastAPI + PydanticAI. Serves `/v1/chat/completions`, routes to agents, runs them. |
| Tool hub (`core/hub.py`) | 8001 | FastMCP server. Discovers tools in `workspace/tools/` and runs each in a bubblewrap sandbox. |
| MCP gateway (`core/gateway.py`) | 8002 | Exposes the agent fleet to external MCP clients at `/mcp`. |
| Dashboard UI (`core/ui.py`) | 8080 | Manage agents, tools, workflows, API keys, and tool secrets. |
| nginx gateway | 80/443 | Single front door for the stack, with optional TLS. |
| Infrastructure | internal | etcd (state registry), Redis with Taskiq (background jobs), Hindsight (agent memory). |

## Quick start

Docker is the only prerequisite. If you are deploying Trellis for an organization, follow [docs/deploy.md](docs/deploy.md) first — it covers pointing Trellis at your own content repo.

The fastest path is the prebuilt multi-arch image, published publicly on GHCR as `ghcr.io/laraibkazi92/trellis-agent-platform` (anonymous pulls — no login — once its GHCR package visibility is public):

```bash
cp .env.example .env    # set SESSION_SECRET
docker compose pull && docker compose up -d      # prebuilt image
# or: docker compose up -d --build               # build from source
```

Orgs pin the engine to a release tag — the first release is `v0.2.0` (set `TRELLIS_IMAGE` in `.env`) — while `main` tracks upstream development.

Every rebuild syncs `workspace/` into etcd, so new agents and tools go live on the next one. Configure your LLM provider keys in the Dashboard (**Admin → Global Tool Configuration**) — stored encrypted in etcd, they serve Google (Gemini), OpenAI, Anthropic, or any OpenAI-compatible endpoint. Then browse to http://localhost and create an API key, or set `DEV_MODE=true` in `.env` to run without authentication.

## Call an agent

```bash
curl -X POST http://localhost/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "model": "demo-assistant",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

Use `"model": "auto"` and a supervisor picks the agent that fits the request.

## Connect an MCP client

```bash
claude mcp add --transport http trellis http://localhost/mcp \
  --header "Authorization: Bearer YOUR_API_KEY"
```

## Workspace layout

- `workspace/agents/` - one directory per agent: `config.yaml` plus a `skills.md` prompt.
- `workspace/tools/` - standalone scripts in any language with a `tool.yaml` manifest. JSON in on stdin, JSON out on stdout.
- `workspace/workflows/` - background agents and scripts triggered by schedules or webhooks.
- `workspace/mcps/` - registrations for external MCP servers.

To run Trellis for an organization with your own content repo, point `TRELLIS_WORKSPACE_DIR` at that checkout instead of `./workspace` — see [docs/deploy.md](docs/deploy.md).

## Docs

- [Deploy](docs/deploy.md) - running Trellis for your org: content repos, image pinning, and TLS
- [Agents](docs/agents.md) - building agent configs and skills prompts
- [Tools](docs/tools.md) - the stdin/stdout tool protocol
- [Workflows](docs/workflows.md) - background agents and scripts
- [MCP](docs/mcp.md) - registering external MCP servers
- [CLI](docs/cli.md) - scaffold workspaces, sync the registry, inspect runs
- [Rules Engine](docs/rules_engine.md) - lock queries onto agents with plain-language rules, ahead of semantic search
- [Upgrading](docs/upgrading.md) - versioning, release tags, and breaking-change notes
- [Branding](branding/trellis-logo/GUIDELINES.md) - logo kit usage guide

## License

[Apache-2.0](LICENSE)
