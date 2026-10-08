# Contributing to Trellis

Thanks for your interest in Trellis! This guide covers the practical bits; the
developer guides for building agents, tools, MCP servers, and workflows live in
[`docs/`](docs/).

## Contribution posture

Trellis is currently maintainer-led. External code contributions are limited
pending contribution terms. Issues, discussions, and feedback are always
welcome — if you spot a bug or have an idea, please open an issue.

Any contributions accepted into this repository are licensed under the
[Apache-2.0](LICENSE) license.

## Getting set up

```bash
git clone https://github.com/laraibkazi92/trellis-agent-platform.git
cd trellis-agent-platform
docker compose up -d --build
```

Rebuilding also re-syncs `workspace/` content (agents, tools, MCP servers,
workflows) into the etcd registry — no manual sync step is required.

## Where things go

| Change | Location |
|---|---|
| Service logic (host, hub, gateway, UI routers) | `core/` |
| Agent definitions | `workspace/agents/<name>/` (`config.yaml` + `skills.md`) |
| Tools | `workspace/tools/<name>/` (`tool.yaml` + entrypoint) |
| External MCP servers | `workspace/mcps/<name>/mcp.yaml` |
| Background workflows | `workspace/workflows/<name>/` |
| Dashboard templates | `templates/` |

Project conventions (tool protocol, directory layout, naming) are documented in
each `docs/*.md` guide — please read the one matching your change.

## Before you open a PR

1. **Run the tests** relevant to your change:
   ```bash
   python -m pytest tests/
   ```
2. **Update docs** if you change behavior — `docs/` and `README.md` are part of
   the product.

## Scope

This repository is the complete product — everything you need to run Trellis.
If you're unsure whether a change fits, open an issue and ask before building.

## Reporting security issues

Please do **not** open public issues for security vulnerabilities. Contact the
maintainer privately via [GitHub](https://github.com/laraibkazi92).
