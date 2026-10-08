# Contributing to Trellis

Thanks for your interest in Trellis! This guide covers the practical bits; the
developer guides for building agents, tools, MCP servers, and workflows live in
[`docs/`](docs/).

## Contribution posture

Trellis is maintainer-led: maintainers decide what gets merged and own the
roadmap. Code contributions — bug fixes, improvements, docs, and tests — are
welcome. If you are planning anything larger than a small fix, please open an
issue first so we can align on the approach before you build.

By submitting a pull request, you agree that your contributions are licensed
under the [Apache-2.0](LICENSE) license, the same as the rest of the project.
There is no CLA to sign.

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
3. **Add the standard header** to new source files:
   `Copyright (C) 2026 Laraib Kazi` / `SPDX-License-Identifier: Apache-2.0`
   (see any file in `core/` for the format).

## Scope

This repository is the complete product — everything you need to run Trellis.
If you're unsure whether a change fits, open an issue and ask before building.

## Reporting security issues

Please do **not** open public issues for security vulnerabilities. Contact the
maintainer privately via [GitHub](https://github.com/laraibkazi92).
