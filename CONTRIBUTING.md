# Contributing to Trellis

This repository is the **framework engine** — the services in `core/`, the sandboxed
tool runner, the registry, and the dashboard. Organizations consume it by pinning a
release tag and supplying their own content (agents, tools, workflows, MCP servers)
in a separate repo, mounted via `TRELLIS_WORKSPACE_DIR`. See
[docs/deploy.md](docs/deploy.md) for that side of it.

This guide covers working on the engine itself. For the framework internals — service
responsibilities, agent types, key directories, and gotchas — read
[AGENTS.md](AGENTS.md).

## Contribution posture

Trellis is maintainer-led: maintainers decide what gets merged and own the roadmap.
Code contributions — bug fixes, improvements, docs, and tests — are welcome. If you
are planning anything larger than a small fix, please open an issue first so we can
align on the approach before you build.

By submitting a pull request, you agree that your contributions are licensed under
the [Apache-2.0](LICENSE) license, the same as the rest of the project. There is no
CLA to sign.

## Getting set up

Docker is the only prerequisite. No local Python toolchain is needed to run the
stack.

```bash
git clone https://github.com/laraibkazi92/trellis-agent-platform.git
cd trellis-agent-platform
cp .env.example .env    # set SESSION_SECRET, then set DEV_MODE=true
docker compose up -d --build
```

Set `DEV_MODE=true` in `.env` to run without authentication — it disables all auth
across host, hub, gateway, and UI. Development only: never expose a `DEV_MODE`
instance.

Rebuilding also re-syncs `workspace/` content (agents, tools, MCP servers,
workflows) into the etcd registry — no manual sync step is required.

## Tests

`pytest` is the only dev-only dependency; the runtime deps live in
`requirements.txt` and the suite imports them, so install both.

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
```

Run the suite from the repository root — it picks up `tests/` from there. The suite
is self-contained (mocked; no etcd, Redis, or LLM services required) but does import
the framework modules, so the runtime deps must be present. Hosts whose system Python
differs from the pinned 3.12 can run it in the project image instead:

```bash
docker run --rm -v "$PWD":/app -w /app trellis-agent-platform sh -c \
  "pip install -q -r requirements.txt -r requirements-dev.txt && python -m pytest -q"
```

## The engine/content contract

Two things are a **public API**, because every org's content repo and its build
tooling depend on them:

1. The `workspace/` layout — `agents/`, `tools/`, `workflows/`, `mcps/`, and
   `shared/`.
2. The tool stdin/stdout JSON protocol (JSON arguments on `stdin`, JSON result on
   `stdout`).

Changing either is a **breaking change**. It requires bumping the version — at `0.x`,
breaking changes may land in a minor release — and adding an entry to
[docs/upgrading.md](docs/upgrading.md) so operators know what to change.

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
   python -m pytest
   ```
   Behavior changes need tests.
2. **Update docs** if you change behavior — `docs/` and `README.md` are part of
   the product.
3. **Keep `core/` org-agnostic.** No org names, tenant identifiers, internal
   hostnames, or content-specific assumptions belong in the engine; that belongs in
   the consuming org's content repo.
4. **Add the standard header** to new source files:
   `Copyright (C) 2026 Laraib Kazi` / `SPDX-License-Identifier: Apache-2.0`
   (see any file in `core/` for the format).

## Release checklist (maintainers)

1. Tag the release: `vX.Y.Z` (the first release is `v0.2.0`). At `0.x`, breaking
   changes may ship in a minor release.
2. Update the default `TRELLIS_IMAGE` pin (`docker-compose.yml`, `.env.example`) to
   the new tag.
3. Push the tag. CI ([`.github/workflows/publish-images.yml`](.github/workflows/publish-images.yml))
   builds and pushes the multi-arch images (linux/amd64 + linux/arm64) to GHCR as
   `ghcr.io/laraibkazi92/trellis-agent-platform:vX.Y.Z` and `:latest`. No secrets to
   configure — **but after the very first push, set the GHCR package visibility to
   public** (package settings → Change visibility); GHCR packages default to private,
   and a private package would force every org to authenticate before `docker compose pull`.
4. Add a [docs/upgrading.md](docs/upgrading.md) entry for the release, listing any
   changes to `docker-compose.yml`, `.env` variables, the registry sync
   (`scripts/sync_to_db.py`), or the tool protocol.

## Reporting security issues

Please do **not** open public issues for security vulnerabilities. Contact the
maintainer privately via [GitHub](https://github.com/laraibkazi92).
