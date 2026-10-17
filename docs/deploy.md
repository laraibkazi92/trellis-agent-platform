# Deployment Guide

This guide is for the **org operator** who runs a Trellis deployment: which repo holds what, how to install the stack, and how to keep your content and state safe across upgrades.

Trellis separates **engine**, **content**, and **state**. Only the engine is versioned by this project; the other two are yours.

| Piece | What it is | Where it lives | Lifecycle |
| --- | --- | --- | --- |
| **Engine** | The framework code and `docker-compose.yml` | This repo, cloned at a **release tag** | Never modified. Re-cloned or `git checkout`-ed on upgrade. |
| **Content** | Agents, tools, workflows, MCP registrations | Your own workspace repo (any Git host) | You own it. Edit, review, tag as you like. |
| **State** | Users, API keys, tool secrets, run history, registry | The `etcd-data` Docker volume | The runtime writes it. Back it up. Never in Git. |

```text
engine clone (pinned tag)          content repo (yours)             docker volume
/opt/trellis                       /opt/my-org-workspace            etcd-data
├── docker-compose.yml  ─mount─►   └── workspace/  ─sync─►          users, API keys,
├── .env                                             (db-sync)      secrets, runs
└── core/, scripts/, gateway/
```

A rebuild or upgrade replaces the engine only. The content mount and the `etcd-data` volume are untouched, so your agents and your data survive.

## Prerequisites

Docker only — Engine with the Compose v2 plugin. The prebuilt image bundles the full toolchain (Python, Node, Go), so no language runtimes are needed on the host.

## Install path A: pull prebuilt images (recommended)

The released images are public on GHCR, multi-arch (`linux/amd64` + `linux/arm64`), and need no login:

```bash
docker compose pull
docker compose up -d
```

> If a pull ever asks for credentials, the GHCR package has not been made public: either set its visibility to public in the repo's package settings, or `docker login ghcr.io` with a token that has `read:packages`.

One service is not published: `nginx-gateway` is built from `./gateway` in the clone, so it compiles locally on first `up` (a small nginx image). After changing anything under `gateway/`, rebuild just that service:

```bash
docker compose up -d --build nginx-gateway
```

`hindsight` (agent memory) is the upstream `ghcr.io/vectorize-io/hindsight` image and is pulled the same way.

### Air-gapped or mirrored installs

If the host has no access to GHCR, export the images from a connected machine and load them on the target:

```bash
# connected machine
docker compose pull
docker save -o trellis-images.tar \
  ghcr.io/laraibkazi92/trellis-agent-platform:v0.2.0 \
  ghcr.io/vectorize-io/hindsight:0.9.1-slim \
  gcr.io/etcd-development/etcd:v3.6.15 \
  redis:alpine \
  nginx:alpine
# target machine
docker load -i trellis-images.tar
```

`nginx:alpine` is included because `nginx-gateway` is built locally from `./gateway` (`FROM nginx:alpine`). Either build that small image on the connected machine first (`docker compose build nginx-gateway`, then `docker save` the tag it shows in `docker image ls`) and load it on the target, or let the target build it using the loaded base image.

Alternatively push the same images to a private registry mirror and point the stack at it with `TRELLIS_IMAGE` in `.env`:

```bash
TRELLIS_IMAGE=registry.internal.example.com/trellis-agent-platform:v0.2.0
```

## Install path B: build from source

Use this when you carry local patches or want a fully offline build:

```bash
docker compose up -d --build
```

`--build` builds every app service from the local context and ignores `TRELLIS_IMAGE`. The app containers run as `${TRELLIS_UID:-1000}:${TRELLIS_GID:-1000}` so files written into the bind-mounted workspace are owned by you, not root — set both in `.env` to match your host user:

```bash
TRELLIS_UID=$(id -u)
TRELLIS_GID=$(id -g)
```

## First-run setup

```bash
# 1. Clone the engine at a release tag
git clone --branch v0.2.0 https://github.com/laraibkazi92/trellis-agent-platform.git
cd trellis-agent-platform

# 2. Seed your environment file
cp .env.example .env

# 3. Edit .env (see the table below), then start the stack
docker compose up -d            # or: docker compose up -d --build
```

Browse to `http://localhost`, sign in as an `ADMIN_USERS` address, and create an API key.

The variables below are the ones you must touch for a first deployment. Everything else in `.env.example` is an optional default whose runtime value normally lives in the Admin Dashboard and is stored in etcd.

| Variable | Required | Purpose |
| --- | --- | --- |
| `SESSION_SECRET` | Yes | Signs sessions and seeds the Fernet encryption key (`ENCRYPTION_KEY` falls back to it). |
| `ADMIN_USERS` | Yes | Comma-separated admin identities (e.g. `ops@example.com`). |
| `TRELLIS_WORKSPACE_DIR` | Recommended | Workspace bind-mount source. Defaults to `./workspace` inside the clone. Point it at your content repo to keep the engine pristine. |
| `TRELLIS_IMAGE` | Optional | Pins the engine image tag or digest, e.g. `ghcr.io/laraibkazi92/trellis-agent-platform:v0.2.0`. |
| `TRELLIS_UID` / `TRELLIS_GID` | Optional | Container uid:gid for workspace file ownership. Defaults to `1000:1000`. |
| `DEV_MODE` | No | Keep `false` for anything shared. `true` disables **all** authentication. |
| `HOST_BIND` | Optional | Host address published ports bind to. Default `0.0.0.0`. |
| `SYNC_FORCE_PRUNE` | Optional | Escape hatch for the registry prune guard. Default `false`. |
| `SSL_ENABLED` | Optional | Set `True` to serve the front door over HTTPS. Default `False`. |

## Using a separate content repo

Keep the engine clone exactly as released and mount your own checkout as the workspace. Both are supported; pick one.

### Option 1: `TRELLIS_WORKSPACE_DIR` (simplest)

Every app service bind-mounts `${TRELLIS_WORKSPACE_DIR:-./workspace}` at `/app/workspace`. Point it at your content repo in `.env`:

```bash
TRELLIS_WORKSPACE_DIR=../my-org-workspace/workspace
```

Relative paths resolve from the clone's directory (the directory holding `docker-compose.yml`).

### Option 2: a compose override file

Copy the shipped example and edit the path:

```bash
cp docker-compose.workspace-example.yml docker-compose.override.yml
# edit the paths inside, then:
docker compose up -d
```

Compose auto-loads `docker-compose.override.yml`, and `docker-compose.override.yml` is gitignored — use this when you want per-instance divergence (a dev override differing from prod) or an explicit file rather than an env var.

The merge rule that makes this safe: compose merges `volumes` by **container path**, not as a list. Re-declaring only `/app/workspace` replaces that one mount and leaves the other mounts intact — `health-data:/app/data` on `host` and `ui` is retained. Paths inside an override resolve relative to the base compose file's directory (the engine clone).

### Scaffolding the content repo

`trellis init` runs on the Python standard library, so it needs no framework dependencies:

```bash
python scripts/trellis init ../my-org-workspace
```

It creates the standard layout under `PATH` (never overwriting existing files, so it is safe to re-run):

```text
../my-org-workspace/
└── workspace/
    ├── agents/
    ├── tools/
    ├── mcps/
    ├── workflows/
    └── shared/
```

Because the scaffold nests a `workspace/` directory, mount **that** subdirectory — `TRELLIS_WORKSPACE_DIR=../my-org-workspace/workspace`. If no `.env` exists in `PATH`, `init` also copies `.env.example` there as a reference; the running stack reads the engine clone's `.env`, not that copy.

Commit the content repo and point a branch or tag at it. See [CLI](cli.md) for `trellis init`, `sync`, and `logs`.

## Day-2 operations

**LLM provider keys are not in `.env`.** Configure them in **Admin → LLM Providers**, one card per provider (Google (Gemini), OpenAI, Anthropic, DeepSeek, OpenRouter, Ollama, any OpenAI-compatible endpoint, and more — 15 in total). Every provider key, new or old, lives only in that etcd store, Fernet-encrypted; an unset key simply disables that provider. The one exception is `GEMINI_API_KEY` in `.env`, which is consumed only by the Hindsight memory container as the fallback for `HINDSIGHT_LLM_API_KEY`. The **Framework defaults** card at the top of that page sets an org-wide default provider and model that agents and workflows leaving both `provider` and `model` blank inherit; it lives in etcd under `/config/framework/default_llm_*`.

**Third-party credentials are not in `.env` either.** Store them as **Tool Secrets** in the UI (Configuration). They are injected into tool and workflow subprocesses at run time through the identity-scoped secret store. Note that `hub` and `taskiq-worker` deliberately do not load `.env` as `env_file`, because they copy their environment into every subprocess they spawn.

**The volumes you must not lose:**

| Volume | Holds |
| --- | --- |
| `etcd-data` | Users, API keys, tool secrets, agent/tool/workflow/MCP registry, run history. **Not in Git — back it up.** |
| `health-data` | Host/UI health monitor state. |
| `hindsight-data` | Agent memory (embedded Postgres). The embedding model and dimension must be set before first use; changing either later requires wiping this volume. |

> **WARNING** — `docker compose down -v` deletes the `etcd-data` volume, i.e. every user, API key, and run record. Never run it to "clean up". Use `docker compose down` instead.

If the `health-data` volume already exists root-owned (from an earlier run as a different uid), remove only that one and recreate it (`docker volume ls` confirms the exact name — it is `<compose-project>_health-data`, where the compose project defaults to the clone's directory name):

```bash
docker compose down && docker volume rm "$(basename "$PWD")_health-data"
```

**etcd and Redis are not published to the host** — they are reachable only on the internal `trellis-network`. Run framework tooling from inside a container:

```bash
docker compose exec host python scripts/trellis sync
docker compose exec host python scripts/trellis logs [AGENT] --limit 20
```

## Content authoring workflow

The workspace files are the source of truth on every rebuild. The `db-sync` init container runs once at startup (`python scripts/sync_to_db.py`) and pushes `workspace/agents`, `workspace/tools`, `workspace/workflows`, and `workspace/mcps` into the etcd registry. Agent and tool edits made in the UI are **dual-written** back to the matching workspace file, so a UI change surfaces as a diff in your content repo — commit it there.

Two consequences worth internalizing:

- **Tool scripts are filesystem-native.** The UI can edit manifests and configuration, but it cannot author a tool's script. Add or change the script in your content repo (`workspace/tools/<tool>/`), then rebuild or re-sync.
- **Nothing writes back to Git.** Commit and push your content repo yourself; the engine never does it for you.

A dev/prod pattern that works well: a **dev** deployment tracks a branch (`main`) and rebuilds as content lands, while **prod** pins a tag or SHA and is only rebuilt deliberately. Both point `TRELLIS_WORKSPACE_DIR` at their own checkout of the same content repo.

Authoring references: [Agents](agents.md), [Tools](tools.md), [Workflows](workflows.md), [MCP](mcp.md), [Rules Engine](rules_engine.md).

## Registry prune guard

Sync is authoritative: it deletes registry entries whose source directory is gone. That makes a mis-pointed or unmounted workspace dangerous — it would otherwise look like "everything was deleted" and silently wipe the registry.

To prevent that, `db-sync` **refuses to prune when the sync found nothing at all** — no agents, no tools, and no MCPs in the workspace — while etcd still holds registry entries. That total blank is the signature of an unmounted workspace. The refusal exits non-zero, and because `host`, `hub`, `ui`, `taskiq-worker`, and `taskiq-scheduler` wait on `db-sync` completing successfully, the stack does not start onto a wiped registry.

The check is deliberately **global, not per-category**: one empty category alongside a populated one is indistinguishable from ordinary pruning (an org with its own agents but no tools of its own yet, say), so it is allowed. Only the "nothing at all" shape trips the guard.

Fix the cause rather than the guard: correct `TRELLIS_WORKSPACE_DIR`, or fix the bind mount. To proceed anyway — because you really did remove all workspace content — set the escape hatch in `.env` for one run:

```bash
SYNC_FORCE_PRUNE=true
```

The one case that trips the guard by design is deleting **all** demo content in a single rebuild before you have added content of your own: the workspace then syncs nothing while the registry still holds the demo entries. Add your own agent or tool first, or set `SYNC_FORCE_PRUNE=true` for that one rebuild (see [Demo content](#demo-content)).

Ordinary pruning is unaffected — deleting one agent directory while the others remain prunes only that agent, and clearing a whole category is fine as long as the workspace is not entirely blank. A refusal skips the **whole** prune pass for that run (nothing is half-pruned). The same override is available on demand with `python scripts/trellis sync --force-prune`.

## Upgrading the engine

The content repo and the `etcd-data` volume are untouched by an engine upgrade:

```bash
cd trellis-agent-platform
git fetch --tags
git checkout v0.x.y
docker compose pull
docker compose up -d
```

`db-sync` re-syncs your workspace into etcd on the way up, so newly added content in your content repo is picked up at the same time. If you build from source instead, use `docker compose up -d --build`.

If the new release changed anything under `gateway/` (nginx), rebuild that service too: `docker compose up -d --build nginx-gateway`.

Rollback is the reverse: `git checkout <previous-tag>`, `docker compose pull`, `docker compose up -d`. etcd schema migrations note — the bundled etcd is `v3.6.15`; an in-place upgrade of a 3.5 data directory is supported but one-way, so rolling back the etcd image afterwards requires a snapshot/restore. Keep `etcd-data` backed up before upgrading, and see [Upgrading](upgrading.md) for the volume and data caveats referenced from `docker-compose.yml`.

## Demo content

The clone ships three samples: `workspace/agents/demo-assistant/`, `workspace/tools/demo/`, and `workspace/workflows/demo-inventory/`. They are illustrative only — the framework has no dependency on them. Delete all three directories (and rebuild, or run a sync) once your own content is in place. If you mount an external content repo, these directories are not used at all.

> Deleting *every* demo directory in one go, before you have added content of your own, leaves the workspace syncing nothing while etcd still holds the demo entries — which trips the [prune guard](#registry-prune-guard). Either add your own agent or tool first, or set `SYNC_FORCE_PRUNE=true` for that one rebuild.

## TLS and hardening

- **Front door.** `nginx-gateway` publishes ports 80 and 443 and is the single entry point for the stack. Set `SSL_ENABLED=True` and `SSL_DNS_NAME=<your-domain>` in `.env` to serve HTTPS; certificates are read from `SSL_CERT_DIR` (default `./gateway/ssl`, expecting `cert.pem` and `key.pem`). The cert-directory volume mount is commented out in `docker-compose.yml` — enable it by uncommenting that block, or via a local `docker-compose.override.yml`, which keeps the engine clone pristine.
- **Bind address.** `HOST_BIND` defaults to `0.0.0.0`, so published ports are reachable from anywhere. Set `HOST_BIND=127.0.0.1` to keep them loopback-only — this also covers the Hindsight ports (8888 API, 9999 Control Plane UI). etcd and Redis are never published regardless.
- **Authentication.** Keep `DEV_MODE=false` for anything shared: `true` disables API-key auth, UI login, and MCP auth across `host`, `hub`, `gateway`, and `ui`, and only logs a startup warning — it does not restrict the bind host. Optional SSO is configured with `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` or the `OIDC_*` variables, plus `ALLOWED_DOMAINS` to restrict by email domain.
- **Tool sandbox.** The `hub` container runs least-privilege — all capabilities dropped except `SYS_ADMIN` and `SETFCAP`, plus `no-new-privileges` and unmasked system paths — because every tool executes inside a bubblewrap sandbox and the container must not hold more rights than bwrap needs. If tool execution still fails with bwrap/userns errors on an exotic kernel or hardened seccomp policy, the documented local fallback is replacing the hub's `cap_drop`/`cap_add`/`security_opt` block with `privileged: true`, which grants much broader container access.

## Verifying the deployment

```bash
docker compose ps                       # every service up; db-sync exited 0
curl -sI localhost                      # front door answers through nginx
docker compose exec host curl -sf http://127.0.0.1:8000/health
docker compose logs db-sync             # sync counts
docker compose exec host python scripts/trellis logs --limit 5
```
