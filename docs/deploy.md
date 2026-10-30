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

> **v0.7.1 breaking changes.** The legacy in-process sandbox backends (bwrap, Landlock,
> the shipped AppArmor profile), the network profiles and the opt-in egress proxy were
> removed: every tool/MCP call is a runner container, and tool containers use Docker's
> default bridge (`network: egress`) or no network (`none`). If you are upgrading an
> existing install, read [upgrading.md → v0.7.1](upgrading.md#v071-2026-10-26) first: it
> lists every removal with the action to take.
>
> **v0.7.2 breaking changes for edges.** An edge no longer holds a token-signing key
> (`AGENT_TOKEN_SECRET`/`ENFORCE_AGENT_TOKENS` leave the proxy *and* the runner, and the
> runner runs with `RUNNER_ROLE=edge`), and the edge/relay wire protocol moved to
> `proto: 3`, so central and every edge are upgraded in the same window. A stack running
> as `TRELLIS_UID`/`TRELLIS_GID` `0` no longer starts. Read
> [upgrading.md → v0.7.2](upgrading.md#v072-2026-10-27) before you upgrade an edge.

## Prerequisites

Docker Engine with the Compose v2 plugin is the only host dependency. The prebuilt image
bundles the full toolchain (Python, Node, Go), so no language runtimes are needed on the
host. Every tool call is a container started by the `runner` service, so the only host-side
question is which OCI runtime is registered: `runsc` (gVisor) where it is installed, `runc`
otherwise (`CONTAINER_DEFAULT_RUNTIME`). The runner's own `GET /v1/healthz` reports the
verdict.

- **Production:** register `runsc` on the host. gVisor is the isolation boundary between a
  tool container and the host kernel, so a production deployment must not run on `runc`.
  The feature set is validated against the gVisor release **`release-20261019.0`**: run at
  least that release and confirm it with `runsc --version` on the host before deploying.
- **A dev machine (a laptop, WSL2, any Docker host without gVisor):** no gVisor needed,
  see [Dev machine](#dev-machine-runc).

What a tool container can see is proven by the runsc isolation harness
(`docker-compose.ci-isolation.yml`, self-hosted with `runsc` registered) and, on `runc`, by
the `Sandbox smoke` workflow.

The hub container runs as `${TRELLIS_UID:-1000}`, the operator uid that owns the workspace,
not root, and tool containers run as that same uid.

## Install path A: pull prebuilt images (recommended)

The released images are public on GHCR, multi-arch (`linux/amd64` + `linux/arm64`), and need no login:

```bash
docker compose pull
docker compose up -d
```

> If a pull ever asks for credentials, the GHCR package has not been made public: either set its visibility to public in the repo's package settings, or `docker login ghcr.io` with a token that has `read:packages`.

### Pinning and verifying a release

`TRELLIS_IMAGE` in `.env` pins a **tag** (`:v0.7.5`) because a tag stays readable in a diff. Tags are mutable, so if you need the image to be byte-identical forever, pin the **digest** published in that release's workflow summary instead:

```bash
TRELLIS_IMAGE=ghcr.io/laraibkazi92/trellis-agent-platform@sha256:<digest>
```

Every release published after provenance was wired up is attested by GitHub's keyless signer, which proves the image was built by `.github/workflows/publish-images.yml` from the commit its tag points at. Verify a pulled image with the GitHub CLI (no signing key, no registry login — the attestation is stored next to the image):

```bash
gh attestation verify oci://ghcr.io/laraibkazi92/trellis-agent-platform:v0.7.5 \
  -R laraibkazi92/trellis-agent-platform
```

Images published before that change carry no attestation, and the check fails for them — that is expected, not a broken release.

If the check fails with *"the provided token was denied access to the requested resource"*, the problem is `gh`'s credentials, not the release: `gh` resolves the image digest through GitHub rather than anonymously, and a default `gh auth login` does not include the `read:packages` scope. Grant it once and retry:

```bash
gh auth refresh -s read:packages
```

The registry itself needs nothing extra — anonymous pulls of the public package work, and `docker pull`/`docker compose pull` are unaffected by this.

One service is not published: `nginx-gateway` is built from `./gateway` in the clone, so it compiles locally on first `up` (a small nginx image). After changing anything under `gateway/`, rebuild **only** that service:

```bash
docker compose build nginx-gateway
docker compose up -d --no-build --no-deps nginx-gateway
```

Do not use `docker compose up -d --build nginx-gateway` for this: `--build` on `up` also builds every service with a `build:` section in that service's dependency graph, which replaces the app image you pulled from GHCR with a local build that reports `TRELLIS_VERSION=dev` and carries no attestation.

`hindsight` (agent memory) is the upstream `ghcr.io/vectorize-io/hindsight` image and is pulled the same way.

### Air-gapped or mirrored installs

If the host has no access to GHCR, export the images from a connected machine and load them on the target:

```bash
# connected machine
docker compose pull
docker save -o trellis-images.tar \
  ghcr.io/laraibkazi92/trellis-agent-platform:v0.7.5 \
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
TRELLIS_IMAGE=registry.internal.example.com/trellis-agent-platform:v0.7.5
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

## Dev machine (`runc`)

You do not need gVisor to run the whole stack locally. A host without gVisor registered
(most laptops, any VM-based Docker install) runs every container on `runc` instead:

```bash
# .env
DEV_MODE=true                            # no login while you iterate; never expose this
CONTAINER_DEFAULT_RUNTIME=runc           # the runtime to use when gVisor is not installed
RUNNER_TOKEN=$(openssl rand -hex 32)     # required by the runner and every caller
AGENT_TOKEN_SECRET=$(openssl rand -hex 32)   # required: tokens are enforced by default
TRELLIS_HOST_WORKSPACE=/absolute/path/to/workspace   # HOST path, not /app/workspace
```

- **`runc` gives up kernel-syscall isolation.** That is fine for a laptop and not fine for
  anything shared, which is why the compose default stays `runsc`. Do not promote a dev
  `.env` to a server.
- **`TRELLIS_HOST_WORKSPACE` must be a path the Docker daemon can see.** On Linux with a
  native daemon that is the ordinary absolute path. On a VM-based Docker install (macOS,
  Windows, some WSL2 setups) it must sit under a path the daemon shares with the host (for
  example `/Users/you/...` on macOS, or `/home/you/...` inside WSL2 on Windows). A path
  outside the shared roots makes every tool bind mount resolve to nothing and the runner's
  startup canary refuses to serve.
- **`AGENT_TOKEN_SECRET` is not optional, even in `DEV_MODE`.** Tokens default to
  `ENFORCE_AGENT_TOKENS=enforce`, and a stack that enforces with no signing key exits at
  startup. Setting `ENFORCE_AGENT_TOKENS=off` alongside `DEV_MODE=true` also works; it is
  refused on a stack that is not in `DEV_MODE`.
- **What you cannot reproduce locally.** Every container runs on `runc`, so a failure that
  only happens under gVisor (a syscall gVisor does not implement, for instance) will not
  reproduce here; use a `runsc` host for that.
- **Tool access rules still apply.** The shipped `workspace/policies/tool_access.yaml` has
  no rules, so the agent allowlist alone decides; if you add a rule, remember that a local
  dev login usually carries no identity-provider groups and will be denied in `enforce`
  mode.

## First-run setup

```bash
# 1. Clone the engine at a release tag
git clone --branch v0.7.5 https://github.com/laraibkazi92/trellis-agent-platform.git
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
| `TRELLIS_IMAGE` | Optional | Pins the engine image tag or digest, e.g. `ghcr.io/laraibkazi92/trellis-agent-platform:v0.7.5`. |
| `TRELLIS_UID` / `TRELLIS_GID` | Optional | Container uid:gid for workspace file ownership. Defaults to `1000:1000`; both must be non-zero — the runner refuses to start otherwise, because `0` is root and a root tool owns every file it writes (v0.7.2). |
| `DEV_MODE` | No | Keep `false` for anything shared. `true` disables **all** authentication. |
| `OIDC_GROUPS_CLAIM` | Optional | Identity-provider claim holding group membership for the tool-access group rules (default `groups`). Accepted as a list or a comma-separated string. |
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
    ├── policies/          # tool_access.yaml (group rules); add it yourself
    └── shared/
```

`trellis init` does not create `policies/`: copy the shipped
`workspace/policies/tool_access.yaml` (it ships with `rules: []`) or start from the format
in [tools.md → Tool access rules](tools.md#tool-access-rules). The sync warns when the file
is missing and keeps whatever policy the registry already holds.

Because the scaffold nests a `workspace/` directory, mount **that** subdirectory — `TRELLIS_WORKSPACE_DIR=../my-org-workspace/workspace`. If no `.env` exists in `PATH`, `init` also copies `.env.example` there as a reference; the running stack reads the engine clone's `.env`, not that copy.

Commit the content repo and point a branch or tag at it. See [CLI](cli.md) for `trellis init`, `sync`, and `logs`.

## Day-2 operations

**LLM provider keys are not in `.env`.** Configure them in **Admin → LLM Providers**, one card per provider (Google (Gemini), OpenAI, Anthropic, DeepSeek, OpenRouter, Ollama, any OpenAI-compatible endpoint, and more — 15 in total). Every provider key, new or old, lives only in that etcd store, Fernet-encrypted; an unset key simply disables that provider. The one exception is `GEMINI_API_KEY` in `.env`, which is consumed only by the Hindsight memory container as the fallback for `HINDSIGHT_LLM_API_KEY`. The **Framework defaults** card at the top of that page sets an org-wide default provider and model that agents and workflows leaving both `provider` and `model` blank inherit; it lives in etcd under `/config/framework/default_llm_*`.

**Third-party credentials are not in `.env` either.** Store them as **Tool Secrets** in the UI (Configuration). They are injected into tool and workflow containers at run time through the identity-scoped secret store. Note that `hub` and `taskiq-worker` deliberately do not load `.env` as `env_file`: their processes sit on the secret-decryption path, and since v0.7.1 a `background_script` container receives only the secrets/variables its workflow declared — never the worker's own environment.

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

**Tools on a network you cannot reach.** If a tool's API lives behind a network the central host cannot dial, publish it with an edge node instead of opening a path in: `trellis-proxy` dials out over WSS and the tools appear centrally as native tools. See [Edge nodes (trellis-proxy)](proxy.md).

## Content authoring workflow

The workspace files are the source of truth on every rebuild. The `db-sync` init container runs once at startup (`python scripts/sync_to_db.py`) and pushes `workspace/agents`, `workspace/tools`, `workspace/workflows`, `workspace/mcps`, and `workspace/policies/tool_access.yaml` (tool-access group rules) into the etcd registry. Agent and tool edits made in the UI are **dual-written** back to the matching workspace file, so a UI change surfaces as a diff in your content repo — commit it there.

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
git fetch --tags --force          # plain --tags keeps a re-pointed tag at its old commit
git checkout v0.x.y
git rev-parse --short v0.x.y      # must match the commit named in that release's notes
docker compose pull
docker image inspect "${TRELLIS_IMAGE:-ghcr.io/laraibkazi92/trellis-agent-platform:v0.x.y}" \
  --format '{{.RepoDigests}}'     # must match the digest named in that release's notes
docker compose up -d
```

`--force` matters: a tag can be re-pointed to a rebuilt commit without the version
changing. `git fetch --tags` then prints `! [rejected] … (would clobber existing tag)` and
`git checkout` succeeds on the **old** commit without failing — and `docker compose up -d`
alone does not re-pull an image tag the host already has. The `rev-parse` and `image
inspect` lines are what tell you which build you are actually on.

`db-sync` re-syncs your workspace into etcd on the way up, so newly added content in your content repo is picked up at the same time. If you build from source instead, use `docker compose up -d --build`.

If the new release changed anything under `gateway/` (nginx), rebuild that service too: `docker compose build nginx-gateway && docker compose up -d --no-build --no-deps nginx-gateway`. Use that two-step form rather than `up -d --build nginx-gateway`, which also rebuilds the app services in the dependency graph.

Rollback is the reverse: `git checkout <previous-tag>`, `docker compose pull`, `docker compose up -d`. etcd schema migrations note — the bundled etcd is `v3.6.15`; an in-place upgrade of a 3.5 data directory is supported but one-way, so rolling back the etcd image afterwards requires a snapshot/restore. Keep `etcd-data` backed up before upgrading, and see [Upgrading](upgrading.md) for the volume and data caveats referenced from `docker-compose.yml`.

## Demo content

The clone ships three samples: `workspace/agents/demo-assistant/`, `workspace/tools/demo/`, and `workspace/workflows/demo-inventory/`. They are illustrative only — the framework has no dependency on them. Delete all three directories (and rebuild, or run a sync) once your own content is in place. If you mount an external content repo, these directories are not used at all.

> Deleting *every* demo directory in one go, before you have added content of your own, leaves the workspace syncing nothing while etcd still holds the demo entries — which trips the [prune guard](#registry-prune-guard). Either add your own agent or tool first, or set `SYNC_FORCE_PRUNE=true` for that one rebuild.

## TLS and hardening

- **Edge tunnels.** Edges must dial `wss://`; see [proxy-tls.md](proxy-tls.md) for an
  internal CA, the certificate SANs, and an `/edge`-only terminator if `:80` must keep
  serving plain HTTP.
- **Front door.** `nginx-gateway` publishes ports 80 and 443 and is the single entry point for the stack. Set `SSL_ENABLED=True` and `SSL_DNS_NAME=<your-domain>` in `.env` to serve HTTPS; certificates are read from `SSL_CERT_DIR` (default `./gateway/ssl`, expecting `cert.pem` and `key.pem`). The cert-directory volume mount is commented out in `docker-compose.yml` — enable it by uncommenting that block, or via a local `docker-compose.override.yml`, which keeps the engine clone pristine.
- **Bind address.** `HOST_BIND` defaults to `0.0.0.0`, so published ports are reachable from anywhere. Set `HOST_BIND=127.0.0.1` to keep them loopback-only — this also covers the Hindsight ports (8888 API, 9999 Control Plane UI). etcd and Redis are never published regardless.
- **Authentication.** Keep `DEV_MODE=false` for anything shared: `true` disables API-key auth, UI login, and MCP auth across `host`, `hub`, `gateway`, and `ui`, and only logs a startup warning — it does not restrict the bind host. Optional SSO is configured with `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` or the `OIDC_*` variables, plus `ALLOWED_DOMAINS` to restrict by email domain.
- **Tool containers.** Every tool invocation is its own container, started by the `runner`
  service (`runsc` in production, `runc` on a dev machine). The hub drops all capabilities
  (`cap_drop: [ALL]`, empty `cap_add`, `no-new-privileges`) because no tool process runs
  inside it. See [Security notes](#security-notes) and
  [Execution isolation](#execution-isolation).

## Execution isolation

Every local tool call runs in its **own container**, created by a dedicated `runner`
service; the hub no longer forks tool subprocesses and no longer needs a sandbox of its
own. A container sees its toolkit directory read-only, `shared/` read-only, a sized tmpfs
for `/tmp`, and (only when the tool declares `output_dirs`) the calling agent's output
directory. Nothing else from the workspace is visible.

`trellis-proxy` gives an edge the same model: the edge's own `runner` service creates the
containers, and the proxy forwards calls over a shared socket volume.

### Secrets never in container configuration

Resolved secrets reach a tool only through a one-line stdin preamble (`{"env": {...}}`)
applied by `trellis-exec`, the shim the engine image installs at
`/usr/local/bin/trellis-exec` (images derived from the engine image inherit it).
`docker inspect` on a running tool or MCP-session container therefore shows no declared
secret, only fixed variables such as `HOME`, `PATH`, `LANG` and `TRELLIS_USER_*`, while the
process inside still reads the values from its environment. Everything after the preamble
newline is the tool's own stdin, so the JSON stdin/stdout protocol and MCP stdio framing
are unchanged. A malformed or oversized preamble (64 KiB total, 16 KiB per value) makes the
shim exit `78` before anything runs, and it never logs a key or a value. If you build a tool
image from this one and override the entrypoint, keep that contract.

### Prerequisite: gVisor (`runsc`)

The runner refuses to start when its configured runtime is missing or cannot start a
trivial container. There is no silent fallback to `runc`.

**Minimum version.** This release is validated against the gVisor release tag
**`release-20261019.0`**. Run at least that release and confirm it with `runsc --version`
before you deploy; an older `runsc` may start containers and still fail on the networking
model described in [Network policy](#network-policy). The runner checks this itself but
cannot act on it: `runsc` is a **host** runtime, so when the binary is not reachable from
the runner's own container (the normal case) the preflight reports the check as *skipped*
with an instruction to confirm on the host, and when it can read a version older than the
minimum it logs a **non-fatal warning** and keeps serving. The version is a warning, not a
gate, so a real incompatibility shows up later as a failed container start, not as a
startup refusal.

1. Install `runsc` on the **host** (not in a container) from the gVisor release you
   have tested, and pin that version in your own provisioning. Releases since
   2025 ship `runsc` **plus a `gvisor-bin/` directory next to it**; installing only
   the `runsc` binary starts fine but fails every container with
   `sidecar "gvisor_sentry" not usable`:

   ```bash
   # x86_64; use gvisor-aarch64.* on arm hosts
   VER=release-20261019.0
   curl -fsSLO "https://github.com/google/gvisor/releases/download/$VER/gvisor-x86_64.tar.bz2"
   curl -fsSLO "https://github.com/google/gvisor/releases/download/$VER/SHA512SUMS"
   grep ' gvisor-x86_64.tar.bz2$' SHA512SUMS | sha512sum -c -
   sudo tar -xjmf gvisor-x86_64.tar.bz2 -C /usr/bin --no-same-owner
   sudo chmod 0755 /usr/bin/runsc /usr/bin/containerd-shim-runsc-v1 /usr/bin/gvisor-bin/*
   ```

   (The per-binary `runsc` / `runsc.sha512` files under
   `storage.googleapis.com/gvisor/releases/release/latest/...` printed in older guides
   return 404 for current releases; use the GitHub release assets.)

2. Register it with the Docker daemon and restart Docker:

   ```json
   {
     "runtimes": {
       "runsc": {
         "path": "/usr/bin/runsc",
         "runtimeArgs": ["--network=sandbox"]
       }
     }
   }
   ```

   `--network=sandbox` keeps networking inside gVisor's netstack, which is the mode this
   release is validated in. Do **not** add `--ignore-cgroups=true`: per-container
   `--memory`/`--cpus`/`--pids-limit` come from the manifest `limits:` block and need
   cgroups.

   Registering a runtime is one of the few daemon settings Docker reloads in place:
   after editing `daemon.json`, `sudo systemctl reload docker` is enough
   (`docker info --format '{{json .Runtimes}}'` shows it). A full restart also
   works but restarts every running container.

3. Prove it before starting the stack:

   ```bash
   docker info --format '{{json .Runtimes}}' | grep runsc
   runsc --version
   docker run --rm --runtime=runsc hello-world
   ```

   All three must succeed. A per-tool `container_runtime: runc` in `tool.yaml` is the escape
   hatch for a tool that cannot run under gVisor; it forfeits the kernel-syscall
   isolation and must be justified per tool.

### The runner service and its socket

`runner` is the **only** service that mounts `/var/run/docker.sock`. Treat access to
that socket as root on the host, and do not mount it anywhere else — not into `hub`,
`host`, an edge proxy, or a debugging container.

- **API:** a Unix socket at `/run/trellis/runner.sock`, shared read-write through the
  `runner-run` volume with `host`, `hub`, `gateway` and `taskiq-worker`. It is never a
  TCP port; `network_mode: "none"` means no tool network can reach it.
- **Auth:** `RUNNER_TOKEN` is required and must be identical on the runner and every
  caller. Generate it with `openssl rand -hex 32`. The only exception is
  `DEV_MODE=true`, which logs a loud warning and accepts unauthenticated calls.
- **Posture:** `read_only` rootfs, `cap_drop: [ALL]` plus `CHOWN` and
  `DAC_OVERRIDE` (`CHOWN` to chgrp the control socket to `${TRELLIS_GID}`;
  `DAC_OVERRIDE` because the workspace is owned by `${TRELLIS_UID}` and the runner
  writes the canary and the agents' output directories there), `no-new-privileges`,
  a tmpfs `/tmp`. It runs as root only to open the Docker socket; every container
  it starts runs as `${TRELLIS_UID}:${TRELLIS_GID}`.
- **Restart:** `restart: unless-stopped` with a healthcheck that probes `/v1/healthz`.
  It is a single process on purpose (container slots live in memory), so it is also a
  single point of failure: while it is down, local tool calls fail with a clear error
  and chat-only agents keep working. Do not scale it to two replicas.
- **No etcd dependency:** it starts independently of the registry and reads manifests
  from its workspace mount.

Startup gates (logged, fail closed) are: the configured runtime is registered, and if it
is `runsc` a trivial container starts under it; `RUNNER_IMAGE` exists locally (the runner
never pulls); the socket is `0660` for the app gid; `TRELLIS_UID`/`TRELLIS_GID` name a
non-root user; every runtime a manifest declares is registered; and the host-path canary
passes. Use `python scripts/runner_preflight.py` with the runner's environment to see each
gate without fighting a restart loop.

### `TRELLIS_HOST_WORKSPACE` must be the host path

Docker resolves every bind mount for a tool container against the **host** filesystem,
so the runner needs to know where its `/app/workspace` actually lives:

```bash
# .env
TRELLIS_WORKSPACE_DIR=../my-org-workspace/workspace   # what compose mounts
TRELLIS_HOST_WORKSPACE=/srv/trellis/my-org-workspace/workspace   # absolute host path
```

Pointing it at a container path (`/app/workspace`) is the classic mistake. The startup
canary writes a marker through the runner's view and reads it back through the host
path; a mismatch refuses to serve, with:

```text
TRELLIS_HOST_WORKSPACE='/app/workspace' must be the HOST path of the workspace (the
directory that is mounted at /app/workspace inside the runner); pointing it at a
container path makes every bind mount resolve to the wrong files.
```

The check re-runs on `SIGHUP` and every `RUNNER_REAP_INTERVAL_S` seconds (default 300).
A failed re-check stops new calls (`runner_path_mismatch`) rather than running a tool
against the wrong tree.

### Network policy

A manifest's `network:` has exactly two values:

| Value | Container network |
| --- | --- |
| `egress` (default) | Docker's **default bridge**: whatever route and resolvers the host has |
| `none` | No network at all: no route, no loopback, no resolver |

There are no network profiles, no host firewall rules, no CONNECT proxy and no generated
`resolv.conf`. `core/execution/netprofiles.py`, `scripts/setup-network-profiles.sh`,
`scripts/egress_proxy.py`, `scripts/generate_egress_acl.py`,
`docker-compose.egress*.yml` and the `DOCKER-USER` rules they installed were removed in
v0.7.1, together with `TRELLIS_INTERNAL_CIDRS`, `TRELLIS_ENGINE_SUBNETS`,
`TOOLS_INTERNAL_DNS` and the `TOOLS_NET_*_SUBNET` pair. The v0.6 profile names `allow`,
`internet` and `internal` still load as `egress` with one deprecation warning per distinct
value per process; `deny`/`off` load as `none`, and an unrecognized value falls back to
`none`. A workflow's `config.yaml` is validated at sync time, so an unknown value there
stops `db-sync` instead.

The console `execute` container is always `none`, and the `runner` itself runs with
`network_mode: "none"`; neither has an option to change that.

**Why the default bridge.** Under `runsc`, Docker's embedded resolver (`127.0.0.11`) on a
user-defined network is unreachable: container-name and external lookups both time out. The
default bridge works because Docker copies the host's real upstream resolvers into the
container's `resolv.conf`, and that is the only reason tool, MCP and workflow containers
ride it. Two consequences:

- Containers on the default bridge can reach **each other** by IP, so one tool container is
  not isolated from another at layer 3.
- Engine services are not on the default bridge (compose puts them on the project network),
  so a tool cannot resolve `host`, `hub`, `relay`, `etcd` or `redis` by service name.
  Published front-door ports remain reachable through the host's bridge gateway, which is
  the same exposure any container on that bridge has.

The accepted risk that follows from this is stated in [Security notes](#security-notes);
`network: none` is the only per-tool containment this release offers.

### Sizing

Each concurrent tool call is a container with its own memory/CPU/pids limits
(`limits:` in `tool.yaml`; defaults 512 MiB, 1.0 CPU, 256 pids). Budget:

```text
runner RAM ≈ RUNNER_MAX_CONTAINERS × typical memory_mb × 1.5
```

The 1.5 factor covers gVisor's own overhead and page cache, which is charged to the
container's cgroup. With the defaults (32 global × 512 MiB) plan for ~24 GiB before you
raise `RUNNER_MAX_CONTAINERS`; lower the global or per-tool caps on a small host
(`RUNNER_MAX_CONTAINERS`, `RUNNER_MAX_CONTAINERS_PER_TOOL`). Remember that a tool's
`tmpfs_mb` counts against its `memory_mb` (validators keep `tmpfs_mb ≤ memory_mb / 2`).
Image layers are shared, so the first pull dominates disk, not per-call cost.

A workflow run holds one of those global slots for its whole duration
(`WORKFLOW_RUN_TIMEOUT`, default `3600` s), so size the cap for scripted workflows and
interactive calls together.

## Security notes

- **Accepted network risk.** With `network: egress`, a tool container can reach anything the
  Docker host can reach: the internet, the host's private networks and internal services on
  its routing table, and the cloud metadata endpoint (`169.254.169.254`). There is no
  per-destination allowlist or egress filter in this release. Treat every tool manifest as a
  statement about what that tool may reach, set `network: none` on anything that does not
  call an external API, and review tool code the way you review a service account.
- **`runsc` is the isolation boundary.** It is the only thing between a tool container and
  the host kernel. A production deployment must not run on `runc`.
- **Secrets are not container configuration.** They arrive through the `trellis-exec` stdin
  preamble, so `docker inspect` shows none of them. See
  [Secrets never in container configuration](#secrets-never-in-container-configuration).
- **Tool access rules gate tools; the console is separate.** `workspace/policies/tool_access.yaml`
  narrows who may call a hub, edge or MCP tool, and it can only narrow what an agent's
  allowlist already grants. Of the console tools, only `execute` passes through it; the file
  tools (`ls`, `read_file`, `write_file`, `edit_file`, `glob`, `grep`) stay in the host
  process, rooted at `reports/<agent>`, and are constrained by the agent's console
  allowlist alone. `execute` itself runs in a throwaway container with no network and an
  empty `/workspace`.
- **Identity comes from the token.** No request body carries a caller identity, and a token
  is enforced by default (`ENFORCE_AGENT_TOKENS=enforce`). Keep `DEV_MODE=false` on anything
  shared.
- **Workspace ownership.** Tool containers run as `${TRELLIS_UID}:${TRELLIS_GID}` with all
  capabilities dropped, a read-only root filesystem and `no-new-privileges`. That uid must
  own the workspace tree, or a tool cannot write under `output/` or `reports/`.

The infrastructure checks behind these statements:

| Proof | Covers |
| --- | --- |
| `docker-compose.ci-isolation.yml` (self-hosted host with `runsc` registered) | What a real gVisor tool container can see, write and reach: `tests/live -m runsc`, including "no egress under `network: none`". |
| `.github/workflows/sandbox-smoke.yml` → job `Sandbox smoke` | The same container contract end to end on the runtime every dev machine has (`runc`): build the stack, run `scripts/sandbox_smoke.py --tool text_stats`. |

## Smoke checks after a deploy

```bash
docker compose ps                       # every service up; db-sync exited 0
curl -sI localhost                      # front door answers through nginx
docker compose exec host curl -sf http://127.0.0.1:8000/health
docker compose exec hub curl -s http://127.0.0.1:8001/healthz   # liveness only
docker compose exec runner python -m core.execution.runner --healthcheck
#   ^ probes /v1/healthz over the socket with RUNNER_TOKEN: runtime, image, canary
docker compose logs db-sync             # sync counts, tool-access policy line
# The container execution contract, end to end (needs the runner + Docker).
docker compose exec hub python scripts/sandbox_smoke.py --tool text_stats
docker compose exec host python scripts/trellis logs --limit 5
```

The runner's `/v1/healthz` is the place to look when tool calls fail: it reports the
runtime, the image and the host-path canary separately, and a failing gate refuses new
calls with a specific code instead of running a tool against the wrong tree. The hub's own
`/healthz` is only a liveness probe; chat-only agents keep working while the runner is
down.

