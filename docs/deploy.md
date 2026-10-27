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
> default bridge (`network: egress`) or no network (`none`). Sections below that still
> describe the v0.6 machinery — *Sandbox settings and rollback*, *Hardened Landlock-only
> variant*, *Network profiles*, *Egress mode* — carry a **Removed in v0.7.1** note and are
> kept as history until the v0.7.1 docs pass rewrites them. Follow
> [upgrading.md → v0.7.1](upgrading.md#v071--in-development-breaking) instead.

## Prerequisites

Docker Engine with the Compose v2 plugin is the only host dependency — the prebuilt image bundles the full toolchain (Python, Node, Go), so no language runtimes are needed on the host. Every tool call is a container started by the `runner` service, so the only host-side question is which OCI runtime is registered: `runsc` (gVisor) where it is installed, `runc` otherwise (`CONTAINER_DEFAULT_RUNTIME`). `GET /v1/healthz` over the runner's socket reports the verdict.

> The v0.6 backend matrix (bwrap / Landlock per host kernel and LSM) no longer applies: since
> v0.7.1 the container runner is the only execution path, so the host only needs Docker plus
> the runtime the runner uses — `runsc` (gVisor) in production, `runc` on a dev machine
> (`CONTAINER_DEFAULT_RUNTIME`). What a tool container can see is proven by the runsc
> isolation harness (`docker-compose.ci-isolation.yml`, self-hosted with runsc registered)
> and, on `runc`, by the `Sandbox smoke` workflow.

In every supported case the hub container runs as `${TRELLIS_UID:-1000}` — the operator uid that owns the workspace — not root, and tool containers run as that same uid.

## Install path A: pull prebuilt images (recommended)

The released images are public on GHCR, multi-arch (`linux/amd64` + `linux/arm64`), and need no login:

```bash
docker compose pull
docker compose up -d
```

> If a pull ever asks for credentials, the GHCR package has not been made public: either set its visibility to public in the repo's package settings, or `docker login ghcr.io` with a token that has `read:packages`.

### Pinning and verifying a release

`TRELLIS_IMAGE` in `.env` pins a **tag** (`:v0.4.0`) because a tag stays readable in a diff. Tags are mutable, so if you need the image to be byte-identical forever, pin the **digest** published in that release's workflow summary instead:

```bash
TRELLIS_IMAGE=ghcr.io/laraibkazi92/trellis-agent-platform@sha256:<digest>
```

Every release published after provenance was wired up is attested by GitHub's keyless signer, which proves the image was built by `.github/workflows/publish-images.yml` from the commit its tag points at. Verify a pulled image with the GitHub CLI (no signing key, no registry login — the attestation is stored next to the image):

```bash
gh attestation verify oci://ghcr.io/laraibkazi92/trellis-agent-platform:v0.4.0 \
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
  ghcr.io/laraibkazi92/trellis-agent-platform:v0.4.0 \
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
TRELLIS_IMAGE=registry.internal.example.com/trellis-agent-platform:v0.4.0
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
git clone --branch v0.4.0 https://github.com/laraibkazi92/trellis-agent-platform.git
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
| `TRELLIS_IMAGE` | Optional | Pins the engine image tag or digest, e.g. `ghcr.io/laraibkazi92/trellis-agent-platform:v0.4.0`. |
| `TRELLIS_UID` / `TRELLIS_GID` | Optional | Container uid:gid for workspace file ownership. Defaults to `1000:1000`. |
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
    └── shared/
```

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
git fetch --tags
git checkout v0.x.y
docker compose pull
docker compose up -d
```

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
- **Tool sandbox.** Every tool invocation is its own container, started by the `runner`
  service (`runsc` in production, `runc` on a dev machine — see
  [Execution isolation](#execution-isolation-v06)). The hub container runs as
  `${TRELLIS_UID:-1000}` — the operator uid that owns the bind-mounted workspace — and drops
  all capabilities (`cap_drop: [ALL]`, empty `cap_add`, `no-new-privileges`), because no tool
  process runs inside it any more. A tool container gets only the mounts its manifest
  declares, `network: egress` (Docker's default bridge) or `none`, and the cgroup limits from
  `limits:`. **`runsc` is the isolation boundary**: it is the only thing between a tool and
  the host kernel, so a production deployment must not run on `runc`.

**v0.7.1:** the in-process backends (`bwrap`, `Landlock`, the `trellis-sandbox` helper) and
the shipped `deploy/apparmor/trellis-hub` profile were deleted. The hub needs no relaxed LSM
profile — nothing executes in it — and the v0.6 `smoke`/`apparmor`/`egress` CI jobs are gone
with the backends they proved. The proofs that a tool container is real are now:

| Proof | Covers |
| --- | --- |
| `docker-compose.ci-isolation.yml` (self-hosted host with `runsc` registered) | What a real gVisor tool container can see, write and reach — `tests/live -m runsc`, including "no egress under `network: none`". |
| `.github/workflows/sandbox-smoke.yml` → job `Sandbox smoke` | The same container contract end to end on the container runtime every dev machine has (`runc`): build the stack, run `scripts/sandbox_smoke.py --tool text_stats`. |

### Sandbox settings and rollback

> **Removed in v0.7.1.** Every variable in the table below is gone — nothing in the code
> reads `SANDBOX_*` any more (setting one is ignored, not honoured) — and there is no
> backend to roll back to: the container runner is the only execution path. Per-tool
> `container_runtime: runsc | runc` is the only sandbox-related manifest knob left, and
> `CONTAINER_DEFAULT_RUNTIME` the only deployment-wide one.

| Variable | Default | Effect |
| --- | --- | --- |
| `SANDBOX_BACKEND` | `auto` | `auto` (bwrap, then Landlock), `bwrap`, or `landlock`. An invalid value warns and behaves as `auto`. |
| `SANDBOX_SECCOMP` | `on` | Landlock helper's syscall deny-list. `off` passes `--no-seccomp`; use it if the filter breaks a runtime. The same filter is what refuses UDP/raw IP sockets under `network: none`, so with `off` that policy denies TCP connect/bind only and a tool can still reach the network over UDP (documented warning at startup). |
| `SANDBOX_NET_DEFAULT` | `allow` | Deployment-wide network policy for tools: `allow` or `none`. A tool's own `network:` in `tool.yaml` overrides it. `none` gives the tool no network at all (loopback included) — bwrap via `--unshare-net`, Landlock via `--deny-net` on ABI 4+. An invalid value warns and falls back to `allow`. |
| `SANDBOX_UID` / `SANDBOX_GID` | the hub's own uid (compose: `${SANDBOX_UID:-${TRELLIS_UID}}`, default `1000`) | uid/gid Landlock tools run as (and own the per-run `TMPDIR`). `0` is rejected. **This uid must own the `/app/workspace` tree**, otherwise Landlock tools cannot write there. On a non-root hub it must equal the hub's uid — there is no privileged helper to drop to a different one. bwrap is unaffected: it maps the hub uid 1:1 inside its namespaces. |
| `SANDBOX_TMP_ROOT` | `/tmp/trellis` | Parent for per-run tmpdirs; created `0711`. Point it at a larger filesystem if `/tmp` is small. Compose forwards it to the hub; empty means the default. |
| `SANDBOX_RLIMIT_AS_MB` | `4096` (4 GiB) | Address-space cap for each tool, **Landlock backend only**. `0` disables the limit. |
| `SANDBOX_RLIMIT_CPU_S` | `600` | CPU-seconds cap for each tool, **Landlock backend only**. `0` disables the limit. |
| `SANDBOX_RLIMIT_NPROC` | disabled | Process/thread cap for the tool's uid, **Landlock backend only**. Off by default because it counts every process of that uid on the host (containers share the kernel uid table), so a shared operator uid sits near the limit; set it only when the sandbox uid is dedicated. The container's `pids_limit` is the per-container backstop. |
| `SANDBOX_RLIMIT_FSIZE_MB` | `64` | Largest file a tool may write (MiB), **Landlock backend only**. `0` disables the limit. |

These limits are `setrlimit(2)` calls made by the Landlock helper (`sandbox/trellis-sandbox.c`) just before `exec`, so they are inherited by everything the tool spawns and are much harder to raise after the sandbox drop. **They apply to the Landlock backend only**: the helper is not in bwrap's argv and the hub passes no rlimit flags to bwrap, so under bwrap nothing is capped per tool. The container's own limits are the backstop on that path — `pids_limit`, plus `mem_limit` or `deploy.resources` if you need a hard memory bound. A tool that exceeds `SANDBOX_RLIMIT_FSIZE_MB` is killed by `SIGXFSZ`; one that exceeds `SANDBOX_RLIMIT_AS_MB` fails the allocation with `ENOMEM`.

The backend and probe results are cached at startup, so apply any change with `docker compose up -d hub` (no rebuild needed). `SANDBOX_SECCOMP=off` must be set **before** the hub starts for the same reason: the preflight caches its verdict, including the helper argv it probes with.

Rollback levers, cheapest first: `SANDBOX_BACKEND=bwrap` (one env var, no rebuild), `SANDBOX_SECCOMP=off` (disables the syscall filter but keeps filesystem confinement), and re-adding only `SYS_ADMIN` to the hub's `cap_add` if a host needs it for bwrap.

To return to the old root-hub posture (for example, a host where bwrap can only set up its user namespace as root), delete the hub's `user:` line and restore the capabilities the root helper expects — `cap_add: [SYS_ADMIN, SETFCAP, SETUID, SETGID, CHOWN]` — then `docker compose up -d hub`. That is only needed when bwrap cannot start as the operator uid; it brings back the privilege-separation wart this migration removed (bwrap tools are uid 0 inside their namespaces, owned by root on the host, and Landlock relies on a setuid drop), so exhaust `SYS_ADMIN` alone and `SANDBOX_BACKEND=landlock` first.

### Hardened Landlock-only variant

> **Removed in v0.7.1.** There is no Landlock backend (and no `trellis-sandbox` helper) to
> pin any more. Hardening a deployment now means the runtime: `runsc` (the default), nobody
> else's data in the workspace, and `network: none` on tools that do not need egress.

If you never want bwrap's container-level exceptions, pin the Landlock backend. The helper only *adds* restrictions (it runs unprivileged, applies Landlock, and installs seccomp), so Docker's default seccomp and AppArmor profiles are **expected** to be fine — this variant is not exercised in CI yet, so validate it against your Docker version before standardising on it:

```yaml
    cap_drop: [ALL]
    security_opt:
      - "no-new-privileges:true"
    environment:
      SANDBOX_BACKEND: landlock
```

The base hub already runs as `${TRELLIS_UID}` with `cap_drop: [ALL]` and an empty `cap_add`, so this only removes the three `*=unconfined` options (`systempaths=unconfined`, `seccomp=unconfined`, `apparmor=unconfined`) that exist for bwrap. No capability is needed: the helper runs as the workspace owner, so keep `SANDBOX_UID` at its default (the hub's own uid) — a non-root hub cannot drop to a different uid. `security_opt` is a list, so a plain `docker-compose.override.yml` appends to the base values instead of replacing them — edit the hub block directly, or replace that list with Compose's `!override` tag (Compose 2.24+).

One caveat: `docker compose up --wait` fails when `/healthz` returns 503 — that is the intended signal, not a broken deploy. `host` depends on `hub` with `condition: service_started`, not `service_healthy`, so chat-only agents still start.

## Execution isolation (v0.6)

Since v0.6 every local tool call runs in its **own gVisor container**, created by a
dedicated `runner` service. The hub no longer forks tool subprocesses and no longer
needs a sandbox of its own: the compose default is `SANDBOX_BACKEND=container`, and the
in-process `auto`/`bwrap`/`landlock` backends are **local-development only**. Each
container sees its own toolkit directory read-only, `shared/` read-only, a sized tmpfs
for `/tmp`, and (only when the tool declares `output_dirs`) the calling agent's output
directory. The network is a deny-by-default profile.

### Secrets never in container configuration

Resolved secrets reach a tool only through a one-line stdin preamble
(`{"env": {...}}`) applied by `trellis-exec`, the shim the engine image installs at
`/usr/local/bin/trellis-exec` (derived images inherit it). `docker inspect` on a running
tool or MCP-session container therefore shows no declared secret — only fixed variables
such as `HOME`, `PATH`, `LANG` and `TRELLIS_USER_*` — while the process inside still reads
them from its environment. Everything after the preamble newline is the tool's own stdin,
so the JSON stdin/stdout protocol and MCP stdio framing are unchanged; a malformed
preamble makes the shim exit `78` before anything runs, and it never logs a key or value.
If you build a tool image from this one and override the entrypoint, keep that contract.

### Prerequisite: gVisor (`runsc`)

The runner refuses to start when its configured runtime is missing or cannot start a
trivial container — there is no silent fallback to `runc`.

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

   (The `storage.googleapis.com/gvisor/releases/release/latest/...` URLs printed in
   older guides return 404 for current releases; use the GitHub release assets.)

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

   `--network=sandbox` keeps networking in gVisor's netstack so the `DOCKER-USER`
   profile rules apply to the traffic that leaves the container. Do **not** add
   `--ignore-cgroups=true`: per-container `--memory`/`--cpus`/`--pids-limit` come from
   the manifest `limits:` block and need cgroups.

   Registering a runtime is one of the few daemon settings Docker reloads in place:
   after editing `daemon.json`, `sudo systemctl reload docker` is enough
   (`docker info --format '{{json .Runtimes}}'` shows it). A full restart also
   works but restarts every running container.

3. Prove it before starting the stack:

   ```bash
   docker info --format '{{json .Runtimes}}' | grep runsc
   docker run --rm --runtime=runsc hello-world
   ```

   Both must succeed. A per-tool `container_runtime: runc` in `tool.yaml` is the escape
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

Startup gates (logged, fail closed) are: the runtime is present *and* starts a trivial
container, `RUNNER_IMAGE` exists locally (the runner never pulls), the network-profile
rules verify, the socket is `0660` for the app gid, and the host-path canary passes. Use
`python scripts/runner_preflight.py` with the runner's environment to see each gate
without fighting a restart loop.

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

### Network profiles

> **Removed in v0.7.1.** There are no profiles and no host firewall rules. `network:` is
> `egress` (the default: Docker's default bridge — the container reaches whatever the host
> can, cloud metadata included) or `none`. The `internal`/`internet`/`allow` values load as
> `egress` with one deprecation warning per value; `deny`/`off` load as `none`. The table
> and scripts below describe the v0.6 deployment and are kept as history until the v0.7.1
> docs pass rewrites this section.

| Profile | Docker network | Subnet (default) | Egress policy |
| --- | --- | --- | --- |
| `none` | — (`network_mode: none`) | — | loopback only |
| `internal` | `trellis-tools-internal` | `172.31.241.0/24` | ACCEPT `TRELLIS_INTERNAL_CIDRS` + the resolver in `TOOLS_INTERNAL_DNS`; DROP everything else |
| `internet` | `trellis-tools-internet` | `172.31.240.0/24` | ACCEPT public; DROP RFC1918, CGNAT, link-local, multicast, metadata, engine subnets |

`tool.yaml`'s `network:` defaults to `none`; legacy `allow` maps to `internet`. On top
of the per-profile policy, `DOCKER-USER` drops — for every profile — cloud metadata
(`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`, `169.254.169.123`), the host
bridge gateway, and every compose network in `TRELLIS_ENGINE_SUBNETS` (etcd, redis,
hub, relay, host). The rules are matched on the profile networks' CIDRs so they also
cover gVisor netstack traffic exiting through the Docker bridge.

Create the networks and rules once per host, as root:

```bash
sudo scripts/setup-network-profiles.sh            # networks + rules (idempotent)
sudo scripts/setup-network-profiles.sh --verify   # exit non-zero if anything is missing
```

The two tool networks are created by this script, not by `docker compose`, because they
need pinned subnets and `enable_icc=false`; they are deliberately absent from the
compose `networks:` block. Re-run `--verify` after a reboot, a firewall reload, or a
Docker upgrade (Docker recreates `DOCKER-USER` empty), and from provisioning before
`docker compose up -d`. The runner performs the same check at startup. `--teardown`
removes only the rules, which is useful for tests.

For a tool that needs to reach an internal API or SSH, add the destination to
`TRELLIS_INTERNAL_CIDRS` (comma-separated) and give it `network: internal`. SSH is L3
traffic, so a CIDR is enough — hostname allowlists still need the opt-in CONNECT proxy
from [Egress mode](#egress-mode-opt-in).

**Name resolution.** gVisor cannot reach Docker's embedded resolver (`127.0.0.11`),
which Docker writes into the resolv.conf of every container on a user-defined network,
so `getaddrinfo` fails inside every network profile by default. The runner therefore
generates a resolv.conf per profile and bind-mounts it read-only over the container's:

| Profile | Variable | Default |
| --- | --- | --- |
| `internet` | `TOOLS_INTERNET_DNS` | `1.1.1.1,8.8.8.8` |
| `internal` | `TOOLS_INTERNAL_DNS` | empty (no resolver) |

The file lives at `<workspace>/.runner-dns/<profile>.conf` (the workspace is the only
path both the runner and the Docker daemon can see) and contains resolver addresses
only. Set the variable to an empty string to keep Docker's file, or to a comma-separated
list of IPs to override it; entries that are not IP addresses are ignored with a warning.
An `internal` resolver must itself be inside an allowlisted `TRELLIS_INTERNAL_CIDRS`
entry, otherwise the profile's blanket deny drops the queries. Tools on `none` have no
network and therefore no DNS.

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

Rolling back to the in-process sandbox is `SANDBOX_BACKEND=auto` plus uncommenting the
hub's legacy `security_opt` lines; the runner service stays in the compose file, idle.
That path is for development hosts only — see [Sandbox settings and
rollback](#sandbox-settings-and-rollback).

## Egress mode (opt-in)

> **Removed in v0.7.1.** `docker-compose.egress.yml`, `docker-compose.egress-ci.yml`,
> `scripts/egress_proxy.py` and `scripts/generate_egress_acl.py` were deleted with the
> network profiles: tool containers get Docker's default bridge (`network: egress`) or no
> network at all (`none`), and no proxy, ACL or allowlist is involved. The commands below
> — including `sandbox_smoke.py --check-egress`, a flag that no longer exists — describe
> the v0.6 deployment and are kept only as history until the v0.7.1 docs pass rewrites this
> section. `network: none` is the only containment option now.

By default the hub — and therefore every tool it spawns — has the same unrestricted outbound access as any other container on `trellis-network`. Egress mode removes that: the hub gets a route to **one** CONNECT proxy and nothing else, and that proxy only connects to domains some tool declared in its `tool.yaml`. LLM providers are unaffected: those calls are made by `host`, which keeps its default-network route.

### Enable and disable

Egress mode is a compose override, and a committed override file is **not** auto-loaded. Enable it in `.env`:

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.egress.yml
```

or pass the files explicitly:

```bash
docker compose -f docker-compose.yml -f docker-compose.egress.yml up -d
```

> **The override is not sticky.** Any later plain `docker compose up -d` (with `COMPOSE_FILE` no longer set) silently drops it and puts the hub back on `trellis-network` with full outbound access. Keep `COMPOSE_FILE` in `.env` for as long as you want egress mode, and check `docker inspect tool-hub --format '{{json .NetworkSettings.Networks}}'` after every deploy.

> **Image requirement.** The proxy runs `scripts/egress_proxy.py` from the app image. `v0.3.0` is the first release that ships it; if you pin an older `TRELLIS_IMAGE` (or build from a pre-`v0.3.0` checkout), add `--build`.

What the override adds:

- `toolnet`, an `internal: true` network with no default route;
- the hub on `toolnet` **only** (`networks: !override`; Compose otherwise merges and keeps `default`);
- `host`, `gateway`, `taskiq-worker`, `etcd`, and `redis` on both networks — they still need to reach the hub, or be reached by it, by service name;
- `egress-proxy`, the only container on both `toolnet` and `default`, running `scripts/egress_proxy.py`;
- `HTTP_PROXY`/`HTTPS_PROXY` (and lowercase forms) plus `NO_PROXY` on the hub, which tools inherit.

`NO_PROXY` is load-bearing: the hub talks to etcd and the runner socket path must never be proxied. Those names must bypass the proxy, which is why the override lists `etcd,redis,host,hub,gateway,taskiq-worker,localhost,127.0.0.1,::1`.

### The allowlist

Each tool entry may declare the external domains it needs:

```yaml
- name: issues_fetch
  runtime: python
  entrypoint: fetch_issues.py
  egress:
    - api.example.com
    - "*.vendor.example"
```

The proxy container generates its allowlist at startup from the **union** of every `workspace/tools/**/tool.yaml`:

```bash
python scripts/generate_egress_acl.py                 # union on stdout
python scripts/generate_egress_acl.py --out FILE      # write it
python scripts/generate_egress_acl.py --check         # CI: validate only
```

Entries are stored as plain lowercase DNS suffixes; `example.com` covers the name itself and every `*.example.com`. Wildcards are accepted as input and normalized, parents are dropped (`api.example.com` disappears once `example.com` is present), and an invalid entry is fatal — the proxy container does not start, which fails closed. An empty union writes an empty file and prints a warning; the proxy then denies everything. There is no allow-all mode.

Restart the proxy after editing tool manifests: `docker compose restart egress-proxy`. A tool that needs a new domain is a content change plus that restart, not a rebuild.

### Guarantees

- **No direct route.** The hub is attached only to `toolnet` (`internal: true`), so a tool cannot open a TCP connection to the internet. `sandbox_smoke.py --check-egress` asserts this from inside the sandbox.
- **CONNECT allowlist.** The proxy accepts only `CONNECT host:port`; the port must be in `EGRESS_PORTS` (default `443`) and the host must match the generated suffix list. Anything else is `405`/`403`.
- **No IP literals, no private destinations.** A CONNECT to `1.2.3.4:443` is rejected before any lookup. Every resolved address is checked, and if any is private, loopback, link-local, reserved, unspecified, or multicast the tunnel is refused. Set `EGRESS_ALLOW_PRIVATE_DESTINATIONS=true` only for a CI mock or an on-prem API that genuinely lives on a private network.
- **DNS is a residual channel.** `internal: true` removes the default route, so TCP/UDP cannot leave. The embedded Docker resolver still forwards external name lookups from the host stack (the query carries the container's source address; there is no route check), so a compromised tool can encode data in query names if the host resolver reaches the internet. `network: none` closes this channel; otherwise treat external DNS as egress.
- **Bounded tunnels.** Connect timeout (10 s), idle timeout (60 s), absolute tunnel lifetime (600 s), and a concurrent-tunnel cap (64) are enforced; the cap answers `503`.

### Non-guarantees (v1)

- **The allowlist is a union, not per-tool.** Any tool can reach any domain any tool declared. A compromised tool cannot invent an endpoint, but it can talk to another tool's vendor. Per-tool enforcement needs proxy authentication and is the v2 refinement.
- **Tools still reach etcd and redis.** The hub shares `toolnet` with them (they must, for the registry and secrets), and tools share the hub's network namespace. `network: none` is the mitigation for tools that need no network at all; treat etcd/redis isolation as a separate platform concern.
- **Non-HTTP egress is blocked.** SSH, arbitrary TCP, and anything that is not `CONNECT` on an allowlisted port cannot work in egress mode. Raw sockets and UDP have no route either, because the only attached network is `toolnet` and it has no default route. That is intended.
- **Node `fetch`/`undici` ignore `HTTP_PROXY`** (and fail closed, because there is no direct route). Go tools built in the hub honour the proxy, so `proxy.golang.org` and any module host must be in the union if a tool imports third-party packages at build time. Python `requests`/`httpx` honour the env vars.
- **No TLS interception.** The proxy tunnels bytes; it cannot inspect or filter HTTP, and it does not cache.

### Rollback

Egress mode is one `-f` away from off, and no data is involved:

```bash
# 1. Remove COMPOSE_FILE from .env (or omit the -f flags).
# 2. Recreate the stack on the default network. --remove-orphans also deletes
#    egress-proxy, which is no longer part of the config and would otherwise
#    keep toolnet attached (and block step 3).
docker compose --remove-orphans up -d
# 3. toolnet has no members now; remove the leftover network by name.
docker network ls | grep toolnet
docker network rm <project>_toolnet
```

Order matters: `docker network rm` fails while the orphaned proxy container is still attached. A full `docker compose down` (without `-v`) also removes both, but stops the stack. Never use `down -v`: it deletes the `etcd-data` volume.

### Troubleshooting

- **`ENETUNREACH` / `EHOSTUNREACH` inside a tool** means it tried a direct connection: either the proxy is down (`docker compose logs egress-proxy`), or the domain is not in the union. The proxy log has one line per decision with `decision=deny reason=...`.
- **`403` from a client that sets `HTTPS_PROXY`** is the proxy refusing the target: `reason=not-allowlisted`, `port-not-allowed`, `ip-literal`, or `private-destination`. Regenerate the ACL (`docker compose restart egress-proxy`) after adding the domain.
- **`502`** means the name was allowlisted and public, but the upstream connect failed (timeout, refused).
- **Failures are fast, not timeouts.** If `NO_PROXY` was overridden, calls to `http://host:8000` fail immediately with `405` (plain HTTP through a CONNECT-only proxy) or `403 port-not-allowed` (if the client CONNECTs); nothing hangs. Compare `docker compose exec hub printenv NO_PROXY` with the value in `docker-compose.egress.yml`.
- **The hub lost its network after a deploy** means the override was dropped. Re-apply it and re-check the membership above.

```bash
docker compose ps                       # every service up; db-sync exited 0
curl -sI localhost                      # front door answers through nginx
docker compose exec host curl -sf http://127.0.0.1:8000/health
docker compose exec hub curl -s localhost:8001/healthz | python -m json.tool
# The container execution contract, end to end (needs the runner + Docker).
docker compose exec hub python scripts/sandbox_smoke.py --tool text_stats
docker compose logs db-sync             # sync counts
docker compose exec host python scripts/trellis logs --limit 5
```

`/healthz` returning 503 is a real sandbox diagnosis (`code` + `remediation`), not a dead deployment: the hub is up, chat-only agents keep working, and only local tool calls fail until the cause is fixed. The verdict is cached at startup and re-probed after a classified tool failure marks it stale (one probe set at a time, at most once per minute), so a host fixed under a running hub is re-checked on the next health check or tool call. The limit is one-directional: a hub that started with a failing verdict keeps it until restarted, because nothing invalidates a verdict that never let a tool run. Fix the host, then restart the hub (`docker compose up -d hub`) to re-probe.
