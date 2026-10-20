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

Docker Engine with the Compose v2 plugin is the only host dependency — the prebuilt image bundles the full toolchain (Python, Node, Go), so no language runtimes are needed on the host. The host kernel and LSM decide which sandbox backend can run tools; the hub probes both at startup and reports the verdict at `/healthz` (`backend`, `code`, `remediation`):

| Host | bwrap | Landlock | Support |
| --- | --- | --- | --- |
| Rootful Docker, AppArmor relaxed (`apparmor=unconfined`) | ✅ | ✅ | **Primary path**; both backends covered by the `smoke` matrix job on Ubuntu 24.04 |
| Rootful Docker + the `deploy/apparmor/trellis-hub` profile | ✅ | ✅ | Policy-compliance alternative for orgs that ban unconfined profiles; **validated under enforcement** by the `apparmor` CI job on Ubuntu 24.04 |
| AppArmor locked, SELinux disabled, rootless Docker / userns-remap | ❌ | ✅ | **Supported, auto-fallback**; covered by the `sandbox-smoke` CI job on Ubuntu 24.04 |
| SELinux enforcing (RHEL/CentOS/Fedora) | ❌ | ✅ | **Not certified** — needs a real-host validation |
| Kernel < 5.13, or Landlock blocked by an LSM/seccomp policy | ❌ | ❌ | Unsupported; `/healthz` returns 503 with a diagnosis |

In every supported case the hub container runs as `${TRELLIS_UID:-1000}` — the operator uid that owns the workspace — not root. The matrix is about the host kernel and LSM, not the container uid.

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
  ghcr.io/laraibkazi92/trellis-agent-platform:v0.3.0 \
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
TRELLIS_IMAGE=registry.internal.example.com/trellis-agent-platform:v0.3.0
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
git clone --branch v0.3.0 https://github.com/laraibkazi92/trellis-agent-platform.git
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
| `TRELLIS_IMAGE` | Optional | Pins the engine image tag or digest, e.g. `ghcr.io/laraibkazi92/trellis-agent-platform:v0.3.0`. |
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
- **Tool sandbox.** Every tool invocation runs in one of two sandbox backends, selected once at hub startup (`core/sandbox.py`): `auto` (the default) prefers **bwrap** and falls back to **Landlock** when bwrap cannot run. The hub container itself runs as `${TRELLIS_UID:-1000}` — the operator uid that owns the bind-mounted workspace — drops all capabilities (`cap_drop: [ALL]`, no `cap_add`), and keeps `no-new-privileges`.
  - **bwrap** is the stronger isolation and stays the default wherever it works. Each tool gets a read-only bind of `/`, a read-write bind of `/app/workspace`, a private tmpfs `/tmp`, a fresh `/proc`, and its own user, PID, IPC, and UTS namespaces, with every capability dropped (`--cap-drop ALL`). To build that root bwrap calls `mount(2)` and `pivot_root(2)`, which it performs with the `CAP_SYS_ADMIN` it receives inside its own user namespace — so the container needs **no capabilities** (`cap_drop: [ALL]`, empty `cap_add`), only `seccomp=unconfined` (Docker's seccomp profile blocks `pivot_root`), `systempaths=unconfined` (bwrap mounts a fresh `/proc`), and **`apparmor=unconfined`**: AppArmor is independent of seccomp, and Docker's `docker-default` profile contains `deny mount,`, which blocks every tool's first bind mount. Orgs that forbid unconfined profiles can use the shipped `deploy/apparmor/trellis-hub` profile instead (see below). Tools with `network: none` additionally get `--unshare-net`: a private network namespace with no interfaces, so even loopback is unreachable. The preflight probes that separately (`evidence.bwrap_netns`): a host that refuses netns creation keeps the bwrap verdict healthy but warns `netns_denied`, because only `none` tools are affected.
  - **Landlock** is the unprivileged fallback: a static helper (`/usr/local/bin/trellis-sandbox`) confines filesystem writes (`/` read-only; `/app/workspace` and a per-run `TMPDIR` writable), installs a syscall deny-list unless `SANDBOX_SECCOMP=off`, and runs the tool as `SANDBOX_UID` (default: the hub's own uid) with capabilities cleared. Because that is the hub's identity by default there is no uid drop to perform; the helper only drops identity when it starts privileged (a root hub). It creates no namespaces and needs no mounts, so it works under `docker-default`, SELinux, and rootless Docker. Tools with `network: none` run with `--deny-net`, which handles Landlock's TCP connect/bind rights without granting any — deny-all, loopback included — and, while the seccomp deny-list is at its default `on`, also refuses AF_INET/AF_INET6 datagram and raw socket creation via seccomp; it requires Landlock ABI 4+ (Linux 6.7+). On an older kernel such a tool exits 65 (`landlock_net_unsupported`) instead of running with network access.
  - **Same identity in both backends.** bwrap maps the hub's uid 1:1 inside its namespaces (it does not switch to root), so tools run as `${TRELLIS_UID}` with `CapEff=0`; Landlock runs them as `SANDBOX_UID`, which defaults to the same uid. Files they create under `/app/workspace` are operator-owned — the same ownership contract as the rest of the stack.
  - **Filesystem permissions.** Tools run as the workspace owner, so normal writes work: in both backends a tool can create files in an operator-owned `0755` directory under `/app/workspace`. Use `$TMPDIR` for scratch that should not survive the run.
  - **Landlock limitations.** It restores filesystem blast-radius control and privilege separation, not bwrap's process isolation. `/proc` is shared; the hub and its tools run as one uid, so Yama `kernel.yama.ptrace_scope >= 1` is what keeps another process's environment out, and the hub returns 503 when the scope is 0 or missing. `/tmp` is shared too: each run gets a `0700` directory, but tools share one uid, so **never write secrets there**. `/dev/shm` is not writable, so POSIX shared memory (numpy/torch multiprocessing) fails. `/dev/ptmx` is not granted, so PTY allocation fails (`pexpect`, `node-pty`, `script`). `truncate` on a read-only file is unconfined at Landlock ABI 2 (Debian 12). At ABI >= 6, signal scoping makes `kill -0` on a process outside the sandbox return `EPERM` instead of `ESRCH`. `network: none` denies TCP connect/bind through Landlock, and the helper's seccomp filter additionally refuses AF_INET/AF_INET6 datagram and raw socket creation (`EACCES`), closing the UDP/raw gap on ABI 4–6. That second half is the deny-list: with `SANDBOX_SECCOMP=off` the policy is TCP-only, and a UDP socket is created normally — use bwrap (`--unshare-net`) for tools that must have no IP network when the filter is disabled. bwrap's `--unshare-net` remains the stronger policy: the tool gets no interface at all, independent of the filter.
  - **Fallback.** If tool execution still fails with bwrap/userns errors on an exotic host, add back only `SYS_ADMIN` to the hub — the sole capability the container may need. Never re-add `SETUID`/`SETGID`/`CHOWN`: on a non-root hub they would grant privilege escalation rather than enable a uid drop. Replacing the hub's `cap_drop`/`security_opt` block with `privileged: true` remains a worse last resort; it removes every container-level control above, so treat it as a temporary host workaround and record why.

The AppArmor profile is `docker-default` with its `deny mount,` replaced by `mount,`, `pivot_root,` added (bwrap's final step into its root is mediated separately from mount rules), and `userns,` added at `abi <abi/4.0>,` so the rule is mediated. It is not a hardening win over `apparmor=unconfined` — it is the policy-compliance option. It is **validated under enforcement** by the `apparmor` job in `.github/workflows/sandbox-smoke.yml`: an Ubuntu 24.04 GitHub-hosted runner VM (AppArmor enabled in the kernel, AppArmor 4.0 userspace, Docker's `docker-default` available, `apparmor_restrict_unprivileged_userns=1`) loads the profile host-side with `apparmor_parser -r -K`, then runs the full stack plus the sandbox smoke harness with `security_opt: apparmor=trellis-hub` — once with `auto` selecting bwrap, once with the Landlock fallback forced. The ABI 4.0 pin needs AppArmor 4.0 userspace; Ubuntu 22.04's parser cannot compile this profile, but 22.04 has no unprivileged-userns restriction, so `apparmor=unconfined` remains the supported posture there. It is not used when the hub keeps `apparmor=unconfined`. Install it on the **host** — profiles load on the host kernel, not inside the container — and select it for the hub:

```bash
sudo install -m 0644 deploy/apparmor/trellis-hub /etc/apparmor.d/trellis-hub
sudo apparmor_parser -r /etc/apparmor.d/trellis-hub
```

```yaml
    security_opt:
      - "apparmor=trellis-hub"
```

### CI validation

`.github/workflows/sandbox-smoke.yml` runs two kernel/LSM-facing jobs on `ubuntu-24.04` — an Ubuntu 24.04 GitHub-hosted runner VM, with AppArmor enabled in the kernel and Docker's `docker-default` profile active:

| Job | Proves |
| --- | --- |
| `smoke` (`bwrap` + `landlock` matrix legs) | The default path (`auto → bwrap`) works with `apparmor=unconfined`; the fallback works when the container is confined by `docker-default`; the native helper suite passes. |
| `egress` (egress changes, dispatch, PR) | The opt-in egress override removes the hub's default network, the CONNECT proxy allows an allowlisted name and denies a sibling name and an IP literal, and `NO_PROXY` covers the framework services. |
| `apparmor` (sandbox changes, `workflow_dispatch`, nightly) | The shipped `deploy/apparmor/trellis-hub` profile loads and confines the hub (`apparmor=trellis-hub`, label asserted at runtime) with no `apparmor=unconfined`, and both bwrap and the forced Landlock fallback pass the full smoke harness. |

### Sandbox settings and rollback

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

## Egress mode (opt-in)

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

`NO_PROXY` is load-bearing: tools call the framework API at `FRAMEWORK_API_URL=http://host:8000`, and the hub talks to etcd. Those names must bypass the proxy, which is why the override lists `etcd,redis,host,hub,gateway,taskiq-worker,localhost,127.0.0.1,::1`.

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
docker compose exec hub trellis-sandbox --version
# Egress mode only: topology, allowlist, IP-literal guard, NO_PROXY.
docker compose exec hub python scripts/sandbox_smoke.py --check-egress
docker compose logs db-sync             # sync counts
docker compose exec host python scripts/trellis logs --limit 5
```

`/healthz` returning 503 is a real sandbox diagnosis (`code` + `remediation`), not a dead deployment: the hub is up, chat-only agents keep working, and only local tool calls fail until the cause is fixed. The verdict is cached at startup and re-probed after a classified tool failure marks it stale (one probe set at a time, at most once per minute), so a host fixed under a running hub is re-checked on the next health check or tool call. The limit is one-directional: a hub that started with a failing verdict keeps it until restarted, because nothing invalidates a verdict that never let a tool run. Fix the host, then restart the hub (`docker compose up -d hub`) to re-probe.
