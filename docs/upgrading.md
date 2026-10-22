# Upgrading Trellis

How an operator upgrades the Trellis **engine** (this repo) to a new release, and what
per-version hazards to check first.

This guide assumes the recommended split layout: the engine is cloned and pinned to a
release tag, and your agents/tools/workflows/mcps live in a separate content checkout
pointed at by `TRELLIS_WORKSPACE_DIR` (see `.env.example` → *Deployment Layout*). If you
run with the default `./workspace` inside this clone, the same steps apply, but be aware
that your content is then inside the tree you check out tags into.

---

## Versioning & the compatibility promise

Releases are tagged `vMAJOR.MINOR.PATCH`. `v0.2.0` is the first release.

| Surface | Status |
| --- | --- |
| `workspace/` layout — `agents/`, `tools/`, `workflows/`, `mcps/`, `shared/` | Public API |
| Tool protocol — JSON arguments on `stdin`, JSON results on `stdout` | Public API |
| Agent `config.yaml` / `skills.md`, `tool.yaml`, `mcp.yaml` manifests | Public API |
| `docker-compose.yml` services, `.env` keys, registry sync behavior | Stable, but changes are announced per release below |
| Internal modules under `core/`, module import paths, `scripts/` internals | Not stable |

During 0.x, **breaking changes may land in minor releases** (e.g. `0.2` → `0.3`). Every
breaking change is listed in the per-release notes below. Pin the engine to a release tag;
`main` is upstream development and may contain unreleased breaking changes.

Because the workspace layout and the tool protocol are the API-facing part of the engine,
your content repo is expected to keep working across engine upgrades. If a release requires
a change on your side, it is called out explicitly.

---

## Standard upgrade procedure

Run from the engine clone:

```bash
git fetch --tags
git describe --tags            # note the tag you are on now, for rollback
git checkout v0.4.1            # target release tag
docker compose pull            # fetch the multi-arch app image for that tag
docker compose up -d           # recreate services; nginx-gateway is built from ./gateway
```

Notes:

- `docker compose pull` fetches the app image published to GHCR
  (`ghcr.io/laraibkazi92/trellis-agent-platform:vX.Y.Z`). The `nginx-gateway` service has no
  remote image — it is built locally from `./gateway` on `up`.
- If you build from source instead of pulling (`TRELLIS_IMAGE` unset or overridden), use
  `docker compose up -d --build`; that ignores the image default and builds locally.
- The `db-sync` init container runs on every start and re-syncs your workspace into etcd.
  An engine upgrade therefore does **not** touch your content repo, and does not touch users,
  API keys, or run history in etcd. It does rewrite the registry entries derived from your
  workspace, so the registry always reflects the current state of your content checkout.
- `.env` is not managed by the upgrade. Keep your existing `.env`; diff it against the new
  `.env.example` for added/removed keys. New optional keys have working defaults.
- There is no app-side schema migration: framework runtime state lives in etcd, so the only
  migrations are the per-release ones listed below.

---

## Rollback

```bash
git checkout v0.2.1            # previous tag
docker compose pull
docker compose up -d
```

Rolling back the engine code and images is safe for your content and etcd data, with two
caveats:

1. **State migrations are one-way.** The etcd 3.5 → 3.6 storage migration cannot be undone by
   checking out an older tag (see below). Snapshot before upgrading, or you cannot go back.
2. **Volume state is not versioned.** Volumes (`etcd-data`, `health-data`, `hindsight-data`)
   persist across tag changes. A rollback does not restore an older schema or older embedding
   data; do not rely on rollback to fix a bad data migration.

Pin the tag you are rolling back *from* before you upgrade (`git describe --tags`), so the
rollback command is unambiguous.

---

## Per-release notes

These apply when moving **onto** the listed release. They also already apply to deployments
created before that release that are running the current images (the etcd minor and the
Hindsight image pin changed in `main` ahead of the tag).

### v0.2.0

| Area | Hazard |
| --- | --- |
| etcd | 3.5 → 3.6 storage migration is one-way. Snapshot first. |
| Container user | Changing `TRELLIS_UID`/`TRELLIS_GID` leaves existing volumes owned by the old uid. |
| Agent memory | Changing Hindsight embeddings model or dimensions after first use breaks recall. |
| Agent search | Changing `AGENT_EMBEDDING_MODEL` invalidates stored agent embeddings; re-embed. |
| Hindsight image | Server image tag must match `hindsight-client` in `requirements.txt`. |

#### etcd 3.5 → 3.6 storage migration (one-way)

The compose stack pins `gcr.io/etcd-development/etcd:v3.6.x`. Upgrading an existing 3.5 data
directory in place is supported, but **one-way**: once the data dir has been migrated to the
3.6 storage version, rolling back to a 3.5 image requires a snapshot/restore. Pulling the
older image and restarting is not enough.

Snapshot before you upgrade:

```bash
# take the snapshot, then copy it off the etcd-data volume
docker compose exec etcd etcdctl snapshot save /tmp/pre-upgrade.db
docker compose cp etcd:/tmp/pre-upgrade.db ./pre-upgrade-etcd.db
```

Keep that file outside the clone and off the `etcd-data` volume, since a snapshot that only
exists inside the volume is lost with the volume. Snapshot *before* the first start on the
new etcd image; a snapshot taken after migration no longer restores a 3.5-compatible state.

#### Changing `TRELLIS_UID` / `TRELLIS_GID`

The app containers run as `TRELLIS_UID:TRELLIS_GID` so files written into the bind-mounted
workspace are owned by you instead of root. Two consequences when you change these values:

- Files already in the bind-mounted workspace are still owned by the **old** uid/gid.
- The `/app/data` health volume inherits its ownership when it is **first created**. If it
  already exists root-owned, the new uid cannot write to it.

Remove **only** the health volume and recreate:

```bash
docker compose down
docker volume rm "$(basename "$PWD")_health-data"
docker compose up -d
```

Do **not** use `docker compose down -v` here. That also deletes the `etcd-data` volume,
which holds users, API keys, and run history.

Fix workspace file ownership on the content checkout (outside Docker) with `chown`/`chmod`
as you would for any other directory. The `hub` service runs as `${TRELLIS_UID:-1000}` like
the rest of the app containers; this does not affect the other services.

#### Hindsight embeddings: model, provider, or dimensions

Agent memory is backed by Hindsight. Its embedding provider, model, and output dimension are
set in `.env` (`HINDSIGHT_EMBEDDINGS_PROVIDER`, `HINDSIGHT_EMBEDDINGS_MODEL`,
`HINDSIGHT_EMBEDDINGS_DIMENSIONS`) and materialized into the `hindsight-data` volume on first
use.

Change any of these **before** the first use of the new setting. If you change them after
data exists, stored vectors have the old dimension and recall breaks on a mismatch. To
recover, wipe the volume and start clean:

```bash
docker compose down
docker volume rm "$(basename "$PWD")_hindsight-data"
docker compose up -d
```

This deletes stored memories. There is no in-place re-embedding path; re-embedding happens
by starting fresh.

For reference, `gemini-embedding-2` supports output dimensions 128–3072 (recommended 768 /
1536 / 3072) and auto-normalizes truncated dimensions; `gemini-embedding-001` is text-only.
The embeddings provider value for Gemini/Google is `google`, not `gemini`.

#### `AGENT_EMBEDDING_MODEL` and semantic agent discovery

Semantic agent discovery (`search_agents` / `auto_select`) indexes agents at sync time using
the embeddings model selected in **Admin → Limits & Tuning** (`agent_embedding_model`) and the
Google key configured in **Admin → LLM Providers**. Changing `AGENT_EMBEDDING_MODEL`
invalidates every previously stored agent embedding. Re-embed by rebuilding / re-running the
registry sync (a `docker compose up -d --build`, or `python scripts/trellis sync` from inside
a container) so `search_agents` works again. Until then, semantic search falls back to
keyword matching.

#### Hindsight server image vs. `hindsight-client`

The Hindsight server image tag and the `hindsight-client` pin in `requirements.txt` must
match. This is a single upstream monorepo that publishes the Python client and the server
image together under the same version number, and consecutive minor releases include real
API-surface changes. On each engine upgrade, confirm the two agree:

```bash
grep hindsight-client requirements.txt
grep 'ghcr.io/vectorize-io/hindsight' docker-compose.yml
```

The image is the `-slim` variant (no bundled local ML models, relies on the Gemini API for
LLM and embeddings). Because of that, the `local` reranker is unavailable and the default is
`rrf` (Reciprocal Rank Fusion passthrough).

### v0.2.1 — 2026-10-18

Changes since `v0.2.0`.

#### LLM provider expansion (pydantic-ai 2.57.0)

Existing agents and etcd data keep working; the only action is a rebuild so the new
dependencies are installed.

- **Dependencies:** `requirements.txt` now pins `pydantic-ai[huggingface]==2.57.0` and
  `google-genai==2.31.0` (was `pydantic-ai==2.31.0` / `google-genai==2.18.1`). Do not keep
  the old `google-genai` pin: it breaks Google model dispatch. Rebuild with
  `docker compose up -d --build`.
- **No etcd migration.** Provider credentials are still one flat dict at
  `/identities/system/system/llm_keys`. The existing `GEMINI_API_KEY`, `GOOGLE_API_KEY`,
  `OPENAI_API_KEY`, and `ANTHROPIC_API_KEY` entries keep their names and precedence, and
  the four legacy `provider` values still resolve.
- **New page.** Provider keys are no longer on the tool/MCP secrets page; they live on
  **Admin → LLM Providers** — one card per provider. The tool-secrets page keeps tool/MCP
  secrets and variables. The keys for the 11 new providers (DeepSeek, Fireworks AI, Together AI,
  Moonshot AI, Vercel AI Gateway, Z.AI, OpenRouter, Alibaba, Ollama, LiteLLM, Hugging Face)
  are set there.
- **`openai-compatible` key name:** `OPENAI_COMPATIBLE_API_KEY` is the preferred name;
  `OPENAI_API_KEY` is still accepted, so deployments that never set the new name keep
  working.
- **Ollama needs a base URL.** pydantic-ai 2.57 refuses to guess one, and Trellis always
  passes an explicit value; it defaults to `http://localhost:11434` and can be overridden
  per agent or globally on the new page (`OLLAMA_BASE_URL`).
- **`base_url` is now honoured for `google`/`openai`/`anthropic`.** The old resolver ignored
  a per-agent `base_url` for these three (it only mattered for `openai-compatible`). A stale
  endpoint left on an existing agent will now be used — remove it if it was not intentional.
  Providers that cannot take an endpoint (`deepseek`, `openrouter`, …) reject one with a clear
  error instead of silently dropping it.

#### Framework LLM defaults

An admin can now set one org-wide default provider + model in **Admin → LLM Providers →
Framework defaults**. Agents and background workflows that leave both `provider` and `model`
blank inherit it; the value lives only in etcd and is never written into an agent's YAML.

- **Behaviour change — call this out.** An agent or workflow with `model` blank used to build a
  model with an **empty id** and fail on the first request. It now resolves — either to the
  admin's framework default, or, when nothing is configured, to `google` / `gemini-2.5-flash`.
  A config that has never served a request may therefore start running (and billing). This only
  affects configurations that were already broken; a fully-specified agent is unchanged.
- **A provider with a blank model now resolves** to that provider's registry default (e.g.
  `deepseek` → `deepseek-chat`) instead of failing. `openai-compatible` still requires an
  explicit model — it has no registry default.
- **`litellm` endpoint default.** A `litellm` agent, workflow, or framework default with no
  `base_url` now resolves to `http://localhost:4000`. Previously no endpoint was passed at all,
  and the underlying OpenAI SDK silently fell back to `https://api.openai.com/v1` — sending the
  gateway credential to a host the operator never chose. Set `base_url` explicitly when the
  LiteLLM proxy runs elsewhere; `localhost` inside the host container is only reachable in the
  same network namespace.
- **Workflow schema widening.** `AgentUpdateModel.model` is now optional, so background agents
  can be saved with a blank model (inherit). This is a widening only: every existing stored
  workflow keeps its model and is unaffected.
- **New etcd keys, no migration.** The default lives at
  `/config/framework/default_llm_provider`, `/config/framework/default_llm_model`, and
  `/config/framework/default_llm_base_url`. All three are empty by default, and empty means
  today's behaviour apart from the case-E fallback above.
- **Rules decider pairing.** An admin provider override with a blank model now persists that
  provider's registry default instead of pairing the override with the environment
  `RULES_EVALUATION_MODEL` (which could egress to the wrong vendor). Deployments that set only
  `RULES_EVALUATION_MODEL` with no provider override are unchanged.
- **Endpoint environment residual.** Trellis always passes a configured `base_url` explicitly
  to the provider SDK, but for a provider that supports an endpoint and has **no** configured
  `base_url` — neither per-agent, nor the framework default, nor a global store — the SDK may
  still read its own endpoint environment variable (for example `OPENAI_BASE_URL`). Set the
  endpoint explicitly if you do not want that fallback.

### v0.3.0 — 2026-10-20

Changes since `v0.2.1`: tool sandboxing, per-tool network policy, and opt-in egress mode. The
`TRELLIS_IMAGE` default moves to `v0.3.0`; `docker compose pull && docker compose up -d`
recreates the hub with the new posture.

#### Tools now run inside a sandbox

The hub probes two backends at startup and picks **bwrap** where it works, otherwise
**Landlock**. `/healthz` reports the verdict (`backend`, `code`, `remediation`).

- **Filesystem:** `/` is read-only, `/app/workspace` read-write, `/tmp` a private tmpfs
  (nothing persists), `/var/tmp` and sensitive paths such as `/etc/shadow` denied. A tool that
  wrote outside the workspace now fails with `Permission denied` — move its data under
  `/app/workspace` or into the tool directory.
- **Identity:** the hub and its tools run as `TRELLIS_UID` with no capabilities
  (`cap_drop: [ALL]`). See the root-owned files section below.
- **Limits:** 8 MiB stdout / 256 KiB stderr per call, 4 GB address space, 600 s CPU, 64 MB
  file size, and `pids_limit: 1024` per container.
- **Docker options:** the hub requires `seccomp=unconfined`, `systempaths=unconfined`, and
  `apparmor=unconfined` (shipped in `docker-compose.yml`). Removing them breaks bwrap.
- **Ubuntu 24.04:** `apparmor_restrict_unprivileged_userns=1` refuses user namespaces to
  unconfined containers, so bwrap is unavailable and the hub falls back to Landlock
  automatically. To keep bwrap, install `deploy/apparmor/trellis-hub` (requires AppArmor 4.0
  userspace; validated in CI) or relax the sysctl.
- **Kernel support:** Landlock needs ABI 3+ (Linux 6.2+). With neither backend available,
  tool calls fail closed and `/healthz` reports why.

#### Root-owned files in the workspace from the old root-hub posture

The hub and its tools now run as `TRELLIS_UID` with no capabilities (`cap_drop: [ALL]`, no
`cap_add`). That applies to tool subprocesses too: under bwrap they are no longer uid 0
inside their namespaces. Deployments that previously ran the hub as root may therefore have
root-owned files and directories under `/app/workspace` that bwrap tools created as uid 0.

What you see: a tool that used to work now fails with `Permission denied` when writing to
one of those paths (the tool can read them, since world-readable, but not create or replace
entries). The failure is DAC, not the sandbox — the same write would fail for any
non-root user.

Remedy, outside Docker, on the host that holds the bind mount:

```bash
# whole workspace (simplest)
sudo chown -R "$TRELLIS_UID:$TRELLIS_GID" ./workspace
# or only the offending trees, e.g.
sudo chown -R "$TRELLIS_UID:$TRELLIS_GID" ./workspace/tools/foo/data
```

Also confirm `SANDBOX_UID`/`SANDBOX_GID` match the hub uid — they default to
`TRELLIS_UID`/`TRELLIS_GID`, and a non-root hub cannot drop to a different identity, so a
mismatch means Landlock tools run as an identity that does not own the workspace.
`SANDBOX_UID` no longer defaults to a separate "tool" identity; on the default deployment it
is the hub's own uid.

Rollback to the root-hub posture (removing the hub's `user:` line and restoring the old
capabilities) is only justified when a host cannot run bwrap as a non-root user at all — it
reintroduces the privilege-separation problem this migration removed. See
[deploy.md](deploy.md#sandbox-settings-and-rollback).

#### Per-tool network policy

`tool.yaml` gains `network: allow|none` (default **allow**). `none` gives the tool no IP
network at all: bwrap uses a private network namespace; Landlock denies TCP connect/bind and
a seccomp rule refuses UDP/raw sockets. Loopback is blocked as well.

- Set `network: none` on every tool that does not call an external API — that is the cheapest
  exfiltration control available.
- `SANDBOX_NET_DEFAULT=none` flips the default for tools that do not set the field.
- `SANDBOX_SECCOMP=off` weakens `none` to TCP-only under Landlock (UDP/raw become reachable);
  the hub warns at startup. Keep seccomp on.

#### Opt-in egress mode

`docker-compose.egress.yml` moves the hub onto an internal-only network whose only route out
is a CONNECT proxy that connects to domains declared in `tool.yaml` `egress:`. It is off by
default. Enable it with `COMPOSE_FILE` in `.env`; see
[deploy.md](deploy.md#egress-mode-opt-in) for enabling, rollback, and the v1 limits (union
allowlist, Node clients ignoring proxy variables, etcd still reachable from tools).

#### Probe lifecycle

`/healthz` re-probes and re-selects after a classified sandbox failure (at most once per
minute), so a host change is picked up without a restart. This is one-directional: a hub that
started with no working backend still needs one restart after the host is fixed.

#### Upgrade actions

1. `docker compose pull && docker compose up -d` — recreates the hub with the new user,
   capabilities, limits, and healthcheck.
2. Check `/healthz`: `ok: true` and the expected `backend`; if not, the payload carries a
   `code` and `remediation`.
3. Fix root-owned workspace files if the previous deployment ran the hub as root (section
   above).
4. Audit tools: move writes into `/app/workspace`, and add `network: none` where no external
   API is used.

---

### v0.4.0 — 2026-10-21

Changes since `v0.3.0`: edge nodes (`trellis-proxy`), so tools can run on a host that only
dials out. The `TRELLIS_IMAGE` default moves to `v0.4.0`. The central side (`edge-relay`
service plus the `/edge` route) ships in the same compose file, and **edges themselves are
opt-in** — an install that never enrolls one keeps behaving exactly as it did on `v0.3.0`.

#### What an edge is

A `trellis-proxy` node runs this same image on the host where the tools live and opens an
**outbound-only** tunnel to the central install. No inbound port and no VPN. The hub treats
the edge's tools as ordinary tools: they appear in the registry as `<site>__<tool>`, run
under the same sandbox policy *on the edge*, and their files stay on the edge host.

- New service: `edge-relay` (central side, internal port 8100) — nginx routes `/edge` to it.
- New admin page: **Admin → Edges** — site enrollment, live connections, revocation.
- Enrollment: create a site in the UI, copy its token to the edge host. Authoring and the
  protocol are in [proxy.md](proxy.md); the edge-side compose file is `deploy/proxy/`.
- Edge tools are written into etcd by the relay and marked `managed_by: edge-relay`. The
  registry sync (`scripts/sync_to_db.py`) **preserves** those entries — they never exist on
  central disk, so without that carve-out every `db-sync` would delete every remote tool.
  An undecodable edge config fails closed rather than being pruned.
- TLS for the tunnel (either terminating on the main nginx or in a dedicated `/edge`
  terminator): [proxy-tls.md](proxy-tls.md). Note the fail-loud caveat there — a wrong
  `EDGE_MTLS_CA` path stops nginx, taking the UI and API down with `/edge`, not just `/edge`.

#### New `.env` keys (all optional, defaults shown)

| Key | Default | Purpose |
| --- | --- | --- |
| `EDGE_RELAY_URL` | compose service name | hub → relay address, for a split-host install |
| `EDGE_TOOL_RECONCILE_SECONDS` | `10` | how often the hub re-reads relay-published tools (`0` disables) |
| `EDGE_AUDIT_LOG` | `/app/data/edge-audit.log` | relay audit trail (inside `health-data`, 10 MB × 5) |
| `EDGE_RATE_LIMIT_PER_MIN` / `_RPS` / `_BURST` | `120` / `30` / `20` | per-site call budget; a site record can override the per-minute value |
| `EDGE_MTLS_CA` | unset | CA bundle for edge client certs; requires `SSL_ENABLED=true` |
| `TRELLIS_VERSION` | the release tag on a pulled image; `dev` on a local build | reported in the edge hello frame and **Admin → Edges** |
| `EDGE_DEV_SITE` / `EDGE_DEV_TOKEN` | unset | **DEV ONLY**, ignored unless `DEV_MODE=true`; plaintext, no rotation, no audit |

#### Upgrade actions

1. `docker compose pull && docker compose up -d` — pulls `v0.4.0` and starts `edge-relay`.
2. **Rebuild the edge proxy:**
   ```bash
   docker compose build nginx-gateway
   docker compose up -d --no-build --no-deps nginx-gateway
   ```
   The `/edge` routes live in `gateway/entrypoint.sh`, which is built locally rather than
   pulled, so `pull` alone leaves the old entrypoint in place and `/edge` returns 404.
   **Do not** use `docker compose up -d --build nginx-gateway`: `--build` on `up` also
   builds every service with a `build:` section in that service's dependency graph, so it
   replaces the image you just pulled with a local build — verified on a live host, the app
   image then reports `TRELLIS_VERSION=dev` and carries no attestation.
3. Confirm `/healthz` is still `ok: true` with the backend you expect, and that
   **Admin → Edges** renders.
4. Only if you want edges: deploy `deploy/proxy/` on the edge host and enroll a site
   (step-by-step in [proxy.md](proxy.md#enrollment)).

Changes to declare:

- **Compose services:** added `edge-relay`; `nginx-gateway` gained `/edge` routes (rebuild
  required, see step 2). No ports added on the host.
- **`.env` keys:** added, all optional and defaulted (table above).
- **Registry sync:** preserves `managed_by: edge-relay` tools; ignores undecodable edge
  configs instead of pruning them.
- **Tool protocol / `workspace/` layout:** none.
- **Data migrations:** none. etcd gains `<site>__<tool>` entries only when a site enrolls.
- **Image pins:** unchanged (etcd, Redis, Hindsight).

---

### v0.4.1 — 2026-10-21

Documentation-only release. No code, image content, compose service, `.env` key, or registry
behavior changed since `v0.4.0`; the only functional difference is the `TRELLIS_IMAGE` default,
which moves to `v0.4.1`.

It exists because the `v0.4.0` **tag** shipped upgrade instructions telling you to run
`docker compose up -d --build nginx-gateway`. That command builds every service with a
`build:` section in that service's dependency graph, so it does not just rebuild the edge
proxy — it replaces the app image pulled from GHCR with a local build that reports
`TRELLIS_VERSION=dev` and carries no attestation. The fix landed on `main` right after
`v0.4.0`; this tag re-ships it so the instructions you read from the tag are correct.

**If you already upgraded to `v0.4.0`:** nothing is broken. Check what your app image is:

```bash
docker image inspect "${TRELLIS_IMAGE:-ghcr.io/laraibkazi92/trellis-agent-platform:v0.4.0}" \
  --format '{{index .RepoDigests 0}}'
```

- `@sha256:fc37e6c8…` (or any digest that is not the image ID itself) — you are on the released
  image. No action.
- An empty `RepoDigests` or a digest equal to the image ID — that is a local build. Restore
  the released artifact with `docker compose pull && docker compose up -d`, and rebuild the
  proxy with the two-step form:

  ```bash
  docker compose build nginx-gateway
  docker compose up -d --no-build --no-deps nginx-gateway
  ```

**Upgrade from `v0.4.0`:** `docker compose pull && docker compose up -d`, then the two-step
proxy rebuild above if you have not already done it. The `v0.4.0` notes otherwise apply
unchanged.

- **Compose services:** none changed.
- **`.env` keys:** none added or removed.
- **Registry sync / tool protocol / data migrations:** none.
- **Image pins:** `TRELLIS_IMAGE` default → `v0.4.1` (identical image content to `v0.4.0`,
  different build, so it has its own digest and attestation).

---

### v0.5.0 — 2026-10-22

Changes since `v0.4.1`: an edge can now export **MCP servers** over the same outbound
tunnel, caller identity reaches the edge, edge tool/MCP environments are scoped to
declared keys, and credentials can live per user on the edge. The compose files now
default `TRELLIS_IMAGE` to `v0.5.0`, so `docker compose pull && docker compose up -d`
moves an install that does not pin its own tag; if you do pin one, update it (see
[Standard upgrade](#standard-upgrade-published-images)).

Everything is additive for an install that never enrolls an edge, but several behaviour
changes can bite silently. Read all seven under
[Behaviour changes to announce](#behaviour-changes-to-announce); the three most likely to
break an existing deployment are the edge **env allowlist** (undeclared variables stop
being inherited), 4-part edge MCP tool names, and a site that is already `public: true`
now also exposing its MCP tools.

#### Upgrade order: central first, then edges

The wire protocol moves to `proto: 2`. The handshake stays strict, so ordering matters:

| Central | Edge | Result |
| --- | --- | --- |
| v0.5 | v0.4.x | **Supported.** Tools work unchanged; the relay sees `caps=["tools"]`, no MCPs; MCP calls answer `404` |
| v0.4.x | v0.5 | **Clean refusal.** `CLOSE_VERSION` (close code `4001`) at the handshake; the edge logs one terminal "version mismatch — upgrade central first" line and retries only at the maximum backoff (60 s, jittered) |
| v0.5 | v0.5 | Full feature set |

Upgrade **central first**, verify it is healthy, then upgrade edge VMs one at a time. A
v0.5 edge pointed at an old central is not broken silently — it stops at the handshake
and says so — but it does stop serving until central is upgraded.

#### Standard upgrade (published images)

```bash
git fetch --tags
# The compose files default TRELLIS_IMAGE to v0.5.0, so this pulls the release image:
docker compose pull
docker compose up -d
```

If you pin `TRELLIS_IMAGE` in `.env`, repoint it at the new tag (or digest) first —
otherwise you keep running whatever you pinned.

No new nginx route lands in `v0.5.0`: a `v0.4.x` gateway already proxies `/edge`. If you
do rebuild it (for example you are coming from an older tag), use the two-step form:

```bash
docker compose build nginx-gateway
docker compose up -d --no-build --no-deps nginx-gateway
```

**Never `docker compose up -d --build` on a published-image box.** `--build` on `up`
builds every service with a `build:` section in the service's dependency graph, replacing
the image you just pulled with a local build that reports `TRELLIS_VERSION=dev` and
carries no attestation. The two-step proxy rebuild is the supported form, same as
`v0.4.0`/`v0.4.1`.

Building from source (`TRELLIS_IMAGE` unset or overridden) is the one case where
`docker compose up -d --build` is correct.

#### New `proxy.yaml` keys (edge only, all optional)

| Key | Default | Purpose |
| --- | --- | --- |
| `env_passthrough` | `false` | `true` restores the v0.4 denylist env (tunnel token still stripped) |
| `mcps_dir` | `workspace/mcps` | where this edge's `mcp.yaml` files live |
| `export_mcps` | `[]` | allowlist: bare name or mapping `{name, include_tools, exclude_tools, credential_mode, session_ttl_minutes, max_sessions}` |
| `secrets_dir` | `edge-secrets` | shared credential store, `<tool-or-mcp>.env` |
| `user_secrets_dir` | `edge-user-secrets` | per-user store, `<normalized-email>.env` |

`exports` entries also accept the mapping form `{name, credential_mode}` (a bare name
means `shared`). `mcp.yaml` gains `network: allow|none` (default `allow`, stdio only;
`http`/`sse` ignore it). An unknown value warns and falls back to `allow` rather than
dropping the config.

New edge env vars, each an override for the key above: `TRELLIS_EDGE_ENV_PASSTHROUGH`,
`TRELLIS_EDGE_MCPS_DIR`, `TRELLIS_EDGE_SECRETS_DIR`, `TRELLIS_EDGE_USER_SECRETS_DIR`.
No new `.env` keys on central. Values that are not valid are ignored/warn — they never
fail startup.

#### Compose and volume changes

Central: **nothing new**. `edge-relay` and the `/edge` route already exist since
`v0.4.0`; the same service now routes MCP calls.

Edge (`deploy/proxy/docker-compose.yml`): the sample now mounts the three new
directories. If you maintain your own edge compose file, add the equivalents:

```yaml
volumes:
  - ./workspace:/app/workspace
  - ./workspace/mcps:/app/workspace/mcps           # mcps_dir (part of workspace, listed explicitly)
  - ./proxy.yaml:/etc/trellis/proxy.yaml:ro
  - ./edge-secrets:/etc/trellis/edge-secrets       # shared service accounts
  - ./edge-user-secrets:/etc/trellis/edge-user-secrets   # per-user, written by the CLI
```

- Create both credential directories `0700`, owned by `TRELLIS_UID`, before starting.
- The credential stores must live **outside** the sandbox-writable workspace: tool code
  runs as the same uid and can read whatever the workspace exposes, so a per-user store
  inside it hands every caller every other caller's password.
- `mcps_dir` defaults to `workspace/mcps` and is only read at publish time. If the MCP
  manifests are not part of the workspace checkout, point `mcps_dir:` at a separate
  mount instead (`/etc/trellis/mcps`).
- **stdio MCP sessions need a writable sandbox root.** Each session's `HOME`/`TMPDIR`
  lives under it (`mcp-sessions/`), so a `:ro` workspace is fine for tools but not for an
  edge that exports stdio MCP servers.

#### Behaviour changes to announce

1. **Env allowlist (the biggest silent break).** An exported tool or stdio MCP server no
   longer inherits the edge container's environment. It sees a fixed base
   (`PATH`, `HOME`, `LANG`, `TZ`, `TMPDIR`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`,
   `SSL_CERT_FILE`, `LC_*`, `TRELLIS_*`) plus only the keys its `tool.yaml`/`mcp.yaml`
   declares (`secrets`, `optional_secrets`, `variables`, `secret_groups` fields).
   A tool reading an undeclared variable silently sees it unset — declare the key, or set
   `env_passthrough: true` and restart the proxy to restore v0.4 behaviour (minus the
   token; `SIGHUP` cannot apply it).
2. **CA-bundle variables are not in the allowlist.** `REQUESTS_CA_BUNDLE`,
   `CURL_CA_BUNDLE` and `SSL_CERT_DIR` must be declared by any tool/MCP server that needs
   them (only `SSL_CERT_FILE` is always present). A corporate base image that set just
   those will start failing TLS calls after the upgrade.
3. **Edge MCP tool names are 4-part** — `mcp__<site>__<mcp>__<tool>`. An agent that lists
   an edge MCP tool in `allowed_tools` must use that form.
4. **Central MCP names may not contain `__`.** The separator is what distinguishes an
   edge MCP from a central one. Such a name is now rejected when saved (`ValueError`) and
   warned-and-skipped by the registry sync. Rename before upgrading if you wrote one by
   hand.
5. **`public: true` on a site now also exposes its MCP tools.** Site visibility used to
   cover tools only. Review public sites before an edge starts exporting MCP servers.
6. **`SIGHUP` retires every live MCP session.** Credentials for a session are resolved
   once at creation, so the signal is how an edited credential file takes effect without
   waiting out the idle TTL. The next call reopens the session (no error), which costs the
   user one re-login. Tunnel reconnects do **not** retire sessions.
7. **Session directories for email users move once.** They are now keyed by a normalized
   email (`sha256` of the lowercased address), so directories written by a build that
   keyed the raw address are orphaned: those users log in once more. Nothing else reads
   the old directories; they can be deleted.

#### Preparing edge credentials before switching a mode

Default `shared` needs nothing beyond the files. Do these **in order** before setting any
`credential_mode` (per entry in `exports`/`export_mcps`):

1. Create and mount the `secrets_dir` / `user_secrets_dir` volumes (above).
2. Populate the shared file for each exported tool or MCP server —
   `<secrets_dir>/<tool-or-mcp>.env`, mode `0600`:
   ```bash
   install -m 600 /dev/null ./edge-secrets/devops-cli.env   # then edit it
   ```
3. Provision each operator who will use a `per_user`/`per_user_required` entry:
   ```bash
   docker compose exec -T trellis-proxy \
     python core/proxy.py user-secrets set ops@example.com \
     --config /etc/trellis/proxy.yaml <<'EOF'
   DEVOPS_USERNAME=ops
   DEVOPS_PASSWORD=...
   EOF
   ```
4. **Then** set `credential_mode` and `SIGHUP`. Switching to `per_user_required` before
   step 3 makes every call for an unprovisioned user fail closed with
   `no credentials for <email> on edge <site>`.

`user-secrets list` prints key names only, so it is safe to paste into a ticket. Verify
with `SIGHUP` and one real call per user; credentials never cross the tunnel, so nothing
appears centrally to check.

#### Enabling MCP export

Add `export_mcps:` to the edge's `proxy.yaml` and `SIGHUP` — the catalog republishes
without a restart (a stdio server with no static `tools:` block is discovered live, 20 s
per server, concurrently). Verify in **Admin → Edges**: the site shows `proto 2`, the
`mcp` capability badge, and one row per server. If a server is missing, the edge log names
it — the usual causes are a name colliding with a central MCP, an oversized schema, or a
hello frame over the 10 MiB cap (the largest catalogs are dropped, tools stay online).

#### Node MCP servers and sandbox limits

Set `SANDBOX_RLIMIT_AS_MB=8192` for stdio MCP servers written in Node — the `4096`
default is tight and an allocation failure looks like a crash. `SANDBOX_RLIMIT_CPU_S`
counts **consumed** CPU, so the 600 s default does not retire an idle long-lived session.
Both apply to the Landlock backend only; see
[deploy.md → Sandbox settings and rollback](deploy.md#sandbox-settings-and-rollback).

#### Rollback

- **Revert central to `v0.4.x`:** v0.5 edges stop at the handshake (`CLOSE_VERSION`). That
  is safe and visible; their tools go offline until central is restored. Nothing on the
  edge is corrupted.
- **Revert only the edges:** central keeps serving, including its tools. A reverted edge
  advertises `caps=["tools"]`, and central **keeps** the leftover `/registry/mcps/*`
  entries rather than pruning them on an empty catalog, so agents that list
  `allowed_mcps: ["<site>__<mcp>"]` still see those tools but every call answers the
  `404` from the failure table. They are pruned by the next v0.5 publish from that site.
- **Restoring central while edges are newer** is the safer direction; the reverse
  (old central, new edge) is the one that refuses.

Changes to declare:

- **Compose services:** none added or removed on central. Edge compose gains volumes for
  `mcps_dir`, `secrets_dir`, `user_secrets_dir`.
- **`.env` keys:** none added centrally. Edge gains four `TRELLIS_EDGE_*` overrides
  (optional); `SANDBOX_RLIMIT_AS_MB=8192` recommended for Node MCP servers.
- **Registry sync:** `/registry/mcps/` is preserved for `managed_by: edge-relay` entries,
  like `/registry/tools/`; a reference to a not-yet-connected edge warns instead of
  failing.
- **Tool protocol / `workspace/` layout:** unchanged. `mcp.yaml` gains optional
  `network:`; `proxy.yaml` gains five keys; edge MCP tool names are 4-part.
- **Data migrations:** none in etcd. One-time move of edge MCP session directories for
  email users (one re-login).
- **Image pins:** `TRELLIS_IMAGE` default moves `v0.4.1` → `v0.5.0` in `docker-compose.yml`,
  `.env.example` and both egress compose files. If you pin a tag or digest in `.env`,
  update it yourself — the default only applies when `TRELLIS_IMAGE` is unset.

---

## Release checklist (maintainer template)

Copy this into the release PR/notes and fill it in per release.

```markdown
### vX.Y.Z — YYYY-MM-DD

- [ ] Tag created: `vX.Y.Z`; CHANGELOG / release notes written.
- [ ] CI published multi-arch images to GHCR
      (`ghcr.io/laraibkazi92/trellis-agent-platform:vX.Y.Z`).
- [ ] `TRELLIS_IMAGE` default in docker-compose.yml updated to the new tag.
- [ ] Upgrade instructions re-read **from the tag**, not from `main`
      (`git show vX.Y.Z:docs/upgrading.md`) — a doc fix that lands after tagging does not
      reach anyone who checks out the tag.
- [ ] Fresh-clone smoke test: `cp .env.example .env && docker compose up -d`, agent call over
      REST and `/mcp` both succeed, `db-sync` completes.
- [ ] Upgrade smoke test: previous tag → this tag via `docker compose pull && up -d`.

Changes to declare (state "none" where nothing changed):

- Compose services: added / removed / renamed / changed healthchecks, ports, volumes, caps.
- `.env` keys: added (defaulted?), renamed, removed.
- Registry sync (`scripts/sync_to_db.py`): new manifest fields, prune-guard behavior,
  categories scanned.
- Tool protocol / `workspace/` layout: any change is BREAKING — describe the migration.
- Data migrations: etcd storage version, embeddings model/dimensions, volume ownership.
- Image pins: Hindsight server tag vs. `hindsight-client`, etcd minor.
```
