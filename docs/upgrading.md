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
git checkout v0.2.0            # target release tag
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
git checkout v0.2.0            # previous tag
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

---

## Release checklist (maintainer template)

Copy this into the release PR/notes and fill it in per release.

```markdown
### vX.Y.Z — YYYY-MM-DD

- [ ] Tag created: `vX.Y.Z`; CHANGELOG / release notes written.
- [ ] CI published multi-arch images to GHCR
      (`ghcr.io/laraibkazi92/trellis-agent-platform:vX.Y.Z`).
- [ ] `TRELLIS_IMAGE` default in docker-compose.yml updated to the new tag.
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
