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
as you would for any other directory. The `hub` service stays root on purpose (it runs the
bubblewrap sandbox); this does not affect the other services.

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
the embeddings model configured in **Admin → Global Tool Configuration**. Changing
`AGENT_EMBEDDING_MODEL` invalidates every previously stored agent embedding. Re-embed by
rebuilding / re-running the registry sync (a `docker compose up -d --build`, or
`python scripts/trellis sync` from inside a container) so `search_agents` works again. Until
then, semantic search falls back to keyword matching.

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
