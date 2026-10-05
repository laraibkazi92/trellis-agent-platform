# CLI Guide

`scripts/trellis` is an operator CLI for the small day-to-day operations that don't need the Dashboard UI or `docker compose`: scaffolding a workspace, syncing the registry, and inspecting recent agent runs. Only `init` runs on the stdlib alone — `sync` (via `scripts/sync_to_db.py`, which imports `yaml` and `core.auth`) and `logs` (via `core.auth`) need the framework's dependencies installed, so run them with the project's Python (virtualenv or framework container).

Run it with the project's Python:

```bash
python scripts/trellis --help
```

## `init` — scaffold a workspace

```bash
python scripts/trellis init [PATH]   # PATH defaults to the current directory
```

Creates the standard workspace layout under `PATH`:

```text
PATH/
└── workspace/
    ├── agents/
    ├── tools/
    ├── mcps/
    ├── workflows/
    └── shared/
```

Each subdirectory gets a `.gitkeep` placeholder. If no `.env` exists in `PATH`, the repo's `.env.example` is copied there as a starting point and the CLI prints a reminder to fill it in. `init` never overwrites anything — anything that already exists is reported and left untouched, so it is safe to re-run.

## `sync` — push the filesystem into the registry

```bash
python scripts/trellis sync
```

Delegates to `scripts/sync_to_db.py`'s `main()` (identical behavior to `python scripts/sync_to_db.py`): it walks `workspace/agents`, `workspace/workflows`, `workspace/tools`, and `workspace/mcps`, writes configs to etcd, and deletes registry entries whose source directories are gone. It connects using `ETCD_HOST`/`ETCD_PORT` (defaults `127.0.0.1:2379`).

In normal operation the compose `db-sync` init container does this for you on `docker compose up -d --build`; the CLI form is for running it on demand against an already-running etcd.

## `logs` — inspect recent agent runs

```bash
python scripts/trellis logs [AGENT] [--limit N]
```

Reads run records (`/runs/<agent>/<run_id>` in etcd) via the framework's `IdentityManager` (`core.auth.get_identity_manager()`), using the same `ETCD_HOST`/`ETCD_PORT` environment variables as the rest of the framework.

- **Without AGENT**: one summary line per run for every registered agent — short `run_id`, `state`, `updated_at`, and the first ~60 characters of the run's error/output/prompt (first one present wins).
- **With AGENT**: detailed blocks for that agent's runs, with one line each for state, timestamps, prompt, output, and error.
- `--limit N` caps how many runs are shown **per agent** (default 20; runs are newest-first).

Example:

```text
$ python scripts/trellis logs --limit 3
ticket-agent:
  a1b2c3d4  completed  2026-10-05T09:41:12+00:00  Summarize and close the oldest triage ticket...
  e5f6a7b8  failed     2026-10-05T08:03:55+00:00  connection refused while calling issues API
```

`logs` is read-only and fails fast: each etcd read is capped at ~5 seconds, so an unreachable etcd produces an actionable error and exit code 1 rather than hanging.

## Version

```bash
python scripts/trellis --version
```
