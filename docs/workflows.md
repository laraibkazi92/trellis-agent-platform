# Background Workflows: Consuming & Building

Background Workflows are asynchronous tasks that run without direct human interaction. They are triggered by cron schedules or inbound webhooks and can be either procedural scripts or LLM-powered agents.

> **Execution model.** A `background_script` pipeline runs as **one runner container per
> run** (mounts and environment in [How a script workflow runs](#how-a-script-workflow-runs)),
> and a `background_agent` is an ordinary agent run. A workflow's per-manifest `network:` is
> `egress` (the default, Docker's default bridge) or `none`. Tools a workflow declares still
> pass the [tool access rules](tools.md#tool-access-rules), and a workflow identity carries
> no groups.

---

## Consuming Workflows

### Triggering

**Automatic (Cron)**: Workflows with `trigger.type: cron` run automatically on their schedule after being synced. No further action is required.

**Automatic (Webhook)**: Workflows with `trigger.type: webhook` run whenever a correctly signed `POST` arrives at `http://localhost:8000/webhooks/<workflow-name>`. See [Webhook Triggers](#webhook-triggers) below.

**Manual**: Run a workflow on demand from the Dashboard UI (**Workflows → Run**, admin only). There is no REST endpoint for manual runs — the Run button enqueues the exact same task the scheduler would.

### Monitoring

View workflow run history, status, and logs in the Dashboard UI at **http://localhost:8080** under **Workflows**.

### Accessing Output

- **Reports**: Anything a script workflow writes to `workspace/reports/<workflow-name>/` shows up in the Dashboard UI under **Reports**.
- **Notifications**: Workflows that call `slack_post_message` or similar tools deliver results directly to the configured channel.

---

## Building Workflows

### Directory Structure

Workflows live in `workspace/workflows/`. Each workflow is a self-contained directory.

```text
workspace/workflows/
└── my-workflow/
    ├── config.yaml    # Type, triggers, model settings (if background_agent)
    ├── skills.md      # (background_agent only) LLM system prompt
    └── pipeline.py    # (background_script only) Procedural Python logic
```

Both workflow types require `config.yaml`. The second file depends on the type.

---

### Workflow Types

#### Script Workflows (`type: background_script`)

Use for deterministic, procedural tasks where LLM reasoning is not needed: data pipelines, report generation, metric aggregation.

```yaml
name: daily-report
version: 0.3.0
author: support-team@acme.com
description: "Compiles a comprehensive daily HTML report from open tickets."
type: background_script
runtime: python
entrypoint: pipeline.py
tags: ["summary", "daily", "reporting"]
trigger:
  type: cron
  expression: "0 18 * * *"   # Daily at 6:00 PM UTC
```

The `pipeline.py` is a **standard Python script**, not an agent and not the stdin/stdout
JSON protocol. It runs as a normal process inside one `runner` container per run, with
access to exactly the secrets and variables it declares (nothing is inherited from the
worker). What the container looks like is in
[How a script workflow runs](#how-a-script-workflow-runs).

`allowed_tools` is optional here and it is a **mount list**, not a per-call gate: only the
suites holding the tools it names are mounted (read-only). A suite with none of them is
absent from the container; a tool that shares a suite with a listed one is still present
and still runnable. The list is also the run's allowlist for the tool-access rules, so a
workflow that declares an edge tool or an MCP tool is legal even though there are no files
to mount for it.

The rendered trigger payload is evaluated against the workflow's `guardrails` before the script
starts, exactly like a `background_agent`'s input: a blocking rule marks the run `failed`
(`guardrail blocked input`) and no container is ever created. The rule format is the same one
documented for agents in the [Agent Guide](agents.md). Two consequences worth knowing: rules in
`/config/framework/guardrails_defaults` apply here too (a workflow with no `guardrails` key is
not exempt), and a `redact` rule rewrites the payload the script receives — scripts parse their
stdin as machine input, so prefer `block` for them. Script **stdout** is not inspected.

```python
# pipeline.py — example structure
import os
import sys

def main():
    # Secrets are injected as env vars (background context)
    issues_token = os.environ["ISSUES_CLIENT_SECRET"]
    slack_token = os.environ["SLACK_BOT_TOKEN"]
    
    # ... fetch data, process, build report ...
    
    # Output can go to a report file, Slack, etc.

if __name__ == "__main__":
    main()
```

#### Agent Workflows (`type: background_agent`)

Use when the task requires LLM reasoning, dynamic tool selection, or decision-making at runtime.

```yaml
name: my-bg-agent
version: 0.1.0
author: dev@acme.com
description: "Checks open tickets and posts a Slack digest."
type: background_agent
model: gemini-3-flash-preview
thinking_level: low
allowed_tools:
  - fetch_issues
  - fetch_support
  - slack_post_message
trigger:
  type: cron
  expression: "0 9 * * 1-5"   # Weekdays at 9:00 AM UTC
```

Provide a `skills.md` alongside the config. The system prompt follows the same conventions as user-facing agents — see the [Agent Guide](agents.md) for best practices.

### How a script workflow runs

One `background_script` run is **one runner container**, created from the engine image and
the deployment runtime (`runsc` by default; a dev machine sets
`CONTAINER_DEFAULT_RUNTIME=runc`). The worker still owns the run record, the heartbeat,
cancellation polling and the guardrail check on the input; the pipeline process runs in the
container.

| Mount | Container path | Mode |
| --- | --- | --- |
| the workflow's own directory | `/app/workspace/workflows/<name>` | read-only, and the **working directory** |
| shared code | `/app/workspace/shared` | read-only (when it exists) |
| the tool suites its `allowed_tools` names | `/app/workspace/tools/<suite>` | read-only |
| the workflow's output dir | `/app/workspace/output/<name>` | read-write |
| the workflow's report dir | `/app/workspace/reports/<name>` | read-write |
| scratch space | `/tmp` | tmpfs, sized by `limits.tmpfs_mb` |

Everything else is absent: no other workflow, no suite the workflow did not declare, no
`agents/`, `mcps/`, `.env` or registry state. That is the enforcement, because the container
carries no agent token and makes no hub round trip. It is per **suite**, not per tool: a
suite holding none of the allowed tools is not mounted at all, while a tool that shares a
suite with an allowed one is present and runnable.

The pipeline's environment is exactly what the workflow declares:

- `secrets:` and `variables:` on the workflow itself, plus the keys the tools it declares
  require, resolved from the workflow's stored secrets. Nothing else is inherited, so
  `SESSION_SECRET`, `RUNNER_TOKEN`, provider keys and any operator variable in the worker's
  environment are absent.
- They arrive through the `trellis-exec` stdin preamble, so `docker inspect` on the running
  container shows none of them — except the framework's own run-context names below, which
  are public and live in the container configuration. The preamble is capped at 64 KiB
  total and 16 KiB per value.
- `TRELLIS_AGENT_NAME` carries the workflow name, so a tool the pipeline shells out to can
  find `reports/<name>/`. `TRELLIS_REPORTS_DIR` and `TRELLIS_OUTPUT_DIR` point at
  `/app/workspace/reports/<name>` and `/app/workspace/output/<name>` — the two read-write
  mounts above — so a pipeline never hard-codes either path.
  `TRELLIS_USER_ID`, `TRELLIS_USER_EMAIL` and `TRELLIS_RUN_ID` are present as container
  variables when the run has them.
- `network:` is `egress` (default) or `none`. `egress` is Docker's default bridge, so the
  pipeline reaches whatever the host reaches, and **not** the compose project network:
  `http://hub:8001` or `http://etcd:2379` does not resolve. Call the framework API with an
  explicit URL and a declared token, or do the work through a declared tool.
- `limits:` overrides only the knobs it names. The defaults are sized for a whole pipeline
  (4096 MiB memory, 2 CPUs, 1024 pids, 1024 MiB tmpfs), never a single tool's 512 MiB.

Two costs to plan for: each run pays container create/start/teardown (about a second, more
on a cold `runsc` image), and it holds one of the runner's global container slots
(`RUNNER_MAX_CONTAINERS`, default 32) until it finishes. A pipeline that hangs holds that
slot until its deadline (`WORKFLOW_RUN_TIMEOUT`, default 3600 s), and enough of them push
ordinary tool calls into `429 capacity_exhausted`.

A saturated pool no longer fails a workflow run outright. The worker retries the call with
a capped, jittered backoff inside a window of `WORKFLOW_SLOT_WAIT_S` (default `300`,
`0` disables the wait) and records `run_waiting` once, then `run_slot_acquired` with how
long it queued. Every waited second is charged against the run's own deadline, so a run that
queued for four minutes does not also get its full `WORKFLOW_RUN_TIMEOUT` on top; if no slot
frees in time it fails with reason `runner_capacity` naming the wait. Tool calls are
unchanged: a saturated pool is still an immediate `429` there.

Cancelling a run now stops its container. The worker's poller calls the runner's
`POST /v1/stop`, which kills and removes every container labelled with the run id, and the
run is recorded as `run_cancelled` with `container_stopped: true` and the count (or `false`
plus a reason when the stop genuinely failed). The same stop runs when the worker's own wait
expires, so a timed-out run does not leave a container running to the runner's deadline.
One caveat: the label is the run id from the verified agent token, so a stack running with
`ENFORCE_AGENT_TOKENS=off` (development only) has no run id to match and cannot stop a
container.

`db-sync` validates a workflow's `runtime`, `entrypoint`, `network`, `limits`,
`allowed_tools` and declared env names before publishing it. A runtime outside
`python`/`node`/`bash`/`exec`, an entrypoint that is not a plain relative path inside the
workflow directory or is missing, an unknown `limits` knob or `network`, or an env name that
cannot be a process variable stops the sync with exit 2 and writes nothing.

---

### `config.yaml` — All Fields

```yaml
name: my-workflow                 # Required. Unique identifier.
version: 0.1.0                   # Required. Semantic version.
author: user@example.com         # Required.
description: "Does X on schedule." # Required.
type: background_script          # Required. One of: background_script, background_agent.
runtime: python                  # Required for background_script. One of: python, node, bash, exec.
entrypoint: pipeline.py          # Required for background_script. Main file to execute.
model: gemini-3-flash-preview    # Required for background_agent. LLM model identifier.
thinking_level: low              # Required for background_agent. One of: none, low, medium, high.
allowed_tools:                   # Required for background_agent. Tool names the agent may call.
  - get_system_time              #   For background_script it is the mount list (optional).
allowed_mcps:                    # Optional, background_agent only. MCP servers the agent may use.
  - coralogix
network: egress                  # Optional, background_script only. egress (default) | none.
limits:                          # Optional, background_script only. Only the knobs you name.
  memory_mb: 4096                #   Defaults: 4096 MiB, 2 CPUs, 1024 pids, 1024 MiB tmpfs.
  cpus: 2.0
tags:                            # Optional. Labels for UI filtering.
  - reporting
trigger:
  type: cron                     # Required. One of: cron, webhook.
  expression: "0 18 * * *"      # Required for cron. Standard 5-field cron expression; pass a
                                  #   YAML list (or "|"-separated string) for multiple schedules.
```

---

### Cron Expression Reference

```
┌─── minute       (0 - 59)
│  ┌─── hour         (0 - 23)
│  │  ┌─── day of month (1 - 31)
│  │  │  ┌─── month        (1 - 12)
│  │  │  │  ┌─── day of week  (0 - 7, 0 and 7 = Sunday)
│  │  │  │  │
*  *  *  *  *
```

Common expressions:
| Expression | Meaning |
|-----------|---------|
| `0 18 * * *` | Every day at 6:00 PM UTC |
| `0 9 * * 1-5` | Weekdays at 9:00 AM UTC |
| `*/30 * * * *` | Every 30 minutes |
| `0 0 * * 0` | Sundays at midnight UTC |

**Multiple schedules**: give `expression` a YAML list (`["0 9 * * 1-5", "0 18 * * *"]`) or a `|`-separated string; the workflow fires on each.

---

### Webhook Triggers

A workflow with `trigger.type: webhook` runs whenever a correctly signed `POST` hits the host's webhook endpoint:

```bash
curl -X POST http://localhost:8000/webhooks/my-workflow \
  -H "X-Signature: $SIG" \
  -H "Content-Type: application/json" \
  -d '{"event": "ping"}'
```

The endpoint validates the request's signature against the trigger's `secret`, wraps the raw payload as an event, and enqueues the workflow via Taskiq. The response is `{"status": "accepted", "task_id": "..."}` — the run itself is asynchronous; watch it under **Workflows** in the Dashboard.

```yaml
trigger:
  type: webhook
  provider: generic        # One of: generic, github, slack, notion.
  secret: <value>          # Literal value, "env:VAR_NAME" (read at request time), or
                           #   "secret:KEY" (resolved from this workflow's stored secrets).
```

**Providers** — each has its own signature scheme:

| Provider | Validation |
|----------|------------|
| `generic` | HMAC-SHA256 hex digest (or the static secret itself) in `X-Signature` or `Authorization: Bearer ...` |
| `github` | `X-Hub-Signature-256: sha256=<HMAC-SHA256 hex>` over the raw body |
| `slack` | `X-Slack-Signature: v0=<HMAC>` over `v0:<timestamp>:<body>`; requests older than 5 minutes are rejected |
| `notion` | `Notion-Signature` HMAC header (falls back to `generic` validation) |

The easiest way to configure a webhook trigger is the Dashboard's workflow editor (**Workflows → Edit**): pick the provider and provide a secret — if you leave the secret blank, a random one is generated and shown to you once.

> **Secrets scope note**: webhook-triggered runs execute under the reserved `webhook` identity, so tool secrets resolve from that identity's store (`general` + `user`-scoped keys) — not the workflow's `background` scope that cron/manual runs use. If a workflow can fire both ways, declare its keys under `general` so every path gets them.

---

### Secrets and Variables for Workflows

Workflows resolve tool secrets using the `background` context. Populate these in the Dashboard UI under **Secrets** (background scope).

Tool `tool.yaml` with context-scoped secrets:
```yaml
secrets:
  background:
    - ISSUES_CLIENT_SECRET       # Service account for background jobs
    - SLACK_BOT_TOKEN
  user:
    - ISSUES_API_TOKEN           # User's personal token for interactive agents
variables:
  background:
    - ISSUES_CLIENT_ID
    - ISSUES_URL
  user:
    - ISSUES_EMAIL
    - ISSUES_URL
```

This lets the same tool authenticate differently depending on whether it's called by a user agent (personal credentials) or a background workflow (service account credentials).

**Secret resolution order**:
1. `general` secrets — always injected
2. `background` secrets — injected when caller is a background workflow
3. `user` secrets — injected when caller is a user-facing agent

---

### Tool access rules

A workflow's tool calls go through the same evaluator as an agent's
(`core/tool_access.py`, documented in [tools.md → Tool access rules](tools.md#tool-access-rules)).
Two halves decide a call: the workflow's own `allowed_tools`/`allowed_mcps` (always
enforced) and the group rules in `workspace/policies/tool_access.yaml`.

The one thing to know about workflows is that their identity carries **no groups**. A run
mints `svc_agent_<name>` with no group claim, so a rule that matches a tool the workflow
uses denies that run no matter who triggered it. If a workflow must reach a rule-guarded
tool, either leave that tool out of the rules or relax the mode for the deployment:
`TOOL_ACCESS_MODE` is `off`, `shadow` or `enforce` (default `enforce`), and `off`/`shadow`
relax only the group-rule half, never the allowlist.

For a `background_script`, the same `allowed_tools` list is also the container's mount list,
so declaring a tool there both grants it and puts its suite on the filesystem. A tool that
is not declared is not mounted at all.

---

### Sync to Registry

After creating or editing workflow files, push to etcd:

```bash
docker compose up -d --build
```

Confirm the output shows your workflow (workflows sync through the agent path, so the line says "agent"):
```
Saved config for agent: my-workflow (Type: background_agent)
Saved skills for agent: my-workflow
```
The "Saved skills" line only appears for `background_agent` workflows that ship a `skills.md`.

The scheduler picks up new cron triggers automatically after sync. No restart required.

---

### Development Checklist

- [ ] `config.yaml` has a unique `name` and correct `type` (`background_script` / `background_agent`)
- [ ] `pipeline.py` (`background_script`) or `skills.md` (`background_agent`) is present
- [ ] Cron expression tested at [crontab.guru](https://crontab.guru) — or, for webhooks, a signed `POST` to `/webhooks/<name>` returns `{"status": "accepted", ...}`
- [ ] Required secrets declared in the relevant tool's `tool.yaml` under `background` context (`general` if the workflow also fires via webhook)
- [ ] Background-scoped secrets populated in the Dashboard UI
- [ ] A `background_script` declares every credential and endpoint it reads (`secrets:`/`variables:`) and writes only under `output/<name>/` or `reports/<name>/`
- [ ] A `background_script`'s `runtime` is one of `python`, `node`, `bash`, `exec`, and its `entrypoint` exists inside the workflow directory
- [ ] `docker compose up -d --build` run after changes
