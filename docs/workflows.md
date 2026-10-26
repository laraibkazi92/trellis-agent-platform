# Background Workflows: Consuming & Building

Background Workflows are asynchronous tasks that run without direct human interaction. They are triggered by cron schedules or inbound webhooks and can be either procedural scripts or LLM-powered agents.

> **v0.7.1 removed the sandbox-backend and network-profile model.** Every tool call is a
> `runner` container, and a workflow's per-manifest `network:` is only `egress` (the
> default: Docker's default bridge) or `none` — the `internal`/`internet`/`allow` profile
> names load as `egress` with one deprecation warning per value, and
> `SANDBOX_BACKEND`/`TRELLIS_INTERNAL_CIDRS` no longer exist. Script workflows still run
> their tools as subprocesses today; moving each run into one sandboxed container is
> tracked for this release, as is the full rewrite of this page. Cross-check with
> [upgrading.md → v0.7.1](upgrading.md#v071--in-development-breaking).

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

The `pipeline.py` is a **standard Python script** — not an agent, not stdin/stdout JSON. It runs as a normal process with access to all environment variables injected for the `background` secret context.

The rendered trigger payload is evaluated against the workflow's `guardrails` before the script
starts, exactly like a `background_agent`'s input: a blocking rule marks the run `failed`
(`guardrail blocked input`) and the process is never spawned. The rule format is the same one
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

---

### `config.yaml` — All Fields

```yaml
name: my-workflow                 # Required. Unique identifier.
version: 0.1.0                   # Required. Semantic version.
author: user@example.com         # Required.
description: "Does X on schedule." # Required.
type: background_script          # Required. One of: background_script, background_agent.
runtime: python                  # Required for background_script. One of: python, ts, go, bash.
entrypoint: pipeline.py          # Required for background_script. Main file to execute.
model: gemini-3-flash-preview    # Required for background_agent. LLM model identifier.
thinking_level: low              # Required for background_agent. One of: none, low, medium, high.
allowed_tools:                   # Required for background_agent. Tool names the agent may call.
  - get_system_time
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
- [ ] `docker compose up -d --build` run after changes
