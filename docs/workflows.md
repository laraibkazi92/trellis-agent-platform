# Background Workflows: Consuming & Building

Background Workflows are asynchronous tasks that run without direct human interaction. They are triggered by cron schedules and can be either procedural scripts or LLM-powered agents.

---

## Consuming Workflows

### Triggering

**Automatic (Cron)**: Workflows with `trigger.type: cron` run automatically on their schedule after being synced. No further action is required.

**Manual via Admin API**: Trigger a workflow on demand via the admin endpoint:

```bash
curl -X POST http://localhost:8000/admin/workflows/my-workflow/trigger \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Monitoring

View workflow run history, status, and logs in the Dashboard UI at **http://localhost:8080** under **Workflows**.

### Accessing Output

- **HTML Reports**: Script workflows that use `generate_html_report` save files to `workspace/reports/<workflow-name>/`. They are accessible in the Dashboard UI under **Reports**.
- **Notifications**: Workflows that call `slack_post_message` or similar tools deliver results directly to the configured channel.

---

## Building Workflows

### Directory Structure

Workflows live in `workspace/workflows/`. Each workflow is a self-contained directory.

```text
workspace/workflows/
└── my-workflow/
    ├── config.yaml    # Type, triggers, model settings (if agent type)
    ├── skills.md      # (Agent type only) LLM system prompt
    └── pipeline.py    # (Script type only) Procedural Python logic
```

Both workflow types require `config.yaml`. The second file depends on the type.

---

### Workflow Types

#### Script Workflows (`type: script`)

Use for deterministic, procedural tasks where LLM reasoning is not needed: data pipelines, report generation, metric aggregation.

```yaml
name: daily-report
version: 0.3.0
author: support-team@acme.com
description: "Compiles a comprehensive daily HTML report from open tickets."
type: script
runtime: python
entrypoint: pipeline.py
tags: ["summary", "daily", "reporting"]
trigger:
  type: cron
  expression: "0 18 * * *"   # Daily at 6:00 PM UTC
```

The `pipeline.py` is a **standard Python script** — not an agent, not stdin/stdout JSON. It runs as a normal process with access to all environment variables injected for the `background` secret context.

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

#### Agent Workflows (`type: background`)

Use when the task requires LLM reasoning, dynamic tool selection, or decision-making at runtime.

```yaml
name: my-bg-agent
version: 0.1.0
author: dev@acme.com
description: "Checks open tickets and posts a Slack digest."
type: background
model: gemini-3-flash-preview
thinking_level: low
allowed_tools:
  - tl_issues_fetch
  - tl_fetch_support
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
type: script                     # Required. One of: script, background.
runtime: python                  # Required for script type. One of: python, node, go.
entrypoint: pipeline.py          # Required for script type. Main file to execute.
model: gemini-3-flash-preview    # Required for background type. LLM model identifier.
thinking_level: low              # Required for background type. One of: none, low, medium, high.
allowed_tools:                   # Required for background type. Tool names the agent may call.
  - get_system_time
tags:                            # Optional. Labels for UI filtering.
  - reporting
trigger:
  type: cron                     # Required. Currently supported: cron.
  expression: "0 18 * * *"      # Required for cron type. Standard 5-field cron expression.
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

Confirm the output shows your workflow:
```
Saved config for workflow: my-workflow
```

The scheduler picks up new cron triggers automatically after sync. No restart required.

---

### Development Checklist

- [ ] `config.yaml` has a unique `name` and correct `type`
- [ ] `pipeline.py` (script type) or `skills.md` (background type) is present
- [ ] Cron expression tested at [crontab.guru](https://crontab.guru)
- [ ] Required secrets declared in the relevant tool's `tool.yaml` under `background` context
- [ ] Background-scoped secrets populated in the Dashboard UI
- [ ] `docker compose up -d --build` run after changes
