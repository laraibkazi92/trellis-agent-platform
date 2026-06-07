# Developer Guide: Background Workflows

This guide provides essential information for building, configuring, and deploying asynchronous background tasks within **Trellis**.

## 🔄 Background Workflows Overview

Unlike standard agents which operate synchronously via chat interfaces, **Background Workflows** run asynchronously. They are triggered by scheduled events (like cron jobs) or external webhooks, and operate without direct human interaction.

Workflows reside entirely within the `workspace/workflows/` directory:

```text
workspace/workflows/
└── my-workflow/
    ├── config.yaml    # Core configuration and triggers
    ├── skills.md      # (For Agent type only) LLM instructions
    └── pipeline.py    # (For Script type only) Procedural logic
```

## 🔀 Types of Workflows

The framework supports two distinct types of background workflows, defined by the `type` field in their `config.yaml`.

### 1. Script Workflows (`type: script`)

Script workflows execute hardcoded, procedural logic using a specific runtime environment. They are ideal for deterministic tasks, data pipelines, or aggregating information where an LLM's reasoning is not required.

**Key Configuration Fields (`config.yaml`):**
*   **`type`**: Must be `script`.
*   **`runtime`**: The execution environment (e.g., `python`, `node`, `go`).
*   **`entrypoint`**: The main file to execute (e.g., `pipeline.py`).

**Example `config.yaml` (Script Workflow):**
```yaml
name: daily-report
version: 0.3.0
author: support-team@acme.com
description: Compiles a comprehensive daily HTML report using a procedural Python pipeline.
type: script
runtime: python
entrypoint: pipeline.py
tags: ["summary", "daily", "reporting"]
trigger:
  type: cron
  expression: "0 18 * * *"
```

### 2. Agent Workflows (`type: background` or `type: agent`)

Agent workflows are powered by an LLM, making them capable of complex reasoning, decision-making, and dynamic tool usage in the background.

**Key Configuration Fields (`config.yaml`):**
*   **`type`**: Must be `background` (or `agent` operating in a background context).
*   **`model`**: The LLM to use (e.g., `gemini-3.1-pro-preview`).
*   **`thinking_level`**: Controls the reasoning depth (`none`, `low`, `medium`, `high`).
*   **`allowed_tools`**: List of tool names the agent can execute autonomously.

You must also provide a **`skills.md`** file detailing the system instructions, defining the agent's background objective.

**Example `config.yaml` (Agent Workflow):**
```yaml
name: test_bg_agent
version: 0.1.0
author: dev@acme.com
description: Test background agent that checks system health daily.
type: background
model: gemini-3.1-pro-preview
thinking_level: none
allowed_tools:
  - get_system_time
trigger:
  type: cron
  expression: "0 0 * * *"
```

## ⏱️ Triggers

Workflows are initiated based on the `trigger` block defined in `config.yaml`.

*   **`type: cron`**: Executes based on a standard cron expression.
    *   *Example*: `expression: "0 18 * * *"` (Runs daily at 6:00 PM).

## 🔐 Contextual Secrets and Variables

When writing tools that your workflows will use, be aware that you can isolate secrets to specific contexts within the tool's configuration (`tool.yaml`). 

*   `background`: Secrets required *only* when the tool is executed by a background workflow.
*   `user`: Secrets required *only* when executed by a standard user-facing agent.
*   `general`: Secrets required by both.