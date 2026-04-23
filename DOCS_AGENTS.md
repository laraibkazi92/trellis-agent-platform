# Developer Guide: Building Agents

This guide provides essential information for developers to build, configure, and deploy agents within the **Trellis Agent Platform**.

## 🤖 Agent Architecture

Agents in this framework are defined by a combination of configuration (metadata, model parameters, tool access) and instruction (skills, prompt). 

### Directory Structure

Each agent must be entirely contained within its own subdirectory inside the `agents/` folder:

```text
agents/
└── my-agent/
    ├── config.yaml    # Core configuration and tool access
    └── skills.md      # System instructions and behavior
```

---

## 1. Configuration (`config.yaml`)

The `config.yaml` file defines the identity, LLM parameters, and permissions of the agent.

### Required Fields

*   **`name`** *(string)*: A unique identifier for the agent (e.g., `troubleshooting-agent`). This is used for routing and DB storage.
*   **`version`** *(string)*: Semantic versioning of the agent (e.g., `0.1.0`).
*   **`author`** *(string)*: Email or name of the creator (e.g., `user@example.com`).
*   **`description`** *(string)*: A concise summary of what the agent does. Displayed in the UI.
*   **`model`** *(string)*: The specific LLM to use. Common choices include:
    *   `gemini-3-flash-preview`
    *   *(Other models supported by PydanticAI/Gemini integrations)*
*   **`thinking_level`** *(string)*: Controls the reasoning depth. Allowed values typically include `low`, `medium`, `high`.
*   **`allowed_tools`** *(array of strings)*: A list of tool `name`s this agent is permitted to execute. If the agent needs no tools, provide an empty list `[]`.

### Example `config.yaml`

```yaml
name: agent-builder
version: 0.1.0
author: dev@acme.com
description: Meta-agent for creating and updating agents and tools within the framework.
tags: ["system", "meta", "scaffolding"]
model: gemini-3-flash-preview
thinking_level: medium
allowed_tools:
  - framework_scaffolder
  - github_search
```

---

## 2. Instructions (`skills.md`)

The `skills.md` file contains the system instructions for the agent. This is passed directly to the LLM to define its behavior, context, and operational rules.

### Best Practices for `skills.md`

1.  **Role Definition**: Clearly state who the agent is and its primary objective at the very beginning.
2.  **Tool Usage Guidance**: Explain *when* and *how* to use the tools specified in `allowed_tools`.
3.  **Formatting Rules**: If the agent should output specific Markdown structures (like JSON blocks, specific headers, or tables), provide templates here.
4.  **Tone & Constraints**: Set boundaries on what the agent should *not* do, and how it should communicate (e.g., "Be concise", "Do not invent Issues tickets").

---

## 🔄 Synchronizing Changes

The Trellis Agent Platform uses `etcd` as its central state registry. After you create or edit an agent's files, you **must** synchronize the local files to the registry so the host picks them up.

Run this command from the project root:

```bash
python scripts/sync_to_db.py
```

Check the logs to ensure your agent's config and skills were saved successfully.
