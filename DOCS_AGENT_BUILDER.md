# Developer Guide: Using the Agent Builder (Meta-Agent)

The **Agent Builder** is a specialized meta-agent within Trellis. It acts as the Framework Architect, designed to help you rapidly scale the framework by porting external logic—such as existing Claude Code skills, standalone scripts, or READMEs—into production-grade, framework-compatible assets.

## 🤖 What does it do?

When you point the Agent Builder to an existing set of instructions or scripts, it autonomously performs the following tasks:

1. **Scaffolds Agents**: Creates the required `config.yaml` and `skills.md` files in the `agents/` directory.
2. **Scaffolds Tools**: Sets up `tool.yaml` configurations and generates or wraps entrypoint scripts in the `tools/` directory.
3. **Translates Logic**: Converts shell-based instructions (e.g., "run `cd folder && python my_script.py`") into framework-native tool calls.
4. **Generates Metadata**: Assigns semantic versions, authors, descriptions, and UI-friendly tags.

---

## 🚀 Porting External/Claude Code Skills

If you have an existing set of `skills.md` or standalone Python/Go/Node.js scripts (like those used with Claude Code), you can ask the Agent Builder to port them over.

### Step 1: Start a Chat with the Agent Builder

Ensure your framework is running (`docker compose up -d`). You can interact with the `agent-builder` either through the Dashboard UI, the `/v1/chat/completions` API, or via an external MCP client like Claude Desktop.

### Step 2: Prompt the Meta-Agent

Provide the absolute paths to your existing files and describe what you want the new agent to be called.

**Example Prompt:**

> "Please port the Claude Code skills located at `/absolute/path/to/my-claude-skills/SKILL.md` and the python tools in `/absolute/path/to/my-claude-skills/scripts/` into a new agent called `my-ported-agent`. Ensure the python scripts are wrapped as framework-compatible tools."

### Step 3: Let it Work

The Agent Builder will:
1. Read your source files to understand the business logic and required inputs/outputs.
2. Determine if the logic should be unified into a single tool or split into multiple tools.
3. Use its internal `framework_scaffolder` tool to write the new `config.yaml`, `skills.md`, `tool.yaml`, and script wrappers to your local file system.

---

## 🛠 How it Works Under the Hood

The Agent Builder is strictly instructed to use **Logical "As-Is" Porting**:
* **Inline Reference Data**: If your old skills refer to external files (like a `formats.md` for Slack templates), the builder will inline that content directly into the new agent's `skills.md`.
* **Command Translation**: It strips out shell-specific commands (`cd`, `python ...`) and replaces them with instructions to use the newly created framework tools.
* **Tool Wrappers**: It ensures that all generated tools adhere to the framework's standard I/O protocol (reading from `stdin` as JSON and printing to `stdout` as JSON).

---

## ⚠️ Important: Post-Generation Steps

Because Trellis uses `etcd` as its central state registry, newly scaffolded files on your filesystem are not immediately available to the framework.

**After the Agent Builder confirms it has finished generating the files, you MUST run the synchronization script:**

```bash
python scripts/sync_to_db.py
```

This will load the new agent configurations, skills, and tools into the database. You can then navigate to your Dashboard UI (`http://localhost:8080`) to verify your new agent is active and configure any required **Tool Secrets**.
