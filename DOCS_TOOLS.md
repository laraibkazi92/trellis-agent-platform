# Developer Guide: Building Tools

This guide provides detailed instructions on how to build, configure, and register tools within the **Trellis Agent Platform**. Tools are external functions that agents can call to interact with APIs, databases, or the local environment.

## 🛠 Tool Architecture

The framework uses a polyglot Hub (FastMCP) that supports tools written in Python, Go, and Node.js. Tools communicate via standard input/output using a specific JSON protocol.

### Directory Structure

Tools live in the `tools/` directory. You can group multiple related tools in a single subdirectory.

```text
tools/
└── tickets/
    ├── tool.yaml              # Configuration for all tools in this folder
    ├── tl_fetch_issues.py       # Implementation script 1
    ├── tl_extract_summary.py  # Implementation script 2
    ├── lib/                   # Optional shared code folder
    └── .env.example           # Recommended for documenting required secrets
```

---

## 1. The I/O Protocol

Regardless of the language you choose, your tool script must adhere to this standard:

*   **Input**: Read a single JSON object from `stdin`. This object contains the arguments passed by the agent.
*   **Output**: Print a single JSON object to `stdout`. This object is returned to the agent.
*   **Logging/Errors**: Use `stderr` for any logging, debugging, or error messages. Do **not** print non-JSON text to `stdout`, as it will break the parsing process.

---

## 2. Configuration (`tool.yaml`)

The `tool.yaml` file defines the tools in a directory. It can be a single object or an array of objects.

### Required Fields

*   **`name`** *(string)*: Unique identifier for the tool (e.g., `tl_issues_fetch`). Agents use this name in their `allowed_tools` list.
*   **`version`** *(string)*: Semantic version (e.g., `3.2.0`).
*   **`author`** *(string)*: Creator's name or email.
*   **`description`** *(string)*: Clear description of what the tool does. The LLM uses this to decide when to call it.
*   **`runtime`** *(string)*: The execution environment (e.g., `python`, `node`, `go`).
*   **`entrypoint`** *(string)*: The main file to execute (e.g., `tl_fetch_issues.py`).
*   **`rel_path`** *(string)*: The relative path to the tool directory from the root (e.g., `tools/tickets`).
*   **`inputs`** *(object)*: Schema of arguments the tool accepts. Each key is an argument name, containing:
    *   `type`: `string`, `boolean`, `array`, `object`, `number`.
    *   `description`: What the argument represents.
    *   `required`: `true` or `false`.
*   **`outputs`** *(object)*: Schema of the JSON returned via `stdout`.
*   **`secrets`** *(array of strings)*: (Optional) List of environment variable names the tool needs (e.g., `ISSUES_API_TOKEN`). The framework injects these into the tool's environment at runtime.

### Example `tool.yaml`

```yaml
- name: tl_issues_fetch
  version: 3.2.0
  author: markh@acme.com
  description: Fetches one or more Issues issues including comments.
  runtime: python
  entrypoint: tl_fetch_issues.py
  rel_path: tools/tickets
  inputs:
    issues_keys:
      type: array
      description: List of Issues keys (e.g., OPS-123) to fetch.
      required: true
    include_comments:
      type: boolean
      description: Whether to include issue comments.
      required: false
  secrets:
    - ISSUES_EMAIL
    - ISSUES_API_TOKEN
  outputs:
    issues:
      type: array
      description: List of raw Issues issue data.
```

---

## 3. Local Development & Testing

Because tools are just standard scripts reading `stdin`, you can test them locally without running the entire framework:

```bash
# Example: Testing a Python tool
echo '{"issues_keys": ["OPS-123"]}' | ISSUES_API_TOKEN=your_token python tools/tickets/tl_fetch_issues.py
```

### Best Practices

*   **Flat over Nested**: Keep your tool folder self-contained. Avoid complex packaging.
*   **Shared Logic**: If scripts in a tool suite share code, place it in a `lib/` subdirectory within the tool's folder.
*   **Secrets**: Never hardcode API keys in scripts. Define them in `tool.yaml`'s `secrets` array and access them via environment variables (e.g., `os.getenv('ISSUES_API_TOKEN')`).

---

## 🔄 Synchronizing Changes

Run this from the project root after creating or modifying `tool.yaml`:

```bash
python scripts/sync_to_db.py
```
