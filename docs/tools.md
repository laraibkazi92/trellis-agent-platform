# Tools: Consuming & Building

Tools are standalone executables that agents call to interact with external systems — APIs, databases, CLIs, or any process. They are language-agnostic and communicate via JSON over stdin/stdout.

---

## Consuming Tools (As an Agent Developer)

### Wiring a Tool to an Agent

Add the tool's `name` to the agent's `allowed_tools` list in `config.yaml`:

```yaml
allowed_tools:
  - tl_issues_fetch
  - get_system_time
  - slack_post_message
```

The name must exactly match the `name` field in the tool's `tool.yaml`. The hub will expose only the listed tools to the agent.

### Providing Secrets and Variables

Tools that call external APIs need credentials. These are stored per-user in etcd and injected as environment variables at runtime — never hardcoded.

1. Open the Dashboard UI at **http://localhost:8080**
2. Navigate to **Secrets** (for API keys/tokens) or **Variables** (for non-sensitive config)
3. Add the key names declared in the tool's `tool.yaml`

For **background workflows**, populate secrets under the workflow/background context scope, not the user scope.

### Testing a Tool Locally

Tools read from stdin, so you can test any tool independently without running the full stack:

```bash
# Python tool
echo '{"issues_keys": ["OPS-123"], "include_comments": true}' \
  | ISSUES_API_TOKEN=your_token python workspace/tools/tickets/tl_fetch_issues.py

# With multiple env vars
echo '{"ticket_id": "FD-456"}' \
  | SUPPORT_API_KEY=key SUPPORT_DOMAIN=acme.support.com \
  python workspace/tools/tickets/tl_fetch_support.py
```

Check the tool's `tool.yaml` for required `inputs`, `secrets`, and `variables` before testing.

---

## Building Tools

### Sandbox Model

Every tool invocation runs inside a bubblewrap (bwrap) sandbox: read-only root bind, a writable bind for `/app/workspace`, tmpfs `/tmp`, and unshared user/pid/ipc/uts namespaces. The hub container itself is least-privilege — all capabilities dropped except `SYS_ADMIN` + `SETFCAP` (the minimum bwrap needs to create its user namespace as root), with unmasked system paths (so the kernel permits a fresh `/proc` inside the sandbox), an unrestricted seccomp filter (so bwrap's `pivot_root` isn't blocked from building the sandbox root) and `no-new-privileges` — so tools cannot write outside the workspace/tmp or regain privileges via setuid binaries or file capabilities.

### Directory Structure

Tools live in `workspace/tools/`. Group related tools in one directory — a single directory can define multiple tools via a list in `tool.yaml`.

```text
workspace/tools/
└── my-tool/
    ├── tool.yaml          # Tool definitions (YAML list of tool objects)
    ├── my_script.py       # Implementation entrypoint
    ├── lib/               # Optional: shared code within this tool suite
    │   └── clients.py
    └── .env.example       # Recommended: document required secrets for developers
```

---

### The I/O Protocol

All tool scripts — regardless of language — must follow this protocol:

- **Input**: Read a single JSON object from `stdin`.
- **Output**: Print a single JSON object to `stdout`.
- **Errors / Logs**: Write to `stderr` only. **Never print non-JSON text to `stdout`** — it breaks parsing.

**Python template:**
```python
import json
import sys
import os

def main():
    args = json.load(sys.stdin)
    
    # Access inputs
    my_arg = args["my_arg"]
    optional_arg = args.get("optional_arg", "default")
    
    # ... do work ...
    
    result = {"output_field": "value"}
    json.dump(result, sys.stdout)

if __name__ == "__main__":
    main()
```

**Error handling — return structured errors, don't raise unhandled exceptions:**
```python
try:
    result = do_work(args)
    json.dump({"success": True, "data": result}, sys.stdout)
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    json.dump({"success": False, "error": str(e)}, sys.stdout)
```

---

### `tool.yaml` — All Fields

`tool.yaml` is a YAML list — one entry per tool. Multiple tools can share a directory and file.

```yaml
- name: my_tool                   # Required. Unique identifier. Must match agent's allowed_tools entry.
  version: 0.1.0                  # Required. Semantic version.
  author: user@example.com        # Required.
  description: "Fetches X from Y." # Required. LLM reads this to decide when and how to call the tool.
  runtime: python                 # Required. One of: python, node, go.
  entrypoint: my_script.py        # Required. File to execute relative to the tool directory.
  rel_path: tools/my-tool         # Required. Directory path relative to repo root.
  inputs:                         # Required. Schema of the stdin JSON object.
    my_arg:
      type: string                # One of: string, boolean, array, object, number.
      description: "What this argument is."
      required: true
    optional_arg:
      type: boolean
      description: "Whether to include X."
      required: false
  outputs:                        # Required. Schema of the stdout JSON object.
    result:
      type: string
      description: "The result value."
    items:
      type: array
      description: "List of result objects."
  secrets:                        # Optional. API keys / credentials injected as env vars at runtime.
    general:
      - MY_API_KEY                # Required for all callers (user and background).
    user:
      - USER_PERSONAL_TOKEN       # Required only when called by a user-facing agent.
    background:
      - BG_SERVICE_ACCOUNT_KEY    # Required only when called by a background workflow.
  variables:                      # Optional. Non-sensitive config (URLs, IDs). Same structure as secrets.
    user:
      - MY_SERVICE_URL
      - MY_EMAIL
    background:
      - BG_SERVICE_URL
```

**Secrets vs Variables**: Both are stored in etcd and injected as environment variables. `secrets` is for sensitive credentials; `variables` is for non-sensitive config like base URLs or email addresses.

**Simple form** (no context scoping — all callers get the same keys):
```yaml
secrets:
  - MY_API_KEY
  - ANOTHER_SECRET
variables:
  - MY_SERVICE_URL
```

**Contextual scoping** (`general` / `user` / `background`): Lets one tool authenticate differently depending on whether it's called by a user agent (personal token) or a background workflow (service account). Required fields differ by context.

---

### Retries, timeouts, and idempotency

**Transient retries** — when a tool exits non-zero and its `stderr` contains a known transient network keyword (`timeout`, `connection refused`, `econnrefused`, `eof`, `network is unreachable`, `temporary failure`), the Hub retries the invocation up to **3 attempts** via `stamina`. Re-executing a tool that already mutated external state can duplicate side effects (e.g. a second ticket), so tools with non-idempotent side effects (creates, updates, writes) should opt out with `retry_on_transient: false`. The first failed attempt then surfaces the error to the caller instead of re-running.

> **Author guidance:** `retry_on_transient` defaults to `true`. If your tool creates, posts, updates, deletes, sends, comments, or otherwise has a non-idempotent side effect against a 3rd-party system (Issues, Slack, Support, SSH/infra operations, local writes, etc.), you must explicitly set `retry_on_transient: false` in that tool's `tool.yaml` entry — do not rely on the default. Read-only/query tools can safely leave it unset.

**Timeouts** — every subprocess execution is bounded by `TOOL_EXECUTION_TIMEOUT` (default **300 s**). Override the default for a single tool with `timeout_seconds`. Timeouts are **immediately fatal — never retried**: a tool that hung for the full timeout is almost certainly stuck, and retrying would only multiply wall-clock time and side-effect risk. The failure is still recorded as a health event for the circuit breaker.

```yaml
- name: issues_create_ticket
  version: 0.1.0
  author: user@example.com
  description: "Creates a Issues ticket."
  runtime: python
  entrypoint: create_ticket.py
  rel_path: tools/issues
  retry_on_transient: false      # Optional. Default true. Opt out for non-idempotent tools.
  timeout_seconds: 600           # Optional. Defaults to TOOL_EXECUTION_TIMEOUT (300 s).
```

---

### Runtimes

| Runtime | `entrypoint` | Notes |
|---------|-------------|-------|
| `python` | `.py` file | Python 3.12 container environment |
| `node` | `.js` file | Node.js; install deps in the tool directory |
| `go` | compiled binary | Build and commit the binary to the directory |

---

### Multi-Tool Directories

A single directory can host multiple related tools. `tool.yaml` is a YAML list:

```yaml
- name: issues_fetch
  entrypoint: tl_fetch_issues.py
  ...

- name: issues_comment
  entrypoint: tl_post_comment.py
  ...
```

Both tools share the same `lib/` and `.env.example`.

---

### Shared Code Patterns

**Within a tool suite** (scripts in the same directory): Use a `lib/` subdirectory.
```python
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from lib.clients import get_issues_client
```

**Across separate tool suites**: Extract to `workspace/shared/` and insert the workspace root into `sys.path`.
```python
import sys, os
# Insert workspace root so shared modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.issues.client import IssuesClient
from shared.slack.client import SlackClient
```

---

### Sync to Registry

After creating or modifying `tool.yaml`, push to etcd:

   ```bash
   docker compose up -d --build
   ```

Confirm the output shows your tool:
```
Saved config for tool: my_tool
```

The hub reloads tool configs dynamically, so no restart is needed for most changes.

---

### Local Development Checklist

- [ ] `tool.yaml` has a unique `name` not already in use
- [ ] `rel_path` matches the actual directory path from repo root
- [ ] Script reads all inputs from `sys.stdin` (JSON), writes only JSON to `sys.stdout`
- [ ] Secrets/variables declared in `tool.yaml` and accessible via `os.getenv()`
- [ ] Tool tested locally with `echo '{...}' | ENV_VAR=val python script.py`
- [ ] `docker compose up -d --build` run after changes
