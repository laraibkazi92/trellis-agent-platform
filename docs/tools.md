# Tools: Consuming & Building

Tools are standalone executables that agents call to interact with external systems — APIs, databases, CLIs, or any process. They are language-agnostic and communicate via JSON over stdin/stdout.

---

## Consuming Tools (As an Agent Developer)

### Wiring a Tool to an Agent

Add the tool's `name` to the agent's `allowed_tools` list in `config.yaml`:

```yaml
allowed_tools:
  - fetch_issues
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
echo '{"issue_keys": ["OPS-123"], "include_comments": true}' \
  | ISSUES_API_TOKEN=your_token python workspace/tools/tickets/fetch_issues.py

# With multiple env vars
echo '{"ticket_id": "FD-456"}' \
  | SUPPORT_API_KEY=key SUPPORT_DOMAIN=acme.support.example.com \
  python workspace/tools/tickets/fetch_support.py
```

Check the tool's `tool.yaml` for required `inputs`, `secrets`, and `variables` before testing.

---

## Building Tools

### Sandbox Model

Every tool invocation runs in one of two sandbox backends, chosen once at hub startup. `auto` (the default) prefers **bwrap** and falls back to **Landlock** when bwrap cannot run; both drop all capabilities. The confinement they provide differs:

| Property | bwrap | Landlock |
| --- | --- | --- |
| Write confinement | `/` read-only, `/app/workspace` read-write, private tmpfs `/tmp` | `/` read-only, `/app/workspace` and a per-run `TMPDIR` read-write (equivalent) |
| Process isolation | private PID/IPC/UTS namespaces | shared; `kill -0` on an outside process returns `EPERM` at ABI >= 6 |
| `/proc` | fresh procfs | shared, read-only; Yama `ptrace_scope>=1` keeps other processes' data out |
| `/tmp` | private per run | shared between runs (per-run `0700` dir, same uid) |
| `/dev/shm` | available in the private `/dev` | not writable (POSIX shm fails) |
| PTY (`/dev/ptmx`) | available | not granted (`pexpect`, `node-pty`, `script` fail) |
| Tool identity | the hub uid (`TRELLIS_UID`, the workspace owner) mapped 1:1 in its namespaces, `CapEff=0` | operator uid (`SANDBOX_UID`, default = hub uid = workspace owner), capabilities cleared |
| Resource limits | none per tool — the hub container's limits (`pids_limit`, and `mem_limit`/`deploy.resources` if you set one) apply to every tool | address space 4 GiB / CPU 600 s / file size 64 MiB, applied by the helper before `exec` and configurable via `SANDBOX_RLIMIT_AS_MB`, `SANDBOX_RLIMIT_CPU_S`, `SANDBOX_RLIMIT_FSIZE_MB` (`0` disables) |

Writes past the Landlock file-size limit fail with `SIGXFSZ` (the tool is killed, it does not just get an `EFBIG`); allocations past the address-space limit fail with `ENOMEM`. bwrap has no equivalent per-tool caps, so size a container limit around its heaviest tool.

Tools run as `SANDBOX_UID`, which defaults to the hub's own uid — the workspace owner — so in both backends they can write anywhere you can. `HOME` is `/tmp` under bwrap and the per-run tmpdir under Landlock.

What that means for tool code:

- Use `$TMPDIR` (also `HOME` under Landlock) for scratch work. It is writable in both backends and removed after the run.
- **Never persist secrets in `$TMPDIR`.** Under Landlock it is shared between concurrent runs (same uid), so a `0700` directory is not a boundary. Keep credentials in memory or in the injected environment.
- Keep files the host should see under `/app/workspace` — it is the only path guaranteed to survive the run. Normal Unix permissions still apply, but because the tool runs as the workspace owner, writes into operator-owned directories (including `0755`) work in both backends. Use `$TMPDIR` for throwaway scratch.
- Avoid POSIX shared memory and PTY allocation under Landlock; use `$TMPDIR` files and subprocess pipes instead.

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
  author: user@example.com        # Optional. Author metadata; not validated or used at runtime.
  description: "Fetches X from Y." # Required. LLM reads this to decide when and how to call the tool.
  runtime: python                 # Required. One of: python, ts, go, bash.
  entrypoint: my_script.py        # Required. File to execute relative to the tool directory.
  rel_path: tools/my-tool         # Managed automatically — the registry sync computes it from the
                                  #   tool directory and overwrites any value; no need to set it.
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
  public: false                   # Optional. Expose this tool for direct execution by external MCP
                                  #   clients via the Gateway's search_tools/use_tool (no agent hop).
  network: allow                  # Optional. allow (default) or none. "none" gives the tool no
                                  #   network at all, loopback included.
  egress:                         # Optional. Domains this tool reaches when egress mode is on.
    - api.example.com             #   Plain lowercase DNS suffix: covers the name and *.api.example.com.
    - "*.vendor.example"          #   A leading '*.' is accepted and normalized to a plain suffix.
  optional_secrets:               # Optional. Injected when present; never required for the tool to run.
    - MY_OPTIONAL_TOKEN
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

**`public` tools**: Setting `public: true` exposes the tool through the Gateway MCP's `search_tools`/`use_tool`, so external MCP clients can execute it directly with no intermediate agent hop. Only public tools are embedded for tool search at registry-sync time. MCP servers can do the same per server (`public`) or per tool (`public_tools`) — see the [MCP guide](mcp.md).

**`optional_secrets` / `secret_groups`**: `optional_secrets` are injected when the caller has stored them but never count against configuration readiness. `secret_groups` is a UI hint that renders a set of optional secrets as a single card with a selector (e.g. an environment dropdown) on the configuration page; each group is `{label, select_label, options: [{value, label, fields: [{key, label, type}]}]}`.

**`network`**: Set `none` for every tool that does not call an external API — it is the cheapest exfiltration control, since a compromised tool then has nowhere to send the workspace or its injected secrets. `none` also blocks loopback, so a tool that must reach the framework API itself needs `allow`. Under the Landlock backend the policy requires kernel Landlock ABI 4+ (Linux 6.7+); bwrap always supports it with `--unshare-net`. In both backends `none` also refuses UDP and raw IP sockets — under bwrap because there is no interface at all, under Landlock because the helper's seccomp filter (default `SANDBOX_SECCOMP=on`) refuses the socket — so the tool has no IP network at all; AF_UNIX sockets still work. The one exception is `SANDBOX_SECCOMP=off` on the Landlock backend: the filter also goes away, and `none` then denies TCP connect/bind only, leaving UDP usable. Deployments can flip the default for all tools with `SANDBOX_NET_DEFAULT=none`. An unrecognized value warns and falls back to `allow` rather than disqualifying the tool.

**`egress`**: The domains a tool needs when the operator has enabled [egress mode](deploy.md#egress-mode-opt-in). It is a list of plain DNS suffixes — `example.com` covers `example.com` and every `*.example.com` — and the proxy is the only way out. A leading `*.` is accepted and normalized to the same plain suffix, so `"*.example.com"` and `example.com` are the same entry.

Three things to know before using it:

- **v1 is a union.** The proxy generates one allowlist from every tool's `egress:` list, so any tool can reach any declared domain. The field still matters: it is the auditable declaration of what your deployment needs, and per-tool enforcement can build on it later. Keep it as narrow as the vendor's API allows.
- **Enforcement is opt-in at the deployment level.** Without the compose override nothing reads `egress:` and tools keep their normal outbound access. With it, a domain that is missing from the union is simply unreachable (`ENETUNREACH` or `403`).
- **Some clients ignore the proxy env.** Python `requests`/`httpx` honour `HTTPS_PROXY`; Node's built-in `fetch`/`undici` do not, and fail closed because there is no direct route. Go tools are compiled in the hub and honour the proxy during that build, so add `proxy.golang.org` (and any module host) to a tool's `egress:` list when it imports third-party packages.

The allowlist is regenerated when the proxy container starts, so after editing `egress:` run `docker compose restart egress-proxy` (or rebuild). Tools that need no network should still use `network: none`: it is stronger than egress mode because there is no route even to the proxy.

---

### Retries, timeouts, and idempotency

**Transient retries** — when a tool exits non-zero and its `stderr` contains a known transient network keyword (`timeout`, `connection refused`, `econnrefused`, `eof`, `network is unreachable`, `temporary failure`), the Hub retries the invocation up to **3 attempts** via `stamina`. Re-executing a tool that already mutated external state can duplicate side effects (e.g. a second ticket), so tools with non-idempotent side effects (creates, updates, writes) should opt out with `retry_on_transient: false`. The first failed attempt then surfaces the error to the caller instead of re-running.

> **Author guidance:** `retry_on_transient` defaults to `true`. If your tool creates, posts, updates, deletes, sends, comments, or otherwise has a non-idempotent side effect against a 3rd-party system (ticketing systems, Slack, support systems, SSH/infra operations, local writes, etc.), you must explicitly set `retry_on_transient: false` in that tool's `tool.yaml` entry — do not rely on the default. Read-only/query tools can safely leave it unset.

**Timeouts** — every subprocess execution is bounded by `TOOL_EXECUTION_TIMEOUT` (default **300 s**; change it in the Admin Dashboard -> Limits & Tuning, or set the env var as a deployment default). Override the default for a single tool with `timeout_seconds`. Timeouts are **immediately fatal — never retried**: a tool that hung for the full timeout is almost certainly stuck, and retrying would only multiply wall-clock time and side-effect risk. The failure is still recorded as a health event for the circuit breaker.

```yaml
- name: issues_create_ticket
  version: 0.1.0
  author: user@example.com
  description: "Creates an issue."
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
| `python` | `.py` file | Runs with the hub's Python 3.12 interpreter |
| `ts` | `.ts` file | Executed with `npx tsx`; install deps in the tool directory |
| `go` | compiled binary | Build and commit the binary to `<tool-dir>/.bin/<tool-name>` — the hub executes it from there |
| `bash` | `.sh` file | Runs with `bash` |

---

### Multi-Tool Directories

A single directory can host multiple related tools. `tool.yaml` is a YAML list:

```yaml
- name: issues_fetch
  entrypoint: fetch_issues.py
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
- [ ] Tool directory lives under `workspace/tools/` (the sync derives `rel_path` automatically)
- [ ] Script reads all inputs from `sys.stdin` (JSON), writes only JSON to `sys.stdout`
- [ ] Secrets/variables declared in `tool.yaml` and accessible via `os.getenv()`
- [ ] Tool tested locally with `echo '{...}' | ENV_VAR=val python script.py`
- [ ] `docker compose up -d --build` run after changes
