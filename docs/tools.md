# Tools: Consuming & Building

Tools are standalone executables that agents call to interact with external systems — APIs, databases, CLIs, or any process. They are language-agnostic and communicate via JSON over stdin/stdout.

> **v0.7.1 removed the sandbox-backend and network-profile model.** There is exactly one
> execution path — the `runner` starts one container per call (`runsc` in production,
> `runc` on dev machines) — and per-manifest `network:` is now only `egress` (the default:
> Docker's default bridge) or `none`. `SANDBOX_BACKEND`, the bwrap/Landlock backends, the
> AppArmor profile, `TRELLIS_INTERNAL_CIDRS` and the opt-in egress proxy are gone. This
> page is corrected where the change is security-relevant; the full rewrite is tracked for
> the v0.7.1 docs pass, so prefer [upgrading.md → v0.7.1](upgrading.md#v071--in-development-breaking)
> when the two disagree.

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

There is one execution model since v0.7.1: every local tool call is its own **runner
container** (see the [container execution contract](#container-execution-contract-v06)
below). The in-process `bwrap` and `Landlock` backends, the `trellis-sandbox` helper, the
shipped AppArmor profile and the `SANDBOX_BACKEND` selector were removed — a deployment that
still sets `SANDBOX_BACKEND` is ignored rather than honoured.

What that means for tool code:

- The container's `$HOME` and `$TMPDIR` are a disposable tmpfs: scratch space only, gone
  with the container.
- **Never persist secrets in `$TMPDIR`.** Keep credentials in memory or in the injected
  environment.
- Files the host should see go under a declared `output_dirs` mount
  (`/app/workspace/output/<agent>` or `reports/<agent>`); everything else in the workspace
  is read-only or absent. Normal Unix permissions still apply, and the tool runs as
  `TRELLIS_UID`, the workspace owner.
- POSIX shared memory and PTY allocation work as they do in any container started from the
  image; size `limits:` around a tool that needs more than the defaults.

### Container execution contract (v0.6)

Since v0.6 every local tool call is its **own gVisor container**, created by the `runner`
service from your manifest. Container paths are the same ones tools already use, so the
JSON stdin/stdout protocol, `TRELLIS_USER_ID`/`TRELLIS_USER_EMAIL`, and wrapper scripts do
not change; what changes is what exists around the process.

| Mount | Container path | Mode |
| --- | --- | --- |
| your own suite | `/app/workspace/tools/<suite>` | read-only |
| shared code | `/app/workspace/shared` | read-only |
| calling agent's reports | `/app/workspace/reports/<agent>` | read-write **iff** `output_dirs` lists `reports` |
| calling agent's output | `/app/workspace/output/<agent>` | read-write **iff** `output_dirs` lists `output` |

Everything else is absent: no other suite, no `agents/`, no manifests, no `.env`, no
session state, and no engine network. A tool that must leave a file behind declares
`output_dirs:` and writes under the mounted agent directory; the mount exists only when
the call carries an agent identity, so an anonymous caller gets none. `stdout` remains
the way results reach the agent.

- **`HOME`, `TMPDIR`, `TMP`, `TEMP` are one disposable tmpfs** at `/tmp`, sized by
  `limits.tmpfs_mb`. It is destroyed with the container, so it is scratch space only and
  nothing in it is visible on the host.
- **`network:` is `egress` (default) or `none`.** `egress` is Docker's **default bridge**:
  the container can reach whatever the host can reach, including RFC1918 addresses and the
  cloud metadata endpoint. `none` removes the network entirely (no route, no loopback, no
  resolver) and is the only containment option v0.7.1 offers. The v0.6 profile names
  `allow`, `internet` and `internal` still load as `egress` and log **one** deprecation
  warning per value per process; `deny`/`off` load as `none`.
- **Environment:** only the keys your manifest declares (`secrets`, `optional_secrets`,
  `variables`, `secret_groups` fields) plus `TRELLIS_USER_ID`/`TRELLIS_USER_EMAIL` are
  present; the rest of the environment is the image's base (`PATH`, `LANG`, `TZ`, ...).
  `FRAMEWORK_API_URL` and `FRAMEWORK_EXECUTION_TOKEN` are no longer injected.
- **Secrets never appear in the container's configuration.** The runner hands them over as
  a one-line stdin preamble (`{"env": {...}}`) that the engine image's `trellis-exec`
  shim applies before exec-ing your script, so `docker inspect` on a running tool shows no
  declared secret and the tool still reads them with `os.getenv()`. The only variables a
  container's configuration carries are the fixed allowlist in `core/execution/env.py`:
  `HOME`, `PATH`, `TMPDIR`, `TMP`, `TEMP`, `LANG`, `LANGUAGE`, `LC_ALL`, `LC_CTYPE`, `TZ`,
  `TERM`, `PYTHONUNBUFFERED`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`,
  `TRELLIS_USER_ID`, `TRELLIS_USER_EMAIL`, `TRELLIS_RUN_ID`. Everything else your manifest
  declares (secrets, `variables`, a literal `env:` block) arrives through the preamble. If
  your manifest pins `image:` to something that is *not* derived from the engine image, that
  image must provide `/usr/local/bin/trellis-exec` (or your own equivalent that reads the
  same one-line preamble); a container started without it never runs its command.
- **Identity and rootfs:** the tool runs as `TRELLIS_UID:TRELLIS_GID` with all
  capabilities dropped, a read-only root filesystem and `no-new-privileges`.
- **Runtime:** `container_runtime` selects `runsc` (default), `runsc-variant`, or `runc`
  for one tool. `runc` forfeits kernel-syscall isolation and needs a per-tool reason.
  `image:` is reserved and ignored.

`limits:` sets the container's cgroup v2 limits:

| Field | Default | Range | Effect |
| --- | --- | --- | --- |
| `memory_mb` | `512` | 32–65536 | `--memory`; exceeding it OOM-kills only this container |
| `cpus` | `1.0` | >0–64 | CPU quota (`--cpus`) |
| `pids` | `256` | 16–32768 | `--pids-limit` |
| `tmpfs_mb` | `128` | 1–32768, ≤ `memory_mb / 2` | size of the `/tmp` tmpfs |

The tmpfs cap is charged to the same cgroup, so `tmpfs_mb > memory_mb / 2` is rejected
when the manifest is parsed.

```yaml
- name: issues_create_ticket
  # ... required fields ...
  network: egress                 # egress (default) | none
  container_runtime: runsc        # runsc (default) | runsc-variant | runc
  output_dirs: [reports]          # subset of [reports, output]
  limits:
    memory_mb: 1024
    cpus: 1.5
    pids: 512
    tmpfs_mb: 256                 # <= memory_mb / 2
```

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
  network: none                   # Optional. egress (default) | none. `none` gives the
                                  #   tool no network at all, loopback included. Legacy
                                  #   `allow`/`internet`/`internal` load as egress with one
                                  #   warning per value; `deny`/`off` load as none.
  egress:                         # Optional and INERT since v0.7.1: the egress allowlist
    - api.example.com             #   proxy was removed. Accepted so old manifests parse.
    - "*.vendor.example"
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

**`network`**: `egress` is the default and means Docker's default bridge — the container
can reach whatever the host can reach, **including cloud metadata** (`169.254.169.254`) and
anything on the host's private networks. `none` is the only containment option: no route,
no loopback, no resolver, so a compromised tool has nowhere to send the workspace or its
injected secrets. A tool that must reach the framework API itself needs `egress` (loopback
is gone under `none`). A value that is not recognized warns and falls back to `none` (a typo
must not hand a tool the network), and nothing is dropped. Legacy `allow`/`internet`/
`internal` load as `egress` with one deprecation warning per value per process; `deny`/`off`
load as `none`.

**`egress`**: **Inert since v0.7.1.** The opt-in egress allowlist proxy
(`docker-compose.egress.yml`, `scripts/egress_proxy.py`) was removed with the network
profiles: nothing reads the list and no domain is enforced. The field is still accepted so
existing manifests keep parsing; use `network: none` for anything that does not need the
network, because that is now the only real control.

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

---

## Tool Authorization

Every tool call the framework dispatches passes **one** decision, made in
`core/tool_access.py`. Admin → **Tool Authorization** (`/admin/tool-authz`) shows what that
decision currently uses; it is **read-only**.

Two independent halves decide one call:

1. **The agent's own allowlist**, resolved from its record (`allowed_tools`, `allowed_mcps`,
   `<site>__*` wildcards, console names — see `core/allowlist.py`). This half is always
   enforced. A caller with **no agent record** (a gateway client, a directly exposed tool) is
   decided by the tool's own `public` flag instead.
2. **Group rules**, from `workspace/policies/tool_access.yaml`. A target matched by at least
   one rule is usable only by a caller whose token groups intersect one of those rules'
   group sets; a target no rule matches is governed by the allowlist alone. Rules are
   allow-lists of groups — no priorities, no deny-overrides, no "everyone" group.

```yaml
# workspace/policies/tool_access.yaml
rules:
  - name: platform-ops-only          # optional label (unique), shown in denials
    targets: [text_stats]            # one pattern or a list; `target:` also works
    groups: [platform-ops]           # one or more; an empty list is a validation error

  - targets: ["dc1__*", "mcp__coralogix__*"]
    groups: [edge-operators, sre]
```

`targets` entries are shell globs matched against the reference the enforcement point uses:
a hub tool (`text_stats`), a central MCP tool (`mcp__coralogix__list_alerts`), an edge tool
(`dc1__node_ssh`), an edge MCP tool (`mcp__dc1__devops-cli__kubectl`), the console `execute`
tool or an MCP *session* (`coralogix`, `dc1__devops-cli`).

**Only `execute` is covered among the console tools.** The console file tools — `read_file`,
`write_file`, `edit_file`, `ls`, `glob`, `grep` — do not pass through this evaluator at all. A
rule naming one of them is accepted but decides nothing (the policy load and the sync warn
about it), and those tools stay constrained by the agent's **console allowlist** alone. Do not
expect a group rule to narrow file access.

`describe_tool` and the discovery catalog reads are ungated as well: they return schemas only
and execute nothing, so neither the allowlist nor the group rules apply to them.

The file is part of the workspace: `scripts/sync_to_db.py` validates it and writes it to the
registry on every rebuild, and each enforcing process watches that key, so an edit lands
everywhere within a second or two — no restart. An invalid file is refused by the sync (the
previous document stays) and, at runtime, an unreadable or invalid document **fails closed**:
every call a group rule could have decided is denied until the read succeeds.

The mode is the deployment variable `TOOL_ACCESS_MODE` (valid: `off`, `shadow`, `enforce`;
default `enforce`, and an unrecognized value behaves as `enforce`):

| Mode | Behavior |
| --- | --- |
| `enforce` | Decisions are final. |
| `shadow` | A *group-rule* denial is logged and pushed onto the shared ring, then allowed. |
| `off` | The group-rule half is skipped; the allowlist half still applies. |

Neither relaxed mode touches the allowlist half, so a shadow window can never execute a call
outside the agent's manifest. `ENFORCE_AGENT_TOKENS` — not this switch — governs whether agent
tokens are required at all.

**Groups come from the token.** The agent token carries the caller's groups (claim `g`),
resolved once when the run's token is minted from the user record the IdP login wrote. Token
claims are the only source: there is no per-request group publication, no stored-group read and
no etcd mapping any more.

**Where it is enforced:** the hub (local and edge tools), the edge relay (edge tool calls and
MCP sessions), the host before it asks the runner for an execute/MCP-session call, and the
bound-tool wrappers an agent gets from its own allowlist. The admin page's shadow-denial table
tags each entry with the surface that raised it (`hub`, `relay`, `host`, `bound_tool`).

**What the admin page shows (read-only):** the loaded rules with their groups and the policy
version, the current `TOOL_ACCESS_MODE`, every agent's effective allowlist, and the bounded
shadow-denial ring (agent, target, reason, rule, groups, surface, timestamp). Nothing on the
page writes; if the policy cannot be read, the page says so prominently — that state is
fail-closed at runtime.
