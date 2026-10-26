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

## Tool Authorization (Default-Deny Boundary)

Admin → **Tool Authorization** (`/admin/tool-authz`) gates tool discovery and direct tool
calls through `use_tool`. A call is allowed only when an ordered policy rule matches its
principal, tool name and scope — **no matching rule means deny**. The gate ships dark and is
rolled out in stages:

| Mode | Behavior |
| --- | --- |
| `off` (default) | No-op. Identical to running without a policy. |
| `shadow` | Evaluates and records would-be denials, still allows. Use this to build the policy. |
| `enforcing` | Denies unmatched tools at both `tools:call` and `tools:read`. |

1. Click **Bootstrap** to generate one explicit rule per currently-public tool with
   `allow_principals: ["*"]` and both scopes — day-one compatibility, tightened by deleting
   lines. It also emits one rule per agent covering every tool the agent binds directly
   (`allowed_tools` / `allowed_mcps`), granted to that agent's own principal
   (`agent:<name>`, or `workflow:<name>` for a background type), so the bound-tool and hub
   surfaces have something to match from the start. It enumerates an `allowed_mcps`
   server's tools as they are registered when it runs, so re-run it (or hand-add the
   missing rule) after a server gains a tool. **Bootstrap replaces the whole document**:
   on an already-tuned policy prefer adding the one rule by hand, since re-running resets
   the deletions that tightened it.
2. Switch to `shadow` and let normal traffic run. Review the denial table (shared across
   services, sampled, capped at 200) and reconcile every entry.
3. Switch to `enforcing`. Rollback is immediate: set the mode back to `shadow`/`off` — the etcd
   watch invalidates every process's cache without a restart.

Policy document (`/registry/tool_policies`):

```yaml
default_action: deny            # the only accepted value
rules:
  - tools: [opsctl, "mcp__srv__*"]        # fnmatch globs over local / mcp__server__tool /
                                          # mcp__site__mcp__tool names
    allow_principals: [user:alice, group:ops, "agent:supervisor"]
    scopes: [tools:read, tools:call]
    rate_limit_per_min: 60                # schema-only in v1 (not enforced)
```

Principals are `user:<sub>`, `agent:<name>`, `workflow:<name>`, `group:<name>` or `*`.
`group:` membership is the identity provider's groups claim **unioned** with
`/config/framework/principal_groups` (a `principal: [group, ...]` map):

- The claim name comes from `OIDC_GROUPS_CLAIM` (default `groups`). Both login callbacks
  (OIDC and GitHub) read it from the validated profile, accept a comma-separated string or
  a list, and store it as `groups` on the user record (never in the session cookie). A
  missing or malformed claim means "no groups" — it never fails a login. For OIDC the
  value must be present in the **ID token**: the framework does not call the userinfo
  endpoint, so a provider that only exposes groups there yields zero groups (check the
  admin page's "Your resolved groups" after logging in).
- The HTTP auth middleware, which already loads the user record for the ban check,
  publishes those groups to the policy engine for the duration of the request. That is
  what makes `group:` rules match `use_tool`/gateway traffic.
- Calls that do not pass through that middleware (a direct hub `/tools/call`, the admin
  page) resolve the same groups from the stored record through a 30 s per-process read
  cache. An etcd failure resolves to "no groups" (so `group:` rules simply do not match)
  and never raises.
- **Groups are refreshed at login only.** The record is written by the login callback;
  the 30 s cache is just a read cache. A user removed from a group at the IdP keeps their
  `group:` grants until they log in again (and API-key traffic never re-authenticates
  through the IdP at all). Remove the group from `/config/framework/principal_groups`
  if you granted it there, or re-login the user.
- The etcd mapping is a **manual grant unioned on top**: it can add a group, it cannot
  remove one the IdP asserted, and it is the only source when the IdP sends no claim.
  The admin page shows the signed-in admin's resolved groups, read-only.

Agent-driven calls resolve to `agent:<name>`/`workflow:<name>`, so user-scoped rules only
apply where the caller is a user: a gateway call on a user's behalf, or a direct hub call that
carries a user id. Because the claim is published for the whole request, a tool call made
*inside* a chat-triggered agent run also carries that user's claim groups — so a `group:` rule
can match an `agent:` principal when the user who started the run belongs to the group.
**Background runs are different:** they execute in the task worker with no request context and
resolve to `workflow:<name>`, which has no stored user record — IdP groups never apply there;
only the etcd mapping does.

**Scope:** the boundary covers `use_tool` (gateway and supervisor/agent) and `search_tools`.
Tools bound directly to an agent are gated separately — see **Bound tools** below — and every
call the hub dispatches is gated by its own switch — see **Direct hub calls** below. That last
switch sits on the hub's last mile, so it also re-checks traffic that the other two surfaces
already let through.
Denials are logged as structured JSON (`event: tool_authz_deny`) with the principal, tool,
scope and mode — never tool arguments.

### Bound tools

Tools listed in an agent's `allowed_tools` / `allowed_mcps` are registered straight onto the
agent (`core/agent_factory.py`) and never pass through `use_tool`, so they have their own
switch on the same page: **Bound tools**, stored at
`/config/framework/bound_tools_mode`.

| Mode | Behavior |
| --- | --- |
| `off` (default) | No-op. Bound tools run exactly as they did before the gate existed. |
| `shadow` | Evaluates each call, records would-be denials in the shared ring (`surface: bound_tool`), still runs the tool. |
| `enforcing` | A bound call with no matching rule returns an access-denied message to the model and the tool does not run. |

- **Default off.** Nothing changes until an operator promotes the mode, and promotion to
  `enforcing` requires the confirmation checkbox. Use `shadow` first: a policy written by
  hand for `use_tool` traffic may not have rules for `agent:<name>` / `workflow:<name>` yet.
  A freshly bootstrapped one does — Bootstrap emits a rule per agent for its bound tools —
  but only for the bindings that existed when it ran.
- The evaluator, scope (`tools:call`), principal resolution and rule language are the same as
  `use_tool` — one policy document, one deny ring, only the rollout key and the
  `surface` tag differ. MCP tools are matched by their registry name
  (`mcp__server__tool`, `mcp__site__mcp__tool`), not the agent-side short name.
- **Not covered:** console tools (`ls`, `read_file`, …), A2A/subagent delegation and admin
  tools. These are framework capabilities, not hub tools, and stay outside the policy.
- A tool that is **both** bound to an agent and public can also be reached through the
  supervisor's `use_tool`; that path is evaluated by the *use_tool* switch, not the bound-tool
  one. Enforcing bound tools alone does not close it.
- Rollback is immediate: set the mode back to `shadow`/`off`; the etcd watch invalidates every
  process's cache without a restart.

### Direct hub calls

`/tools/call` on the hub (`core/hub.py`, port 8001) is its own entry point: a caller there
does not have to pass through `use_tool` or a bound-tool wrapper. It has a third switch on the
same page — **Direct hub calls**, stored at `/config/framework/hub_call_mode` — that gates every
tool call before the tool is dispatched (locally or to an edge).

| Mode | Behavior |
| --- | --- |
| `off` (default) | No-op: no token verification, no policy evaluation. Current v0.7 behavior. |
| `shadow` | Evaluates each call, records would-be denials in the shared ring (`surface: hub_direct`), still runs the tool. |
| `enforcing` | A call with no matching rule returns `SYSTEM: Access denied. Tool '<name>' is not permitted for this principal.` and the tool does not run. |

- **It gates every hub call, not only "direct" ones.** The switch sits where the hub
  dispatches, so agent and bound-tool traffic passes it too. Promoting it to `enforcing`
  therefore denies agent calls with no matching rule *regardless of* `tool_authz_mode` and
  `bound_tools_mode`. Promote it last, after the other two surfaces are settled.
- **It resolves the same principal and groups the host did.** The hub re-derives the
  principal from the token the framework forwards, never from an `agent:` / `workflow:`
  string the caller supplies, so for framework traffic it is the principal the host already
  evaluated: `user:<id>` for a gateway call on a user's behalf, `agent:<name>` /
  `workflow:<name>` otherwise. It resolves `group:` membership from that token's user record
  too — the same record the host's middleware publishes from — so a `group:` rule reaches
  the same verdict on both sides instead of matching on the host and denying at the last
  mile. `workflow:` runs carry a service user id with no record, so the record contributes
  no groups there — only `/config/framework/principal_groups` can grant a workflow a group
  (as on every other surface). Given the same policy, enforcing therefore does not change a
  decision the other gates already made; what it closes is the path that met none of them,
  a direct `/tools/call`.
- **The fallback is a different principal.** A token that cannot be verified (a key
  mismatch, an expired token) contributes no claims, so the principal falls back to
  `__user_id` or `anonymous`: `agent:` / `workflow:` rules cannot match, and the call is
  denied unless a `user:`, `group:` or `*` rule covers the fallback. A supplied `__user_id`
  also inherits that user's stored groups, so a `group:` rule is reachable from this path.
  The hub logs a warning when a token was presented and did not verify; a call with no token
  at all falls back silently.
  Check the shadow ring for `hub_direct` rows before promoting — an entry means some
  caller's principal has no rule. The ring is sampled and rate-limited per surface, so
  absence only means nothing was denied in the window.
- **The principal comes from the agent token the framework forwards.** Every agent-driven hub
  call already carries `__agent_token` (the run's short-lived token, `core/agent_token.py`). The
  hub verifies it and resolves the principal exactly as the other surfaces do:
  `workflow:<agent>` for a background run, `user:<id>` for a gateway call on behalf of a user,
  `agent:<name>` otherwise, then `user:<id>` from `__user_id` alone, then `anonymous`.
  An invalid or expired token is *not* a call failure here: it simply contributes no claims, so
  the call falls back to the user id (agent-token rejection is the separate
  `ENFORCE_AGENT_TOKENS` gate). A failure inside the check itself fails closed with
  `SYSTEM: Error checking tool access for '<name>'. Please try again later.`
- **Network isolation is the assumption.** The hub is meant to be reachable only from the
  framework (compose network, no published port). A caller that can reach `/tools/call` directly
  *and* present a user id but no token resolves to `user:<id>` — the policy, not the network, is
  what stops it once the mode is `enforcing`. Keep the hub port unpublished; the gate is
  defense in depth, not a substitute for the network boundary.
- **`DEV_MODE` has no authz bypass on this path.** The hub has never skipped tool authz for
  dev; `DEV_MODE` only supplies the well-known fallback agent-token signing key, so tokens still
  verify and the gate still applies. Default `off` is what keeps local development unchanged.
- Rules for this surface are ordinary policy rules (`tools:call`); the bootstrap generator's
  public-tool rules (`allow_principals: ["*"]`) already cover public tools for it.
- **All three surfaces share one 200-entry ring.** The persist throttle is per surface, but the
  ring is a single list, so a noisy surface can evict another's entries. Don't soak two
  surfaces at once; run one at a time and review before promoting it.
- Rollback is immediate: set the mode back to `shadow`/`off`; the etcd watch invalidates every
  process's cache without a restart.
