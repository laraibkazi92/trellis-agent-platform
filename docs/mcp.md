# MCP Server Guide

Model Context Protocol (MCP) servers expand the capabilities of agents within `Trellis` by providing standard interfaces to external tools and data sources. 

This guide explains how to register external MCP servers so they are natively available to your agents — either centrally (`workspace/mcps/`) or exported from an edge node (see [Edge-hosted MCP servers](#edge-hosted-mcp-servers)).

## Directory Structure

All MCP servers are configured in the `workspace/mcps/` directory of the project. Each server should have its own directory containing an `mcp.yaml` file.

```text
workspace/
└── mcps/
    └── logs/
        └── mcp.yaml
```

## Configuration Schema (`mcp.yaml`)

The `mcp.yaml` defines how the Universal Agent Host (`core/host.py`) connects to the external MCP server. The framework supports four transports: `stdio` (for local executables), `sse` (for HTTP SSE servers), and `http` / `streamable-http` (for Streamable HTTP servers — two aliases for the same transport).

### Fields

- `name`: The unique identifier for the MCP server.
- `transport`: The communication protocol. One of `stdio`, `sse`, `http`, `streamable-http`.
- `command`: The command to execute (for `stdio`) or the connection URL (for `sse`/`http`/`streamable-http`).
- `args` (Optional): A list of arguments to pass to the command (only applicable for `stdio`).
- `env` (Optional): A dictionary of environment variables (for `stdio`) or HTTP headers (for `sse`/`http`/`streamable-http`).
- `secrets` (Optional): A list of required user secrets. These will automatically appear in the UI's Secret Manager.
- `optional_secrets` (Optional): Secrets injected when present but not required for the server to start.
- `variables` (Optional): Non-sensitive configuration variables. Same structure as `secrets` (including contextual scoping); resolved and injected exactly like secrets, just stored as plain variables.
- `public` (Optional): Expose **all** tools from this MCP server directly to external MCP clients via the Gateway's `search_tools`/`use_tool` tools (no agent hop required).
- `public_tools` (Optional): A whitelist of specific tool names to expose publicly when `public` is not set server-wide.
- `tools` (Optional): A static list of tool definitions (`name`, `description`, `inputSchema`) exposed by the server. You normally don't write this by hand: when it's absent, the registry sync live-connects to the server (opening a discovery session in a runner container for `stdio`, or connecting to the HTTP URL, with a ~20s budget), discovers its tools, and persists the discovered list into the registry config automatically. That list then feeds the runtime's discovery fast-path and the semantic tool-search index (`mcp__{server}__{tool}` embeddings). Hand-listing `tools` in `mcp.yaml` skips discovery entirely — useful when the server can't be reached from the sync environment; if discovery fails, the config is still saved and the runtime falls back to live discovery.
- `network` (Optional): `egress` (default: ordinary Docker egress on the default bridge) or `none` (no network at all). Only applies to `stdio` servers, and it is enforced on the runner's container (see [How stdio MCP servers run](#how-stdio-mcp-servers-run)). `http`/`sse` transports ignore it. Legacy `allow`/`internet`/`internal` load as `egress` with one deprecation warning per value; `deny`/`off` load as `none`.
- `remote` (Optional): **written by the edge relay only, never authored in a file.** A `{site, mcp}` block marks the server as edge-hosted: central never connects to it and never resolves central secrets for it. See [Edge-hosted MCP servers](#edge-hosted-mcp-servers).

## Secure Secret Management

To keep credentials secure, you should never hardcode API keys or tokens in `mcp.yaml`. Instead, declare them in the `secrets` list. The framework supports **Secret Interpolation** within the `env` dictionary.

If an environment variable or header value contains `{SECRET_NAME}`, the framework will automatically substitute it with the user's secure value from the database.

### Example: Remote SSE Server (HTTP)

```yaml
name: my-remote-mcp
transport: sse
command: "https://api.example.com/v1/mcp"
env:
  # The framework interpolates the {MY_API_KEY} placeholder
  Authorization: "Bearer {MY_API_KEY}"
secrets:
  - "MY_API_KEY"
```

### Example: Local Stdio Server (Command)

```yaml
name: my-local-mcp
transport: stdio
command: "npx"
args:
  - "-y"
  - "@modelcontextprotocol/server-postgres"
  - "postgresql://localhost/mydb"
env:
  # For stdio, un-interpolated secrets are automatically added to the environment
  POSTGRES_PASSWORD: "{MY_DB_PASSWORD}"
secrets:
  - "MY_DB_PASSWORD"
```

## How stdio MCP servers run

A `stdio` server is **not** a child of `host` or `trellis-proxy`. Since v0.6 it runs in a
container created by the local `runner` service, from the manifest on disk:

- **One container per session.** A central agent's session (per MCP, per user) and an edge
  session (per MCP, per caller identity) each get their own container, with `HOME`/`TMPDIR`
  on that container's tmpfs. Two users on the same server therefore share no filesystem, no
  process namespace and no `HOME`, and an ordinary tool call sees neither.
- **Login state dies with the session.** Anything the server writes under `$HOME` (tokens,
  cookies, SSH keys it generated) lives in the tmpfs: it is gone on TTL expiry, LRU
  eviction, `SIGHUP`, a runner restart, or process death. There is no persisted per-user
  login state to back up or clean up — and no host directory where another user could read
  it. A server that needs durable state must be given a real mount by its own image or
  manifest; `$HOME` is not one.
- **Discovery is a throwaway container.** Catalog discovery (`discover_external_mcps` on
  central, the edge's live `list_tools()`) opens a session with `kind="discovery"` and a
  60 s deadline, then tears it down. It leaves no container and no directory behind; the
  catalog is cached in memory (edge: per export signature, dropped on `SIGHUP`).
- **Only declared env is sent.** The request carries the manifest's declared keys
  (`secrets`, `optional_secrets`, `variables`, the `env:` block) plus
  `TRELLIS_USER_ID`/`TRELLIS_USER_EMAIL`. The runner rejects any other key with `400`, and
  it builds `PATH` and the rest of the base environment itself.
- **`mcp.yaml`'s `network:` is `egress` (default) or `none`.** `egress` is Docker's default
  bridge: the server reaches whatever the host reaches. `none` removes the network
  entirely. There is no bind mount of the workspace beyond the MCP's own directory
  (read-only) plus `shared/`.
- **A lost session is reported, not retried.** If the runner no longer has the session
  (restart, reaper, deleted container), that call returns `mcp_session_lost`; the next
  call starts a fresh container. No MCP call is ever replayed automatically.

### Memory sizing (sessions × `limits.memory_mb` ≤ 60 % of host RAM)

Each warm session is a running container, so plan for their peak memory:

```text
MAX_SESSIONS_EDGE × limits.memory_mb  ≤  0.6 × host RAM
```

The default `limits.memory_mb` is 2048. On a 16 GiB edge that allows at most
`floor(16 × 0.6 × 1024 / 2048) = 4` concurrent session containers, so set
`MAX_SESSIONS_EDGE=4` in the edge's `.env` (and `max_sessions:` per `export_mcps` entry
below that). Lower `limits.memory_mb` per MCP only if its manifest says so — a Node
server usually needs the 2 GiB default, and a `tmpfs_mb` at or near `memory_mb` will
OOM-kill it. On central, warm sessions are the cached per-user MCP clients (TTL 300 s,
at most 100); the runner's own container limits still apply, so size the host for the
number of agents × users you expect to hold a session at once.

## Applying Changes

Whenever you add or modify an `mcp.yaml` file, you must sync the configuration to the internal registry (etcd). 

Run the following command from the root directory:

```bash
docker compose up -d --build
```

The output will confirm that your MCP server has been registered:
```text
Syncing MCPs to etcd...
  Discovered and persisted 3 tools for MCP: logs
  Saved config for MCP: logs
  Indexed embedding for MCP tool: mcp__logs__search_logs
```

If the server can't be reached from the sync environment, you'll see a `WARNING: could not discover tools...` line instead; the config is still saved and the runtime discovers the server live.

After syncing, head over to the **Secrets** tab in the UI to populate any required keys. Agents will automatically discover and load the tools from your registered MCP servers.

## Edge-hosted MCP servers

Since `v0.5.0` an **edge node** (`trellis-proxy`) can export MCP servers the same way it
exports tools. The server process runs on the edge VM, reaches networks central cannot,
and its credentials stay there; central receives only the tool catalog and forwards
`tools/call`.

From central there is nothing to configure here: an edge publishes its catalog in the
tunnel handshake and the relay writes it into the registry. Authoring and edge policy are
covered in [proxy.md → Exporting MCP servers](proxy.md#exporting-mcp-servers).

### What central sees

One registry entry per exported server, `/registry/mcps/<site>__<mcp>/config`:

- `transport: "remote"`, `remote: {site, mcp}`, `managed_by: "edge-relay"`;
- `tools: [{name, description, inputSchema}]` with each `inputSchema` **verbatim** from
  the edge's `mcp.yaml` — no cleaning, no coercion, root-level `oneOf`/`anyOf`/`$ref`
  included;
- `edge_transport` (`stdio`/`http`/`sse`): display only, since central never connects;
- `public` / `public_tools` derived from the **site** record, never from the edge.

Per tool, the relay also writes a description-only embedding under
`/registry/tools/mcp__<site>__<mcp>__<tool>/embedding`, so tool search ranks edge MCP
tools like any other.

**Admin → Edges** shows, per site: the exported MCP servers with name, tool count and
transport, the site's MCP count, and protocol badges — `proto 3` plus one badge per
capability (`tools`, `mcp`). Only `proto 3` edges (v0.7.2) connect at all: the call
frame stopped carrying an agent token, so an older edge is refused at the handshake.
A server the edge configured but dropped for size is absent from this table; the edge
log says why.

The registry entry is read-only: the MCP editor renders it as edge-managed and saves/deletes
are refused. Edit the server on the edge and `SIGHUP` the proxy.

### Reference forms (public manifest API)

These forms are stable API — they appear in agent manifests (`allowed_mcps`,
`allowed_tools`) and in a site's `public_tools`. Every segment is 1–64 characters, starts
with a letter or digit, may contain letters, digits, `-` and `_`, may **not** contain `__`,
and may **not** end with `_`:

```text
edge tool ref:      ^SEG__SEG$
edge mcp ref:       ^SEG__SEG$                       (in allowed_mcps)
edge mcp wildcard:  ^SEG__\*$                        (in allowed_mcps, optional)
edge mcp tool ref:  ^mcp__SEG__SEG__SEG$             (4 parts)
central mcp tool:   ^mcp__SEG__SEG$                  (3 parts after split)

SEG = [A-Za-z0-9](?:[A-Za-z0-9-]|_(?=[A-Za-z0-9-])){0,63}
```

`SEG` is deliberately **stricter than `NAME_RE`** (`[A-Za-z0-9][A-Za-z0-9_-]{0,63}`, what
the relay uses for published names): a trailing `_` is a legal name character but is
rejected in a reference, because it makes the `__` boundary ambiguous — `a___b` would read
either as site `a_` + name `b` or as site `a` + name `_b`. Inside a segment, `_` must be
followed by a letter, digit or `-`; that is how the `__` ban is spelled. (The regex is a
Python `re` pattern in `core/models.py`; pydantic-core, which validates the registry
`Remote*Spec` fields, has no lookarounds and spells the same ban without one.) A name
that becomes a reference segment therefore may not end in `_`: `save_mcp_config` and
Admin → Edges reject it outright, an edge-published tool is skipped with a warning, and
db-sync skips that one MCP manifest instead of failing the run. A **central tool** is
addressed by its bare name, so a trailing `_` stays legal there.

Ambiguity rules:

- Site and MCP names cannot contain `__` or end with `_`, and an edge tool name cannot
  end with `_`; the separator and the trailing underscore both make a
  `<site>__<tool>` reference ambiguous, and such a name is rejected when the manifest is
  saved or synced.
- `mcp` is a **reserved site name**, so no site can make its tools collide with the
  `mcp__…` namespace.
- The split is therefore unique: a tool name starting `mcp__` with **four** parts is an
  edge MCP tool, with **three** parts it is a central MCP tool.
- **A central MCP name or tool name containing `__` is now illegal.** Previously it could
  exist; `save_mcp_config` now raises and the registry sync warns and skips. There are no
  such names in-tree, but a hand-written one will be refused after upgrading — rename it.
  The runtime also decides which reading applies from the registry (does
  `<site>__<mcp>` exist *and* carry a `remote` block?), not from the name's shape, so a
  legacy name is never silently redirected to an edge.

### Wiring edge MCPs to an agent

In the agent's `config.yaml`:

```yaml
allowed_mcps:
  - dc1__devops-cli        # one exported server on edge `dc1`
  - dc1__*                 # every server currently discovered on that site
allowed_tools:
  # Optional narrowing: any of these forms registers only that tool.
  - mcp__dc1__devops-cli__tenant_account_tools
```

- `allowed_mcps` entries for edges are `<site>__<mcp>`. Bare names still mean central
  servers; nothing changes there.
- `<site>__*` is sugar for "every MCP server this edge has currently published". It is
  expanded at build time against the discovered catalog, never matches across sites, and a
  server the edge starts exporting later does **not** appear on its own: the built agent is
  cached (`_agent_cache`) with no TTL, so the agent must be rebuilt (save it in the editor)
  or evicted, or the host restarted.
- The agent-facing tool name is **always** `mcp__<site>__<mcp>__<tool>`, whatever form was
  used to allow it. Bare tool names would collide across sites, and 4-part is the only
  form the gateway can route back.
- A reference to an edge that is not connected (or a server not yet published) is a
  **warning** during registry sync, not a failure: the agent saves and the tool appears
  once the site connects.

### Visibility in search and the gateway

Tool search and the gateway's `search_tools`/`use_tool` see an edge MCP tool when the
site record grants it:

- site `public: true` → **all** MCP tools of that site are visible. **Upgrade note:** a
  site that was already `public: true` for its tools now also exposes its MCP tools, which
  it did not in `v0.4.x`. Review public sites before enabling MCP export.
- otherwise, the site's `public_tools` may name a server or a single tool in any of the
  four reference forms — `<site>__<mcp>`, `mcp__<site>__<mcp>`, `<site>__<mcp>__<tool>`,
  `mcp__<site>__<mcp>__<tool>` — and the matching bare tool names are stored on the MCP
  config, which is what `search_tools` compares against.

An edge cannot widen its own visibility: only the central site record decides.

### Configuration status

An edge MCP is **configured** iff its edge is currently connected — the same rule as edge
tools. There are no central secrets to resolve: central has nothing to launch and no key
to inject. An offline edge reports `edge '<site>' is not connected` as the missing
requirement, which is also what an agent status page shows.

### Schemas and provider normalization (v0.5)

The published and stored `inputSchema` is byte-identical everywhere: `mcp.yaml` → hello →
registry → gateway (external MCP clients). Arguments are forwarded un-coerced and the MCP
server validates them.

For **`google` only**, the provider-facing copy is different: when the agent is built, a
root-level `oneOf`/`anyOf` is flattened before it is handed to `Tool.from_schema` —
branches merged into `properties` (first wins) with `required` = the intersection of the
branch `required` sets — because the Gemini API silently drops a parameter schema whose
root is a union. Other providers get the schema unchanged.

Consequence to know when debugging a google agent: the flattened schema advertises every
branch's properties, so the model may omit an argument that only its chosen branch needs.
The MCP server validates and returns its own error; nothing is lost or rewritten in the
catalog itself, and a non-google agent sees the discriminated union.

### Failure semantics for edge MCPs

| Condition | What the agent gets |
| --- | --- |
| Edge offline | `503 edge_offline` → `MCP tool '…' is offline (edge '<site>' is not connected).` |
| MCP or tool not exported | `404` → `Edge '<site>' does not export MCP tool '…'.` Also the answer from a v0.4 edge, which exports no MCPs at all |
| Rate limited | `429`, shared with the site's tool budget → `Edge '<site>' is rate-limiting tool calls; '…' was not sent.` |
| Edge overloaded | `503 edge_overloaded` → `Edge '<site>' is busy and cannot accept MCP tool '…' right now.` |
| Deadline (`edge_timeout`) | `504` → `MCP tool '…' timed out on edge '<site>' (no result before the deadline).` The session is kept and **the call is never replayed** |
| Tool error reported by the edge | `200` with `error` → `MCP tool '…' failed on edge '<site>': <reason>`. A server that answers `isError: true` is a normal result and is passed through as such |
| Session lost (`mcp_session_lost`) | In-call result: the server crashed, or the session hit its TTL/LRU cap. **Recoverable — retry manually**; the next call starts a fresh session (login state is gone) |
| Missing credentials (`missing_credentials`) | In-call result with exactly `no credentials for <email> on edge <site>` under `per_user_required` (`anonymous` in place of an address when the call carries no identity). **Recoverable** once the user seals the declared secret keys in Configuration → Edge credentials |
| Credential rejected (`credential_rejected`) | The sealed blob is bound to another target/user/site or to a retired edge key. **Recoverable** after reloading the credential form and re-entering the set; the call never ran |

All of these reach the model as an error string for that one call. Central has no retry
hook for edge MCP calls — a state-changing action must never be re-executed automatically.