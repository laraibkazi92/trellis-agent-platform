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
- `tools` (Optional): A static list of tool definitions (`name`, `description`, `inputSchema`) exposed by the server. You normally don't write this by hand: when it's absent, the registry sync live-connects to the server (spawning the `stdio` command or opening the HTTP URL, with a ~20s budget), discovers its tools, and persists the discovered list into the registry config automatically. That list then feeds the runtime's discovery fast-path and the semantic tool-search index (`mcp__{server}__{tool}` embeddings). Hand-listing `tools` in `mcp.yaml` skips discovery entirely — useful when the server can't be reached from the sync environment; if discovery fails, the config is still saved and the runtime falls back to live discovery.
- `network` (Optional): `allow` (default) or `none`. Only applies to `stdio` servers: `none` gives the spawned process no IP network (bwrap `--unshare-net`, or Landlock TCP deny on ABI ≥ 4). `http`/`sse` transports ignore it. On an edge this is the stdio MCP server's sandbox net policy, and it is enforced on the edge, not here.
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
transport, the site's MCP count, and protocol badges — `proto 2` plus one badge per
capability (`tools`, `mcp`). A v0.4 edge shows `proto 1` and `tools` only. A server the
edge configured but dropped for size is absent from this table; the edge log says why.

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
`Remote*Spec` fields, has no lookarounds and spells the same ban without one — so a site
or tool name ending in `_` can be published but not expressed as a reference.)

Ambiguity rules:

- Site, MCP and tool names cannot contain `__`; that double underscore is the separator,
  and a name containing one is rejected when the manifest is saved or synced.
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
| Missing credentials (`missing_credentials`) | In-call result with exactly `no credentials for <email> on edge <site>` under `per_user_required` (`anonymous` in place of an address when the call carries no identity). **Recoverable** once an operator runs `user-secrets set` |

All of these reach the model as an error string for that one call. Central has no retry
hook for edge MCP calls — a state-changing action must never be re-executed automatically.