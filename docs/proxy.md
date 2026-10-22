# Edge Nodes (trellis-proxy)

An **edge node** is a Trellis install on a network you cannot reach from the central
host: an internal VM, a private subnet, an on-prem appliance. It has outbound access to
the internet but no public IP and accepts no inbound connections.

`trellis-proxy` closes that gap without opening a path into the customer network. It runs
the **same image** as the central stack with a different entrypoint, dials out over WSS,
and executes some of its local tools and MCP servers on request. Those tools appear
centrally as normal native tools, so agents, tool search, health tracking, and usage
accounting work unchanged.

Since `v0.5.0` an edge also exports **MCP servers**: it publishes each server's tool
catalog verbatim and executes `tools/call` against a long-lived per-user session, with
the server's credentials staying on the edge. Agents and workflows still run centrally.

> **Status:** the tunnel, native tool registration, and MCP export are implemented
> (wire protocol v2). Edges enroll from **Admin → Edges**, their tools appear in
> `/registry/tools` as `<site>__<tool>` and their MCP tools as
> `mcp__<site>__<mcp>__<tool>`, and the hub/gateway execute both like a central tool.
> Edge-hosted agents are not part of this release.

## Topology

```text
INTERNAL VM -- outbound 443 only, no public IP
┌──────────────────────────────────────────────────┐
│ trellis-proxy   (same image, new entrypoint)     │
│  workspace/tools/**   (tool.yaml)                │
│  workspace/mcps/**    (mcp.yaml, v0.5)           │
│  proxy.yaml          (site, server_url, exports, │
│                       export_mcps)               │
│  edge-secrets/       (shared credentials)        │
│  edge-user-secrets/  (per-user credentials)      │
│  sandbox (bwrap | Landlock)                      │
└──────────────────┬───────────────────────────────┘
                   │ wss://central/edge/v1/connect
                   ▼
CENTRAL
nginx :443 ── location /edge ──► edge-relay:8100      (compose service, since v0.4.0)
                                    │ site → live connection (in memory)
                                    │ POST /v1/sites/{site}/call  (internal only)
                                    │ POST /v1/sites/{site}/mcps/{mcp}/call
                                    └── writes /registry/edges/<site>/…
                                        writes /registry/tools/<site>__<tool>/…
                                        writes /registry/mcps/<site>__<mcp>/…
                                        records tool health
                                        ▲
                                     hub.run_tool
                                     agent_factory / gateway
                                       config.remote → relay HTTP
```

The relay is a tunnel terminator, not an MCP server: it speaks plain internal HTTP to the
hub and one WebSocket per site to the edges. It runs as a single replica because the
site → connection map lives in process memory.

## Enrollment

There is no bootstrap flow. An admin registers the site first, so every connection is
attributable to an operator action.

1. **Admin → Edges → create site.** Choose the site id (e.g. `plant-floor`) and a display
   name. The enrollment token is shown **once**; the registry stores only its SHA256.
2. **Install the edge.** Copy [`deploy/proxy/`](../deploy/proxy/), fill in `proxy.yaml`,
   write the token to `edge-token` (mounted as the `edge_token` docker secret and read via
   `token_file:`), then `docker compose up -d`. Full runbook:
   [deploy/proxy/README.md](../deploy/proxy/README.md).
3. **Connect.** The proxy dials `wss://<central-host>/edge/v1/connect` with subprotocol
   `trellis.edge.v1` and its token. The relay derives the site from the token hash —
   never from a client-supplied name — and publishes the tools listed in `exports` as
   `<site>__<tool>`, plus the MCP servers listed in `export_mcps` (see
   [Exporting MCP servers](#exporting-mcp-servers)).
4. **Use.** Agents reach edge tools through ordinary tool search and calls; nothing in the
   agent config references the edge. MCP servers are named explicitly — an agent opts in
   with `allowed_mcps: ["<site>__<mcp>"]` (see
   [mcp.md](mcp.md#wiring-edge-mcps-to-an-agent)) — but their tools are still ordinary
   tool-search entries.
5. **Rotate or revoke** in **Admin → Edges** whenever the token changes hands. Revocation
   closes a live socket with `4403` and rejects the next handshake with `401`.

A second connection for the same site **supersedes** the first (`4409` close), so a
redeploy never gets stuck behind a zombie socket. If two hosts run the same site by
mistake, only one of them serves calls.

## Authoring tools

An edge tool is authored like a local one: `workspace/tools/<tool>/tool.yaml` plus its
script, same fields, same sandbox. There is no remote-specific marker to add and no
`mcp__` naming — the relay does the translation from catalog to registry.

What differs on an edge:

- **`exports` is the allowlist.** `proxy.yaml` lists which tools this node publishes. An
  empty list publishes nothing; a tool that is not listed is neither advertised nor
  executed, even if the central side asks for it. An entry is either a bare name or a
  mapping `{name, credential_mode}`.
- **Only declared keys reach the child.** A tool no longer inherits the edge's process
  environment. The keys named in its `tool.yaml` — `secrets`, `optional_secrets`,
  `variables`, and the field keys of `secret_groups` — are what gets injected; anything
  else in the edge container's `.env` is invisible. See
  [Environment scoping](#environment-scoping).
- **Credentials are resolved per call from edge-local files**, with an optional per-user
  store, so the v0.4 limitation that every edge tool ran as one service account no longer
  applies. See [Edge-local credentials](#edge-local-credentials).
- **`retry_on_transient` defaults to `false`** for remote tools: a dropped tunnel must not
  silently replay a call that already had a side effect.

Tool manifests published by an edge are read-only in the central tool editor; edit them
on the edge and send `SIGHUP` to re-publish the catalog (the proxy reconnects; in-flight
calls fail rather than being replayed). See
[Reloading without a restart](#reloading-without-a-restart).

## Exporting MCP servers

An edge can publish MCP servers from `mcps_dir` (default `workspace/mcps`, same
`mcp.yaml`/`MCPConfig` schema as central) exactly as it publishes tools. The central side
never connects to them: the edge publishes each tool's `inputSchema` **verbatim** and
executes `tools/call` locally, so no inbound path and no central credential is involved.
Consuming an edge MCP from an agent is covered in
[MCP Server Guide → Edge-hosted MCP servers](mcp.md#edge-hosted-mcp-servers).

`export_mcps` is a second, independent allowlist. An empty list exports nothing. Two
forms per entry:

```yaml
export_mcps:
  # bare name: shared credentials, default session policy
  - coralogix
  # mapping form: every key optional except `name`
  - name: devops-cli
    include_tools: [tenant_account_tools, list_actions]   # publish only these
    exclude_tools: [tenant_admin_tools]                   # never publish/serve these
    credential_mode: per_user_required                    # shared | per_user | per_user_required
    session_ttl_minutes: 30                               # idle TTL for a user's session
    max_sessions: 8                                       # concurrent sessions for this server
```

All six keys are validated at config load, so a typo is a startup error naming the entry
rather than a server that silently never publishes.

**The edge is the name authority.** `include_tools` narrows the published catalog to just
those names; `exclude_tools` is applied after it and wins over an included name; any name
neither published nor known is refused locally with `unknown_tool` or `unknown_mcp`, even
when the relay explicitly asks for it. `exports`/`export_mcps` are enforced on the edge
precisely because the target MCP server accepts flat action names: a compromised relay
cannot widen the surface, and a state-changing action cannot be reached by guessing a
tool name the operator did not publish.

### What gets published

One `hello` frame carries the tool catalog plus every MCP catalog: per server, the name,
the edge-side transport (for display) and each tool's `name`, `description` and
`inputSchema`. Central writes it to `/registry/mcps/<site>__<mcp>/config` with
`transport: "remote"` and a `remote: {site, mcp}` block, and indexes a
description-only embedding per tool (`mcp__<site>__<mcp>__<tool>`) so tool search can
rank it. Schemas are never rewritten, cleaned or coerced on the way; arguments are passed
to the server as the model produced them and the server validates them.

A tool description is truncated to 8 KiB when published (`MAX_MCP_DESC_CHARS`), so a
published description can be shorter than the `mcp.yaml` one. The `inputSchema` is never
touched — an oversized schema is a rejection, not a truncation.

### Catalogs: static or discovered

- **Static `tools:` in `mcp.yaml`** — published verbatim, with no connection at publish
  time. Use this when the server cannot be reached from the edge's discovery path or when
  you want the catalog pinned to the file (the reference `devops-cli` shape does this).
- **Live discovery** — with no `tools:` block the edge runs `tools/list` against a
  throwaway client: a 20 s budget per server (`DISCOVERY_TIMEOUT_S`), concurrent across
  servers on a reload, and cached per export signature so a reconnect does not re-spawn
  everything. A server that fails discovery is skipped with a log; the other exports and
  all tools keep working.

An MCP server that requires `per_user_required` credentials cannot be discovered (there is
no caller to resolve against) — declare a static `tools:` catalog for it.

### Catalog limits

| Limit | Value | On overflow |
|---|---|---|
| MCP servers per edge (`MAX_MCPS`) | 50 | only the 50 whose names sort first are exported; the rest are skipped and logged |
| Tools per server (`MAX_MCP_TOOLS_PER_SERVER`) | 256 | the server's catalog is refused; logged |
| `inputSchema` bytes per tool (`MAX_MCP_SCHEMA_BYTES`) | 128 KiB | that server is dropped from the publish; logged |
| Whole hello frame (`MAX_FRAME_BYTES`) | 10 MiB | the **largest MCP catalogs are dropped** with an `ERROR` log until it fits |

The last one is the important failure mode: the relay refuses an oversized hello and the
edge would redial with the same frame forever, which takes *everything* down. The edge
therefore degrades visibly — it drops the largest MCP catalogs and keeps publishing its
tools plus the remaining MCPs. An MCP the operator configured can therefore be absent
from Admin → Edges while its host still serves tool calls; the `ERROR` line in
`docker compose logs trellis-proxy` names the server and says to export fewer or smaller
MCP servers.

## Environment scoping

`v0.4.0` handed each tool the proxy's environment minus a denylist. Since `v0.5.0` it is
an **allowlist**, on the edge only (the central hub is unchanged):

- always present: `PATH`, `HOME`, `LANG`, `TZ`, `TMPDIR`, `HTTP_PROXY`, `HTTPS_PROXY`,
  `NO_PROXY`, `SSL_CERT_FILE` (and their lowercase variants), plus every `LC_*` and
  `TRELLIS_*` name;
- plus only the keys the tool or MCP server declares in its manifest — `secrets`,
  `optional_secrets`, `variables` (list- or dict-shaped) and the field keys of every
  `secret_groups` option.

Everything else in the edge container's environment is invisible to the child. The tunnel
token (`TRELLIS_EDGE_TOKEN`, and a custom `token_env` name if you set one) and the
framework's own control-plane names are stripped **in every mode**, including passthrough
and a literal `mcp.yaml` `env:`. Provider API keys are the deliberate exception: a tool
that calls an LLM declares `OPENAI_API_KEY` and it still arrives.

Identity is injected per call, never inherited: `TRELLIS_USER_ID` and `TRELLIS_USER_EMAIL`
are set from the frame for that caller only.

**The escape hatch.** A legacy tool that cannot declare every key it reads can set
`env_passthrough: true` (or `TRELLIS_EDGE_ENV_PASSTHROUGH=true`), which restores the v0.4
denylist behaviour — minus the token. It gives up the isolation between tools: every
exported tool then sees the whole sanitized edge environment. It needs a restart to
change.

**CA bundle gap.** `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `SSL_CERT_DIR` are *not* in
the allowlist. A corporate base image that sets only those will see TLS failures from an
exported tool or MCP server until the keys are declared in `tool.yaml`/`mcp.yaml` (or
passthrough is enabled). `SSL_CERT_FILE` is always present.

## Edge-local credentials

Credentials live in files on the edge VM only. They never cross the tunnel and never touch
etcd — the relay forwards an identity, not a secret.

> **Trust boundary.** The edge trusts central's identity assertion. The `user_email` in a
> call frame was resolved centrally from the authenticated user and arrives over the
> authenticated tunnel; the edge does not re-authenticate the caller, and it has no way
> to. Anyone able to submit a call frame with an arbitrary `user_email` can act as that
> user on the edge. Keep the tunnel token and the relay's internal API inside the trust
> perimeter you already give the central install.

### Stores

| Setting | Default | Env override | Holds |
|---|---|---|---|
| `secrets_dir` | `edge-secrets` | `TRELLIS_EDGE_SECRETS_DIR` | `<tool-or-mcp>.env`, one service account per exported item |
| `user_secrets_dir` | `edge-user-secrets` | `TRELLIS_EDGE_USER_SECRETS_DIR` | `<normalized-email>.env`, one file per person |

Both must live **outside** the sandbox-writable workspace, and both need an edge volume:
the workspace is the only path a tool can write, so a credential store inside it would be
readable (and writable) by every exported tool. The sample compose mounts them at
`/etc/trellis/edge-secrets` and `/etc/trellis/edge-user-secrets`; if you maintain your own
compose file, add the mounts
([upgrading.md](upgrading.md#compose-and-volume-changes)). The *paths* need a restart;
their *contents* do not (tool calls re-read them, MCP sessions re-read them at creation or
on `SIGHUP`).

### Modes and resolution order

`credential_mode` is edge policy in `proxy.yaml` — set per entry in `exports` or
`export_mcps`, default `shared`. It is not a `tool.yaml` field.

| Mode | Per declared key, first match wins |
|---|---|
| `shared` (default) | `<secrets_dir>/<name>.env` → process environment → unset |
| `per_user` | `<user_secrets_dir>/<email>.env` → shared file → process environment → unset |
| `per_user_required` | the user's file **only**; if none of the declared keys is there the call fails closed with `missing_credentials` and **nothing executes** |

`shared` never reads per-user files. Only keys the manifest declares are read out of a
file, so an extra key in someone's `.env` cannot reach a child process. An anonymous
caller (no `user_email`) has no per-user file, so `per_user` falls back to the shared
file and `per_user_required` fails closed. For MCP sessions, credentials are resolved once
at session creation (see [MCP sessions](#mcp-sessions)).

### File format

Plain `KEY=VALUE`, one per line — the same dotenv subset in both stores:

```bash
# /etc/trellis/edge-secrets/devops-cli.env   (mode 0600)
# `#` starts a whole comment line (there is no trailing-comment syntax);
# a leading `export ` is accepted.
DEVOPS_URL=https://devops.internal
DEVOPS_USERNAME=svc-edge
export DEVOPS_PASSWORD=...
CORALOGIX_API_KEY=...
```

No interpolation, no quoting shell semantics beyond one layer of matching quotes, no
`${VAR}` expansion, and no trailing comments — a `#` must be the first non-space
character. `KEY=` (empty or whitespace-only) counts as **unset** in every layer, so a
blank template line can neither satisfy `per_user_required` nor blank a working value.
Later duplicates win. An unparseable line is ignored rather than failing the file.

### Permissions

Files written by `user-secrets set` are atomic and `0600`; directories it creates are
`0700` (the parent is only chmod-ed when it creates it, so an operator-mounted `0750`
directory stays theirs). A permissive **shared** file logs a warning and is still read —
the shared account is the operator's call, and refusing to run would turn a permission nit
into an outage. A permissive per-user file also warns.

### `user-secrets` CLI

Run it inside the edge container, against the same `proxy.yaml` the proxy uses:

```bash
# write or merge one operator's keys (reads KEY=VALUE from stdin)
docker compose exec -T trellis-proxy \
  python core/proxy.py user-secrets set ops@example.com \
  --config /etc/trellis/proxy.yaml <<'EOF'
DEVOPS_USERNAME=ops
DEVOPS_PASSWORD=...
EOF

# key names only — safe to paste into a ticket
python core/proxy.py user-secrets list --config /etc/trellis/proxy.yaml

# revoke (removes the file; the next call fails under per_user_required)
python core/proxy.py user-secrets delete ops@example.com --config /etc/trellis/proxy.yaml
```

`set` merges into an existing file (so rotating one password does not drop the others),
writes a leading `# email: <address>` comment used by `list` for display only, and
refuses to overwrite a file it cannot read (exit 1) rather than silently discarding its
keys. The address is normalized into the filename — lowercased, non-alphanumerics
collapsed to `-`, plus an 8-character hash suffix, e.g.
`ops-example-com_1a2b3c4d.env` — so case variants of one address share one file.

## MCP sessions

One long-lived session per `(mcp, user identity)`. The identity key is the normalized
`user_email`, else `user`, else `"anonymous"`; each session gets its own `HOME`/`TMPDIR`
under the sandbox writable root, which is what isolates two users' login state even when
they share credentials.

- **Idle TTL** 30 minutes, overridable per `export_mcps` entry (`session_ttl_minutes`). A
  periodic sweep retires idle sessions; a call in progress is never swept.
- **Caps:** 8 sessions per MCP (`max_sessions`), 32 per edge. At the cap the least
  recently used **idle** session is evicted.
- **Survives a tunnel reconnect.** Sessions are edge-local, so a relay restart or a
  network blip does not cost a user their login.
- **A `SIGHUP` retires every session** (no error to the next caller — the server is simply
  reopened). That is the operator's way to make an edited credential file apply without
  waiting out the 30-minute TTL.
- **A crash is reported, not hidden:** that call's result carries `mcp_session_lost` and
  the server is restarted lazily on the *next* call. TTL expiry and LRU eviction produce
  the same one-shot marker. **No MCP call is ever replayed automatically** — a
  state-changing action must not run twice.
- **A deadline is not a crash.** When the call's `edge_timeout` expires the session is
  kept (the login state stays intact) and only that call fails.
- **Per-session serialization:** calls to one session are serialized; `kind:"mcp"` frames
  share the tunnel-wide in-flight semaphore (`MAX_INFLIGHT`) with tool calls.

stdio servers are spawned under the same sandbox backend as tools, with the server
directory as `cwd` — the layout `npx`-style servers expect. `http`/`streamable-http`/`sse`
servers spawn no process and run no sandbox; the declared credentials are sent as headers
only. `mcp.yaml`'s `network:` (`allow`/`none`, default `allow`) controls the stdio
process's network namespace.

### Sandbox limits for Node MCP servers

A stdio MCP server lives for the whole session rather than one call, so size the limits
for a long-lived Node process:

- `SANDBOX_RLIMIT_AS_MB=8192` is the recommended value; the `4096` default is tight for
  Node and produces an `ENOMEM` that looks like a server crash.
- `SANDBOX_RLIMIT_CPU_S` is consumed CPU, not wall clock, so the 600 s default does not
  retire an idle session.
- These are `setrlimit` calls made by the **Landlock** helper before `exec`; under bwrap
  they do not apply and the container's own limits are the backstop. See
  [deploy.md → Sandbox settings and rollback](deploy.md#sandbox-settings-and-rollback).

## Protocol v2 and compatibility

`v0.5.0` bumps the edge/relay protocol to `proto: 2`. The handshake stays strict:

- The hello frame gains `caps` (`["tools"]` or `["tools", "mcp"]`) and `mcps` (the
  catalogs). A proto-1 hello has neither and is read as tools-only.
- Calls carry `kind: "tool" | "mcp"` (absent means `"tool"`, so v0.4 frames are
  unchanged), plus `mcp` for MCP calls and the optional `user_email`.
- **Upgrade central before edges.** A v0.5 edge dialing a v0.4 relay is refused at the
  handshake with `CLOSE_VERSION` (close code `4001`); the edge logs one terminal
  "version mismatch — upgrade central first" line and retries only at the maximum backoff
  (60 s, jittered), so it never reads as a generic disconnect.
  The reverse — a v0.4 edge against a v0.5 relay — is fully supported: its tools work
  unchanged and MCP calls to it answer `404` ("edge does not export MCPs").


## Failure semantics

| Condition | Behavior |
| --- | --- |
| Edge offline | Relay answers `503 edge_offline` → the hub returns `Tool '<site>__<tool>' is offline (edge '<site>' is not connected).`; a health event is recorded; no retry storm |
| Edge drops mid-call | In-flight calls fail with `edge_disconnected`; they are never replayed |
| Token revoked | Handshake `401`; a live socket is closed with `4403` |
| Relay restart | Edges reconnect with jittered backoff (1 s → 60 s); catalogs are republished |
| Tool timeout | The edge kills the process tree (existing sandbox logic) and returns an error result |
| MCP server not exported | Relay answers `404 unknown_mcp`; central reports that the site does not export the MCP tool |
| MCP deadline (`edge_timeout`) | The call fails; the session is **kept** (login state intact) and nothing is replayed |
| MCP server crashed / session evicted | That call returns `mcp_session_lost`; the next call starts a fresh session |
| MCP credentials missing (`per_user_required`) | The call returns `missing_credentials` (`no credentials for <email> on edge <site>`); nothing is spawned |
| Hub → relay timeout | `504` → tool error |
| Invalid catalog entry | That tool is rejected and logged; the site's other tools still register |
| Name collision with a local tool | Registration is refused for the colliding tool only, and logged |
| Duplicate connection for a site | The older connection is closed with `4409` |
| Edge publishes an empty catalog | Existing tools (and MCP servers) are **kept** (a mistyped `tools_dir`/`mcps_dir` or missing volume must not wipe the central inventory); the site's status carries a warning. Narrowing `exports` in Admin still prunes |

## Central requirements

- The `edge-relay` service (added by `docker-compose.yml`; one worker, internal port
  8100) and the `/edge` location in `gateway/entrypoint.sh`. **Rebuild nginx and the app
  image when you deploy this**: an edge pointed at an older nginx gets `404` on `/edge`,
  and an older app image has no `services/`, so `edge-relay` crash-loops with
  `ModuleNotFoundError`. When you build from source, `docker compose up -d --build` does it;
  on a published-image install, pull the tag and use the two-step nginx rebuild from
  [upgrading.md](upgrading.md#standard-upgrade-published-images) — never `up -d --build`
  there. Plain `docker compose up -d` reuses whatever app image is already on disk.
- `ENCRYPTION_KEY` (or `SESSION_SECRET`) is passed to `edge-relay` so it can decrypt the
  LLM provider key it needs to embed `public: true` edge tools for tool search. Without
  it the tools still publish and run, but they are never indexed and log a warning.
- The relay itself never decrypts tool secrets (only the provider key for embeddings).
- Outbound-free posture unchanged: the relay never dials an edge, so no central firewall
  rule is needed for edges beyond accepting 443 from them.
- **TLS.** The tunnel carries the site's permanent token and every tool payload, so an edge
  that crosses an untrusted network must dial `wss://`. Setup (internal CA, cert SANs, both
  termination options): [proxy-tls.md](proxy-tls.md).

## Security notes

- The only public surface is `/edge/v1/connect`. `POST /v1/sites/{site}/call` is internal
  to the compose network; it is not routed from nginx.
- The relay sees tool arguments and results in plaintext. If you operate Trellis as
  shared SaaS, you can read a customer's internal data in transit; end-to-end payload
  encryption is not part of this release.
- Site compromise is bounded to that site's catalogs. Central/relay compromise is bounded
  to the union of exported tools — not the customer's network.
- **Exported tools are trusted code on that VM.** They run unsandboxed from the proxy's
  point of view in the sense that they share its uid: they can read the workspace, the
  edge's `env_file` (a file on disk is readable to the uid even though its keys are no
  longer *inherited* into the child env), and the credential stores, and (if they are
  malicious) the token file or the proxy's memory. The token cannot cross to another
  site — it is site-scoped and the relay derives identity from its hash — but a malicious
  *tool author* on a trusted edge can impersonate that edge. Review tool code the way you
  review a service account.
  The token is read from a file and the file is unlinked, so it is not inherited through
  the process environment; a read-only secret mount cannot be unlinked, which is a
  residual (same-uid) exposure.
- **The edge trusts central's identity assertion.** Per-user credentials are selected by
  the `user_email` central puts in the call frame, over the authenticated tunnel; the
  edge cannot verify it independently. See
  [Edge-local credentials](#edge-local-credentials).
- Edge payloads are capped (10 MB frame, 1 MB arguments, 200 tools per site, 50 MCP
  servers × 256 tools × 128 KiB schema, 16 in flight) and the relay logs site, tool, call
  id, duration, and outcome — never arguments or results. MCP calls log the same fields
  plus `mcp` under the `mcp_call` event. The user id travels in the call frame for
  attribution and is not logged with the payload.

## Operating an edge fleet

### Audit trail

Every connect, disconnect, and call produces one JSON line in
`/app/data/edge-audit.log` (inside the `health-data` volume, rotated at 10 MB with 5
backups, path configurable via `EDGE_AUDIT_LOG`):

```json
{"ts":"2026-10-21T10:04:11.912+00:00","event":"call","site":"plant-floor",
 "tool":"boiler_status","call_id":"…","user":"dev-user@local.host",
 "outcome":"ok","ms":42,"args_bytes":18,"result_bytes":210}
```

`outcome` is one of `ok`, `tool_error`, `invalid_arguments`, `unknown_tool`,
`edge_offline`, `edge_disconnected`, `edge_overloaded`, `edge_timeout`, `rate_limited`,
`relay_error` — so a failed call is distinguishable from a missing tunnel.
**Arguments and results are never written**, only their byte counts: the relay is not a
place where a customer's internal data should accumulate.

MCP calls produce an `mcp_call` event with the same fields plus `mcp` and share the tool
endpoint's per-site rate-limit bucket. An edge-reported MCP failure (including
`mcp_session_lost` and `missing_credentials`) records as `tool_error`: the relay sees one
error string, not the codes the edge uses internally.

### Rate limiting

Two independent limits:

| Layer | Setting | Default | Scope |
|---|---|---|---|
| nginx `/edge` | `EDGE_RATE_LIMIT_RPS` / `EDGE_RATE_LIMIT_BURST` | 30 r/s, burst 20 | per client IP, connection-level flood |
| relay | `EDGE_RATE_LIMIT_PER_MIN` | 120 calls/min | per site (token bucket) |
| relay | site record `rate_limit_per_min` | inherits the default | per site override, editable in Admin → Edges |

An over-limit call never reaches the edge: the relay answers `429 rate_limited` and the
hub surfaces "Edge '<site>' is rate-limiting tool calls; '<site>__<tool>' was not sent." The
limit is a token bucket with capacity equal to the rate, so a short burst is allowed and
sustained traffic is capped.

### Optional mutual TLS

TLS for the tunnel itself is a prerequisite and is covered in [proxy-tls.md](proxy-tls.md).
Everything in this section is an *additional* client-certificate check on top of it.


Set `EDGE_MTLS_CA` to a CA bundle **inside the nginx container** and uncomment the SSL
volume in `docker-compose.yml`, for example:

```bash
SSL_ENABLED=True
SSL_CERT_DIR=./gateway/ssl          # cert.pem + key.pem + edge-ca.pem
EDGE_MTLS_CA=/etc/nginx/ssl/edge-ca.pem
```

nginx then *requests* a client certificate on the TLS listener
(`ssl_verify_client optional`) and the `/edge` location refuses anything whose
certificate did not verify (`403`). The dashboard and `/v1` API are unaffected — they
simply continue without a client certificate. Issue each edge a certificate signed by that CA, then point the proxy at it (mounted
read-only into the edge container):

```yaml
# deploy/proxy/docker-compose.yml -- mount the directory read-only
# volumes:
#   - ./tls:/etc/trellis/tls:ro
```
```yaml
# proxy.yaml
tls_ca_file: /etc/trellis/tls/ca.pem
tls_cert_file: /etc/trellis/tls/edge.pem
tls_key_file: /etc/trellis/tls/edge-key.pem
```

The env equivalents are `TRELLIS_EDGE_TLS_CA`, `TRELLIS_EDGE_TLS_CERT`, and
`TRELLIS_EDGE_TLS_KEY`. The proxy builds an `ssl.SSLContext` and presents the
certificate on the WSS handshake; without it, a relay with `EDGE_MTLS_CA` set answers
`403`. Note that `ssl_verify_client optional` is listener-level, so browsers may be
prompted for a certificate — the dashboard and `/v1` do not require one.

mTLS is defence in depth on top of the enrollment token, not a replacement: the relay
still resolves the bearer token to a site.

**A misconfigured `EDGE_MTLS_CA` stops nginx, not just `/edge`.** If the variable is set
without `SSL_ENABLED=true`, or the CA file is not inside the container, the entrypoint
refuses to start (that is deliberate: silently ignoring mTLS would be a worse failure).
The dashboard, `/v1`, and `/mcp` share that nginx, so remove the variable to recover.

### Filesystem

Tools run inside the same sandbox as the hub's, which grants exactly one writable path:
`/app/workspace` (override with `SANDBOX_RW_PATH`). The directory must exist in the proxy
container. Mount it writable if any exported tool writes files; a read-only mount is fine
only for read-only tools. The proxy logs a warning at startup when the path is missing.

MCP session state lives under that same root (`mcp-sessions/<mcp>/<hash>/`, mode `0700`),
as each session's `HOME`/`TMPDIR`. A read-only workspace mount therefore breaks stdio MCP
sessions — and server login state is exactly what they store there.

### Reloading without a restart

`SIGHUP` (`docker kill -s HUP trellis-proxy`) re-reads `proxy.yaml`, rebuilds the
catalogs, and republishes by reconnecting — in-flight calls fail rather than being
replayed.

Live (applied on the next publish):

- `exports` and each entry's `credential_mode`;
- `export_mcps` in both forms, including `include_tools`/`exclude_tools`,
  `credential_mode`, `session_ttl_minutes` and `max_sessions`;
- `tools_dir`, `mcps_dir`;
- the catalogs themselves — MCP discovery is concurrent and bounded at 20 s per server,
  and the previous entries/catalogs keep serving until the new ones are installed
  atomically, so an MCP call is never refused during the rebuild;
- **credential file contents.** Tool calls re-read the files every time; MCP sessions
  resolve credentials once at creation, so `SIGHUP` also retires every live MCP session
  (the next call reopens it with the edited file, without an error).

Restart-required (the proxy logs a warning and keeps the current value if you try):

- `site`, `server_url`, the token (`token_env`/`token_file`), the `tls_*` files;
- `sandbox` (backend selection) and `env_passthrough`;
- the `secrets_dir` / `user_secrets_dir` **paths** — the running proxy and the
  `user-secrets` CLI must agree on where the files live.

### Relay shutdown

On a graceful relay stop the edge redials within about a second (the backoff floor),
whether or not the `drain` frame reaches it — uvicorn can close the socket during
shutdown before the relay's drain loop runs. In-flight calls at that moment fail; they
are never replayed.

### Revocation latency

Revoking a token closes the **next handshake** immediately and the **live** tunnel at the
next heartbeat, i.e. within 20 seconds. Deleting a site behaves the same way and also
removes its published tools and MCP servers.

### Reconciliation

A newly connected edge's tools become callable within `EDGE_TOOL_RECONCILE_SECONDS`
(default 10, `0` disables the watcher). The hub keeps its current tool table if the
registry cannot be read, and never unregisters a tool whose config is unreadable.

### High availability

The relay keeps `site → connection` in process memory and therefore runs **one worker**
(`--workers 1` in `docker-compose.yml`). Two supported options if that ever becomes a
bottleneck:

1. **Sticky ingress** — run N relay replicas and route each edge by site (nginx
   `hash $arg_site consistent` on a site query parameter, or a header the proxy sends).
2. **Site → replica index** — publish the owning replica id to
   `/registry/edges/<site>/status` and have the hub target
   `http://edge-relay-<id>:8100`. More moving parts; needed only for real scale.

Do not put the relay behind a plain round-robin load balancer: a call landing on the
replica that does not hold the socket answers `503 edge_offline`.
