# trellis-proxy (edge nodes)

`trellis-proxy` runs on an internal VM that the central Trellis install cannot reach:
outbound 443 works, inbound does not exist. It dials out to the central host over WSS,
publishes the tools **and MCP servers** listed in its `exports` / `export_mcps`
allowlists, and runs them locally.

Feature overview, topology, and failure semantics: [docs/proxy.md](../../docs/proxy.md).
Reference forms for agents (`<site>__<tool>`, `allowed_mcps: ["<site>__<mcp>"]`) and the
protocol v2 compat matrix: [docs/mcp.md](../../docs/mcp.md),
[docs/upgrading.md](../../docs/upgrading.md).

> **Status:** enrollment is live — create the site in **Admin → Edges**, then write the
> one-time token to `edge-token` on this host (mounted as a docker secret and read through
> `token_file:` in `proxy.yaml`).

## Prerequisites

- **Outbound 443 to the central host.** Nothing else. No inbound port, no port forward,
  no VPN; the tunnel is initiated from this side and re-established on its own.
- Docker Engine with the Compose v2 plugin. The image bundles Python, Node, and Go, so no
  language runtimes are needed on the VM — including for a Node stdio MCP server.
- An enrollment token from an admin (`edge_<site>_<random>`, shown once when the site is
  created in **Admin → Edges**) and the **site id** it belongs to.
- **TLS on the central listener** (`wss://`). The tunnel carries the permanent token and
  every tool payload, so it is not optional outside a single trusted segment. Runbook,
  including an internal CA and the `/edge`-only terminator:
  [docs/proxy-tls.md](../../docs/proxy-tls.md).
- Optional: egress to whatever the exported tools/MCP servers call (vendor APIs,
  internal systems), and `HTTPS_PROXY` / `NO_PROXY` in `.env` if this network only
  permits egress through a proxy. The proxy honours both for the tunnel itself.

## Install

```bash
# 1. Copy this directory to the edge host and enter it.
cd deploy/proxy

# 2. Copy your tools and MCP server manifests in. Same layout and schemas as the
#    central workspace (workspace/tools/<tool>/tool.yaml, workspace/mcps/<mcp>/mcp.yaml).
mkdir -p workspace
cp -a /path/to/your/tools/. workspace/tools/
cp -a /path/to/your/mcps/. workspace/mcps/

# 3. Configure the node.
cp proxy.yaml.example proxy.yaml
$EDITOR proxy.yaml          # site, server_url, tools_dir, exports, mcps_dir, export_mcps,
                            # secrets_dir

# 4. Provide the enrollment token. It is mounted as a docker secret (never an env var,
#    which a tool could read from /proc/<pid>/environ) and referenced by token_file:.
umask 077
printf '%s' 'edge_dc1_...' > edge-token

# 5. Create the shared credential store OUTSIDE the workspace, owned by the uid the
#    container runs as (TRELLIS_UID/TRELLIS_GID, default 1000). A bind-mount directory
#    Docker creates for you is root-owned, and the proxy could not read it.
install -d -m 0700 edge-secrets
sudo chown -R "${TRELLIS_UID:-1000}:${TRELLIS_GID:-1000}" edge-secrets

# 6. Generate the per-user credential key OUTSIDE the workspace, mode 0400. The private
#    half never leaves this host; central and the relay only ever see the public key.
#    Use the published image so the `cryptography` version matches the proxy.
#    Keep it in edge-keys/ (mounted as a DIRECTORY): `edge-keygen --rotate` writes the
#    retained `edge-key.old` beside it, and the proxy can only read that sibling if the
#    whole directory is mounted.
install -d -m 0700 edge-keys
docker run --rm -v "$PWD":/w \
  -e EDGE_PRIVATE_KEY_PATH=/w/edge-keys/edge-key \
  ghcr.io/laraibkazi92/trellis-agent-platform:latest \
  python core/proxy.py edge-keygen --path /w/edge-keys/edge-key
sudo chown -R "${TRELLIS_UID:-1000}:${TRELLIS_GID:-1000}" edge-keys

# 7. .env holds non-secret edge settings (proxy URL knobs). It is NOT
#    the credential store (mode 0600, never the tunnel token). Shared credentials are
#    one file per exported tool/MCP:
install -m 0600 /dev/null .env
$EDITOR .env                # HTTPS_PROXY=...
install -m 0600 /dev/null edge-secrets/devops-cli.env
$EDITOR edge-secrets/devops-cli.env      # DEVOPS_URL=..., DEVOPS_PASSWORD=..., ...
sudo chown "${TRELLIS_UID:-1000}:${TRELLIS_GID:-1000}" edge-secrets/devops-cli.env

# 8. Start it.
docker compose up -d

**Per-user credentials are entered in the central UI**, not here: sign in, open
Configuration → Edge credentials, pick the target and seal the declared secret keys with
the edge's published key. Central stores ciphertext; only this VM can open it. There is no
`edge-user-secrets/` directory and no `user-secrets` command in 0.6 (see
docs/upgrading.md, "v0.6.0").

**The keys must also be *declared*.** A credential file is not a second environment:
since 0.5.0 a child process receives an allowlist base env plus only the keys its
manifest declares — `secrets`, `optional_secrets`, `variables`, and the `fields` of each
`secret_groups` option in `tool.yaml` / `mcp.yaml`. A file key that no manifest declares
is never injected, so put the key in the manifest as well. For a legacy tool that cannot
declare every key it reads, `env_passthrough: true` restores the v0.4 whole-environment
behaviour (the tunnel token and framework secrets are still stripped).

`proxy.yaml` is mounted read-only at `/etc/trellis/proxy.yaml`. The sample compose mounts
the workspace at `/app/workspace` read-write, because exported tools may write there (the
runner mounts one writable output dir when a manifest asks for it); mount it `:ro` only
when every exported item is read-only (writes then fail inside the tool container). `workspace/mcps` sits inside the workspace tree, `edge-secrets`
outside it, and the edge key is a read-only file mount into `trellis-proxy` only (never
into `runner`). Tool/MCP edits are a content change plus a `SIGHUP` to re-publish the
catalog (the proxy reconnects, so an in-flight call fails rather than being replayed), or a
restart. No manual file copy is needed after editing a manifest.

## Credentials

The shared store is edge-local: it is never sent over the tunnel or stored in central
etcd. Per-user sets are browser-sealed ciphertext in central and are opened here with the
edge key. `proxy.yaml` chooses, per exported item, which source a call may read:

| `credential_mode` | Chain, per declared key |
| --- | --- |
| `shared` (default) | `edge-secrets/<name>.env` → process env → unset |
| `per_user` | the caller's sealed set if present; else shared → process env → unset |
| `per_user_required` | the caller's sealed set **only** — nothing sealed refuses the call (`missing_credentials`, `no credentials for <email> on edge <site>`) before anything is spawned |

A sealed set is all-or-nothing for **secrets**: a declared secret it omits stays missing
and is never filled from the shared file or the process env. `variables` (endpoints) are
always this edge's configuration and are never taken from a sealed set.

Populate the shared store with one `<tool-or-mcp>.env` per exported item:

```bash
install -m 0600 edge-secrets/devops-cli.env
$EDITOR edge-secrets/devops-cli.env       # KEY=VALUE lines
sudo chown "${TRELLIS_UID:-1000}:${TRELLIS_GID:-1000}" edge-secrets/devops-cli.env

# key names only; values are never printed
docker compose exec trellis-proxy python -c \
  'from core.edge_user_secrets import CredentialStore, parse_env_file; \
   print(sorted(parse_env_file(CredentialStore().shared_file("devops-cli"))))'
```

The key lifecycle is `edge-keygen` (create), `--show` (public fingerprint), `--rotate`
(keep `edge-key.old` for the overlap) and `--drop-old-key` (end it). Losing the key means
every user re-enters their set; there is no recovery, by design.

File format, parsed defensively and never evaluated:

- one `KEY=VALUE` per line; blank lines and `#` comments are skipped;
- an optional leading `export ` is accepted (shell/dotenv habit);
- one layer of matching quotes is stripped, and nothing is interpolated — `$OTHER` stays
  the literal text `$OTHER`;
- `KEY=` (empty) means **unset** in the shared layer, so a blank template line cannot
  blank a working credential;
- values cannot contain newlines, and a malformed line is ignored rather than costing the
  rest of the file.

Set `credential_mode` last: going to `per_user_required` before every operator has sealed a
set turns their next call into a fail-closed `missing_credentials` error. A tool's mode is
applied by `SIGHUP`; MCP sessions resolve credentials once at creation, so `SIGHUP` also
retires every live session and the next call reopens it with the current set.

## MCP servers

`export_mcps` is a second, independent allowlist. A bare name uses the defaults; the
mapping form adds per-server policy (`include_tools`, `exclude_tools`, `credential_mode`,
`session_ttl_minutes`, `max_sessions`) — see `proxy.yaml.example` for the worked
`devops-cli` shape (stateful Node stdio server, explicit `tools:` catalog, top-level
`oneOf` schemas, `per_user_required`).

- **Sessions are per `(mcp, user)`**, not per connection: one long-lived server process
  and one `HOME`/`TMPDIR` per user, so login state survives calls *and* tunnel reconnects
  and never crosses between users — even when everyone shares one service account.
- **Idle sessions are retired** after `session_ttl_minutes` (default 30, LRU beyond
  `max_sessions`, default 8 per server / 32 per edge). A retired or crashed session is
  reported in that call as `mcp_session_lost` and restarted lazily on the next one; **no
  MCP call is ever replayed automatically**.
- **`inputSchema` is published verbatim** — `oneOf`/`anyOf`, `const`, `enum`, `$ref` all
  survive to the registry and to external MCP clients. A description longer than 8 KiB is
  truncated (the schema never is), so the published description can be shorter than
  `mcp.yaml`.
- **Node servers may need more address space** than the default: raise the manifest's
  `limits:` block (`memory`, `cpus`) in `mcp.yaml` / `tool.yaml` -- the runner applies it
  as cgroup v2 limits on the session container. There is no env knob for it.

## Verify

```bash
docker compose logs -f trellis-proxy  # one line per connection state change, never bodies
```

`docker compose ps` only proves the process is alive: the proxy never exits on a tunnel
failure, it reconnects in a loop, so the container shows `Up` either way. Watch the log or
the central view. The one-line check that matters is on the **central** side: the relay
behind nginx reports the site as connected.

```bash
# on the central host (the relay is not published; go through its own container network)
docker compose exec host curl -sf http://edge-relay:8100/healthz
```

**Admin → Edges** is the full verdict: connected/offline per site, the tool inventory the
catalog published, and — for MCP export — one row per server (name, tool count,
transport) plus a `proto` badge and one badge per capability (`tools`, `mcp`). Scan for
`proto 2` together with the `mcp` badge; a site showing `proto 2` and only `tools`
published no MCP server (empty `export_mcps`, a manifest that failed to load, or a catalog
too large for the hello budget — the proxy logs which). An agent turn against one exported
tool and one exported MCP tool is the end-to-end proof.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Handshake fails with **HTTP 401** / close **4403** | Token unknown, revoked, or disabled; or it belongs to a different site than `proxy.yaml` says | Re-check the token in `edge-token` (or `token_file:`); if revoked, have an admin rotate it and write the new value |
| Tunnel closes with **4409** (`site superseded`) | A newer connection for the same site exists — typically an old container still running on a second host | Stop the duplicate (`docker compose down` there); 4409 is also what a redeploy sees for a moment, so confirm it repeats before acting |
| Tunnel closes with **4001** right after `Connected … as site` | Version mismatch: this edge speaks protocol v2 and the central relay is still v0.4.x — the proxy logs `version mismatch: … upgrade central first` once, then retries only at the maximum backoff | Upgrade **central** first; the proxy reconnects on its own once it is (see `docs/upgrading.md`) |
| **Nothing published** / no tools in Admin → Edges | `exports` is empty (or names do not match `tool.yaml` `name:` fields, or `tools_dir` does not exist in the container) | `exports` is an allowlist and an empty list publishes nothing. List the tools explicitly, then SIGHUP. Publishing an empty catalog keeps the site's existing central tools and flags a warning, so a typo cannot wipe the inventory |
| Site connected but **no MCP rows** in Admin → Edges | `export_mcps` is empty, a name does not match an `mcp.yaml` under `mcps_dir`, `include_tools` filtered everything, or the catalog did not fit the hello frame budget | Check `docker compose logs trellis-proxy` for the load/publish warning, fix `export_mcps`/the manifest, then SIGHUP |
| MCP call fails with **`missing_credentials`** | `credential_mode: per_user_required` and the caller has no sealed set (or it lacks a declared secret) | Have the user seal the declared secret keys in Configuration → Edge credentials, or relax the mode to `per_user`/`shared` |
| **`credential_rejected`** on a tool/MCP call | The sealed blob is for another target/user/site, or it was sealed to a key the edge retired | Reload the credential form (it re-fetches the current key) and re-enter the set |
| Sealed credentials never reach a container | The edge has no key (`No usable edge credential key` at startup), or a rotation dropped the old key too early | Run `edge-keygen --show` and compare the fingerprint with Admin → Edges; generate one if missing |
| Tool runs but a variable the manifest declares is missing | The key is in the file but **not declared** in `tool.yaml` / `mcp.yaml`, or `KEY=` is empty | Declare it (`secrets`/`optional_secrets`/`variables`/`secret_groups`) and give it a value; `env_passthrough: true` only as a last resort |
| Node MCP server is killed / fails to start | The manifest's `limits:` block is at or below the default memory | Raise `limits: {memory: ...}` in `mcp.yaml` and reopen the session |
| **`503 edge_offline`** on a tool call | The site is not connected: tunnel down, wrong token, or relay restarted | `docker compose logs -f trellis-proxy` for the reconnect reason; edges retry with jittered backoff (1 s → 60 s) |
| `CERTIFICATE_VERIFY_FAILED` / `certificate is not valid for '<name>'` | The edge does not trust the relay's CA, or the URL does not match the cert SAN | [docs/proxy-tls.md](../../docs/proxy-tls.md) §5–6 |
| **No outbound connection at all** | Egress firewall, or a proxy that needs `HTTPS_PROXY`/`NO_PROXY` | Test from inside the container: `docker compose exec trellis-proxy curl -sI https://trellis.example.com/`. `wss://` needs 443 and, if a proxy is enforced, `HTTPS_PROXY` set in `.env` |
| **`token_file … is empty`** on restart | The token file was a writable copy, and the proxy removed it after the first read (it logs `token file … was removed after reading`) | Re-provision `edge-token`, or use the sample compose secret (mounted read-only, so it survives restarts) |
| Tool calls fail with a runner/container error | The edge `runner` is down, its `RUNNER_TOKEN` does not match, `TRELLIS_HOST_WORKSPACE` is wrong, or the configured `CONTAINER_DEFAULT_RUNTIME` is not registered (e.g. `runsc` on a dev machine) | `docker compose logs runner` for the specific check; fix the env value or set `CONTAINER_DEFAULT_RUNTIME=runc` on a host without gVisor |
| Tool works on the edge but not through the central agent | Tool not in `exports`, name collision with an existing central tool (registration refused), or invalid schema | The relay logs the rejected tool and keeps the rest; fix `exports`/name/schema and restart |

## Upgrade order

**Central first, then edges.** An old edge against a new central is fully supported (a
v0.4 edge is tools-only, and the relay sees `caps: ["tools"]`); a new edge against an old
central is refused at the handshake with close code **4001**, which the proxy logs as
`version mismatch … upgrade central first` once and then retries only at the maximum
backoff (60 s, jittered). On boxes that run published images (nginx/gateway fronted), use
the documented two-step rebuild — never `docker compose up -d --build` — so signed
provenance survives; details in [docs/upgrading.md](../../docs/upgrading.md).

Rolling back is safe in both directions: reverting central stops v0.5 edges at the
handshake (visible, no data loss), and reverting an edge leaves central serving its
tools-only catalog. `/registry/mcps/<site>__*` entries left behind are inert to v0.4 and
pruned by the next v0.5 publish.

## Security model

- **Declared tools only.** The relay can invoke the tools and MCP tools in this node's
  catalog and nothing else. The edge independently re-checks its own `exports` /
  `export_mcps` allowlists and refuses any `tools/call` name it did not publish, so a
  compromised relay still cannot reach an unexported tool or the network behind it.
- **No inbound path.** The tunnel is outbound from this VM. There is no listener, no
  published port, and nothing on the central side that can dial into this network.
- **Credentials do not mix.** The shared service account lives in this host's
  `edge-secrets/` volume, never in the workspace (tool code runs as the same uid and can
  read whatever the workspace exposes). A per-user set exists here only as ciphertext
  sealed to this edge's public key; the private key is a 0400 file mounted read-only into
  `trellis-proxy` only and never into a tool container. Only the keys a manifest declares
  reach a process; the tunnel token and framework control-plane secrets never do, in any
  mode. Central stores the envelope and can never open it.
- **The edge trusts central's identity assertion.** `TRELLIS_USER_EMAIL` / `TRELLIS_USER_ID`
  arrive over the authenticated tunnel, and that identity is part of the AAD the sealed
  set is bound to. Central is the authority for who is calling; the edge enforces what
  that caller may read. A blob stored for one person cannot be opened for another -- the
  GCM tag fails, which is `credential_rejected`.
- **Tool code is trusted.** Tools share the proxy's uid, so they can read what it can
  read. Review exported tool code like a service account. The enrollment token is
  file-mounted (not inherited through the environment) and the file is unlinked after
  reading; a read-only secret mount cannot be unlinked, which is the documented residual.
