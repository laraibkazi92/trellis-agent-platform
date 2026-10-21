# trellis-proxy (edge nodes)

`trellis-proxy` runs on an internal VM that the central Trellis install cannot reach:
outbound 443 works, inbound does not exist. It dials out to the central host over WSS,
publishes the tools listed in its `exports` allowlist, and runs them locally.

Feature overview, topology, and failure semantics: [docs/proxy.md](../../docs/proxy.md).

> **Status:** enrollment is live — create the site in **Admin → Edges**, then paste the
> one-time token into this host's `.env` as `TRELLIS_EDGE_TOKEN`.

## Prerequisites

- **Outbound 443 to the central host.** Nothing else. No inbound port, no port forward,
  no VPN; the tunnel is initiated from this side and re-established on its own.
- Docker Engine with the Compose v2 plugin. The image bundles Python, Node, and Go, so no
  language runtimes are needed on the VM.
- An enrollment token from an admin (`edge_<site>_<random>`, shown once when the site is
  created in **Admin → Edges**) and the **site id** it belongs to.
- Optional: egress to whatever the exported tools call (vendor APIs), and `HTTPS_PROXY` /
  `NO_PROXY` in `.env` if this network only permits egress through a proxy. The proxy
  honours both for the tunnel itself.

## Install

```bash
# 1. Copy this directory to the edge host and enter it.
cd deploy/proxy

# 2. Copy your tools in. Same layout and tool.yaml schema as the central workspace.
mkdir -p workspace
cp -a /path/to/your/tools/. workspace/tools/

# 3. Configure the node.
cp proxy.yaml.example proxy.yaml
$EDITOR proxy.yaml          # site, server_url, tools_dir, exports, sandbox

# 4. Provide the enrollment token (0600, never committed). Compose reads .env for both
#    interpolation and env_file.
install -m 0600 /dev/null .env
cat >> .env <<'EOF'
TRELLIS_EDGE_TOKEN=edge_plant-floor_...
EOF

# 5. Start it.
docker compose up -d
```

`proxy.yaml` is mounted read-only at `/etc/trellis/proxy.yaml`; the workspace is mounted
read-only at `/app/workspace`. Tool edits are a content change plus a restart
(`docker compose restart trellis-proxy`) or `SIGHUP` to re-publish the catalog (the proxy
reconnects, so an in-flight call fails rather than being replayed). No manual file copy
is needed after editing `tool.yaml`.

## Verify

```bash
docker compose ps                     # trellis-proxy Up, restarting only if the tunnel fails
docker compose logs -f trellis-proxy  # one line per connection state change, never bodies
```

The one-line check that matters is on the **central** side: the relay behind nginx reports
the site as connected.

```bash
# on the central host (the relay is not published; go through its own container network)
docker compose exec host curl -sf http://edge-relay:8100/healthz
```

In P1 the same verdict is on **Admin → Edges**, which shows connected/offline per site
plus the tool inventory the catalog published. An agent turn that calls one of the
exported tools is the end-to-end proof.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Tunnel closes with **4403** (`token rejected`) | Token unknown, revoked, or disabled; or it belongs to a different site than `proxy.yaml` says | Re-check `TRELLIS_EDGE_TOKEN` in `.env`; if revoked, have an admin rotate it and paste the new value |
| Tunnel closes with **4409** (`site superseded`) | A newer connection for the same site exists — typically an old container still running on a second host | Stop the duplicate (`docker compose down` there); 4409 is also what a redeploy sees for a moment, so confirm it repeats before acting |
| **Nothing published** / no tools in Admin → Edges | `exports` is empty (or names do not match `tool.yaml` `name:` fields) | `exports` is an allowlist and an empty list publishes nothing. List the tools explicitly, then restart |
| **`503 edge_offline`** on a tool call | The site is not connected: tunnel down, wrong token, or relay restarted | `docker compose logs -f trellis-proxy` for the reconnect reason; edges retry with jittered backoff (1 s → 60 s) |
| **No outbound connection at all** | Egress firewall, or a proxy that needs `HTTPS_PROXY`/`NO_PROXY` | Test from inside the container: `docker compose exec trellis-proxy curl -sI https://trellis.example.com/`. `wss://` needs 443 and, if a proxy is enforced, `HTTPS_PROXY` set in `.env` |
| Tool calls fail with a sandbox error | `sandbox: auto` picked a backend this kernel cannot run (no user namespaces, restrictive AppArmor) | Check the mentioned backend in the log, then pin `sandbox: landlock`; for bwrap, enable the shared-sandbox block in `docker-compose.yml` |
| Tool works on the edge but not through the central agent | Tool not in `exports`, name collision with an existing central tool (registration refused), or invalid schema | The relay logs the rejected tool and keeps the rest; fix `exports`/name/schema and restart |

## Security model

- **Declared tools only.** The relay can invoke the tools in this node's catalog and
  nothing else. The edge independently re-checks its own `exports` allowlist, so a
  compromised relay still cannot reach an unexported tool or the network behind it.
- **No inbound path.** The tunnel is outbound from this VM. There is no listener, no
  published port, and nothing on the central side that can dial into this network.
- **Credentials stay local.** Tool secrets live in this host's `.env` / secret store and
  are injected into local tool processes. They never transit the tunnel and are never
  stored in the central etcd.
- **No user-scoped secrets.** Remote tools run as an edge-level service account, not as
  the requesting Trellis user — a consequence of keeping credentials on this side. See the
  feature doc for the residual risk.
