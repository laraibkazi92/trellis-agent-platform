# Edge Nodes (trellis-proxy)

An **edge node** is a Trellis install on a network you cannot reach from the central
host: an internal VM, a private subnet, an on-prem appliance. It has outbound access to
the internet but no public IP and accepts no inbound connections.

`trellis-proxy` closes that gap without opening a path into the customer network. It runs
the **same image** as the central stack with a different entrypoint, dials out over WSS,
and executes some of its local tools on request. Those tools appear centrally as normal
native tools, so agents, tool search, health tracking, and usage accounting work unchanged.

Edges publish **tools only** in this release. Agents and workflows still run centrally.

> **Status:** the tunnel and native registration are implemented. Edges enroll from
> **Admin → Edges**, their tools appear in `/registry/tools` as `<site>__<tool>`, and the
> hub executes them like any local tool. Edge-hosted agents are not part of this release.

## Topology

```text
INTERNAL VM -- outbound 443 only, no public IP
┌──────────────────────────────────────────────────┐
│ trellis-proxy   (same image, new entrypoint)     │
│  workspace/tools/**   (tool.yaml)                │
│  proxy.yaml           (site, server_url, exports)│
│  local secrets        (env / secret store)       │
│  sandbox (bwrap | Landlock)                      │
└──────────────────┬───────────────────────────────┘
                   │ wss://central/edge/v1/connect
                   ▼
CENTRAL
nginx :443 ── location /edge ──► edge-relay:8100      (new compose service)
                                    │ site → live connection (in memory)
                                    │ POST /v1/sites/{site}/call  (internal only)
                                    └── writes /registry/edges/<site>/…
                                        writes /registry/tools/<site>__<tool>/…
                                        records tool health
                                        ▲
                                     hub.run_tool
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
   put the token in `.env` as `TRELLIS_EDGE_TOKEN`, then `docker compose up -d`. Full
   runbook: [deploy/proxy/README.md](../deploy/proxy/README.md).
3. **Connect.** The proxy dials `wss://<central-host>/edge/v1/connect` with subprotocol
   `trellis.edge.v1` and its token. The relay derives the site from the token hash —
   never from a client-supplied name — and publishes the tools listed in `exports` as
   `<site>__<tool>`.
4. **Use.** Agents reach those tools through ordinary tool search and calls. Nothing in
   the agent config references the edge.
5. **Rotate or revoke** in **Admin → Edges** whenever the token changes hands. Revocation
   closes a live socket with `4403` and rejects the next handshake with `401`.

A second connection for the same site **supersedes** the first (`4409` close), so a
redeploy never gets stuck behind a zombie socket. If two hosts run the same site by
mistake, only one of them serves calls.

## Authoring tools

An edge tool is authored exactly like a local one: `workspace/tools/<tool>/tool.yaml` plus
its script, same fields, same sandbox. There is no remote-specific marker to add and no
`mcp__` naming — the relay does the translation from catalog to registry.

Two edge-only rules:

- **`exports` is the allowlist.** `proxy.yaml` lists which tools this node publishes. An
  empty list publishes nothing; a tool that is not listed is neither advertised nor
  executed, even if the central side asks for it.
- **Credentials stay on the edge.** Tools read their API keys from the edge's own `.env`
  or secret store. They are never sent to the central install and never stored in etcd.
  The price is that remote tools run as an edge-level service account: **per-user secrets
  are not available** to them, and `retry_on_transient` defaults to `false` because a
  dropped tunnel must not silently replay a call that already had a side effect.

Tool manifests published by an edge are read-only in the central tool editor; edit them
on the edge and restart, or send `SIGHUP` to re-publish the catalog (the proxy reconnects;
in-flight calls fail rather than being replayed).

## Failure semantics

| Condition | Behavior |
| --- | --- |
| Edge offline | Relay answers `503 edge_offline` → the hub returns `Tool '<site>__<tool>' is offline (edge '<site>' is not connected).`; a health event is recorded; no retry storm |
| Edge drops mid-call | In-flight calls fail with `edge_disconnected`; they are never replayed |
| Token revoked | Handshake `401`; a live socket is closed with `4403` |
| Relay restart | Edges reconnect with jittered backoff (1 s → 60 s); catalogs are republished |
| Tool timeout | The edge kills the process tree (existing sandbox logic) and returns an error result |
| Hub → relay timeout | `504` → tool error |
| Invalid catalog entry | That tool is rejected and logged; the site's other tools still register |
| Name collision with a local tool | Registration is refused for the colliding tool only, and logged |
| Duplicate connection for a site | The older connection is closed with `4409` |

## Central requirements

- The `edge-relay` service (added by `docker-compose.yml`; one worker, internal port
  8100) and the `/edge` location in `gateway/entrypoint.sh`.
The relay reads and writes plain registry records (no secret decryption), so it does not
need `ENCRYPTION_KEY` or `SESSION_SECRET`.
- Outbound-free posture unchanged: the relay never dials an edge, so no central firewall
  rule is needed for edges beyond accepting 443 from them.

## Security notes

- The only public surface is `/edge/v1/connect`. `POST /v1/sites/{site}/call` is internal
  to the compose network; it is not routed from nginx.
- The relay sees tool arguments and results in plaintext. If you operate Trellis as
  shared SaaS, you can read a customer's internal data in transit; end-to-end payload
  encryption is not part of this release.
- Site compromise is bounded to that site's catalogs. Central/relay compromise is bounded
  to the union of exported tools — not the customer's network.
- Edge payloads are capped (10 MB frame, 1 MB arguments, 200 tools per site, 16 in flight)
  and the relay logs site, tool, call id, duration, and outcome — never arguments or
  results. The user id travels in the call frame for attribution and is not logged with
  the payload.

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

### Rate limiting

Two independent limits:

| Layer | Setting | Default | Scope |
|---|---|---|---|
| nginx `/edge` | `EDGE_RATE_LIMIT_RPS` / `EDGE_RATE_LIMIT_BURST` | 30 r/s, burst 20 | per client IP, connection-level flood |
| relay | `EDGE_RATE_LIMIT_PER_MIN` | 120 calls/min | per site (token bucket) |
| relay | site record `rate_limit_per_min` | inherits the default | per site override, editable in Admin → Edges |

An over-limit call never reaches the edge: the relay answers `429 rate_limited` and the
hub surfaces "Edge '<site>' is rate-limiting tool calls; '<tool>' was not sent." The
limit is a token bucket with capacity equal to the rate, so a short burst is allowed and
sustained traffic is capped.

### Optional mutual TLS

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

### Revocation latency

Revoking a token closes the **next handshake** immediately and the **live** tunnel at the
next heartbeat, i.e. within 20 seconds. Deleting a site behaves the same way and also
removes its published tools.

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
