# Trellis Helm Chart (Starter, Community)

A **starter community chart** for running Trellis on Kubernetes. It mirrors the
`docker-compose.yml` deployment shape (the source of truth for commands, ports,
and env wiring) but is intentionally minimal — expect to adapt it to your
cluster's conventions before production use.

## What it deploys

| Component | Chart resource | Port | Notes |
|---|---|---|---|
| Universal Agent Host | `<release>-host` | 8000 | `granian ... core.host:app` (from compose) |
| Polyglot Tool Hub | `<release>-hub` | 8001 | `python core/hub.py` |
| Dashboard UI | `<release>-ui` | 8080 | `uvicorn core.ui:app` |
| MCP Gateway | `<release>-mcp-gateway` | 8002 | `python core/gateway.py` — cluster-internal target of the nginx `/mcp` route |
| nginx edge | `<release>-gateway` | 80 | counterpart of compose's `nginx-gateway` |
| db-sync | init container on host | — | `python scripts/sync_to_db.py`, like compose's one-shot `db-sync` service (disable with `syncInit.enabled=false`) |

All app components share one image (`image.repository`, built from the repo
root Dockerfile). The nginx edge uses the plain `nginx:alpine` image — the
`gateway/` Dockerfile only ships `entrypoint.sh`, so the chart mounts that
script via ConfigMap instead of requiring a custom image build.

## Prerequisites

1. **Build and push the images** — the chart does not reference a public registry:

   ```bash
   REGISTRY=ghcr.io/your-org ./scripts/publish_images.sh
   ```

   Then set `image.repository`/`image.tag` and `gatewayImage.*` accordingly.

2. **Provide workspace content.** The app image does *not* bake `workspace/`
   in (docker-compose bind-mounts it). Point `workspace.persistentVolumeClaim`
   at an existing PVC with your `agents/`, `tools/`, `mcps/`, and `workflows/`
   content, or build a derived image containing it.

3. **Provide external dependencies** (see below): etcd (required), Redis
   (required for background workflows/taskiq), Hindsight (optional, agent
   memory).

## External dependencies (etcd / Redis / Hindsight)

This chart deliberately ships **no mandatory subchart dependencies** — wire
them in whichever way fits your cluster:

**Option A — existing services.** Point the values at services you already run:

```yaml
externalDependencies:
  etcd:
    host: my-etcd.my-namespace.svc.cluster.local
    port: 2379
  redis:
    url: redis://my-redis:6379/0   # or host/port
  hindsight:
    url: http://my-hindsight:8888
```

**Option B — subcharts.** Declare them in `Chart.yaml`'s `dependencies:`
list (the chart ships none) and fetch the tarballs into `charts/`:

```yaml
# Chart.yaml
dependencies:
  - name: etcd
    repository: oci://registry-1.docker.io/bitnamicharts
    version: 11.x.x
```

```bash
helm dependency update charts/trellis
```

…or manage them as separate releases. Either way, point
`externalDependencies.*` at the resulting service names. Because the chart renders
`ETCD_HOST`/`ETCD_PORT`/`REDIS_URL`/`HINDSIGHT_URL` into a ConfigMap, any
source works as long as the addresses resolve from the Trellis pods.

## Configuration highlights

See `values.yaml` for the full list with comments.

- `secrets.*` — rendered into a Secret (`SESSION_SECRET`, `ENCRYPTION_KEY`,
  `GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`). **Set
  `sessionSecret` explicitly — it ships empty, and outside DEV_MODE the app
  refuses to start without `SESSION_SECRET` (or `ENCRYPTION_KEY`) set.** Empty
  values are omitted; if you blank all of them the Secret is not rendered and
  pods referencing it via `envFrom` will not start — keep at least one set or
  manage the Secret yourself.
- `config.*` — non-secret env (DEV_MODE, TZ, CORS, ADMIN_USERS, public URLs).
- `ingress.enabled` — routes `<host>/` to the nginx edge gateway.
- `resources` — applied to every deployment (single block for simplicity).
- `gateway.*` — SSL toggle/domain for the nginx entrypoint, plus
  `dnsResolver` (defaults to kube-dns; the compose script hardcodes Docker's
  `127.0.0.11`).

## The nginx entrypoint ConfigMap

`files/gateway-entrypoint.sh` is a byte-identical copy of the repo's
`gateway/entrypoint.sh` — update it when that file changes. At render time the
template adapts two Docker-specific details to Kubernetes: the DNS resolver
address and the upstream service hostnames (`ui`, `host`, `gateway` become the
chart's `<release>-*` service names). Everything else — routing, SSL handling,
SSE/streaming tuning — is the original script.

## Known starter-chart limitations

- **No taskiq worker/scheduler** deployments yet, so background
  workflows/cron agents don't fire under this chart (they need Redis).
- **Hub sandbox**: the hub deployment replicates the compose capabilities
  (`SYS_ADMIN`, `SETFCAP`, `allowPrivilegeEscalation: false`), but compose's
  `systempaths=unconfined` has no direct Kubernetes equivalent. If tool
  execution fails with bwrap/userns errors on your nodes, tune the hub's
  securityContext (see the comment in `templates/hub.yaml`).
- **SSL certificates** for the edge gateway are not wired to a volume; to
  enable HTTPS, mount cert/key at `/etc/nginx/ssl/` in
  `templates/gateway.yaml` (see the commented volume block in
  `docker-compose.yml`).
