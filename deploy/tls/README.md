# Internal TLS for the edge tunnel

Runbook: [docs/proxy-tls.md](../../docs/proxy-tls.md). This directory holds the
artifacts it refers to.

```
make-certs.sh                    # CA + server certificate, DNS and/or IP SAN
edge-tls.conf                    # /edge-only TLS listener (nginx)
docker-compose.edge-tls.yml      # the edge-tls container for that listener
```

## Two ways to terminate TLS

1. **TLS on the main nginx** (`SSL_ENABLED=true`) — simplest, but `:80` redirects
   every route to HTTPS, so update any client that speaks plain HTTP first.
   No files from this directory are needed beyond the certificate itself.
2. **`edge-tls` in front** (this directory) — leaves `:80` untouched and only
   encrypts `/edge`. Edges dial `wss://<host>:8443/edge/v1/connect`.

## Quick start (option 2)

```bash
cd <repo root>

# 1. One cert for both names/IPs an edge might dial:
./deploy/tls/make-certs.sh --name trellis.internal --ip 10.0.0.41 --out ./gateway/ssl

# 2. Start the terminator (TLS_CERT_DIR defaults to ./gateway/ssl):
docker compose -f docker-compose.yml -f deploy/tls/docker-compose.edge-tls.yml up -d edge-tls

# 3. Check it answers over TLS:
curl -fsS --cacert gateway/ssl/ca.pem https://10.0.0.41:8443/healthz
```

Then copy `gateway/ssl/ca.pem` to each edge and set, in its `proxy.yaml`:

```yaml
server_url: wss://10.0.0.41:8443/edge/v1/connect
tls_ca_file: /etc/trellis/tls/ca.pem
```

## Notes

- `EDGE_TLS_PORT` moves the published port (default `8443`); `TLS_CERT_DIR`
  points at a certificate directory other than `./gateway/ssl`.
- Every edge reaches the inner nginx from this container's IP, so they share one
  nginx `limit_req` bucket (30 r/s by default). Per-site call limits in the relay
  are unaffected. With many edges, prefer option 1 so nginx sees real client IPs.
- Certificates from this CA are for the tunnel. If humans will also open the
  dashboard at that name, either install `ca.pem` in their OS/browser trust store
  or use a certificate from your existing PKI; browsers reject private-CA certs
  with more than ~397 days of validity.
