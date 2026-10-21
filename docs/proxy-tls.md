# TLS for the edge tunnel

`trellis-proxy` sends two things over the tunnel that must not travel in clear text:

- the site's enrollment token (`Authorization: Bearer edge_<site>_<secret>`), which is a
  **permanent** credential — the registry keeps only its SHA256, so a captured token can be
  replayed until an admin rotates it;
- every tool argument and result, which is the internal data the edge exists to protect.

So `server_url` must be `wss://` for any edge that crosses a network you do not fully
control. The proxy verifies the relay's certificate with `ssl.create_default_context()`;
there is no switch to disable verification, and `tls_ca_file` is the trust anchor it uses.

TLS is unrelated to **mTLS** (`EDGE_MTLS_CA`), which adds a client certificate on top and
is covered in [proxy.md](proxy.md#optional-mutual-tls). Do TLS first; mTLS is optional.

## 1. Decide two things

**What the edge dials.** The certificate has to contain a Subject Alternative Name (SAN)
matching the URL exactly. A CN-only certificate verifies nowhere.

| Edge dials | Certificate needs | Notes |
| --- | --- | --- |
| `wss://trellis.internal/…` | `DNS:trellis.internal` | Preferred: survives an IP change |
| `wss://10.0.0.41/…` | `IP:10.0.0.41` | No DNS needed; reissue if the IP changes |
| Both, depending on the site | `DNS:trellis.internal,IP:10.0.0.41` | One certificate, both work |

**Where TLS terminates.** Both options end with the relay on the internal network; pick one.

| | A. TLS on the main nginx | B. `edge-tls` in front |
| --- | --- | --- |
| Change to the rest of the stack | `:80` → `301 https://…` for **all** routes | none |
| Extra process | none | one `nginx:alpine` container |
| Edge URL | `wss://<host>/edge/v1/connect` | `wss://<host>:8443/edge/v1/connect` |
| When | fresh install, or every HTTP client can move to HTTPS | agents/MCP clients must stay on `http://` |
| Docs | step 3A | step 3B ([deploy/tls/](../deploy/tls/README.md)) |

## 2. Create the certificate

One certificate can cover both dial targets. From the repository root on the central host:

```bash
./deploy/tls/make-certs.sh --name trellis.internal --ip 10.0.0.41 --out ./gateway/ssl
```

It writes `ca.pem`, `ca.key`, `cert.pem`, `key.pem`, verifies the chain, prints the SAN, and
keeps the keys at mode 0600. `--force` replaces an existing set.

Equivalent by hand (internal CA; a self-signed cert is the same command with `-x509` and no
CA step):

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout ca.key -out ca.pem -subj "/CN=Trellis Internal CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout key.pem -out server.csr -subj "/CN=trellis.internal"

cat > server.ext <<'EOF'
subjectAltName=DNS:trellis.internal,IP:10.0.0.41
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out cert.pem -days 825 -sha256 -extfile server.ext
```

| File | Goes to | Why |
| --- | --- | --- |
| `cert.pem` | central TLS listener (`/etc/nginx/ssl/cert.pem`) | presented to the edge; include the intermediate chain if your CA has one |
| `key.pem` | same, mode 0600 | private key |
| `ca.pem` | **every edge** (`tls_ca_file`) | the only thing an edge trusts |
| `ca.key` | offline | signs renewals; losing it means re-trusting every edge |

nginx loads the certificate once, at start. After regenerating it, reload the listener —
`docker compose exec nginx-gateway nginx -s reload` (3A) or `docker compose restart edge-tls`
(3B). A plain `up -d` will not recreate a container whose mounts and environment did not
change, so it would keep serving the old certificate.

## 3A. Terminate on the main nginx

The certificate directory is mounted by the existing (commented) volume.

```bash
cd ~/trellis-agent-platform          # the central install
mkdir -p gateway/ssl
cp /path/to/cert.pem gateway/ssl/cert.pem
cp /path/to/key.pem  gateway/ssl/key.pem
chmod 600 gateway/ssl/key.pem
```

Uncomment the SSL volume under `nginx-gateway:` in `docker-compose.yml`:

```yaml
    volumes:
      - ${SSL_CERT_DIR:-./gateway/ssl}:/etc/nginx/ssl:ro
```

Set in `.env` (the variables already exist):

```
SSL_ENABLED=true
SSL_DNS_NAME=trellis.internal
SSL_CERT_DIR=./gateway/ssl
```

Recreate nginx — it needs the new volume and environment, so `restart` is not enough:

```bash
docker compose up -d nginx-gateway
docker compose logs nginx-gateway | grep -E "SSL is enabled|Falling back to HTTP"
```

You want `SSL is enabled and certificates found.` If you see `Falling back to HTTP`, stop
and fix the mount first — everything else will look like a certificate problem.

Two consequences, both deliberate:

- **Port 80 redirects every route to HTTPS.** Update agents, MCP clients, scripts, and
  bookmarks that use `http://…` (some POST/SSE clients do not follow a 301 correctly). If
  they cannot move, use 3B instead.
- The container healthcheck probes `http://127.0.0.1/`, which now redirects. If
  `docker compose ps` shows `nginx-gateway (unhealthy)` while the site works, that is the
  probe, not the ingress. Silence it with a `docker-compose.override.yml` healthcheck that
  requests `https://127.0.0.1/` with `--no-check-certificate`.

## 3B. Terminate in front, `/edge` only

Leaves `:80` and every existing client untouched. Nothing in this path is required for 3A.

```bash
cd ~/trellis-agent-platform
./deploy/tls/make-certs.sh --name trellis.internal --ip 10.0.0.41 --out ./gateway/ssl

docker compose -f docker-compose.yml -f deploy/tls/docker-compose.edge-tls.yml up -d edge-tls
docker compose ps edge-tls
docker compose logs edge-tls
```

It publishes `${EDGE_TLS_PORT:-8443}`, forwards `/edge` to `nginx-gateway:80`, answers
`/healthz`, and returns `404` for everything else. To make it permanent, copy
`deploy/tls/docker-compose.edge-tls.yml` to `docker-compose.override.yml` at the repository
root and use plain `docker compose up -d`.

Because every edge arrives from this container's IP, they share one nginx `limit_req`
bucket (30 r/s by default). Per-site call limits in the relay are unaffected. With more than
a handful of edges, prefer 3A.

## 4. Configure the edge

Copy only the CA to the edge VM:

```bash
# on the edge host, in deploy/proxy/
mkdir -p tls
scp central:/path/to/ca.pem tls/ca.pem
chmod 644 tls/ca.pem
```

Mount it (add to the `volumes:` list in `deploy/proxy/docker-compose.yml`):

```yaml
    volumes:
      - ./tls:/etc/trellis/tls:ro
      - ./workspace:/app/workspace
      - ./proxy.yaml:/etc/trellis/proxy.yaml:ro
```

Then pick the line that matches step 1. `tls_ca_file` alone is complete — do **not** set
`tls_cert_file`/`tls_key_file` unless you are also doing mTLS.

**Dial by DNS name:**

```yaml
server_url: wss://trellis.internal/edge/v1/connect   # :8443 with 3B
tls_ca_file: /etc/trellis/tls/ca.pem
```

**Dial by IP:**

```yaml
server_url: wss://10.0.0.41/edge/v1/connect          # :8443 with 3B
tls_ca_file: /etc/trellis/tls/ca.pem
```

Env equivalents, if you prefer not to edit the file: `TRELLIS_SERVER_URL`,
`TRELLIS_EDGE_TLS_CA`.

A name that only resolves on the edge **host** does not resolve inside the container: add
`extra_hosts: ["trellis.internal:10.0.0.41"]` to the edge service, or use the IP form.

Recreate the proxy (a new volume needs `up -d`, not `restart`):

```bash
cd deploy/proxy
docker compose up -d trellis-proxy
```

## 5. Verify

**The listener.** From the central host — `--cacert`, never `-k`:

```bash
# 3A: any route answers (200, or a 3xx to the login page)
curl -sS --cacert gateway/ssl/ca.pem https://trellis.internal/ -o /dev/null -w '%{http_code}\n'

# 3B: the terminator answers /healthz and 404s everything else
curl -fsS --cacert gateway/ssl/ca.pem https://10.0.0.41:8443/healthz
```

**The exact trust path the proxy uses**, from inside the edge container (same
`create_default_context(cafile=…)`, so this is not an approximation). Use the URL that
matches your termination path — 3B only serves `/edge` and `/healthz`, so `/` answers 404
even when TLS is perfect:

```bash
# 3A
docker compose exec trellis-proxy python -c "
import ssl, urllib.request
ctx = ssl.create_default_context(cafile='/etc/trellis/tls/ca.pem')
print(urllib.request.urlopen('https://trellis.internal/', context=ctx).status)
"

# 3B
docker compose exec trellis-proxy python -c "
import ssl, urllib.request
ctx = ssl.create_default_context(cafile='/etc/trellis/tls/ca.pem')
print(urllib.request.urlopen('https://10.0.0.41:8443/healthz', context=ctx).status)
"
```

**The tunnel:**

```bash
docker compose logs -f trellis-proxy        # "Connected to wss://… as site …", no reconnect loop
```

Central side:

```bash
docker compose exec edge-relay curl -s http://127.0.0.1:8100/healthz   # "connected": true
docker compose logs --tail 20 edge-relay | grep "edge connected"
```

Then Admin → Edges shows **Connected**, and one tool call proves the whole path.

## 6. Prove verification is actually on

Do this once per install. Two runs that must both fail:

```bash
# 1. Trust the wrong anchor: remove tls_ca_file from proxy.yaml
#    Expected: CERTIFICATE_VERIFY_FAILED … unable to get local issuer certificate

# 2. Dial a name/IP that is not in the SAN
#    Expected: … certificate is not valid for '<name>'
```

If either succeeds, the connection is not verified — stop and fix it.

## Renewal and rollback

| Task | Path A | Path B |
| --- | --- | --- |
| Renew the server cert | replace `gateway/ssl/cert.pem` + `key.pem`, `docker compose exec nginx-gateway nginx -s reload` | same, then `docker compose restart edge-tls` |
| Edges affected | none — they trust `ca.pem` | none |
| Replace the CA | re-trust the new `ca.pem` on **every** edge | same |
| Disable TLS | `SSL_ENABLED=false` + `docker compose up -d nginx-gateway` | `docker compose stop edge-tls` |

After disabling TLS, edges fall back to `ws://` in clear text: **rotate each site's token**
in Admin → Edges, and fix the transport before reconnecting.

## Troubleshooting

| Symptom (exact text) | Cause | Fix |
| --- | --- | --- |
| `WARNING: SSL_ENABLED is true but certificates are missing … Falling back to HTTP.` | volume not mounted, or wrong `SSL_CERT_DIR` | uncomment the volume; check `docker compose config` |
| `proxy config: tls_ca_file not found: …` | CA not mounted into the edge container | add the `./tls:/etc/trellis/tls:ro` mount, `up -d` |
| `proxy config: TLS files require a wss:// server_url (got 'ws://…')` | mixed config | change `server_url` to `wss://` |
| `CERTIFICATE_VERIFY_FAILED … unable to get local issuer certificate` | trusting the leaf instead of the CA, or the server is not sending its intermediate | trust `ca.pem`; serve leaf + intermediate in `cert.pem` |
| `… certificate is not valid for 'trellis.internal'` / `IP address mismatch` | SAN missing or does not match the URL | reissue with the exact `DNS:`/`IP:` entry |
| `[SSL: WRONG_VERSION_NUMBER]` | dialing TLS at a plain-HTTP port (nginx fell back, or wrong port) | check the listener log line from step 3 |
| `HTTP 404` on `/edge` | nginx image predates the feature | `docker compose up -d --build nginx-gateway` |
| Certificate warning in the admin's browser | internal CA is not in the OS/browser trust store | install `ca.pem` there, or use your existing PKI |

## Operational notes

- The proxy's retry loop is unchanged: a certificate error is not retried specially, so a
  wrong anchor shows as a repeating `connection failed` line. Fix the file; there is no
  flag to skip verification.
- Browsers reject private-CA certificates with more than ~397 days of validity. If humans
  will also open the dashboard at this name, generate with `--days 397`; the tunnel itself
  does not care.
- Keep `ca.key` offline. Renewing the **leaf** with the same CA is invisible to edges;
  replacing the CA is a fleet-wide operation.
