# Base images are pinned by digest (the manifest-list digest, so linux/amd64 and
# linux/arm64 still both resolve) because this Dockerfile produces the published
# release image: a mutable tag lets the toolchain change under a tag that is
# supposed to be reproducible. Dependabot bumps the digest weekly
# (.github/dependabot.yml); re-check the arm64 leg after a manual bump.
ARG PYTHON_BASE=python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2

# Use Python 3.12 slim as the base image
FROM ${PYTHON_BASE}
# Pinned like the base: `latest` would change the dependency resolver under a
# release tag. Verified to resolve both published architectures.
COPY --from=ghcr.io/astral-sh/uv:0.13.4@sha256:9f130421e930bfbdc563c00740466603f8723158e90297d07957c2294640262b /uv /uvx /bin/

# Install system dependencies for Node.js and Go.
# TARGETARCH is provided by BuildKit's predefined platform args (amd64/arm64/...); it
# must be re-declared inside the stage to be visible. Defaulting to amd64 keeps the
# legacy builder (no BuildKit target args) working. Using it for the Go tarball makes
# the image buildable for arm64 (Apple Silicon, arm servers) -- the previous hardcoded
# linux-amd64 tarball produced a broken Go toolchain on arm64 hosts. Note: Go publishes
# its 32-bit ARM tarball as linux-armv6l, so TARGETARCH=arm would 404 -- only amd64/arm64
# are published by CI; add an explicit case mapping if linux/arm/v7 is ever needed. A bad
# arch fails loudly (explicit case below, then curl -f), never silently.
ARG TARGETARCH
RUN apt-get update && apt-get install -y \
    curl \
    git \
    ca-certificates \
    && update-ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Go toolchain, checksum-verified. The URL is fixed by version, but a download over
# TLS is still the one image input nobody signs for us, so the published sha256 is
# checked before unpacking. Only the architectures CI publishes are mapped: an
# unmapped TARGETARCH fails here instead of producing a broken toolchain.
ARG GO_VERSION=1.22.2
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
        amd64) go_sha256=5901c52b7a78002aeff14a21f93e0f064f74ce1360fce51c6ee68cd471216a17 ;; \
        arm64) go_sha256=36e720b2d564980c162a48c7e97da2e407dfcc4239e1e58d98082dfa2486a0c1 ;; \
        *) echo "no pinned checksum for TARGETARCH=${TARGETARCH:-amd64}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/go.tar.gz "https://golang.org/dl/go${GO_VERSION}.linux-${TARGETARCH:-amd64}.tar.gz"; \
    echo "${go_sha256}  /tmp/go.tar.gz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz

# Add Go to PATH
ENV PATH=$PATH:/usr/local/go/bin

# Install tsx globally for TypeScript support in tools
RUN npm install -g tsx

# Set the working directory
WORKDIR /app

# Point Python HTTP clients to the OS-level trust store
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN uv pip install --system --no-cache -r requirements.txt && uv pip install --system --upgrade certifi

# Precompile bytecode for installed packages so it's baked into the image layer
# instead of being recompiled on every container recreate (each restart otherwise
# gets a fresh writable layer with no .pyc cache, costing ~10s+ per worker on import).
RUN python -m compileall -q /usr/local/lib/python3.12/site-packages

# Natively install the updated certificates into the Debian OS
RUN cp $(python -c "import certifi; print(certifi.where())") /usr/local/share/ca-certificates/mozilla-certifi.crt \
    && update-ca-certificates

# Copy the rest of the application code
COPY core/ core/
# services/ holds the edge relay (`uvicorn services.edge_relay.app:app`, compose service
# `edge-relay`). It is not part of the hub's tool path, but it ships in the same image.
COPY services/ services/
COPY templates/ templates/
COPY scripts/ scripts/
COPY docs/ docs/

# Non-root runtime user. docker-compose passes the host uid:gid (TRELLIS_UID/TRELLIS_GID)
# as PUID/PGID so files written into the bind-mounted workspace/ are owned by the operator
# instead of root. /app/data is created here and owned by that user: the `health-data`
# named volume inherits this ownership when Docker first populates it (first `up`).
# Every app service — the hub included — runs as ${TRELLIS_UID:-1000} via compose's
# `user:`, which is also the identity tool containers run as (they are started by the
# runner, not by the hub).
ARG PUID=1000
ARG PGID=1000
# Reported in the edge hello frame / Admin -> Edges so an operator can spot a proxy
# running an older build than the central install. Supplied by the release workflow.
ARG TRELLIS_VERSION=0.0.0
ENV TRELLIS_VERSION=${TRELLIS_VERSION}
RUN groupadd -g ${PGID} trellis \
    && useradd -u ${PUID} -g ${PGID} -m -s /usr/sbin/nologin trellis \
    && mkdir -p /app/data \
    && chown -R ${PUID}:${PGID} /app

# Set PYTHONPATH to the root so core imports work
ENV PYTHONPATH=/app

# Expose ports for Host and potentially Gateway/Hub (if using SSE)
EXPOSE 8000 8001 8002

# Default command
CMD ["python", "core/host.py"]
