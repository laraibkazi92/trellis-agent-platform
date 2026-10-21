# Static Landlock sandbox helper (core/sandbox.py). Built on the same base image
# as the runtime stage so the static binary matches its architecture.
FROM python:3.12-slim AS sandbox-build
COPY sandbox/trellis-sandbox.c /src/trellis-sandbox.c
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && mkdir -p /out \
    && gcc -O2 -Wall -Wextra -static -s -o /out/trellis-sandbox /src/trellis-sandbox.c \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Use Python 3.12 slim as the base image
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Install system dependencies for Node.js and Go.
# TARGETARCH is provided by BuildKit's predefined platform args (amd64/arm64/...); it
# must be re-declared inside the stage to be visible. Defaulting to amd64 keeps the
# legacy builder (no BuildKit target args) working. Using it for the Go tarball makes
# the image buildable for arm64 (Apple Silicon, arm servers) -- the previous hardcoded
# linux-amd64 tarball produced a broken Go toolchain on arm64 hosts. Note: Go publishes
# its 32-bit ARM tarball as linux-armv6l, so TARGETARCH=arm would 404 -- only amd64/arm64
# are published by CI; add an explicit case mapping if linux/arm/v7 is ever needed. A bad
# arch fails loudly (curl -f and tar both error), never silently.
ARG TARGETARCH
RUN apt-get update && apt-get install -y \
    curl \
    git \
    bubblewrap \
    ca-certificates \
    && update-ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && curl -fsSL "https://golang.org/dl/go1.22.2.linux-${TARGETARCH:-amd64}.tar.gz" | tar -C /usr/local -xzf - \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

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

# Landlock + uid-drop sandbox helper used when bwrap cannot run.
COPY --chmod=0755 --from=sandbox-build /out/trellis-sandbox /usr/local/bin/trellis-sandbox

# Non-root runtime user. docker-compose passes the host uid:gid (TRELLIS_UID/TRELLIS_GID)
# as PUID/PGID so files written into the bind-mounted workspace/ are owned by the operator
# instead of root. /app/data is created here and owned by that user: the `health-data`
# named volume inherits this ownership when Docker first populates it (first `up`).
# Every app service — the hub included — runs as ${TRELLIS_UID:-1000} via compose's
# `user:`; the sandbox helper drops identity only when it starts privileged (a root hub),
# so on the default non-root hub tools run at this same uid, which is the workspace owner.
ARG PUID=1000
ARG PGID=1000
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
