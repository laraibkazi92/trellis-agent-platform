# Use Python 3.12 slim as the base image
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Install system dependencies for Node.js and Go
RUN apt-get update && apt-get install -y \
    curl \
    git \
    bubblewrap \
    ca-certificates \
    && update-ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && curl -fsSL https://golang.org/dl/go1.22.2.linux-amd64.tar.gz | tar -C /usr/local -xzf - \
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

# Natively install the updated certificates into the Debian OS
RUN cp $(python -c "import certifi; print(certifi.where())") /usr/local/share/ca-certificates/mozilla-certifi.crt \
    && update-ca-certificates

# Copy the rest of the application code
COPY core/ core/
COPY templates/ templates/
COPY scripts/ scripts/
COPY docs/ docs/

# Set PYTHONPATH to the root so core imports work
ENV PYTHONPATH=/app

# Expose ports for Host and potentially Gateway/Hub (if using SSE)
EXPOSE 8000 8001 8002

# Default command
CMD ["python", "core/host.py"]
