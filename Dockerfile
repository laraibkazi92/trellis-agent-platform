# Use Python 3.12 slim as the base image
FROM python:3.12-slim

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

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install --upgrade certifi

# Copy the rest of the application code
COPY core/ core/
COPY agents/ agents/
COPY tools/ tools/
COPY templates/ templates/
COPY scripts/ scripts/
COPY DOCS_*.md ./

# Set PYTHONPATH to the root so core imports work
ENV PYTHONPATH=/app
ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

# Expose ports for Host and potentially Gateway/Hub (if using SSE)
EXPOSE 8000 8001 8002

# Default command
CMD ["python", "core/host.py"]
