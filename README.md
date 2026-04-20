# Multi-Agent Framework v2.0

A centralized multi-agent management system with dynamic tool orchestration using PydanticAI and Model Context Protocol (MCP).

## Architecture Overview

The system consists of several key components:

- **Control Plane**: A FastAPI backend that manages agents, tools, and secrets. It also acts as an OpenAI-compatible gateway.
- **Agent Nodes**: Individual agent containers built using PydanticAI, exposing OpenAI API, MCP Server, and Agent-to-Agent endpoints.
- **Tool Hub**: A centralized MCP server that dynamically loads tool functions and injects credentials from etcd.
- **Web UI**: An Astro-based frontend for managing agents and tools.
- **Infrastructure**: Docker Compose, PostgreSQL, etcd, and Traefik for dynamic routing.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.13+
- [uv](https://github.com/astral-sh/uv) (for local testing and dependency management)

### Local Development

1. **Clone the repository**:
   ```bash
   git clone <repo-url>
   cd trellis-agent-platform
   ```

2. **Start the infrastructure**:
   ```bash
   docker-compose up -d
   ```

3. **Initialize the database**:
   ```bash
   docker-compose exec control-plane alembic upgrade head
   ```

4. **Access the Web UI**:
   Open [http://localhost](http://localhost) in your browser.

5. **Access the API Gateway**:
   The gateway is available at [http://localhost/v1/chat/completions](http://localhost/v1/chat/completions). Use the agent name in the `model` field.

## Deployment

### Local Testing

You can run integration tests using `pytest` and `uv`:

```bash
uv run pytest control-plane/tests
```

### EC2 Deployment

See the [deploy/](deploy/README.md) directory for detailed instructions on deploying the framework to an AWS EC2 instance.

## Directory Structure

- `agents/`: Agent implementations and templates.
- `all-tools-mcp-server/`: Dynamic MCP server for tools.
- `control-plane/`: Management API and gateway.
- `tools/`: Tool function implementations.
- `traefik/`: Reverse proxy configuration.
- `web-ui/`: Frontend dashboard.
- `__plan_docs/`: Specification and design documents.

## License

MIT
