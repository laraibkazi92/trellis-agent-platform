# MCP Server Guide

Model Context Protocol (MCP) servers expand the capabilities of agents within `Trellis` by providing standard interfaces to external tools and data sources. 

This guide explains how to register external MCP servers so they are natively available to your agents.

## Directory Structure

All MCP servers are configured in the `mcps/` directory at the root of the project. Each server should have its own directory containing an `mcp.yaml` file.

```text
Trellis/
└── mcps/
    └── logs/
        └── mcp.yaml
```

## Configuration Schema (`mcp.yaml`)

The `mcp.yaml` defines how the Universal Agent Host (`core/host.py`) connects to the external MCP server. The framework supports two transports: `stdio` (for local executables) and `sse` (for HTTP-based servers).

### Fields

- `name`: The unique identifier for the MCP server.
- `transport`: The communication protocol. Either `stdio` or `sse`.
- `command`: The command to execute (for `stdio`) or the connection URL (for `sse`).
- `args` (Optional): A list of arguments to pass to the command (only applicable for `stdio`).
- `env` (Optional): A dictionary of environment variables (for `stdio`) or HTTP headers (for `sse`).
- `secrets` (Optional): A list of required user secrets. These will automatically appear in the UI's Secret Manager.

## Secure Secret Management

To keep credentials secure, you should never hardcode API keys or tokens in `mcp.yaml`. Instead, declare them in the `secrets` list. The framework supports **Secret Interpolation** within the `env` dictionary.

If an environment variable or header value contains `{SECRET_NAME}`, the framework will automatically substitute it with the user's secure value from the database.

### Example: Remote SSE Server (HTTP)

```yaml
name: my-remote-mcp
transport: sse
command: "https://api.example.com/v1/mcp"
env:
  # The framework interpolates the {MY_API_KEY} placeholder
  Authorization: "Bearer {MY_API_KEY}"
secrets:
  - "MY_API_KEY"
```

### Example: Local Stdio Server (Command)

```yaml
name: my-local-mcp
transport: stdio
command: "npx"
args:
  - "-y"
  - "@modelcontextprotocol/server-postgres"
  - "postgresql://localhost/mydb"
env:
  # For stdio, un-interpolated secrets are automatically added to the environment
  POSTGRES_PASSWORD: "{MY_DB_PASSWORD}"
secrets:
  - "MY_DB_PASSWORD"
```

## Applying Changes

Whenever you add or modify an `mcp.yaml` file, you must sync the configuration to the internal registry (etcd). 

Run the following command from the root directory:

```bash
python scripts/sync_to_db.py
```

The output will confirm that your MCP server has been registered:
```text
Syncing MCPs to etcd...
  Saved config for MCP: logs
```

After syncing, head over to the **Secrets** tab in the UI to populate any required keys. Agents will automatically discover and load the tools from your registered MCP servers.