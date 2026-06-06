---
name: investigate-agent-run
description: Use this skill when asked to investigate, track, debug, or verify the run status of a background agent or task within the `trellis-agent-platform`.
---
## Architecture Context
The `trellis-agent-platform` uses a distributed architecture to run agents:
- **`etcd-server`**: Central state registry holding agent states, run histories, and tool configurations.
- **`agent-host`**: Orchestrates agent logic using PydanticAI.
- **`taskiq-worker`**: Executes background agents and jobs.
- **`tool-hub`**: A FastMCP server that manages and executes tools.

When an agent fails or produces unexpected results, the issue could stem from code logic, misconfigured tool entrypoints, missing credentials, or container state. Use the following step-by-step workflow to investigate.

## Step-by-Step Troubleshooting Workflow

### 1. Verify Infrastructure State
Ensure all core services are up and healthy.
```bash
docker ps
```
Look for `agent-host`, `taskiq-worker`, `tool-hub`, and `etcd-server`.

### 2. Fetch Agent Execution State (etcd)
Agent run histories and statuses are stored in etcd. You can query them using the `IdentityManager` within the `agent-host` container.

Run this command to get the latest runs for a specific agent (replace `<agent_name>`):
```bash
docker exec agent-host python -c "from core.agent_factory import get_identity_manager; import json; print(json.dumps(get_identity_manager().get_agent_runs('<agent_name>'), indent=2))"
```
*Look at the latest run's `state`, `error`, and `output` fields in the `metadata` to understand what happened.*

### 3. Inspect Worker Logs
If the agent crashed or behaved unexpectedly, the traceback or contextual logs will be in the `taskiq-worker` logs.
```bash
docker compose logs --tail=100 taskiq-worker
```
*Look for missing environment variables, missing API keys, or exceptions thrown by tools.*

### 4. Trace Tool Configurations
If the agent hallucinated data or a tool call failed silently, the tool definition might be misconfigured.
- Navigate to `workspace/tools/<tool_suite>/`.
- Read `tool.yaml`.
- Ensure the `entrypoint` field points to the *actual* implementation script (e.g., `tl_search_support.py`) and NOT a test script or dummy file.
- Verify the script expects JSON on `stdin` and outputs JSON to `stdout`.

### 5. Apply Fixes & Sync State
If you modified a `tool.yaml`, agent configuration, or added missing secrets, you must push these changes to etcd and reload the services:

1. Sync configurations to etcd:
   ```bash
   docker exec agent-host python scripts/sync_to_db.py
   ```
2. Restart the Tool Hub (if tool configurations changed):
   ```bash
   docker restart tool-hub
   ```

### 6. Trigger a Verification Run
To confirm the fix works, you can manually trigger a background run of the agent.

1. Create a trigger script (`trigger.py`) in the host:
   ```python
   import asyncio
   from core.tasks import run_background_agent
   from core.tasks import broker

   async def main():
       await broker.startup()
       task = await run_background_agent.kiq("<agent_name>", "Manual execution triggered for verification", "admin")
       print(f"Queued task with ID: {task.task_id}")
       await broker.shutdown()

   if __name__ == "__main__":
       asyncio.run(main())
   ```
2. Copy it to the container and execute it:
   ```bash
   cat << 'EOF' > trigger.py
   # (paste the code above)
   EOF
   docker cp trigger.py agent-host:/app/trigger.py
   docker exec agent-host python /app/trigger.py
   ```
3. Follow the logs to verify successful execution:
   ```bash
   docker compose logs -f taskiq-worker
   ```
4. Verify the final generated artifacts (like HTML reports) in their respective `workspace/` output directories.
