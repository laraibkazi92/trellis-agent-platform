import sys
import os
import json
import unittest
from unittest.mock import MagicMock, patch, AsyncMock
from collections import namedtuple

# Ensure workspace / core is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if "pyetcd" not in sys.modules:
    sys.modules["pyetcd"] = MagicMock()

from core.auth import IdentityManager, retry_etcd
from core.tasks import _truncate_output, MAX_RUN_OUTPUT_CHARS, MAX_RUN_ERROR_CHARS
from scripts.prune_etcd_runs import prune_agent

EtcdMeta = namedtuple("EtcdMeta", ["key"])


class RunResilienceAndPruningTests(unittest.TestCase):
    def setUp(self):
        self.mock_client = MagicMock()
        with patch("pyetcd.client", return_value=self.mock_client):
            self.identity_mgr = IdentityManager(host="localhost", port=2379)
            self.identity_mgr.client = self.mock_client

    def test_get_agent_run_found(self):
        run_data = {
            "run_id": "run-123",
            "agent_name": "test-agent",
            "state": "completed",
            "timestamp": "2026-08-17T12:00:00+00:00",
            "metadata": {"output": "hello"}
        }
        self.mock_client.get.return_value = (json.dumps(run_data).encode("utf-8"), None)
        
        result = self.identity_mgr.get_agent_run("test-agent", "run-123")
        self.assertIsNotNone(result)
        self.assertEqual(result["run_id"], "run-123")
        self.assertEqual(result["state"], "completed")
        self.mock_client.get.assert_called_once_with("/runs/test-agent/run-123")

    def test_get_agent_run_not_found(self):
        self.mock_client.get.return_value = (None, None)
        result = self.identity_mgr.get_agent_run("test-agent", "nonexistent")
        self.assertIsNone(result)

    def test_get_agent_runs_with_limit(self):
        runs_data = [
            (json.dumps({"run_id": f"run-{i}", "updated_at": f"2026-08-17T12:0{i}:00+00:00"}).encode("utf-8"), EtcdMeta(key=f"/runs/test-agent/run-{i}".encode("utf-8")))
            for i in range(5)
        ]
        self.mock_client.get_prefix.return_value = runs_data

        # Limit to 2
        results = self.identity_mgr.get_agent_runs("test-agent", limit=2)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["run_id"], "run-4")
        self.assertEqual(results[1]["run_id"], "run-3")

    def test_prune_agent_runs_deletes_excess(self):
        # 5 records in etcd
        runs_data = [
            (json.dumps({"run_id": f"run-{i}", "updated_at": f"2026-08-17T12:0{i}:00+00:00"}).encode("utf-8"), EtcdMeta(key=f"/runs/test-agent/run-{i}".encode("utf-8")))
            for i in range(5)
        ]
        self.mock_client.get_prefix.return_value = runs_data

        deleted = self.identity_mgr.prune_agent_runs("test-agent", keep_last=3)
        self.assertEqual(deleted, 2)
        # Should delete oldest 2: run-0 and run-1
        self.mock_client.delete.assert_any_call("/runs/test-agent/run-0")
        self.mock_client.delete.assert_any_call("/runs/test-agent/run-1")

    def test_retry_etcd_fast_fails_on_resource_exhausted(self):
        class ResourceExhaustedError(Exception):
            pass

        call_count = 0

        @retry_etcd(max_retries=10, delay=0.01)
        def failing_func(self_ref):
            nonlocal call_count
            call_count += 1
            raise ResourceExhaustedError("StatusCode.RESOURCE_EXHAUSTED: message larger than max (11271132 vs 4194304)")

        with self.assertRaises(ResourceExhaustedError):
            failing_func(self.identity_mgr)

        # Fast-fail must not retry 10 times
        self.assertEqual(call_count, 1)

    def test_truncate_output_under_limit(self):
        text = "Small output"
        self.assertEqual(_truncate_output(text, max_chars=100), text)

    def test_truncate_output_over_limit(self):
        text = "A" * 1000
        truncated = _truncate_output(text, max_chars=200)
        self.assertLess(len(truncated), 300)
        self.assertIn("[... Truncated", truncated)
        self.assertTrue(truncated.startswith("AAAA"))
        self.assertTrue(truncated.endswith("AAAA"))

    def test_prune_script_utility(self):
        runs_data = [
            (json.dumps({"run_id": f"run-{i}", "updated_at": f"2026-08-17T12:0{i}:00+00:00"}).encode("utf-8"), EtcdMeta(key=f"/runs/ticket-triage/run-{i}".encode("utf-8")))
            for i in range(4)
        ]
        self.mock_client.get_prefix.return_value = runs_data

        # Dry run
        prune_agent(self.identity_mgr, "ticket-triage", keep=2, dry_run=True)
        self.mock_client.delete.assert_not_called()

        # Actual run
        prune_agent(self.identity_mgr, "ticket-triage", keep=2, dry_run=False)
        self.assertEqual(self.mock_client.delete.call_count, 2)


class WorkflowsRouterResilienceTests(unittest.IsolatedAsyncioTestCase):
    async def test_workflows_view_handles_single_workflow_failure_gracefully(self):
        from core.routers.workflows import workflows_view
        from fastapi import Request

        mock_request = MagicMock(spec=Request)
        mock_request.session = {}

        mock_identity = MagicMock()
        mock_identity.list_agents.return_value = ["healthy-wf", "bloated-wf"]
        mock_identity.get_disabled_workflows.return_value = []
        mock_identity.get_identity_config.return_value = {}
        mock_identity.list_mcps.return_value = []
        mock_identity.get_all_tool_configs.return_value = {}
        mock_identity.get_all_mcp_configs.return_value = {}

        def mock_get_agent_config(name):
            return {"name": name, "type": "background_script", "trigger": {}}

        mock_identity.get_agent_config.side_effect = mock_get_agent_config

        def mock_get_agent_runs(name, limit=None):
            if name == "bloated-wf":
                raise RuntimeError("StatusCode.RESOURCE_EXHAUSTED")
            return [{"run_id": "r1", "state": "completed", "timestamp": "2026-08-17T12:00:00"}]

        mock_identity.get_agent_runs.side_effect = mock_get_agent_runs

        with patch("core.routers.workflows.identity_mgr", mock_identity), \
             patch("core.routers.workflows.get_current_user", new_callable=AsyncMock) as mock_user, \
             patch("core.routers.workflows.templates.TemplateResponse") as mock_template:
            
            mock_user.return_value = {"email": "admin@example.com"}
            mock_template.return_value = MagicMock()

            await workflows_view(mock_request)

            # Ensure template rendered successfully
            mock_template.assert_called_once()
            _, kwargs = mock_template.call_args
            ctx = kwargs.get("context")
            self.assertIsNotNone(ctx)
            workflows_list = ctx.get("workflows_list")
            self.assertEqual(len(workflows_list), 2)
            
            healthy = next(w for w in workflows_list if w["name"] == "healthy-wf")
            self.assertEqual(healthy["run_stats"]["completed"], 1)
            
            bloated = next(w for w in workflows_list if w["name"] == "bloated-wf")
            self.assertEqual(bloated["run_stats"]["completed"], 0)
            self.assertIn("RESOURCE_EXHAUSTED", bloated.get("runs_error", ""))


if __name__ == "__main__":
    unittest.main()
