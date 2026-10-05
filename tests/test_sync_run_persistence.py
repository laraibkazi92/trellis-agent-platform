# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for run-state persistence of synchronous /v1/chat/completions requests.

core.host.chat_completions records every sync run through the same
IdentityManager run-state machine core/tasks.py uses for background runs
(/runs/{agent}/{run_id}: processing -> completed/failed), tagging
metadata.source == "sync" so core/routers/workflows.py keeps the background
workflows UI showing only background executions. Handlers are called directly
with fakes (no etcd, no real agents), matching the suite's conventions.
"""
import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from core import discovery, host
from core.routers import workflows

EXTERNAL_USER_AGENT_CONFIG = {
    "name": "general-agent", "type": "user_agent", "external": True, "allowed_tools": [],
}


class FakeAgent:
    def __init__(self, output="general reply", usage=None, error=None):
        self._result = SimpleNamespace(output=output, usage=usage)
        self._error = error

    async def run(self, prompt, message_history=None, deps=None):
        if self._error:
            raise self._error
        return self._result


class FakeIdentityManagerHost:
    def __init__(self, agent_configs=None, record_error=None):
        self._agent_configs = agent_configs or {}
        self._record_error = record_error
        self.run_records = []
        self.usage_calls = []

    def get_disabled_standard_agents(self):
        return []

    def get_agent_config(self, name):
        return self._agent_configs.get(name)

    def record_agent_run_state(self, agent_name, run_id, state, metadata):
        if self._record_error:
            raise self._record_error
        self.run_records.append((agent_name, run_id, state, metadata))
        return True

    def record_usage(self, user_id, input_tokens, output_tokens):
        self.usage_calls.append((user_id, input_tokens, output_tokens))

    def record_agent_usage(self, user_id, agent_name, input_tokens, output_tokens):
        pass


class FakeHealthMonitor:
    def get_status(self, entity_type, name):
        return {"status": "Online"}

    def record_event(self, *args, **kwargs):
        pass


class FakeMemoryManager:
    def active_for(self, cfg):
        return False


def _run_chat(monkeypatch, fake_mgr, fake_agent, user_id="user-1", content="What's the status?"):
    monkeypatch.setattr(host, "identity_mgr", fake_mgr)

    async def fake_get_agent(name):
        return fake_agent

    monkeypatch.setattr(host, "get_agent", fake_get_agent)
    monkeypatch.setattr(host, "health_monitor", FakeHealthMonitor())
    monkeypatch.setattr(host, "get_memory_manager", lambda: FakeMemoryManager())

    token = host.user_id_var.set(user_id)
    try:
        request = host.ChatRequest(
            model="general-agent",
            messages=[host.ChatMessage(role="user", content=content)],
        )
        return asyncio.run(host.chat_completions(request))
    finally:
        host.user_id_var.reset(token)


# --- chat_completions: processing -> completed sequence ---------------------------

def test_sync_chat_records_processing_then_completed(monkeypatch):
    fake_mgr = FakeIdentityManagerHost(agent_configs={"general-agent": EXTERNAL_USER_AGENT_CONFIG})

    response = _run_chat(monkeypatch, fake_mgr, FakeAgent(usage=SimpleNamespace(input_tokens=5, output_tokens=7)))

    assert response == {"choices": [{"message": {"role": "assistant", "content": "general reply"}}]}
    assert [r[2] for r in fake_mgr.run_records] == ["processing", "completed"]
    assert {r[0] for r in fake_mgr.run_records} == {"general-agent"}
    assert len({r[1] for r in fake_mgr.run_records}) == 1

    processing_meta = fake_mgr.run_records[0][3]
    assert processing_meta == {"prompt": "What's the status?", "user_id": "user-1", "source": "sync"}

    completed_meta = fake_mgr.run_records[1][3]
    assert completed_meta["source"] == "sync"
    assert completed_meta["user_id"] == "user-1"
    assert completed_meta["prompt"] == "What's the status?"
    assert completed_meta["output"] == "general reply"
    assert completed_meta["usage"] == {"request_tokens": 5, "response_tokens": 7, "total_tokens": 12}

    # Token usage recording for the user is unchanged by run persistence
    assert fake_mgr.usage_calls == [("user-1", 5, 7)]


def test_sync_chat_records_failed_state_on_agent_error(monkeypatch):
    fake_mgr = FakeIdentityManagerHost(agent_configs={"general-agent": EXTERNAL_USER_AGENT_CONFIG})

    with pytest.raises(HTTPException) as exc_info:
        _run_chat(monkeypatch, fake_mgr, FakeAgent(error=RuntimeError("agent exploded")))

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "Internal error while running the agent."
    assert [r[2] for r in fake_mgr.run_records] == ["processing", "failed"]

    failed_meta = fake_mgr.run_records[1][3]
    assert failed_meta["error"] == "agent exploded"
    assert failed_meta["source"] == "sync"
    assert failed_meta["user_id"] == "user-1"
    assert fake_mgr.usage_calls == []


def test_sync_chat_survives_run_persistence_failure(monkeypatch):
    fake_mgr = FakeIdentityManagerHost(
        agent_configs={"general-agent": EXTERNAL_USER_AGENT_CONFIG},
        record_error=RuntimeError("etcd unavailable"),
    )

    response = _run_chat(monkeypatch, fake_mgr, FakeAgent(output="still works"))

    assert response["choices"][0]["message"]["content"] == "still works"
    assert fake_mgr.run_records == []


def test_sync_chat_truncates_long_prompt_in_run_metadata(monkeypatch):
    fake_mgr = FakeIdentityManagerHost(agent_configs={"general-agent": EXTERNAL_USER_AGENT_CONFIG})

    _run_chat(monkeypatch, fake_mgr, FakeAgent(), content="x" * 20000)

    recorded_prompt = fake_mgr.run_records[0][3]["prompt"]
    assert len(recorded_prompt) < 20000
    assert "Truncated" in recorded_prompt


# --- workflows_view: sync runs stay out of the background UI ----------------------

BACKGROUND_WORKFLOW_CONFIG = {
    "name": "bg-flow", "type": "background_agent", "description": "",
    "allowed_tools": [], "allowed_mcps": [],
}


class FakeIdentityManagerWorkflowsRuns:
    """Minimal fake covering identity_mgr usage in workflows_view() and
    discover_agents(), following tests/test_workflows_secret_groups.py."""

    def __init__(self, agent_configs, agent_runs=None):
        self._agent_configs = agent_configs
        self._agent_runs = agent_runs or {}

    def list_agents(self):
        return list(self._agent_configs)

    def get_disabled_workflows(self):
        return []

    def get_agent_config(self, name):
        return self._agent_configs.get(name)

    def get_all_agent_configs(self):
        return dict(self._agent_configs)

    def list_mcps(self):
        return []

    def get_agent_runs(self, name, limit=None):
        return list(self._agent_runs.get(name, []))

    def get_all_health_statuses(self, entity_type):
        return {}

    def get_all_agent_skills(self):
        return {}

    def get_all_tool_configs(self):
        return {}

    def get_all_mcp_configs(self):
        return {}

    def get_tool_config(self, name):
        return None

    def get_mcp_config(self, name):
        return None

    def get_identity_config(self, identity, category, keys=None):
        return {}


def _bg_run(run_id, state, metadata=None):
    return {"run_id": run_id, "agent_name": "bg-flow", "state": state, "metadata": metadata or {}}


async def _fake_get_current_user(request):
    return {"sub": "admin-1", "email": "admin@example.com"}


def _run_workflows_view(monkeypatch, fake_mgr):
    monkeypatch.setattr(workflows, "get_current_user", _fake_get_current_user)
    monkeypatch.setattr(workflows, "is_admin", lambda request: True)
    monkeypatch.setattr(workflows, "identity_mgr", fake_mgr)
    monkeypatch.setattr(discovery, "identity_mgr", fake_mgr)

    captured = {}

    def fake_template_response(request=None, name=None, context=None):
        captured["context"] = context
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(workflows.templates, "TemplateResponse", fake_template_response)

    request = SimpleNamespace(session={"user": {"sub": "admin-1", "email": "admin@example.com"}})
    asyncio.run(workflows.workflows_view(request))
    return captured["context"]


def test_workflows_view_excludes_sync_runs_from_background_queue(monkeypatch):
    fake_mgr = FakeIdentityManagerWorkflowsRuns(
        agent_configs={"bg-flow": BACKGROUND_WORKFLOW_CONFIG},
        agent_runs={"bg-flow": [
            _bg_run("bg-1", "completed"),
            _bg_run("bg-2", "processing"),
            _bg_run("sync-1", "completed", {"source": "sync", "prompt": "hi"}),
            _bg_run("sync-2", "processing", {"source": "sync", "prompt": "hi"}),
        ]},
    )

    context = _run_workflows_view(monkeypatch, fake_mgr)

    assert [r["run_id"] for r in context["queue"]["completed"]] == ["bg-1"]
    assert [r["run_id"] for r in context["queue"]["processing"]] == ["bg-2"]
    wf = context["workflows_list"][0]
    assert wf["run_stats"] == {"pending": 0, "processing": 1, "completed": 1, "failed": 0}
    assert wf["is_running"] is True


def test_workflows_view_sync_processing_run_alone_does_not_mark_workflow_running(monkeypatch):
    fake_mgr = FakeIdentityManagerWorkflowsRuns(
        agent_configs={"bg-flow": BACKGROUND_WORKFLOW_CONFIG},
        agent_runs={"bg-flow": [_bg_run("sync-1", "processing", {"source": "sync"})]},
    )

    context = _run_workflows_view(monkeypatch, fake_mgr)

    wf = context["workflows_list"][0]
    assert wf["is_running"] is False
    assert wf["run_stats"] == {"pending": 0, "processing": 0, "completed": 0, "failed": 0}
    assert all(not entries for entries in context["queue"].values())
