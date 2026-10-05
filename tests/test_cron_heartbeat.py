# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``dynamic_cron_heartbeat`` in core.tasks.

taskiq 0.12.x's ``@broker.task`` decorator wraps the coroutine in an
``AsyncTaskiqDecoratedTask`` and keeps the untouched original available as
``.original_func`` — awaiting that directly runs the heartbeat body without
touching the Redis broker. Everything the heartbeat calls out to (identity
manager, the run_background_* task entrypoints, pycron, datetime) is
monkeypatched at the ``core.tasks`` module level, so no etcd/Redis/network
is involved.
"""

import asyncio
from datetime import datetime
from types import SimpleNamespace

import core.tasks as tasks

_AGENT = "nightly-agent"
_SCRIPT = "cleanup-script"

_NOW_MINUTE_ZERO = datetime(2026, 10, 5, 10, 0)
_NOW_MINUTE_SEVEN = datetime(2026, 10, 5, 10, 7)


class _FakeIdentityMgr:
    """Sync identity manager covering every method the heartbeat touches."""

    def __init__(self, agents, disabled=None, fail_record=False, fail_prune=False):
        self.agents = agents
        self.disabled = disabled or []
        self.fail_record = fail_record
        self.fail_prune = fail_prune
        self.pruned = []
        self.run_states = []
        self.config_fetches = []

    def list_agents(self):
        return list(self.agents)

    def get_disabled_workflows(self):
        return list(self.disabled)

    def get_agent_config(self, name):
        self.config_fetches.append(name)
        return self.agents.get(name)

    def prune_agent_runs(self, name, keep):
        if self.fail_prune:
            raise RuntimeError("prune boom")
        self.pruned.append((name, keep))

    def record_agent_run_state(self, name, task_id, state, data=None):
        if self.fail_record:
            raise RuntimeError("record boom")
        self.run_states.append((name, task_id, state, data))


class _FakeKiqTask:
    """Stands in for a taskiq task object: only .kiq is used by the heartbeat."""

    def __init__(self):
        self.calls = []

    async def kiq(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(task_id="t-1")


class _FakePycron:
    def __init__(self, matching):
        self.matching = set(matching)
        self.seen = []

    def is_now(self, expr, now):
        self.seen.append(expr)
        return expr in self.matching


def _run_heartbeat(monkeypatch, mgr, matching=(), minute_zero=False):
    """Patch core.tasks module globals, then await the raw heartbeat coroutine."""
    agent_task, script_task = _FakeKiqTask(), _FakeKiqTask()
    pycron_fake = _FakePycron(matching)

    fixed_now = _NOW_MINUTE_ZERO if minute_zero else _NOW_MINUTE_SEVEN

    class _FakeDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now

    monkeypatch.setattr(tasks, "datetime", _FakeDatetime)
    monkeypatch.setattr(tasks, "pycron", pycron_fake)
    monkeypatch.setattr(tasks, "get_identity_manager", lambda: mgr)
    monkeypatch.setattr(tasks, "run_background_agent", agent_task)
    monkeypatch.setattr(tasks, "run_background_script", script_task)

    heartbeat = tasks.dynamic_cron_heartbeat.original_func
    assert asyncio.iscoroutinefunction(heartbeat)
    asyncio.run(heartbeat())
    return agent_task, script_task, pycron_fake, fixed_now


def _agent_config(**overrides):
    config = {"type": "background_agent", "trigger": {"type": "cron", "expression": "0 5 * * *"}}
    config.update(overrides)
    return config


# --- Dispatch paths -----------------------------------------------------------

def test_cron_agent_is_dispatched_with_service_identity(monkeypatch):
    mgr = _FakeIdentityMgr({_AGENT: _agent_config()})
    agent_task, script_task, _, now = _run_heartbeat(
        monkeypatch, mgr, matching={"0 5 * * *"}
    )

    assert len(agent_task.calls) == 1
    (call,) = agent_task.calls
    assert call["agent_name"] == _AGENT
    assert call["user_id"] == f"svc_agent_{_AGENT}"
    assert call["prompt"].startswith("<event_payload><![CDATA[")
    assert now.isoformat() in call["prompt"]

    # Pending run state is recorded with the task id and dispatch payload.
    assert mgr.run_states == [
        (_AGENT, "t-1", "pending", {"prompt": call["prompt"], "user_id": f"svc_agent_{_AGENT}"})
    ]
    assert script_task.calls == []


def test_cron_script_is_dispatched_via_script_path(monkeypatch):
    mgr = _FakeIdentityMgr(
        {_SCRIPT: _agent_config(type="background_script")}
    )
    agent_task, script_task, _, _ = _run_heartbeat(
        monkeypatch, mgr, matching={"0 5 * * *"}
    )

    assert len(script_task.calls) == 1
    assert script_task.calls[0]["agent_name"] == _SCRIPT
    assert script_task.calls[0]["user_id"] == f"svc_agent_{_SCRIPT}"
    assert agent_task.calls == []
    assert mgr.run_states == [(_SCRIPT, "t-1", "pending", mgr.run_states[0][3])]


def test_disabled_workflow_is_skipped_entirely(monkeypatch):
    mgr = _FakeIdentityMgr(
        {_AGENT: _agent_config()},
        disabled=[_AGENT],
    )
    agent_task, script_task, pycron_fake, _ = _run_heartbeat(
        monkeypatch, mgr, matching={"0 5 * * *"}, minute_zero=True
    )

    assert agent_task.calls == []
    assert script_task.calls == []
    assert mgr.config_fetches == []  # short-circuits before the config fetch
    assert mgr.pruned == []
    assert pycron_fake.seen == []


def test_non_background_agents_are_not_dispatched(monkeypatch):
    mgr = _FakeIdentityMgr(
        {
            "chatty": {"type": "user_agent", "trigger": {"type": "cron", "expression": "0 5 * * *"}},
            "untyped": {"trigger": {"type": "cron", "expression": "0 5 * * *"}},
        }
    )
    agent_task, script_task, pycron_fake, _ = _run_heartbeat(
        monkeypatch, mgr, matching={"0 5 * * *"}, minute_zero=True
    )

    assert agent_task.calls == []
    assert script_task.calls == []
    assert pycron_fake.seen == []  # cron evaluation is never reached
    assert mgr.pruned == []  # pruning is also gated on background type


def test_agent_without_cron_trigger_is_not_dispatched(monkeypatch):
    mgr = _FakeIdentityMgr({"no-trigger": {"type": "background_agent"}})
    agent_task, _, _, _ = _run_heartbeat(monkeypatch, mgr, minute_zero=True)

    assert agent_task.calls == []


# --- Hourly pruning -----------------------------------------------------------

def test_prune_runs_at_minute_zero_with_keep_100(monkeypatch):
    mgr = _FakeIdentityMgr(
        {
            _AGENT: _agent_config(),
            "no-trigger": {"type": "background_agent"},
            "chatty": {"type": "user_agent"},
        }
    )
    _run_heartbeat(monkeypatch, mgr, matching={"0 5 * * *"}, minute_zero=True)

    # Every non-disabled background agent/script is pruned, cron or not.
    assert mgr.pruned == [(_AGENT, 100), ("no-trigger", 100)]


def test_prune_skipped_when_minute_nonzero(monkeypatch):
    mgr = _FakeIdentityMgr({_AGENT: _agent_config()})
    _run_heartbeat(monkeypatch, mgr, matching={"0 5 * * *"}, minute_zero=False)

    assert mgr.pruned == []


def test_prune_failure_does_not_break_heartbeat(monkeypatch):
    mgr = _FakeIdentityMgr({_AGENT: _agent_config()}, fail_prune=True)
    agent_task, _, _, _ = _run_heartbeat(
        monkeypatch, mgr, matching={"0 5 * * *"}, minute_zero=True
    )

    assert len(agent_task.calls) == 1  # dispatch still happened


# --- Multi-expression triggers --------------------------------------------------

def test_multiple_expressions_dispatch_at_most_once(monkeypatch):
    mgr = _FakeIdentityMgr(
        {_AGENT: _agent_config(trigger={"type": "cron", "expression": ["no-match", "0 9 * * *"]})}
    )
    agent_task, _, pycron_fake, _ = _run_heartbeat(
        monkeypatch, mgr, matching={"0 9 * * *"}
    )

    # Both expressions are evaluated in order; the match breaks the loop.
    assert pycron_fake.seen == ["no-match", "0 9 * * *"]
    assert len(agent_task.calls) == 1


# --- Fail-open state recording ---------------------------------------------------

def test_record_state_failure_heartbeat_still_completes(monkeypatch):
    mgr = _FakeIdentityMgr({_AGENT: _agent_config()}, fail_record=True)
    agent_task, _, _, _ = _run_heartbeat(monkeypatch, mgr, matching={"0 5 * * *"})

    assert len(agent_task.calls) == 1  # dispatch happened before the failed record
    assert mgr.run_states == []
