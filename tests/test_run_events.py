# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Run event log, heartbeat and run-record pruning tests for core.auth.

Everything runs against an in-memory fake etcd client (no etcd, no network, no
sleeps), and the core.tasks coroutines are driven directly via asyncio.run.
"""

import asyncio
import json
import threading
from datetime import datetime
from types import SimpleNamespace

import core.tasks as tasks
from core.auth import RUN_EVENT_GENESIS_DIGEST, IdentityManager, _run_event_digest

_AGENT = "a"
_RUN = "run-1"
_BASE = f"/runs/{_AGENT}/{_RUN}"


class _Meta:
    def __init__(self, key):
        self.key = key


class FakeClient:
    def __init__(self):
        self.store = {}
        self.lock_names = []
        self._locks = {}
        self._guard = threading.Lock()

    def get(self, path):
        return self.store.get(path), None

    def put(self, path, value):
        self.store[path] = value.encode("utf-8") if isinstance(value, str) else value

    def get_prefix(self, prefix):
        keys = sorted(key for key in list(self.store) if key.startswith(prefix))
        return [(self.store[key], _Meta(key.encode("utf-8"))) for key in keys]

    def delete(self, path):
        self.store.pop(path, None)

    def delete_prefix(self, prefix):
        for key in [k for k in list(self.store) if k.startswith(prefix)]:
            del self.store[key]

    def lock(self, name, ttl=None):
        self.lock_names.append(name)
        with self._guard:
            return self._locks.setdefault(name, threading.Lock())


def _mgr():
    mgr = IdentityManager.__new__(IdentityManager)
    mgr.client = FakeClient()
    return mgr


def _event_key(seq):
    return f"{_BASE}/events/{seq:08d}"


def _state(mgr, run_id=_RUN):
    value, _ = mgr.client.get(f"/runs/{_AGENT}/{run_id}")
    return json.loads(value.decode("utf-8"))


def _event(mgr, seq, run_id=_RUN):
    value, _ = mgr.client.get(f"/runs/{_AGENT}/{run_id}/events/{seq:08d}")
    return json.loads(value.decode("utf-8"))


def _run_record(run_id, updated_at, state="completed"):
    return {
        "run_id": run_id,
        "agent_name": _AGENT,
        "state": state,
        "timestamp": updated_at,
        "updated_at": updated_at,
        "created_at": updated_at,
        "metadata": {},
    }


# --- Chain integrity ---------------------------------------------------------

def test_appends_chain_and_advance_state_head():
    mgr = _mgr()
    assert mgr.record_agent_run_state(_AGENT, _RUN, "pending", {"k": "v"}) is True

    seqs = [
        mgr.append_run_event(_AGENT, _RUN, event_type)
        for event_type in ("run_enqueued", "run_started", "run_completed")
    ]
    assert seqs == [1, 2, 3]
    assert mgr.verify_run_history(_AGENT, _RUN) == {
        "ok": True,
        "count": 3,
        "broken_at_seq": None,
    }

    events = [_event(mgr, seq) for seq in (1, 2, 3)]
    assert events[0]["prev_digest"] == RUN_EVENT_GENESIS_DIGEST
    for previous, current in zip(events, events[1:]):
        assert current["prev_digest"] == previous["digest"]
    for event in events:
        assert event["digest"] == _run_event_digest(
            event["prev_digest"], event["seq"], event["type"], event["ts"], event["payload"]
        )

    state = _state(mgr)
    assert state["last_seq"] == 3
    assert state["history_digest"] == events[-1]["digest"]
    assert state["state"] == "pending"
    assert state["metadata"] == {"k": "v"}
    assert state["created_at"]


def test_tampered_event_payload_is_detected():
    mgr = _mgr()
    mgr.record_agent_run_state(_AGENT, _RUN, "pending", {})
    for event_type in ("run_enqueued", "run_started", "run_completed"):
        mgr.append_run_event(_AGENT, _RUN, event_type)

    document = _event(mgr, 2)
    document["payload"] = {"tampered": True}
    mgr.client.put(_event_key(2), json.dumps(document, sort_keys=True))

    result = mgr.verify_run_history(_AGENT, _RUN)
    assert result["ok"] is False
    assert result["broken_at_seq"] == 2


def test_append_without_run_record_recovers_chain_head():
    # enqueue_workflow_run appends even when the pending state write failed, so the
    # first event can exist with no run record. The chain head must come from the
    # stored events instead of restarting at seq 1 (which would overwrite).
    mgr = _mgr()
    seqs = [mgr.append_run_event(_AGENT, _RUN, "run_enqueued") for _ in range(3)]

    assert seqs == [1, 2, 3]
    assert len([key for key in mgr.client.store if "/events/" in key]) == 3
    assert mgr.verify_run_history(_AGENT, _RUN)["ok"] is True


def test_tail_truncation_is_detected():
    mgr = _mgr()
    mgr.record_agent_run_state(_AGENT, _RUN, "processing", {})
    for event_type in ("run_enqueued", "run_started", "run_completed"):
        mgr.append_run_event(_AGENT, _RUN, event_type)

    # Deleting the newest event leaves an internally consistent chain, so only the
    # run record's retained head can reveal it.
    mgr.client.delete(_event_key(3))

    result = mgr.verify_run_history(_AGENT, _RUN)
    assert result["ok"] is False
    assert result["broken_at_seq"] == 3


# --- Ordering and readback ---------------------------------------------------

def test_event_keys_are_zero_padded():
    mgr = _mgr()
    mgr.record_agent_run_state(_AGENT, _RUN, "processing", {})
    for index in range(12):
        assert mgr.append_run_event(_AGENT, _RUN, "step", {"i": index}) == index + 1

    keys = sorted(key for key in mgr.client.store if "/events/" in key)
    assert keys == [_event_key(seq) for seq in range(1, 13)]
    assert [event["seq"] for event in mgr.get_run_events(_AGENT, _RUN, limit=0)] == list(
        range(1, 13)
    )


def test_get_run_events_returns_newest_limit_ascending():
    mgr = _mgr()
    mgr.record_agent_run_state(_AGENT, _RUN, "processing", {})
    for index in range(5):
        mgr.append_run_event(_AGENT, _RUN, "step", {"i": index})

    assert [event["seq"] for event in mgr.get_run_events(_AGENT, _RUN, limit=2)] == [4, 5]
    assert [event["seq"] for event in mgr.get_run_events(_AGENT, _RUN, limit=0)] == [
        1,
        2,
        3,
        4,
        5,
    ]


def test_empty_history_reads_and_verifies_clean():
    mgr = _mgr()
    assert mgr.get_run_events(_AGENT, "run-empty") == []
    assert mgr.verify_run_history(_AGENT, "run-empty") == {
        "ok": True,
        "count": 0,
        "broken_at_seq": None,
    }


# --- Concurrency -------------------------------------------------------------

def test_concurrent_appends_serialize_under_state_lock():
    mgr = _mgr()
    mgr.record_agent_run_state(_AGENT, _RUN, "processing", {})
    state_lock = mgr.client.lock_names[-1]
    assert state_lock == f"/runs/{_AGENT}/{_RUN}_lock"

    barrier = threading.Barrier(25)
    results = []
    errors = []

    def worker(index):
        try:
            barrier.wait()
            results.append(mgr.append_run_event(_AGENT, _RUN, "step", {"i": index}))
        except Exception as err:  # noqa: BLE001 - surfaced via assert below
            errors.append(err)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(25)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sorted(results) == list(range(1, 26))
    assert len([key for key in mgr.client.store if "/events/" in key]) == 25
    assert mgr.verify_run_history(_AGENT, _RUN)["ok"] is True
    assert set(mgr.client.lock_names[1:]) == {state_lock}


def test_state_transition_after_appends_preserves_chain_head():
    # record_agent_run_state merges the existing record; if it ever overwrote it,
    # the next append would restart at seq 1 and the chain would break.
    mgr = _mgr()
    mgr.record_agent_run_state(_AGENT, _RUN, "pending", {})
    assert mgr.append_run_event(_AGENT, _RUN, "run_enqueued") == 1

    mgr.record_agent_run_state(_AGENT, _RUN, "processing", {"step": 1})
    state = _state(mgr)
    assert state["state"] == "processing"
    assert state["last_seq"] == 1
    assert state["history_digest"]

    assert mgr.append_run_event(_AGENT, _RUN, "run_started") == 2
    assert mgr.verify_run_history(_AGENT, _RUN) == {
        "ok": True,
        "count": 2,
        "broken_at_seq": None,
    }


def test_state_transition_merges_metadata():
    # Attempt accounting written at enqueue must survive the worker's generic
    # processing/completed metadata writes, or retries never observe the attempt.
    mgr = _mgr()
    mgr.record_agent_run_state(
        _AGENT, _RUN, "pending", {"prompt": "p", "attempt": 2, "prior_run_id": "r0"}
    )
    mgr.record_agent_run_state(_AGENT, _RUN, "processing", {"prompt": "p2", "user_id": "u"})

    metadata = _state(mgr)["metadata"]
    assert metadata["attempt"] == 2
    assert metadata["prior_run_id"] == "r0"
    assert metadata["prompt"] == "p2"
    assert metadata["user_id"] == "u"


def test_appends_serialize_with_state_transitions():
    mgr = _mgr()
    mgr.record_agent_run_state(_AGENT, _RUN, "pending", {})

    barrier = threading.Barrier(20)
    errors = []

    def worker(index):
        try:
            barrier.wait()
            if index % 2:
                mgr.append_run_event(_AGENT, _RUN, "step", {"i": index})
            else:
                mgr.record_agent_run_state(_AGENT, _RUN, "processing", {"i": index})
        except Exception as err:  # noqa: BLE001 - surfaced via assert below
            errors.append(err)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    events = mgr.get_run_events(_AGENT, _RUN, limit=0)
    assert [event["seq"] for event in events] == list(range(1, 11))
    assert mgr.verify_run_history(_AGENT, _RUN)["ok"] is True
    assert _state(mgr)["last_seq"] == 10


# --- Heartbeat ---------------------------------------------------------------

def test_heartbeat_roundtrip_and_missing():
    mgr = _mgr()
    assert mgr.get_run_heartbeat(_AGENT, _RUN) is None

    mgr.record_run_heartbeat(_AGENT, _RUN)

    raw = mgr.client.store[f"{_BASE}/heartbeat"].decode("utf-8")
    parsed = datetime.fromisoformat(raw)
    assert parsed.utcoffset().total_seconds() == 0
    assert mgr.get_run_heartbeat(_AGENT, _RUN) == raw


# --- Listings and pruning ----------------------------------------------------

def test_get_agent_runs_skips_subkeys():
    mgr = _mgr()
    mgr.client.put(
        "/runs/a/run-old", json.dumps(_run_record("run-old", "2026-01-01T00:00:00+00:00"))
    )
    mgr.client.put(
        "/runs/a/run-new", json.dumps(_run_record("run-new", "2026-01-02T00:00:00+00:00"))
    )
    mgr.client.put("/runs/a/run-new/events/00000001", json.dumps({"seq": 1}))
    mgr.client.put("/runs/a/run-new/heartbeat", "2026-01-02T00:00:01+00:00")

    runs = mgr.get_agent_runs(_AGENT)
    assert [run["run_id"] for run in runs] == ["run-new", "run-old"]
    assert [run["run_id"] for run in mgr.get_agent_runs(_AGENT, limit=1)] == ["run-new"]


def test_prune_deletes_subtree_without_touching_sibling_run_ids():
    mgr = _mgr()
    mgr.client.put(
        "/runs/a/run-1", json.dumps(_run_record("run-1", "2026-01-01T00:00:00+00:00"))
    )
    mgr.client.put(
        "/runs/a/run-10", json.dumps(_run_record("run-10", "2026-01-02T00:00:00+00:00"))
    )
    assert mgr.append_run_event(_AGENT, "run-1", "run_started") == 1
    mgr.record_run_heartbeat(_AGENT, "run-1")
    assert mgr.append_run_event(_AGENT, "run-10", "run_started") == 1

    assert mgr.prune_agent_runs(_AGENT, keep_last=1) == 1

    for gone in (
        "/runs/a/run-1",
        "/runs/a/run-1/events/00000001",
        "/runs/a/run-1/heartbeat",
    ):
        assert gone not in mgr.client.store
    assert "/runs/a/run-10" in mgr.client.store
    assert "/runs/a/run-10/events/00000001" in mgr.client.store


def test_prune_script_counts_records_only_and_deletes_subtrees():
    from scripts import prune_etcd_runs

    mgr = _mgr()
    mgr.client.put(
        "/runs/a/run-1", json.dumps(_run_record("run-1", "2026-01-01T00:00:00+00:00"))
    )
    mgr.client.put(
        "/runs/a/run-10", json.dumps(_run_record("run-10", "2026-01-02T00:00:00+00:00"))
    )
    mgr.append_run_event(_AGENT, "run-1", "run_started")
    mgr.record_run_heartbeat(_AGENT, "run-1")
    mgr.append_run_event(_AGENT, "run-10", "run_started")

    # The script skips sub-keys when counting, so keep=1 prunes only the older run
    # (the old shape counted each event as a record and deleted the newest run's).
    prune_etcd_runs.prune_agent(mgr, _AGENT, keep=1)

    assert "/runs/a/run-1" not in mgr.client.store
    assert "/runs/a/run-1/events/00000001" not in mgr.client.store
    assert "/runs/a/run-1/heartbeat" not in mgr.client.store
    assert "/runs/a/run-10" in mgr.client.store
    assert "/runs/a/run-10/events/00000001" in mgr.client.store


# --- core.tasks emission -----------------------------------------------------

class _RecordingMgr:
    def __init__(self, run_record=None):
        self.run_record = run_record
        self.log = []

    def record_agent_run_state(self, agent_name, run_id, state, metadata):
        self.log.append(("state", state, metadata))
        return True

    def append_run_event(self, agent_name, run_id, event_type, payload=None):
        self.log.append(("event", event_type, payload))
        return 1

    def record_run_heartbeat(self, agent_name, run_id):
        self.log.append(("heartbeat", run_id))

    def get_agent_run(self, agent_name, run_id):
        return self.run_record


class _BareMgr:
    """Manager without the run-event/heartbeat methods (older registry contract)."""

    def record_agent_run_state(self, *args, **kwargs):
        return True


class _FakeKiqTask:
    def __init__(self):
        self.calls = []

    async def kiq(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(task_id="t-1")


def test_enqueue_workflow_run_emits_run_enqueued_after_pending(monkeypatch):
    mgr = _RecordingMgr()
    agent_task, script_task = _FakeKiqTask(), _FakeKiqTask()
    monkeypatch.setattr(tasks, "get_identity_manager", lambda: mgr)
    monkeypatch.setattr(tasks, "run_background_agent", agent_task)
    monkeypatch.setattr(tasks, "run_background_script", script_task)

    asyncio.run(tasks.enqueue_workflow_run("nightly", {"type": "background_agent"}, "<p/>"))

    assert agent_task.calls[0]["agent_name"] == "nightly"
    assert script_task.calls == []
    assert mgr.log == [
        (
            "state",
            "pending",
            {"prompt": "<p/>", "user_id": "svc_agent_nightly"},
        ),
        ("event", "run_enqueued", {"user_id": "svc_agent_nightly"}),
    ]


def test_abort_if_cancelled_emits_run_cancelled():
    cancelled = _RecordingMgr(run_record={"state": "cancelled"})
    assert asyncio.run(tasks._abort_if_cancelled(cancelled, "nightly", "t-1")) is True
    assert cancelled.log == [
        ("event", "run_cancelled", {"reason": "cancelled_before_start"})
    ]

    active = _RecordingMgr(run_record={"state": "processing"})
    assert asyncio.run(tasks._abort_if_cancelled(active, "nightly", "t-2")) is False
    assert active.log == []


def test_run_event_helpers_swallow_missing_manager_methods():
    mgr = _BareMgr()
    asyncio.run(tasks._append_run_event(mgr, "nightly", "t-1", "run_started"))
    asyncio.run(tasks._write_heartbeat(mgr, "nightly", "t-1"))


def test_run_event_helpers_skip_unknown_task_id():
    mgr = _RecordingMgr()
    asyncio.run(tasks._append_run_event(mgr, "nightly", "unknown", "run_started"))
    asyncio.run(tasks._write_heartbeat(mgr, "nightly", "unknown"))
    assert mgr.log == []
