# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for the orphaned-run reaper (``core.tasks.reap_orphaned_runs``).

The real ``IdentityManager`` runs against the in-memory fake etcd client from
``tests/test_run_events.py``, so the terminal-state guard, the retry CAS claim and
the hash-chained event log are all exercised for real. Everything the task body
touches that is not the registry (the broker, the two ``run_background_*`` task
entrypoints, the clock, tunable overrides) is monkeypatched at the ``core.tasks``
/ ``core.tunables`` module level: no etcd, no Redis, no network, no sleeps.

Staleness is never left to the wall clock: run records are seeded with explicit
timestamps and ``tasks._utcnow`` (plus ``core.auth.datetime``, which stamps
heartbeats/retries/events) is frozen to a fixed ``now``.
"""

import asyncio
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import core.auth as auth
import core.tasks as tasks
import core.tunables as tunables
from core.auth import IdentityManager

_NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
_clock = {"now": _NOW}


class _FrozenDatetime(datetime):
    """datetime whose ``now()`` is the test clock (the C type itself is immutable)."""

    @classmethod
    def now(cls, tz=None):
        current = _clock["now"]
        return current if tz is not None else current.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def _frozen_environment(monkeypatch):
    """Freeze the clock and keep tunables off etcd for every test here."""
    _clock["now"] = _NOW
    monkeypatch.setattr(auth, "datetime", _FrozenDatetime)
    monkeypatch.setattr(tasks, "_utcnow", lambda: _clock["now"])
    # A "fresh" tunable cache means resolve() never kicks the background etcd refresh.
    monkeypatch.setattr(tunables, "_overrides", {})
    monkeypatch.setattr(tunables, "_overrides_checked_at", time.monotonic())
    monkeypatch.setattr(tunables, "_refresh_in_flight", False)
    for env_var in (
        "REAPER_STALE_HEARTBEAT_S",
        "REAPER_STALE_PENDING_S",
        "REAPER_STALE_PROCESSING_S",
        "REAPER_SCAN_PER_AGENT",
    ):
        monkeypatch.delenv(env_var, raising=False)


# --- Fake etcd client / manager harness (mirrors tests/test_run_events.py) ----


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


class _FakeKiqTask:
    """Stands in for a taskiq task object: only ``.kiq`` is used by dispatch."""

    def __init__(self, prefix="retry"):
        self.calls = []
        self._prefix = prefix

    async def kiq(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(task_id=f"{self._prefix}-{len(self.calls)}")


def _install(monkeypatch, mgr):
    """Point core.tasks at the fake manager and the fake dispatch tasks."""
    agent_task, script_task = _FakeKiqTask("agent"), _FakeKiqTask("script")
    monkeypatch.setattr(tasks, "get_identity_manager", lambda: mgr)
    monkeypatch.setattr(tasks, "run_background_agent", agent_task)
    monkeypatch.setattr(tasks, "run_background_script", script_task)
    return agent_task, script_task


# --- Seeding / readback helpers ---------------------------------------------


def _ago(seconds):
    return _NOW - timedelta(seconds=seconds)


def _iso(value):
    return value.isoformat()


def _seed_agent(mgr, name, config):
    mgr.client.put(f"/registry/agents/{name}/config", json.dumps(config))


def _seed_run(mgr, name, run_id, state, updated_at, metadata=None):
    record = {
        "run_id": run_id,
        "agent_name": name,
        "state": state,
        "timestamp": updated_at,
        "updated_at": updated_at,
        "created_at": updated_at,
        "metadata": {} if metadata is None else metadata,
    }
    mgr.client.put(f"/runs/{name}/{run_id}", json.dumps(record))
    return record


def _record(mgr, name, run_id):
    value, _ = mgr.client.get(f"/runs/{name}/{run_id}")
    return json.loads(value.decode("utf-8"))


def _events(mgr, name, run_id):
    return mgr.get_run_events(name, run_id, limit=0)


def _reap():
    """Drive the task body directly: no broker, no Redis, no wrapper."""
    return asyncio.run(tasks.reap_orphaned_runs.original_func())


# --- 1. Healthy runs --------------------------------------------------------


def test_healthy_runs_are_untouched(monkeypatch):
    mgr = _mgr()
    _seed_agent(mgr, "wf", {"type": "background_agent"})
    _seed_run(mgr, "wf", "run-live", "processing", _iso(_ago(3600)))
    # A heartbeat 10s old via the real writer: comfortably inside the 90s tunable.
    _clock["now"] = _ago(10)
    mgr.record_run_heartbeat("wf", "run-live")
    _clock["now"] = _NOW
    _seed_run(mgr, "wf", "run-waiting", "pending", _iso(_ago(60)))
    _install(monkeypatch, mgr)

    totals = _reap()

    assert totals == {"scanned": 2, "orphaned": 0, "retried": 0, "errors": 0}
    assert _record(mgr, "wf", "run-live")["state"] == "processing"
    assert _record(mgr, "wf", "run-waiting")["state"] == "pending"
    for run_id in ("run-live", "run-waiting"):
        assert _events(mgr, "wf", run_id) == []
        assert "orphaned" not in _record(mgr, "wf", run_id)["metadata"]


# --- 2. Stale heartbeat -----------------------------------------------------


def test_stale_heartbeat_orphans_the_run(monkeypatch):
    mgr = _mgr()
    _seed_agent(mgr, "wf", {"type": "background_agent"})
    _seed_run(mgr, "wf", "run-1", "processing", _iso(_ago(3600)), metadata={"prompt": "<p/>"})
    _clock["now"] = _ago(120)
    mgr.record_run_heartbeat("wf", "run-1")
    _clock["now"] = _NOW
    _install(monkeypatch, mgr)

    totals = _reap()

    assert totals == {"scanned": 1, "orphaned": 1, "retried": 0, "errors": 0}
    record = _record(mgr, "wf", "run-1")
    assert record["state"] == "failed"
    metadata = record["metadata"]
    assert metadata["orphaned"] is True
    assert metadata["orphan_reason"] == "stale_heartbeat"
    assert metadata["heartbeat_age_s"] == 120
    assert metadata["attempt"] == 1
    assert metadata["orphaned_at"] == _iso(_NOW)

    events = _events(mgr, "wf", "run-1")
    assert [event["type"] for event in events] == ["run_orphaned"]
    assert events[0]["payload"] == {
        "reason": "stale_heartbeat",
        "heartbeat_age_s": 120,
        "fallback": False,
        "attempt": 1,
    }
    assert mgr.verify_run_history("wf", "run-1") == {
        "ok": True,
        "count": 1,
        "broken_at_seq": None,
    }


# --- 3. Stuck pending -------------------------------------------------------


def test_stuck_pending_is_orphaned_fresh_pending_is_not(monkeypatch):
    mgr = _mgr()
    _seed_agent(mgr, "wf", {"type": "background_agent"})
    _seed_run(mgr, "wf", "run-stuck", "pending", _iso(_ago(600)))
    _seed_run(mgr, "wf", "run-fresh", "pending", _iso(_ago(60)))
    _install(monkeypatch, mgr)

    totals = _reap()

    assert totals == {"scanned": 2, "orphaned": 1, "retried": 0, "errors": 0}
    stuck = _record(mgr, "wf", "run-stuck")
    assert stuck["state"] == "failed"
    assert stuck["metadata"]["orphan_reason"] == "stale_pending"
    assert stuck["metadata"]["heartbeat_age_s"] is None

    fresh = _record(mgr, "wf", "run-fresh")
    assert fresh["state"] == "pending"
    assert _events(mgr, "wf", "run-fresh") == []


# --- 4. Processing without a heartbeat falls back to updated_at -------------


def test_processing_without_heartbeat_falls_back_to_updated_at(monkeypatch):
    mgr = _mgr()
    _seed_agent(mgr, "wf", {"type": "background_agent"})
    # No heartbeat key at all (a pre-heartbeat run).
    _seed_run(mgr, "wf", "run-old", "processing", _iso(_ago(7200)))
    # Below the 3600s reaper_stale_processing_s tunable: still healthy.
    _seed_run(mgr, "wf", "run-ok", "processing", _iso(_ago(1800)))
    _install(monkeypatch, mgr)

    totals = _reap()

    assert totals == {"scanned": 2, "orphaned": 1, "retried": 0, "errors": 0}
    old = _record(mgr, "wf", "run-old")
    assert old["state"] == "failed"
    assert old["metadata"]["orphan_reason"] == "stale_heartbeat"
    assert old["metadata"]["heartbeat_age_s"] is None
    assert _events(mgr, "wf", "run-old")[0]["payload"]["heartbeat_age_s"] is None
    assert _record(mgr, "wf", "run-ok")["state"] == "processing"

    # The fallback flag itself is only exposed by the decision helper.
    assert tasks._orphan_reason("processing", None, _ago(7200), _NOW) == {
        "reason": "stale_heartbeat",
        "heartbeat_age_s": None,
        "fallback": True,
    }


# --- 5. Terminal states -----------------------------------------------------


def test_terminal_states_are_never_rewritten(monkeypatch):
    mgr = _mgr()
    _seed_agent(mgr, "wf", {"type": "background_agent"})
    before = {}
    for state in ("completed", "cancelled", "failed"):
        run_id = f"run-{state}"
        _seed_run(mgr, "wf", run_id, state, _iso(_ago(7200)), metadata={"attempt": 1})
        mgr.append_run_event("wf", run_id, f"run_{state}")
        before[run_id] = (_record(mgr, "wf", run_id), len(_events(mgr, "wf", run_id)))
    _install(monkeypatch, mgr)

    totals = _reap()

    assert totals == {"scanned": 3, "orphaned": 0, "retried": 0, "errors": 0}
    for run_id, (record, event_count) in before.items():
        assert _record(mgr, "wf", run_id) == record
        assert len(_events(mgr, "wf", run_id)) == event_count


def test_terminal_guard_wins_over_a_stale_scan_snapshot(monkeypatch):
    """A run cancelled/completed between the scan and the write must not be rewritten."""
    mgr = _mgr()
    _seed_agent(mgr, "wf", {"type": "background_agent"})
    stale_view = {
        "run_id": "run-1",
        "agent_name": "wf",
        "state": "processing",
        "timestamp": _iso(_ago(7200)),
        "updated_at": _iso(_ago(7200)),
        "created_at": _iso(_ago(7200)),
        "metadata": {"attempt": 1},
    }
    real_get_run = mgr.get_agent_run

    def get_agent_run(agent_name, run_id):
        if agent_name == "wf" and run_id == "run-1":
            return dict(stale_view)
        return real_get_run(agent_name, run_id)

    mgr.get_agent_run = get_agent_run
    # By write time the stored record is already terminal.
    mgr.client.put("/runs/wf/run-1", json.dumps({**stale_view, "state": "completed"}))
    _install(monkeypatch, mgr)

    totals = _reap()

    assert totals["orphaned"] == 0
    assert _record(mgr, "wf", "run-1")["state"] == "completed"
    assert _events(mgr, "wf", "run-1") == []


# --- 6. Bounded retry -------------------------------------------------------


def test_bounded_retry_enqueues_once_after_backoff(monkeypatch):
    mgr = _mgr()
    _seed_agent(
        mgr,
        "wf",
        {"type": "background_agent", "retries": {"max_attempts": 2, "backoff_s": 60}},
    )
    _seed_run(mgr, "wf", "run-1", "processing", _iso(_ago(900)), metadata={"prompt": "<p/>"})
    _clock["now"] = _ago(120)
    mgr.record_run_heartbeat("wf", "run-1")
    _clock["now"] = _NOW
    agent_task, script_task = _install(monkeypatch, mgr)

    # First pass: orphaned and scheduled, but never re-enqueued in the same pass.
    first = _reap()
    assert first == {"scanned": 1, "orphaned": 1, "retried": 0, "errors": 0}
    assert agent_task.calls == [] and script_task.calls == []
    orphaned = _record(mgr, "wf", "run-1")
    assert orphaned["state"] == "failed"
    assert orphaned["metadata"]["retry_at"] == _iso(_NOW + timedelta(seconds=60))
    assert "retried_run_id" not in orphaned["metadata"]

    # Second pass, one second past the backoff: exactly one dispatch.
    _clock["now"] = _NOW + timedelta(seconds=61)
    second = _reap()
    assert second == {"scanned": 1, "orphaned": 0, "retried": 1, "errors": 0}
    assert len(agent_task.calls) == 1
    assert script_task.calls == []
    assert agent_task.calls[0]["agent_name"] == "wf"
    assert agent_task.calls[0]["prompt"] == "<p/>"

    new_run_id = "agent-1"
    retried = _record(mgr, "wf", new_run_id)
    assert retried["state"] == "pending"
    assert retried["metadata"]["attempt"] == 2
    assert retried["metadata"]["prior_run_id"] == "run-1"
    assert _record(mgr, "wf", "run-1")["metadata"]["retried_run_id"] == new_run_id

    old_events = _events(mgr, "wf", "run-1")
    assert [event["type"] for event in old_events] == ["run_orphaned", "run_retried"]
    assert old_events[-1]["payload"] == {"new_run_id": new_run_id, "attempt": 2}

    new_events = _events(mgr, "wf", new_run_id)
    assert [event["type"] for event in new_events] == ["run_enqueued", "run_retried"]
    assert new_events[-1]["payload"] == {"prior_run_id": "run-1", "attempt": 2}

    assert mgr.verify_run_history("wf", "run-1")["ok"] is True
    assert mgr.verify_run_history("wf", new_run_id)["ok"] is True

    # record_agent_run_state stamps with the wall clock (its function-local datetime
    # import bypasses the frozen module attribute), so pin the fresh record's
    # timestamps before the third pass to keep it deterministic.
    retried["timestamp"] = retried["updated_at"] = retried["created_at"] = _iso(
        _NOW + timedelta(seconds=61)
    )
    mgr.client.put(f"/runs/wf/{new_run_id}", json.dumps(retried))

    # Third pass: the claim sentinel is now a real id, so nothing is dispatched again.
    third = _reap()
    assert third == {"scanned": 2, "orphaned": 0, "retried": 0, "errors": 0}
    assert len(agent_task.calls) == 1


# --- 7/8. Attempt policy ----------------------------------------------------


def test_attempt_cap_respected(monkeypatch):
    mgr = _mgr()
    _seed_agent(
        mgr,
        "capped",
        {"type": "background_agent", "retries": {"max_attempts": 2, "backoff_s": 60}},
    )
    _seed_agent(
        mgr,
        "extendable",
        {"type": "background_agent", "retries": {"max_attempts": 3, "backoff_s": 60}},
    )
    for name in ("capped", "extendable"):
        _seed_run(mgr, name, "run-1", "processing", _iso(_ago(900)), metadata={"attempt": 2})
        _clock["now"] = _ago(120)
        mgr.record_run_heartbeat(name, "run-1")
    _clock["now"] = _NOW
    agent_task, _ = _install(monkeypatch, mgr)

    totals = _reap()

    assert totals == {"scanned": 2, "orphaned": 2, "retried": 0, "errors": 0}
    capped = _record(mgr, "capped", "run-1")
    assert capped["state"] == "failed"
    assert capped["metadata"]["attempt"] == 2
    assert "retry_at" not in capped["metadata"]

    extendable = _record(mgr, "extendable", "run-1")
    assert extendable["metadata"]["attempt"] == 2
    assert extendable["metadata"]["retry_at"] == _iso(_NOW + timedelta(seconds=60))
    assert agent_task.calls == []


def test_missing_or_malformed_retries_means_one_attempt(monkeypatch):
    mgr = _mgr()
    _seed_agent(mgr, "plain", {"type": "background_agent"})
    _seed_agent(
        mgr,
        "broken",
        {"type": "background_agent", "retries": {"max_attempts": "lots", "backoff_s": "soon"}},
    )
    for name in ("plain", "broken"):
        _seed_run(mgr, name, "run-1", "processing", _iso(_ago(900)))
        _clock["now"] = _ago(120)
        mgr.record_run_heartbeat(name, "run-1")
    _clock["now"] = _NOW
    agent_task, _ = _install(monkeypatch, mgr)

    first = _reap()

    assert first == {"scanned": 2, "orphaned": 2, "retried": 0, "errors": 0}
    for name in ("plain", "broken"):
        record = _record(mgr, name, "run-1")
        assert record["state"] == "failed"
        assert record["metadata"]["attempt"] == 1
        assert "retry_at" not in record["metadata"]

    # Even a long wait never dispatches: max_attempts defaults to 1.
    _clock["now"] = _NOW + timedelta(seconds=7200)
    assert _reap()["retried"] == 0
    assert agent_task.calls == []


# --- 9. Sweep scope ---------------------------------------------------------


def test_sweep_scope_and_no_pruning(monkeypatch):
    mgr = _mgr()
    _seed_agent(mgr, "ui-agent", {"type": "user_agent"})
    _seed_agent(mgr, "cleanup", {"type": "background_script"})
    _seed_agent(mgr, "nightly", {"type": "background_agent"})
    for name in ("ui-agent", "cleanup", "nightly"):
        _seed_run(mgr, name, "run-1", "pending", _iso(_ago(600)))

    scanned = []
    real_get_runs = mgr.get_agent_runs

    def get_agent_runs(agent_name, limit=None):
        scanned.append(agent_name)
        return real_get_runs(agent_name, limit)

    mgr.get_agent_runs = get_agent_runs
    pruned = []
    mgr.prune_agent_runs = lambda *args, **kwargs: pruned.append((args, kwargs))
    _install(monkeypatch, mgr)

    totals = _reap()

    assert "ui-agent" not in scanned
    assert set(scanned) == {"cleanup", "nightly"}
    assert pruned == []
    assert totals["orphaned"] == 2
    assert _record(mgr, "ui-agent", "run-1")["state"] == "pending"
    assert _record(mgr, "cleanup", "run-1")["state"] == "failed"
    assert _record(mgr, "nightly", "run-1")["state"] == "failed"


# --- 10. Claim idempotence at the auth layer --------------------------------


def test_concurrent_claim_run_retry_has_a_single_winner(monkeypatch):
    mgr = _mgr()
    _seed_run(
        mgr,
        "wf",
        "run-1",
        "failed",
        _iso(_ago(60)),
        metadata={"attempt": 1, "retry_at": _iso(_ago(1))},
    )

    barrier = threading.Barrier(10)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait()
            results.append(mgr.claim_run_retry("wf", "run-1"))
        except Exception as err:  # noqa: BLE001 - surfaced via assert below
            errors.append(err)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert results.count(True) == 1
    assert results.count(False) == 9
    assert _record(mgr, "wf", "run-1")["metadata"]["retried_run_id"] == "claimed"


# --- 11. Corrupt data -------------------------------------------------------


def test_corrupt_records_do_not_break_the_pass(monkeypatch):
    mgr = _mgr()
    _seed_agent(mgr, "wf", {"type": "background_agent"})
    # Junk timestamp: unparseable, so the age is unknowable and never orphaned.
    _seed_run(mgr, "wf", "run-junk-time", "pending", "not-a-timestamp")
    # Non-dict metadata on a healthy pending run.
    _seed_run(mgr, "wf", "run-junk-meta", "pending", _iso(_ago(60)), metadata=["nope"])
    # Processing with an unparseable heartbeat: ignored rather than orphaned.
    _seed_run(mgr, "wf", "run-junk-heartbeat", "processing", _iso(_ago(7200)))
    mgr.client.put("/runs/wf/run-junk-heartbeat/heartbeat", "definitely-not-a-timestamp")
    _install(monkeypatch, mgr)

    totals = _reap()

    assert totals == {"scanned": 3, "orphaned": 0, "retried": 0, "errors": 0}
    assert _record(mgr, "wf", "run-junk-time")["state"] == "pending"
    assert _record(mgr, "wf", "run-junk-meta")["state"] == "pending"
    assert _record(mgr, "wf", "run-junk-heartbeat")["state"] == "processing"
    for run_id in ("run-junk-time", "run-junk-meta", "run-junk-heartbeat"):
        assert _events(mgr, "wf", run_id) == []


# --- 12. Scan window --------------------------------------------------------


def test_stuck_run_beyond_the_scan_window_is_still_reaped(monkeypatch):
    # get_agent_runs() is newest-first, so a limit-based scan would miss a stuck
    # run once enough newer runs exist. The reaper must look past that window.
    mgr = _mgr()
    _seed_agent(mgr, "wf", {"type": "background_agent"})
    _seed_run(mgr, "wf", "run-stuck", "pending", _iso(_ago(600)))
    for index in range(25):
        _seed_run(mgr, "wf", f"run-done-{index}", "completed", _iso(_ago(5 + index)))
    _install(monkeypatch, mgr)

    totals = _reap()

    assert totals["orphaned"] == 1
    assert _record(mgr, "wf", "run-stuck")["state"] == "failed"
    assert [event["type"] for event in _events(mgr, "wf", "run-stuck")] == ["run_orphaned"]


# --- 13. Retry accounting survives the worker's state writes ----------------


def test_retry_chain_stops_at_max_attempts_across_worker_transitions(monkeypatch):
    # The worker rewrites metadata on processing/completed, so `attempt` must survive
    # those writes or every orphan spawns another attempt forever.
    mgr = _mgr()
    _seed_agent(
        mgr,
        "wf",
        {"type": "background_agent", "retries": {"max_attempts": 2, "backoff_s": 60}},
    )
    _seed_run(mgr, "wf", "run-0", "processing", _iso(_ago(900)), metadata={"prompt": "p"})
    _clock["now"] = _ago(120)
    mgr.record_run_heartbeat("wf", "run-0")
    _clock["now"] = _NOW
    agent_task, _ = _install(monkeypatch, mgr)

    assert _reap()["retried"] == 0

    _clock["now"] = _NOW + timedelta(seconds=61)
    assert _reap()["retried"] == 1
    assert len(agent_task.calls) == 1
    retried_id = "agent-1"
    assert _record(mgr, "wf", retried_id)["metadata"]["attempt"] == 2

    # Worker picks the retry up and rewrites metadata for `processing`.
    mgr.record_agent_run_state("wf", retried_id, "processing", {"prompt": "p", "user_id": "u"})
    preserved = _record(mgr, "wf", retried_id)["metadata"]
    assert preserved["attempt"] == 2 and preserved["prior_run_id"] == "run-0"

    # That attempt now dies too: still stale-heartbeat, but the cap is reached.
    _clock["now"] = _NOW + timedelta(seconds=300)
    mgr.record_run_heartbeat("wf", retried_id)
    _clock["now"] = _NOW + timedelta(seconds=600)
    totals = _reap()

    assert totals["orphaned"] == 1
    assert totals["retried"] == 0
    final = _record(mgr, "wf", retried_id)
    assert final["state"] == "failed"
    assert final["metadata"]["attempt"] == 2
    assert "retry_at" not in final["metadata"]
    assert len(agent_task.calls) == 1  # no third attempt


def test_scheduled_retry_is_abandoned_when_the_cap_drops(monkeypatch):
    mgr = _mgr()
    _seed_agent(mgr, "wf", {"type": "background_agent"})  # default max_attempts = 1
    _seed_run(
        mgr,
        "wf",
        "run-1",
        "failed",
        _iso(_ago(60)),
        metadata={"prompt": "p", "attempt": 1, "retry_at": _iso(_ago(1))},
    )
    agent_task, _ = _install(monkeypatch, mgr)

    totals = _reap()

    assert totals["retried"] == 0
    assert agent_task.calls == []
    metadata = _record(mgr, "wf", "run-1")["metadata"]
    assert "retry_at" not in metadata
    assert metadata["retry_abandoned"] == "attempts_exhausted"


# --- 14. A reaped pending run must not execute when the queue delivers it ----


def test_reaped_run_is_skipped_when_the_worker_picks_it_up(monkeypatch):
    mgr = _mgr()
    _seed_agent(mgr, "wf", {"type": "background_agent"})
    _seed_run(mgr, "wf", "run-late", "failed", _iso(_ago(600)))
    _seed_run(mgr, "wf", "run-done", "completed", _iso(_ago(600)))
    # A genuinely cancelled run still emits its event.
    _seed_run(mgr, "wf", "run-cancelled", "cancelled", _iso(_ago(600)))

    async def scenario():
        return [
            await tasks._abort_if_cancelled(mgr, "wf", "run-late"),
            await tasks._abort_if_cancelled(mgr, "wf", "run-done"),
            await tasks._abort_if_cancelled(mgr, "wf", "run-cancelled"),
        ]

    assert asyncio.run(scenario()) == [True, True, True]
    assert _events(mgr, "wf", "run-late") == []
    assert _events(mgr, "wf", "run-done") == []
    assert [event["type"] for event in _events(mgr, "wf", "run-cancelled")] == ["run_cancelled"]
