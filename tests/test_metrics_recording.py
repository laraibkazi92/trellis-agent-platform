# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""LLM latency/TTFT metric recording, aggregation and provider attribution.

Everything runs against an in-memory fake etcd client (no etcd, no network, no
sleeps). The fake implements the ``get``/``put``/``put_if_not_exists``/``replace``
contract the CAS loop in ``IdentityManager._atomic_update_usage_json`` relies on,
so the real ``IdentityManager`` code paths are exercised end to end.
"""

import asyncio
import json
import threading
from types import SimpleNamespace

import pytest

import core.llm_defaults as llm_defaults
import core.memory as memory
import core.tasks as tasks
from core import host
from core.auth import LATENCY_SAMPLE_CAP, IdentityManager, _latency_summary
from core.llm_defaults import (
    FrameworkDefaults,
    needs_framework_defaults,
    provider_for_config,
    resolve_effective_llm_config,
)

_AGENT = "metric-agent"
_PROVIDER = "google"
_AGENT_KEY = f"/metrics/agents/{_AGENT}"
_PROVIDER_KEY = f"/metrics/providers/{_PROVIDER}"


# --- Fake etcd client / manager harness ---------------------------------------

class _Meta:
    def __init__(self, key):
        self.key = key


class FakeClient:
    """In-memory etcd stand-in with the CAS primitives metrics rely on."""

    def __init__(self):
        self.store = {}
        self.lock_names = []
        self._locks = {}
        self._guard = threading.Lock()

    @staticmethod
    def _as_bytes(value):
        return value.encode("utf-8") if isinstance(value, str) else value

    def get(self, path):
        with self._guard:
            return self.store.get(path), None

    def put(self, path, value):
        with self._guard:
            self.store[path] = self._as_bytes(value)

    def put_if_not_exists(self, path, value):
        with self._guard:
            if path in self.store:
                return False
            self.store[path] = self._as_bytes(value)
            return True

    def replace(self, path, old, new):
        with self._guard:
            current = self.store.get(path)
            if current is None or current != self._as_bytes(old):
                return False
            self.store[path] = self._as_bytes(new)
            return True

    def get_prefix(self, prefix):
        with self._guard:
            keys = sorted(key for key in list(self.store) if key.startswith(prefix))
            return [(self.store[key], _Meta(key.encode("utf-8"))) for key in keys]

    def delete(self, path):
        with self._guard:
            self.store.pop(path, None)

    def delete_prefix(self, prefix):
        with self._guard:
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


def _raw(mgr, path):
    value, _ = mgr.client.get(path)
    assert value is not None, f"expected a stored document at {path}"
    return value.decode("utf-8")


def _doc(mgr, path):
    return json.loads(_raw(mgr, path))


def _record(mgr, ttft_ms, total_ms, ok=True, provider=_PROVIDER, agent=_AGENT):
    mgr.record_agent_latency("user-secret-id", agent, provider, ttft_ms, total_ms, ok)


# --- 1. Aggregation -----------------------------------------------------------

def test_aggregation_counts_errors_and_sample_shape():
    mgr = _mgr()
    _record(mgr, 100, 1000)
    _record(mgr, 200, 2000)
    _record(mgr, None, 3000)
    _record(mgr, None, 4000, ok=False)

    for key in (_AGENT_KEY, _PROVIDER_KEY):
        doc = _doc(mgr, key)
        assert doc["count"] == 4
        assert doc["error_count"] == 1
        assert len(doc["samples"]) == 4
        assert [sample["total_ms"] for sample in doc["samples"]] == [1000.0, 2000.0, 3000.0, 4000.0]
        assert [sample["ttft_ms"] for sample in doc["samples"]] == [100.0, 200.0, None, None]
        for sample in doc["samples"]:
            assert set(sample) == {"ts", "ttft_ms", "total_ms"}
            assert isinstance(sample["ts"], str) and sample["ts"]
        # Metrics are per agent/provider: no user identity is ever persisted.
        assert "user-secret-id" not in _raw(mgr, key)
        assert "user_id" not in doc

    summary = mgr.get_agent_latency(_AGENT)
    assert summary["count"] == 4 and summary["error_count"] == 1
    assert summary["error_rate"] == pytest.approx(0.25)
    # Nearest-rank over [100, 200]: p50 -> index 1, p95 -> index 2.
    assert summary["ttft_p50_ms"] == 100.0
    assert summary["ttft_p95_ms"] == 200.0
    assert summary["total_p50_ms"] == 2000.0
    assert summary["total_p95_ms"] == 4000.0
    assert mgr.get_provider_latency(_PROVIDER) == summary


# --- 2. Concurrency -----------------------------------------------------------

def test_concurrent_recording_does_not_lose_updates():
    mgr = _mgr()
    threads = 20
    per_thread = 5
    barrier = threading.Barrier(threads)
    errors = []

    def worker(worker_id):
        try:
            barrier.wait(timeout=10)
            for i in range(per_thread):
                mgr.record_agent_latency(
                    "user-secret-id", _AGENT, _PROVIDER,
                    10.0 + worker_id, 100.0 + i,
                )
        except BaseException as exc:  # pragma: no cover - surfaced by the assert
            errors.append(exc)

    pool = [threading.Thread(target=worker, args=(n,)) for n in range(threads)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join(timeout=60)
    assert not errors
    assert not any(thread.is_alive() for thread in pool)

    doc = _doc(mgr, _AGENT_KEY)
    assert doc["count"] == threads * per_thread
    assert len(doc["samples"]) == threads * per_thread
    assert _doc(mgr, _PROVIDER_KEY)["count"] == threads * per_thread


# --- 3. Ring cap --------------------------------------------------------------

def test_ring_cap_keeps_newest_samples():
    mgr = _mgr()
    total_calls = LATENCY_SAMPLE_CAP + 5
    for call in range(1, total_calls + 1):
        _record(mgr, None, call)

    doc = _doc(mgr, _AGENT_KEY)
    assert doc["count"] == total_calls
    assert len(doc["samples"]) == LATENCY_SAMPLE_CAP
    assert doc["samples"][0]["total_ms"] == 6.0
    assert doc["samples"][-1]["total_ms"] == float(total_calls)
    assert doc["samples"] == sorted(doc["samples"], key=lambda sample: sample["total_ms"])
    assert mgr.get_agent_latency(_AGENT)["count"] == total_calls


# --- 4. Percentiles / error rate ---------------------------------------------

def test_percentiles_and_error_rate():
    mgr = _mgr()
    # 91 calls, total_ms 10..100; ttft_ms mirrors i*10 except every tenth call,
    # which is non-streaming (ttft None). Hand-computed nearest-rank values:
    #   total   91 values -> p50 rank ceil(0.5*91)=46 -> 55, p95 rank 87 -> 96
    #   ttft    81 values -> p50 rank ceil(0.5*81)=41 -> 55*10, p95 rank 77 -> 95*10
    for i in range(10, 101):
        _record(mgr, None if i % 10 == 0 else i * 10, i)

    summary = mgr.get_agent_latency(_AGENT)
    assert summary["count"] == 91
    assert summary["error_count"] == 0
    assert summary["error_rate"] == 0.0
    assert summary["total_p50_ms"] == 55.0
    assert summary["total_p95_ms"] == 96.0
    assert summary["ttft_p50_ms"] == 550.0
    assert summary["ttft_p95_ms"] == 950.0

    # error_rate is a plain ratio (not pre-rounded) and degenerates to 0.0.
    assert _latency_summary({"count": 3, "error_count": 1})["error_rate"] == pytest.approx(1 / 3)
    assert _latency_summary({"count": 4, "error_count": 1})["error_rate"] == 0.25
    assert _latency_summary({"count": 2, "error_count": 2})["error_rate"] == 1.0
    assert _latency_summary({"count": 0, "error_count": 0})["error_rate"] == 0.0
    assert _latency_summary({"count": 0, "error_count": 3})["error_rate"] == 0.0


def test_absent_and_malformed_documents_read_as_zeroed_summary():
    mgr = _mgr()
    absent = mgr.get_agent_latency("never-recorded")
    assert absent == {
        "count": 0,
        "error_count": 0,
        "error_rate": 0.0,
        "ttft_p50_ms": None,
        "ttft_p95_ms": None,
        "total_p50_ms": None,
        "total_p95_ms": None,
        "guardrail_hits": {},
    }
    assert mgr.get_provider_latency("never-recorded") == absent
    assert _latency_summary(None) == absent

    mgr.client.put(_AGENT_KEY, b"{not json at all")
    assert mgr.get_agent_latency(_AGENT) == absent

    mgr.client.put(_PROVIDER_KEY, json.dumps(["not", "a", "dict"]))
    assert mgr.get_provider_latency(_PROVIDER) == absent


# --- 5. Provider attribution --------------------------------------------------

def _pin_framework_defaults(monkeypatch, defaults):
    monkeypatch.setattr(llm_defaults, "get_framework_defaults", lambda: defaults)


def test_provider_for_config_explicit_provider_wins(monkeypatch):
    _pin_framework_defaults(monkeypatch, FrameworkDefaults(provider="ollama", model="llama3.2"))
    config = {"provider": "google", "model": "gemini-3-flash-preview"}
    assert needs_framework_defaults(config["provider"], config["model"]) is False
    assert provider_for_config(config) == "google"


def test_provider_for_config_infers_from_model(monkeypatch):
    _pin_framework_defaults(monkeypatch, FrameworkDefaults())
    assert provider_for_config({"provider": "", "model": "gpt-4o-mini"}) == "openai"


def test_provider_for_config_falls_back_to_framework_defaults(monkeypatch):
    defaults = FrameworkDefaults(provider="google", model="gemini-3-flash-preview", base_url=None)
    _pin_framework_defaults(monkeypatch, defaults)

    assert needs_framework_defaults("", "") is True
    assert provider_for_config({"provider": "", "model": "", "base_url": ""}) == "google"

    effective = resolve_effective_llm_config("", "", "", defaults)
    assert effective.provider == "google"
    assert effective.model == "gemini-3-flash-preview"
    assert effective.source == "framework"


def test_provider_for_config_unknown_model_is_none_without_raising(monkeypatch):
    _pin_framework_defaults(monkeypatch, FrameworkDefaults())
    assert provider_for_config({"provider": "", "model": "mystery-model-9000"}) is None
    assert provider_for_config({"provider": "", "model": "vendor/mystery-model"}) is None


# --- 6. Failure recording -----------------------------------------------------

def test_failure_recording_increments_count_and_error_count():
    mgr = _mgr()
    _record(mgr, None, 500)
    _record(mgr, None, 750, ok=False)

    doc = _doc(mgr, _AGENT_KEY)
    assert doc["count"] == 2
    assert doc["error_count"] == 1
    assert len(doc["samples"]) == 2
    assert _doc(mgr, _PROVIDER_KEY)["error_count"] == 1


def test_unknown_provider_writes_only_the_agent_document():
    mgr = _mgr()
    _record(mgr, 50, 500, provider=None)

    assert _doc(mgr, _AGENT_KEY)["count"] == 1
    assert not [key for key in mgr.client.store if key.startswith("/metrics/providers/")]


# --- 7. Host helper isolation -------------------------------------------------

class _RecordingManager:
    def __init__(self, raises=False):
        self.calls = []
        self.raises = raises

    def record_agent_latency(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.raises:
            raise RuntimeError("etcd is down")


def test_host_record_latency_forwards_arguments(monkeypatch):
    fake = _RecordingManager()
    monkeypatch.setattr(host, "identity_mgr", fake)

    asyncio.run(host._record_latency("google", "agent-x", "user-1", 120.5, 900.0, True))

    assert fake.calls == [(("user-1", "agent-x", "google", 120.5, 900.0, True), {})]


def test_host_record_latency_swallows_manager_failures(monkeypatch, caplog):
    monkeypatch.setattr(host, "identity_mgr", _RecordingManager(raises=True))

    asyncio.run(host._record_latency("google", "agent-x", "user-1", None, 900.0, False))

    assert "Failed to record LLM latency for agent-x" in caplog.text


# --- 8. Background run --------------------------------------------------------

def test_background_run_records_latency(monkeypatch):
    agent_name = "wf-metric"
    run_id = "run-1"
    mgr = _mgr()
    mgr.client.put(
        f"/registry/agents/{agent_name}/config",
        json.dumps({"name": agent_name, "type": "background_agent",
                    "provider": "google", "model": "gemini-3-flash-preview"}),
    )

    class FakeAgent:
        async def run(self, prompt):
            return SimpleNamespace(
                output="done",
                usage=SimpleNamespace(input_tokens=1, output_tokens=2),
            )

    async def fake_build_agent(name):
        assert name == agent_name
        return FakeAgent()

    class FakeMemoryManager:
        def active_for(self, config):
            return False

    minted = []
    monkeypatch.setattr(tasks, "build_agent", fake_build_agent)
    monkeypatch.setattr(tasks, "get_identity_manager", lambda: mgr)
    monkeypatch.setattr(tasks, "mint_for_run", lambda *a, **k: minted.append((a, k)) or "run-token")
    monkeypatch.setattr(tasks, "provider_for_config", lambda config: "google")
    monkeypatch.setattr(memory, "get_memory_manager", lambda: FakeMemoryManager())
    clock = iter([100.0, 100.25])
    monkeypatch.setattr(tasks, "time", SimpleNamespace(monotonic=lambda: next(clock)))

    context = SimpleNamespace(message=SimpleNamespace(task_id=run_id))
    result = asyncio.run(
        tasks.run_background_agent.original_func(
            agent_name, "do the thing", "svc_agent_wf-metric", context,
        )
    )

    assert result == "done"
    assert minted and minted[0][1]["run_id"] == run_id

    run = json.loads(_raw(mgr, f"/runs/{agent_name}/{run_id}"))
    assert run["state"] == "completed"
    latency_ms = run["metadata"]["latency_ms"]
    assert isinstance(latency_ms, int) and latency_ms >= 0
    assert latency_ms == 250

    doc = _doc(mgr, f"/metrics/agents/{agent_name}")
    assert doc["count"] == 1
    assert doc["error_count"] == 0
    assert len(doc["samples"]) == 1
    sample = doc["samples"][0]
    assert sample["ttft_ms"] is None
    assert isinstance(sample["total_ms"], float)
    assert sample["total_ms"] == pytest.approx(250.0)
    assert _doc(mgr, _PROVIDER_KEY)["count"] == 1


# --- 9. No double write -------------------------------------------------------

def test_single_call_writes_one_sample_per_document():
    mgr = _mgr()
    _record(mgr, 33.0, 321.0)

    agent_doc = _doc(mgr, _AGENT_KEY)
    provider_doc = _doc(mgr, _PROVIDER_KEY)
    assert (agent_doc["count"], len(agent_doc["samples"])) == (1, 1)
    assert (provider_doc["count"], len(provider_doc["samples"])) == (1, 1)
    assert agent_doc["samples"] == provider_doc["samples"]


# --- 10. CAS exhaustion is reported, never silently overwritten -------------


def test_cas_exhaustion_raises_and_leaves_the_document_untouched():
    # The old fallback did a blind `put` from a stale read, overwriting concurrent
    # samples. Exhaustion must surface as EtcdContentionError instead.
    from core.auth import EtcdContentionError

    mgr = _mgr()
    _record(mgr, 100, 1000)
    before = _raw(mgr, f"/metrics/agents/{_AGENT}")

    mgr.client.replace = lambda path, old, new: False
    with pytest.raises(EtcdContentionError):
        _record(mgr, 200, 2000)

    assert _raw(mgr, f"/metrics/agents/{_AGENT}") == before


def test_provider_for_config_rejects_an_unknown_provider_id():
    from core.llm_defaults import provider_for_config

    assert provider_for_config({"provider": "not-a-provider", "model": "whatever"}) is None


def test_provider_write_failure_does_not_duplicate_the_agent_sample(monkeypatch, caplog):
    # record_agent_latency is deliberately not @retry_etcd-wrapped: a retry after the
    # agent write landed would record the same turn twice.
    mgr = _mgr()
    original = mgr._atomic_update_usage_json
    calls = {"n": 0}

    def flaky(key, update_fn):
        calls["n"] += 1
        if "/metrics/providers/" in key:
            raise RuntimeError("contended")
        return original(key, update_fn)

    monkeypatch.setattr(mgr, "_atomic_update_usage_json", flaky)
    mgr.record_agent_latency("u", _AGENT, _PROVIDER, 10.0, 500.0, True)

    assert calls["n"] == 2
    assert _doc(mgr, f"/metrics/agents/{_AGENT}")["count"] == 1
    assert f"/metrics/providers/{_PROVIDER}" not in mgr.client.store
    assert "Failed to record provider latency" in caplog.text


def test_cas_exhaustion_raises_without_retrying_the_whole_call():
    # No @retry_etcd on record_agent_latency: an exhausted agent write raises once
    # and must not append a second sample.
    from core.auth import EtcdContentionError

    mgr = _mgr()
    mgr.client.replace = lambda path, old, new: False
    mgr.client.put_if_not_exists = lambda path, value: False

    with pytest.raises(EtcdContentionError):
        _record(mgr, 100, 1000)
    assert f"/metrics/agents/{_AGENT}" not in mgr.client.store


async def _return(value):
    return value


def test_background_failure_records_error_latency_without_run_metadata(monkeypatch):
    agent_name = "wf-fail"
    run_id = "run-fail"
    mgr = _mgr()
    mgr.client.put(
        f"/registry/agents/{agent_name}/config",
        json.dumps({"name": agent_name, "type": "background_agent",
                    "provider": "google", "model": "gemini-3-flash-preview"}),
    )

    class FailingAgent:
        async def run(self, prompt):
            raise RuntimeError("model exploded")

    class FakeMemoryManager:
        def active_for(self, config):
            return False

    monkeypatch.setattr(tasks, "build_agent", lambda name: _return(FailingAgent()))
    monkeypatch.setattr(tasks, "get_identity_manager", lambda: mgr)
    monkeypatch.setattr(tasks, "mint_for_run", lambda *a, **k: "run-token")
    monkeypatch.setattr(tasks, "provider_for_config", lambda config: "google")
    monkeypatch.setattr(memory, "get_memory_manager", lambda: FakeMemoryManager())
    clock = iter([200.0, 200.5])
    monkeypatch.setattr(tasks, "time", SimpleNamespace(monotonic=lambda: next(clock)))

    context = SimpleNamespace(message=SimpleNamespace(task_id=run_id))
    with pytest.raises(RuntimeError):
        asyncio.run(
            tasks.run_background_agent.original_func(
                agent_name, "boom", "svc_agent_wf-fail", context,
            )
        )

    run = json.loads(_raw(mgr, f"/runs/{agent_name}/{run_id}"))
    assert run["state"] == "failed"
    assert "latency_ms" not in run["metadata"]
    doc = _doc(mgr, f"/metrics/agents/{agent_name}")
    assert (doc["count"], doc["error_count"]) == (1, 1)
    assert _doc(mgr, f"/metrics/providers/google")["error_count"] == 1
