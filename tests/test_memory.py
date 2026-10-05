# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for core.memory (Hindsight-backed agent memory).

All Hindsight interaction is faked by monkeypatching ``MemoryManager._get_client``,
so nothing here touches etcd or the network. Every MemoryManager operation is
fail-open by design; these tests pin that contract (flag gating + TTL cache,
recall formatting across both response shapes, retain payload construction).
"""

import asyncio
from types import SimpleNamespace

import core.memory as memory_mod
from core.memory import MEMORY_FLAG_KEY, MemoryManager, _FLAG_TTL_SECONDS


class _FakeIdentityMgr:
    """Sync identity manager fake: only get_config is needed for flag gating."""

    def __init__(self, config_value=True, error=None):
        self.config_value = config_value
        self.error = error
        self.get_config_calls = []

    def get_config(self, key, default=None):
        self.get_config_calls.append((key, default))
        if self.error is not None:
            raise self.error
        return self.config_value


class _FakeHindsight:
    """Fake Hindsight client exposing the async arecall/aretain surface."""

    def __init__(self, recall_response=None, recall_error=None, retain_error=None, reject_top_k=False):
        self.recall_response = recall_response
        self.recall_error = recall_error
        self.retain_error = retain_error
        self.reject_top_k = reject_top_k
        self.recall_calls = []
        self.retain_calls = []

    async def arecall(self, **kwargs):
        self.recall_calls.append(kwargs)
        if self.reject_top_k and "top_k" in kwargs:
            raise TypeError("arecall() got an unexpected keyword argument 'top_k'")
        if self.recall_error is not None:
            raise self.recall_error
        return self.recall_response

    async def aretain(self, **kwargs):
        self.retain_calls.append(kwargs)
        if self.retain_error is not None:
            raise self.retain_error


def _patch_client(monkeypatch, client):
    monkeypatch.setattr(MemoryManager, "_get_client", lambda self: client)


# --- Feature gating: is_globally_enabled --------------------------------------

def test_flag_false_when_config_returns_false():
    ident = _FakeIdentityMgr(config_value=False)
    mgr = MemoryManager(ident)
    assert mgr.is_globally_enabled() is False


def test_flag_false_when_config_returns_none():
    ident = _FakeIdentityMgr(config_value=None)
    mgr = MemoryManager(ident)
    assert mgr.is_globally_enabled() is False


def test_flag_true_when_config_set():
    ident = _FakeIdentityMgr(config_value=True)
    mgr = MemoryManager(ident)
    assert mgr.is_globally_enabled() is True
    assert ident.get_config_calls == [(MEMORY_FLAG_KEY, False)]


def test_flag_cached_within_ttl(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(memory_mod.time, "monotonic", lambda: clock["t"])
    ident = _FakeIdentityMgr(config_value=True)
    mgr = MemoryManager(ident)

    assert mgr.is_globally_enabled() is True
    clock["t"] += _FLAG_TTL_SECONDS - 1.0  # still inside the TTL window
    assert mgr.is_globally_enabled() is True
    assert len(ident.get_config_calls) == 1  # second call served from cache


def test_flag_cache_expires_after_ttl(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(memory_mod.time, "monotonic", lambda: clock["t"])
    ident = _FakeIdentityMgr(config_value=True)
    mgr = MemoryManager(ident)

    assert mgr.is_globally_enabled() is True
    clock["t"] += _FLAG_TTL_SECONDS + 1.0
    ident.config_value = False  # admin toggled the flag off
    assert mgr.is_globally_enabled() is False  # re-read after TTL expiry
    assert len(ident.get_config_calls) == 2


def test_flag_fails_closed_on_etcd_read_error():
    ident = _FakeIdentityMgr(error=RuntimeError("etcd unavailable"))
    mgr = MemoryManager(ident)
    assert mgr.is_globally_enabled() is False
    # The failed read is cached too: a second rapid call stays False without re-raising.
    assert mgr.is_globally_enabled() is False
    assert len(ident.get_config_calls) == 1


# --- Feature gating: active_for -----------------------------------------------

def test_active_for_requires_global_flag_and_dict_opt_in():
    ident = _FakeIdentityMgr(config_value=False)
    mgr = MemoryManager(ident)
    assert mgr.active_for({"agent_memory": True}) is False


def test_active_for_true_for_opted_in_dict():
    mgr = MemoryManager(_FakeIdentityMgr(config_value=True))
    assert mgr.active_for({"agent_memory": True}) is True


def test_active_for_false_for_dict_without_opt_in():
    mgr = MemoryManager(_FakeIdentityMgr(config_value=True))
    assert mgr.active_for({}) is False
    assert mgr.active_for({"agent_memory": False}) is False


def test_active_for_reads_agent_memory_attribute_from_objects():
    mgr = MemoryManager(_FakeIdentityMgr(config_value=True))
    assert mgr.active_for(SimpleNamespace(agent_memory=True)) is True
    assert mgr.active_for(SimpleNamespace(agent_memory=False)) is False
    assert mgr.active_for(SimpleNamespace()) is False


# --- Recall -------------------------------------------------------------------

def test_recall_blank_query_returns_empty_without_client(monkeypatch):
    def _no_client(self):
        raise AssertionError("client must not be constructed for a blank query")

    monkeypatch.setattr(MemoryManager, "_get_client", _no_client)
    mgr = MemoryManager(_FakeIdentityMgr())
    assert asyncio.run(mgr.recall("bank", "")) == ""
    assert asyncio.run(mgr.recall("bank", "   ")) == ""


def test_recall_formats_object_response_with_results_attributes(monkeypatch):
    client = _FakeHindsight(
        recall_response=SimpleNamespace(
            results=[SimpleNamespace(text="alpha"), SimpleNamespace(text="beta")]
        )
    )
    _patch_client(monkeypatch, client)
    mgr = MemoryManager(_FakeIdentityMgr())

    out = asyncio.run(mgr.recall("bank-a", "how do I rotate certs?"))

    assert out == "## Relevant context from past interactions\n- alpha\n- beta"
    assert client.recall_calls == [
        {"bank_id": "bank-a", "query": "how do I rotate certs?", "top_k": 5}
    ]


def test_recall_formats_bare_list_of_dicts_response(monkeypatch):
    client = _FakeHindsight(recall_response=[{"text": "one"}, {"text": "two"}])
    _patch_client(monkeypatch, client)
    mgr = MemoryManager(_FakeIdentityMgr())

    out = asyncio.run(mgr.recall("bank-a", "query"))

    assert out == "## Relevant context from past interactions\n- one\n- two"


def test_recall_truncates_to_limit(monkeypatch):
    client = _FakeHindsight(
        recall_response=[
            {"text": "one"}, {"text": "two"}, {"text": "three"},
        ]
    )
    _patch_client(monkeypatch, client)
    mgr = MemoryManager(_FakeIdentityMgr())

    out = asyncio.run(mgr.recall("bank-a", "query", limit=2))

    assert out == "## Relevant context from past interactions\n- one\n- two"
    assert client.recall_calls[0]["top_k"] == 2


def test_recall_falls_back_when_top_k_kwarg_rejected(monkeypatch):
    client = _FakeHindsight(
        recall_response=[{"text": "fallback"}], reject_top_k=True
    )
    _patch_client(monkeypatch, client)
    mgr = MemoryManager(_FakeIdentityMgr())

    out = asyncio.run(mgr.recall("bank-a", "query"))

    assert out == "## Relevant context from past interactions\n- fallback"
    # The top_k signature is tried first, then the reduced one.
    assert client.recall_calls == [
        {"bank_id": "bank-a", "query": "query", "top_k": 5},
        {"bank_id": "bank-a", "query": "query"},
    ]


def test_recall_fails_open_on_client_error(monkeypatch):
    client = _FakeHindsight(recall_error=RuntimeError("hindsight down"))
    _patch_client(monkeypatch, client)
    mgr = MemoryManager(_FakeIdentityMgr())
    assert asyncio.run(mgr.recall("bank-a", "query")) == ""


def test_recall_empty_or_textless_results_return_empty(monkeypatch):
    _patch_client(monkeypatch, _FakeHindsight(recall_response=[]))
    mgr = MemoryManager(_FakeIdentityMgr())
    assert asyncio.run(mgr.recall("bank-a", "query")) == ""

    # Results present but none carry usable text.
    _patch_client(monkeypatch, _FakeHindsight(recall_response=[{"other": "x"}, {"text": ""}, SimpleNamespace()]))
    assert asyncio.run(mgr.recall("bank-a", "query")) == ""


# --- Retain -------------------------------------------------------------------

def test_retain_builds_content_and_calls_aretain(monkeypatch):
    client = _FakeHindsight()
    _patch_client(monkeypatch, client)
    mgr = MemoryManager(_FakeIdentityMgr())

    asyncio.run(mgr.retain("bank-a", "what is the VPN endpoint?", "It is vpn.example.com"))

    assert client.retain_calls == [
        {
            "bank_id": "bank-a",
            "content": "User asked: what is the VPN endpoint?\nAgent responded: It is vpn.example.com",
            "context": "conversation",
        }
    ]


def test_retain_skips_when_either_side_empty(monkeypatch):
    client = _FakeHindsight()
    _patch_client(monkeypatch, client)
    mgr = MemoryManager(_FakeIdentityMgr())

    asyncio.run(mgr.retain("bank-a", "", "response"))
    asyncio.run(mgr.retain("bank-a", "question", ""))
    asyncio.run(mgr.retain("bank-a", None, None))

    assert client.retain_calls == []


def test_retain_never_raises_on_client_error(monkeypatch):
    client = _FakeHindsight(retain_error=RuntimeError("hindsight down"))
    _patch_client(monkeypatch, client)
    mgr = MemoryManager(_FakeIdentityMgr())

    assert asyncio.run(mgr.retain("bank-a", "q", "a")) is None
    assert len(client.retain_calls) == 1


# --- Singleton ----------------------------------------------------------------

def test_get_memory_manager_is_a_singleton_with_injected_identity_mgr(monkeypatch):
    from core import agent_factory

    sentinel = object()
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: sentinel)
    monkeypatch.setattr(memory_mod, "_memory_mgr", None)

    first = memory_mod.get_memory_manager()
    second = memory_mod.get_memory_manager()

    assert first is second
    assert isinstance(first, MemoryManager)
    assert first._identity_mgr is sentinel
