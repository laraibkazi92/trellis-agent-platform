# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for Phase 2 (Gateway MCP & Host API Enforcement) — see
__spec_docs/internal_external_agents_spec.md.

Covers:
  - core.agent_search.search_agents excluding external: False agents from candidates
    (both the embedding-ranked path and the keyword fallback path).
  - core.gateway._get_visible_agents omitting external: False agents.
  - core.gateway.search_agents (the MCP tool) calling _search_agents_ranked with the
    caller's real limit and decorating -- never re-excluding -- results (Phase E, E4,
    see __spec_docs/rules_engine_hardening_plan.md).
  - core.gateway.use_agent returning the exact access-denied string for external: False.
  - core.host chat_completions raising 403 with the exact detail message for
    external: False, and proceeding normally for external: True.
"""
import asyncio
import logging
import threading
from types import SimpleNamespace

import pytest

from core import agent_search
from core import gateway
from core import host
from core.auth import user_id_var


# --- core.agent_search.search_agents ----------------------------------------

class FakeIdentityManagerSearch:
    def __init__(self, agent_configs):
        self._agent_configs = agent_configs

    def get_all_agent_configs(self):
        return dict(self._agent_configs)

    def get_all_agent_embeddings(self):
        return {}

    def get_disabled_standard_agents(self):
        return []

    def get_all_health_statuses(self, kind):
        return {}


def test_search_agents_excludes_external_false_keyword_fallback(monkeypatch):
    fake_identity = FakeIdentityManagerSearch({
        "general-agent": {"name": "general-agent", "description": "handles general requests", "type": "user_agent"},
        "data-parser": {
            "name": "data-parser",
            "description": "parses raw input",
            "type": "user_agent",
            "external": False,
        },
    })
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: None)

    results = asyncio.run(agent_search.search_agents("general requests", limit=0))

    names = [r["name"] for r in results]
    assert "general-agent" in names
    assert "data-parser" not in names


def test_search_agents_excludes_external_false_embedding_path(monkeypatch):
    fake_identity = FakeIdentityManagerSearch({
        "general-agent": {"name": "general-agent", "description": "handles general requests", "type": "user_agent"},
        "data-parser": {
            "name": "data-parser",
            "description": "parses raw input",
            "type": "user_agent",
            "external": False,
        },
    })
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: [1.0, 0.0])
    monkeypatch.setattr(agent_search, "cosine", lambda a, b: 1.0 if b else 0.0)

    results = asyncio.run(agent_search.search_agents("general requests", limit=0))

    names = [r["name"] for r in results]
    assert "general-agent" in names
    assert "data-parser" not in names


def test_search_agents_includes_external_true_normally(monkeypatch):
    fake_identity = FakeIdentityManagerSearch({
        "general-agent": {"name": "general-agent", "description": "handles general requests", "type": "user_agent", "external": True},
    })
    monkeypatch.setattr(agent_search, "identity_mgr", fake_identity)
    monkeypatch.setattr(agent_search, "embed_text", lambda *a, **k: None)

    results = asyncio.run(agent_search.search_agents("general requests", limit=0))

    assert [r["name"] for r in results] == ["general-agent"]


# --- core.gateway._get_visible_agents ----------------------------------------
#
# Phase D of the Trellis Rules Engine hardening plan
# (__spec_docs/rules_engine_hardening_plan.md) changed _get_visible_agents to stop
# depending on Host's /health JSON body for per-agent status/exclusion -- it now
# computes that in-process from etcd (via identity_mgr) and only uses Host's /health
# as a status-code-only liveness ping. FakeHTTPResponse.json() intentionally raises
# when no payload is supplied, so a test fails loudly if the implementation ever
# starts reading the response body again.

class FakeHTTPResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise AssertionError(
                "_get_visible_agents should not parse the /health response body "
                "under Phase D -- only its status code is a liveness signal"
            )
        return self._payload


class FakeHTTPClient:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload
        self._status_code = status_code

    async def get(self, url, timeout=None):
        return FakeHTTPResponse(self._status_code, self._payload)


def _patch_gateway_etcd(monkeypatch, disabled=(), agent_configs=None, agent_health=None, tool_health=None):
    monkeypatch.setattr(gateway.identity_mgr, "get_disabled_standard_agents", lambda: list(disabled))
    monkeypatch.setattr(gateway.identity_mgr, "get_all_agent_configs", lambda: dict(agent_configs or {}))

    def fake_get_all_health_statuses(entity_type):
        if entity_type == "agent":
            return dict(agent_health or {})
        return dict(tool_health or {})

    monkeypatch.setattr(gateway.identity_mgr, "get_all_health_statuses", fake_get_all_health_statuses)


def test_get_visible_agents_omits_external_false(monkeypatch):
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
        {"name": "data-parser", "description": "parses input", "type": "user_agent", "is_configured": True, "external": False},
    ]

    async def fake_discover_agents(user_id=None, agent_configs=None, agent_health=None):
        return discovered

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)
    _patch_gateway_etcd(monkeypatch)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents())

    names = [a["name"] for a in visible]
    assert "general-agent" in names
    assert "data-parser" not in names


def test_get_visible_agents_fails_on_host_liveness_error_status(monkeypatch):
    """A non-200 Host /health status code is still a hard, immediate failure."""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None, agent_configs=None, agent_health=None):
        return discovered

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)
    _patch_gateway_etcd(monkeypatch)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient(status_code=503)
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents())

    assert visible == [{"name": "Error", "description": "Host API unreachable (HTTP 503)"}]


def test_get_visible_agents_fails_on_host_liveness_exception(monkeypatch, caplog):
    """Host unreachable at the transport level also fails clearly, as before --
    with a stable generic description (raw detail only in the logs)."""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None, agent_configs=None, agent_health=None):
        return discovered

    class RaisingClient:
        async def get(self, url, timeout=None):
            raise ConnectionError("connection refused")

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)
    _patch_gateway_etcd(monkeypatch)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=RaisingClient()
    )), raising=False)
    user_id_var.set("user-1")

    with caplog.at_level(logging.ERROR, logger="core.gateway"):
        visible = asyncio.run(gateway._get_visible_agents())

    assert visible == [{"name": "Error", "description": "Host API temporarily unreachable. Please try again later."}]
    assert "connection refused" not in visible[0]["description"]
    assert "connection refused" in caplog.text


def test_get_visible_agents_annotates_offline_status_from_etcd(monkeypatch):
    """Offline status is computed in-process from etcd health records, not Host's body."""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None, agent_configs=None, agent_health=None):
        return discovered

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)
    _patch_gateway_etcd(
        monkeypatch,
        agent_configs={"general-agent": {"allowed_tools": []}},
        agent_health={"general-agent": {"status": "Offline"}},
    )
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents())

    assert len(visible) == 1
    assert "[STATUS: OFFLINE" in visible[0]["description"]
    assert visible[0]["configured"] is False


def test_get_visible_agents_annotates_degraded_status_from_offline_tool(monkeypatch):
    """Degraded (an agent's own health is fine but an allowed tool is offline) is
    still derived by cross-referencing tool health, mirroring host.py's /health
    handler, just computed here instead of read from its JSON response."""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None, agent_configs=None, agent_health=None):
        return discovered

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)
    _patch_gateway_etcd(
        monkeypatch,
        agent_configs={"general-agent": {"allowed_tools": ["netctl"]}},
        tool_health={"netctl": {"status": "Offline"}},
    )
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents())

    assert len(visible) == 1
    assert "[STATUS: DEGRADED" in visible[0]["description"]
    assert "netctl" in visible[0]["description"]


def test_get_visible_agents_fails_gracefully_on_etcd_error_after_liveness_check(monkeypatch, caplog):
    """A transient etcd failure while computing per-agent decoration must degrade to the
    same friendly error shape as every other failure path here, not propagate as a raw
    exception. (The decoration bulk-fetch now runs before the Host liveness ping --
    see _get_visible_agents' docstring on collapsing the double bulk-fetch -- so this
    failure surfaces before the liveness check is ever reached rather than after it;
    the guarantee this test pins down, that the failure degrades gracefully instead of
    crashing, is unchanged.)"""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None, agent_configs=None, agent_health=None):
        return discovered

    def _raise_timeout():
        raise TimeoutError("etcd transient timeout fetching agent configs")

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)
    monkeypatch.setattr(gateway.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(gateway.identity_mgr, "get_all_agent_configs", _raise_timeout)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    with caplog.at_level(logging.ERROR, logger="core.gateway"):
        visible = asyncio.run(gateway._get_visible_agents())

    assert len(visible) == 1
    assert visible[0]["name"] == "Error"
    assert visible[0]["description"] == "Failed to compute agent status. Please try again later."
    assert "etcd transient timeout fetching agent configs" not in visible[0]["description"]
    assert "etcd transient timeout fetching agent configs" in caplog.text


def test_get_visible_agents_defaults_to_online_when_decoration_data_missing(monkeypatch):
    """Decoration-only, no drop: an agent absent from the etcd health/config maps
    (e.g. momentarily inconsistent bulk reads) is still returned, just undecorated."""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None, agent_configs=None, agent_health=None):
        return discovered

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)
    _patch_gateway_etcd(monkeypatch)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents())

    assert visible == [{"name": "general-agent", "description": "does stuff", "configured": True}]


# --- core.gateway.search_agents (the MCP tool) ---------------------------------
#
# Phase E of the Trellis Rules Engine hardening plan
# (__spec_docs/rules_engine_hardening_plan.md, E4) reworked this tool to call
# _search_agents_ranked directly with the caller's real `limit` (no more
# limit=0-then-intersect-then-truncate), and to use _get_visible_agents() purely to
# annotate results -- never to drop one search_agents already decided to return.

class FakeContext:
    def __init__(self):
        self.progress_messages = []

    async def report_progress(self, current=None, total=None, message=None):
        self.progress_messages.append(message)


def test_gateway_search_agents_passes_callers_real_limit(monkeypatch):
    """The old limit=0-then-truncate dance is gone -- _search_agents_ranked is called
    with the caller's own `limit` directly."""
    captured = {}

    async def fake_ranked(query, limit=None, include_disabled=False):
        captured["limit"] = limit
        return [{"name": "general-agent", "description": "handles stuff", "status": "Online"}]

    async def fake_visible(names=None):
        return [{"name": "general-agent", "description": "handles stuff", "configured": True}]

    monkeypatch.setattr(gateway, "_search_agents_ranked", fake_ranked)
    monkeypatch.setattr(gateway, "_get_visible_agents", fake_visible)

    ctx = FakeContext()
    results = asyncio.run(gateway.search_agents(ctx, "find something", limit=3))

    assert captured["limit"] == 3
    assert results == [{"name": "general-agent", "description": "handles stuff", "configured": True}]


def test_gateway_search_agents_decorates_never_excludes(monkeypatch):
    """A result _search_agents_ranked returns (including a rules-engine lock, or the
    "unavailable match" note from E1/E3) is never dropped just because it's absent from
    _get_visible_agents()'s decoration source -- it falls back to its own name/
    description/configured=True instead."""

    async def fake_ranked(query, limit=None, include_disabled=False):
        return [
            {"name": "decorated-agent", "description": "raw description", "status": "Online"},
            {"name": "undecorated-agent", "description": "own description", "status": "Online"},
        ]

    async def fake_visible(names=None):
        return [{"name": "decorated-agent", "description": "richly annotated description", "configured": False}]

    monkeypatch.setattr(gateway, "_search_agents_ranked", fake_ranked)
    monkeypatch.setattr(gateway, "_get_visible_agents", fake_visible)

    ctx = FakeContext()
    results = asyncio.run(gateway.search_agents(ctx, "find something", limit=5))

    assert results == [
        {"name": "decorated-agent", "description": "richly annotated description", "configured": False},
        {"name": "undecorated-agent", "description": "own description", "configured": True},
    ]


def test_gateway_search_agents_preserves_unavailable_match_note(monkeypatch):
    """The "unavailable match" note item from search_agents() (Phase E, E1/E3) carries
    unavailable_match=True specifically so this decoration step doesn't clobber its
    crafted, self-contained description -- the matched agent's own name still resolves
    in _get_visible_agents()'s catalog (it isn't disabled/internal/background), so
    without this guard the note's wording would be silently overwritten with the
    agent's ordinary catalog description."""

    async def fake_ranked(query, limit=None, include_disabled=False):
        return [
            {
                "name": "troubleshooting-agent",
                "description": "The routing policy identified 'troubleshooting-agent' as the best "
                                "match for this query, but it is currently not configured. Showing "
                                "next-best alternatives below.",
                "status": "Unconfigured",
                "unavailable_match": True,
            },
            {"name": "ticket-summary-agent", "description": "raw description", "status": "Online"},
        ]

    async def fake_visible(names=None):
        return [
            {
                "name": "troubleshooting-agent",
                "description": "Specialized troubleshooting agent. [NOT CONFIGURED — configure at /agents/troubleshooting-agent/configure]",
                "configured": False,
            },
            {"name": "ticket-summary-agent", "description": "richly annotated description", "configured": True},
        ]

    monkeypatch.setattr(gateway, "_search_agents_ranked", fake_ranked)
    monkeypatch.setattr(gateway, "_get_visible_agents", fake_visible)

    ctx = FakeContext()
    results = asyncio.run(gateway.search_agents(ctx, "find something", limit=5))

    assert results[0] == {
        "name": "troubleshooting-agent",
        "description": "The routing policy identified 'troubleshooting-agent' as the best "
                        "match for this query, but it is currently not configured. Showing "
                        "next-best alternatives below.",
        "configured": False,
    }
    assert results[1] == {
        "name": "ticket-summary-agent",
        "description": "richly annotated description",
        "configured": True,
    }


def test_gateway_search_agents_unavailable_match_offline_agent_reports_configured_false(monkeypatch):
    """An agent that is matched but offline must report configured=False on its note item
    in Gateway MCP even if its credentials are configured, so callers never invoke an offline agent."""
    async def fake_ranked(query, limit=None, include_disabled=False):
        return [
            {
                "name": "troubleshooting-agent",
                "description": "The routing policy identified 'troubleshooting-agent' as the best "
                                "match for this query, but it is currently offline. Showing "
                                "next-best alternatives below.",
                "status": "Offline",
                "unavailable_match": True,
            },
            {"name": "ticket-summary-agent", "description": "raw description", "status": "Online"},
        ]

    async def fake_visible(names=None):
        return [
            {
                "name": "troubleshooting-agent",
                "description": "Specialized troubleshooting agent.",
                "configured": True,  # Credentials set, but agent is offline
            },
            {"name": "ticket-summary-agent", "description": "richly annotated description", "configured": True},
        ]

    monkeypatch.setattr(gateway, "_search_agents_ranked", fake_ranked)
    monkeypatch.setattr(gateway, "_get_visible_agents", fake_visible)

    ctx = FakeContext()
    results = asyncio.run(gateway.search_agents(ctx, "find something", limit=5))

    assert results[0]["configured"] is False
    assert results[0]["name"] == "troubleshooting-agent"
    assert "currently offline" in results[0]["description"]
    assert results[1]["configured"] is True


def test_gateway_search_agents_ordinary_offline_candidate_reports_configured_false(monkeypatch):
    """An ordinary candidate that is offline must report configured=False in Gateway search_agents."""
    async def fake_ranked(query, limit=None, include_disabled=False):
        return [
            {"name": "offline-agent", "description": "raw description", "status": "Offline"},
            {"name": "online-agent", "description": "raw description", "status": "Online"},
        ]

    async def fake_visible(names=None):
        return [
            {"name": "offline-agent", "description": "Offline agent [STATUS: OFFLINE]", "configured": False},
            {"name": "online-agent", "description": "Online agent", "configured": True},
        ]

    monkeypatch.setattr(gateway, "_search_agents_ranked", fake_ranked)
    monkeypatch.setattr(gateway, "_get_visible_agents", fake_visible)

    ctx = FakeContext()
    results = asyncio.run(gateway.search_agents(ctx, "find something", limit=5))

    assert results[0]["name"] == "offline-agent"
    assert results[0]["configured"] is False
    assert results[1]["name"] == "online-agent"
    assert results[1]["configured"] is True


def test_gateway_search_agents_offline_fallback_miss_reports_configured_false(monkeypatch):
    """If an offline agent misses visible_by_name decoration lookup, the fallback still reports configured=False."""
    async def fake_ranked(query, limit=None, include_disabled=False):
        return [
            {"name": "unregistered-offline", "description": "fallback desc", "status": "Offline"},
        ]

    async def fake_visible(names=None):
        return []

    monkeypatch.setattr(gateway, "_search_agents_ranked", fake_ranked)
    monkeypatch.setattr(gateway, "_get_visible_agents", fake_visible)

    ctx = FakeContext()
    results = asyncio.run(gateway.search_agents(ctx, "find something", limit=5))

    assert results[0]["name"] == "unregistered-offline"
    assert results[0]["configured"] is False


def test_gateway_search_agents_returns_empty_when_nothing_ranked(monkeypatch):
    async def fake_ranked(query, limit=None, include_disabled=False):
        return []

    async def _fail_visible(names=None):
        raise AssertionError("_get_visible_agents should not be called when nothing was ranked")

    monkeypatch.setattr(gateway, "_search_agents_ranked", fake_ranked)
    monkeypatch.setattr(gateway, "_get_visible_agents", _fail_visible)

    ctx = FakeContext()
    results = asyncio.run(gateway.search_agents(ctx, "find something", limit=5))

    assert results == []


def test_gateway_search_agents_surfaces_host_error_sentinel(monkeypatch):
    """If _get_visible_agents() comes back as the single "Error" sentinel (Host
    unreachable, or an etcd failure computing decoration), that's surfaced directly
    rather than silently decorating with fallback values as if nothing were wrong."""

    async def fake_ranked(query, limit=None, include_disabled=False):
        return [{"name": "general-agent", "description": "handles stuff", "status": "Online"}]

    async def fake_visible(names=None):
        return [{"name": "Error", "description": "Host API unreachable (HTTP 503)"}]

    monkeypatch.setattr(gateway, "_search_agents_ranked", fake_ranked)
    monkeypatch.setattr(gateway, "_get_visible_agents", fake_visible)

    ctx = FakeContext()
    results = asyncio.run(gateway.search_agents(ctx, "find something", limit=5))

    assert results == [{"name": "Error", "description": "Host API unreachable (HTTP 503)"}]


# --- core.gateway.use_agent ---------------------------------------------------

def _patch_no_call(monkeypatch, target, attr):
    async def _fail(*args, **kwargs):
        raise AssertionError(f"{attr} should not have been called")
    monkeypatch.setattr(target, attr, _fail)


def test_use_agent_denies_external_false(monkeypatch):
    monkeypatch.setattr(gateway.identity_mgr, "get_agent_config", lambda name: {"name": name, "external": False})
    _patch_no_call(monkeypatch, gateway, "is_agent_configured")

    ctx = FakeContext()
    result = asyncio.run(gateway.use_agent(ctx, "data-parser", "parse this"))

    assert result == "SYSTEM: Access denied. Agent 'data-parser' is internal and cannot be called directly."


def test_use_agent_allows_external_true(monkeypatch):
    monkeypatch.setattr(gateway.identity_mgr, "get_agent_config", lambda name: {"name": name, "external": True})

    async def fake_is_agent_configured(agent_name, user_id):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    monkeypatch.setattr(gateway, "is_agent_configured", fake_is_agent_configured)

    class FakeStreamResponse:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def raise_for_status(self):
            pass

        async def aiter_lines(self):
            import json as _json
            yield _json.dumps({"choices": [{"message": {"content": "hello there"}}]})

    class FakeHTTPStreamClient:
        def stream(self, method, url, **kwargs):
            return FakeStreamResponse()

    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(http_client=FakeHTTPStreamClient())), raising=False)

    ctx = FakeContext()
    result = asyncio.run(gateway.use_agent(ctx, "general-agent", "hello"))

    assert result == "hello there"


# --- core.host chat_completions -----------------------------------------------

def _make_request(model):
    return host.ChatRequest(model=model, messages=[host.ChatMessage(role="user", content="hi")])


def test_chat_completions_denies_external_false(monkeypatch):
    monkeypatch.setattr(host.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(host.identity_mgr, "get_agent_config", lambda name: {"name": name, "type": "user_agent", "external": False})
    _patch_no_call(monkeypatch, host, "get_agent")

    request = _make_request("data-parser")

    with pytest.raises(host.HTTPException) as exc_info:
        asyncio.run(host.chat_completions(request))

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Access denied: Agent 'data-parser' is internal and cannot be called directly."


def test_chat_completions_exempts_supervisor(monkeypatch):
    monkeypatch.setattr(host.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(host.identity_mgr, "get_agent_config", lambda name: {"name": name, "type": "user_agent", "external": False})
    monkeypatch.setattr(host.identity_mgr, "record_agent_run_state", lambda *a, **k: True)
    monkeypatch.setattr(host.health_monitor, "get_status", lambda kind, name: {"status": "Online"})
    monkeypatch.setattr(host.health_monitor, "record_event", lambda *a, **k: None)

    class FakeResult:
        output = "supervisor reply"
        usage = None

    async def fake_get_agent(name):
        class FakeAgent:
            async def run(self, *a, **k):
                return FakeResult()
        return FakeAgent()

    monkeypatch.setattr(host, "get_agent", fake_get_agent)

    monkeypatch.setattr(host, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False))

    request = _make_request("supervisor")

    result = asyncio.run(host.chat_completions(request))

    assert result["choices"][0]["message"]["content"] == "supervisor reply"


def test_chat_completions_allows_external_true(monkeypatch):
    monkeypatch.setattr(host.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(host.identity_mgr, "get_agent_config", lambda name: {"name": name, "type": "user_agent", "external": True})
    monkeypatch.setattr(host.identity_mgr, "record_agent_run_state", lambda *a, **k: True)
    monkeypatch.setattr(host.health_monitor, "get_status", lambda kind, name: {"status": "Online"})
    monkeypatch.setattr(host.health_monitor, "record_event", lambda *a, **k: None)

    class FakeResult:
        output = "general reply"
        usage = None

    async def fake_get_agent(name):
        class FakeAgent:
            async def run(self, *a, **k):
                return FakeResult()
        return FakeAgent()

    monkeypatch.setattr(host, "get_agent", fake_get_agent)

    monkeypatch.setattr(host, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False))

    request = _make_request("general-agent")

    result = asyncio.run(host.chat_completions(request))

    assert result["choices"][0]["message"]["content"] == "general reply"


# --- Phase 3 (Cycle 4): ranked-subset decoration (I1) --------------------------
#
# `_get_visible_agents(names=[...])` must decorate the ranked subset using only the
# four bulk etcd getters + Host liveness ping + targeted per-name calls -- never the
# full-catalog `discover_agents()` / `get_all_agent_skills()` paths. `names=None`
# preserves the original full-catalog behavior.

def test_search_agents_decoration_avoids_catalog_discovery(monkeypatch):
    """`search_agents` decorates ranked names from the subset path only: the
    full-catalog `discover_agents()` and bulk `get_all_agent_skills()` must never
    fire, and the decorated description comes from the etcd config, not the raw
    ranked result."""
    async def fake_ranked(query, limit=None, include_disabled=False):
        return [{"name": "general-agent", "description": "raw description", "status": "Online"}]

    async def _fail_if_called(*args, **kwargs):
        raise AssertionError("must not be called on the subset path")

    monkeypatch.setattr(gateway, "_search_agents_ranked", fake_ranked)
    monkeypatch.setattr(gateway, "discover_agents", _fail_if_called)
    monkeypatch.setattr(gateway.identity_mgr, "get_all_agent_skills", _fail_if_called)

    _patch_gateway_etcd(monkeypatch, agent_configs={
        "general-agent": {
            "name": "general-agent",
            "description": "Rich catalog description",
            "type": "user_agent",
            "external": True,
        },
    })

    async def fake_is_agent_configured(agent_name, user_id):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    monkeypatch.setattr(gateway, "is_agent_configured", fake_is_agent_configured)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    results = asyncio.run(gateway.search_agents(FakeContext(), "find something"))

    assert results == [{
        "name": "general-agent",
        "description": "Rich catalog description",
        "configured": True,
    }]


def test_get_visible_agents_subset_decorates_only_requested_names(monkeypatch):
    """The subset path omits unrequested agents, decorates only the requested names,
    and appends the verbatim NOT CONFIGURED note from `is_agent_configured`'s
    missing-secrets output; `names=None` still returns the full catalog."""
    requested = []

    async def fake_is_agent_configured(agent_name, user_id):
        requested.append(agent_name)
        if agent_name == "b":
            return {"configured": False, "missing_secrets": ["B_KEY"], "missing_variables": []}
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    _patch_gateway_etcd(monkeypatch, agent_configs={
        "a": {"name": "a", "description": "Agent A", "type": "user_agent", "external": True},
        "b": {"name": "b", "description": "Agent B", "type": "user_agent", "external": True},
        "c": {"name": "c", "description": "Agent C", "type": "user_agent", "external": True},
    })

    async def _fail_if_called(*args, **kwargs):
        raise AssertionError("discover_agents must not be called on the subset path")

    monkeypatch.setattr(gateway, "discover_agents", _fail_if_called)
    monkeypatch.setattr(gateway, "is_agent_configured", fake_is_agent_configured)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents(names=["a", "b"]))

    assert len(visible) == 2
    assert sorted(a["name"] for a in visible) == ["a", "b"]
    assert sorted(requested) == ["a", "b"]
    a_entry = next(a for a in visible if a["name"] == "a")
    b_entry = next(a for a in visible if a["name"] == "b")
    assert a_entry["configured"] is True
    assert b_entry["configured"] is False
    assert b_entry["description"].endswith(
        " [NOT CONFIGURED — missing secrets: B_KEY. Configure at /agents/b/configure]"
    )

    # Regression pin: names=None still takes the full-catalog discover_agents() path.
    async def fake_discover_agents(user_id=None, agent_configs=None, agent_health=None):
        return [
            {"name": "a", "description": "Agent A", "type": "user_agent", "is_configured": True, "external": True},
            {"name": "b", "description": "Agent B", "type": "user_agent", "is_configured": True, "external": True},
            {"name": "c", "description": "Agent C", "type": "user_agent", "is_configured": True, "external": True},
        ]

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)

    full = asyncio.run(gateway._get_visible_agents())

    assert sorted(a["name"] for a in full) == ["a", "b", "c"]
    assert sorted(requested) == ["a", "b"]


def test_get_visible_agents_subset_is_agent_configured_exception_fails_open(monkeypatch):
    """A per-agent readiness-check exception must fail open (configured=True, no NOT
    CONFIGURED note) rather than dropping the agent or failing the whole subset."""
    _patch_gateway_etcd(monkeypatch, agent_configs={
        "a": {"name": "a", "description": "Agent A", "type": "user_agent", "external": True},
    })

    async def _fail_if_called(*args, **kwargs):
        raise AssertionError("discover_agents must not be called on the subset path")

    async def raising_is_agent_configured(agent_name, user_id):
        raise RuntimeError("etcd unreachable")

    monkeypatch.setattr(gateway, "discover_agents", _fail_if_called)
    monkeypatch.setattr(gateway, "is_agent_configured", raising_is_agent_configured)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents(names=["a"]))

    assert len(visible) == 1
    assert visible[0]["name"] == "a"
    assert visible[0]["configured"] is True
    assert "[NOT CONFIGURED" not in visible[0]["description"]


def test_get_visible_agents_subset_omits_ineligible_names(monkeypatch):
    """Names failing the catalog checks (unknown, disabled, non-routable, internal) are
    omitted from the ranked subset; only eligible names come back."""
    _patch_gateway_etcd(
        monkeypatch,
        disabled=["disabled-agent"],
        agent_configs={
            "disabled-agent": {"name": "disabled-agent", "description": "D", "type": "user_agent", "external": True},
            "background-agent": {"name": "background-agent", "description": "B", "type": "background_agent", "external": True},
            "internal-agent": {"name": "internal-agent", "description": "I", "type": "user_agent", "external": False},
            "good-agent": {"name": "good-agent", "description": "G", "type": "user_agent", "external": True},
        },
    )

    async def fake_is_agent_configured(agent_name, user_id):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    monkeypatch.setattr(gateway, "is_agent_configured", fake_is_agent_configured)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents(
        names=["unknown-agent", "disabled-agent", "background-agent", "internal-agent", "good-agent"]
    ))

    assert [a["name"] for a in visible] == ["good-agent"]


def test_get_visible_agents_subset_annotates_offline_and_degraded(monkeypatch):
    """Offline/Degraded decoration is computed per requested name from the bulk etcd
    health maps, exactly as the full-catalog path does."""
    from datetime import datetime, timezone

    _patch_gateway_etcd(
        monkeypatch,
        agent_configs={
            "offline-agent": {"name": "offline-agent", "description": "Offline", "type": "user_agent", "external": True, "allowed_tools": []},
            "degraded-agent": {"name": "degraded-agent", "description": "Degraded", "type": "user_agent", "external": True, "allowed_tools": ["t1"]},
            "ok-agent": {"name": "ok-agent", "description": "OK", "type": "user_agent", "external": True, "allowed_tools": []},
        },
        agent_health={
            "offline-agent": {"status": "Offline", "last_failure_time": datetime.now(timezone.utc).isoformat()},
        },
        tool_health={"t1": {"status": "Offline"}},
    )

    async def fake_is_agent_configured(agent_name, user_id):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    monkeypatch.setattr(gateway, "is_agent_configured", fake_is_agent_configured)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents(
        names=["offline-agent", "degraded-agent", "ok-agent"]
    ))
    by_name = {a["name"]: a for a in visible}

    assert by_name["offline-agent"]["configured"] is False
    assert by_name["offline-agent"]["description"].endswith(" [STATUS: OFFLINE - DO NOT ROUTE REQUESTS HERE]")
    assert by_name["degraded-agent"]["configured"] is True
    assert by_name["degraded-agent"]["description"].endswith(" [STATUS: DEGRADED - Offline tools: t1]")
    assert by_name["ok-agent"]["configured"] is True


def test_get_visible_agents_subset_uses_targeted_skills_for_empty_description(monkeypatch):
    """A requested agent with no config description falls back to its own skills.md
    first paragraph via a targeted per-name fetch, never the full-catalog bulk fetch."""
    calls = []

    def fake_get_agent_skills(name):
        calls.append(name)
        return "# Header\n\nFirst real paragraph.\n\nSecond."

    async def _fail_if_called(*args, **kwargs):
        raise AssertionError("get_all_agent_skills must not be called on the subset path")

    async def fake_is_agent_configured(agent_name, user_id):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    _patch_gateway_etcd(monkeypatch, agent_configs={
        "skills-agent": {"name": "skills-agent", "type": "user_agent", "external": True},
    })
    monkeypatch.setattr(gateway.identity_mgr, "get_agent_skills", fake_get_agent_skills)
    monkeypatch.setattr(gateway.identity_mgr, "get_all_agent_skills", _fail_if_called)
    monkeypatch.setattr(gateway, "is_agent_configured", fake_is_agent_configured)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents(names=["skills-agent"]))

    assert len(visible) == 1
    assert visible[0]["description"] == "First real paragraph."
    assert calls == ["skills-agent"]


def test_get_visible_agents_subset_fetches_skills_concurrently(monkeypatch):
    """Two requested agents with no config description must have their skills fetched
    concurrently: both fake lookups rendezvous at a shared ``threading.Barrier(2)`` that
    only releases once both are in flight. A sequential implementation would block on
    the first ``barrier.wait()``, hit the 2s timeout, and both descriptions would fall
    back to 'No description available.' instead of both agents coming back decorated."""
    loop_thread_id = threading.get_ident()
    barrier = threading.Barrier(2, timeout=2)
    released = []

    def fake_get_agent_skills(name):
        barrier.wait()
        released.append((name, threading.get_ident()))
        return f"Skills for {name}."

    async def fake_is_agent_configured(agent_name, user_id):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    _patch_gateway_etcd(monkeypatch, agent_configs={
        "skills-a": {"name": "skills-a", "type": "user_agent", "external": True},
        "skills-b": {"name": "skills-b", "type": "user_agent", "external": True},
    })
    monkeypatch.setattr(gateway.identity_mgr, "get_agent_skills", fake_get_agent_skills)
    monkeypatch.setattr(gateway, "is_agent_configured", fake_is_agent_configured)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents(names=["skills-a", "skills-b"]))
    by_name = {a["name"]: a for a in visible}

    assert sorted(by_name) == ["skills-a", "skills-b"]
    assert by_name["skills-a"]["description"] == "Skills for skills-a."
    assert by_name["skills-b"]["description"] == "Skills for skills-b."
    assert {name for name, _ in released} == {"skills-a", "skills-b"}
    assert all(thread_id != loop_thread_id for _, thread_id in released)


def test_get_visible_agents_subset_returns_generic_error_sentinel_on_decoration_failure(monkeypatch, caplog):
    """An unexpected exception while decorating the ranked subset must degrade to the
    generic 'Failed to verify agent configurations' sentinel, keeping the raw detail
    out of the returned description and only in the logs."""
    _patch_gateway_etcd(monkeypatch, agent_configs={
        "a": {"name": "a", "description": "Agent A", "type": "user_agent", "external": True},
    })

    def _raise_decoration(*args, **kwargs):
        raise RuntimeError("decoration exploded")

    monkeypatch.setattr(gateway, "is_routable_agent_type", _raise_decoration)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    with caplog.at_level(logging.ERROR, logger="core.gateway"):
        visible = asyncio.run(gateway._get_visible_agents(names=["a"]))

    assert visible == [{"name": "Error", "description": "Failed to verify agent configurations. Please try again later."}]
    assert "decoration exploded" not in visible[0]["description"]
    assert "decoration exploded" in caplog.text


def test_get_visible_agents_full_path_returns_generic_error_sentinel_when_discover_fails(monkeypatch, caplog):
    """A failure inside the full-catalog discover_agents() path must also degrade to the
    generic sentinel, with the raw detail logged rather than returned."""
    async def raising_discover_agents(user_id=None, agent_configs=None, agent_health=None):
        raise RuntimeError("discover exploded")

    _patch_gateway_etcd(monkeypatch)
    monkeypatch.setattr(gateway, "discover_agents", raising_discover_agents)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    with caplog.at_level(logging.ERROR, logger="core.gateway"):
        visible = asyncio.run(gateway._get_visible_agents())

    assert visible == [{"name": "Error", "description": "Failed to verify agent configurations. Please try again later."}]
    assert "discover exploded" not in visible[0]["description"]
    assert "discover exploded" in caplog.text


def test_get_visible_agents_subset_skills_failure_degrades_only_that_name(monkeypatch, caplog):
    """One agent's skills-fetch failure must degrade only that name to the generic
    fallback description, never the whole subset to the Error sentinel."""
    def fake_get_agent_skills(name):
        if name == "b":
            raise RuntimeError("skills exploded")
        return "# H\n\nParagraph A."

    async def fake_is_agent_configured(agent_name, user_id):
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    _patch_gateway_etcd(monkeypatch, agent_configs={
        "a": {"name": "a", "type": "user_agent", "external": True},
        "b": {"name": "b", "type": "user_agent", "external": True},
    })
    monkeypatch.setattr(gateway.identity_mgr, "get_agent_skills", fake_get_agent_skills)
    monkeypatch.setattr(gateway, "is_agent_configured", fake_is_agent_configured)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient()
    )), raising=False)
    user_id_var.set("user-1")

    with caplog.at_level(logging.WARNING, logger="core.gateway"):
        visible = asyncio.run(gateway._get_visible_agents(names=["a", "b"]))

    by_name = {a["name"]: a for a in visible}
    assert by_name["a"]["description"] == "Paragraph A."
    assert by_name["b"]["description"] == "No description available."
    assert not (len(visible) == 1 and visible[0]["name"] == "Error")
    assert "skills exploded" in caplog.text


# --- Phase 5 (Cycle 4): chat_completions 500 detail leak ------------------------

def test_chat_completions_500_hides_internal_detail(monkeypatch, caplog):
    """An execution failure must surface a generic 500 detail -- the raw exception
    text stays in logs / health records, never in the API response (Task 5.4)."""
    monkeypatch.setattr(host.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(
        host.identity_mgr,
        "get_agent_config",
        lambda name: {"name": name, "type": "user_agent", "external": True},
    )
    monkeypatch.setattr(host.identity_mgr, "record_agent_run_state", lambda *a, **k: True)
    monkeypatch.setattr(host.health_monitor, "get_status", lambda kind, name: {"status": "Online"})

    recorded_events = []

    def fake_record_event(entity_type, name, is_success, error_details=None):
        recorded_events.append((entity_type, name, is_success, error_details))

    monkeypatch.setattr(host.health_monitor, "record_event", fake_record_event)

    async def fake_get_agent(name):
        class FailingAgent:
            async def run(self, *args, **kwargs):
                raise RuntimeError("secret-ish detail")
        return FailingAgent()

    monkeypatch.setattr(host, "get_agent", fake_get_agent)

    monkeypatch.setattr(host, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False))

    request = _make_request("general-agent")

    with caplog.at_level(logging.ERROR, logger="core.host"):
        with pytest.raises(host.HTTPException) as exc_info:
            asyncio.run(host.chat_completions(request))

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "Internal error while running the agent."
    assert "secret-ish detail" not in exc_info.value.detail
    assert "execution failed" in caplog.text
    assert any(
        event[0] == "agent" and event[1] == "general-agent" and event[2] is False
        for event in recorded_events
    )


def test_chat_completions_get_agent_failure_is_not_wrapped(monkeypatch):
    """`get_agent` runs before the execution try/except, so its failures must
    propagate as-is instead of being converted into a generic 500."""
    monkeypatch.setattr(host.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(
        host.identity_mgr,
        "get_agent_config",
        lambda name: {"name": name, "type": "user_agent", "external": True},
    )
    monkeypatch.setattr(host.health_monitor, "get_status", lambda kind, name: {"status": "Online"})

    async def fake_get_agent(name):
        raise RuntimeError("build failed")

    monkeypatch.setattr(host, "get_agent", fake_get_agent)

    request = _make_request("general-agent")

    with pytest.raises(RuntimeError) as exc_info:
        asyncio.run(host.chat_completions(request))

    assert not isinstance(exc_info.value, host.HTTPException)
    assert str(exc_info.value) == "build failed"


# --- Shutdown drain (_background_tasks) ----------------------------------------

def test_host_drain_background_tasks_waits_for_completion():
    completed = []

    async def work():
        await asyncio.sleep(0.01)
        completed.append(True)
        return "done"

    async def _scenario():
        task = host._spawn_background(work(), "test-host-drain-complete")
        await host._drain_background_tasks(timeout=5.0)
        return task

    task = asyncio.run(_scenario())

    assert completed == [True]
    assert task.done()
    assert not task.cancelled()
    assert task.result() == "done"
    assert task not in host._background_tasks


def test_host_drain_background_tasks_cancels_hung_task():
    started = asyncio.Event()

    async def work():
        started.set()
        await asyncio.sleep(60)

    async def _scenario():
        task = host._spawn_background(work(), "test-host-drain-hang")
        await asyncio.wait_for(started.wait(), timeout=2)
        await host._drain_background_tasks(timeout=0.05)
        await asyncio.gather(task, return_exceptions=True)
        return task

    task = asyncio.run(_scenario())

    assert task.cancelled()
    assert task not in host._background_tasks
