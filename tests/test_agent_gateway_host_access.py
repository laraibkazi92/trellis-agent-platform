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

    async def fake_discover_agents(user_id=None):
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

    async def fake_discover_agents(user_id=None):
        return discovered

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=FakeHTTPClient(status_code=503)
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents())

    assert visible == [{"name": "Error", "description": "Host API unreachable (HTTP 503)"}]


def test_get_visible_agents_fails_on_host_liveness_exception(monkeypatch):
    """Host unreachable at the transport level also fails clearly, as before."""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None):
        return discovered

    class RaisingClient:
        async def get(self, url, timeout=None):
            raise ConnectionError("connection refused")

    monkeypatch.setattr(gateway, "discover_agents", fake_discover_agents)
    monkeypatch.setattr(gateway, "app", SimpleNamespace(state=SimpleNamespace(
        http_client=RaisingClient()
    )), raising=False)
    user_id_var.set("user-1")

    visible = asyncio.run(gateway._get_visible_agents())

    assert len(visible) == 1
    assert visible[0]["name"] == "Error"
    assert "Host API unreachable" in visible[0]["description"]


def test_get_visible_agents_annotates_offline_status_from_etcd(monkeypatch):
    """Offline status is computed in-process from etcd health records, not Host's body."""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None):
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


def test_get_visible_agents_annotates_degraded_status_from_offline_tool(monkeypatch):
    """Degraded (an agent's own health is fine but an allowed tool is offline) is
    still derived by cross-referencing tool health, mirroring host.py's /health
    handler, just computed here instead of read from its JSON response."""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None):
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


def test_get_visible_agents_fails_gracefully_on_etcd_error_after_liveness_check(monkeypatch):
    """A transient etcd failure while computing per-agent decoration (after the Host
    liveness ping has already succeeded) must degrade to the same friendly error shape
    as every other failure path here, not propagate as a raw exception."""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None):
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

    visible = asyncio.run(gateway._get_visible_agents())

    assert len(visible) == 1
    assert visible[0]["name"] == "Error"
    assert "Failed to compute agent status" in visible[0]["description"]


def test_get_visible_agents_defaults_to_online_when_decoration_data_missing(monkeypatch):
    """Decoration-only, no drop: an agent absent from the etcd health/config maps
    (e.g. momentarily inconsistent bulk reads) is still returned, just undecorated."""
    discovered = [
        {"name": "general-agent", "description": "does stuff", "type": "user_agent", "is_configured": True, "external": True},
    ]

    async def fake_discover_agents(user_id=None):
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

    async def fake_visible():
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

    async def fake_visible():
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

    async def fake_visible():
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


def test_gateway_search_agents_returns_empty_when_nothing_ranked(monkeypatch):
    async def fake_ranked(query, limit=None, include_disabled=False):
        return []

    async def _fail_visible():
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

    async def fake_visible():
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

    import core.memory as memory_module
    monkeypatch.setattr(memory_module, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False))

    request = _make_request("supervisor")

    result = asyncio.run(host.chat_completions(request))

    assert result["choices"][0]["message"]["content"] == "supervisor reply"


def test_chat_completions_allows_external_true(monkeypatch):
    monkeypatch.setattr(host.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(host.identity_mgr, "get_agent_config", lambda name: {"name": name, "type": "user_agent", "external": True})
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

    import core.memory as memory_module
    monkeypatch.setattr(memory_module, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False))

    request = _make_request("general-agent")

    result = asyncio.run(host.chat_completions(request))

    assert result["choices"][0]["message"]["content"] == "general reply"
