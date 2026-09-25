"""Tests for Phase 4 (Supervisor Agent Two-Tier Integration) — see
__spec_docs/direct_tool_gateway_execution_spec.md.

Two groups:
  - Group A: exercises the `search_tools`/`use_tool` closures registered by
    `core.agent_factory._register_admin_tools` directly, via a minimal `FakeAgent` that
    captures `@agent.tool_plain(...)`-decorated functions into a plain dict (mirrors how
    tests/test_gateway_tool_execution.py calls gateway tool functions directly rather than
    spinning up a real FastMCP/pydantic-ai runtime).
  - Group B: builds a real supervisor `Agent` via `agent_factory.build_agent("supervisor")`
    (with etcd/hub/model calls mocked) and asserts `search_tools`/`use_tool` end up
    registered alongside the pre-existing `search_agents` and the subagent toolset's `task`.
"""
import asyncio
import logging
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from core import agent_factory
from core.auth import user_id_var


class FakeAgent:
    """Stand-in for pydantic_ai.Agent — only `tool_plain` is exercised by
    `_register_admin_tools`. Captures the decorated coroutine functions by name so tests
    can call them directly without building a real Agent/model."""

    def __init__(self):
        self.tools: Dict[str, Any] = {}

    def tool_plain(self, name=None, description=None):
        def decorator(func):
            self.tools[name or func.__name__] = func
            return func
        return decorator


def _build_fake_agent() -> FakeAgent:
    fake_agent = FakeAgent()
    agent_factory._register_admin_tools(fake_agent)
    return fake_agent


def _patch_no_call(monkeypatch, target, attr):
    async def _fail(*args, **kwargs):
        raise AssertionError(f"{attr} should not have been called")
    monkeypatch.setattr(target, attr, _fail)


# --- Group A: registered tool behavior ---------------------------------------

def test_register_admin_tools_includes_search_tools_and_use_tool_alongside_search_agents():
    fake_agent = _build_fake_agent()
    assert "search_agents" in fake_agent.tools
    assert "manage_agent" in fake_agent.tools
    assert "search_tools" in fake_agent.tools
    assert "use_tool" in fake_agent.tools


def test_search_agents_tool_preserves_unavailable_match_note(monkeypatch):
    """Phase E of the Trellis Rules Engine hardening plan
    (__spec_docs/rules_engine_hardening_plan.md, E1/E3) added an "unavailable match"
    note to core.agent_search.search_agents()'s output, marked with
    unavailable_match=True, specifically so a caller that also decorates results by
    agent name doesn't clobber its already-final, self-contained sentence. This
    wrapper's own "[NOT CONFIGURED ...]" append must be skipped for that item -- found
    by an adversarial Phase E review pass: without this guard, an offline-reason note
    could be double-annotated as "...currently offline... [NOT CONFIGURED ...]",
    actively misleading the Supervisor LLM about why the agent isn't available."""
    fake_agent = _build_fake_agent()

    note_description = (
        "The routing policy identified 'troubleshooting-agent' as the best match for "
        "this query, but it is currently not configured. Showing next-best "
        "alternatives below."
    )

    async def fake_search(query, limit=8, include_disabled=False):
        return [{
            "name": "troubleshooting-agent",
            "description": note_description,
            "status": "Unconfigured",
            "unavailable_match": True,
        }]

    async def fake_discover_agents(user_id=None):
        return [{
            "name": "troubleshooting-agent",
            "is_configured": False,
            "missing_secrets": ["API_KEY"],
            "missing_variables": [],
        }]

    import core.agent_search as agent_search_module
    import core.discovery as discovery_module
    monkeypatch.setattr(agent_search_module, "search_agents", fake_search)
    monkeypatch.setattr(discovery_module, "discover_agents", fake_discover_agents)
    user_id_var.set("user-1")

    result = asyncio.run(fake_agent.tools["search_agents"]("Analyze the PCAP trace"))

    assert result == [{
        "name": "troubleshooting-agent",
        "description": note_description,
        "status": "Unconfigured",
        "unavailable_match": True,
        "configured": False,
    }]


def test_search_agents_tool_unavailable_match_offline_agent_reports_configured_false(monkeypatch):
    """An agent that is matched but offline must have configured=False set on its note item
    in Supervisor search_agents, even if its credentials are configured, so Supervisor never delegates to it."""
    fake_agent = _build_fake_agent()

    note_description = (
        "The routing policy identified 'troubleshooting-agent' as the best match for "
        "this query, but it is currently offline. Showing next-best alternatives below."
    )

    async def fake_search(query, limit=8, include_disabled=False):
        return [{
            "name": "troubleshooting-agent",
            "description": note_description,
            "status": "Offline",
            "unavailable_match": True,
        }]

    async def fake_discover_agents(user_id=None):
        return [{
            "name": "troubleshooting-agent",
            "is_configured": True,  # Credentials are set
        }]

    import core.agent_search as agent_search_module
    import core.discovery as discovery_module
    monkeypatch.setattr(agent_search_module, "search_agents", fake_search)
    monkeypatch.setattr(discovery_module, "discover_agents", fake_discover_agents)
    user_id_var.set("user-1")

    result = asyncio.run(fake_agent.tools["search_agents"]("Analyze the PCAP trace"))

    assert result[0]["configured"] is False
    assert result[0]["status"] == "Offline"


def test_search_agents_tool_still_annotates_ordinary_unconfigured_result(monkeypatch):
    """Non-regression: an ordinary (non-note) unconfigured result still gets the
    "[NOT CONFIGURED ...]" note appended, exactly as before Phase E."""
    fake_agent = _build_fake_agent()

    async def fake_search(query, limit=8, include_disabled=False):
        return [{"name": "ticket-summary-agent", "description": "Generates summaries.", "status": "Online"}]

    async def fake_discover_agents(user_id=None, **kwargs):
        return [{
            "name": "ticket-summary-agent",
            "is_configured": False,
            "missing_secrets": ["API_KEY"],
            "missing_variables": [],
        }]

    async def fake_is_agent_configured(agent_name, user_id=None):
        return {
            "configured": False,
            "missing_secrets": ["API_KEY"],
            "missing_variables": [],
        }

    import core.agent_search as agent_search_module
    import core.discovery as discovery_module
    monkeypatch.setattr(agent_search_module, "search_agents", fake_search)
    monkeypatch.setattr(discovery_module, "discover_agents", fake_discover_agents)
    monkeypatch.setattr(discovery_module, "is_agent_configured", fake_is_agent_configured)
    user_id_var.set("user-1")

    result = asyncio.run(fake_agent.tools["search_agents"]("Generate an executive summary"))

    assert result == [{
        "name": "ticket-summary-agent",
        "description": "Generates summaries. [NOT CONFIGURED — missing secrets: API_KEY. Configure at /agents/ticket-summary-agent/configure]",
        "status": "Online",
        "configured": False,
    }]


def test_search_agents_tool_ordinary_offline_candidate_reports_configured_false(monkeypatch):
    """An ordinary offline candidate in Supervisor search_agents must report configured=False,
    and skip calling is_agent_configured."""
    fake_agent = _build_fake_agent()

    async def fake_search(query, limit=8, include_disabled=False):
        return [{"name": "ticket-summary-agent", "description": "Generates summaries.", "status": "Offline"}]

    called = False

    async def fake_is_agent_configured(agent_name, user_id=None):
        nonlocal called
        called = True
        return {"configured": True, "missing_secrets": [], "missing_variables": []}

    import core.agent_search as agent_search_module
    import core.discovery as discovery_module
    monkeypatch.setattr(agent_search_module, "search_agents", fake_search)
    monkeypatch.setattr(discovery_module, "is_agent_configured", fake_is_agent_configured)
    user_id_var.set("user-1")

    result = asyncio.run(fake_agent.tools["search_agents"]("Generate an executive summary"))

    assert result[0]["configured"] is False
    assert result[0]["status"] == "Offline"
    assert not called  # Short-circuits without checking configuration for offline agents


def test_search_agents_tool_without_user_id_reports_configured_boolean(monkeypatch):
    """When user_id is None, every returned result must still include the configured boolean key."""
    fake_agent = _build_fake_agent()

    async def fake_search(query, limit=8, include_disabled=False):
        return [
            {"name": "agent-online", "description": "Online agent.", "status": "Online"},
            {"name": "agent-offline", "description": "Offline agent.", "status": "Offline"},
        ]

    import core.agent_search as agent_search_module
    monkeypatch.setattr(agent_search_module, "search_agents", fake_search)
    user_id_var.set(None)

    result = asyncio.run(fake_agent.tools["search_agents"]("Find agents"))

    assert len(result) == 2
    assert result[0]["configured"] is True
    assert result[1]["configured"] is False


def test_search_tools_tool_delegates_to_ranked_search_with_caller_user_id(monkeypatch):
    fake_agent = _build_fake_agent()
    cards = [
        {"name": "netctl", "description": "Inspect cluster nodes.", "parameters": {}, "configured": True, "status": "Online", "source": "local"},
    ]

    async def fake_ranked(query, limit=8, user_id=None):
        assert query == "list all clusters in preprod"
        assert user_id == "user-1"
        return cards

    import core.tool_search as tool_search_module
    monkeypatch.setattr(tool_search_module, "search_tools", fake_ranked)
    user_id_var.set("user-1")

    result = asyncio.run(fake_agent.tools["search_tools"]("list all clusters in preprod"))

    assert result == cards


def test_use_tool_denies_unwhitelisted_tool(monkeypatch):
    fake_agent = _build_fake_agent()
    fake_identity = SimpleNamespace(get_tool_config=lambda name: {"name": name, "public": False})
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    import core.discovery as discovery_module
    _patch_no_call(monkeypatch, discovery_module, "is_tool_configured")
    _patch_no_call(monkeypatch, agent_factory, "get_hub_client")
    user_id_var.set("user-1")

    result = asyncio.run(fake_agent.tools["use_tool"]("system_restart", {}))

    assert result == "SYSTEM: Access denied. Tool 'system_restart' is internal and not exposed for direct execution."


def test_use_tool_denies_unknown_tool(monkeypatch):
    fake_agent = _build_fake_agent()
    fake_identity = SimpleNamespace(get_tool_config=lambda name: None)
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)
    user_id_var.set("user-1")

    result = asyncio.run(fake_agent.tools["use_tool"]("does_not_exist", {}))

    assert "Access denied" in result


def test_use_tool_reports_missing_configuration(monkeypatch):
    fake_agent = _build_fake_agent()
    fake_identity = SimpleNamespace(get_tool_config=lambda name: {"name": name, "public": True})
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    async def fake_is_tool_configured(tool_name, user_id=None):
        return {
            "configured": False,
            "missing_secrets": ["EXAMPLE-API_PRODUCTION_USERNAME", "EXAMPLE-API_PRODUCTION_PASSWORD"],
            "missing_variables": [],
            "optional_missing_secrets": [],
        }

    import core.discovery as discovery_module
    monkeypatch.setattr(discovery_module, "is_tool_configured", fake_is_tool_configured)
    _patch_no_call(monkeypatch, agent_factory, "get_hub_client")
    user_id_var.set("user-1")

    result = asyncio.run(fake_agent.tools["use_tool"]("opsctl", {"args": ["connector", "detail"]}))

    assert result.startswith("SYSTEM: Tool 'opsctl' requires configuration before it can be used.")
    assert "EXAMPLE-API_PRODUCTION_USERNAME" in result
    assert "/configuration" in result


def test_use_tool_executes_resource_inspection_directly_tier1(monkeypatch):
    """Simulates a Tier 1 supervisor query ('list clusters in preprod') resolving via
    use_tool -> Hub, with no agent delegation involved at all."""
    fake_agent = _build_fake_agent()
    fake_identity = SimpleNamespace(get_tool_config=lambda name: {"name": name, "public": True})
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    async def fake_configured(tool_name, user_id=None):
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    import core.discovery as discovery_module
    monkeypatch.setattr(discovery_module, "is_tool_configured", fake_configured)

    calls = []

    class FakeResult:
        data = {"clusters": ["cluster-1", "cluster-2"]}
        structured_content = None
        content = None

    class FakeHubClient:
        async def call_tool(self, name, arguments, raise_on_error=True):
            calls.append((name, arguments, raise_on_error))
            return FakeResult()

    async def fake_get_hub_client():
        return FakeHubClient()

    monkeypatch.setattr(agent_factory, "get_hub_client", fake_get_hub_client)
    user_id_var.set("user-42")

    result = asyncio.run(fake_agent.tools["use_tool"]("netctl", {"environment": "preprod", "args": ["cluster", "list"]}))

    assert result == {"clusters": ["cluster-1", "cluster-2"]}
    name, arguments, raise_on_error = calls[0]
    assert name == "netctl"
    assert arguments == {"environment": "preprod", "args": ["cluster", "list"], "__user_id": "user-42"}
    assert raise_on_error is False


def test_use_tool_routes_external_mcp_tool_by_prefixed_name(monkeypatch):
    fake_agent = _build_fake_agent()
    fake_identity = SimpleNamespace(
        get_mcp_config=lambda name: {"name": name, "public": False, "public_tools": ["clusters_get_all"]}
    )
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    async def fake_configured(tool_name, user_id=None):
        assert tool_name == "mcp__example-mcp__clusters_get_all"
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    import core.discovery as discovery_module
    monkeypatch.setattr(discovery_module, "is_tool_configured", fake_configured)

    calls = []

    class FakeResult:
        data = None
        structured_content = {"clusters": []}
        content = None

    class FakeExternalClient:
        async def call_tool(self, name, arguments, raise_on_error=True):
            calls.append((name, arguments, raise_on_error))
            return FakeResult()

    async def fake_get_external_mcp_client(server_name, user_id):
        assert server_name == "example-mcp"
        assert user_id == "user-42"
        return FakeExternalClient()

    monkeypatch.setattr(agent_factory, "get_external_mcp_client", fake_get_external_mcp_client)
    user_id_var.set("user-42")

    result = asyncio.run(fake_agent.tools["use_tool"]("mcp__example-mcp__clusters_get_all", {"env": "staging"}))

    assert result == {"clusters": []}
    name, arguments, raise_on_error = calls[0]
    assert name == "clusters_get_all"
    assert arguments == {"env": "staging"}
    assert raise_on_error is False


def test_use_tool_surfaces_execution_errors(monkeypatch, caplog):
    fake_agent = _build_fake_agent()
    fake_identity = SimpleNamespace(get_tool_config=lambda name: {"name": name, "public": True})
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)

    async def fake_configured(tool_name, user_id=None):
        return {"configured": True, "missing_secrets": [], "missing_variables": [], "optional_missing_secrets": []}

    import core.discovery as discovery_module
    monkeypatch.setattr(discovery_module, "is_tool_configured", fake_configured)

    async def fake_get_hub_client():
        raise ConnectionError("hub unreachable")

    monkeypatch.setattr(agent_factory, "get_hub_client", fake_get_hub_client)
    user_id_var.set("user-1")

    with caplog.at_level(logging.ERROR, logger="core.tool_search"):
        result = asyncio.run(fake_agent.tools["use_tool"]("opsctl", {"args": ["--help"]}))

    assert result == "SYSTEM: Error executing tool 'opsctl'. Please try again later."
    assert "hub unreachable" not in result
    assert "hub unreachable" in caplog.text


# --- Group B: full build_agent("supervisor") integration ---------------------

class FakeIdentityManager:
    def __init__(self, agent_config: Dict, agent_skills: str):
        self._agent_config = agent_config
        self._agent_skills = agent_skills

    def get_agent_config(self, name: str) -> Optional[Dict]:
        return dict(self._agent_config) if name == "supervisor" else None

    def get_agent_skills(self, name: str) -> str:
        return self._agent_skills if name == "supervisor" else ""

    def get_config(self, key: str, default=None):
        return default


SUPERVISOR_CONFIG = {
    "name": "supervisor",
    "model": "gemini-3-flash-preview",
    "thinking_level": "medium",
    "tags": ["routing", "orchestration"],
    "a2a_access": [],
}


def test_build_agent_supervisor_registers_two_tier_toolset(monkeypatch):
    """Builds a real supervisor Agent (etcd/hub/model calls mocked) and verifies
    search_tools and use_tool land in its toolset alongside the pre-existing
    search_agents and the subagent toolset's task tool."""
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")

    fake_identity = FakeIdentityManager(dict(SUPERVISOR_CONFIG), "You are the supervisor.")
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: fake_identity)
    monkeypatch.setattr(agent_factory, "_health_monitor", None, raising=False)
    monkeypatch.setattr(agent_factory, "_supervisor_registry", None, raising=False)
    monkeypatch.setattr(agent_factory, "_hub_tools_cache", [], raising=False)
    monkeypatch.setattr(agent_factory, "_external_mcp_tools", {}, raising=False)

    async def fake_get_hub_client():
        return object()

    async def fake_discover_external_mcps(force=False):
        return None

    monkeypatch.setattr(agent_factory, "get_hub_client", fake_get_hub_client)
    monkeypatch.setattr(agent_factory, "discover_external_mcps", fake_discover_external_mcps)

    import core.memory as memory_module
    monkeypatch.setattr(memory_module, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False))

    agent = asyncio.run(agent_factory.build_agent("supervisor"))

    if agent_factory._supervisor_registry is not None:
        agent_factory._supervisor_registry._snapshot.stop()

    function_tools = agent._function_toolset.tools
    assert "search_tools" in function_tools
    assert "use_tool" in function_tools
    assert "search_agents" in function_tools

    subagent_tool_names = set()
    for toolset in agent._user_toolsets:
        subagent_tool_names.update(getattr(toolset, "tools", {}).keys())
    assert "task" in subagent_tool_names
