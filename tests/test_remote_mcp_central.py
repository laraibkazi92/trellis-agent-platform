# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Central consumption of edge-exported MCP servers (v0.5.0 Phase 4).

Pins the central half of L1: an agent on central can list and call the tools of an
MCP server an edge exports over the tunnel, exactly like a central MCP server, while
central never connects to it, never resolves central secrets for it, and never routes
it through ``mcp_client_cache`` (the MCP session and its credentials live edge-side).

Covered contracts:

- ``core.remote_mcp.call_edge_mcp`` maps every relay status onto the same
  ``{"content", "isError", "structuredContent"}`` / ``{"error": ...}`` dict shape
  ``core.hub::_run_remote`` returns, takes identity from the verified token's claims
  only, leaves the per-user credential decision to the edge (it knows the export's
  ``credential_mode``), and caps oversized results.
- ``discover_external_mcps`` takes an edge MCP's catalog from its static ``tools``.
- ``build_agent`` registers the 4-part ``mcp__<site>__<mcp>__<tool>`` name.
- The gateway ``use_tool`` seam dispatches 4-part names to the relay caller.
- The whitelist guard and the configuration guard both understand 4-part names.

HTTP seam: tests monkeypatch ``core.remote_mcp._remote_client`` (the per-call
``httpx.AsyncClient`` factory), so no network, no relay process, and no etcd is
involved. Every etcd-backed seam is monkeypatched in the same spirit.
"""

import asyncio
import copy
import json
import logging
from types import SimpleNamespace

import httpx
import pytest

from core import agent_factory, agent_token, discovery, gateway, remote_mcp, tool_access, tool_search
from core.auth import user_id_var
from core.models import MCPConfig, MCPToolDefinition, RemoteMcpSpec

SITE = "dc1"
MCP = "devops-cli"
TOOL = "tenant_account_tools"
SERVER_KEY = f"{SITE}__{MCP}"
PREFIXED = f"mcp__{SITE}__{MCP}__{TOOL}"
RELAY_URL = "http://relay.internal:8100"

CONFIGURED = {
    "configured": True,
    "missing_secrets": [],
    "missing_variables": [],
    "optional_missing_secrets": [],
}


# --- shared fakes ---------------------------------------------------------------


class FakeContext:
    def __init__(self):
        self.progress_messages = []

    async def report_progress(self, current=None, total=None, message=None):
        self.progress_messages.append(message)


class FakeFunctionToolset:
    def __init__(self):
        self.tools = {}

    def add_tool(self, tool):
        self.tools[tool.name] = tool


class FakeAgent:
    """Captures both registration paths ``build_agent`` can take for MCP tools."""

    def __init__(self, *args, **kwargs):
        self._function_toolset = FakeFunctionToolset()
        self.tools = {}

    def tool(self, name=None, description=None):
        def decorator(fn):
            self.tools[name or fn.__name__] = fn
            return fn

        return decorator


def edge_mcp_payload(**overrides):
    """The relay-written ``/registry/mcps/<site>__<mcp>/config`` shape."""
    payload = {
        "name": SERVER_KEY,
        "description": "DevOps CLI MCP",
        "transport": "remote",
        "remote": {"site": SITE, "mcp": MCP},
        "managed_by": "edge-relay",
        "edge_transport": "stdio",
        "public": False,
        "public_tools": [],
        "tools": [
            {
                "name": TOOL,
                "description": "Tenant account tools.",
                "inputSchema": {
                    "type": "object",
                    "oneOf": [{"properties": {"action": {"const": "list"}}}],
                },
            }
        ],
    }
    payload.update(overrides)
    return payload


def install_transport(monkeypatch, handler):
    """Install the httpx seam: remote_mcp._remote_client -> MockTransport client."""
    requests = []
    timeouts = []

    def wrapped(request):
        requests.append(request)
        return handler(request)

    def factory(timeout_seconds):
        timeouts.append(timeout_seconds)
        return httpx.AsyncClient(
            transport=httpx.MockTransport(wrapped), timeout=timeout_seconds
        )

    monkeypatch.setattr(remote_mcp, "_remote_client", factory)
    monkeypatch.setenv(remote_mcp.RELAY_URL_ENV, RELAY_URL + "/")
    return requests, timeouts


def json_response(status, payload):
    def handler(_request):
        return httpx.Response(status, json=payload)

    return handler


def relay_error(status, code, message="boom"):
    return json_response(status, {"error": {"code": code, "message": message}})


def mint(agent, *, user_id=None, user_email=None):
    return agent_token.mint(agent, user_id=user_id, user_email=user_email)


def call_edge(tool=TOOL, args=None, user_id="user-1", timeout_seconds=120, token=None):
    return asyncio.run(
        remote_mcp.call_edge_mcp(
            SITE, MCP, tool, args if args is not None else {"action": "list"}, user_id,
            timeout_seconds=timeout_seconds,
            agent_token=token,
        )
    )


@pytest.fixture(autouse=True)
def _no_real_identity_lookup(monkeypatch):
    """DEV_MODE is off by default so a developer's shell cannot leak the dev email.

    The sealed-credential read is etcd I/O as well; tests that assert forwarding
    override this with their own fake.
    """
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.delenv("DEV_USER_EMAIL", raising=False)
    monkeypatch.setenv("AGENT_TOKEN_SECRET", "remote-mcp-central-unit-secret-0123456789")
    monkeypatch.setattr(remote_mcp.identity_mgr, "get_user", lambda user_id: None)
    monkeypatch.setattr(remote_mcp.edge_secrets_central, "get", lambda *args, **kwargs: None)


@pytest.fixture(autouse=True)
def _bound_edge_tool_granted(monkeypatch):
    """An edge MCP tool bound to an agent is gated by the evaluator, so the run needs
    a token whose agent record grants it (and an empty policy: no group rules)."""
    from core import auth, agent_token, tool_access

    class _NoPolicy:
        def put(self, key, value):
            raise AssertionError(f"no write expected: {key}")

        def get(self, key, **_kwargs):
            return None, None

    monkeypatch.setenv("AGENT_TOKEN_SECRET", "remote-mcp-central-unit-secret-0123456789")
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.setattr(tool_access, "_client", lambda: _NoPolicy())
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    tool_access.reset_snapshot()
    monkeypatch.setattr(
        auth,
        "get_identity_manager",
        lambda: SimpleNamespace(
            get_agent_config=lambda name: {"allowed_mcps": [SERVER_KEY]}
        ),
    )
    agent_token.mint_for_run("edge-agent", "user-1", run_id="run-edge")
    yield
    auth.agent_token_var.set(None)


# --- 1. call_edge_mcp: request shape and response mapping -----------------------


def test_call_edge_mcp_posts_relay_mcp_endpoint_with_identity(monkeypatch):
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "ok": True,
                "result": {
                    "content": [{"type": "text", "text": "ok"}],
                    "isError": False,
                    "structuredContent": {"tenants": ["a"]},
                },
            },
        )

    requests, timeouts = install_transport(monkeypatch, handler)
    # The caller's email is a token claim, not a registry read.
    monkeypatch.setattr(
        remote_mcp.identity_mgr, "get_user", lambda user_id: pytest.fail("per-call identity read")
    )
    token = mint("agent-a", user_id="user-1", user_email="ops@example.com")

    result = call_edge(args={"action": "list"}, user_id="user-1", timeout_seconds=120, token=token)

    assert seen["url"] == f"{RELAY_URL}/v1/sites/{SITE}/mcps/{MCP}/call"
    # No body identity: the relay builds the edge frame's identity from the
    # verified token, so asserting an identity here could never take effect.
    assert seen["body"] == {
        "tool": TOOL,
        "args": {"action": "list"},
        "deadline_ms": (120 + 30) * 1000,
        "agent_token": token,
        "sealed": None,
    }
    # Same dict shape hub._run_remote returns for a remote tool.
    assert result == {
        "content": [{"type": "text", "text": "ok"}],
        "isError": False,
        "structuredContent": {"tenants": ["a"]},
    }
    # The read timeout leads deadline_ms by 5 s so the edge's own timeout wins.
    assert timeouts == [155]


def test_call_edge_mcp_forwards_the_callers_sealed_blob(monkeypatch):
    seen = {}
    blob = {"v": 1, "ciphertext": "opaque", "keys": ["DEVOPS_PASSWORD"]}
    asked = []

    def fake_get(identity_mgr, site, user_id, kind, name):
        asked.append((site, user_id, kind, name))
        return dict(blob)

    monkeypatch.setattr(remote_mcp.edge_secrets_central, "get", fake_get)

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"ok": True, "result": {"content": [], "isError": False}}
        )

    install_transport(monkeypatch, handler)
    token = mint("agent-a", user_id="user-1", user_email="ops@example.com")

    call_edge(args={}, user_id="user-1", timeout_seconds=120, token=token)

    assert asked == [(SITE, "user-1", "mcp", MCP)]
    assert seen["body"]["sealed"] == blob


def test_call_edge_mcp_identity_comes_from_the_token_not_an_argument(monkeypatch):
    """The ``user_id`` argument cannot override the token's user, and nothing in the
    body claims an identity at all."""
    requests, _ = install_transport(
        monkeypatch, json_response(200, {"result": {"content": []}})
    )
    token = mint("agent-a", user_id="alice", user_email="alice@example.com")

    call_edge(user_id="mallory", token=token)

    body = json.loads(requests[0].content)
    assert "user" not in body
    assert "user_email" not in body
    assert body["agent_token"] == token


def test_call_edge_mcp_without_a_token_posts_no_identity(monkeypatch):
    """No token (dev/rollout): no identity, no sealed lookup.

    The ``user_id`` argument no longer selects anything: without claims there is no
    verified caller to seal a credential set to, so central sends ``sealed: null``
    and the edge's ``credential_mode`` decides.
    """
    requests, _ = install_transport(
        monkeypatch, json_response(200, {"result": {"content": []}})
    )
    monkeypatch.setattr(
        remote_mcp.identity_mgr, "get_user", lambda user_id: pytest.fail("per-call identity read")
    )
    monkeypatch.setattr(
        remote_mcp.edge_secrets_central,
        "get",
        lambda *args, **kwargs: pytest.fail("no claims, no sealed lookup"),
    )

    call_edge()

    body = json.loads(requests[0].content)
    assert "user" not in body
    assert "user_email" not in body
    assert body["agent_token"] is None
    assert body["sealed"] is None


def test_call_edge_mcp_service_token_carries_no_email(monkeypatch):
    requests, _ = install_transport(
        monkeypatch, json_response(200, {"result": {"content": []}})
    )
    monkeypatch.setattr(
        remote_mcp.identity_mgr, "get_user", lambda user_id: pytest.fail("per-call identity read")
    )
    token = mint("nightly", user_id="svc_agent_reporter")

    result = call_edge(user_id="svc_agent_reporter", token=token)

    body = json.loads(requests[0].content)
    # The service principal's lack of an email lives in the token, not the body.
    assert "user_email" not in body
    assert body["agent_token"] == token
    assert result == {"content": []}


def test_call_edge_mcp_leaves_the_per_user_decision_to_the_edge(monkeypatch):
    """An email-less token holding a set is dispatched: central has nothing to judge.

    A blob is sealed to the email *or the user id*, so an email-less identity that
    holds one is a legitimate caller (a webhook run mints the literal id ``webhook``).
    ``per_user_required`` without a set is the edge's refusal -- it is the only side
    that knows its ``credential_mode``.
    """
    requests, _ = install_transport(monkeypatch, json_response(200, {"result": {"content": []}}))
    monkeypatch.setattr(
        remote_mcp.edge_secrets_central,
        "get",
        lambda *args, **kwargs: {"v": 1, "ciphertext": "opaque", "keys": ["K"]},
    )
    token = mint("nightly", user_id="svc_agent_reporter")

    result = call_edge(user_id="svc_agent_reporter", token=token)

    # Dispatched: the edge owns the per-user decision (it knows its credential_mode).
    assert requests
    assert "identity_incomplete" not in str(result)


def test_call_edge_mcp_malformed_token_supplies_no_identity(monkeypatch):
    """A presented-but-invalid token must not borrow the ``user_id`` argument."""
    requests, _ = install_transport(
        monkeypatch, json_response(200, {"result": {"content": []}})
    )

    call_edge(user_id="mallory", token="t1.forged.signature")

    body = json.loads(requests[0].content)
    assert "user" not in body
    assert "user_email" not in body
    # The token is forwarded for the relay to reject; no identity is asserted.
    assert body["agent_token"] == "t1.forged.signature"


def test_call_edge_mcp_caps_oversized_result(monkeypatch):
    huge = "x" * 120_000
    install_transport(
        monkeypatch,
        json_response(200, {"result": {"content": [{"type": "text", "text": huge}]}}),
    )

    result = call_edge()

    assert "exceeded the 24k token limit" in result["error"]
    assert result["partial_data_preview"].endswith("... [TRUNCATED DUE TO SAFETY LIMITS]")


def test_call_edge_mcp_deadline_is_capped(monkeypatch):
    requests, timeouts = install_transport(
        monkeypatch, json_response(200, {"result": {"content": []}})
    )

    call_edge(timeout_seconds=4_000)

    assert json.loads(requests[0].content)["deadline_ms"] == remote_mcp._MAX_DEADLINE_MS
    assert timeouts == [4_035]


def test_call_edge_mcp_200_with_error_body(monkeypatch):
    install_transport(monkeypatch, relay_error(200, "mcp_session_lost", "session gone"))

    result = call_edge()

    assert result == {
        "error": (
            f"MCP tool '{SITE}__{MCP}__{TOOL}' failed on edge '{SITE}': session gone"
        )
    }


@pytest.mark.parametrize(
    "response,needle",
    [
        (relay_error(400, "invalid_arguments", "bad args"), "rejected the arguments: bad args"),
        (relay_error(404, "unknown_tool", "nope"), "does not export MCP tool"),
        (relay_error(429, "rate_limited", "slow down"), "rate-limiting tool calls"),
        (relay_error(503, "edge_offline", "offline"), "is offline (edge 'dc1' is not connected)"),
        (relay_error(503, "edge_overloaded", "busy"), "is busy and cannot accept"),
        (relay_error(504, "edge_timeout", "timeout"), "timed out on edge 'dc1'"),
        (json_response(500, {"oops": True}), "relay returned HTTP 500"),
    ],
)
def test_call_edge_mcp_maps_status_to_actionable_error(monkeypatch, response, needle):
    install_transport(monkeypatch, response)

    result = call_edge()

    assert set(result) == {"error"}
    assert needle in result["error"]
    assert f"{SITE}__{MCP}__{TOOL}" in result["error"]


def test_call_edge_mcp_transport_failures_return_error_not_raise(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    install_transport(monkeypatch, handler)

    result = call_edge()

    assert "is unreachable" in result["error"]
    assert "may already have run" not in result["error"]


def test_call_edge_mcp_404_keeps_the_relays_reason(monkeypatch):
    """`unknown_mcp` and `unknown_tool` are different operator problems."""
    install_transport(monkeypatch, relay_error(404, "unknown_mcp", "mcp 'devops-cli' is not exported"))

    result = call_edge()

    assert "does not export MCP tool" in result["error"]
    assert "Relay said: mcp 'devops-cli' is not exported." in result["error"]


@pytest.mark.parametrize("url", ["garbage/v1", "htp://relay.internal:8100", "http://[::1/v1"])
def test_call_edge_mcp_never_raises_on_a_misconfigured_relay_url(monkeypatch, url):
    """A bad EDGE_RELAY_URL raises InvalidURL/UnsupportedProtocol, not a TransportError;
    it must come back as an actionable error instead of escaping into the agent turn."""
    monkeypatch.setenv(remote_mcp.RELAY_URL_ENV, url)

    result = asyncio.run(
        remote_mcp.call_edge_mcp(SITE, MCP, TOOL, {}, "user-1", timeout_seconds=5)
    )

    assert set(result) == {"error"}
    assert remote_mcp.RELAY_URL_ENV in result["error"]
    assert url in result["error"]


# --- 2. discover_external_mcps: static catalog, no connect, no secrets ---------


class FakeDiscoverIdentity:
    def __init__(self, configs):
        self.configs = configs

    def list_mcps(self):
        return list(self.configs)

    def get_mcp_config(self, name):
        return self.configs.get(name)

    def get_resolved_config(self, *args, **kwargs):
        raise AssertionError("edge MCPs must never resolve central secrets")


def install_discovery(monkeypatch, configs):
    def boom(*args, **kwargs):
        raise AssertionError("edge MCPs must never be connected from central")

    monkeypatch.setattr(agent_factory, "get_external_mcp_client", boom)
    monkeypatch.setattr(agent_factory, "_inject_config", boom)
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeDiscoverIdentity(configs))
    monkeypatch.setattr(agent_factory, "_external_mcp_tools", {})
    monkeypatch.setattr(agent_factory, "_external_remote_mcps", {})
    monkeypatch.setattr(agent_factory, "_last_discovery_time", 0.0)


def test_discover_external_mcps_uses_static_catalog_without_connecting(monkeypatch):
    install_discovery(monkeypatch, {SERVER_KEY: edge_mcp_payload()})

    asyncio.run(agent_factory.discover_external_mcps(force=True))

    tools = agent_factory._external_mcp_tools[SERVER_KEY]
    assert [t.name for t in tools] == [TOOL]
    # Verbatim schema: a top-level oneOf must survive the registry round trip.
    assert tools[0].inputSchema["oneOf"] == edge_mcp_payload()["tools"][0]["inputSchema"]["oneOf"]
    # Discovery records which keys are edge-exported, so registration never has to infer
    # it from the shape of the key.
    assert agent_factory._external_remote_mcps == {SERVER_KEY: (SITE, MCP)}


def test_discover_external_mcps_skips_edge_mcp_without_static_tools(monkeypatch, caplog):
    install_discovery(monkeypatch, {SERVER_KEY: edge_mcp_payload(tools=[])})

    with caplog.at_level(logging.DEBUG, logger="core.agent_factory"):
        asyncio.run(agent_factory.discover_external_mcps(force=True))

    assert agent_factory._external_mcp_tools == {}
    assert "published no tools" in caplog.text


# --- 3. build_agent: 4-part registration and edge dispatch ---------------------


def install_build_stubs(
    monkeypatch, agent_config, discovered, provider="google", model="gemini-2.5-flash",
    remote_keys=None,
):
    import core.memory as core_memory

    effective = SimpleNamespace(
        provider=provider, model=model, base_url=None, source="explicit"
    )

    class FakeIdentity:
        def get_agent_config(self, name):
            return dict(agent_config)

        def get_agent_skills(self, name):
            return ""

    def boom(*args, **kwargs):
        raise AssertionError("edge MCP tools must not use the central MCP client cache")

    async def fake_hub_client():
        return SimpleNamespace()

    async def fake_discover():
        return None

    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: FakeIdentity())
    monkeypatch.setattr(agent_factory, "get_external_mcp_client", boom)
    monkeypatch.setattr(agent_factory.llm_defaults, "needs_framework_defaults", lambda p, m: False)
    monkeypatch.setattr(
        agent_factory.llm_defaults, "resolve_effective_llm_config", lambda *a, **k: effective
    )
    monkeypatch.setattr(agent_factory.llm_factory, "get_provider_api_key", lambda provider: "k")
    monkeypatch.setattr(agent_factory, "resolve_model", lambda *a, **k: object())
    monkeypatch.setattr(agent_factory, "build_model_settings", lambda *a, **k: None)
    monkeypatch.setattr(agent_factory, "Agent", FakeAgent)
    monkeypatch.setattr(agent_factory, "get_hub_client", fake_hub_client)
    monkeypatch.setattr(agent_factory, "discover_external_mcps", fake_discover)
    monkeypatch.setattr(agent_factory, "_hub_tools_cache", [])
    monkeypatch.setattr(agent_factory, "_external_mcp_tools", discovered)
    # Edge-exported keys come from discovery metadata, not from a key-shaped guess.
    # `remote_keys` defaults to the single workload server; pass every key to model a
    # workspace with several edge MCPs (or none).
    keys = {SERVER_KEY} if remote_keys is None else set(remote_keys)
    monkeypatch.setattr(
        agent_factory,
        "_external_remote_mcps",
        {key: tuple(key.split("__", 1)) for key in discovered if key in keys},
    )
    monkeypatch.setattr(
        core_memory, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False)
    )


def build_edge_agent(monkeypatch, schema=None, **agent_config):
    config = {"name": "edge-agent", "provider": "google", "model": "gemini-2.5-flash"}
    config.update(agent_config)
    install_build_stubs(
        monkeypatch,
        config,
        {
            SERVER_KEY: [
                MCPToolDefinition(
                    name=TOOL, description="Tenant tools.", inputSchema=schema if schema else {}
                )
            ]
        },
        provider=config["provider"],
        model=config["model"],
    )
    return asyncio.run(agent_factory.build_agent("edge-agent"))


def test_build_agent_registers_four_part_name_when_server_allowed(monkeypatch):
    agent = build_edge_agent(monkeypatch, allowed_mcps=[SERVER_KEY])

    assert list(agent.tools) == [PREFIXED]
    # Never the bare tool name: bare names would collide across edge sites.
    assert TOOL not in agent.tools


def test_build_agent_registers_four_part_name_when_allowed_tools_lists_it(monkeypatch):
    agent = build_edge_agent(monkeypatch, allowed_tools=[PREFIXED])

    assert list(agent.tools) == [PREFIXED]


def test_build_agent_does_not_register_unallowed_edge_tool(monkeypatch):
    agent = build_edge_agent(
        monkeypatch, allowed_mcps=["other__server"], allowed_tools=["some_other_tool"]
    )

    assert agent.tools == {}


# --- 3b. allowed_mcps `<site>__*` wildcard (Phase 7) ---------------------------
#
# Optional sugar for "every MCP this site currently exports". Expanded per build against
# the discovery snapshot -- never stored expanded -- so it grants nothing for a site with
# no discovered servers, and it can never cross sites (`dc1__*` is not `dc10__x`).

OTHER_SITE = "dc10"
OTHER_MCP = "web"
OTHER_KEY = f"{OTHER_SITE}__{OTHER_MCP}"
OTHER_TOOL = "ping"
OTHER_PREFIXED = f"mcp__{OTHER_SITE}__{OTHER_MCP}__{OTHER_TOOL}"
CENTRAL_KEY = "example-mcp"
CENTRAL_PREFIXED = f"mcp__{CENTRAL_KEY}__lookup"


def _tool(name):
    return MCPToolDefinition(name=name, description=f"{name} tool.", inputSchema={})


def wildcard_workspace():
    """Two edge sites, plus a central MCP, exactly as discovery would report them."""
    discovered = {
        SERVER_KEY: [_tool(TOOL), _tool("list_actions")],
        OTHER_KEY: [_tool(OTHER_TOOL)],
        CENTRAL_KEY: [_tool("lookup")],
    }
    return discovered, {SERVER_KEY, OTHER_KEY}


def build_multi_mcp_agent(monkeypatch, **agent_config):
    config = {"name": "edge-agent", "provider": "google", "model": "gemini-2.5-flash"}
    config.update(agent_config)
    discovered, remote_keys = wildcard_workspace()
    install_build_stubs(
        monkeypatch,
        config,
        discovered,
        provider=config["provider"],
        model=config["model"],
        remote_keys=remote_keys,
    )
    return asyncio.run(agent_factory.build_agent("edge-agent"))


def test_wildcard_registers_every_tool_of_that_site(monkeypatch):
    agent = build_multi_mcp_agent(monkeypatch, allowed_mcps=[f"{SITE}__*"])

    assert sorted(agent.tools) == sorted(
        [PREFIXED, f"mcp__{SERVER_KEY}__list_actions"]
    )


def test_wildcard_does_not_cross_sites(monkeypatch):
    """`dc1__*` must not grant `dc10__x`: the grant compares the site segment, not a
    string prefix."""
    agent = build_multi_mcp_agent(monkeypatch, allowed_mcps=[f"{SITE}__*"])

    assert OTHER_PREFIXED not in agent.tools


def test_wildcard_never_grants_a_central_server(monkeypatch):
    agent = build_multi_mcp_agent(monkeypatch, allowed_mcps=[f"{SITE}__*"])

    assert CENTRAL_PREFIXED not in agent.tools
    assert "lookup" not in agent.tools


def test_wildcard_does_not_grant_a_central_server_named_like_the_site(monkeypatch):
    """Only a discovered *edge* server can satisfy a wildcard, so a central MCP whose
    name happens to equal the site is untouched."""
    install_build_stubs(
        monkeypatch,
        {"name": "edge-agent", "allowed_mcps": [f"{SITE}__*"]},
        {SITE: [_tool("lookup")]},
        remote_keys=set(),
    )

    agent = asyncio.run(agent_factory.build_agent("edge-agent"))

    assert agent.tools == {}


def test_exact_ref_still_works_next_to_a_wildcard(monkeypatch):
    agent = build_multi_mcp_agent(
        monkeypatch, allowed_mcps=[OTHER_KEY, f"{SITE}__*"]
    )

    assert OTHER_PREFIXED in agent.tools
    assert PREFIXED in agent.tools


def test_only_a_star_grants_nothing_and_does_not_raise(monkeypatch, caplog):
    with caplog.at_level(logging.DEBUG, logger="core.agent_factory"):
        agent = build_multi_mcp_agent(monkeypatch, allowed_mcps=["*"])

    assert agent.tools == {}
    assert "malformed allowed_mcps wildcard" in caplog.text


@pytest.mark.parametrize("entry", ["__*", "dc1*", "dc1__*__x", "dc1__**"])
def test_malformed_wildcards_grant_nothing_and_do_not_raise(monkeypatch, entry, caplog):
    with caplog.at_level(logging.DEBUG, logger="core.agent_factory"):
        agent = build_multi_mcp_agent(monkeypatch, allowed_mcps=[entry])

    assert agent.tools == {}
    assert "malformed allowed_mcps wildcard" in caplog.text


def test_wildcard_for_an_unknown_site_registers_nothing(monkeypatch, caplog):
    with caplog.at_level(logging.DEBUG, logger="core.agent_factory"):
        agent = build_multi_mcp_agent(monkeypatch, allowed_mcps=["dc9__*"])

    assert agent.tools == {}
    # Debug, not a warning: the edge may simply not have dialled in yet.
    assert "grants nothing until that edge connects" in caplog.text
    warnings = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING and r.name == "core.agent_factory"
    ]
    assert warnings == []


# The workload's meta-tool shape (v0.5.0 Phase 6): a root union with no top-level
# `properties`, which Gemini silently drops -> the model calls the tool with `{}`.
ROOT_UNION_SCHEMA = {
    "type": "object",
    "oneOf": [
        {
            "properties": {"action": {"const": "get"}, "id": {"type": "integer"}},
            "required": ["action", "id"],
        },
        {
            "properties": {"action": {"const": "list_actions"}},
            "required": ["action"],
        },
    ],
}

FLATTENED_ROOT_UNION_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"const": "get"},
        "id": {"type": "integer"},
    },
    "required": ["action"],
}


def build_edge_agent_with_schema(monkeypatch, schema, provider="google", model="gemini-2.5-flash"):
    """Build over one edge MCP tool carrying ``schema``; returns (agent, discovered tool)."""
    tool = MCPToolDefinition(name=TOOL, description="Tenant tools.", inputSchema=schema)
    install_build_stubs(
        monkeypatch,
        {"name": "edge-agent", "provider": provider, "model": model, "allowed_mcps": [SERVER_KEY]},
        {SERVER_KEY: [tool]},
        provider=provider,
        model=model,
    )
    return asyncio.run(agent_factory.build_agent("edge-agent")), tool


def test_build_agent_flattens_root_union_for_google_but_catalog_stays_verbatim(monkeypatch):
    schema = copy.deepcopy(ROOT_UNION_SCHEMA)
    agent, tool = build_edge_agent_with_schema(monkeypatch, schema)

    registered = agent._function_toolset.tools[PREFIXED]
    assert registered.function_schema.json_schema == FLATTENED_ROOT_UNION_SCHEMA
    # L6 is unaffected: the edge catalog the registry/discovery holds is verbatim.
    assert tool.inputSchema == ROOT_UNION_SCHEMA


def test_build_agent_keeps_root_union_for_openai(monkeypatch):
    schema = copy.deepcopy(ROOT_UNION_SCHEMA)
    agent, tool = build_edge_agent_with_schema(
        monkeypatch, schema, provider="openai", model="gpt-4o"
    )

    registered = agent._function_toolset.tools[PREFIXED]
    assert registered.function_schema.json_schema == ROOT_UNION_SCHEMA
    assert tool.inputSchema == ROOT_UNION_SCHEMA


def test_build_agent_leaves_a_non_union_edge_tool_unchanged_on_google(monkeypatch):
    schema = {
        "type": "object",
        "properties": {"tenant": {"type": "string"}},
        "required": ["tenant"],
    }
    agent, tool = build_edge_agent_with_schema(monkeypatch, schema)

    registered = agent._function_toolset.tools[PREFIXED]
    assert registered.function_schema.json_schema == schema
    assert tool.inputSchema == schema


def test_build_agent_edge_wrapper_calls_relay_caller(monkeypatch):
    agent = build_edge_agent(monkeypatch, allowed_mcps=[SERVER_KEY])
    calls = []

    async def fake_call_edge_mcp(site, mcp, tool, args, user_id, **kwargs):
        calls.append((site, mcp, tool, args, user_id))
        return {"content": [{"type": "text", "text": "done"}], "isError": False}

    monkeypatch.setattr(agent_factory, "call_edge_mcp", fake_call_edge_mcp)
    user_id_var.set("user-1")

    result = asyncio.run(agent.tools[PREFIXED](None, action="list"))

    assert result == [{"type": "text", "text": "done"}]
    assert calls == [(SITE, MCP, TOOL, {"action": "list"}, "user-1")]


def test_build_agent_edge_wrapper_turns_error_payload_into_error_string(monkeypatch):
    agent = build_edge_agent(monkeypatch, allowed_mcps=[SERVER_KEY])

    async def fake_call_edge_mcp(*args, **kwargs):
        return {"error": "MCP tool 'x' failed on edge 'dc1': session gone"}

    monkeypatch.setattr(agent_factory, "call_edge_mcp", fake_call_edge_mcp)
    user_id_var.set("user-1")

    result = asyncio.run(agent.tools[PREFIXED](None, action="list"))

    assert result == (
        f"Tool '{PREFIXED}' returned an error: MCP tool 'x' failed on edge 'dc1': session gone"
    )


# --- 4. Gateway use_tool dispatch through the edge seam ------------------------


def install_gateway(monkeypatch, mcp_config, edge_caller):
    # Every edge-published config carries `remote`; that block is what tells central the
    # 4-part name routes to an edge (never the name's own shape).
    config = None if mcp_config is None else {
        "remote": {"site": SITE, "mcp": MCP},
        **mcp_config,
    }
    monkeypatch.setattr(
        gateway.identity_mgr,
        "get_mcp_config",
        lambda name: config if name == SERVER_KEY else None,
    )
    # The external MCP client sits at the front door: the gateway mints the reserved
    # identity, which has no agent record of its own, so the target's published
    # exposure -- not an agent allowlist -- is what decides. Same as production.
    monkeypatch.setattr(
        gateway.identity_mgr, "get_agent_config", lambda name: None
    )
    agent_token.mint_for_run(
        tool_access.FRONT_DOOR_AGENT, "user-1", run_id="run-gateway"
    )

    async def fake_configured(tool_name, user_id=None):
        return dict(CONFIGURED)

    def boom(*args, **kwargs):
        raise AssertionError("4-part names must not go through mcp_client_cache")

    monkeypatch.setattr(gateway, "is_tool_configured", fake_configured)
    monkeypatch.setattr(gateway, "get_external_mcp_client", boom)
    monkeypatch.setattr(gateway, "call_edge_mcp", edge_caller)
    user_id_var.set("user-1")


def test_gateway_use_tool_dispatches_four_part_name_to_edge_caller(monkeypatch):
    calls = []

    async def fake_call_edge_mcp(site, mcp, tool, args, user_id, **kwargs):
        calls.append((site, mcp, tool, args, user_id))
        return {
            "content": [{"type": "text", "text": "ignored"}],
            "isError": False,
            "structuredContent": {"tenants": ["a"]},
        }

    install_gateway(monkeypatch, {"public": True}, fake_call_edge_mcp)

    result = asyncio.run(gateway.use_tool(FakeContext(), PREFIXED, {"action": "list"}))

    assert result == {"tenants": ["a"]}
    assert calls == [(SITE, MCP, TOOL, {"action": "list"}, "user-1")]


def test_gateway_use_tool_returns_content_text_when_unstructured(monkeypatch):
    async def fake_call_edge_mcp(*args, **kwargs):
        return {"content": [{"type": "text", "text": "line 1"}, {"type": "text", "text": "line 2"}]}

    install_gateway(monkeypatch, {"public": True}, fake_call_edge_mcp)

    assert asyncio.run(gateway.use_tool(FakeContext(), PREFIXED, {})) == "line 1\nline 2"


def test_gateway_use_tool_surfaces_edge_error_as_system_string(monkeypatch):
    async def fake_call_edge_mcp(*args, **kwargs):
        return {"error": f"MCP tool '{SERVER_KEY}__{TOOL}' is offline (edge '{SITE}' is not connected)."}

    install_gateway(monkeypatch, {"public": True}, fake_call_edge_mcp)

    result = asyncio.run(gateway.use_tool(FakeContext(), PREFIXED, {}))

    assert result == (
        f"SYSTEM: MCP tool '{SERVER_KEY}__{TOOL}' is offline (edge '{SITE}' is not connected)."
    )


def test_gateway_use_tool_denies_four_part_name_of_internal_edge_mcp(monkeypatch):
    async def never_called(*args, **kwargs):
        raise AssertionError("an internal edge MCP must never be executed")

    install_gateway(monkeypatch, {"public": False, "public_tools": []}, never_called)

    result = asyncio.run(gateway.use_tool(FakeContext(), PREFIXED, {}))

    assert result.startswith("SYSTEM: Access denied.")


# --- 5. published_exposure: 4-part forms ----------------------------
#
# The front-door exposure rule the evaluator takes as `public=`: a caller with no
# agent record may call exactly what a tool/MCP record publishes.
#
# The edge reading is registry-backed: these configs must carry the relay-written
# `remote` block, exactly like production. A 4-part name whose `<site>__<mcp>` key has
# no `remote` block is a *central* server (see the mcp__srv__do__thing tests).


def whitelisted(tool_name, mcp_config, key=SERVER_KEY):
    config = None if mcp_config is None else {"remote": {"site": SITE, "mcp": MCP}, **mcp_config}
    mgr = SimpleNamespace(get_mcp_config=lambda name: config if name == key else None)
    return asyncio.run(tool_search.published_exposure(tool_name, mgr))


def test_whitelist_allows_public_edge_mcp():
    assert whitelisted(PREFIXED, {"public": True, "public_tools": []}) is True


def test_whitelist_allows_listed_edge_tool_of_internal_mcp():
    config = {"public": False, "public_tools": [TOOL]}
    assert whitelisted(PREFIXED, config) is True


def test_whitelist_denies_unlisted_edge_tool():
    config = {"public": False, "public_tools": ["other_tool"]}
    assert whitelisted(PREFIXED, config) is False


def test_whitelist_denies_unknown_edge_mcp():
    assert whitelisted(PREFIXED, None) is False


def test_whitelist_denies_a_name_without_a_tool():
    assert whitelisted("mcp__only", {"public": True}) is False


def test_whitelist_resolves_an_edge_tool_whose_name_contains_the_separator():
    """The tool half is re-joined, so an edge tool name may itself contain `__`."""
    named = f"{PREFIXED}__extra"
    assert whitelisted(named, {"public": False, "public_tools": [f"{TOOL}__extra"]}) is True


def test_whitelist_central_three_part_name_unchanged():
    mgr = SimpleNamespace(
        get_mcp_config=lambda name: {"public": True} if name == "example-mcp" else None
    )
    assert asyncio.run(
        tool_search.published_exposure("mcp__example-mcp__list", mgr)
    ) is True


# --- 5b. a 4-part CENTRAL name is not an edge name ------------------------------
#
# A central MCP `srv` with a tool called `do__thing` produces `mcp__srv__do__thing`,
# which is 4 parts. Reading that as edge site `srv` / mcp `do` denied it and would have
# POSTed to the wrong endpoint; the registry decides, not the shape.

CENTRAL_SRV = "srv"
CENTRAL_TOOL = "do__thing"
CENTRAL_NAME = f"mcp__{CENTRAL_SRV}__{CENTRAL_TOOL}"


def test_whitelist_treats_a_four_part_central_name_as_central():
    mgr = SimpleNamespace(
        get_mcp_config=lambda name: (
            {"public": True, "secrets": []} if name == CENTRAL_SRV else None
        )
    )

    assert asyncio.run(tool_search.published_exposure(CENTRAL_NAME, mgr)) is True


def test_is_tool_configured_keeps_a_four_part_central_name_central(monkeypatch):
    """Central secret resolution must still happen for `mcp__srv__do__thing`."""
    monkeypatch.setattr(
        discovery.identity_mgr,
        "get_mcp_config",
        lambda name: {"name": CENTRAL_SRV, "secrets": ["CENTRAL_KEY"]} if name == CENTRAL_SRV else None,
    )
    monkeypatch.setattr(discovery.identity_mgr, "get_edge_status", lambda site: {"connected": True})
    monkeypatch.setattr(
        discovery.identity_mgr,
        "get_identity_config",
        lambda identity, category: {} if getattr(identity, "id", None) == "system" else {},
    )

    status = asyncio.run(discovery.is_tool_configured(CENTRAL_NAME, "user-1"))

    assert status["configured"] is False
    assert status["missing_secrets"] == ["CENTRAL_KEY"]


def test_gateway_dispatches_a_four_part_central_name_to_the_central_client(monkeypatch):
    # The gateway's external client sits at the front door: the reserved identity, no
    # record of its own, so the server's `public` flag decides.
    agent_token.mint_for_run(
        tool_access.FRONT_DOOR_AGENT, "user-1", run_id="run-gateway"
    )
    mgr = SimpleNamespace(
        get_mcp_config=lambda name: {"public": True} if name == CENTRAL_SRV else None,
        # The evaluator resolves the caller's record: the front door has none.
        get_agent_config=lambda name: None,
    )
    calls = []

    class FakeClient:
        async def call_tool(self, name, arguments, raise_on_error=False):
            calls.append((name, arguments))
            return SimpleNamespace(data={"ok": True}, structured_content=None, content=[])

    async def fake_client(server_name, user_id):
        return FakeClient()

    async def fake_configured(tool_name, user_id=None):
        return dict(CONFIGURED)

    def boom(*args, **kwargs):
        raise AssertionError("a central MCP name must never be POSTed to the relay")

    result = asyncio.run(
        tool_search.execute_whitelisted_tool(
            CENTRAL_NAME,
            {"x": 1},
            "user-1",
            identity_manager=mgr,
            is_configured=fake_configured,
            get_external_mcp_client_fn=fake_client,
            call_edge_mcp_fn=boom,
        )
    )

    assert result == {"ok": True}
    assert calls == [(CENTRAL_TOOL, {"x": 1})]


def test_a_central_mcp_named_with_a_double_underscore_registers_centrally(monkeypatch):
    """A central MCP named `a__b` stays central: only discovery metadata marks an edge."""
    config = {
        "name": "a__b",
        "transport": "stdio",
        "command": "npx",
        "tools": [{"name": "run", "description": "Run.", "inputSchema": {}}],
    }

    class Identity:
        def get_agent_config(self, name):
            return {"name": "central-agent", "allowed_mcps": ["a__b"]}

        def get_agent_skills(self, name):
            return ""

    import core.memory as core_memory

    effective = SimpleNamespace(
        provider="google", model="gemini-2.5-flash", base_url=None, source="explicit"
    )

    def boom(*args, **kwargs):
        raise AssertionError("an edge tool must not be registered for a central server")

    async def fake_hub_client():
        return SimpleNamespace()

    async def fake_discover():
        return None

    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: Identity())
    monkeypatch.setattr(agent_factory, "_register_remote_mcp_tool", boom)
    monkeypatch.setattr(agent_factory.llm_defaults, "needs_framework_defaults", lambda p, m: False)
    monkeypatch.setattr(
        agent_factory.llm_defaults, "resolve_effective_llm_config", lambda *a, **k: effective
    )
    monkeypatch.setattr(agent_factory.llm_factory, "get_provider_api_key", lambda provider: "k")
    monkeypatch.setattr(agent_factory, "resolve_model", lambda *a, **k: object())
    monkeypatch.setattr(agent_factory, "build_model_settings", lambda *a, **k: None)
    monkeypatch.setattr(agent_factory, "Agent", FakeAgent)
    monkeypatch.setattr(agent_factory, "get_hub_client", fake_hub_client)
    monkeypatch.setattr(agent_factory, "discover_external_mcps", fake_discover)
    monkeypatch.setattr(agent_factory, "_hub_tools_cache", [])
    monkeypatch.setattr(
        agent_factory,
        "_external_mcp_tools",
        {"a__b": [MCPToolDefinition(name="run", description="Run.", inputSchema={})]},
    )
    monkeypatch.setattr(agent_factory, "_external_remote_mcps", {})
    monkeypatch.setattr(
        core_memory, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False)
    )

    agent = asyncio.run(agent_factory.build_agent("central-agent"))

    # Registered under the bare tool name via the central path, not the 4-part edge form.
    assert list(agent.tools) == ["run"]


def test_save_mcp_config_refuses_a_central_name_containing_the_separator():
    from core.auth import IdentityManager

    class Client:
        def __init__(self):
            self.puts = []

        def put(self, key, value):
            self.puts.append(key)

    mgr = IdentityManager.__new__(IdentityManager)
    mgr.client = Client()

    with pytest.raises(ValueError, match="may not contain '__'"):
        mgr.save_mcp_config("a__b", {"name": "a__b"})

    # The relay's own `<site>__<mcp>` key is the one legitimate shape.
    mgr.save_mcp_config(
        "dc1__devops-cli", {"name": "dc1__devops-cli", "managed_by": "edge-relay"}
    )
    assert mgr.client.puts == ["/registry/mcps/dc1__devops-cli/config"]


def test_sync_mcp_warns_and_skips_a_name_containing_the_separator(capsys):
    from scripts import sync_to_db

    saved = []
    mgr = SimpleNamespace(save_mcp_config=lambda name, config: saved.append(name))

    sync_to_db.sync_mcp(mgr, {"name": "a__b", "transport": "stdio"})

    assert saved == []
    assert "may not contain '__'" in capsys.readouterr().out


def test_save_mcp_config_refuses_a_name_ending_in_underscore():
    """No `mcp__<server>__<tool>` ref can end in `_`, so the name is refused on write."""
    from core.auth import IdentityManager

    class Client:
        def __init__(self):
            self.puts = []

        def put(self, key, value):
            self.puts.append(key)

    mgr = IdentityManager.__new__(IdentityManager)
    mgr.client = Client()

    with pytest.raises(ValueError, match="may not end with '_'"):
        mgr.save_mcp_config("trailing_", {"name": "trailing_"})

    mgr.save_mcp_config("trailing-", {"name": "trailing-"})
    assert mgr.client.puts == ["/registry/mcps/trailing-/config"]


def test_save_tool_config_refuses_an_edge_tool_name_ending_in_underscore():
    """Only edge `<site>__<tool>` keys are reference segments; central tool names are
    addressed bare, so a trailing `_` stays legal for them."""
    from core.auth import IdentityManager

    class Client:
        def __init__(self):
            self.puts = []

        def put(self, key, value):
            self.puts.append(key)

    mgr = IdentityManager.__new__(IdentityManager)
    mgr.client = Client()

    with pytest.raises(ValueError, match="may not end with '_'"):
        mgr.save_tool_config(
            "plant-floor__boiler_status_",
            {"name": "boiler_status_", "managed_by": "edge-relay"},
        )

    mgr.save_tool_config("boiler_status_", {"name": "boiler_status_"})
    mgr.save_tool_config(
        "plant-floor__boiler_status", {"name": "boiler_status", "managed_by": "edge-relay"}
    )
    assert mgr.client.puts == [
        "/registry/tools/boiler_status_/config",
        "/registry/tools/plant-floor__boiler_status/config",
    ]


def test_sync_mcp_warns_and_skips_a_name_ending_in_underscore(capsys):
    from scripts import sync_to_db

    saved = []
    mgr = SimpleNamespace(save_mcp_config=lambda name, config: saved.append(name))

    sync_to_db.sync_mcp(mgr, {"name": "devops-cli_", "transport": "stdio"})

    assert saved == []
    assert "may not end with '_'" in capsys.readouterr().out


def test_a_four_part_allowed_tool_does_not_require_the_site_named_central_mcp():
    """`allowed_tools: [mcp__dc1__devops-cli__tenant_account_tools]` must resolve to the
    edge server's config, never to a central MCP that happens to be named `dc1`."""
    agent_config = {"allowed_tools": [PREFIXED]}
    tool_configs = {}
    mcp_configs = {
        SERVER_KEY: edge_mcp_payload(secrets=[]),
        # Same name as the edge site, with a required secret: reading the 4-part name as
        # a central 3-part name would make this a phantom requirement.
        SITE: {"name": SITE, "secrets": ["PHANTOM_SECRET"], "secret_groups": []},
    }

    resolved = discovery._resolve_agent_requirements(agent_config, tool_configs, mcp_configs)

    assert resolved["required_secrets"] == set()


def test_a_four_part_central_allowed_tool_resolves_its_own_server():
    agent_config = {"allowed_tools": [CENTRAL_NAME]}
    mcp_configs = {
        CENTRAL_SRV: {"name": CENTRAL_SRV, "secrets": ["CENTRAL_KEY"], "secret_groups": []},
        "srv__do": {"name": "srv__do", "secrets": ["EDGE_KEY"], "secret_groups": []},
    }

    resolved = discovery._resolve_agent_requirements(agent_config, {}, mcp_configs)

    # `srv__do` is registered, so the edge reading wins — that is the only case where
    # the 4-part shape is genuine, and it is still decided by the registry.
    assert resolved["required_secrets"] == {"EDGE_KEY"}



# --- 6. is_tool_configured: edge MCPs gated on connectivity --------------------


def install_config_identity(monkeypatch, mcp_configs, edge_status=None, identity_config=None):
    monkeypatch.setattr(
        discovery.identity_mgr,
        "get_mcp_config",
        lambda name: mcp_configs.get(name),
    )
    monkeypatch.setattr(
        discovery.identity_mgr,
        "get_edge_status",
        lambda site: edge_status if edge_status is not None else {"connected": True},
    )

    def central_secret_path(identity, category):
        assert identity_config is not None, "central secret resolution reached for an edge MCP"
        return identity_config

    monkeypatch.setattr(discovery.identity_mgr, "get_identity_config", central_secret_path)


def test_is_tool_configured_edge_tool_with_connected_edge(monkeypatch):
    install_config_identity(monkeypatch, {SERVER_KEY: edge_mcp_payload()})

    status = asyncio.run(discovery.is_tool_configured(PREFIXED, "user-1"))

    assert status["configured"] is True
    assert status["missing_secrets"] == []


def test_is_tool_configured_edge_tool_with_offline_edge(monkeypatch):
    install_config_identity(
        monkeypatch, {SERVER_KEY: edge_mcp_payload()}, edge_status={"connected": False}
    )

    status = asyncio.run(discovery.is_tool_configured(PREFIXED, "user-1"))

    assert status["configured"] is False
    assert status["missing_variables"] == [f"edge '{SITE}' is not connected"]


def test_is_tool_configured_edge_mcp_never_resolves_central_secrets(monkeypatch):
    """A declared-but-unresolvable central secret must not affect an edge MCP: the
    remote block short-circuits before any secret read (which asserts if reached)."""
    install_config_identity(
        monkeypatch,
        {SERVER_KEY: edge_mcp_payload(secrets=["SHOULD-NOT-BE-READ"])},
    )

    status = asyncio.run(discovery.is_tool_configured(PREFIXED, "user-1"))

    assert status["configured"] is True


def test_is_tool_configured_unknown_four_part_name_is_not_configured(monkeypatch):
    install_config_identity(monkeypatch, {})

    status = asyncio.run(discovery.is_tool_configured(PREFIXED, "user-1"))

    assert status["configured"] is False
    assert status["missing_secrets"] == []


def test_is_tool_configured_central_three_part_name_unchanged(monkeypatch):
    install_config_identity(
        monkeypatch,
        {"example-mcp": {"name": "example-mcp", "secrets": ["EXAMPLE_KEY"]}},
        identity_config={},
    )

    status = asyncio.run(
        discovery.is_tool_configured("mcp__example-mcp__list", "user-1")
    )

    assert status["configured"] is False
    assert status["missing_secrets"] == ["EXAMPLE_KEY"]


def test_is_tool_configured_malformed_mcp_name_is_not_configured(monkeypatch):
    install_config_identity(monkeypatch, {SERVER_KEY: edge_mcp_payload()})

    assert asyncio.run(discovery.is_tool_configured("mcp__only", "user-1"))["configured"] is False


# --- tool search: edge MCP tools rank under their 4-part name ------------------


def test_search_tools_lists_edge_mcp_tools_under_four_part_name(monkeypatch):
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_tool_configs", lambda: {})
    monkeypatch.setattr(
        tool_search.identity_mgr,
        "get_all_mcp_configs",
        lambda: {SERVER_KEY: edge_mcp_payload(public=True)},
    )
    # The relay indexes the embedding under the `use_tool` execution form.
    monkeypatch.setattr(
        tool_search.identity_mgr, "get_all_tool_embeddings", lambda: {PREFIXED: [1.0, 0.0]}
    )
    monkeypatch.setattr(tool_search.identity_mgr, "get_all_health_statuses", lambda kind: {})
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: [1.0, 0.0])

    results = asyncio.run(tool_search.search_tools("tenant accounts", limit=5))

    assert [r["name"] for r in results] == [PREFIXED]
    assert results[0]["source"] == SERVER_KEY


# --- models: the relay-written remote block ------------------------------------



def test_mcp_config_parses_remote_transport_without_command():
    config = MCPConfig(**edge_mcp_payload())

    assert config.transport == "remote"
    assert config.remote == RemoteMcpSpec(site=SITE, mcp=MCP)
    assert config.command is None
    assert config.tools[0].name == TOOL


def test_mcp_config_remote_is_optional():
    assert MCPConfig(name="example-mcp").remote is None


def test_remote_mcp_spec_uses_the_same_name_pattern_as_remote_tools():
    from core.models import RemoteToolSpec

    # Same rule as RemoteToolSpec: character set + length, with `__` banned (the
    # separator that makes `mcp__<site>__<mcp>__<tool>` and `<site>__<mcp>` splittable).
    for bad in ("bad name", "", "x" * 65, "a__b", "a__", "__a"):
        with pytest.raises(ValueError):
            RemoteMcpSpec(site=SITE, mcp=bad)
        with pytest.raises(ValueError):
            RemoteToolSpec(site=SITE, tool=bad)
    for good in ("devops-cli", "tenant_account_tools", "a_b", "a_"):
        assert RemoteMcpSpec(site=SITE, mcp=good).mcp == good
        assert RemoteToolSpec(site=SITE, tool=good).tool == good


# --- describe_tool_entry + lazy tool-search cards (P6) -------------------------

D_LOCAL_TOOL = "text_stats"
D_LOCAL_INPUTS = {
    "text": {"type": "string", "description": "Text to measure.", "required": True},
    "unit": {"type": "string"},
}
D_CENTRAL_SRV = "central-srv"
D_CENTRAL_TOOL = "do"
D_EDGE_SITE = "dc1"
D_EDGE_TOOL = "echo"
D_EDGE_TOOL_KEY = f"{D_EDGE_SITE}__{D_EDGE_TOOL}"
D_EDGE_MCP_KEY = f"{D_EDGE_SITE}__{MCP}"
D_EDGE_MCP_PREFIXED = f"mcp__{D_EDGE_SITE}__{MCP}__{TOOL}"


class DetailIdentity:
    """The registry reads ``describe_tool_entry``/``search_tools`` perform."""

    def __init__(self, tool_configs=None, mcp_configs=None):
        self.tool_configs = tool_configs or {}
        self.mcp_configs = mcp_configs or {}
        self.edge_configs = {}

    def get_tool_config(self, name):
        return self.tool_configs.get(name)

    def get_mcp_config(self, name):
        return self.mcp_configs.get(name)

    def get_edge_config(self, site):
        return self.edge_configs.get(site)


def install_detail_relay(monkeypatch, handler):
    """``core.tool_search`` builds its own client, so patch its module's ``httpx``."""
    requests = []

    def wrapped(request):
        requests.append(request)
        return handler(request)

    def factory(*args, **kwargs):
        return httpx.AsyncClient(
            transport=httpx.MockTransport(wrapped), timeout=kwargs.get("timeout")
        )

    monkeypatch.setattr(tool_search, "httpx", SimpleNamespace(AsyncClient=factory))
    monkeypatch.setenv(tool_search.RELAY_URL_ENV, RELAY_URL)
    return requests


def _edge_tool_config(tool=D_EDGE_TOOL, *, detail="lazy", inputs=None, site=D_EDGE_SITE):
    return {
        "name": f"{site}__{tool}",
        "description": f"{tool} summary",
        "runtime": "remote",
        "inputs": {} if inputs is None else inputs,
        "remote": {"site": site, "tool": tool},
        "managed_by": "edge-relay",
        "public": True,
        "detail": detail,
    }


def _edge_tool_detail_response(tool=D_EDGE_TOOL, *, site=D_EDGE_SITE):
    return {
        "site": site,
        "tool": tool,
        "detail": {"q": {"type": "string", "required": True}},
        "description": f"{tool} full description",
        "detail_state": "full",
        "cached": False,
    }


def test_describe_local_tool_reads_parameters_from_tool_yaml(monkeypatch):
    mgr = DetailIdentity(
        tool_configs={
            D_LOCAL_TOOL: {
                "name": D_LOCAL_TOOL,
                "description": "Count words in a string.",
                "inputs": D_LOCAL_INPUTS,
            }
        }
    )
    requests = install_detail_relay(
        monkeypatch, lambda request: pytest.fail("a local tool never touches the relay")
    )

    info = asyncio.run(tool_search.describe_tool_entry(D_LOCAL_TOOL, identity_manager=mgr))

    assert info == {
        "name": D_LOCAL_TOOL,
        "description": "Count words in a string.",
        "parameters": {
            "text": {
                "type": "string",
                "description": "Text to measure.",
                "required": True,
            },
            "unit": {"type": "string", "description": "", "required": False},
        },
        "source": "local",
        "detail": "full",
    }
    assert requests == []


def test_describe_central_mcp_tool_reads_parameters_from_its_schema(monkeypatch):
    mgr = DetailIdentity(
        mcp_configs={
            D_CENTRAL_SRV: {
                "name": D_CENTRAL_SRV,
                "transport": "stdio",
                "tools": [
                    {
                        "name": D_CENTRAL_TOOL,
                        "description": "Do the thing.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "n": {"type": "integer", "description": "How many."},
                                "label": {"type": "string"},
                            },
                            "required": ["n"],
                        },
                    }
                ],
            }
        }
    )
    requests = install_detail_relay(
        monkeypatch, lambda request: pytest.fail("a central MCP never touches the relay")
    )

    info = asyncio.run(
        tool_search.describe_tool_entry(
            f"mcp__{D_CENTRAL_SRV}__{D_CENTRAL_TOOL}", identity_manager=mgr
        )
    )

    assert info["parameters"] == {
        "n": {"type": "integer", "description": "How many.", "required": True},
        "label": {"type": "string", "description": "", "required": False},
    }
    assert info["source"] == D_CENTRAL_SRV
    assert info["detail"] == "full"
    assert requests == []


def test_describe_edge_tool_posts_the_bare_name(monkeypatch):
    mgr = DetailIdentity(tool_configs={D_EDGE_TOOL_KEY: _edge_tool_config()})
    requests = install_detail_relay(
        monkeypatch, lambda request: httpx.Response(200, json=_edge_tool_detail_response())
    )

    info = asyncio.run(
        tool_search.describe_tool_entry(D_EDGE_TOOL_KEY, identity_manager=mgr)
    )

    assert len(requests) == 1
    assert str(requests[0].url) == f"{RELAY_URL}/v1/sites/{D_EDGE_SITE}/tool_detail"
    assert json.loads(requests[0].content) == {"tool": D_EDGE_TOOL}
    assert info["name"] == D_EDGE_TOOL_KEY
    assert info["description"] == "echo full description"
    assert info["source"] == "local"
    assert info["detail"] == "full"
    assert info.get("unavailable") is not True


def test_describe_edge_tool_maps_the_inputs_to_parameters(monkeypatch):
    mgr = DetailIdentity(tool_configs={D_EDGE_TOOL_KEY: _edge_tool_config()})
    install_detail_relay(
        monkeypatch, lambda request: httpx.Response(200, json=_edge_tool_detail_response())
    )

    info = asyncio.run(
        tool_search.describe_tool_entry(D_EDGE_TOOL_KEY, identity_manager=mgr)
    )

    assert info["parameters"] == {
        "q": {"type": "string", "description": "", "required": True}
    }


def test_describe_edge_mcp_tool_posts_the_server_and_bare_tool(monkeypatch):
    """The relay's MCP payload carries the ``inputSchema`` itself as ``detail``."""
    schema = {"type": "object", "properties": {"action": {"type": "string"}}}
    mgr = DetailIdentity(
        mcp_configs={
            D_EDGE_MCP_KEY: edge_mcp_payload(
                public=True,
                detail="lazy",
                tools=[{"name": TOOL, "description": "Tenant account tools."}],
            )
        }
    )
    requests = install_detail_relay(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={
                "site": D_EDGE_SITE,
                "mcp": MCP,
                "tool": TOOL,
                "detail": schema,
                "description": "Tenant account tools.",
                "detail_state": "full",
                "cached": False,
            },
        ),
    )

    info = asyncio.run(
        tool_search.describe_tool_entry(D_EDGE_MCP_PREFIXED, identity_manager=mgr)
    )

    assert len(requests) == 1
    assert str(requests[0].url) == f"{RELAY_URL}/v1/sites/{D_EDGE_SITE}/mcp_tool_detail"
    assert json.loads(requests[0].content) == {"mcp": MCP, "tool": TOOL}
    assert info["detail"] == "full"
    assert info["description"] == "Tenant account tools."


def test_describe_edge_mcp_tool_maps_the_relay_schema_to_parameters(monkeypatch):
    schema = {
        "type": "object",
        "properties": {"action": {"type": "string", "description": "What to do."}},
        "required": ["action"],
    }
    mgr = DetailIdentity(
        mcp_configs={
            D_EDGE_MCP_KEY: edge_mcp_payload(
                public=True,
                detail="lazy",
                tools=[{"name": TOOL, "description": "Tenant account tools."}],
            )
        }
    )
    install_detail_relay(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={
                "site": D_EDGE_SITE,
                "mcp": MCP,
                "tool": TOOL,
                "detail": schema,
                "description": "Tenant account tools.",
                "detail_state": "full",
                "cached": False,
            },
        ),
    )

    info = asyncio.run(
        tool_search.describe_tool_entry(D_EDGE_MCP_PREFIXED, identity_manager=mgr)
    )

    assert info["parameters"] == {
        "action": {"type": "string", "description": "What to do.", "required": True}
    }


def test_describe_edge_tool_maps_a_503_edge_offline_to_unavailable(monkeypatch):
    mgr = DetailIdentity(tool_configs={D_EDGE_TOOL_KEY: _edge_tool_config()})
    install_detail_relay(
        monkeypatch,
        lambda request: httpx.Response(
            503,
            json={"error": {"code": "edge_offline", "message": "edge 'dc1' is not connected"}},
        ),
    )

    info = asyncio.run(tool_search.describe_tool_entry(D_EDGE_TOOL_KEY, identity_manager=mgr))

    assert info == {
        "name": D_EDGE_TOOL_KEY,
        "unavailable": True,
        "reason": "edge_offline",
    }


def test_describe_edge_tool_maps_a_connection_error_to_unavailable(monkeypatch):
    mgr = DetailIdentity(tool_configs={D_EDGE_TOOL_KEY: _edge_tool_config()})

    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    install_detail_relay(monkeypatch, handler)

    info = asyncio.run(tool_search.describe_tool_entry(D_EDGE_TOOL_KEY, identity_manager=mgr))

    assert info["unavailable"] is True
    assert info["reason"] == "edge_unavailable"


def test_describe_edge_tool_degrades_on_malformed_json(monkeypatch):
    mgr = DetailIdentity(tool_configs={D_EDGE_TOOL_KEY: _edge_tool_config()})
    install_detail_relay(monkeypatch, lambda request: httpx.Response(200, text="not json"))

    info = asyncio.run(tool_search.describe_tool_entry(D_EDGE_TOOL_KEY, identity_manager=mgr))

    assert info == {
        "name": D_EDGE_TOOL_KEY,
        "unavailable": True,
        "reason": "edge_unavailable",
    }


def install_search_registry(
    monkeypatch, tool_configs, mcp_configs=None, embeddings=None
):
    """Point the process-wide ``tool_search.identity_mgr`` at in-memory records."""
    mcp_configs = mcp_configs or {}
    embeddings = embeddings or {}
    mgr = tool_search.identity_mgr
    monkeypatch.setattr(mgr, "get_all_tool_configs", lambda: tool_configs)
    monkeypatch.setattr(mgr, "get_all_mcp_configs", lambda: mcp_configs)
    monkeypatch.setattr(mgr, "get_all_tool_embeddings", lambda: embeddings)
    monkeypatch.setattr(mgr, "get_all_health_statuses", lambda kind: {})
    monkeypatch.setattr(mgr, "get_tool_config", lambda name: tool_configs.get(name))
    monkeypatch.setattr(mgr, "get_mcp_config", lambda name: mcp_configs.get(name))
    monkeypatch.setattr(
        mgr, "get_edge_config", lambda site: {"name": site, "enabled": True}
    )
    monkeypatch.setattr(tool_search, "embed_text", lambda text, task_type: [1.0, 0.0])


def test_search_tools_renders_a_lazy_edge_card_summary_only(monkeypatch):
    tool_configs = {
        "dc1__lazy_tool": _edge_tool_config(
            "lazy_tool", detail="lazy", inputs={}
        ),
        "dc1__full_tool": _edge_tool_config(
            "full_tool", detail="full", inputs={"q": {"type": "string"}}
        ),
    }
    install_search_registry(
        monkeypatch,
        tool_configs,
        embeddings={"dc1__lazy_tool": [1.0, 0.0], "dc1__full_tool": [0.5, 0.5]},
    )
    requests = install_detail_relay(
        monkeypatch, lambda request: pytest.fail("detail=False must not read the relay")
    )

    results = asyncio.run(tool_search.search_tools("tool", limit=0))

    by_name = {card["name"]: card for card in results}
    assert by_name["dc1__lazy_tool"]["detail"] == "lazy"
    assert by_name["dc1__lazy_tool"]["parameters"] == {}
    assert by_name["dc1__lazy_tool"]["description"] == "lazy_tool summary"
    assert by_name["dc1__full_tool"]["detail"] == "full"
    assert by_name["dc1__full_tool"]["parameters"] == {
        "q": {"type": "string", "description": "", "required": False}
    }
    assert requests == []


def test_search_tools_detail_fetches_only_the_selected_lazy_cards(monkeypatch):
    tool_configs = {
        "dc1__lazy_a": _edge_tool_config("lazy_a", detail="lazy", inputs={}),
        "dc1__lazy_b": _edge_tool_config("lazy_b", detail="lazy", inputs={}),
        "dc1__full_c": _edge_tool_config(
            "full_c", detail="full", inputs={"q": {"type": "string"}}
        ),
    }
    install_search_registry(
        monkeypatch,
        tool_configs,
        embeddings={
            "dc1__lazy_a": [1.0, 0.0],
            "dc1__lazy_b": [1.0, 0.0],
            "dc1__full_c": [0.0, 1.0],
        },
    )
    requests = install_detail_relay(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json=_edge_tool_detail_response(json.loads(request.content)["tool"]),
        ),
    )

    summary_cards = asyncio.run(tool_search.search_tools("tool", limit=3, detail=False))
    lazy_count = sum(1 for card in summary_cards if card["detail"] == "lazy")
    assert lazy_count == 2

    detailed = asyncio.run(tool_search.search_tools("tool", limit=3, detail=True))

    # One relay read per lazy card in the returned window -- no more.
    assert len(requests) == lazy_count
    assert sorted(json.loads(request.content)["tool"] for request in requests) == [
        "lazy_a",
        "lazy_b",
    ]
    by_name = {card["name"]: card for card in detailed}
    for name in ("dc1__lazy_a", "dc1__lazy_b"):
        # The card is upgraded from the fetched detail: flag and description.
        assert by_name[name]["detail"] == "full"
        assert by_name[name]["description"] == f"{name.partition('__')[2]} full description"
    # The already-full card is served from the registry, never fetched.
    assert by_name["dc1__full_c"]["detail"] == "full"
    assert by_name["dc1__full_c"]["parameters"]["q"]["type"] == "string"


def test_search_tools_detail_fills_a_lazy_card_parameters(monkeypatch):
    tool_configs = {"dc1__lazy_a": _edge_tool_config("lazy_a", detail="lazy", inputs={})}
    install_search_registry(monkeypatch, tool_configs)
    install_detail_relay(
        monkeypatch,
        lambda request: httpx.Response(200, json=_edge_tool_detail_response("lazy_a")),
    )

    cards = asyncio.run(tool_search.search_tools("tool", limit=1, detail=True))

    assert cards[0]["detail"] == "full"
    assert cards[0]["parameters"] == {
        "q": {"type": "string", "description": "", "required": True}
    }


def test_search_tools_detail_is_bounded_by_the_limit(monkeypatch):
    tool_configs = {
        "dc1__lazy_a": _edge_tool_config("lazy_a", detail="lazy", inputs={}),
        "dc1__lazy_b": _edge_tool_config("lazy_b", detail="lazy", inputs={}),
    }
    install_search_registry(
        monkeypatch,
        tool_configs,
        embeddings={"dc1__lazy_a": [1.0, 0.0], "dc1__lazy_b": [1.0, 0.0]},
    )
    requests = install_detail_relay(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json=_edge_tool_detail_response(json.loads(request.content)["tool"]),
        ),
    )

    cards = asyncio.run(tool_search.search_tools("tool", limit=1, detail=True))

    assert [card["name"] for card in cards] == ["dc1__lazy_a"]
    assert len(requests) == 1
    assert json.loads(requests[0].content) == {"tool": "lazy_a"}


def test_search_tools_a_failed_detail_fetch_leaves_the_card_lazy(monkeypatch):
    tool_configs = {"dc1__lazy_a": _edge_tool_config("lazy_a", detail="lazy", inputs={})}
    install_search_registry(monkeypatch, tool_configs)
    install_detail_relay(
        monkeypatch,
        lambda request: httpx.Response(
            503, json={"error": {"code": "edge_offline", "message": "gone"}}
        ),
    )

    cards = asyncio.run(tool_search.search_tools("tool", limit=1, detail=True))

    assert cards[0]["name"] == "dc1__lazy_a"
    assert cards[0]["detail"] == "lazy"
    assert cards[0]["parameters"] == {}


def test_search_tools_keeps_an_unfetched_mcp_sibling_lazy(monkeypatch):
    """After one per-tool fetch, the sibling has no schema and must stay summary-only."""
    mcp_configs = {
        D_EDGE_MCP_KEY: edge_mcp_payload(
            public=True,
            detail="full",
            detail_tools=[TOOL],
            tools=[
                {
                    "name": TOOL,
                    "description": "Tenant account tools.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"action": {"type": "string"}},
                    },
                },
                {"name": "sibling_tool", "description": "Never fetched."},
            ],
        )
    }
    install_search_registry(monkeypatch, {}, mcp_configs=mcp_configs)
    install_detail_relay(
        monkeypatch, lambda request: pytest.fail("a full-flagged record reads no detail")
    )

    cards = asyncio.run(tool_search.search_tools("tenant", limit=0))

    by_name = {card["name"]: card for card in cards}
    sibling = by_name[f"mcp__{D_EDGE_SITE}__{MCP}__sibling_tool"]
    assert sibling["detail"] == "lazy"
    assert sibling["parameters"] == {}
