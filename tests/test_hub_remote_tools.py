# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Remote (edge-hosted) tool dispatch — trellis-proxy P1.

Pins the contract between ``core/hub.py`` and the edge relay's internal
``POST /v1/sites/{site}/call`` endpoint, plus the discovery-side connectivity
gating:

- ``load_tool_configs`` accepts a remote config with no ``rel_path`` and returns
  ``(config, None)`` instead of dropping it.
- ``_run_remote`` maps every relay status onto the same result-dict shape a local
  tool returns, records a health event per outcome, and only raises
  ``TransientToolError`` for transient conditions the tool opted into.
- ``run_tool`` routes remote configs to the relay and still records usage exactly
  once per invocation.
- ``register_tools`` refuses a remote tool whose ``remote.site`` disagrees with
  its ``<site>__`` registry prefix.
- ``is_tool_configured`` gates a remote tool on edge connectivity (fail-open).

HTTP seam: the tests monkeypatch :func:`core.hub._remote_client`, the per-call
``httpx.AsyncClient`` factory. That is the narrowest seam that still exercises
the real request construction and the real response-status mapping — the handler
receives a genuine ``httpx.Request`` (URL + JSON body are asserted) and returns
mock responses, so no network, no relay process, and no patching of httpx
internals is involved.
"""

import asyncio
import json

import httpx
import pytest

from core import discovery, hub
from core.models import ToolConfig


SITE = "plant-floor"
TOOL = "boiler_status"
REGISTRY_NAME = f"{SITE}__{TOOL}"
RELAY_URL = "http://relay.internal:8100"


@pytest.fixture(autouse=True)
def _reset_registered_tools():
    """The reconcile state is process-global; each test starts from a clean hub."""
    hub._registered_tools.clear()
    hub._unreadable_tool_names.clear()
    yield
    hub._registered_tools.clear()
    hub._unreadable_tool_names.clear()


@pytest.fixture(autouse=True)
def _no_real_identity_lookup(monkeypatch):
    """The email lookup is etcd I/O; each test pins its own profile instead.

    DEV_MODE is forced off so a developer's shell cannot turn a profile lookup into
    the dev fallback email.
    """
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.delenv("DEV_USER_EMAIL", raising=False)
    monkeypatch.setattr(hub.identity_mgr, "get_user", lambda user_id: None)


def make_remote_config(**kw):
    payload = {
        "name": REGISTRY_NAME,
        "description": "boiler status",
        "runtime": "remote",
        "remote": {"site": SITE, "tool": TOOL},
        "inputs": {"unit": {"type": "string", "required": True}},
    }
    payload.update(kw)
    return ToolConfig(**payload)


class FakeMCP:
    """Stand-in for FastMCP that captures registered tool handlers."""

    def __init__(self):
        self.handlers = {}

    def tool(self, name=None, description=None):
        def decorator(fn):
            self.handlers[name] = fn
            return fn

        return decorator

    # The reconcile path removes a changed tool before re-adding it. Expose the
    # same tiny surface FastMCP's LocalProvider offers.
    @property
    def local_provider(self):
        return self

    def remove_tool(self, name):
        self.handlers.pop(name, None)


def install_fake_health(monkeypatch):
    events = []

    def fake_record_event(entity_type, name, is_success, error_details=None):
        events.append(
            {
                "entity_type": entity_type,
                "name": name,
                "is_success": is_success,
                "error_details": error_details,
            }
        )
        return {}

    monkeypatch.setattr(hub.health_monitor, "record_event", fake_record_event)
    return events


def install_fake_usage(monkeypatch):
    calls = []
    monkeypatch.setattr(
        hub.identity_mgr,
        "record_tool_usage",
        lambda user_id, tool_name: calls.append((user_id, tool_name)),
    )
    return calls


def install_transport(monkeypatch, handler):
    """Install the httpx seam: hub._remote_client -> MockTransport client."""
    requests = []

    def wrapped(request):
        requests.append(request)
        return handler(request)

    def factory(timeout_seconds):
        return httpx.AsyncClient(
            transport=httpx.MockTransport(wrapped), timeout=timeout_seconds
        )

    monkeypatch.setattr(hub, "_remote_client", factory)
    monkeypatch.setenv("EDGE_RELAY_URL", RELAY_URL + "/")
    monkeypatch.setenv("TOOL_EXECUTION_TIMEOUT", "300")
    return requests


def json_response(status, payload):
    def handler(_request):
        return httpx.Response(status, json=payload)

    return handler


def relay_error(status, code, message="boom"):
    return json_response(status, {"error": {"code": code, "message": message}})


def run_remote(config, arguments, user_id=None):
    return asyncio.run(hub._run_remote(config, arguments, user_id))


async def _run_tool_and_drain(config, arguments):
    """Await run_tool, then drain the fire-and-forget usage task."""
    result = await hub.run_tool(config, None, arguments)
    await asyncio.gather(*hub._background_tasks, return_exceptions=True)
    return result


# --- load_tool_configs ---------------------------------------------------------


def test_load_tool_configs_accepts_remote_without_rel_path(monkeypatch):
    stored = {
        "name": REGISTRY_NAME,
        "description": "boiler status",
        "runtime": "remote",
        "remote": {"site": SITE, "tool": TOOL},
        "inputs": {"unit": {"type": "string", "required": True}},
        "managed_by": "edge-relay",
        "retry_on_transient": False,
        # deliberately no rel_path: edge tools have no central directory
    }
    monkeypatch.setattr(hub.identity_mgr, "list_tools", lambda: [REGISTRY_NAME])
    monkeypatch.setattr(hub.identity_mgr, "get_tool_config_safe", lambda name: (True, dict(stored)))

    configs = hub.load_tool_configs()

    assert list(configs) == [REGISTRY_NAME]
    config, tool_dir = configs[REGISTRY_NAME]
    assert tool_dir is None
    assert config.remote.site == SITE
    assert config.remote.tool == TOOL
    assert config.runtime == "remote"
    assert config.retry_on_transient is False


# --- _run_remote mapping -------------------------------------------------------


def test_remote_dispatch_success_returns_result_and_records_health(monkeypatch):
    config = make_remote_config()
    health = install_fake_health(monkeypatch)
    requests = install_transport(
        monkeypatch, json_response(200, {"tool": TOOL, "result": {"temp": 42}})
    )

    result = run_remote(config, {"unit": "1"}, user_id="user-1")

    assert result == {"temp": 42}
    assert health == [
        {"entity_type": "tool", "name": REGISTRY_NAME, "is_success": True, "error_details": None}
    ]
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == f"{RELAY_URL}/v1/sites/{SITE}/call"
    body = json.loads(request.content)
    assert body == {
        "tool": TOOL,
        "args": {"unit": "1"},
        "deadline_ms": 330_000,  # (300 s tunable + 30 s slack) * 1000
        "user": "user-1",
        # No profile in the registry stub, so nothing is forwarded.
        "user_email": None,
    }
    # The tunable resolves to a float; the relay's strict schema rejects 330000.0.
    # Caught by the P1 end-to-end run, not by equality (float == int is True).
    assert isinstance(body["deadline_ms"], int)


def test_remote_call_forwards_the_resolved_user_email(monkeypatch):
    monkeypatch.setattr(
        hub.identity_mgr, "get_user", lambda user_id: {"email": "user-1@corp.example"}
    )
    config = make_remote_config()
    install_fake_health(monkeypatch)
    requests = install_transport(
        monkeypatch, json_response(200, {"tool": TOOL, "result": {"ok": True}})
    )

    run_remote(config, {}, user_id="user-1")

    body = json.loads(requests[0].content)
    assert body["user"] == "user-1"
    assert body["user_email"] == "user-1@corp.example"


def test_remote_call_in_dev_mode_sends_the_dev_user_email(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    called = []
    monkeypatch.setattr(
        hub.identity_mgr, "get_user", lambda user_id: called.append(user_id)
    )
    config = make_remote_config()
    install_fake_health(monkeypatch)
    requests = install_transport(
        monkeypatch, json_response(200, {"tool": TOOL, "result": {"ok": True}})
    )

    run_remote(config, {}, user_id="user-1")

    body = json.loads(requests[0].content)
    assert body["user_email"] == "dev-user@local.host"
    # DEV_MODE short-circuits the registry read entirely.
    assert called == []


def test_remote_call_for_a_service_agent_forwards_no_email(monkeypatch):
    """A service identity has no user profile, so no email is forwarded at all."""
    called = []
    monkeypatch.setattr(
        hub.identity_mgr,
        "get_user",
        lambda user_id: called.append(user_id) or None,
    )
    config = make_remote_config()
    install_fake_health(monkeypatch)
    requests = install_transport(
        monkeypatch, json_response(200, {"tool": TOOL, "result": {"ok": True}})
    )

    run_remote(config, {}, user_id="svc_agent_triage")

    body = json.loads(requests[0].content)
    assert body["user"] == "svc_agent_triage"
    assert body["user_email"] is None
    # The lookup was attempted (and found nothing) rather than skipped by DEV_MODE.
    assert called == ["svc_agent_triage"]


def test_remote_call_survives_an_identity_lookup_failure(monkeypatch):
    """An etcd hiccup costs the call its email, never the call itself."""
    def boom(user_id):
        raise RuntimeError("etcd unavailable")

    monkeypatch.setattr(hub.identity_mgr, "get_user", boom)
    config = make_remote_config()
    install_fake_health(monkeypatch)
    requests = install_transport(
        monkeypatch, json_response(200, {"tool": TOOL, "result": {"ok": True}})
    )

    result = run_remote(config, {}, user_id="user-1")

    assert result == {"ok": True}
    assert json.loads(requests[0].content)["user_email"] is None


def test_build_tool_env_exports_the_caller_email_for_local_tools(monkeypatch, tmp_path):
    """The refactor onto resolve_user_email must not drop the local-tool variable."""
    monkeypatch.setattr(
        hub.identity_mgr, "get_user", lambda user_id: {"email": "local@corp.example"}
    )
    monkeypatch.setattr(
        hub.identity_mgr, "generate_execution_token", lambda user_id: "token"
    )
    monkeypatch.setattr(
        hub.identity_mgr, "get_config", lambda key, default=None: default
    )
    config = ToolConfig(
        name="echo", description="echo", runtime="python", entrypoint="main.py"
    )

    env = asyncio.run(hub._build_tool_env(config, tmp_path, "user-1"))

    assert env["TRELLIS_USER_EMAIL"] == "local@corp.example"


def test_remote_tool_level_error_is_returned_and_recorded_as_failure(monkeypatch):
    config = make_remote_config()
    health = install_fake_health(monkeypatch)
    install_transport(
        monkeypatch,
        json_response(200, {"tool": TOOL, "error": {"code": "tool_error", "message": "pump jammed"}}),
    )

    result = run_remote(config, {})

    assert result == {
        "error": f"Tool '{REGISTRY_NAME}' failed on edge '{SITE}': pump jammed"
    }
    assert len(health) == 1
    assert health[0]["is_success"] is False
    assert health[0]["error_details"] == result["error"]


@pytest.mark.parametrize(
    "status,code,expected",
    [
        (400, "invalid_arguments", f"Tool '{REGISTRY_NAME}' rejected the arguments: bad arg"),
        (404, "unknown_tool", f"Edge '{SITE}' no longer exports tool '{REGISTRY_NAME}'"),
        (504, "edge_timeout", f"Tool '{REGISTRY_NAME}' timed out on edge '{SITE}'"),
        (
            503,
            "edge_offline",
            f"Tool '{REGISTRY_NAME}' is offline (edge '{SITE}' is not connected).",
        ),
        (
            503,
            "edge_disconnected",
            f"Tool '{REGISTRY_NAME}' is offline (edge '{SITE}' is not connected).",
        ),
    ],
)
def test_remote_error_status_mappings_never_raise(monkeypatch, status, code, expected):
    config = make_remote_config()
    health = install_fake_health(monkeypatch)
    install_transport(monkeypatch, relay_error(status, code, "bad arg"))

    result = run_remote(config, {})

    assert expected in result["error"]
    assert len(health) == 1
    assert health[0]["is_success"] is False


def test_remote_edge_overloaded_is_transient_only_when_opted_in(monkeypatch):
    config = make_remote_config(retry_on_transient=True)
    install_fake_health(monkeypatch)
    install_transport(monkeypatch, relay_error(503, "edge_overloaded", "too many in flight"))

    with pytest.raises(hub.TransientToolError) as excinfo:
        run_remote(config, {})

    assert SITE in str(excinfo.value)


def test_remote_edge_overloaded_without_retry_returns_error(monkeypatch):
    config = make_remote_config(retry_on_transient=False)
    health = install_fake_health(monkeypatch)
    install_transport(monkeypatch, relay_error(503, "edge_overloaded", "too many in flight"))

    result = run_remote(config, {})

    assert "is busy" in result["error"]
    assert health[0]["is_success"] is False


@pytest.mark.parametrize("retry_on_transient", [True, False])
def test_remote_transport_error_honors_retry_on_transient(monkeypatch, retry_on_transient):
    config = make_remote_config(retry_on_transient=retry_on_transient)
    health = install_fake_health(monkeypatch)

    def handler(_request):
        raise httpx.ConnectError("name resolution failed")

    install_transport(monkeypatch, handler)

    if retry_on_transient:
        with pytest.raises(hub.TransientToolError):
            run_remote(config, {})
        # A retryable condition is not a health event: stamina retries it first.
        assert health == []
    else:
        result = run_remote(config, {})
        assert "is unreachable" in result["error"]
        assert SITE in result["error"]
        assert health[0]["is_success"] is False


def test_remote_unknown_status_reports_code_and_bounded_preview(monkeypatch):
    config = make_remote_config()
    health = install_fake_health(monkeypatch)

    def handler(_request):
        return httpx.Response(500, text="x" * 500)

    install_transport(monkeypatch, handler)

    result = run_remote(config, {})

    assert "HTTP 500" in result["error"]
    # The body preview is capped at 200 chars, never the whole body.
    assert result["error"].count("x") == 200
    assert health[0]["is_success"] is False


def test_remote_hub_read_timeout_is_never_retried(monkeypatch):
    """A client-side read timeout may have run on the edge, so it is not transient
    even when the tool opted into retries; the error dict names the edge."""
    config = make_remote_config(retry_on_transient=True)
    health = install_fake_health(monkeypatch)
    attempts = []

    def handler(_request):
        attempts.append(1)
        raise httpx.ReadTimeout("relay did not answer")

    install_transport(monkeypatch, handler)

    result = run_remote(config, {})

    assert "did not respond on edge" in result["error"]
    assert SITE in result["error"]
    assert len(attempts) == 1
    assert health[0]["is_success"] is False


def test_remote_dispatch_never_logs_arguments_or_results(monkeypatch, caplog):
    import logging

    config = make_remote_config()
    install_fake_health(monkeypatch)
    install_transport(monkeypatch, json_response(200, {"tool": TOOL, "result": {"secret": "RESULT-SECRET"}}))

    with caplog.at_level(logging.DEBUG, logger="core.hub"):
        run_remote(config, {"unit": "ARG-SECRET"})

    assert "ARG-SECRET" not in caplog.text
    assert "RESULT-SECRET" not in caplog.text


# --- register_tools ------------------------------------------------------------


def test_register_tools_skips_remote_site_name_mismatch(monkeypatch, caplog):
    import logging

    config = make_remote_config(remote={"site": "other-site", "tool": TOOL})
    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: {REGISTRY_NAME: (config, None)})
    monkeypatch.setattr(hub, "mcp", fake_mcp)

    with caplog.at_level(logging.ERROR, logger="core.hub"):
        hub.register_tools()

    assert fake_mcp.handlers == {}
    assert "does not match the registry prefix" in caplog.text


def test_register_tools_registers_a_matching_remote_tool(monkeypatch):
    config = make_remote_config()
    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: {REGISTRY_NAME: (config, None)})
    monkeypatch.setattr(hub, "mcp", fake_mcp)

    hub.register_tools()

    handler = fake_mcp.handlers[REGISTRY_NAME]
    # The catalog schema drives the generated signature, so the edge's inputs
    # are visible to the model exactly like a local tool's.
    assert "unit" in handler.__signature__.parameters


# --- run_tool ------------------------------------------------------------------


def test_run_tool_records_usage_once_for_remote_call(monkeypatch):
    config = make_remote_config()
    install_fake_health(monkeypatch)
    usage = install_fake_usage(monkeypatch)
    install_transport(monkeypatch, json_response(200, {"tool": TOOL, "result": {"ok": True}}))

    result = asyncio.run(_run_tool_and_drain(config, {"__user_id": "user-1", "unit": "1"}))

    assert result == {"ok": True}
    assert usage == [("user-1", REGISTRY_NAME)]


def test_run_tool_remote_background_agent_sends_user_id_only(monkeypatch):
    """Edge tools have no agent-identity semantics: `user` carries the identity and
    `__agent_name` is never invented as an argument (a local tool would receive it)."""
    config = make_remote_config()
    install_fake_health(monkeypatch)
    install_fake_usage(monkeypatch)
    requests = install_transport(
        monkeypatch, json_response(200, {"tool": TOOL, "result": {"ok": True}})
    )

    asyncio.run(_run_tool_and_drain(config, {"__user_id": "svc_agent_triage", "unit": "1"}))

    body = json.loads(requests[0].content)
    assert body["user"] == "svc_agent_triage"
    assert "__agent_name" not in body["args"]
    assert body["args"] == {"unit": "1"}


# --- discovery -----------------------------------------------------------------


REMOTE_TOOL_CONFIG = {
    "name": REGISTRY_NAME,
    "description": "boiler status",
    "runtime": "remote",
    "remote": {"site": SITE, "tool": TOOL},
    "managed_by": "edge-relay",
}


def test_is_tool_configured_remote_configured_when_edge_connected(monkeypatch):
    monkeypatch.setattr(
        discovery.identity_mgr, "get_tool_config", lambda name: dict(REMOTE_TOOL_CONFIG)
    )
    # raising=False: get_edge_status lands with the P1 registry work; the test
    # must still run against a checkout that does not have it yet.
    monkeypatch.setattr(
        discovery.identity_mgr,
        "get_edge_status",
        lambda site: {"connected": True},
        raising=False,
    )

    status = asyncio.run(discovery.is_tool_configured(REGISTRY_NAME, user_id="user-1"))

    assert status == {
        "configured": True,
        "missing_secrets": [],
        "missing_variables": [],
        "optional_missing_secrets": [],
    }


@pytest.mark.parametrize("edge_status", [{"connected": False}, None, {}])
def test_is_tool_configured_remote_not_configured_when_edge_offline(monkeypatch, edge_status):
    monkeypatch.setattr(
        discovery.identity_mgr, "get_tool_config", lambda name: dict(REMOTE_TOOL_CONFIG)
    )
    monkeypatch.setattr(
        discovery.identity_mgr,
        "get_edge_status",
        lambda site: edge_status,
        raising=False,
    )

    status = asyncio.run(discovery.is_tool_configured(REGISTRY_NAME))

    assert status["configured"] is False
    # Same shape as the secret-based path; the edge is named as the missing part.
    assert set(status) == {
        "configured",
        "missing_secrets",
        "missing_variables",
        "optional_missing_secrets",
    }
    assert status["missing_secrets"] == []
    assert status["missing_variables"] == [f"edge '{SITE}' is not connected"]


def test_is_tool_configured_remote_fails_open_on_registry_error(monkeypatch):
    monkeypatch.setattr(
        discovery.identity_mgr, "get_tool_config", lambda name: dict(REMOTE_TOOL_CONFIG)
    )

    def broken(site):
        raise RuntimeError("etcd unavailable")

    monkeypatch.setattr(discovery.identity_mgr, "get_edge_status", broken, raising=False)

    status = asyncio.run(discovery.is_tool_configured(REGISTRY_NAME))

    assert status["configured"] is True


def test_discover_tools_labels_remote_tools_with_their_site(monkeypatch):
    local_config = {
        "name": "echo",
        "description": "local",
        "runtime": "python",
        "entrypoint": "main.py",
        "rel_path": "workspace/tools/echo",
    }
    monkeypatch.setattr(
        discovery.identity_mgr,
        "get_all_tool_configs",
        lambda: {"echo": local_config, REGISTRY_NAME: dict(REMOTE_TOOL_CONFIG)},
    )
    monkeypatch.setattr(discovery.identity_mgr, "get_all_mcp_configs", lambda: {})
    monkeypatch.setattr(discovery.identity_mgr, "get_all_health_statuses", lambda kind: {})

    tools = {t["name"]: t for t in asyncio.run(discovery.discover_tools())}

    assert tools[REGISTRY_NAME]["runtime"] == "remote"
    assert tools[REGISTRY_NAME]["site"] == SITE
    # Non-remote payloads keep their existing shape.
    assert "site" not in tools["echo"]
    assert tools["echo"]["runtime"] == "python"


# --- runtime reconcile -------------------------------------------------------------
#
# register_tools() used to run once at boot, which made a newly connected edge's
# tools searchable but not executable. These pin the reconcile behaviour that
# fixes it.


def test_register_tools_reconciles_a_tool_added_after_startup(monkeypatch):
    registry = {}
    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: dict(registry))
    monkeypatch.setattr(hub, "mcp", fake_mcp)

    assert hub.register_tools() == 0

    registry[REGISTRY_NAME] = (make_remote_config(), None)

    assert hub.register_tools() == 1
    assert REGISTRY_NAME in fake_mcp.handlers


def test_register_tools_is_idempotent_for_an_unchanged_tool(monkeypatch):
    registry = {REGISTRY_NAME: (make_remote_config(), None)}
    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: dict(registry))
    monkeypatch.setattr(hub, "mcp", fake_mcp)

    assert hub.register_tools() == 1
    assert hub.register_tools() == 0


def test_register_tools_removes_a_tool_that_disappeared(monkeypatch):
    registry = {REGISTRY_NAME: (make_remote_config(), None)}
    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: dict(registry))
    monkeypatch.setattr(hub, "mcp", fake_mcp)

    hub.register_tools()
    registry.clear()

    assert hub.register_tools() == 1
    assert REGISTRY_NAME not in fake_mcp.handlers


def test_register_tools_replaces_a_tool_whose_schema_changed(monkeypatch):
    registry = {REGISTRY_NAME: (make_remote_config(), None)}
    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: dict(registry))
    monkeypatch.setattr(hub, "mcp", fake_mcp)

    hub.register_tools()
    first = fake_mcp.handlers[REGISTRY_NAME]

    changed = make_remote_config(inputs={"unit": {"type": "string", "required": True}, "limit": {"type": "integer"}})
    registry[REGISTRY_NAME] = (changed, None)

    assert hub.register_tools() == 1
    assert fake_mcp.handlers[REGISTRY_NAME] is not first


# --- rate limiting -----------------------------------------------------------------


def test_rate_limited_returns_an_error_without_retrying(monkeypatch):
    # The relay always writes retry_on_transient=False for remote tools; no replay.
    config = make_remote_config(retry_on_transient=False)
    health = install_fake_health(monkeypatch)
    requests = install_transport(
        monkeypatch, relay_error(429, "rate_limited", "too many calls")
    )

    result = run_remote(config, {"unit": "1"})

    assert "rate-limiting" in result["error"]
    assert len(requests) == 1
    assert health[-1]["is_success"] is False


def test_rate_limited_is_retryable_only_when_the_tool_opts_in(monkeypatch):
    config = make_remote_config(retry_on_transient=True)
    install_fake_health(monkeypatch)
    install_transport(monkeypatch, relay_error(429, "rate_limited"))

    with pytest.raises(hub.TransientToolError):
        run_remote(config, {"unit": "1"})


def test_register_tools_keeps_the_table_when_the_registry_read_fails(monkeypatch):
    """A failed etcd read must not look like 'every tool was deleted'.

    load_tool_configs returns None for a read failure and {} for an empty registry;
    conflating them removed every tool from every agent until the next tick.
    """
    registry = {REGISTRY_NAME: (make_remote_config(), None)}
    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: dict(registry))
    monkeypatch.setattr(hub, "mcp", fake_mcp)

    assert hub.register_tools() == 1

    monkeypatch.setattr(hub, "load_tool_configs", lambda: None)

    assert hub.register_tools() == 0
    assert REGISTRY_NAME in fake_mcp.handlers
    assert REGISTRY_NAME in hub._registered_tools


def test_load_tool_configs_returns_none_when_the_registry_cannot_be_listed(monkeypatch):
    """None means 'could not read' and must be distinct from {} ('empty registry')."""

    def _boom():
        raise RuntimeError("etcd down")

    monkeypatch.setattr(hub.identity_mgr, "list_tools", _boom)

    assert hub.load_tool_configs() is None

    monkeypatch.setattr(hub.identity_mgr, "list_tools", lambda: [])

    assert hub.load_tool_configs() == {}


def test_an_unreadable_tool_config_is_protected_from_the_prune(monkeypatch):
    """One corrupt key must not unregister a working tool, and must not stop the pass."""
    good = make_remote_config()
    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "mcp", fake_mcp)

    # First pass: the tool is readable and gets registered.
    monkeypatch.setattr(hub.identity_mgr, "list_tools", lambda: [REGISTRY_NAME])
    monkeypatch.setattr(
        hub.identity_mgr,
        "get_tool_config_safe",
        lambda name: (True, good.model_dump(mode="json")),
    )
    assert hub.register_tools() == 1
    assert REGISTRY_NAME in fake_mcp.handlers

    # Second pass: the same entry is now unreadable (corrupt JSON / transient read
    # failure). It stays registered and the pass still completes.
    monkeypatch.setattr(hub.identity_mgr, "get_tool_config_safe", lambda name: (False, None))

    assert hub.register_tools() == 0
    assert REGISTRY_NAME in fake_mcp.handlers


def test_an_oversized_remote_result_is_truncated_like_a_local_tool(monkeypatch):
    """The edge is semi-trusted: the hub enforces the 96k context cap itself."""
    config = make_remote_config()
    install_fake_health(monkeypatch)
    install_transport(
        monkeypatch,
        json_response(200, {"tool": TOOL, "result": {"blob": "x" * 100_000}}),
    )

    result = run_remote(config, {}, user_id="user-1")

    assert "Global Safety Net" in result["error"]
    assert result["partial_data_preview"].endswith("[TRUNCATED DUE TO SAFETY LIMITS]")
    assert len(result["partial_data_preview"]) < 100_000


def test_run_remote_actually_retries_a_transient_failure(monkeypatch):
    """The retry decorator belongs on _run_remote, not on a helper it replaced."""
    config = make_remote_config(retry_on_transient=True)
    install_fake_health(monkeypatch)
    attempts = []

    def flaky(_request):
        attempts.append(1)
        if len(attempts) < 3:
            raise httpx.ConnectError("relay hop refused")
        return httpx.Response(200, json={"tool": TOOL, "result": {"temp": 21}})

    install_transport(monkeypatch, flaky)

    result = run_remote(config, {})

    assert result == {"temp": 21}
    assert len(attempts) == 3


@pytest.mark.parametrize("url", ["garbage/v1", "http://[::1/v1"])
def test_remote_dispatch_never_raises_on_a_misconfigured_relay_url(monkeypatch, url):
    """A bad EDGE_RELAY_URL raises InvalidURL/UnsupportedProtocol, which is not a
    TransportError: without an explicit clause it escaped into the agent turn."""
    config = make_remote_config()
    health = install_fake_health(monkeypatch)
    monkeypatch.setenv("EDGE_RELAY_URL", url)

    result = run_remote(config, {})

    assert "EDGE_RELAY_URL" in result["error"]
    assert url in result["error"]
    assert health[0]["is_success"] is False
