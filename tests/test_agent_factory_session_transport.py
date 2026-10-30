# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Central stdio MCPs become runner sessions, not host subprocesses.

The transport class and the FastMCP client are faked, so nothing connects: these
tests pin the request central builds (declared env only, manifest digest, agent,
user identity), the session kind for a warm session vs. discovery, and that the
old ``sanitized_env()`` merge is gone.
"""

import asyncio

import pytest

from core import agent_factory
from core.execution.spec import declared_env_keys, manifest_digest


class FakeRunnerStdioTransport:
    """Records the kwargs central would send to the runner."""

    created: list["FakeRunnerStdioTransport"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        FakeRunnerStdioTransport.created.append(self)


class FakeClient:
    """A FastMCP client stand-in: enter/exits, no connection, empty catalog."""

    def __init__(self, transport):
        self.transport = transport

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def list_tools(self):
        return []


class FakeIdentityManager:
    def __init__(self, configs, secrets=None, email="user@corp.example"):
        self.configs = configs
        self.secrets = secrets or {}
        self.email = email

    def get_mcp_config(self, name):
        return self.configs.get(name)

    def list_mcps(self):
        return list(self.configs)

    def get_resolved_config(self, user_id, category, keys=None):
        return {key: self.secrets[key] for key in (keys or ()) if key in self.secrets}

    def get_user(self, user_id):
        return {"email": self.email}


@pytest.fixture(autouse=True)
def clear_globals(monkeypatch):
    agent_factory.mcp_client_cache.clear()
    monkeypatch.setattr(agent_factory, "RunnerStdioTransport", FakeRunnerStdioTransport)
    monkeypatch.setattr(agent_factory, "FastMCPClient", FakeClient)
    monkeypatch.delenv("DEV_MODE", raising=False)
    # These tests pin the request the host builds, not who may open a session: the
    # token rollout window keeps the pre-runner gate out of the way (it is covered in
    # tests/test_enforcement_matrix.py).
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    FakeRunnerStdioTransport.created = []
    yield
    agent_factory.mcp_client_cache.clear()


def _config(**overrides):
    payload = {
        "name": "devops-cli",
        "transport": "stdio",
        "command": "node",
        "args": ["server.js"],
    }
    payload.update(overrides)
    return payload


def _install(monkeypatch, configs, **kwargs):
    manager = FakeIdentityManager(configs, **kwargs)
    monkeypatch.setattr(agent_factory, "get_identity_manager", lambda: manager)
    return manager


def test_get_external_mcp_client_builds_a_runner_session(monkeypatch):
    _install(
        monkeypatch,
        {
            "devops-cli": _config(
                env={"DEVOPS_PASSWORD": "{DEVOPS_PASSWORD}", "EXTRA_HEADER": "kept"},
                secrets=["DEVOPS_PASSWORD"],
            )
        },
        secrets={"DEVOPS_PASSWORD": "s3cret"},
    )

    client = asyncio.run(agent_factory.get_external_mcp_client("devops-cli", "user-1"))

    transport = FakeRunnerStdioTransport.created[0]
    assert client.transport is transport
    assert transport.kwargs["target"] == "devops-cli"
    assert len(transport.kwargs["session_key"]) == 32
    assert transport.kwargs["manifest_digest"] == manifest_digest(
        agent_factory.MCPConfig(**_config(
            env={"DEVOPS_PASSWORD": "{DEVOPS_PASSWORD}", "EXTRA_HEADER": "kept"},
            secrets=["DEVOPS_PASSWORD"],
        ))
    )
    # No identity in the request: the session's identity is the token's claims (the
    # per-call email/agent lookup is gone, v0.7.1 Phase 2).
    assert "agent" not in transport.kwargs
    assert "user_id" not in transport.kwargs
    assert "user_email" not in transport.kwargs
    assert transport.kwargs["deadline_ms"] == 2_100_000  # 30 min idle TTL + 5 min grace
    # Declared keys only: the resolved credential and the manifest's own `env:` keys.
    # The env block's keys have to be forwardable, or an interpolated value under a
    # differently-named key (`env: {DEVOPS_PASSWORD: "{PG_PASSWORD}"}`) is filtered out
    # and the container receives the literal braces.
    assert transport.kwargs["env"] == {
        "DEVOPS_PASSWORD": "s3cret",
        "EXTRA_HEADER": "kept",
    }


def test_a_declared_name_with_no_value_is_dropped_instead_of_sent_as_braces(monkeypatch):
    """`{OPT}` used to reach the remote origin. The edge drops the entry; so does central."""
    _install(
        monkeypatch,
        {
            "remote": _config(
                name="remote",
                transport="http",
                command="https://mcp.example/x",
                env={"Authorization": "Bearer {OPT}", "mcp-version": "v2"},
                optional_secrets=["OPT"],
            )
        },
    )
    captured = {}

    class FakeHttpTransport:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(agent_factory, "StreamableHttpTransport", FakeHttpTransport)

    asyncio.run(agent_factory.get_external_mcp_client("remote", "user-1"))

    assert captured["headers"] == {"mcp-version": "v2"}


def test_a_declared_name_with_a_value_is_still_substituted_for_a_remote_origin(monkeypatch):
    """The drop above must not cost a caller who does have the value."""
    _install(
        monkeypatch,
        {
            "remote": _config(
                name="remote",
                transport="http",
                command="https://mcp.example/x",
                env={"Authorization": "Bearer {OPT}"},
                optional_secrets=["OPT"],
            )
        },
        secrets={"OPT": "s3cret"},
    )
    captured = {}

    class FakeHttpTransport:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(agent_factory, "StreamableHttpTransport", FakeHttpTransport)

    asyncio.run(agent_factory.get_external_mcp_client("remote", "user-1"))

    assert captured["headers"] == {"Authorization": "Bearer s3cret"}


def test_get_external_mcp_client_does_not_name_the_background_agent_in_the_body(monkeypatch):
    """The agent name is a token claim now; the runner derives it, so the body has none."""
    _install(
        monkeypatch,
        {"devops-cli": _config(secrets=["DEVOPS_PASSWORD"])},
        secrets={"DEVOPS_PASSWORD": "s3cret"},
    )

    asyncio.run(agent_factory.get_external_mcp_client("devops-cli", "svc_agent_nightly"))

    assert "agent" not in FakeRunnerStdioTransport.created[0].kwargs


def test_get_external_mcp_client_never_merges_the_host_environment(monkeypatch):
    """The old ``sanitized_env()`` merge is gone: only the manifest's keys are sent."""
    _install(
        monkeypatch,
        {"devops-cli": _config(secrets=["DEVOPS_PASSWORD"])},
        secrets={"DEVOPS_PASSWORD": "s3cret"},
    )

    asyncio.run(agent_factory.get_external_mcp_client("devops-cli", "user-1"))

    env = FakeRunnerStdioTransport.created[0].kwargs["env"]
    config = agent_factory.MCPConfig(**_config(secrets=["DEVOPS_PASSWORD"]))
    assert set(env) <= declared_env_keys(config)
    for leaked in ("PATH", "HOME", "SESSION_SECRET", "RUNNER_TOKEN"):
        assert leaked not in env


def test_discover_external_mcps_opens_a_throwaway_discovery_session(monkeypatch):
    config = _config(env={"DEVOPS_PASSWORD": "literal", "EXTRA": "x"},
                     secrets=["DEVOPS_PASSWORD"])
    _install(monkeypatch, {"devops-cli": config},
             secrets={"DEVOPS_PASSWORD": "s3cret"})
    monkeypatch.setattr(agent_factory, "_external_mcp_tools", {})
    monkeypatch.setattr(agent_factory, "_external_remote_mcps", {})
    monkeypatch.setattr(agent_factory, "_last_discovery_time", 0.0)

    asyncio.run(agent_factory.discover_external_mcps(force=True))

    transport = FakeRunnerStdioTransport.created[0]
    assert transport.kwargs["kind"] == "discovery"
    assert transport.kwargs["target"] == "devops-cli"
    assert transport.kwargs["deadline_ms"] == 60_000
    assert len(transport.kwargs["session_key"]) == 32
    assert transport.kwargs["env"] == {"DEVOPS_PASSWORD": "literal", "EXTRA": "x"}


def test_discovery_of_an_http_server_is_unchanged(monkeypatch):
    """http/sse never touch the runner: they are remote origins."""
    _install(monkeypatch, {"remote": _config(name="remote", transport="http",
                                             command="https://mcp.example/x")})
    monkeypatch.setattr(agent_factory, "_external_mcp_tools", {})
    monkeypatch.setattr(agent_factory, "_external_remote_mcps", {})
    monkeypatch.setattr(agent_factory, "_last_discovery_time", 0.0)

    asyncio.run(agent_factory.discover_external_mcps(force=True))

    assert FakeRunnerStdioTransport.created == []


# --- the front door: who may open a stdio session ------------------------------ #


def _enforcing_run(monkeypatch, *, record=None, token_for=None, mcp_public=False):
    """Enforce mode + a minted run token, with the agent record faked in the registry."""
    import types

    from core import agent_token, auth, tool_access

    secret = "mcp-session-gate-secret-0123456789abcdef"
    monkeypatch.setenv("AGENT_TOKEN_SECRET", secret)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)

    class _NoPolicy:
        def put(self, key, value):
            raise AssertionError(f"no write expected: {key}")

        def get(self, key, **_kwargs):
            return None, None

    monkeypatch.setattr(tool_access, "_client", lambda: _NoPolicy())
    tool_access.reset_snapshot()

    manager = agent_factory.get_identity_manager()
    manager.get_agent_config = lambda name: record if name == "agent-a" else None
    manager.get_mcp_config = lambda name: {
        "name": name, "transport": "stdio", "command": "node", "public": mcp_public
    }

    monkeypatch.setattr(
        auth,
        "get_identity_manager",
        lambda: types.SimpleNamespace(
            get_agent_config=manager.get_agent_config,
            get_mcp_config=manager.get_mcp_config,
        ),
    )
    auth.agent_token_var.set(agent_token.mint(token_for or "agent-a", user_id="user-1"))
    return manager


def test_a_public_stdio_server_opens_a_session_for_the_front_door(monkeypatch):
    """No agent record + a server published `public: true` ⇒ the session opens."""
    _enforcing_run(monkeypatch, record=None, token_for="gateway", mcp_public=True)

    try:
        asyncio.run(agent_factory.get_external_mcp_client("devops-cli", "user-1"))
    finally:
        from core import auth

        auth.agent_token_var.set(None)

    assert len(FakeRunnerStdioTransport.created) == 1


def test_a_non_public_stdio_server_refuses_the_front_door_with_access_denied(monkeypatch):
    """No record + a non-public server ⇒ a distinguishable access-denied refusal."""
    from core import auth
    from core.tool_gate import ToolAccessDenied

    _enforcing_run(monkeypatch, record=None, token_for="gateway", mcp_public=False)

    try:
        with pytest.raises(PermissionError) as caught:
            asyncio.run(agent_factory.get_external_mcp_client("devops-cli", "user-1"))
    finally:
        auth.agent_token_var.set(None)

    assert isinstance(caught.value, ToolAccessDenied)
    assert "access_denied" in str(caught.value)
    assert "devops-cli" in str(caught.value)
    # Never a session: no container was requested.
    assert FakeRunnerStdioTransport.created == []


def test_a_record_without_the_server_grant_is_denied(monkeypatch):
    """An agent record that lacks the server is refused before the runner is asked."""
    from core import auth

    _enforcing_run(
        monkeypatch, record={"allowed_tools": ["text_stats"]}, token_for="agent-a"
    )

    try:
        with pytest.raises(PermissionError) as caught:
            asyncio.run(agent_factory.get_external_mcp_client("devops-cli", "user-1"))
    finally:
        auth.agent_token_var.set(None)

    assert "access_denied" in str(caught.value)
    assert FakeRunnerStdioTransport.created == []
