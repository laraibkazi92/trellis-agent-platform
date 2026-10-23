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
    assert transport.kwargs["agent"] is None
    assert transport.kwargs["user_id"] == "user-1"
    assert transport.kwargs["user_email"] == "user@corp.example"
    assert transport.kwargs["deadline_ms"] == 2_100_000  # 30 min idle TTL + 5 min grace
    # Declared keys only: the literal for an undeclared key never reaches the runner.
    assert transport.kwargs["env"] == {"DEVOPS_PASSWORD": "s3cret"}


def test_get_external_mcp_client_names_the_background_agent(monkeypatch):
    _install(
        monkeypatch,
        {"devops-cli": _config(secrets=["DEVOPS_PASSWORD"])},
        secrets={"DEVOPS_PASSWORD": "s3cret"},
    )

    asyncio.run(agent_factory.get_external_mcp_client("devops-cli", "svc_agent_nightly"))

    assert FakeRunnerStdioTransport.created[0].kwargs["agent"] == "nightly"


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
    assert transport.kwargs["env"] == {"DEVOPS_PASSWORD": "literal"}


def test_discovery_of_an_http_server_is_unchanged(monkeypatch):
    """http/sse never touch the runner: they are remote origins."""
    _install(monkeypatch, {"remote": _config(name="remote", transport="http",
                                             command="https://mcp.example/x")})
    monkeypatch.setattr(agent_factory, "_external_mcp_tools", {})
    monkeypatch.setattr(agent_factory, "_external_remote_mcps", {})
    monkeypatch.setattr(agent_factory, "_last_discovery_time", 0.0)

    asyncio.run(agent_factory.discover_external_mcps(force=True))

    assert FakeRunnerStdioTransport.created == []
