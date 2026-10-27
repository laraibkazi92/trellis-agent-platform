# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Wiring invariants for Phase 3 enforcement.

The unit matrices drive `_authorize_call` and `_authorize` directly; these tests
pin the two things that were wrong when only those were covered: the shipped
compose must actually configure every enforcement point, and `run_tool` must
authorize *before* dispatching and never hand the token to the tool.
"""

import asyncio
import json
from pathlib import Path

import pytest
import yaml

from core import agent_token, hub
from core.models import ToolConfig

ROOT = Path(__file__).resolve().parents[1]

# Services that must be able to verify (or mint) agent tokens.
ENFORCING_SERVICES = {
    "host",
    "hub",
    "gateway",
    "taskiq-worker",
    "edge-relay",
    "runner",
}

# Services that evaluate the tool-access decision or render it (the admin page reads
# the mode and the loaded policy). `runner` is deliberately absent: it has no registry
# and makes no allowlist/group-rule decision.
TOOL_ACCESS_SERVICES = (
    "host",
    "hub",
    "gateway",
    "taskiq-worker",
    "edge-relay",
    "ui",
)


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN_SECRET", "test-secret-that-is-long-enough-123456")
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    yield


@pytest.fixture(autouse=True)
def _no_live_policy(monkeypatch):
    """The evaluator's policy read must never reach a developer's local etcd.

    These tests pin wiring, not policy resolution. With no registry the snapshot is
    `policy_unavailable` and every call is denied, so the result would otherwise depend
    on whether an etcd happens to be listening on 127.0.0.1:2379 -- which is exactly
    how this suite passed locally and failed in CI.
    """
    from core import tool_access

    class _NoPolicy:
        def get(self, key, **_kwargs):
            return None, None

        def put(self, key, value):
            raise AssertionError(f"unexpected policy write: {key}")

    monkeypatch.setattr(tool_access, "_client", lambda: _NoPolicy())
    tool_access.reset_snapshot()
    yield
    tool_access.reset_snapshot()


def _services(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["services"]


def test_central_compose_configures_every_enforcement_point():
    services = _services(ROOT / "docker-compose.yml")
    for name in ENFORCING_SERVICES:
        env = services[name].get("environment") or {}
        assert "AGENT_TOKEN_SECRET" in env, f"{name} cannot verify agent tokens"
        assert env["ENFORCE_AGENT_TOKENS"].endswith("enforce)") or "enforce" in str(
            env["ENFORCE_AGENT_TOKENS"]
        )
    # The runner has no allowlist to check any more: its knob is gone.
    assert "RUNNER_AUTHORIZATION" not in services["runner"]["environment"]


def test_compose_passes_the_tool_access_switch_to_every_enforcing_process():
    """`TOOL_ACCESS_MODE` must be interpolated for all six services.

    `host` and `ui` are `.env`-fed, hub/edge-relay/gateway/taskiq-worker only read the
    variables listed here. `.env` is read from the file, NOT from the shell, so a shell
    override (`TOOL_ACCESS_MODE=shadow docker compose up`) would flip the four while
    leaving host and ui on the code default -- a stack where the console/MCP gate and
    the admin page disagree with the hub. Every service that can evaluate or render the
    mode must carry the interpolation.
    """
    services = _services(ROOT / "docker-compose.yml")
    for name in TOOL_ACCESS_SERVICES:
        env = services[name].get("environment") or {}
        assert env.get("TOOL_ACCESS_MODE", "").endswith("enforce}"), name


def test_the_edge_proxy_never_verifies_an_agent_token():
    """v0.7.1: the edge trusts the relay's frame identity; the proxy has no key.

    The **runner** keeps the key: it verifies signature and expiry, derives the agent
    and the output dir from the token's claims, and (since Phase 4) makes no allowlist
    decision at all -- the relay already made it for the call it forwarded.
    """
    services = _services(ROOT / "deploy" / "proxy" / "docker-compose.yml")

    proxy_env = services["trellis-proxy"]["environment"]
    assert "AGENT_TOKEN_SECRET" not in proxy_env
    assert "ENFORCE_AGENT_TOKENS" not in proxy_env

    runner_env = services["runner"]["environment"]
    assert "AGENT_TOKEN_SECRET" in runner_env
    assert "set AGENT_TOKEN_SECRET" in runner_env["AGENT_TOKEN_SECRET"]
    # Enforcing by default: the edge runner verifies the token the relay forwarded.
    assert "off" not in runner_env["ENFORCE_AGENT_TOKENS"]
    # Gone in Phase 4 with the runner's own allowlist check.
    assert "RUNNER_AUTHORIZATION" not in runner_env


def _config(**overrides) -> ToolConfig:
    data = dict(name="echo", description="d", runtime="python", entrypoint="echo.py")
    data.update(overrides)
    return ToolConfig(**data)


def test_run_tool_authorizes_before_dispatch_and_strips_the_token(monkeypatch):
    seen = {}

    async def fake_attempt(config, tool_dir, arguments, user_id, claims=None, agent_token=None):
        seen["arguments"] = dict(arguments)
        seen["claims"] = claims
        seen["token"] = agent_token
        return {"ok": True}

    monkeypatch.setattr(hub, "_run_tool_attempt", fake_attempt)
    monkeypatch.setattr(
        hub.identity_mgr,
        "get_agent_config",
        lambda name: {"allowed_tools": ["echo"]} if name == "agent-a" else None,
    )
    monkeypatch.setattr(hub.identity_mgr, "record_tool_usage", lambda *a, **k: None)

    token = agent_token.mint("agent-a", user_id="user-1", run_id="run-1")
    result = asyncio.run(
        hub.run_tool(
            _config(),
            None,
            {"text": "hi", "__user_id": "user-1", "__agent_token": token},
        )
    )

    assert result == {"ok": True}
    assert "__agent_token" not in seen["arguments"]
    assert "__agent_name" not in seen["arguments"]
    assert seen["claims"].agent == "agent-a"
    assert seen["token"].startswith("t1.")


def test_run_tool_refuses_a_forged_token_without_dispatching(monkeypatch):
    called = []

    async def fake_attempt(*args, **kwargs):
        called.append(True)
        return {"ok": True}

    monkeypatch.setattr(hub, "_run_tool_attempt", fake_attempt)
    monkeypatch.setattr(
        hub.identity_mgr, "get_agent_config", lambda name: {"allowed_tools": ["echo"]}
    )
    monkeypatch.setattr(hub.identity_mgr, "record_tool_usage", lambda *a, **k: None)

    forged = agent_token.mint("agent-a", user_id="user-1")[:-4] + "AAAA"
    result = asyncio.run(
        hub.run_tool(
            _config(), None, {"__user_id": "user-1", "__agent_token": forged}
        )
    )

    assert "access_denied" in result["error"]
    assert called == []


def test_expiring_token_is_refreshed_at_a_boundary(monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    original = agent_token.mint("agent-a", user_id="user-1", run_id="run-1", ttl_s=1)
    refreshed = agent_token.refresh(original)
    claims = agent_token.verify(refreshed)
    assert refreshed != original
    assert claims.agent == "agent-a"
    assert claims.run_id == "run-1"
    # A comfortably valid token is returned unchanged.
    assert agent_token.refresh(refreshed) == refreshed
