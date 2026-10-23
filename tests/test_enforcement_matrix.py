# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The enforcement matrix: {hub, runner} x {no token, bad sig, expired, X for Y}.

Both enforcement points are driven directly, without a container backend or a live
relay: ``core.hub._authorize_call`` (local tools) and
``core.execution.runner._authorize`` (sessions, console, discovery). The two relay
routes are covered in ``tests/test_edge_relay.py``.

The property under test is the one in the plan's invariant 9: no call executes
without a valid, unexpired token and without the agent's effective allowlist being
re-resolved by the party that owns the resource.
"""

import asyncio
import json
import time

import pytest
import yaml

from core import agent_token, hub
from core.execution import runner as runner_module
from core.execution.contract import ExecRequest, SessionCreateRequest
from core.models import ToolConfig

SECRET = "enforcement-matrix-secret-0123456789abcdef"
SESSION_KEY = "a" * 32
ECHO = ToolConfig(
    name="echo", description="Echo a block of text back.", runtime="python", entrypoint="echo.py"
)

HUB_AGENTS = {
    "agent-a": {"allowed_tools": ["echo", "execute"]},
    "agent-b": {"allowed_tools": []},
}

RUNNER_AGENTS = {
    "agent-a": {
        "name": "agent-a",
        "type": "user_agent",
        "allowed_tools": ["execute"],
        "allowed_mcps": ["coralogix"],
    },
    "agent-b": {
        "name": "agent-b",
        "type": "user_agent",
        "allowed_tools": [],
        "allowed_mcps": [],
    },
}


# --------------------------------------------------------------------------- #
# token fixtures: the four grid columns
# --------------------------------------------------------------------------- #


def _bad_token(case: str, agent: str = "agent-a") -> str | None:
    """One token per refusal column; ``expired`` is relative to the real clock."""
    if case == "missing":
        return None
    if case == "bad_sig":
        token = agent_token.mint(agent)
        head, signature = token.rsplit(".", 1)
        index = len(signature) // 2
        flipped = "A" if signature[index] != "A" else "B"
        return f"{head}.{signature[:index]}{flipped}{signature[index + 1:]}"
    if case == "expired":
        # ttl 1 s, minted 120 s ago: past exp + CLOCK_SKEW_S by a wide margin.
        return agent_token.mint(agent, ttl_s=1, now=time.time() - 120)
    raise AssertionError(f"unknown case {case!r}")


BAD_TOKEN_CASES = ["missing", "bad_sig", "expired"]


# --------------------------------------------------------------------------- #
# hub: core.hub._authorize_call
# --------------------------------------------------------------------------- #


@pytest.fixture
def hub_env(monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.setattr(
        hub.identity_mgr, "get_agent_config", lambda name: HUB_AGENTS.get(name)
    )
    return HUB_AGENTS


def _hub_call(token):
    """``_authorize_call`` is async because it reads the registry off-loop."""
    return asyncio.run(hub._authorize_call(ECHO, token, "user-1"))


def _assert_hub_denied(denial, *, contains: str = "access_denied") -> None:
    assert denial is not None, "expected the hub to refuse the call"
    assert contains in denial["error"], denial


@pytest.mark.parametrize("case", BAD_TOKEN_CASES)
def test_hub_enforce_refuses_a_bad_token(hub_env, monkeypatch, case):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")

    claims, denial = _hub_call(_bad_token(case))

    assert claims is None
    _assert_hub_denied(denial)


def test_hub_enforce_refuses_a_token_for_an_agent_without_the_tool(hub_env, monkeypatch):
    """Agent X's token presented for Y's tool: Y's allowlist does not grant `echo`."""
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")

    claims, denial = _hub_call(agent_token.mint("agent-b"))

    assert claims is not None and claims.agent == "agent-b"
    _assert_hub_denied(denial, contains="not in agent 'agent-b' allowlist")


def test_hub_enforce_refuses_an_unknown_agent(hub_env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")

    _, denial = _hub_call(agent_token.mint("ghost"))

    _assert_hub_denied(denial, contains="unknown agent 'ghost'")


def test_hub_enforce_allows_the_granted_tool(hub_env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")

    claims, denial = _hub_call(agent_token.mint("agent-a", user_id="user-1"))

    assert denial is None
    assert claims is not None
    assert claims.agent == "agent-a"
    assert claims.user_id == "user-1"


@pytest.mark.parametrize("case", BAD_TOKEN_CASES)
def test_hub_log_mode_only_records_the_denial(hub_env, monkeypatch, case):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")

    claims, denial = _hub_call(_bad_token(case))

    assert denial is None
    assert claims is None


def test_hub_off_mode_short_circuits(hub_env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "off")

    claims, denial = _hub_call("not-a-token")

    assert (claims, denial) == (None, None)


# --------------------------------------------------------------------------- #
# runner: core.execution.runner._authorize
# --------------------------------------------------------------------------- #


@pytest.fixture
def runner_env(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    for name, config in RUNNER_AGENTS.items():
        directory = root / "agents" / name
        directory.mkdir(parents=True)
        (directory / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")

    monkeypatch.setenv("WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv("DEV_MODE", raising=False)
    runner_module.reset_for_tests()
    try:
        yield root
    finally:
        runner_module.reset_for_tests()


def _session(agent, token, *, target="coralogix", kind="mcp_session"):
    return SessionCreateRequest(
        kind=kind, target=target, agent=agent, session_key=SESSION_KEY, agent_token=token
    )


def _console(agent, token):
    return ExecRequest(
        kind="console",
        target="console",
        agent=agent,
        command="echo hi",
        agent_token=token,
    )


def _tool(agent, token, target="echo"):
    return ExecRequest(kind="tool", target=target, agent=agent, agent_token=token)


def _assert_runner_denied(denial) -> None:
    assert denial is not None, "expected the runner to refuse the call"
    assert denial.status_code == 403
    assert json.loads(denial.body)["detail"]["code"] == "access_denied"


@pytest.mark.parametrize("case", BAD_TOKEN_CASES)
def test_runner_enforce_refuses_a_bad_token(runner_env, case):
    denial = runner_module._authorize(_session("agent-a", _bad_token(case)))

    _assert_runner_denied(denial)


def test_runner_enforce_refuses_a_session_for_an_mcp_outside_the_allowlist(runner_env):
    """Agent X's token, Y's MCP: agent-b declares no MCPs at all."""
    denial = runner_module._authorize(_session("agent-b", agent_token.mint("agent-b")))

    _assert_runner_denied(denial)


def test_runner_enforce_allows_the_granted_mcp(runner_env):
    assert runner_module._authorize(_session("agent-a", agent_token.mint("agent-a"))) is None


def test_runner_console_requires_execute(runner_env):
    assert runner_module._authorize(_console("agent-a", agent_token.mint("agent-a"))) is None
    _assert_runner_denied(
        runner_module._authorize(_console("agent-b", agent_token.mint("agent-b")))
    )


def test_runner_discovery_needs_no_token(runner_env):
    """A discovery run is a throwaway catalog read: no agent owns it.

    The runner control socket already requires the runner bearer token, and the
    caller (central MCP registration / edge catalog refresh) has no agent run to
    mint from -- so a missing agent token must not break discovery.
    """
    assert runner_module._authorize(_session(None, None, target="catalog", kind="discovery")) is None


def test_runner_discovery_still_accepts_a_valid_token(runner_env):
    payload = _session("agent-a", agent_token.mint("agent-a"), target="x", kind="discovery")

    assert runner_module._authorize(payload) is None


def test_runner_refuses_a_token_for_a_different_agent(runner_env):
    payload = _session("agent-a", agent_token.mint("agent-b"))

    _assert_runner_denied(runner_module._authorize(payload))


def test_runner_refuses_an_unknown_agent(runner_env):
    _assert_runner_denied(
        runner_module._authorize(_session("ghost", agent_token.mint("ghost")))
    )


def test_runner_gateway_bypasses_the_allowlist(runner_env):
    # The gateway is a system principal: it has no manifest on disk, by design.
    assert runner_module._authorize(_console("gateway", agent_token.mint("gateway"))) is None


def test_runner_tool_calls_are_the_hubs_decision(runner_env):
    """For ``kind=tool`` the runner proves the token only; the hub owns the allowlist.

    `echo` is deliberately absent from agent-a's on-disk manifest here.
    """
    assert runner_module._authorize(_tool("agent-a", agent_token.mint("agent-a"))) is None


def test_runner_off_mode_short_circuits(runner_env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "off")
    bad = _bad_token("bad_sig")

    assert runner_module._authorize(_session("agent-b", bad)) is None
    assert runner_module._authorize(_console("agent-b", bad)) is None
