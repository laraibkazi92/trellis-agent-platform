# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The enforcement matrix: {hub, runner} x {no token, bad sig, expired, X for Y}.

Both enforcement points are driven directly, without a container backend or a live
relay: ``core.hub._authorize_call`` (local tools) and
``core.execution.runner._authorize`` (tool calls, sessions, console, discovery). The
two relay routes are covered in ``tests/test_edge_relay.py``.

The property under test is the one in the plan's invariant 9: no call executes
without a valid, unexpired token, and every party re-resolves the allowlist for the
resources it owns (the hub for tools, the runner for sessions and console).
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
    # The supervisor is an agent like any other: its own manifest decides.
    "supervisor": {"allowed_tools": ["echo"]},
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
# Deliberately NOT here: `supervisor`. Its manifest is an image asset
# (`core/assets/supervisor/config.yaml`, read by scripts/sync_to_db.py) and is never
# materialised under `workspace/`, so fabricating one here would test a layout that
# does not exist -- and hide the runner bug that layout causes.

# A second, non-public tool: no agent's allowlist grants it here, so it is the
# denial probe for callers that used to be exempt.
NETCTL = ToolConfig(
    name="netctl", description="Inspect cluster nodes.", runtime="python", entrypoint="netctl.py"
)
PUBLIC_ECHO = ToolConfig(
    name="echo",
    description="Echo a block of text back.",
    runtime="python",
    entrypoint="echo.py",
    public=True,
)


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


def _hub_call(token, config=ECHO):
    """``_authorize_call`` is async because it reads the registry off-loop."""
    return asyncio.run(hub._authorize_call(config, token))


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


# --- no exempt principals ----------------------------------------------------
#
# v0.7.1 Phase 3 removed every "this caller is special" branch. These pin the three
# names that used to be exempt (a `system` principal, `gateway`, `supervisor`) against
# the allowlist they actually have -- not against a bypass.


def test_hub_enforce_checks_the_supervisor_against_its_own_allowlist(hub_env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")

    allowed_claims, denial = _hub_call(agent_token.mint("supervisor", user_id="user-1"))
    assert denial is None, denial
    assert allowed_claims.agent == "supervisor"

    _, denied = _hub_call(agent_token.mint("supervisor", user_id="user-1"), NETCTL)
    _assert_hub_denied(denied, contains="not in agent 'supervisor' allowlist")


def test_hub_enforce_a_system_principal_is_not_exempt(hub_env, monkeypatch):
    """A token claiming `principal="system"` gets no bypass: no agent record, no grant."""
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")

    _, denial = _hub_call(agent_token.mint("gateway", principal="system"), NETCTL)

    _assert_hub_denied(denial, contains="unknown agent 'gateway'")


def test_hub_enforce_the_front_door_is_limited_to_public_tools(hub_env, monkeypatch):
    """The gateway mints for the caller it serves and has no manifest of its own.

    Its only possible grant is the tool's own `public` exposure -- the same rule the
    gateway applied before dispatching; everything else is denied.
    """
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    gateway_token = agent_token.mint("gateway", user_id="user-1")

    _, denial = _hub_call(gateway_token, NETCTL)
    _assert_hub_denied(denial, contains="unknown agent 'gateway'")

    claims, allowed = _hub_call(gateway_token, PUBLIC_ECHO)
    assert allowed is None
    assert claims.user_id == "user-1"


def test_hub_enforce_public_exposure_does_not_widen_an_agents_allowlist(
    hub_env, monkeypatch
):
    """`public` is the grant for a caller with no manifest -- never a shortcut for an
    agent whose own allowlist does not name the tool."""
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")

    _, denial = _hub_call(agent_token.mint("agent-b"), PUBLIC_ECHO)

    _assert_hub_denied(denial, contains="not in agent 'agent-b' allowlist")


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


# The requests carry NO identity fields (v0.7.1 Phase 2): the agent, user, email and
# groups all come from the token's claims, and the runner derives them itself.
def _session(token, *, target="coralogix", kind="mcp_session"):
    return SessionCreateRequest(
        kind=kind, target=target, session_key=SESSION_KEY, agent_token=token
    )


def _console(token):
    return ExecRequest(
        kind="console",
        target="console",
        command="echo hi",
        agent_token=token,
    )


def _tool(token, target="echo"):
    return ExecRequest(kind="tool", target=target, agent_token=token)


def _assert_runner_denied(denial) -> None:
    assert denial is not None, "expected the runner to refuse the call"
    assert denial.status_code == 403
    assert json.loads(denial.body)["detail"]["code"] == "access_denied"


@pytest.mark.parametrize("case", BAD_TOKEN_CASES)
def test_runner_enforce_refuses_a_bad_token(runner_env, case):
    denial = runner_module._authorize(_session(_bad_token(case)))

    _assert_runner_denied(denial)


def test_runner_enforce_refuses_a_session_for_an_mcp_outside_the_allowlist(runner_env):
    """Agent X's token, Y's MCP: agent-b declares no MCPs at all."""
    denial = runner_module._authorize(_session(agent_token.mint("agent-b")))

    _assert_runner_denied(denial)


def test_runner_enforce_allows_the_granted_mcp(runner_env):
    assert runner_module._authorize(_session(agent_token.mint("agent-a"))) is None


def test_runner_console_requires_execute(runner_env):
    assert runner_module._authorize(_console(agent_token.mint("agent-a"))) is None
    _assert_runner_denied(
        runner_module._authorize(_console(agent_token.mint("agent-b")))
    )


def test_runner_discovery_needs_no_token(runner_env):
    """A discovery run is a throwaway catalog read: no agent owns it.

    The runner control socket already requires the runner bearer token, and the
    caller (central MCP registration / edge catalog refresh) has no agent run to
    mint from -- so a missing agent token must not break discovery.
    """
    assert runner_module._authorize(_session(None, target="catalog", kind="discovery")) is None


def test_runner_discovery_still_accepts_a_valid_token(runner_env):
    payload = _session(agent_token.mint("agent-a"), target="x", kind="discovery")

    assert runner_module._authorize(payload) is None


def test_runner_ignores_a_forged_body_agent(runner_env):
    """A body cannot name the agent: the token is the only identity authority.

    ``agent`` is a removed field, so pydantic ignores it; agent-b's token stays
    agent-b's, and agent-b declares no MCPs.
    """
    payload = SessionCreateRequest(
        kind="mcp_session",
        target="coralogix",
        session_key=SESSION_KEY,
        agent="agent-a",
        agent_token=agent_token.mint("agent-b"),
    )

    _assert_runner_denied(runner_module._authorize(payload))


def test_runner_refuses_an_unknown_agent(runner_env):
    _assert_runner_denied(
        runner_module._authorize(_session(agent_token.mint("ghost")))
    )


def test_runner_enforce_a_system_principal_is_not_exempt(runner_env):
    """A `system` principal gets no session/console bypass: it is not on disk at all."""
    _assert_runner_denied(
        runner_module._authorize(
            _console(agent_token.mint("gateway", principal="system"))
        )
    )
    # And neither does the front door's ordinary token.
    _assert_runner_denied(runner_module._authorize(_console(agent_token.mint("gateway"))))


# --- the runner authorizes only what it owns ---------------------------------
#
# v0.7.1 Phase 3: `kind="tool"` is the hub's decision. The runner used to re-derive
# the allowlist from a workspace manifest, which denied EVERY front-door/gateway call
# (no agent record exists) and every supervisor call (its manifest ships inside the
# image). The regression tests below use the real shipping layout: no supervisor
# directory under `workspace/agents`, per the fixture above.


@pytest.mark.parametrize("agent", ["supervisor", "gateway"])
def test_runner_enforce_allows_a_tool_call_from_a_manifestless_caller(
    runner_env, agent
):
    """A tool call is authorized by the hub; the runner must not demand a manifest.

    Neither caller has an on-disk agent record here (the supervisor's is an image
    asset, the gateway has none at all), which is exactly the shipping layout.
    """
    token = agent_token.mint(agent, user_id="user-1")

    assert runner_module._authorize(_tool(token)) is None


def test_runner_enforce_a_tool_call_from_an_unknown_agent_is_not_the_runners_call(
    runner_env,
):
    """Even a name with no record anywhere passes the runner: the hub already denied
    or admitted it before dispatch, and the runner cannot re-derive that verdict."""
    assert runner_module._authorize(_tool(agent_token.mint("ghost"))) is None


@pytest.mark.parametrize("agent", ["supervisor", "gateway"])
def test_runner_owned_resources_stay_locked_without_a_manifest(runner_env, agent):
    """Sessions and console containers ARE the runner's: no manifest, no call.

    The same manifest-less tokens that may run a hub-authorized tool are refused a
    container the runner would create and keep alive on its own authority.
    """
    token = agent_token.mint(agent, user_id="user-1")

    _assert_runner_denied(runner_module._authorize(_session(token)))
    _assert_runner_denied(runner_module._authorize(_console(token)))


def test_runner_refuses_an_unrecognized_kind(runner_env):
    """A kind the runner does not know is denied outright, never silently authorized.

    ``ExecKind`` is validated by the contract today; this pins the behaviour for the
    next kind added (workflows in v0.7.1 Phase 6) before it has an owner here.
    """
    payload = _tool(agent_token.mint("agent-a"))
    payload.kind = "workflow"

    _assert_runner_denied(runner_module._authorize(payload))


def test_the_shipped_supervisor_manifest_is_an_image_asset():
    """Layout guard: the supervisor is read from the package, not from the workspace.

    ``scripts/sync_to_db.py`` syncs it from ``core/assets/supervisor`` into etcd, and
    nothing materialises it under ``workspace/agents``. If this ever changes, the
    runner's manifest-free tool path above would start being exercised against a
    directory that exists -- so assert the layout the tests assume.
    """
    from scripts import sync_to_db

    manifest = sync_to_db.SUPERVISOR_DIR / "config.yaml"
    assert manifest.is_file(), f"the shipped supervisor manifest is missing: {manifest}"
    assert sync_to_db.SUPERVISOR_DIR == (
        sync_to_db.BASE_DIR / "core" / "assets" / "supervisor"
    )
    assert not (sync_to_db.AGENTS_DIR / "supervisor").exists()

    config = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    assert config["name"] == "supervisor"
    # The hub checks the supervisor against this list, so it must be a real one.
    assert config["allowed_tools"] == ["text_stats"]


def test_runner_discovery_is_the_one_non_agent_path(runner_env):
    """The legitimate remaining bypass by KIND: a catalog read no agent owns.

    Its agent token (even a `system` one) is not an identity to authorize -- the
    runner bearer token on the control socket is the gate. ``kind="tool"`` is not a
    bypass of the same sort: the hub authorized it (see the tests above); every
    resource the runner owns still needs a manifest.
    """
    payload = _session(
        agent_token.mint("gateway", principal="system"), target="x", kind="discovery"
    )

    assert runner_module._authorize(payload) is None


def test_runner_off_mode_short_circuits(runner_env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "off")
    bad = _bad_token("bad_sig")

    assert runner_module._authorize(_session(bad)) is None
    assert runner_module._authorize(_console(bad)) is None
