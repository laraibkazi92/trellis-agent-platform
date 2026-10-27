# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Direct hub tool calls: one evaluator, one verdict, before anything is dispatched.

``hub.run_tool`` is the last mile for every tool the hub owns -- local and edge-hosted
alike -- and it is also the front door when traffic arrives without going through
``use_tool`` or a bound-tool wrapper. Since v0.7.1 there is exactly one decision
(:mod:`core.tool_access`) and one mode switch (``TOOL_ACCESS_MODE``); the old separate
``hub_call_mode`` gate is gone, which this suite pins by asserting the SAME verdict
drives the call.

Every test is hermetic: the policy registry is faked, the local/remote dispatch seams
are recorded instead of executed, and ``__user_id`` is only ever the no-token dev
fallback.
"""

import asyncio
import json

import pytest

from core import agent_token, auth, hub, tool_access
from core.models import ToolConfig

SECRET = "hub-call-evaluator-unit-secret-0123456789abcdef"
TOOL = "opsctl"
GROUP = "ops"


class FakeEtcd:
    """The policy document and the shared shadow ring behind ``tool_access``."""

    def __init__(self):
        self.policy = None
        self.shared_ring = None
        self.error = None
        self.revision = 1

    def get(self, key, **_kwargs):
        if self.error is not None:
            raise RuntimeError(self.error)
        if key == tool_access.POLICY_PATH:
            if self.policy is None:
                return None, None
            metadata = type("M", (), {"mod_revision": self.revision})()
            return json.dumps(self.policy).encode("utf-8"), metadata
        if key == tool_access.SHADOW_DENIAL_PATH:
            return self.shared_ring, None
        return None, None

    def put(self, key, value):
        if self.error is not None:
            raise RuntimeError(self.error)
        payload = value.encode("utf-8") if isinstance(value, str) else value
        if key == tool_access.SHADOW_DENIAL_PATH:
            self.shared_ring = payload

    def add_watch_callback(self, key, callback):
        return 1

    def cancel_watch(self, watch_id):
        pass


AGENTS = {
    "agent-a": {"allowed_tools": [TOOL], "allowed_mcps": []},
    "agent-b": {"allowed_tools": [], "allowed_mcps": []},
}


def make_config(**kw) -> ToolConfig:
    return ToolConfig(
        name=TOOL, description="Inspects nodes.", runtime="python", entrypoint="main.py", **kw
    )


def make_remote_config() -> ToolConfig:
    return ToolConfig(
        name="plant__boiler",
        description="boiler status",
        runtime="remote",
        remote={"site": "plant", "tool": "boiler"},
    )


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    monkeypatch.setattr(hub.identity_mgr, "record_tool_usage", lambda *args: None)
    monkeypatch.setattr(hub.identity_mgr, "get_agent_config", AGENTS.get)
    fake = FakeEtcd()
    monkeypatch.setattr(tool_access, "_client", lambda: fake)
    monkeypatch.setattr(tool_access, "_last_shadow_persist", 0.0)
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()
    for var in (auth.agent_token_var, auth.user_id_var, auth.run_id_var):
        var.set(None)
    yield fake
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()


@pytest.fixture
def executions(monkeypatch):
    """Record dispatches instead of running a tool (local or remote)."""
    ran = []

    async def fake_local(config, tool_dir, arguments, user_id, claims=None, agent_token=None):
        ran.append(
            {
                "tool": config.name,
                "arguments": dict(arguments),
                "user_id": user_id,
                "token": agent_token,
            }
        )
        return {"ok": True}

    async def fake_remote(config, arguments, *, agent_token=None, claims=None):
        ran.append(
            {
                "tool": config.name,
                "arguments": dict(arguments),
                "user_id": claims.user_id if claims is not None else None,
            }
        )
        return {"ok": True}

    monkeypatch.setattr(hub, "_run_tool_attempt", fake_local)
    monkeypatch.setattr(hub, "_run_remote", fake_remote)
    return ran


def call(arguments, *, config=None, tool_dir=None):
    """Await ``run_tool`` and drain its fire-and-forget usage write."""

    async def _scenario():
        result = await hub.run_tool(config or make_config(), tool_dir, arguments)
        await asyncio.gather(*hub._background_tasks, return_exceptions=True)
        return result

    return asyncio.run(_scenario())


def token(agent="agent-a", user_id="user-1", *, groups=()):
    return agent_token.mint(agent, user_id=user_id, groups=groups)


def policy(*rules):
    return {"rules": [dict(rule) for rule in rules]}


# --- the allowlist half (always enforced) ------------------------------------


def test_a_granted_agent_executes(executions):
    result = call({"__agent_token": token()})

    assert result == {"ok": True}
    assert [entry["tool"] for entry in executions] == [TOOL]
    assert executions[0]["user_id"] == "user-1"  # identity from the claims


def test_an_agent_outside_its_allowlist_is_denied_before_dispatch(executions):
    result = call({"__agent_token": token("agent-b")})

    assert "access_denied" in result["error"]
    assert executions == []


def test_a_remote_tool_is_denied_before_dispatch(executions):
    result = call({"__agent_token": token("agent-b")}, config=make_remote_config())

    assert "access_denied" in result["error"]
    assert executions == []


def test_a_missing_token_is_denied(executions):
    result = call({})

    assert "agent token rejected (missing)" in result["error"]
    assert executions == []


def test_a_token_for_an_unregistered_agent_is_denied_a_public_tool(executions):
    """The front door is a reserved identity, not "an agent with no record"."""
    result = call(
        {"__agent_token": token("ghost-agent")}, config=make_config(public=True)
    )

    assert "reserved front door" in result["error"]
    assert executions == []


def test_the_front_door_identity_gets_a_public_tool(executions):
    result = call(
        {"__agent_token": token(tool_access.FRONT_DOOR_AGENT)},
        config=make_config(public=True),
    )

    assert result == {"ok": True}
    assert [entry["tool"] for entry in executions] == [TOOL]


def test_the_body_cannot_assert_identity(executions):
    """``__user_id`` is not identity: a forged one changes nothing about the verdict."""
    result = call({"__user_id": "someone-else", "__agent_token": token("agent-b")})

    assert "access_denied" in result["error"]
    assert executions == []


def test_a_denied_call_still_records_usage_once(monkeypatch):
    calls = []
    monkeypatch.setattr(
        hub.identity_mgr, "record_tool_usage", lambda *args: calls.append(args)
    )

    call({"__agent_token": token("agent-b")})

    assert calls == [("user-1", TOOL)]


# --- the group-rule half ------------------------------------------------------


def test_a_group_rule_admits_a_matching_token(executions, env):
    env.policy = policy({"targets": [TOOL], "groups": [GROUP]})

    assert call({"__agent_token": token(groups=[GROUP])}) == {"ok": True}
    assert len(executions) == 1


def test_a_group_rule_denies_a_non_matching_token(executions, env):
    env.policy = policy({"targets": [TOOL], "groups": [GROUP]})

    result = call({"__agent_token": token(groups=["support"])})

    assert "access_denied" in result["error"]
    assert GROUP in result["error"] or "groups" in result["error"]
    assert executions == []


def test_a_group_rule_matches_a_glob(executions, env):
    env.policy = policy({"targets": ["ops*"], "groups": [GROUP]})

    assert call({"__agent_token": token(groups=[GROUP])}) == {"ok": True}


def test_shadow_records_the_hub_surface_without_denying(executions, env, monkeypatch):
    monkeypatch.setenv(tool_access.MODE_ENV, "shadow")
    env.policy = policy({"targets": [TOOL], "groups": [GROUP]})

    assert call({"__agent_token": token(groups=["support"])}) == {"ok": True}

    [entry] = tool_access.recent_shadow_denials()
    assert entry["surface"] == "hub"
    assert entry["target"] == TOOL
    assert entry["reason"] == tool_access.REASON_GROUP_DENIED


def test_shadow_does_not_relax_the_allowlist(executions, env, monkeypatch):
    monkeypatch.setenv(tool_access.MODE_ENV, "shadow")
    env.policy = policy()

    result = call({"__agent_token": token("agent-b")})

    assert "access_denied" in result["error"]
    assert executions == []


# --- fail closed --------------------------------------------------------------


def test_an_unreadable_registry_fails_closed(executions, env):
    env.error = "etcd is unreachable"
    env.policy = policy({"targets": [TOOL], "groups": [GROUP]})

    result = call({"__agent_token": token(groups=[GROUP])})

    assert "policy is unavailable" in result["error"]
    assert executions == []


def test_an_invalid_policy_fails_closed(executions, env):
    env.policy = {"rules": [{"targets": [TOOL], "groups": []}]}

    result = call({"__agent_token": token(groups=[GROUP])})

    assert "policy is unavailable" in result["error"]
    assert executions == []


def test_an_unrecognized_mode_behaves_as_enforce(executions, env, monkeypatch):
    monkeypatch.setenv(tool_access.MODE_ENV, "enforcing")  # the old three-switch value
    env.policy = policy({"targets": [TOOL], "groups": [GROUP]})

    result = call({"__agent_token": token(groups=["support"])})

    assert "access_denied" in result["error"]
    assert executions == []


# --- the token rollout window and the dev fallback ----------------------------


def test_log_mode_runs_an_out_of_allowlist_call(executions, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")

    assert call({"__agent_token": token("agent-b")}) == {"ok": True}
    assert len(executions) == 1


def test_log_mode_still_applies_a_group_rule(executions, env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    env.policy = policy({"targets": [TOOL], "groups": [GROUP]})

    result = call({"__agent_token": token(groups=["support"])})

    assert "access_denied" in result["error"]


def test_off_mode_keeps_the_user_id_as_the_dev_fallback(executions, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "off")
    monkeypatch.setenv("DEV_MODE", "true")

    assert call({"__user_id": "dev-user", "__agent_token": "not-a-token"}) == {"ok": True}
    assert executions[0]["user_id"] == "dev-user"


# --- the FastMCP handler surface ---------------------------------------------


class FakeMCP:
    """Just enough of the FastMCP call result to assert the handler's shape."""

    def __init__(self, payload):
        self.content = [type("Block", (), {"text": json.dumps(payload)})()]


def test_the_handler_returns_a_denial_rather_than_raising(executions):
    handler = hub._create_tool_handler(make_config(), None)

    result = asyncio.run(handler(__agent_token=token("agent-b")))

    assert "access_denied" in result["error"]
    assert executions == []
