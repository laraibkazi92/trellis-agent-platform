# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Direct hub ``/tools/call`` caller identity (v0.7.1 Phase 2).

Traffic that reaches ``hub.run_tool`` without going through ``use_tool`` or a bound-tool
wrapper now carries a principal: the hub verifies the ``__agent_token`` on the request
(the one the framework already forwards), takes the caller's identity from its claims,
and asks the shared evaluator under ``hub_call_mode`` / ``surface="hub_direct"`` before
executing. ``__user_id`` is only the no-token (``ENFORCE_AGENT_TOKENS=off``) dev
fallback: it is never consulted once a token verifies.

Every test is hermetic: the authz registry is faked (``tests/_hub_authz_registry.py``),
the local/remote dispatch seams are recorded instead of executed, and the agent-token
gate is pinned ``off`` except where a test pins another mode -- the default here is the
second gate, not the first.
"""

import asyncio
import logging
import time

import pytest

import _hub_authz_registry as hub_authz
from core import agent_token, auth, hub, tool_authz
from core.models import ToolConfig

SECRET = "hub-call-authz-unit-secret-0123456789abcdef"

DENIED = "SYSTEM: Access denied. Tool '{name}' is not permitted for this principal."
CHECK_FAILED = "SYSTEM: Error checking tool access for '{name}'. Please try again later."
DENY_ALL = {"default_action": "deny", "rules": []}


def make_config(**kw):
    return ToolConfig(
        name="opsctl", description="Inspects nodes.", runtime="python", entrypoint="main.py", **kw
    )


def make_remote_config():
    return ToolConfig(
        name="plant__boiler",
        description="boiler status",
        runtime="remote",
        remote={"site": "plant", "tool": "boiler"},
    )


@pytest.fixture(autouse=True)
def _hub_env(monkeypatch):
    """Pin the agent-token gate off and keep usage writes out of etcd.

    ``AGENT_TOKEN_SECRET`` is set so tests can mint real tokens; ``ENFORCE_AGENT_TOKENS``
    stays ``off`` so ``_authorize_call`` cannot deny (or read etcd) before the hub gate
    under test runs.
    """
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "off")
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.setattr(hub.identity_mgr, "record_tool_usage", lambda *args: None)


@pytest.fixture(autouse=True)
def _authz_isolation(monkeypatch):
    """The snapshot, deny ring and agent-type caches are process-global."""
    for var in (auth.agent_token_var, auth.user_id_var, auth.run_id_var):
        var.set(None)
    hub_authz.install(monkeypatch)  # default: every mode off
    tool_authz.clear_shadow_denies()
    monkeypatch.setattr(tool_authz, "_DENY_PERSIST_MIN_INTERVAL_S", 0.0)
    monkeypatch.setattr(tool_authz, "_last_deny_persist", {})
    monkeypatch.setattr(tool_authz, "_agent_type_cache", {})
    monkeypatch.setattr(tool_authz, "_user_groups_cache", {})
    yield
    tool_authz.reset_cache()
    tool_authz.clear_shadow_denies()
    for var in (auth.agent_token_var, auth.user_id_var, auth.run_id_var):
        var.set(None)


@pytest.fixture
def registry(monkeypatch):
    """Install a configured fake authz registry; ``install(**kwargs)`` returns it."""

    def install(**kwargs):
        fake = hub_authz.install(monkeypatch, **kwargs)
        fake.clear_tool_authz_denies()
        return fake

    return install


@pytest.fixture
def executions(monkeypatch):
    """Record dispatches instead of running a tool (local or remote)."""
    ran = []

    async def fake_local(config, tool_dir, arguments, user_id, claims=None, agent_token=None):
        ran.append({"tool": config.name, "arguments": dict(arguments), "user_id": user_id})
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


def mint(agent, user_id=None, *, principal=None, now=None):
    return agent_token.mint(agent, user_id=user_id, principal=principal, now=now)


# --- off: the fast path -------------------------------------------------------


def test_off_runs_the_tool_without_evaluating(monkeypatch, executions, registry):
    fake = registry(policy=DENY_ALL, mode="enforcing", bound_mode="enforcing", hub_mode="off")

    assert call({}) == {"ok": True}

    assert [entry["tool"] for entry in executions] == ["opsctl"]
    assert tool_authz.shadow_denies() == []
    # One snapshot load for the mode; the other surfaces' enforcing modes never apply.
    assert fake.policy_reads == 1


def test_off_stays_a_no_io_fast_path_once_warm(executions, registry):
    fake = registry(policy=DENY_ALL, hub_mode="off")

    assert call({}) == {"ok": True}
    reads_after_first = fake.policy_reads
    assert call({}) == {"ok": True}

    assert fake.policy_reads == reads_after_first


def test_off_tolerates_a_malformed_token_and_no_identity(executions, registry):
    registry(policy=DENY_ALL, hub_mode="off")

    # No verification happens in `off`, so a garbage token is not even inspected.
    assert call({"__agent_token": "t1.garbage.signature"}) == {"ok": True}


# --- shadow: record and execute ----------------------------------------------


def test_shadow_executes_and_records_the_hub_surface(executions, registry):
    fake = registry(policy=DENY_ALL, hub_mode="shadow")

    result = call({"__agent_token": mint("supervisor", "alice")})

    assert result == {"ok": True}
    assert len(executions) == 1
    [entry] = fake.denies
    assert entry["surface"] == "hub_direct"
    assert entry["mode"] == "shadow"
    assert entry["principal"] == "agent:supervisor"
    assert entry["tool"] == "opsctl"
    assert entry["scope"] == "tools:call"


def test_shadow_leaves_the_other_gates_alone(executions, registry):
    registry(policy=DENY_ALL, mode="off", bound_mode="off", hub_mode="shadow")

    assert call({}) == {"ok": True}

    # The use_tool gate is still off: its own mode is untouched by this surface.
    assert tool_authz.allowed("user:alice", "opsctl", "tools:call") is True


# --- enforcing: deny before dispatch ----------------------------------------


def test_enforcing_denies_and_never_reaches_the_tool(executions, registry):
    fake = registry(policy=DENY_ALL, hub_mode="enforcing")

    result = call({"__agent_token": mint("supervisor", "alice")})

    assert result == {"error": DENIED.format(name="opsctl")}
    assert executions == []
    [entry] = fake.denies
    assert entry["mode"] == "enforcing"
    assert entry["surface"] == "hub_direct"


def test_enforcing_denies_a_remote_tool_before_dispatch(executions, registry):
    registry(policy=DENY_ALL, hub_mode="enforcing")

    result = call({}, config=make_remote_config())

    assert result == {"error": DENIED.format(name="plant__boiler")}
    assert executions == []


def test_enforcing_allows_a_granted_principal(executions, registry):
    fake = registry(
        policy={
            "default_action": "deny",
            "rules": [
                {"tools": ["opsctl"], "allow_principals": ["agent:supervisor"], "scopes": ["tools:call"]}
            ],
        },
        hub_mode="enforcing",
    )

    assert call({"__agent_token": mint("supervisor", "alice")}) == {"ok": True}

    assert len(executions) == 1
    assert fake.denies == []


def test_enforcing_denies_when_the_rule_names_someone_else(executions, registry):
    registry(
        policy={
            "default_action": "deny",
            "rules": [
                {"tools": ["opsctl"], "allow_principals": ["user:bob"], "scopes": ["tools:call"]}
            ],
        },
        hub_mode="enforcing",
    )

    assert call({"__agent_token": mint("supervisor", "alice")}) == {
        "error": DENIED.format(name="opsctl")
    }
    assert executions == []


def test_enforcing_requires_the_call_scope(executions, registry):
    registry(
        policy={
            "default_action": "deny",
            "rules": [
                {"tools": ["opsctl"], "allow_principals": ["*"], "scopes": ["tools:read"]}
            ],
        },
        hub_mode="enforcing",
    )

    assert call({}) == {"error": DENIED.format(name="opsctl")}
    assert executions == []


def test_denied_call_still_records_usage_once(monkeypatch, executions, registry):
    used = []
    monkeypatch.setattr(
        hub.identity_mgr, "record_tool_usage", lambda user_id, tool: used.append((user_id, tool))
    )
    registry(policy=DENY_ALL, hub_mode="enforcing")

    call({"__user_id": "alice"})

    # Existing contract: usage is recorded once per invocation, allowed or not.
    assert used == [("alice", "opsctl")]


# --- principal derivation ----------------------------------------------------


@pytest.mark.parametrize(
    "token_call,arguments,agent_configs,expected",
    [
        pytest.param(
            {"agent": "gateway", "user_id": "alice"},
            {"__user_id": "alice"},
            {},
            "user:alice",
            id="gateway-token-with-user",
        ),
        pytest.param(
            {"agent": "supervisor", "user_id": "alice"},
            {"__user_id": "alice"},
            {},
            "agent:supervisor",
            id="plain-agent-token",
        ),
        pytest.param(
            {"agent": "nightly", "user_id": "svc_agent_nightly"},
            {},
            {},
            "workflow:nightly",
            id="background-service-identity",
        ),
        pytest.param(
            {"agent": "nightly", "user_id": "webhook"},
            {},
            {"nightly": {"type": "background_agent"}},
            "workflow:nightly",
            id="background-config-type",
        ),
        pytest.param(None, {"__user_id": "bob"}, {}, "user:bob", id="no-token-with-user"),
        pytest.param(None, {}, {}, "anonymous", id="no-token-no-user"),
    ],
)
def test_principal_derivation(
    executions, registry, token_call, arguments, agent_configs, expected
):
    fake = registry(policy=DENY_ALL, hub_mode="enforcing", agent_configs=agent_configs)
    if token_call is not None:
        arguments = {
            **arguments,
            "__agent_token": agent_token.mint(**token_call),
        }

    assert call(dict(arguments)) == {"error": DENIED.format(name="opsctl")}

    [entry] = fake.denies
    assert entry["principal"] == expected


def test_gateway_token_without_a_user_is_an_agent_principal(executions, registry):
    fake = registry(policy=DENY_ALL, hub_mode="enforcing")

    call({"__agent_token": mint("gateway", None)})

    [entry] = fake.denies
    assert entry["principal"] == "agent:gateway"


# --- caller groups: the token claim, else the stored record ------------------


def group_rule(**kwargs):
    """A policy that allows ``opsctl`` only to ``group:ops``."""
    return {
        "default_action": "deny",
        "rules": [
            {
                "tools": ["opsctl"],
                "allow_principals": ["group:ops"],
                "scopes": ["tools:call"],
            }
        ],
        **kwargs,
    }


def test_token_groups_win_over_the_stored_record(monkeypatch, executions, registry):
    """Mint-time groups are the authority: no record read, and the claim wins.

    The record below disagrees on purpose (a stale/demoted profile). A token-bearing
    call must not re-read it at the last mile, and the fresh claim must decide.
    """
    fake = registry(
        policy=group_rule(), hub_mode="enforcing", users={"alice": {"groups": ["other"]}}
    )
    reads = []
    monkeypatch.setattr(
        fake, "get_user", lambda user_id: reads.append(user_id) or {"groups": ["other"]}
    )
    token = agent_token.mint("supervisor", user_id="alice", groups=("ops",))

    assert call({"__agent_token": token}) == {"ok": True}

    assert len(executions) == 1
    assert fake.denies == []
    assert reads == []


def test_a_token_without_groups_falls_back_to_the_stored_record(executions, registry):
    """A pre-groups token (or a group-less identity) still matches on the record."""
    fake = registry(
        policy=group_rule(), hub_mode="enforcing", users={"alice": {"groups": ["ops"]}}
    )

    assert call({"__agent_token": mint("supervisor", "alice")}) == {"ok": True}

    assert len(executions) == 1
    assert fake.denies == []


def test_malformed_token_is_not_a_call_failure(monkeypatch, executions, registry, caplog):
    """A bad token must cost the call its claims, never crash the call.

    It also costs it the identity the body asserted: a forged or broken token cannot
    borrow the `__user_id` that came with it, so the principal is `anonymous`.
    """
    # `log` rather than the file's usual `off`: with the gate off nothing is verified
    # and the body value is legitimately the caller; this test is about a token that
    # was presented and did not verify.
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    fake = registry(policy=DENY_ALL, hub_mode="enforcing")

    with caplog.at_level(logging.DEBUG, logger="core.hub"):
        result = call({"__agent_token": "t1.not-base64.nope", "__user_id": "alice"})

    assert result == {"error": DENIED.format(name="opsctl")}
    [entry] = fake.denies
    assert entry["principal"] == "anonymous"
    assert "did not verify" in caplog.text


def test_expired_token_does_not_fall_back_to_the_user_id(monkeypatch, executions, registry):
    """An expired token carries no identity, and the body's claim to one is ignored."""
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    fake = registry(policy=DENY_ALL, hub_mode="enforcing")
    expired = mint("supervisor", "alice", now=time.time() - 100_000)

    call({"__agent_token": expired, "__user_id": "alice"})

    [entry] = fake.denies
    assert entry["principal"] == "anonymous"


def test_off_mode_keeps_the_user_id_as_the_dev_fallback(executions, registry):
    """With the agent-token gate off nothing is verified, so `__user_id` stands.

    It is the documented dev/rollout fallback; it is never consulted once a token
    verifies (see the malformed/expired cases above).
    """
    fake = registry(policy=DENY_ALL, hub_mode="enforcing")

    call({"__user_id": "alice"})

    [entry] = fake.denies
    assert entry["principal"] == "user:alice"


# --- modes that are invalid or that the registry cannot serve ---------------


def test_unrecognized_mode_fails_closed(executions, registry):
    fake = registry(policy=DENY_ALL, hub_mode="enforcin")

    assert call({}) == {"error": DENIED.format(name="opsctl")}
    assert executions == []
    [entry] = fake.denies
    assert entry["mode"] == "enforcing"


def test_unreadable_registry_fails_closed(monkeypatch, executions):
    """An exception inside the check denies; it never runs the tool."""

    def boom(*args, **kwargs):
        raise RuntimeError("policy engine unavailable")

    monkeypatch.setattr(tool_authz, "evaluate", boom)
    registry = hub_authz.install(monkeypatch, policy=DENY_ALL, hub_mode="enforcing")

    assert call({}) == {"error": CHECK_FAILED.format(name="opsctl")}
    assert executions == []
    assert registry.denies == []


def test_dev_mode_does_not_bypass_the_gate(monkeypatch, executions, registry):
    """The hub keeps no DEV_MODE hatch: the fallback key only signs tokens."""
    monkeypatch.setenv("DEV_MODE", "true")
    registry(policy=DENY_ALL, hub_mode="enforcing")

    assert call({"__user_id": "dev-user"}) == {"error": DENIED.format(name="opsctl")}
    assert executions == []


# --- the MCP handler surface ------------------------------------------------


class FakeMCP:
    """Capture the registered FastMCP handlers (as the other hub tests do)."""

    def __init__(self):
        self.handlers = {}

    def tool(self, name=None, description=None):
        def decorator(fn):
            self.handlers[name] = fn
            return fn

        return decorator


def test_handler_returns_a_tool_error_rather_than_breaking_the_session(
    monkeypatch, executions, registry
):
    config = make_config()
    fake_mcp = FakeMCP()
    monkeypatch.setattr(hub, "load_tool_configs", lambda: {"opsctl": (config, None)})
    monkeypatch.setattr(hub, "mcp", fake_mcp)
    registry(policy=DENY_ALL, hub_mode="enforcing")

    hub.register_tools()
    handler = fake_mcp.handlers["opsctl"]
    result = asyncio.run(handler(__agent_token=mint("supervisor", "alice")))

    # A normal result dict, exactly like any other tool failure -- not an exception the
    # MCP session would have to recover from.
    assert result == {"error": DENIED.format(name="opsctl")}
    assert executions == []


def test_hub_mode_promoted_after_the_snapshot_ttl_is_honoured(executions, registry):
    """A long-running hub must notice a promotion instead of keeping its boot mode.

    Live symptom this pins: `hub_call_mode` set to shadow was ignored by the running
    hub (no ring entries, tools still allowed) until the container restarted, because
    the fast path trusted an expired snapshot's mode and never triggered a re-read.
    """
    fake = registry(policy=DENY_ALL, hub_mode="off")
    assert call({}) == {"ok": True}
    assert tool_authz.shadow_denies() == []
    reads_when_warm = fake.policy_reads

    fake.hub_mode = "shadow"
    tool_authz._snapshot_expiry = 0.0

    assert call({}) == {"ok": True}          # shadow records, never blocks
    assert [entry["surface"] for entry in tool_authz.shadow_denies()] == ["hub_direct"]
    assert fake.policy_reads > reads_when_warm


# --- groups: the last mile resolves what the host published -------------------


def _group_policy():
    return {
        "default_action": "deny",
        "rules": [
            {
                "tools": ["opsctl"],
                "allow_principals": ["group:ops"],
                "scopes": ["tools:call"],
            }
        ],
    }


def test_group_rule_matches_through_the_token_user(executions, registry):
    """The hub has no middleware to publish a group claim; it resolves the token's user
    record, which is the source the host's middleware publishes from. A `group:` rule
    must reach the same verdict on both sides of the boundary."""
    fake = registry(
        policy=_group_policy(),
        hub_mode="enforcing",
        users={"alice": {"sub": "alice", "groups": ["ops"]}},
    )

    assert call({"__agent_token": mint("supervisor", "alice")}) == {"ok": True}
    assert fake.denies == []
    # A later call with no token at all must not inherit the previous caller's groups:
    # `anonymous` matches no `group:ops` rule unless the publish leaked.
    assert call({}) == {"error": DENIED.format(name="opsctl")}


def test_group_rule_does_not_grant_a_background_run(executions, registry):
    """Background runs resolve to `workflow:<name>`, which has no record groups. Even a
    profile planted under the service user id must not widen them: the host cannot see
    it either, so the last mile must not either."""
    registry(
        policy=_group_policy(),
        hub_mode="enforcing",
        users={
            "alice": {"sub": "alice", "groups": ["ops"]},
            "svc_agent_nightly": {"sub": "svc_agent_nightly", "groups": ["ops"]},
        },
        agent_configs={"nightly": {"type": "background_agent"}},
    )

    result = call({"__agent_token": mint("nightly", "svc_agent_nightly")})

    assert result == {"error": DENIED.format(name="opsctl")}
    assert executions == []
