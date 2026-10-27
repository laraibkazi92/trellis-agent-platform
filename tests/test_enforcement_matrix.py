# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The enforcement matrix: one evaluator, four enforcement points, one mode switch.

Every surface is driven directly, with no container backend and no live relay:

* ``hub``        -- ``core.hub._authorize_call`` (local and edge tools)
* ``relay``      -- ``services.edge_relay.app._authorize_agent`` (edge tools / MCPs)
* ``host``       -- ``core.tool_gate.deny_reason`` (console + MCP-session pre-runner)
* ``bound_tool`` -- ``core.agent_factory._bound_tool_denial`` (tools bound to an agent)

The property under test is the plan's acceptance gate: the group-rule combinations
(no rule / matching group / non-matching group / shadow) decide identically at every
surface, ``shadow`` records without denying, ``enforce`` denies, and an unreadable
registry or policy fails closed. The runner no longer decides anything -- it verifies
the token (central) or serves the identity the edge proxy verified (edge) -- which is
pinned at the end.
"""

import asyncio
import json
import time

import pytest

from core import agent_token, hub, tool_access
from core import auth as core_auth
from core.execution import runner as runner_module
from core.execution.contract import ExecRequest, RunIdentity, SessionCreateRequest
from core.models import ToolConfig
from services.edge_relay import app as relay_app

SECRET = "enforcement-matrix-secret-0123456789abcdef"
SESSION_KEY = "a" * 32

TOOL = "text_stats"
OTHER_TOOL = "netctl"
GROUP = "ops"

SUPERVISOR_AGENTS = {"supervisor": {"allowed_tools": [TOOL], "allowed_mcps": []}}


class FakeEtcd:
    """The policy document, the shared shadow ring and the watch API."""

    def __init__(self):
        self.policy = None
        self.shared_ring = None
        self.error = None
        self.revision = 1
        self.watches = []

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
        if key == tool_access.POLICY_PATH:
            self.policy = json.loads(payload.decode("utf-8"))
            self.revision += 1
        elif key == tool_access.SHADOW_DENIAL_PATH:
            self.shared_ring = payload

    def add_watch_callback(self, key, callback):
        self.watches.append((key, callback))
        return len(self.watches)

    def cancel_watch(self, watch_id):
        pass

    def set_policy(self, document):
        self.policy = document
        self.revision += 1
        tool_access.reset_snapshot()


class FakeRegistry:
    """Agent/edge records the surfaces resolve their allowlists from."""

    def __init__(self, agents=None, site=None):
        self.agents = agents or {}
        self.site = site or {"public": False, "public_tools": []}

    def get_agent_config(self, name):
        return self.agents.get(name)

    def get_edge_config(self, site):
        return self.site


@pytest.fixture
def registry(monkeypatch):
    """A hermetic policy registry, a clean snapshot/ring, and fake agent records."""
    fake = FakeEtcd()
    monkeypatch.setattr(tool_access, "_client", lambda: fake)
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv("DEV_MODE", raising=False)
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()
    monkeypatch.setattr(tool_access, "_last_shadow_persist", 0.0)
    yield fake
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()


@pytest.fixture
def records(monkeypatch):
    """Install one fake record store behind every surface's ``get_identity_manager``.

    Each surface refs its target differently (a bare hub name, an ``<site>__<tool>``
    edge reference), so the caller passes the surface in and its agent fixtures carry
    that surface's own grant: the allowlist and the group rule always name the same
    reference the surface evaluates.
    """

    def install(surface):
        fake = FakeRegistry(
            {
                "agent-a": {"allowed_tools": [surface.target], "allowed_mcps": []},
                "agent-b": {"allowed_tools": [], "allowed_mcps": []},
            }
        )
        monkeypatch.setattr(hub.identity_mgr, "get_agent_config", fake.get_agent_config)
        monkeypatch.setattr(relay_app, "_identity_manager", lambda: fake)
        monkeypatch.setattr(core_auth, "get_identity_manager", lambda: fake)
        return fake

    return install


@pytest.fixture(autouse=True)
def _clean_token_context():
    agent_token_var = core_auth.agent_token_var
    agent_token_var.set(None)
    yield
    agent_token_var.set(None)


def _policy(*rules):
    return {"rules": [dict(rule) for rule in rules]}


def _rule(targets, groups, name=None):
    rule = {"targets": list(targets), "groups": list(groups)}
    if name is not None:
        rule["name"] = name
    return rule


def _token(agent="agent-a", *, groups=(), **kwargs) -> str:
    return agent_token.mint(agent, user_id="user-1", groups=groups, **kwargs)


def _tool_config(name=TOOL, public=False) -> ToolConfig:
    return ToolConfig(
        name=name,
        description="A deterministic tool.",
        runtime="python",
        entrypoint="tool.py",
        public=public,
    )


# --------------------------------------------------------------------------- #
# the four surfaces, behind one shape
# --------------------------------------------------------------------------- #


class Surface:
    """One enforcement point, adapted to ``(allowed?, denial text)``.

    ``target`` is the reference this surface evaluates (the hub/bound-tool/console
    forms are bare names, the edge form is ``<site>__<tool>``), and
    ``reason_visible`` says whether the denial message carries the evaluator's reason
    or only the stable model-facing string.
    """

    def __init__(self, name, call, *, target=TOOL, reason_visible=True, token_context=None):
        self.name = name
        self.target = target
        self.reason_visible = reason_visible
        self._call = call
        self._token_context = token_context

    def verdict(self, token, target=None):
        if self._token_context is not None:
            self._token_context(token)
        denial = self._call(token, target or self.target)
        return denial

    def __repr__(self) -> str:  # pytest ids
        return self.name


def _hub_surface():
    def call(token, target):
        _claims, denial = asyncio.run(hub._authorize_call(_tool_config(target), token))
        return denial["error"] if denial else None

    return Surface("hub", call)


def _relay_surface():
    def call(token, target):
        _claims, denial = asyncio.run(
            relay_app._authorize_agent(token, site="dc1", tool=target.split("__", 1)[1])
        )
        return denial[1] if denial else None

    return Surface("relay", call, target=f"dc1__{TOOL}")


def _host_surface():
    from core import tool_gate

    def call(token, target):
        return asyncio.run(tool_gate.deny_reason(target, surface="host"))

    return Surface(
        "host", call, token_context=lambda token: core_auth.agent_token_var.set(token)
    )


def _bound_tool_surface():
    from core import agent_factory

    def call(token, target):
        return asyncio.run(agent_factory._bound_tool_denial(target))

    return Surface(
        "bound_tool",
        call,
        # The model-facing string is deliberately stable; the reason goes to the log.
        reason_visible=False,
        token_context=lambda token: core_auth.agent_token_var.set(token),
    )


SURFACES = [_hub_surface, _relay_surface, _host_surface, _bound_tool_surface]


@pytest.fixture(params=SURFACES, ids=lambda factory: factory().__repr__())
def surface(request):
    return request.param()


# --------------------------------------------------------------------------- #
# group-rule combinations, identical at every surface
# --------------------------------------------------------------------------- #


def test_no_rule_leaves_the_allowlist_alone(surface, registry, records):
    """No rule constrains the target: agent-a's allowlist admits, agent-b's does not."""
    records(surface)
    registry.policy = _policy()

    assert surface.verdict(_token("agent-a")) is None
    deny = surface.verdict(_token("agent-b"))
    assert deny is not None
    assert "denied" in deny.lower()


def test_a_matching_group_rule_admits(surface, registry, records):
    records(surface)
    registry.policy = _policy(_rule([surface.target], [GROUP], name="platform-ops"))

    assert surface.verdict(_token(groups=[GROUP])) is None


def test_a_non_matching_group_rule_denies(surface, registry, records, caplog):
    """Enforce (the default): one rule, one group, and this token holds neither."""
    records(surface)
    registry.policy = _policy(_rule([surface.target], [GROUP], name="platform-ops"))

    with caplog.at_level("WARNING"):
        deny = surface.verdict(_token(groups=["sre"]))

    assert deny is not None
    # The rule label is named so an operator can find it in the policy file, and it
    # is named identically wherever the decision was made.
    assert "platform-ops" in (deny if surface.reason_visible else caplog.text)
    assert "user-1" not in deny  # never a user, an email or an argument


def test_a_token_without_groups_is_denied_by_a_group_rule(surface, registry, records):
    records(surface)
    registry.policy = _policy(_rule([surface.target], [GROUP]))

    assert surface.verdict(_token()) is not None


def test_shadow_records_without_denying(surface, registry, records, monkeypatch):
    records(surface)
    monkeypatch.setenv(tool_access.MODE_ENV, "shadow")
    registry.policy = _policy(_rule([surface.target], [GROUP], name="platform-ops"))

    assert surface.verdict(_token(groups=["sre"])) is None

    [entry] = tool_access.recent_shadow_denials()
    assert entry["target"] == surface.target
    assert entry["agent"] == "agent-a"
    assert entry["rule"] == "platform-ops"
    assert entry["reason"] == tool_access.REASON_GROUP_DENIED
    assert entry["surface"] == surface.name
    assert entry["groups"] == ["sre"]


def test_off_skips_the_group_rules_entirely(surface, registry, records, monkeypatch):
    records(surface)
    monkeypatch.setenv(tool_access.MODE_ENV, "off")
    registry.policy = _policy(_rule([surface.target], [GROUP]))

    assert surface.verdict(_token(groups=["sre"])) is None
    assert tool_access.recent_shadow_denials() == []


def test_the_allowlist_half_is_enforced_in_every_mode(surface, registry, records, monkeypatch):
    """`shadow`/`off` relax group rules only: a caller outside the manifest still fails."""
    records(surface)
    registry.policy = _policy()
    for mode in ("shadow", "off", "enforce"):
        monkeypatch.setenv(tool_access.MODE_ENV, mode)
        assert surface.verdict(_token("agent-b")) is not None, mode


def test_an_unreadable_registry_fails_closed(surface, registry, records, caplog):
    records(surface)
    registry.error = "etcd is unreachable"

    with caplog.at_level("WARNING"):
        deny = surface.verdict(_token(groups=[GROUP]))

    assert deny is not None
    assert "unavailable" in (deny if surface.reason_visible else caplog.text)


def test_an_invalid_policy_fails_closed(surface, registry, records, caplog):
    records(surface)
    registry.policy = {"rules": [{"targets": [surface.target], "groups": []}]}

    with caplog.at_level("WARNING"):
        deny = surface.verdict(_token(groups=[GROUP]))

    assert deny is not None
    assert "unavailable" in (deny if surface.reason_visible else caplog.text)


@pytest.mark.parametrize("case", ["missing", "bad_sig", "expired"])
def test_the_token_verifying_surfaces_refuse_a_bad_token(surface, registry, records, case):
    records(surface)
    if surface.name not in ("hub", "relay"):
        pytest.skip("the in-process gates reach the token through the run context")
    token = _bad_token(case)

    deny = surface.verdict(token)

    assert deny is not None
    assert "agent token" in deny


def test_the_in_process_gates_deny_a_run_without_a_token(registry, records):
    records(_hub_surface())
    from core import agent_factory, tool_gate

    assert asyncio.run(tool_gate.deny_reason(TOOL, surface="host")) is not None
    assert asyncio.run(agent_factory._bound_tool_denial(TOOL)) is not None


def _bad_token(case: str) -> str | None:
    """One token per refusal column; ``expired`` is relative to the real clock."""
    if case == "missing":
        return None
    if case == "bad_sig":
        good = agent_token.mint("agent-a")
        head, signature = good.rsplit(".", 1)
        index = len(signature) // 2
        flipped = "A" if signature[index] != "A" else "B"
        return f"{head}.{signature[:index]}{flipped}{signature[index + 1:]}"
    if case == "expired":
        return agent_token.mint("agent-a", ttl_s=1, now=time.time() - 120)
    raise AssertionError(f"unknown case {case!r}")


# --------------------------------------------------------------------------- #
# hub-specific: the front door and the rollout window
# --------------------------------------------------------------------------- #


def _hub_call(token, config=None):
    return asyncio.run(hub._authorize_call(config or _tool_config(), token))


def test_the_front_door_is_limited_to_public_tools(registry, records):
    """The gateway mints for the caller it serves and has no record of its own; the
    tool's own `public` exposure is its only possible grant."""
    records(_hub_surface())
    registry.policy = _policy()

    claims, denial = _hub_call(_token("gateway"), _tool_config(OTHER_TOOL))
    assert denial is not None and claims.user_id == "user-1"

    claims, denial = _hub_call(_token("gateway"), _tool_config(TOOL, public=True))
    assert denial is None, denial
    assert claims.user_id == "user-1"


def test_public_exposure_does_not_widen_an_agents_allowlist(registry, records):
    records(_hub_surface())
    registry.policy = _policy()

    _claims, denial = _hub_call(_token("agent-b"), _tool_config(TOOL, public=True))

    assert denial is not None
    assert "access_denied" in denial["error"]


def test_the_supervisor_is_checked_against_its_own_allowlist(registry, records, monkeypatch):
    records(_hub_surface())
    fake = FakeRegistry(SUPERVISOR_AGENTS)
    monkeypatch.setattr(hub.identity_mgr, "get_agent_config", fake.get_agent_config)

    _claims, denial = _hub_call(_token("supervisor"))
    assert denial is None, denial

    _claims, denied = _hub_call(_token("supervisor"), _tool_config(OTHER_TOOL))
    assert denied is not None


def test_an_ordinary_front_door_token_grants_nothing_extra(registry, records):
    """v0.7.1 Phase 4: the `principal` claim is gone; only the public flag grants.

    An ordinary token for the gateway agent (= no agent record) is checked exactly
    like any other: the tool's own exposure is its only possible grant, so a
    non-public tool is denied.
    """
    records(_hub_surface())
    registry.policy = _policy()

    _claims, denial = _hub_call(
        agent_token.mint("gateway", user_id="user-1"),
        _tool_config(OTHER_TOOL),
    )

    assert denial is not None


def test_hub_log_mode_still_runs_an_allowlist_refusal(registry, records, monkeypatch):
    """The token/allowlist rollout window: log and run, but never silently."""
    records(_hub_surface())
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    registry.policy = _policy()

    claims, denial = _hub_call(_token("agent-b"))

    assert claims is not None and denial is None


def test_hub_log_mode_applies_a_group_rule(registry, records, monkeypatch):
    """`shadow`/`enforce` is the group-rule switch, not the token-mode one."""
    records(_hub_surface())
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    registry.policy = _policy(_rule([TOOL], [GROUP]))

    _claims, denial = _hub_call(_token(groups=["sre"]))

    assert denial is not None


def test_hub_off_mode_short_circuits(registry, records, monkeypatch):
    records(_hub_surface())
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "off")
    monkeypatch.setenv("DEV_MODE", "true")

    assert _hub_call("not-a-token") == (None, None)


# --------------------------------------------------------------------------- #
# the runner decides nothing: signature, expiry and the discovery kind only
# --------------------------------------------------------------------------- #


def _session(token, *, target="coralogix", kind="mcp_session"):
    return SessionCreateRequest(
        kind=kind, target=target, session_key=SESSION_KEY, agent_token=token
    )


def _console(token):
    return ExecRequest(
        kind="console", target="console", command="echo hi", agent_token=token
    )


def _tool(token, target=TOOL):
    return ExecRequest(kind="tool", target=target, agent_token=token)


def _assert_runner_denied(denial) -> None:
    assert denial is not None, "expected the runner to refuse the request"
    assert denial.status_code == 403
    assert json.loads(denial.body)["detail"]["code"] == "access_denied"


@pytest.fixture
def runner_env(monkeypatch):
    monkeypatch.delenv("RUNNER_ROLE", raising=False)
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv("DEV_MODE", raising=False)
    runner_module.reset_for_tests()
    try:
        yield
    finally:
        runner_module.reset_for_tests()


@pytest.mark.parametrize("case", ["missing", "bad_sig", "expired"])
def test_runner_refuses_a_bad_token(runner_env, case):
    for payload in (
        _session(_bad_token(case)),
        _console(_bad_token(case)),
        _tool(_bad_token(case)),
    ):
        _assert_runner_denied(runner_module._authorize(payload))


@pytest.mark.parametrize("agent", ["agent-a", "agent-b", "ghost", "gateway", "supervisor"])
@pytest.mark.parametrize("kind", ["tool", "console", "mcp_session"])
def test_the_runner_makes_no_allowlist_decision(runner_env, agent, kind):
    """Whatever the target and whoever the agent: a valid token is all the runner checks.

    The hub authorized tool calls before dispatch and the process that owns the agent
    runtime authorized sessions/console (``core.tool_gate``) -- neither of which the
    runner can re-derive from a manifest it does not have.
    """
    token = _token(agent)

    if kind == "tool":
        payload = _tool(token)
    elif kind == "console":
        payload = _console(token)
    else:
        payload = _session(token)

    assert runner_module._authorize(payload) is None


def test_runner_discovery_needs_no_token(runner_env):
    """The one non-agent path: a throwaway catalog read, gated by the socket token."""
    assert runner_module._authorize(_session(None, target="catalog", kind="discovery")) is None


def test_runner_discovery_still_accepts_a_valid_token(runner_env):
    payload = _session(_token(), target="x", kind="discovery")

    assert runner_module._authorize(payload) is None


def test_runner_discovery_still_refuses_a_bad_token(runner_env):
    _assert_runner_denied(
        runner_module._authorize(_session(_bad_token("bad_sig"), target="x", kind="discovery"))
    )


def test_runner_off_mode_short_circuits(runner_env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "off")
    monkeypatch.setenv("DEV_MODE", "true")
    bad = _bad_token("bad_sig")

    assert runner_module._authorize(_session(bad)) is None
    assert runner_module._authorize(_console(bad)) is None


def test_runner_log_mode_runs_a_bad_token(runner_env, monkeypatch):
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")

    assert runner_module._authorize(_session(_bad_token("expired"))) is None


# --------------------------------------------------------------------------- #
# v0.7.2 R1: the edge role -- no key, no verification, identity from the body
# --------------------------------------------------------------------------- #


@pytest.fixture
def edge_runner_env(monkeypatch):
    """An edge runner: no signing key on this host, and `enforce` set to prove it."""
    monkeypatch.setenv("RUNNER_ROLE", "edge")
    monkeypatch.delenv("AGENT_TOKEN_SECRET", raising=False)
    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "enforce")
    monkeypatch.delenv("DEV_MODE", raising=False)
    runner_module.reset_for_tests()
    try:
        yield
    finally:
        runner_module.reset_for_tests()


def _identity(agent="agent-a", **overrides) -> RunIdentity:
    payload = {
        "agent": agent,
        "user_id": "user-1",
        "user_email": "user@example.test",
        "groups": [GROUP],
        "run_id": "run-edge",
    }
    payload.update(overrides)
    return RunIdentity(**payload)


@pytest.mark.parametrize("kind", ["tool", "console", "mcp_session", "discovery"])
def test_the_edge_role_authorizes_every_kind_without_a_token(edge_runner_env, kind):
    """`enforce` + no key: a central runner would refuse all four; the edge has
    nothing to verify with, so it authorizes on the socket + proxy identity."""
    payload = {
        "tool": _tool(None),
        "console": _console(None),
        "mcp_session": _session(None),
        "discovery": _session(None, kind="discovery"),
    }[kind]

    assert runner_module._authorize(payload) is None


@pytest.mark.parametrize("case", ["missing", "bad_sig", "expired"])
def test_the_edge_role_ignores_an_agent_token(edge_runner_env, monkeypatch, case):
    """A token in the body is never verified: nothing is loaded, nothing is read."""
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)  # mint the bait...
    token = _bad_token(case)
    monkeypatch.delenv("AGENT_TOKEN_SECRET", raising=False)  # ...then drop the key

    def never(*_args, **_kwargs):
        raise AssertionError("the edge runner must never verify a token")

    monkeypatch.setattr(runner_module.agent_token_module, "verify", never)
    payload = _tool(token, target=TOOL)

    assert runner_module._authorize(payload) is None


def test_the_edge_role_takes_identity_from_the_body(edge_runner_env):
    payload = _tool(None).model_copy(
        update={"identity": _identity("agent-a", run_id="run-edge")}
    )

    identity = runner_module._request_identity(payload)

    assert identity is payload.identity
    assert (identity.agent, identity.user_id, identity.run_id) == (
        "agent-a",
        "user-1",
        "run-edge",
    )
    assert identity.groups == [GROUP]


def test_a_central_runner_takes_identity_from_the_token(runner_env):
    payload = _tool(_token("agent-a"))

    identity = runner_module._request_identity(payload)

    assert identity.agent == "agent-a"
    assert identity.user_id == "user-1"


@pytest.mark.parametrize("kind", ["tool", "console", "workflow"])
def test_the_edge_role_needs_body_identity(edge_runner_env, kind):
    """No key to fall back on: a run with no identity cannot be served."""
    payload = (
        ExecRequest(kind="workflow", target="demo-inventory", entrypoint="pipeline.py")
        if kind == "workflow"
        else ExecRequest(
            kind=kind,
            target="console" if kind == "console" else TOOL,
            command="echo hi" if kind == "console" else None,
        )
    )

    denial = runner_module._identity_denial(payload)

    assert denial is not None
    assert denial.status_code == 400
    detail = json.loads(denial.body)["detail"]
    assert detail["code"] == "invalid_request"
    assert "RUNNER_ROLE=edge" in detail["message"]


def test_the_edge_role_leaves_discovery_unidentified(edge_runner_env):
    """The agent-free catalog read is the one kind that may arrive bare."""
    assert runner_module._identity_denial(_session(None, kind="discovery")) is None
    # A session is not a top-level run either: identity is optional there too.
    assert runner_module._identity_denial(_session(None)) is None


@pytest.mark.parametrize("payload_kind", ["exec", "session"])
def test_a_central_runner_refuses_body_identity(runner_env, payload_kind):
    """Identity on the verifying role comes from the token, never from the body."""
    identity = _identity()
    payload = (
        ExecRequest(kind="tool", target=TOOL, identity=identity)
        if payload_kind == "exec"
        else SessionCreateRequest(
            kind="mcp_session", target="coralogix", session_key=SESSION_KEY,
            identity=identity,
        )
    )

    denial = runner_module._identity_denial(payload)

    assert denial is not None
    assert denial.status_code == 400
    detail = json.loads(denial.body)["detail"]
    assert detail["code"] == "invalid_request"
    assert "central runner refuses body identity" in detail["message"]


def test_the_shipped_supervisor_manifest_is_an_image_asset():
    """Layout guard: the supervisor is read from the package, not from the workspace."""
    from scripts import sync_to_db

    manifest = sync_to_db.SUPERVISOR_DIR / "config.yaml"
    assert manifest.is_file(), f"the shipped supervisor manifest is missing: {manifest}"
    assert sync_to_db.SUPERVISOR_DIR == (
        sync_to_db.BASE_DIR / "core" / "assets" / "supervisor"
    )
    assert not (sync_to_db.AGENTS_DIR / "supervisor").exists()

    assert sync_to_db.SUPERVISOR_DIR.joinpath("config.yaml").read_text(
        encoding="utf-8"
    ).find("allowed_tools") > 0
