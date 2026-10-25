# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Default-deny tool authorization (``core.tool_authz``).

Pure unit tests: the etcd-backed identity manager is replaced through
``core.auth.get_identity_manager`` -- ``tool_authz`` imports it lazily inside
``_snapshot_values`` -- so there is no network, no etcd and no sleeping.

The snapshot cache, the shadow-deny ring and the request-group ContextVar are
process-global, so every test starts and ends from a clean slate.
"""

import json
import logging

import pytest

from core import agent_token, auth, tool_authz

SECRET = "tool-authz-unit-secret-0123456789abcdef"

LOCAL_TOOL = "opsctl"
CENTRAL_TOOL = "mcp__srv__do__thing"
EDGE_TOOL = "mcp__site__mcp__tool"


class FakeAuthzManager:
    """Registry stand-in carrying only the three authz reads.

    ``fail_from`` makes ``get_tool_policies`` raise from the Nth snapshot load on,
    which is how a warm-cache etcd outage is simulated without a network.
    """

    def __init__(self, *, policy=None, mode="off", groups=None, fail_from=None):
        self.policy = {} if policy is None else policy
        self.mode = mode
        self.groups = {} if groups is None else groups
        self.fail_from = fail_from
        self.policy_reads = 0

    def get_tool_policies(self):
        self.policy_reads += 1
        if self.fail_from is not None and self.policy_reads >= self.fail_from:
            raise RuntimeError("etcd unavailable")
        return self.policy

    def get_tool_authz_mode(self):
        return self.mode

    def get_principal_groups(self):
        return self.groups


@pytest.fixture(autouse=True)
def _authz_isolation():
    """The engine's caches live at module scope; never leak them across tests."""
    tool_authz.reset_cache()
    tool_authz.clear_shadow_denies()
    tool_authz.clear_request_groups()
    yield
    tool_authz.reset_cache()
    tool_authz.clear_shadow_denies()
    tool_authz.clear_request_groups()


@pytest.fixture
def use_registry(monkeypatch):
    """Install a fake authz registry; returns it so tests can mutate/count reads."""

    def install(**kwargs):
        fake = FakeAuthzManager(**kwargs)
        monkeypatch.setattr(auth, "get_identity_manager", lambda: fake)
        tool_authz.reset_cache()
        return fake

    return install


@pytest.fixture
def run_context(monkeypatch):
    """A clean agent-token/user context (reset afterwards), with a signing key."""
    monkeypatch.setenv("AGENT_TOKEN_SECRET", SECRET)
    monkeypatch.delenv("ENFORCE_AGENT_TOKENS", raising=False)
    tokens = [
        (var, var.set(None))
        for var in (auth.agent_token_var, auth.user_id_var, auth.run_id_var)
    ]
    yield
    for var, token in reversed(tokens):
        var.reset(token)


def _policy(*rules):
    return {"default_action": "deny", "rules": list(rules)}


def _rule(tools, principals=("*",), scopes=None):
    rule = {"tools": list(tools), "allow_principals": list(principals)}
    if scopes is not None:
        rule["scopes"] = list(scopes)
    return rule


def _log_payload(caplog):
    """The parsed JSON payload of the last authz log line."""
    messages = [
        record.getMessage()
        for record in caplog.records
        if record.name == "core.tool_authz" and record.getMessage().startswith("{")
    ]
    assert messages, "expected a structured tool_authz log line"
    return json.loads(messages[-1])


# --- 1. default deny ---------------------------------------------------------

@pytest.mark.parametrize(
    "policy",
    [
        pytest.param({}, id="absent-policy"),
        pytest.param(
            {"default_action": "allow", "rules": []}, id="wrong-default-action"
        ),
        pytest.param(
            {"default_action": "deny", "rules": "not-a-list"}, id="rules-not-a-list"
        ),
        pytest.param(
            {"default_action": "deny", "rules": [{"tools": ["*"]}]},
            id="rule-missing-allow-principals",
        ),
        pytest.param({"default_action": "deny", "rules": []}, id="empty-rules"),
    ],
)
def test_default_deny_for_every_tool_and_scope(use_registry, policy):
    use_registry(policy=policy, mode="enforcing")

    for tool in (LOCAL_TOOL, CENTRAL_TOOL, EDGE_TOOL):
        for scope in tool_authz.SCOPES:
            assert tool_authz.evaluate("user:alice", tool, scope) == ("deny", None)
            assert tool_authz.allowed("user:alice", tool, scope) is False


def test_validate_policy_reports_the_schema_errors_it_denies_on():
    assert tool_authz.validate_policy({}) != []
    assert tool_authz.validate_policy({"default_action": "allow", "rules": []}) != []
    assert tool_authz.validate_policy(
        {"default_action": "deny", "rules": "nope"}
    ) != []
    assert tool_authz.validate_policy(_policy(_rule(["opsctl"]))) == []


# --- 2. glob matching across the registry shapes ------------------------------

@pytest.mark.parametrize(
    ("tool", "pattern", "matches"),
    [
        pytest.param(LOCAL_TOOL, "opsctl", True, id="local-exact"),
        pytest.param(LOCAL_TOOL, "ops*", True, id="local-glob"),
        pytest.param(LOCAL_TOOL, "mcp__*__*", False, id="local-no-cross-match"),
        pytest.param(CENTRAL_TOOL, "mcp__srv__*", True, id="central-server-glob"),
        pytest.param(CENTRAL_TOOL, "mcp__*__*", True, id="central-catch-all"),
        pytest.param(CENTRAL_TOOL, "mcp__other__*", False, id="central-other-server"),
        pytest.param(EDGE_TOOL, "mcp__site__*", True, id="edge-site-glob"),
        pytest.param(EDGE_TOOL, "mcp__*__*", True, id="edge-catch-all"),
        pytest.param(EDGE_TOOL, "mcp__srv__*", False, id="edge-not-central"),
        pytest.param(EDGE_TOOL, "netctl", False, id="no-match"),
    ],
)
def test_glob_patterns_match_registry_tool_shapes(use_registry, tool, pattern, matches):
    use_registry(policy=_policy(_rule([pattern])), mode="enforcing")

    verdict, rule = tool_authz.evaluate("user:alice", tool, "tools:call")

    assert verdict == ("allow" if matches else "deny")
    assert (rule is not None) is matches


# --- 3. principal grammar ----------------------------------------------------

@pytest.mark.parametrize(
    "allowed_principal",
    [
        "user:alice",
        "agent:supervisor",
        "workflow:nightly",
        "*",
    ],
)
def test_principal_patterns(use_registry, allowed_principal):
    use_registry(policy=_policy(_rule([LOCAL_TOOL], [allowed_principal])), mode="enforcing")

    assert tool_authz.allowed(allowed_principal, LOCAL_TOOL, "tools:call") is True
    if allowed_principal != "*":
        assert tool_authz.allowed("user:mallory", LOCAL_TOOL, "tools:call") is False


def test_group_principal_resolved_from_the_request_claim(use_registry):
    use_registry(policy=_policy(_rule([LOCAL_TOOL], ["group:ops"])), mode="enforcing")

    assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is False

    tool_authz.set_request_groups(["ops", "engineering"])

    assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is True
    assert tool_authz.allowed("user:mallory", LOCAL_TOOL, "tools:call") is True


@pytest.mark.parametrize("mapping_key", ["user:alice", "alice"])
def test_group_principal_resolved_from_the_registry_mapping(use_registry, mapping_key):
    use_registry(
        policy=_policy(_rule([LOCAL_TOOL], ["group:ops"])),
        mode="enforcing",
        groups={mapping_key: ["ops"]},
    )

    assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is True
    # A different user is not in the group even though the mapping is non-empty.
    assert tool_authz.allowed("user:mallory", LOCAL_TOOL, "tools:call") is False


def test_unknown_principal_is_denied(use_registry):
    use_registry(
        policy=_policy(_rule([LOCAL_TOOL], ["group:ops"])),
        mode="enforcing",
        groups={"user:alice": ["ops"]},
    )

    assert tool_authz.allowed("user:mallory", LOCAL_TOOL, "tools:call") is False
    # The anonymous caller never inherits groups either.
    assert tool_authz.allowed("", LOCAL_TOOL, "tools:call") is False


# --- 4. ordered, first *matching* rule wins ----------------------------------

def test_first_matching_rule_wins_not_first_rule(use_registry):
    policy = _policy(
        _rule([LOCAL_TOOL], ["user:bob"]),  # rule 0: does not match alice
        _rule([LOCAL_TOOL], ["*"]),  # rule 1: matches everyone
    )
    use_registry(policy=policy, mode="enforcing")

    verdict, rule = tool_authz.evaluate("user:alice", LOCAL_TOOL, "tools:call")
    assert verdict == "allow"
    assert rule is policy["rules"][1]

    verdict, rule = tool_authz.evaluate("user:bob", LOCAL_TOOL, "tools:call")
    assert verdict == "allow"
    assert rule is policy["rules"][0]


def test_rule_whose_scope_excludes_the_request_is_skipped(use_registry):
    use_registry(
        policy=_policy(
            _rule([LOCAL_TOOL], ["*"], scopes=["tools:read"]),
            _rule([LOCAL_TOOL], ["user:bob"], scopes=["tools:call"]),
        ),
        mode="enforcing",
    )

    assert tool_authz.evaluate("user:alice", LOCAL_TOOL, "tools:read")[0] == "allow"
    assert tool_authz.evaluate("user:alice", LOCAL_TOOL, "tools:call") == ("deny", None)
    assert tool_authz.evaluate("user:bob", LOCAL_TOOL, "tools:call")[0] == "allow"


def test_absent_scopes_means_both_scopes(use_registry):
    use_registry(policy=_policy(_rule([LOCAL_TOOL])), mode="enforcing")

    for scope in tool_authz.SCOPES:
        assert tool_authz.allowed("user:alice", LOCAL_TOOL, scope) is True


# --- 5. rollout modes --------------------------------------------------------

def test_off_allows_anything_and_records_nothing(use_registry, caplog):
    use_registry(policy=_policy(), mode="off")

    with caplog.at_level(logging.WARNING, logger="core.tool_authz"):
        assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is True

    assert tool_authz.get_mode() == "off"
    assert tool_authz.shadow_denies() == []
    assert "tool_authz_deny" not in caplog.text


def test_shadow_allows_but_records_the_would_be_denial(use_registry, caplog):
    use_registry(policy=_policy(), mode="shadow")

    with caplog.at_level(logging.WARNING, logger="core.tool_authz"):
        assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is True

    entries = tool_authz.shadow_denies()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["principal"] == "user:alice"
    assert entry["tool"] == LOCAL_TOOL
    assert entry["scope"] == "tools:call"
    assert entry["matched_rule"] is None
    assert {"ts", "principal", "tool", "scope", "matched_rule"} <= set(entry)

    payload = _log_payload(caplog)
    assert payload["event"] == "tool_authz_deny"
    assert payload["mode"] == "shadow"
    assert payload["principal"] == "user:alice"
    # Denials are logged structurally and never carry tool arguments.
    assert set(payload) == {
        "event",
        "mode",
        "principal",
        "tool",
        "scope",
        "matched_rule",
    }


def test_enforcing_denies_logs_and_records_the_ring(use_registry, caplog):
    use_registry(policy=_policy(), mode="enforcing")

    with caplog.at_level(logging.WARNING, logger="core.tool_authz"):
        assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is False

    # Enforcing denials are recorded too (mode-tagged) so the admin table does not go
    # blank the moment an operator flips the switch.
    denies = tool_authz.shadow_denies()
    assert denies and denies[0]["mode"] == "enforcing"
    assert denies[0]["tool"] == LOCAL_TOOL

    payload = _log_payload(caplog)
    assert payload["event"] == "tool_authz_deny"
    assert payload["mode"] == "enforcing"


def test_shadow_deny_ring_is_newest_first(use_registry):
    use_registry(policy=_policy(), mode="shadow")

    tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call")
    tool_authz.allowed("user:alice", "netctl", "tools:read")

    assert [entry["tool"] for entry in tool_authz.shadow_denies()] == [
        "netctl",
        LOCAL_TOOL,
    ]


def test_unrecognized_mode_falls_back_to_off(use_registry):
    use_registry(policy=_policy(), mode="not-a-mode")

    assert tool_authz.get_mode() == "off"
    assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is True


# --- 6. principal resolution -------------------------------------------------

def test_no_token_with_user_is_a_user_principal(run_context):
    auth.user_id_var.set("alice")

    assert tool_authz.resolve_current_principal() == "user:alice"


def test_no_token_no_user_is_anonymous(run_context):
    assert tool_authz.resolve_current_principal() == "anonymous"


def test_background_run_token_is_a_workflow_principal(run_context):
    # Background runs mint their token for the `svc_agent_<workflow>` identity.
    assert agent_token.mint_for_run("nightly", "svc_agent_wf", run_id="run-1")

    assert tool_authz.resolve_current_principal() == "workflow:nightly"


def test_gateway_system_token_attributes_to_the_user(run_context):
    auth.user_id_var.set("alice")
    assert (
        agent_token.mint_for_run("gateway", "alice", run_id="run-1", principal="system")
    )

    assert tool_authz.resolve_current_principal() == "user:alice"


def test_plain_agent_token_is_an_agent_principal(run_context):
    assert agent_token.mint_for_run("supervisor", "alice", run_id="run-1")

    assert tool_authz.resolve_current_principal() == "agent:supervisor"


# --- 7. bootstrap from the public registry -----------------------------------

BOOTSTRAP_TOOL_CONFIGS = {
    "opsctl": {"name": "opsctl", "public": True},
    "system_restart": {"name": "system_restart", "public": False},
    "auditctl": {"name": "auditctl"},  # no `public` key -> internal
}

BOOTSTRAP_MCP_CONFIGS = {
    # Fully public server: both tools, one of them a central name with `__` in it.
    "srv-all": {
        "public": True,
        "tools": [{"name": "do__thing"}, {"name": "health"}],
    },
    # Only one of the two tools is selected.
    "srv-pick": {
        "public": False,
        "public_tools": ["clusters_get_all"],
        "tools": [{"name": "clusters_get_all"}, {"name": "internal_admin_tool"}],
    },
    # An edge-exported server registers under the `<site>__<mcp>` key.
    "site__mcp": {"public": True, "tools": [{"name": "tool"}]},
}

BOOTSTRAP_PUBLIC_NAMES = {
    "opsctl",
    "mcp__srv-all__do__thing",
    "mcp__srv-all__health",
    "mcp__srv-pick__clusters_get_all",
    "mcp__site__mcp__tool",
}


def test_bootstrap_policy_covers_exactly_the_public_tools(use_registry):
    doc = tool_authz.bootstrap_policy(BOOTSTRAP_TOOL_CONFIGS, BOOTSTRAP_MCP_CONFIGS)

    assert doc["default_action"] == "deny"
    assert tool_authz.validate_policy(doc) == []
    assert {rule["tools"][0] for rule in doc["rules"]} == BOOTSTRAP_PUBLIC_NAMES
    assert [rule["tools"][0] for rule in doc["rules"]] == sorted(BOOTSTRAP_PUBLIC_NAMES)

    use_registry(policy=doc, mode="enforcing")
    for name in BOOTSTRAP_PUBLIC_NAMES:
        for scope in tool_authz.SCOPES:
            assert tool_authz.evaluate("*", name, scope)[0] == "allow"

    # Tools that were internal before the bootstrap stay unreachable.
    for name in ("system_restart", "auditctl", "mcp__srv-pick__internal_admin_tool"):
        assert tool_authz.evaluate("*", name, "tools:call")[0] == "deny"


def test_bootstrap_policy_skips_malformed_configs():
    doc = tool_authz.bootstrap_policy(
        {
            "broken": "not-a-dict",
            "": {"public": True, "name": ""},
            "good": {"public": True},
        },
        {
            "": {"public": True, "tools": [{"name": "x"}]},
            "bad-tools": {"public": True, "tools": "nope"},
            "bad-entry": {"public": True, "tools": ["nope", {"name": ""}]},
        },
    )

    # `good` has no explicit name, so it is addressed by its registry key.
    assert {rule["tools"][0] for rule in doc["rules"]} == {"good"}


# --- 8. snapshot cache invalidation ------------------------------------------

def test_snapshot_is_read_once_per_ttl(use_registry):
    fake = use_registry(policy=_policy(_rule([LOCAL_TOOL])), mode="enforcing")

    assert tool_authz.get_mode() == "enforcing"
    assert tool_authz.get_mode() == "enforcing"
    assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is True

    assert fake.policy_reads == 1


def test_reset_cache_forces_a_reread(use_registry):
    fake = use_registry(policy=_policy(), mode="enforcing")
    tool_authz.get_mode()
    assert fake.policy_reads == 1

    tool_authz.reset_cache()

    assert tool_authz.get_mode() == "enforcing"
    assert fake.policy_reads == 2


def test_watch_callback_drops_the_cached_snapshot(use_registry):
    fake = use_registry(policy=_policy(), mode="enforcing")
    tool_authz.get_mode()
    assert fake.policy_reads == 1

    tool_authz._on_authz_change(None)  # what the etcd watch invokes

    assert tool_authz.get_mode() == "enforcing"
    assert fake.policy_reads == 2


def test_edits_are_invisible_until_the_cache_is_dropped(use_registry):
    fake = use_registry(policy=_policy(_rule([LOCAL_TOOL])), mode="enforcing")
    assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is True

    fake.policy = _policy()

    assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is True  # cached

    tool_authz.reset_cache()

    assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is False


def test_read_failure_after_a_good_snapshot_keeps_serving_it(use_registry, monkeypatch, caplog):
    # Zero TTL so every call after the first goes back to the (now failing) registry.
    monkeypatch.setattr(tool_authz, "CACHE_TTL_S", 0.0)
    fake = use_registry(
        policy=_policy(_rule([LOCAL_TOOL])), mode="enforcing", fail_from=2
    )
    assert tool_authz.get_mode() == "enforcing"
    assert fake.policy_reads == 1

    with caplog.at_level(logging.WARNING, logger="core.tool_authz"):
        # The read fails, so the previous snapshot (mode + policy) keeps serving.
        assert tool_authz.get_mode() == "enforcing"
        assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is True
        assert tool_authz.allowed("user:alice", "netctl", "tools:call") is False

    assert fake.policy_reads == 2  # failure is not retried inside the error window
    assert "Failed to read tool authorization state" in caplog.text


def test_cold_read_failure_falls_back_to_off(use_registry):
    use_registry(policy=_policy(), mode="enforcing", fail_from=1)

    # No snapshot yet, so there is nothing to keep serving: the engine reports `off`.
    assert tool_authz.get_mode() == "off"
    assert tool_authz.allowed("user:alice", LOCAL_TOOL, "tools:call") is True


def test_validate_policy_rejects_unknown_fields_and_non_json_values():
    good = {"default_action": "deny", "rules": []}
    assert tool_authz.validate_policy(good) == []

    assert any("unknown policy fields" in e for e in tool_authz.validate_policy(
        {"default_action": "deny", "rules": [], "extra": 1}
    ))
    assert any("unknown fields" in e for e in tool_authz.validate_policy(
        {"default_action": "deny", "rules": [{"tools": ["a"], "allow_principals": ["*"], "note": "x"}]}
    ))

    import datetime as _dt
    errors = tool_authz.validate_policy(
        {"default_action": "deny", "rules": [], "note": _dt.date(2026, 1, 1)}
    )
    assert any("JSON-serializable" in e for e in errors)


def test_watch_install_is_idempotent_and_cancellable(monkeypatch):
    class FakeClient:
        def __init__(self):
            self.watches = []
            self.cancelled = []

        def add_watch_prefix_callback(self, prefix, cb):
            self.watches.append(prefix)
            return len(self.watches)

        def cancel_watch(self, watch_id):
            self.cancelled.append(watch_id)

    client = FakeClient()
    monkeypatch.setattr(auth, "get_identity_manager", lambda: type("M", (), {"client": client})())
    tool_authz.cancel_tool_authz_watch()  # clear any sentinel left by another test

    tool_authz.install_tool_authz_watch()
    tool_authz.install_tool_authz_watch()
    assert client.watches == [
        "/registry/tool_policies",
        "/config/framework/tool_authz_mode",
        "/config/framework/principal_groups",
    ]

    tool_authz.cancel_tool_authz_watch()
    assert client.cancelled == [1, 2, 3]
    tool_authz.cancel_tool_authz_watch()  # idempotent


def test_unrecognized_mode_fails_closed_to_enforcing():
    from core.auth import IdentityManager

    mgr = IdentityManager.__new__(IdentityManager)
    mgr.get_config = lambda key, default=None: "enforcin"  # typo

    assert mgr.get_tool_authz_mode() == "enforcing"
