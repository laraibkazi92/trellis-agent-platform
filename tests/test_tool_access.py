# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The single tool-access evaluator (``core.tool_access``).

Two halves decide one call: the agent's own allowlist (always enforced) and the
workspace group rules (one mode switch). The registry is replaced through the
module's ``_client`` seam, so every test runs without etcd, without a network and
without sleeping.

The snapshot cache, the mode cache and the shadow ring are process-global, so every
test starts and ends from a clean slate.
"""

import asyncio
import json
import threading
import time

import pytest

from core import allowlist, tool_access

LOCAL_TOOL = "text_stats"
CENTRAL_MCP_TOOL = "mcp__coralogix__list_alerts"
EDGE_TOOL = "dc1__node_ssh"
EDGE_MCP_TOOL = "mcp__dc1__devops-cli__kubectl"


class _Metadata:
    def __init__(self, revision):
        self.mod_revision = revision


class FakeEtcd:
    """Minimal registry: the policy document, the shadow ring, and the watch API."""

    def __init__(self):
        self.policy = None
        self.shared_ring = None
        self.error = None
        self.revision = 1
        self.reads = []
        self.puts = []
        self.watches = []
        self.cancelled = []

    # -- registry ---------------------------------------------------------- #
    def get(self, key, **_kwargs):
        if self.error is not None:
            raise RuntimeError(self.error)
        self.reads.append(key)
        if key == tool_access.POLICY_PATH:
            if self.policy is None:
                return None, None
            return json.dumps(self.policy).encode("utf-8"), _Metadata(self.revision)
        if key == tool_access.SHADOW_DENIAL_PATH:
            return self.shared_ring, None
        return None, None

    def put(self, key, value):
        if self.error is not None:
            raise RuntimeError(self.error)
        payload = value.encode("utf-8") if isinstance(value, str) else value
        self.puts.append((key, payload))
        if key == tool_access.POLICY_PATH:
            self.policy = json.loads(payload.decode("utf-8"))
            self.revision += 1
        elif key == tool_access.SHADOW_DENIAL_PATH:
            self.shared_ring = payload

    # -- watch ------------------------------------------------------------- #
    def add_watch_callback(self, key, callback):
        self.watches.append((key, callback))
        return len(self.watches)

    def cancel_watch(self, watch_id):
        self.cancelled.append(watch_id)

    # -- helpers ----------------------------------------------------------- #
    def set_policy(self, document, *, reset=True):
        self.policy = document
        self.revision += 1
        if reset:
            tool_access.reset_snapshot()


@pytest.fixture(autouse=True)
def registry(monkeypatch):
    """A hermetic registry + a clean snapshot, mode cache and shadow ring."""
    fake = FakeEtcd()
    monkeypatch.setattr(tool_access, "_client", lambda: fake)
    monkeypatch.setattr(tool_access, "_watch_ids", None)
    monkeypatch.delenv(tool_access.MODE_ENV, raising=False)
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()
    monkeypatch.setattr(tool_access, "_last_shadow_persist", 0.0)
    monkeypatch.setattr(tool_access, "_warned_policy_lines", set())
    yield fake
    tool_access.reset_snapshot()
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()


def _policy(*rules):
    return {"rules": [dict(rule) for rule in rules]}


def _rule(targets, groups, name=None):
    rule = {"targets": list(targets), "groups": list(groups)}
    if name is not None:
        rule["name"] = name
    return rule


def _allowed(tools=(), mcps=()):
    return allowlist.resolve({"allowed_tools": list(tools), "allowed_mcps": list(mcps)})


def _authorize(target, *, groups=(), allowed=None, agent="agent-a", public=False, **kwargs):
    return tool_access.authorize(
        agent=agent,
        groups=groups,
        target=target,
        allowed=allowed,
        public=public,
        surface=kwargs.pop("surface", "hub"),
        **kwargs,
    )


# --- 1. the allowlist half -----------------------------------------------------


def test_allowlist_denies_a_target_the_agent_does_not_hold(registry):
    decision = _authorize(LOCAL_TOOL, allowed=_allowed(tools=["echo"]))

    assert decision.allowed is False
    assert decision.reason == tool_access.REASON_NOT_IN_ALLOWLIST
    assert LOCAL_TOOL in decision.message
    assert "agent-a" in decision.message
    assert "[hub]" in decision.message  # the surface is attributable in the log


def test_no_agent_record_and_not_public_denies(registry):
    decision = _authorize(LOCAL_TOOL, agent=None, allowed=None)

    assert decision.allowed is False
    assert decision.reason == tool_access.REASON_NOT_IN_ALLOWLIST
    assert "no agent record" in decision.message


def test_allowlist_allows_when_no_rule_matches(registry):
    decision = _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL]))

    assert decision.allowed is True
    assert decision.reason == tool_access.REASON_ALLOWLIST
    assert decision.rule is None


def test_mcp_session_uses_the_allowlist_session_helper(registry):
    decision = _authorize(
        "coralogix", allowed=_allowed(mcps=["coralogix"]), session=True, surface="host"
    )
    assert decision.allowed is True

    denied = _authorize(
        "coralogix", allowed=_allowed(tools=["text_stats"]), session=True, surface="host"
    )
    assert denied.allowed is False
    assert denied.reason == tool_access.REASON_NOT_IN_ALLOWLIST


def test_edge_mcp_session_reference_is_split_into_site_and_server(registry):
    decision = _authorize(
        "dc1__devops-cli", allowed=_allowed(mcps=["dc1__devops-cli"]), session=True
    )
    assert decision.allowed is True

    wildcard = _authorize("dc1__devops-cli", allowed=_allowed(mcps=["dc1__*"]), session=True)
    assert wildcard.allowed is True


# --- 2. the public front door --------------------------------------------------


def test_public_replaces_the_allowlist_part(registry):
    decision = _authorize(LOCAL_TOOL, agent=None, allowed=None, public=True)

    assert decision.allowed is True
    assert decision.reason == tool_access.REASON_PUBLIC


def test_public_does_not_bypass_group_rules(registry):
    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["ops"])))

    denied = _authorize(LOCAL_TOOL, agent=None, allowed=None, public=True)
    assert denied.allowed is False
    assert denied.reason == tool_access.REASON_GROUP_DENIED

    allowed = _authorize(LOCAL_TOOL, agent=None, groups=["ops"], public=True)
    assert allowed.allowed is True
    assert allowed.reason == tool_access.REASON_GROUP_MATCH


# --- 3. target forms -----------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "patterns", "allow_config", "matches"),
    [
        pytest.param(LOCAL_TOOL, ["text_stats"], {"tools": [LOCAL_TOOL]}, True, id="exact"),
        pytest.param(LOCAL_TOOL, ["text_*"], {"tools": [LOCAL_TOOL]}, True, id="glob"),
        pytest.param(LOCAL_TOOL, ["net_*"], {"tools": [LOCAL_TOOL]}, False, id="glob-miss"),
        pytest.param(
            EDGE_TOOL, ["dc1__*"], {"tools": [EDGE_TOOL]}, True, id="edge-tool-glob"
        ),
        pytest.param(
            EDGE_TOOL, [EDGE_TOOL], {"tools": [EDGE_TOOL]}, True, id="edge-tool-exact"
        ),
        pytest.param(
            EDGE_TOOL,
            ["mcp__dc1__*"],
            {"tools": [EDGE_TOOL]},
            False,
            id="edge-tool-not-an-mcp",
        ),
        pytest.param(
            CENTRAL_MCP_TOOL,
            ["mcp__coralogix__*"],
            {"mcps": ["coralogix"]},
            True,
            id="central-mcp-glob",
        ),
        pytest.param(
            CENTRAL_MCP_TOOL,
            ["mcp__*"],
            {"mcps": ["coralogix"]},
            True,
            id="central-mcp-catch-all",
        ),
        pytest.param(
            CENTRAL_MCP_TOOL,
            ["mcp__other__*"],
            {"mcps": ["coralogix"]},
            False,
            id="central-mcp-other-server",
        ),
        pytest.param(
            EDGE_MCP_TOOL,
            ["mcp__dc1__devops-cli__*"],
            {"mcps": ["dc1__devops-cli"]},
            True,
            id="edge-mcp-glob",
        ),
        pytest.param(
            EDGE_MCP_TOOL,
            ["mcp__dc1__devops-cli__kubectl"],
            {"mcps": ["dc1__*"]},
            True,
            id="edge-mcp-exact",
        ),
        pytest.param(
            EDGE_MCP_TOOL,
            ["mcp__coralogix__*"],
            {"mcps": ["dc1__*"]},
            False,
            id="edge-mcp-other-site",
        ),
        pytest.param("execute", ["execute"], {"tools": ["execute"]}, True, id="console"),
    ],
)
def test_rule_patterns_match_every_reference_form(
    registry, target, patterns, allow_config, matches
):
    registry.set_policy(_policy(_rule(patterns, ["ops"])))
    granted = allowlist.resolve(
        {
            "allowed_tools": allow_config.get("tools", []),
            "allowed_mcps": allow_config.get("mcps", []),
        }
    )

    # A caller in none of the groups is denied exactly when a rule matched.
    denied = _authorize(target, allowed=granted)
    assert denied.allowed is (not matches)
    assert denied.reason == (
        tool_access.REASON_GROUP_DENIED if matches else tool_access.REASON_ALLOWLIST
    )

    # ... and a caller in the group is allowed either way.
    assert _authorize(target, groups=["ops"], allowed=granted).allowed is True


# --- 4. group sets -------------------------------------------------------------


def test_rule_with_several_groups_admits_any_of_them(registry):
    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["sre", "platform-ops"], name="ops")))

    for groups in (["sre"], ["platform-ops"], ["sre", "other"]):
        decision = _authorize(LOCAL_TOOL, groups=groups, allowed=_allowed(tools=[LOCAL_TOOL]))
        assert decision.allowed is True, groups
        assert decision.rule == "ops"

    outsider = _authorize(LOCAL_TOOL, groups=["interns"], allowed=_allowed(tools=[LOCAL_TOOL]))
    assert outsider.allowed is False
    assert outsider.reason == tool_access.REASON_GROUP_DENIED
    assert outsider.rule == "ops"


def test_caller_in_none_of_the_groups_is_denied_without_groups(registry):
    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["sre"])))

    decision = _authorize(LOCAL_TOOL, groups=[], allowed=_allowed(tools=[LOCAL_TOOL]))

    assert decision.allowed is False
    assert decision.reason == tool_access.REASON_GROUP_DENIED
    assert LOCAL_TOOL in decision.message


def test_several_matching_rules_are_a_union_of_groups(registry):
    registry.set_policy(
        _policy(
            _rule([LOCAL_TOOL], ["sre"], name="a"),
            _rule(["text_*"], ["observability"], name="b"),
        )
    )

    decision = _authorize(
        LOCAL_TOOL, groups=["observability"], allowed=_allowed(tools=[LOCAL_TOOL])
    )

    assert decision.allowed is True
    assert decision.rule == "b"


def test_group_rules_cannot_grant_what_the_allowlist_denies(registry):
    registry.set_policy(_policy(_rule(["*"], ["ops"])))

    decision = _authorize(LOCAL_TOOL, groups=["ops"], allowed=_allowed(tools=["echo"]))

    assert decision.allowed is False
    assert decision.reason == tool_access.REASON_NOT_IN_ALLOWLIST


def test_session_target_is_matched_by_its_server_reference(registry):
    registry.set_policy(_policy(_rule(["coralogix"], ["ops"])))

    denied = _authorize(
        "coralogix", allowed=_allowed(mcps=["coralogix"]), session=True, surface="host"
    )
    assert denied.allowed is False and denied.reason == tool_access.REASON_GROUP_DENIED

    allowed = _authorize(
        "coralogix",
        groups=["ops"],
        allowed=_allowed(mcps=["coralogix"]),
        session=True,
        surface="host",
    )
    assert allowed.allowed is True


# --- 5. unusable references ----------------------------------------------------

@pytest.mark.parametrize("target", ["", "   ", None])
def test_empty_target_is_unknown_target(registry, target):
    decision = _authorize(target, allowed=_allowed(tools=[LOCAL_TOOL]))

    assert decision.allowed is False
    assert decision.reason == tool_access.REASON_UNKNOWN_TARGET


def test_authorize_claims_takes_the_agent_and_groups_from_the_token(registry):
    from types import SimpleNamespace

    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["ops"])))
    claims = SimpleNamespace(agent="agent-a", groups=("ops",))

    decision = tool_access.authorize_claims(
        claims, target=LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL]), surface="relay"
    )
    assert decision.allowed is True
    assert decision.reason == tool_access.REASON_GROUP_MATCH

    # No verified token: no agent, no groups -- the group rule denies.
    anonymous = tool_access.authorize_claims(
        None, target=LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL])
    )
    assert anonymous.allowed is False
    assert anonymous.reason == tool_access.REASON_GROUP_DENIED


def test_unusable_session_reference_is_unknown_target(registry):
    decision = _authorize(
        "a__b__c", allowed=_allowed(mcps=["a__b"]), session=True, surface="host"
    )

    assert decision.allowed is False
    assert decision.reason == tool_access.REASON_UNKNOWN_TARGET


# --- 6. mode -------------------------------------------------------------------


def test_default_mode_is_enforce(registry):
    assert tool_access.tool_access_mode() == "enforce"


@pytest.mark.parametrize("value", ["off", "shadow", "enforce", " ENFORCE "])
def test_valid_mode_values(registry, monkeypatch, value):
    monkeypatch.setenv(tool_access.MODE_ENV, value)
    assert tool_access.tool_access_mode() == value.strip().lower()


@pytest.mark.parametrize("value", ["enforcing", "on", "true", "1", "deny"])
def test_invalid_mode_fails_closed_to_enforce_and_logs_once(registry, monkeypatch, caplog, value):
    monkeypatch.setenv(tool_access.MODE_ENV, value)

    with caplog.at_level("ERROR", logger="core.tool_access"):
        assert tool_access.tool_access_mode() == "enforce"
        assert tool_access.tool_access_mode() == "enforce"

    errors = [record for record in caplog.records if record.levelname == "ERROR"]
    assert len(errors) == 1  # once per distinct value, not once per call
    assert value in errors[0].getMessage()


def test_off_mode_warns_once_per_process(registry, monkeypatch, caplog):
    monkeypatch.setenv(tool_access.MODE_ENV, "off")

    with caplog.at_level("WARNING", logger="core.tool_access"):
        assert tool_access.tool_access_mode() == "off"
        assert tool_access.tool_access_mode() == "off"

    warnings = [
        record.getMessage()
        for record in caplog.records
        if "group rules are NOT enforced" in record.getMessage()
    ]
    assert len(warnings) == 1


def test_shadow_allows_but_records_the_denial(registry, caplog):
    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["ops"])))
    denied = _authorize(LOCAL_TOOL, groups=["interns"], allowed=_allowed(tools=[LOCAL_TOOL]))
    assert denied.allowed is False

    with caplog.at_level("WARNING", logger="core.tool_access"):
        outcome = tool_access.enforce(
            denied,
            "shadow",
            agent="agent-a",
            groups=["interns"],
            target=LOCAL_TOOL,
            surface="hub",
        )

    assert outcome.allowed is True
    assert outcome.reason == tool_access.REASON_SHADOW

    entries = tool_access.recent_shadow_denials()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["agent"] == "agent-a"
    assert entry["target"] == LOCAL_TOOL
    assert entry["reason"] == tool_access.REASON_GROUP_DENIED
    assert entry["groups"] == ["interns"]
    assert entry["surface"] == "hub"
    assert entry["mode"] == "shadow"
    # No identity beyond the agent/target/groups.
    assert "user" not in entry and "email" not in entry

    messages = [record.getMessage() for record in caplog.records]
    assert any(
        message.startswith("tool_access: would deny agent=agent-a target=text_stats")
        for message in messages
    )


def test_shadow_never_widens_the_allowlist(registry):
    denied = _authorize(LOCAL_TOOL, allowed=_allowed(tools=["echo"]))

    outcome = tool_access.enforce(denied, "shadow")

    assert outcome.allowed is False
    assert outcome.reason == tool_access.REASON_NOT_IN_ALLOWLIST
    assert tool_access.recent_shadow_denials() == []

def test_off_ignores_group_rules_but_keeps_the_allowlist(registry):
    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["ops"])))
    group_denied = _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL]))
    assert group_denied.allowed is False

    outcome = tool_access.enforce(group_denied, "off")
    assert outcome.allowed is True
    assert outcome.reason == tool_access.REASON_MODE_OFF

    allowlist_denied = _authorize(LOCAL_TOOL, allowed=_allowed(tools=["echo"]))
    assert tool_access.enforce(allowlist_denied, "off").allowed is False


def test_enforce_returns_a_denial_unchanged(registry):
    denied = _authorize(LOCAL_TOOL, allowed=_allowed(tools=["echo"]))

    outcome = tool_access.enforce(denied, "enforce")

    assert outcome is denied


def test_enforce_defaults_to_the_env_mode(registry, monkeypatch):
    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["ops"])))
    denied = _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL]))

    monkeypatch.setenv(tool_access.MODE_ENV, "shadow")
    assert tool_access.enforce(denied).allowed is True

    monkeypatch.setenv(tool_access.MODE_ENV, "enforce")
    assert tool_access.enforce(denied).allowed is False


# --- 7. fail closed ------------------------------------------------------------


@pytest.mark.parametrize(
    "document",
    [
        pytest.param({"rules": "not-a-list"}, id="rules-not-a-list"),
        pytest.param({"rules": [{"targets": ["x"]}]}, id="rule-without-groups"),
        pytest.param({"rules": [{"targets": ["x"], "groups": []}]}, id="empty-groups"),
        pytest.param({"rules": [{"groups": ["ops"]}]}, id="rule-without-targets"),
        pytest.param({"rules": [], "default_action": "allow"}, id="unknown-field"),
        pytest.param({"rules": [{"targets": ["x"], "groups": ["ops"], "prio": 1}]}, id="unknown-rule-field"),
        pytest.param(
            {"rules": [{"targets": ["x"], "groups": ["ops"]}, {"targets": ["x"], "groups": ["ops"]}]},
            id="duplicate-rule",
        ),
        pytest.param([], id="not-a-mapping"),
    ],
)
def test_invalid_policy_fails_closed(registry, document):
    registry.set_policy(document)

    decision = _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL]))

    assert decision.allowed is False
    assert decision.reason == tool_access.REASON_POLICY_UNAVAILABLE
    assert not tool_access.policy_snapshot().available


def test_policy_read_error_fails_closed(registry):
    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["ops"])))
    # Warm the snapshot with a good document first: a failure must not fall back to
    # it (that is the fail-open shape this module replaces).
    assert _authorize(LOCAL_TOOL, groups=["ops"], allowed=_allowed(tools=[LOCAL_TOOL])).allowed

    tool_access.reset_snapshot()
    registry.error = "etcd unavailable"

    decision = _authorize(LOCAL_TOOL, groups=["ops"], allowed=_allowed(tools=[LOCAL_TOOL]))
    assert decision.allowed is False
    assert decision.reason == tool_access.REASON_POLICY_UNAVAILABLE
    assert "policy read failed" in tool_access.policy_snapshot().error


def test_off_and_shadow_relax_a_policy_read_failure(registry):
    registry.error = "etcd down"
    denied = _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL]))
    assert denied.reason == tool_access.REASON_POLICY_UNAVAILABLE

    assert tool_access.enforce(denied, "off").allowed is True
    assert tool_access.enforce(denied, "shadow").allowed is True
    assert tool_access.recent_shadow_denials()[0]["reason"] == (
        tool_access.REASON_POLICY_UNAVAILABLE
    )


def test_absent_policy_means_no_group_rules(registry):
    registry.policy = None

    decision = _authorize(LOCAL_TOOL, groups=[], allowed=_allowed(tools=[LOCAL_TOOL]))

    assert decision.allowed is True
    assert decision.reason == tool_access.REASON_ALLOWLIST
    assert tool_access.group_rules() == ()
    assert tool_access.policy_snapshot().available is True


def test_policy_snapshot_never_serves_an_expired_document(registry, monkeypatch):
    """The fast path must never trust a stale document (the ``10b2769`` defect).

    There is no "peek without I/O" API any more: an expired snapshot is simply not
    reusable, so the next :func:`policy_snapshot` goes back to the registry.
    """
    registry.set_policy({"rules": []})
    assert tool_access.policy_snapshot().available is True
    assert registry.reads.count(tool_access.POLICY_PATH) == 1

    # A second call inside the TTL is served from the cache (no new registry read).
    assert tool_access.policy_snapshot().available is True
    assert registry.reads.count(tool_access.POLICY_PATH) == 1

    # Expire it the way the TTL would: the next read must go to the registry.
    monkeypatch.setattr(tool_access, "_snapshot_expiry", 0.0)
    registry.set_policy({"rules": []}, reset=False)

    assert tool_access.policy_snapshot().available is True
    assert registry.reads.count(tool_access.POLICY_PATH) == 2


def test_validate_policy_accepts_the_shipped_workspace_file():
    from pathlib import Path

    import yaml

    path = Path(__file__).resolve().parent.parent / "workspace" / "policies" / "tool_access.yaml"
    document = yaml.safe_load(path.read_text())

    assert tool_access.validate_policy(document) == []
    assert document == {"rules": []}


@pytest.mark.parametrize(
    ("rule", "needle"),
    [
        pytest.param({"targets": ["x"], "groups": "ops"}, "groups must be a list", id="groups-not-a-list"),
        pytest.param({"targets": ["x"], "groups": [""]}, "groups must contain non-empty", id="empty-group-name"),
        pytest.param({"targets": [], "groups": ["ops"]}, "at least one pattern", id="empty-targets"),
        pytest.param({"targets": ["x"], "groups": ["ops"], "name": ""}, "name must be a non-empty", id="empty-name"),
        pytest.param({"targets": ["x"], "groups": ["ops"]}, None, id="valid"),
    ],
)
def test_validate_policy_reports_the_schema_errors_it_denies_on(rule, needle):
    errors = tool_access.validate_policy({"rules": [rule]})

    if needle is None:
        assert errors == []
    else:
        assert any(needle in error for error in errors), errors


def test_duplicate_rule_names_are_invalid():
    document = {
        "rules": [
            {"name": "a", "targets": ["x"], "groups": ["ops"]},
            {"name": "a", "targets": ["y"], "groups": ["ops"]},
        ]
    }

    assert any("duplicates rule name" in error for error in tool_access.validate_policy(document))


def test_publish_policy_validates_before_writing(registry):
    tool_access.publish_policy({"rules": []}, client=registry)
    assert registry.policy == {"rules": []}

    with pytest.raises(tool_access.PolicyInvalid):
        tool_access.publish_policy({"rules": [{"targets": ["x"]}]}, client=registry)
    assert registry.policy == {"rules": []}  # the good document is untouched


# --- 8. the watch --------------------------------------------------------------


def _event(key, value=b""):
    class _KV:
        def __init__(self, k):
            self.key = k.encode("utf-8") if isinstance(k, str) else k
            self.value = value

    class _Event:
        def __init__(self, k):
            self.kv = _KV(k)

    class _Response:
        def __init__(self, k):
            self.events = [_Event(k)]

    return _Response(key)


def test_watch_is_installed_once_and_picks_up_an_edited_policy(registry):
    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["ops"])))
    assert _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL])).allowed is False

    tool_access.install_watch()
    tool_access.install_watch()  # idempotent
    assert len(registry.watches) == 1
    assert registry.watches[0][0] == tool_access.POLICY_PATH

    # An admin edit lands in etcd; the watch callback is what makes it immediate.
    registry.set_policy(_policy())
    registry.watches[0][1](_event(tool_access.POLICY_PATH))

    assert _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL])).allowed is True


def test_watch_ignores_the_shadow_ring_key(registry):
    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["ops"])))
    tool_access.install_watch()
    assert _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL])).allowed is False

    # A ring write must not clear the policy snapshot (same key prefix).
    registry.set_policy(_policy(), reset=False)
    registry.watches[0][1](_event(tool_access.SHADOW_DENIAL_PATH))

    assert _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL])).allowed is False

    registry.watches[0][1](_event(tool_access.POLICY_PATH))
    assert _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL])).allowed is True


def test_cancel_watch_is_idempotent(registry):
    tool_access.install_watch()
    tool_access.cancel_watch()
    tool_access.cancel_watch()

    assert registry.cancelled == [1]


def test_install_watch_falls_back_to_a_prefix_watch(registry, monkeypatch):
    class PrefixOnlyClient(FakeEtcd):
        # pyetcd has an exact-key watch; a stand-in may only offer the prefix form.
        add_watch_callback = None

        def add_watch_prefix_callback(self, key, callback):
            self.watches.append((key, callback))
            return 1

    fake = PrefixOnlyClient()
    monkeypatch.setattr(tool_access, "_client", lambda: fake)

    tool_access.install_watch()

    assert [key for key, _callback in fake.watches] == [tool_access.POLICY_PATH]


# --- 9. the shadow ring --------------------------------------------------------


def test_shadow_ring_is_bounded_and_newest_first(registry):
    for index in range(tool_access.SHADOW_RING_CAP + 10):
        decision = tool_access.deny(tool_access.REASON_GROUP_DENIED, f"denied {index}")
        tool_access.record_shadow_denial(decision, agent="a", target=f"t{index}")

    # Read the process-local ring (the shared one is throttled to ~1 write/second).
    registry.shared_ring = None
    entries = tool_access.recent_shadow_denials()

    assert len(entries) == tool_access.SHADOW_RING_CAP
    assert entries[0]["target"] == f"t{tool_access.SHADOW_RING_CAP + 9}"


def test_shadow_denials_share_one_ring_across_processes(registry):
    decision = tool_access.deny(tool_access.REASON_GROUP_DENIED, "no")
    tool_access.record_shadow_denial(decision, agent="hub-agent", target=LOCAL_TOOL)

    shared = json.loads(registry.shared_ring.decode("utf-8"))
    assert shared["denials"][0]["agent"] == "hub-agent"

    # A second process's ring is what the admin page reads.
    with tool_access._shadow_lock:
        tool_access._shadow_ring.clear()

    entries = tool_access.recent_shadow_denials()
    assert [entry["agent"] for entry in entries] == ["hub-agent"]


def test_clear_shadow_denials_empties_both_rings(registry):
    decision = tool_access.deny(tool_access.REASON_GROUP_DENIED, "no")
    tool_access.record_shadow_denial(decision, agent="a", target=LOCAL_TOOL)

    tool_access.clear_shadow_denials()

    assert tool_access.recent_shadow_denials() == []
    assert json.loads(registry.shared_ring.decode("utf-8")) == {"denials": []}


# --- 10. the async API ---------------------------------------------------------


def test_async_authorize_does_not_block_the_event_loop(registry, monkeypatch):
    """The policy read is blocking, deadline-less I/O: it must leave the loop.

    ``policy_snapshot`` is made slow on purpose; a ticker coroutine on the same loop
    must keep running while the authorize is awaited. The sync ``authorize`` would
    freeze it for the whole read.
    """
    ticks = {"count": 0, "stop": False}

    def slow_snapshot():
        time.sleep(0.2)
        return tool_access.PolicySnapshot()

    monkeypatch.setattr(tool_access, "policy_snapshot", slow_snapshot)

    async def ticker():
        while not ticks["stop"]:
            await asyncio.sleep(0.01)
            ticks["count"] += 1

    async def main():
        task = asyncio.ensure_future(ticker())
        started = time.monotonic()
        decision = await tool_access.authorize_claims_async(
            None,
            target=LOCAL_TOOL,
            allowed=_allowed(tools=[LOCAL_TOOL]),
            public=True,
            surface="hub",
        )
        elapsed = time.monotonic() - started
        ticks["stop"] = True
        await task
        return decision, elapsed

    decision, elapsed = asyncio.run(main())

    assert decision.allowed is True
    assert elapsed >= 0.2  # the read really happened
    # ~20 ticks fit in 200 ms; anything above a few proves the loop was free.
    assert ticks["count"] >= 5


def test_async_enforce_moves_the_shadow_ring_write_off_the_loop(registry, monkeypatch):
    registry.set_policy(_policy(_rule([LOCAL_TOOL], ["ops"])))
    denied = _authorize(LOCAL_TOOL, allowed=_allowed(tools=[LOCAL_TOOL]))
    assert denied.allowed is False

    threads = []
    original = tool_access._persist_shadow_denial

    def recording_persist(entry):
        threads.append(threading.current_thread().name)
        return original(entry)

    monkeypatch.setattr(tool_access, "_persist_shadow_denial", recording_persist)

    outcome = asyncio.run(
        tool_access.enforce_async(
            denied,
            "shadow",
            agent="agent-a",
            groups=["interns"],
            target=LOCAL_TOOL,
            surface="hub",
        )
    )

    assert outcome.allowed is True
    assert outcome.reason == tool_access.REASON_SHADOW
    # The ring write happened, and not on the event loop's own thread.
    assert threads and threads[0] != threading.main_thread().name


# --- 11. inert rule targets are loud -------------------------------------------


def test_a_file_tool_rule_is_a_warning_not_an_error(registry, caplog):
    document = _policy(
        _rule(["read_file", "execute"], ["ops"]), _rule(["ls", "glob"], ["ops"])
    )

    assert tool_access.validate_policy(document) == []
    warnings = tool_access.policy_warnings(document)
    assert any(
        "console tool 'read_file' is not covered by tool-access rules; only "
        "'execute' is enforced" in w
        for w in warnings
    )
    assert any("console tool 'ls' is not covered" in w for w in warnings)
    assert not any("'execute' is not covered" in w for w in warnings)

    messages = [record.getMessage() for record in caplog.records]
    assert any("only 'execute' is enforced" in message for message in messages)


def test_the_loaded_snapshot_surfaces_console_target_warnings(registry):
    registry.set_policy(_policy(_rule(["read_file"], ["ops"])))

    snapshot = tool_access.policy_snapshot()

    assert snapshot.available is True
    assert len(snapshot.warnings) == 1
    assert "'read_file' is not covered" in snapshot.warnings[0]


def test_a_file_tool_rule_does_not_constrain_execute(registry):
    """The rule is legal but inert: it must not narrow the tool that IS enforced."""
    registry.set_policy(_policy(_rule(["read_file"], ["ops"])))

    decision = _authorize("execute", allowed=_allowed(tools=["execute"]))

    assert decision.allowed is True
    assert decision.reason == tool_access.REASON_ALLOWLIST


def test_parse_rules_also_warns_about_an_inert_console_target(registry, caplog):
    """A caller that parses without validating must still hear about the dead rule."""
    caplog.clear()

    with caplog.at_level("WARNING", logger="core.tool_access"):
        parsed = tool_access.parse_rules(_policy(_rule(["grep"], ["ops"], name="files"))["rules"])

    assert parsed[0].targets == ("grep",)
    messages = [record.getMessage() for record in caplog.records]
    assert any(
        "rule 'files': console tool 'grep' is not covered by tool-access rules" in message
        for message in messages
    )
