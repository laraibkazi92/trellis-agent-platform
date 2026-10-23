# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Network profile intent (``core.execution.netprofiles``).

Pure resolution and rule-intent tests: no Docker, no iptables, no root. The
``iptables`` probe is monkeypatched, so what is pinned here is exactly what
``scripts/setup-network-profiles.sh`` would install and what the runner's
preflight would demand on a real host.
"""

import pytest

from core.execution import netprofiles


@pytest.fixture(autouse=True)
def clean_network_env(monkeypatch):
    for name in (
        "TRELLIS_INTERNAL_CIDRS",
        "TRELLIS_ENGINE_SUBNETS",
        "TOOLS_NET_INTERNAL_SUBNET",
        "TOOLS_NET_INTERNET_SUBNET",
    ):
        monkeypatch.delenv(name, raising=False)


def targets(plan):
    """Every ``-d`` destination in a plan, in order."""
    found = []
    for rule in plan.rules:
        args = list(rule.args)
        found.append(args[args.index("-d") + 1])
    return found


def by_action(plan, action):
    return [rule for rule in plan.rules if rule.args[0] == action]


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, "none"),
        ("", "none"),
        ("   ", "none"),
        ("bogus", "none"),
        ("NONE", "none"),
        (" Internal ", "internal"),
        ("internet", "internet"),
    ],
)
def test_normalize_profile(value, expected):
    assert netprofiles.normalize_profile(value) == expected


def test_none_profile_has_no_docker_network():
    assert netprofiles.network_name("none") is None
    assert netprofiles.network_mode("none") == "none"
    assert netprofiles.network_mode("bogus") == "none"


def test_profiles_map_onto_pinned_networks():
    assert netprofiles.network_name("internal") == "trellis-tools-internal"
    assert netprofiles.network_name("internet") == "trellis-tools-internet"
    assert netprofiles.network_mode("internal") == "trellis-tools-internal"
    assert netprofiles.network_mode("internet") == "trellis-tools-internet"
    assert netprofiles.subnet_for("internal") == "172.31.241.0/24"
    assert netprofiles.subnet_for("internet") == "172.31.240.0/24"


def test_none_profile_has_no_rules():
    plan = netprofiles.plan("none")

    assert plan.profile == "none"
    assert plan.network_name is None
    assert plan.rules == ()


# --------------------------------------------------------------------------- #
# internal
# --------------------------------------------------------------------------- #


def test_internal_allows_listed_cidrs_then_denies_everything_else(monkeypatch):
    monkeypatch.setenv("TRELLIS_INTERNAL_CIDRS", "10.20.0.0/16, 192.168.50.0/24")

    plan = netprofiles.plan("internal")

    tail = by_action(plan, "-A")
    head = by_action(plan, "-I")
    # Tail order: the allowlisted destinations, then the blanket deny.
    assert [rule.args[-1] for rule in tail] == ["ACCEPT", "ACCEPT", "REJECT"]
    assert list(tail[-1].args) == [
        "-A", "DOCKER-USER", "-s", "172.31.241.0/24", "-d", "0.0.0.0/0",
        "-j", "REJECT",
    ]
    assert [rule.args[5] for rule in tail[:-1]] == ["10.20.0.0/16", "192.168.50.0/24"]
    # Hard blocks are inserted at the head, so they win over an allowlist entry
    # that overlaps a metadata/engine/gateway range.
    metadata_v4 = [target for target in netprofiles.METADATA_TARGETS if ":" not in target]
    assert all(rule.head for rule in head)
    assert set(targets(plan)) >= set(metadata_v4)
    assert not any(rule.head for rule in tail)


def test_internal_without_allowlist_is_only_deny_plus_metadata():
    plan = netprofiles.plan("internal")

    assert [rule.args[-1] for rule in by_action(plan, "-A")] == ["REJECT"]
    assert "0.0.0.0/0" in targets(plan)
    for metadata in ("169.254.169.254", "100.100.100.200", "169.254.169.123"):
        assert metadata in targets(plan)
    # RFC1918 is reachable through the allowlist, so it is not blanket-denied.
    assert "10.0.0.0/8" not in targets(plan)


# --------------------------------------------------------------------------- #
# internet
# --------------------------------------------------------------------------- #


def test_internet_rejects_metadata_private_and_engine_targets(monkeypatch):
    monkeypatch.setenv("TRELLIS_ENGINE_SUBNETS", "172.20.0.0/16, 172.21.0.0/16")

    plan = netprofiles.plan("internet")
    denied = targets(plan)

    for target in (
        # Metadata aliases: reachable from every profile, including this one.
        "169.254.169.254",
        "100.100.100.200",
        "169.254.169.123",
        # RFC1918 / CGNAT / link-local / multicast / reserved.
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        # The host bridge gateway and the profile's own gateway.
        "172.17.0.1",
        "172.31.240.1",
        # The engine's own networks.
        "172.20.0.0/16",
        "172.21.0.0/16",
    ):
        assert target in denied

    assert all(rule.args[-2:] == ("-j", "REJECT") for rule in plan.rules)
    assert plan.subnet == "172.31.240.0/24"


def test_internet_does_not_blanket_deny_public_egress():
    plan = netprofiles.plan("internet")

    assert "0.0.0.0/0" not in targets(plan)
    # The non-public ranges are appended; metadata/engine/gateway stay at the head.
    assert [rule.args[-1] for rule in by_action(plan, "-A")] == ["REJECT"] * len(
        netprofiles.INTERNET_DENY
    )
    assert by_action(plan, "-I")


def test_subnet_env_overrides_are_honored(monkeypatch):
    monkeypatch.setenv("TOOLS_NET_INTERNAL_SUBNET", "10.250.1.0/24")
    monkeypatch.setenv("TOOLS_NET_INTERNET_SUBNET", "10.250.2.0/24")

    internal = netprofiles.plan("internal")
    internet = netprofiles.plan("internet")

    assert internal.subnet == "10.250.1.0/24"
    assert internet.subnet == "10.250.2.0/24"
    assert internal.rules[0].args[3] == "10.250.1.0/24"
    assert "10.250.1.1" in targets(internal)
    assert "10.250.2.1" in targets(internet)
    assert netprofiles.subnet_for("internal") == "10.250.1.0/24"


def test_network_create_argv_pins_the_bridge_options(monkeypatch):
    monkeypatch.setenv("TOOLS_NET_INTERNAL_SUBNET", "10.250.1.0/24")

    argv = netprofiles.network_create_argv("internal", docker="docker")

    assert argv[:4] == ["docker", "network", "create", "--driver"]
    assert "bridge" in argv
    assert "10.250.1.0/24" in argv
    assert "com.docker.network.bridge.enable_icc=false" in argv
    assert "com.docker.network.bridge.enable_ip_masquerade=true" in argv
    assert argv[-1] == "trellis-tools-internal"
    assert netprofiles.network_create_argv("none") is None


# --------------------------------------------------------------------------- #
# verify / install / teardown
# --------------------------------------------------------------------------- #


def test_verify_rules_reports_every_missing_intent(monkeypatch):
    monkeypatch.setattr(netprofiles, "_run", lambda argv: (1, "No chain/target/match"))

    ok, missing = netprofiles.verify_rules(["internal", "internet"])

    assert ok is False
    expected = [
        " ".join(rule.args)
        for profile in ("internal", "internet")
        for rule in netprofiles.plan(profile).rules
    ]
    assert missing == expected
    assert missing[0].startswith("-A DOCKER-USER")


def test_verify_rules_is_ok_when_every_probe_matches(monkeypatch):
    probes = []
    monkeypatch.setattr(
        netprofiles, "_run", lambda argv: (probes.append(list(argv)) or (0, ""))
    )

    ok, missing = netprofiles.verify_rules(["internal"])

    assert ok is True
    assert missing == []
    assert len(probes) == len(netprofiles.plan("internal").rules)
    # `-C` is the only valid presence check; `-I` is not.
    assert all(argv[1] == "-C" for argv in probes)


def test_install_rules_skips_rules_that_are_already_present(monkeypatch):
    calls = []

    def fake_run(argv):
        calls.append(list(argv))
        return 0, ""

    monkeypatch.setattr(netprofiles, "_run", fake_run)

    assert netprofiles.install_rules(["internal", "internet"]) == []
    assert calls
    assert all(argv[1] in ("-C", "-S") for argv in calls)
    assert not [argv for argv in calls if argv[1] in ("-A", "-I")]


def test_install_rules_is_idempotent(monkeypatch):
    """First pass installs the planned argv; a second pass installs nothing."""
    installed = set()
    calls = []

    def fake_run(argv):
        calls.append(list(argv))
        args = list(argv[1:])
        if args[0] == "-S":
            return 0, ""
        if args[0] == "-D":
            return 1, ""
        if args[0] == "-C":
            return (0 if tuple(args[1:]) in installed else 1), ""
        if args[0] in ("-A", "-I"):
            spec = list(args[1:])
            if args[0] == "-I" and len(spec) > 1 and spec[1].isdigit():
                # iptables -C matches the rule spec, not the insert position.
                spec.pop(1)
            installed.add(tuple(spec))
            return 0, ""
        return 1, "unexpected"

    monkeypatch.setattr(netprofiles, "_run", fake_run)

    added = netprofiles.install_rules(["internal"])

    planned = []
    for rule in netprofiles.plan("internal").rules:
        argv = list(rule.args)
        if rule.head:
            argv.insert(2, "1")
        planned.append(["iptables", *argv])
    assert added == [" ".join(argv[1:]) for argv in planned]
    installs = [argv for argv in calls if argv[1] in ("-A", "-I")]
    assert installs == planned

    before = len(calls)
    assert netprofiles.install_rules(["internal"]) == []
    assert all(argv[1] in ("-C", "-S") for argv in calls[before:])


def test_install_rules_raises_on_iptables_failure(monkeypatch):
    def fake_run(argv):
        if argv[1] == "-C":
            return 1, ""
        return 1, "Permission denied"

    monkeypatch.setattr(netprofiles, "_run", fake_run)

    with pytest.raises(RuntimeError) as excinfo:
        netprofiles.install_rules(["internal"])

    assert "Permission denied" in str(excinfo.value)


def _chain(*rules):
    return "\n".join(["*filter", "-N DOCKER-USER", *rules, "COMMIT", ""])


def test_teardown_removes_every_rule_owned_by_the_profile_networks(monkeypatch):
    """Including a stale allowlisted CIDR the current plan no longer knows about."""
    chain = _chain(
        "-A DOCKER-USER -s 172.31.241.0/24 -d 1.1.1.1/32 -j ACCEPT",
        "-A DOCKER-USER -s 172.31.241.0/24 -j REJECT",
        "-A DOCKER-USER -s 10.9.9.0/24 -d 1.1.1.1/32 -j ACCEPT",  # operator rule
    )
    deleted = []

    def fake_run(argv):
        if argv[1] == "-S":
            return 0, chain
        if argv[1] == "-D":
            deleted.append(list(argv[2:]))
            return 0, ""
        return 1, ""

    monkeypatch.setattr(netprofiles, "_run", fake_run)

    removed = netprofiles.teardown_rules(["internal"])

    assert removed == 2
    assert all("172.31.241.0/24" in argv for argv in deleted)
    assert not any("10.9.9.0/24" in argv for argv in deleted)


def test_install_rebuilds_the_chain_when_the_plan_changed(monkeypatch):
    """A new allowlist entry must not be appended after the blanket reject."""
    chain = _chain("-A DOCKER-USER -s 172.31.241.0/24 -j REJECT")
    events = []

    def fake_run(argv):
        if argv[1] == "-S":
            return 0, chain
        if argv[1] == "-C":
            return 1, ""  # nothing from the new plan is present yet
        if argv[0] == "iptables":
            events.append(list(argv[1:]))
        return 0, ""

    monkeypatch.setattr(netprofiles, "_run", fake_run)
    monkeypatch.setenv("TRELLIS_INTERNAL_CIDRS", "1.1.1.1/32")

    netprofiles.install_rules(["internal"])

    ops = [argv[0] for argv in events]
    assert ops[0] == "-D"  # rebuild, not append
    installs = [argv for argv in events if argv[0] in ("-A", "-I")]
    accept = next(i for i, argv in enumerate(installs) if "-d" in argv and "1.1.1.1/32" in argv)
    blanket = next(
        i
        for i, argv in enumerate(installs)
        if argv[0] == "-A" and "0.0.0.0/0" in argv and "REJECT" in argv
    )
    assert accept < blanket


def test_install_removes_a_stale_allowlist_even_when_every_planned_rule_exists(monkeypatch):
    """Shrinking TRELLIS_INTERNAL_CIDRS must revoke the removed destination."""
    chain = _chain(
        "-A DOCKER-USER -s 172.31.241.0/24 -d 1.1.1.1/32 -j ACCEPT",  # no longer planned
        "-A DOCKER-USER -s 172.31.241.0/24 -j REJECT --reject-with icmp-port-unreachable",
    )
    deleted = []

    def fake_run(argv):
        if argv[1] == "-S":
            return 0, chain
        if argv[1] == "-C":
            return 0, ""  # every planned rule is present
        if argv[1] == "-D":
            deleted.append(list(argv[2:]))
            return 0, ""
        return 0, ""

    monkeypatch.setattr(netprofiles, "_run", fake_run)

    added = netprofiles.install_rules(["internal"])

    assert any("-d" in spec and "1.1.1.1/32" in spec for spec in deleted)
    assert added  # the chain was rebuilt after the stale entry came out
