# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Deny-by-default network profiles for tool containers.

A profile maps to a pinned Docker network (or ``none``) plus a set of
``DOCKER-USER`` rules that hold for gVisor netstack traffic too, because those
packets still egress through the Docker bridge.

The same module installs, verifies and tears the rules down
(``python -m core.execution.netprofiles``), so the shell wrapper in
``scripts/setup-network-profiles.sh`` cannot drift from what the runner checks
at startup.
"""

import ipaddress
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

PROFILE_NONE = "none"
PROFILE_INTERNAL = "internal"
PROFILE_INTERNET = "internet"
PROFILES = (PROFILE_NONE, PROFILE_INTERNAL, PROFILE_INTERNET)

NETWORK_NAMES = {
    PROFILE_INTERNAL: "trellis-tools-internal",
    PROFILE_INTERNET: "trellis-tools-internet",
}
DEFAULT_SUBNETS = {
    PROFILE_INTERNAL: "172.31.241.0/24",
    PROFILE_INTERNET: "172.31.240.0/24",
}
SUBNET_ENV = {
    PROFILE_INTERNAL: "TOOLS_NET_INTERNAL_SUBNET",
    PROFILE_INTERNET: "TOOLS_NET_INTERNET_SUBNET",
}

# Cloud metadata services, in every profile -- including ``internet``.
METADATA_TARGETS = (
    "169.254.169.254",
    "100.100.100.200",
    "169.254.169.123",
    "fd00:ec2::254",
)
# The Docker host bridge gateway is a route back onto the host.
HOST_GATEWAYS = ("172.17.0.1",)
# Never routable from ``internet``: private, CGNAT, link-local, multicast, reserved.
INTERNET_DENY = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

DOCKER_USER_CHAIN = "DOCKER-USER"
_REJECT = "REJECT"


@dataclass(frozen=True)
class Rule:
    """One ``DOCKER-USER`` rule as argv, without the ``iptables`` prefix.

    ``head`` rules (metadata, engine, gateway) are inserted at the top of the
    chain so they win over an ``internal`` allowlist entry that overlaps them.
    """

    args: tuple[str, ...]
    why: str = ""
    head: bool = False

    def as_argv(self, iptables: str = "iptables") -> list[str]:
        return [iptables, *self.args]


@dataclass(frozen=True)
class NetworkPlan:
    profile: str
    network_name: Optional[str]
    subnet: Optional[str]
    rules: tuple[Rule, ...] = field(default_factory=tuple)


def normalize_profile(value: Optional[str]) -> str:
    """Unknown/empty -> ``none`` (deny by default)."""
    normalized = str(value or "").strip().lower()
    return normalized if normalized in PROFILES else PROFILE_NONE


def subnet_for(profile: str) -> Optional[str]:
    profile = normalize_profile(profile)
    if profile == PROFILE_NONE:
        return None
    return os.getenv(SUBNET_ENV[profile]) or DEFAULT_SUBNETS[profile]


def network_name(profile: str) -> Optional[str]:
    return NETWORK_NAMES.get(normalize_profile(profile))


def network_mode(profile: str) -> str:
    """Value for ``HostConfig.NetworkMode``."""
    return network_name(profile) or "none"


_DETECTED_ENGINE_SUBNETS: Optional[list[str]] = None


def detect_engine_subnets(docker: str = "docker") -> list[str]:
    """Docker networks that must be unreachable from every tool profile.

    ``TRELLIS_ENGINE_SUBNETS`` wins when set. Otherwise inspect the compose
    network (``trellis-network`` by default, override with
    ``TRELLIS_ENGINE_NETWORK``) so a default install is not silently unblocked.
    """
    network = os.getenv("TRELLIS_ENGINE_NETWORK", "trellis-network")
    code, out = _run([docker, "network", "inspect", network])
    if code != 0:
        return []
    try:
        payload = json.loads(out)
    except ValueError:
        return []
    subnets: list[str] = []
    if isinstance(payload, list):
        for item in payload:
            for config in (item.get("IPAM") or {}).get("Config") or []:
                subnet = config.get("Subnet")
                if subnet:
                    subnets.append(str(subnet))
    return subnets


def _engine_subnets() -> list[str]:
    global _DETECTED_ENGINE_SUBNETS
    raw = os.getenv("TRELLIS_ENGINE_SUBNETS", "")
    explicit = [part.strip() for part in raw.split(",") if part.strip()]
    if explicit:
        return explicit
    if _DETECTED_ENGINE_SUBNETS is None:
        _DETECTED_ENGINE_SUBNETS = detect_engine_subnets()
    return _DETECTED_ENGINE_SUBNETS


def _internal_cidrs() -> list[str]:
    raw = os.getenv("TRELLIS_INTERNAL_CIDRS", "")
    return [part.strip() for part in raw.split(",") if part.strip()]


def _gateway(subnet: Optional[str]) -> Optional[str]:
    if not subnet:
        return None
    try:
        return str(ipaddress.ip_network(subnet, strict=False).network_address + 1)
    except ValueError:
        return None


def _reject(source: Optional[str], target: str, why: str, *, head: bool = True) -> Rule:
    op = "-I" if head else "-A"
    args = [op, DOCKER_USER_CHAIN]
    if source:
        args += ["-s", source]
    args += ["-d", target, "-j", _REJECT]
    return Rule(tuple(args), why, head=head)


def _accept(source: str, target: str, why: str) -> Rule:
    # Appended, so it sits after the hard blocks (metadata/engine) and before the
    # internal blanket deny that is appended last.
    return Rule(
        ("-A", DOCKER_USER_CHAIN, "-s", source, "-d", target, "-j", "ACCEPT"), why
    )


def plan(profile: str) -> NetworkPlan:
    """Rules this profile needs; safe to call without root (pure intent)."""
    profile = normalize_profile(profile)
    subnet = subnet_for(profile)
    if profile == PROFILE_NONE:
        return NetworkPlan(profile, None, None, ())

    rules: list[Rule] = []
    if profile == PROFILE_INTERNAL:
        # Appended in this order: allowlisted destinations first, then the
        # blanket deny. The hard blocks below are inserted at the head.
        for target in _internal_cidrs():
            rules.append(_accept(subnet, target, "internal: allowlisted CIDR"))
        rules.append(_reject(subnet, "0.0.0.0/0", "internal: default deny", head=False))

    for target in METADATA_TARGETS:
        if ":" not in target:
            rules.append(_reject(subnet, target, "metadata endpoint"))
    for target in HOST_GATEWAYS:
        rules.append(_reject(subnet, target, "host bridge gateway"))
    gateway = _gateway(subnet)
    if gateway:
        rules.append(_reject(subnet, gateway, "profile gateway"))
    for target in _engine_subnets():
        rules.append(_reject(subnet, target, "engine network"))

    if profile == PROFILE_INTERNET:
        for target in INTERNET_DENY:
            rules.append(_reject(subnet, target, "internet: non-public range", head=False))

    return NetworkPlan(profile, NETWORK_NAMES[profile], subnet, tuple(rules))


def required_profiles() -> list[str]:
    """Profiles the deployment says it needs; ``none`` needs no rules."""
    return [p for p in PROFILES if p != PROFILE_NONE and network_name(p)]


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _rule_present(rule: Rule, iptables: str = "iptables") -> bool:
    # `-C` with `-I`/`-A` is not valid; probe with the check form.
    probe = list(rule.args)
    probe[0] = "-C"
    code, _ = _run([iptables, *probe])
    return code == 0


def verify_rules(
    profiles: Iterable[str] = (PROFILE_INTERNAL, PROFILE_INTERNET),
    iptables: str = "iptables",
) -> tuple[bool, list[str]]:
    """Check every intended rule; returns ``(ok, missing)``."""
    missing: list[str] = []
    for profile in profiles:
        for rule in plan(profile).rules:
            if not _rule_present(rule, iptables):
                missing.append(" ".join(rule.args))
    return (not missing, missing)


def install_rules(
    profiles: Iterable[str] = (PROFILE_INTERNAL, PROFILE_INTERNET),
    iptables: str = "iptables",
) -> list[str]:
    """Idempotently install the rules; returns the ones that were missing."""
    added: list[str] = []
    for profile in profiles:
        for rule in plan(profile).rules:
            if _rule_present(rule, iptables):
                continue
            argv = list(rule.args)
            if rule.head:
                # Insert at position 1 (top), not merely at the op's default.
                argv.insert(2, "1")
            code, out = _run([iptables, *argv])
            if code != 0:
                raise RuntimeError(f"iptables {' '.join(rule.args)} failed: {out.strip()}")
            added.append(" ".join(argv))
    return added


def teardown_rules(
    profiles: Iterable[str] = (PROFILE_INTERNAL, PROFILE_INTERNET),
    iptables: str = "iptables",
) -> int:
    """Remove the rules this module owns; returns the count removed."""
    removed = 0
    for profile in profiles:
        for rule in plan(profile).rules:
            probe = list(rule.args)
            probe[0] = "-D"
            code, _ = _run([iptables, *probe])
            if code == 0:
                removed += 1
    return removed


def network_create_argv(profile: str, docker: str = "docker") -> Optional[list[str]]:
    """Idempotent ``docker network create`` argv for a profile (None for ``none``)."""
    name = network_name(profile)
    subnet = subnet_for(profile)
    if not name or not subnet:
        return None
    return [
        docker,
        "network",
        "create",
        "--driver",
        "bridge",
        "--subnet",
        subnet,
        "--opt",
        "com.docker.network.bridge.enable_icc=false",
        "--opt",
        "com.docker.network.bridge.enable_ip_masquerade=true",
        name,
    ]


def network_state(profile: str, docker: str = "docker") -> Optional[dict]:
    """IPAM subnet + ICC option of an existing profile network (None if absent)."""
    name = network_name(profile)
    if not name:
        return None
    code, out = _run([docker, "network", "inspect", name])
    if code != 0:
        return None
    try:
        payload = json.loads(out)
    except ValueError:
        return {"subnet": None, "icc": None}
    item = payload[0] if isinstance(payload, list) and payload else {}
    subnets = [
        str(config.get("Subnet"))
        for config in (item.get("IPAM") or {}).get("Config") or []
        if config.get("Subnet")
    ]
    options = item.get("Options") or {}
    return {
        "subnet": subnets[0] if subnets else None,
        "icc": str(options.get("com.docker.network.bridge.enable_icc", "true")),
    }


def network_matches(profile: str, state: Optional[dict]) -> tuple[bool, str]:
    """Does an existing network match the plan's pinned subnet and ICC setting?"""
    expected = subnet_for(profile)
    if state is None:
        return False, f"network {network_name(profile)!r} does not exist"
    if expected and state.get("subnet") != expected:
        return False, (
            f"network {network_name(profile)!r} has subnet {state.get('subnet')!r}, "
            f"expected {expected!r}; every DOCKER-USER rule is keyed on the expected "
            "subnet, so the profile would be unenforced. Remove the network and "
            "re-run with --all."
        )
    if str(state.get("icc")).lower() != "false":
        return False, (
            f"network {network_name(profile)!r} has ICC enabled; profile networks "
            "must set com.docker.network.bridge.enable_icc=false."
        )
    return True, "ok"


def verify_networks(docker: str = "docker") -> tuple[bool, list[str]]:
    problems: list[str] = []
    for profile in (PROFILE_INTERNAL, PROFILE_INTERNET):
        ok, detail = network_matches(profile, network_state(profile, docker))
        if not ok:
            problems.append(detail)
    return (not problems, problems)


def ensure_networks(docker: str = "docker") -> list[str]:
    """Create missing profile networks; verify existing ones; returns created."""
    created: list[str] = []
    for profile in (PROFILE_INTERNAL, PROFILE_INTERNET):
        argv = network_create_argv(profile, docker)
        if argv is None:
            continue
        state = network_state(profile, docker)
        if state is not None:
            ok, detail = network_matches(profile, state)
            if not ok:
                raise RuntimeError(detail)
            continue
        code, out = _run(argv)
        if code != 0 and "already exists" not in out.lower():
            raise RuntimeError(f"docker network create failed: {out.strip()}")
        created.append(network_name(profile))
    return created


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    action = args[0] if args else "--verify"
    known = {"--install", "--verify", "--teardown", "--networks"}
    if action not in known:
        print(f"usage: python -m core.execution.netprofiles {sorted(known)}", file=sys.stderr)
        return 2
    try:
        if action == "--networks":
            print("\n".join(ensure_networks()) or "networks already exist")
            return 0
        if action == "--install":
            added = install_rules()
            print("\n".join(added) if added else "all rules already present")
            return 0
        if action == "--teardown":
            print(f"removed {teardown_rules()} rule(s)")
            return 0
        networks_ok, network_problems = verify_networks()
        ok, missing = verify_rules()
        if networks_ok and ok:
            print("all network-profile networks and rules present")
            return 0
        for problem in network_problems:
            print(f"network: {problem}", file=sys.stderr)
        if missing:
            print("missing rules:\n  " + "\n  ".join(missing), file=sys.stderr)
        return 1
    except Exception as exc:  # operator-facing CLI
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
