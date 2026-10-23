# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Live network profiles: what a real runsc container can reach.

The probes attempt real TCP connections and name lookups from inside the tool
container. ``network: none`` must reach nothing, ``internal`` only what
``TRELLIS_INTERNAL_CIDRS`` allows, and ``internet`` public destinations only.
Needs the profile networks and ``DOCKER-USER`` rules installed
(``scripts/setup-network-profiles.sh``).
"""

import json
import socket

import pytest

from core.execution import spec as spec_module

pytestmark = [pytest.mark.runsc, pytest.mark.netprofiles]


def _report(result) -> dict:
    assert result.exit_code == 0, f"probe failed: {result.stderr}"
    return json.loads(result.stdout)


def _service_ip(name: str) -> str | None:
    try:
        return socket.gethostbyname(name)
    except OSError:
        return None


def _targets() -> dict[str, str]:
    """Engine destinations resolved from the test process, plus fixed probes."""
    targets = {
        "metadata": "169.254.169.254:80",
        "host_gateway": "172.17.0.1:2379",
        "public": "1.1.1.1:443",
        "rfc1918_10": "10.0.0.1:80",
        "rfc1918_192": "192.168.1.1:80",
    }
    for name, port in (("etcd", 2379), ("redis", 6379), ("hub", 8001)):
        address = _service_ip(name)
        if address:
            targets[name] = f"{address}:{port}"
    return targets


def _blocked(value: str) -> bool:
    return value != "connected"


def test_none_profile_has_no_network_at_all(live):
    report = _report(live.call("probe_none", {"targets": _targets()}))

    assert report["network"], "the probe returned no network results"
    for destination, outcome in report["network"].items():
        assert _blocked(outcome), f"none reached {destination}: {outcome}"


def test_internal_profile_blocks_public_metadata_and_engine(live):
    report = _report(live.call("probe_internal", {"targets": _targets()}))

    for destination in ("public", "metadata", "host_gateway"):
        assert _blocked(report["network"][destination]), destination
    for service in ("etcd", "redis", "hub"):
        if service in report["network"]:
            assert _blocked(report["network"][service]), service


def test_internet_profile_allows_public_and_blocks_everything_private(live):
    report = _report(live.call("probe_internet", {"targets": _targets()}))
    outcomes = report["network"]

    assert outcomes["public"] == "connected"
    for destination in ("metadata", "host_gateway", "rfc1918_10", "rfc1918_192"):
        assert _blocked(outcomes[destination]), destination
    for service in ("etcd", "redis", "hub"):
        if service in outcomes:
            assert _blocked(outcomes[service]), service


def test_internet_profile_resolves_names(live):
    """gVisor cannot use Docker's embedded resolver, so the runner mounts one."""
    if not spec_module.dns_servers("internet"):
        pytest.skip("TOOLS_INTERNET_DNS is empty: no resolver is mounted")

    report = _report(live.call("probe_internet", {"targets": _targets()}))

    resolved = report["dns"]["example.com"]
    assert "." in resolved and not resolved.startswith("gaierror"), resolved
