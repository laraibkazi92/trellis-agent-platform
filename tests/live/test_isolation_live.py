# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Live isolation: what a real runsc container can see, write and reach.

Complements ``tests/test_isolation_matrix.py``, which asserts the *spec* the
runner derives. These assertions run the derived spec on a real Docker daemon
and ask the container itself, so a mount that silently resolves to the wrong
host path fails here and not in production.

``network: none`` is the only containment option since v0.7.1 (``egress`` is
Docker's default bridge, i.e. whatever the host can reach). The reachability
probes below are therefore all-or-nothing, not profiles.
"""

import ipaddress
import json

import pytest

pytestmark = pytest.mark.runsc

# Destinations that must be unreachable from a `none` container: cloud metadata,
# the host's own bridge gateway (where etcd would be if it were published), and an
# arbitrary public address. None of them may connect.
_TARGETS = {
    "metadata": "169.254.169.254:80",
    "host_gateway": "172.17.0.1:2379",
    "public": "1.1.1.1:443",
}


def _report(result) -> dict:
    assert result.exit_code == 0, f"probe failed: {result.stderr}"
    return json.loads(result.stdout)


def _resolved_to_an_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def test_container_sees_only_its_own_suite(live):
    report = _report(live.call("probe_none"))

    # The workspace holds the mounts this run declared, nothing else.
    assert set(report["workspace_listing"]) <= {"tools", "shared", "output"}
    # Exactly one suite is mounted: this one.
    assert report["tools_listing"] == [live.suite]
    assert sorted(report["suite_listing"]) == [
        "echo.py",
        "memhog.py",
        "probe.py",
        "sleep.py",
        "tool.yaml",
    ]
    assert report["output_agents"] == [live.agent]

    # Manifests, other suites and .env are not mounted at all.
    for path in (
        "/app/workspace/agents/demo-assistant/config.yaml",
        "/app/workspace/agents/demo-assistant/skills.md",
        "/app/workspace/tools/demo/tool.yaml",
        "/app/workspace/tools/demo/text_stats.py",
        "/app/workspace/.env",
        "/app/.env",
    ):
        assert report["reads"][path].startswith("FileNotFoundError"), path


def test_writes_are_confined_to_tmp_and_the_declared_output_dir(live):
    report = _report(live.call("probe_none"))

    # Own suite is read-only; the workspace root is not writable; the tool's own
    # report/output directory (declared in the manifest) is.
    assert report["writes"]["own_suite"] == "OSError: Read-only file system"
    assert report["writes"]["workspace"].startswith("PermissionError")
    assert report["writes"]["tools_parent"].startswith("PermissionError")
    assert report["writes"]["parent_of_suite"].startswith("PermissionError")
    assert report["writes"]["output"] == "wrote"
    assert report["writes"]["tmp"] == "wrote"


def test_tool_runs_as_the_workspace_uid_not_root(live):
    report = _report(live.call("probe_none"))

    assert report["uid_gid"] == [live.uid, live.gid]
    assert report["uid_gid"] != [0, 0]
    assert report["cwd"] == f"/app/workspace/tools/{live.suite}"


def test_no_control_plane_credentials_reach_the_tool(live):
    report = _report(live.call("probe_none"))

    assert "RUNNER_TOKEN" not in report["env_keys"]
    assert "AGENT_TOKEN_SECRET" not in report["env_keys"]
    assert "DEEPSEEK_API_KEY" not in report["env_keys"]
    # Only the base image's markers (e.g. GPG_KEY) may look secret-ish.
    assert report["leaked_env"] in ([], ["GPG_KEY"])


def test_egress_tools_get_the_same_filesystem_view(live):
    """`network: egress` is Docker's default bridge: mounts are unchanged by it."""
    report = _report(live.call("probe_egress"))

    assert set(report["workspace_listing"]) <= {"tools", "shared"}
    assert report["tools_listing"] == [live.suite]


def test_network_none_reaches_nothing(live):
    """`network: none` is the whole containment story: no destination, no DNS.

    This is the security meaning of the default flip in v0.7.1. `egress` is what
    everything else gets, so a regression here means a tool that asked for no
    network has one.
    """
    report = _report(live.call("probe_none", {"targets": _TARGETS}))

    assert report["network"], "the probe returned no network results"
    for destination, outcome in report["network"].items():
        assert outcome != "connected", f"none reached {destination}: {outcome}"
    # No name resolves either: without a network there is no route to a resolver.
    for name, resolved in report["dns"].items():
        assert not _resolved_to_an_address(resolved), f"none resolved {name}: {resolved}"
