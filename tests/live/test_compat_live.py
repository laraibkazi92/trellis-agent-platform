# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Live compatibility: the workspace tool contract is unchanged under runsc.

Tools read one JSON object from stdin and write one JSON object to stdout; the
runner sets the suite as the working directory and passes only the env the
manifest declares. These are the guarantees every existing tool relies on, so
they are asserted against a real container rather than a fake backend.
"""

import json

import pytest

pytestmark = pytest.mark.runsc


def _report(result) -> dict:
    assert result.exit_code == 0, f"probe failed: {result.stderr}"
    return json.loads(result.stdout)


def test_python_tool_stdin_stdout_round_trip(live):
    report = _report(live.call("probe_echo", {"hello": "world", "n": 3}))

    assert report["echo"] == {"hello": "world", "n": 3}
    assert report["uid_gid"] == [live.uid, live.gid]
    assert report["cwd"].endswith(f"/tools/{live.suite}")


def test_declared_env_reaches_the_tool(live):
    report = _report(
        live.call("probe_echo", {}, env={"PROBE_MARKER": "declared-value"})
    )

    assert report["env"]["PROBE_MARKER"] == "declared-value"
