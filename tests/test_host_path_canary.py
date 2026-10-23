# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Host-path canary: the runner's view and the Docker host path must agree.

The canary is the only thing standing between a typo in
``TRELLIS_HOST_WORKSPACE`` and every tool silently reading an empty directory, so
these tests pin both directions: agreement passes, disagreement fails closed, and
the marker never outlives the check.
"""

import asyncio
import os
from pathlib import Path

import pytest

from core.execution import canary
from core.execution.backend import ExecRaw
from fixtures.fake_backend import FakeBackend


class _Binder(FakeBackend):
    """Reads the canary file at the *bind source* the way a container would."""

    async def run(self, spec, stdin, timeout_s):  # type: ignore[override]
        self.specs.append(spec)
        source = Path(spec.mounts[0].source)
        name = Path(spec.cmd[-1]).name
        path = source / name
        if not path.is_file():
            return ExecRaw(exit_code=1, stdout=b"", stderr=b"not found")
        return ExecRaw(exit_code=0, stdout=path.read_bytes(), stderr=b"")


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset():
    canary.reset_for_tests()
    yield
    canary.reset_for_tests()


def test_canary_passes_when_the_two_roots_agree(tmp_path):
    backend = _Binder()
    result = _run(
        canary.run(
            backend,
            host_workspace=str(tmp_path),
            workspace_root=str(tmp_path),
            image="img:test",
            runtime="runsc",
        )
    )
    assert result.ok is True
    # The marker is cleaned up, and the container saw the host path.
    assert list(tmp_path.glob(".runner-canary-*")) == []
    assert backend.specs[0].mounts[0].target == "/canary"
    assert backend.specs[0].network_mode == "none"


def test_canary_fails_closed_when_runner_view_and_host_path_disagree(tmp_path):
    runner_view = tmp_path / "runner-view"
    runner_view.mkdir()
    host_path = tmp_path / "host-path"
    host_path.mkdir()

    result = _run(
        canary.run(
            _Binder(),
            host_workspace=str(host_path),
            workspace_root=str(runner_view),
            image="img:test",
            runtime="runsc",
        )
    )

    assert result.ok is False
    assert "TRELLIS_HOST_WORKSPACE" in result.detail
    # The marker was written into the runner's view and then removed; nothing
    # leaked into either directory.
    assert list(runner_view.glob(".runner-canary-*")) == []
    assert list(host_path.glob(".runner-canary-*")) == []


def test_canary_reports_an_unwritable_runner_view(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores the directory mode this test relies on")
    readonly = tmp_path / "readonly"
    readonly.mkdir(mode=0o500)
    try:
        result = _run(
            canary.run(
                _Binder(),
                host_workspace=str(readonly),
                workspace_root=str(readonly),
                image="img:test",
                runtime="runsc",
            )
        )
    finally:
        os.chmod(readonly, 0o700)
    assert result.ok is False
    assert "cannot write the canary file" in result.detail


def test_canary_container_failure_is_a_failed_check_not_a_crash(tmp_path):
    class _Broken(FakeBackend):
        async def run(self, spec, stdin, timeout_s):
            raise RuntimeError("daemon exploded")

    result = _run(
        canary.run(
            _Broken(),
            host_workspace=str(tmp_path),
            workspace_root=str(tmp_path),
            image="img:test",
            runtime="runsc",
        )
    )
    assert result.ok is False
    assert "did not run" in result.detail
    assert list(tmp_path.glob(".runner-canary-*")) == []
