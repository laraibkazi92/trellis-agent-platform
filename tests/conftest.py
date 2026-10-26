# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Shared test fixtures.

The registry-edit endpoints (admin editor, workflow editor, marketplace) dual-write
their config to the workspace files via core/workspace_io. Tests exercise those
endpoints against fake registries, so without this fixture they would write real files
into the repo's workspace/ tree. Redirect the module's roots at a per-test tmp dir.
"""

import os

import pytest

from core import workspace_io

from _llm_key_seam import install_provider_keys


@pytest.fixture(autouse=True)
def _isolated_workspace_io(tmp_path, monkeypatch):
    ws = tmp_path / "workspace"
    ws.mkdir()
    monkeypatch.setattr(workspace_io, "BASE_DIR", tmp_path)
    monkeypatch.setattr(workspace_io, "WORKSPACE_DIR", ws)
    yield


@pytest.fixture(autouse=True)
def _restore_process_env_after_edge_runs():
    """``core.proxy.run`` sets mode env vars with ``setdefault``.

    That is correct for a real edge process but leaks into later tests in the same
    interpreter, so snapshot and restore them.
    """
    names = ("RUNNER_SOCKET", "TRELLIS_EDGE_MODE")
    before = {name: os.environ.get(name) for name in names}
    yield
    for name, value in before.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


@pytest.fixture
def llm_provider_keys(monkeypatch):
    """Seam for the etcd-backed framework LLM provider keys (see tests/_llm_key_seam.py).

    Returns a mutable ``ProviderKeySeam`` that callers may clear/override; it
    records each provider consulted in ``.consulted``. Never touches etcd.
    """
    return install_provider_keys(monkeypatch)
