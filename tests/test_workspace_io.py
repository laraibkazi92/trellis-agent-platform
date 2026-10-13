# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for core/workspace_io.py -- the direct workspace-file persistence used by the
registry-edit endpoints (admin editor, workflow editor, marketplace) instead of a Git
write-back, so the rebuild-time registry sync re-applies UI edits."""

import pytest

from core import workspace_io


@pytest.fixture
def rooted(tmp_path, monkeypatch):
    """Point the module's BASE_DIR/WORKSPACE_DIR at a throwaway tree."""
    ws = tmp_path / "workspace"
    ws.mkdir(exist_ok=True)
    monkeypatch.setattr(workspace_io, "BASE_DIR", tmp_path)
    monkeypatch.setattr(workspace_io, "WORKSPACE_DIR", ws)
    return tmp_path


def test_write_creates_parents_and_leaves_no_temp_file(rooted):
    target = rooted / "workspace" / "agents" / "demo" / "config.yaml"
    assert workspace_io.write_repo_file("workspace/agents/demo/config.yaml", "name: demo\n") is True
    assert target.read_text() == "name: demo\n"
    assert [p.name for p in target.parent.iterdir()] == ["config.yaml"]


def test_write_overwrites_existing(rooted):
    target = rooted / "workspace" / "mcps" / "m" / "mcp.yaml"
    workspace_io.write_repo_file("workspace/mcps/m/mcp.yaml", "a: 1\n")
    workspace_io.write_repo_file("workspace/mcps/m/mcp.yaml", "a: 2\n")
    assert target.read_text() == "a: 2\n"


@pytest.mark.parametrize("rel", ["../escape.yaml", "../../etc/passwd", "workspace/../../x"])
def test_write_rejects_traversal(rooted, rel):
    assert workspace_io.write_repo_file(rel, "nope") is False


def test_write_allows_non_workspace_repo_path(rooted):
    # core/assets/... is a valid repo-root target, not under workspace/.
    assert workspace_io.write_repo_file("core/assets/supervisor/config.yaml", "x: 1\n") is True


def test_delete_removes_file_and_prunes_empty_dirs(rooted):
    workspace_io.write_repo_file("workspace/mcps/m/mcp.yaml", "x: 1\n")
    assert workspace_io.delete_repo_path("workspace/mcps/m/mcp.yaml") is True
    assert not (rooted / "workspace" / "mcps").exists()  # empty category dir pruned
    assert (rooted / "workspace").exists()  # ...but never workspace/ itself


def test_delete_keeps_dir_with_siblings(rooted):
    workspace_io.write_repo_file("workspace/mcps/m/mcp.yaml", "x: 1\n")
    (rooted / "workspace" / "mcps" / "m" / "bundle").mkdir()
    assert workspace_io.delete_repo_path("workspace/mcps/m/mcp.yaml") is True
    assert (rooted / "workspace" / "mcps" / "m").exists()  # non-empty -> kept


def test_delete_missing_file_is_success(rooted):
    assert workspace_io.delete_repo_path("workspace/mcps/ghost/mcp.yaml") is True


def test_delete_rejects_traversal(rooted):
    assert workspace_io.delete_repo_path("../escape.yaml") is False
