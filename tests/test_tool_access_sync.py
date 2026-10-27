# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""``workspace/policies/tool_access.yaml`` -> registry (``scripts/sync_to_db.py``).

The workspace file is the source of truth; db-sync publishes it on every rebuild and
``trellis sync`` re-runs it while the stack is up. From etcd the document reaches
every enforcing process through its watch.

An invalid file must be refused LOUDLY and write nothing: silently keeping the old
policy would leave an operator believing the edit applied, and writing a partial
policy would be worse.
"""

import json

import pytest

from core import tool_access
from scripts import sync_to_db

VALID = """
rules:
  - name: ops-only
    targets: [text_stats]
    groups: [platform-ops]
"""

INVALID_MISSING_GROUPS = """
rules:
  - targets: [text_stats]
"""


class FakeClient:
    def __init__(self, document=None):
        self.documents = {}
        if document is not None:
            self.documents[tool_access.POLICY_PATH] = json.dumps(document)
        self.puts = []
        self.gets = []

    def get(self, key, **_kwargs):
        self.gets.append(key)
        value = self.documents.get(key)
        return (value.encode("utf-8") if value is not None else None), None

    def put(self, key, value):
        payload = value.encode("utf-8") if isinstance(value, str) else value
        self.puts.append((key, payload))
        self.documents[key] = payload.decode("utf-8")


class FakeManager:
    def __init__(self, document=None):
        self.client = FakeClient(document)

    @property
    def published(self):
        raw = self.client.documents.get(tool_access.POLICY_PATH)
        return json.loads(raw) if raw is not None else None


@pytest.fixture(autouse=True)
def clean_snapshot():
    tool_access.reset_snapshot()
    yield
    tool_access.reset_snapshot()


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_valid_file_lands_in_the_registry(tmp_path):
    manager = FakeManager()
    path = _write(tmp_path / "policies" / "tool_access.yaml", VALID)

    assert sync_to_db.sync_tool_access_policy(manager, path) == 0

    assert manager.published == {
        "rules": [
            {"name": "ops-only", "targets": ["text_stats"], "groups": ["platform-ops"]}
        ]
    }
    assert [key for key, _value in manager.client.puts] == [tool_access.POLICY_PATH]
    # ... and the loaded registry document passes the evaluator's own validation.
    assert tool_access.validate_policy(manager.published) == []


def test_shipped_workspace_file_is_valid_and_publishes_no_rules():
    manager = FakeManager()

    # Default path: the file this repo ships.
    assert sync_to_db.sync_tool_access_policy(manager) == 0

    assert manager.published == {"rules": []}
    assert tool_access.validate_policy(manager.published) == []


def test_invalid_file_is_refused_loudly_and_writes_nothing(tmp_path, capsys):
    manager = FakeManager()
    path = _write(tmp_path / "tool_access.yaml", INVALID_MISSING_GROUPS)

    assert sync_to_db.sync_tool_access_policy(manager, path) == 2
    assert manager.client.puts == []

    out = capsys.readouterr().out
    assert "INVALID tool-access policy" in out
    assert "rules[0].groups must be a list" in out


def test_invalid_file_does_not_replace_an_existing_policy(tmp_path):
    existing = {"rules": [{"targets": ["text_stats"], "groups": ["ops"]}]}
    manager = FakeManager(existing)
    path = _write(tmp_path / "tool_access.yaml", "rules:\n  - groups: []\n    targets: [x]\n")

    assert sync_to_db.sync_tool_access_policy(manager, path) == 2
    assert manager.published == existing


def test_unparsable_yaml_is_refused(tmp_path):
    manager = FakeManager()
    path = _write(tmp_path / "tool_access.yaml", "rules: [unclosed\n")

    assert sync_to_db.sync_tool_access_policy(manager, path) == 2
    assert manager.client.puts == []


def test_empty_file_is_refused(tmp_path):
    manager = FakeManager()
    path = _write(tmp_path / "tool_access.yaml", "")

    assert sync_to_db.sync_tool_access_policy(manager, path) == 2
    assert manager.client.puts == []


def test_missing_file_warns_and_leaves_the_registry_alone(tmp_path, capsys):
    existing = {"rules": [{"targets": ["text_stats"], "groups": ["ops"]}]}
    manager = FakeManager(existing)

    assert sync_to_db.sync_tool_access_policy(manager, tmp_path / "nope.yaml") == 0

    assert manager.client.puts == []
    assert manager.published == existing
    assert "WARNING: no" in capsys.readouterr().out


def test_a_file_tool_rule_is_reported_but_still_published(tmp_path, capsys):
    """A rule naming a console file tool is legal, inert, and loudly warned about.

    Refusing the file would be wrong -- the rule decides nothing, it is not malformed
    -- but shipping it silently would let an operator believe file access is gated.
    """
    manager = FakeManager()
    path = _write(
        tmp_path / "tool_access.yaml",
        "rules:\n  - targets: [read_file]\n    groups: [ops]\n",
    )

    assert sync_to_db.sync_tool_access_policy(manager, path) == 0

    assert manager.published == {
        "rules": [{"targets": ["read_file"], "groups": ["ops"]}]
    }
    out = capsys.readouterr().out
    assert "WARNING: rules[0]: console tool 'read_file' is not covered" in out
    assert "only 'execute' is enforced" in out


def test_main_aborts_before_any_other_write_when_the_policy_is_invalid(tmp_path, monkeypatch):
    path = _write(tmp_path / "tool_access.yaml", INVALID_MISSING_GROUPS)
    manager = FakeManager()

    monkeypatch.setattr(sync_to_db, "TOOL_ACCESS_POLICY_PATH", path)
    monkeypatch.setattr(sync_to_db, "IdentityManager", lambda **_kwargs: manager)

    assert sync_to_db.main([]) == 2

    # Nothing else was synced: the file failed validation, so no registry read and
    # no write happened at all.
    assert manager.client.puts == []
    assert manager.client.gets == []
