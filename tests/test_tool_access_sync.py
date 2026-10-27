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


# --------------------------------------------------------------------------- #
# Declared env names (scripts/sync_to_db.py)
# --------------------------------------------------------------------------- #
# A tool/mcp manifest used to sync happily with `secrets: [my-api-key]`; the name
# then resolved, and was silently dropped at the last mile, so the tool ran without
# the credential it declared. The sync refuses it loudly instead.


def test_a_declared_name_that_is_not_an_env_name_fails_the_sync(
    tmp_path, monkeypatch, capsys
):
    workspace = tmp_path / "workspace"
    suite = workspace / "tools" / "ops"
    suite.mkdir(parents=True)
    (suite / "tool.yaml").write_text(
        "name: ops\n"
        "description: d\n"
        "runtime: python\n"
        "entrypoint: run.py\n"
        "secrets: [my-api-key]\n"
    )
    mcps = workspace / "mcps"
    mcps.mkdir(parents=True)

    monkeypatch.setattr(sync_to_db, "TOOLS_DIR", workspace / "tools")
    monkeypatch.setattr(sync_to_db, "MCPS_DIR", mcps)
    manager = FakeManager()
    monkeypatch.setattr(sync_to_db, "IdentityManager", lambda **_kwargs: manager)

    assert sync_to_db.main([]) == 2

    out = capsys.readouterr().out
    assert "REFUSING TO SYNC" in out
    assert "my-api-key" in out
    assert "MY_API_KEY" in out
    # No tool config reached the registry: the sync aborted before the write pass.
    assert not [key for key, _value in manager.client.puts if "/registry/tools/" in key]


def test_a_clean_workspace_passes_the_env_name_check(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    suite = workspace / "tools" / "ops"
    suite.mkdir(parents=True)
    (suite / "tool.yaml").write_text(
        "name: ops\nsecrets: [OPS_API_KEY]\nvariables:\n  user: [OPS_BASE_URL]\n"
    )
    mcp_dir = workspace / "mcps" / "demo"
    mcp_dir.mkdir(parents=True)
    (mcp_dir / "mcp.yaml").write_text("name: demo\nsecrets: [DEMO_TOKEN]\n")

    monkeypatch.setattr(sync_to_db, "TOOLS_DIR", workspace / "tools")
    monkeypatch.setattr(sync_to_db, "MCPS_DIR", workspace / "mcps")

    assert sync_to_db.validate_declared_env_names() == []


def test_a_bad_mcp_env_block_key_fails_the_sync(tmp_path, monkeypatch, capsys):
    workspace = tmp_path / "workspace"
    mcps = workspace / "mcps"
    mcp_dir = mcps / "demo"
    mcp_dir.mkdir(parents=True)
    (mcp_dir / "mcp.yaml").write_text(
        "name: demo\ncommand: srv\nenv:\n  my-key: x\n"
    )

    monkeypatch.setattr(sync_to_db, "TOOLS_DIR", workspace / "tools")
    monkeypatch.setattr(sync_to_db, "MCPS_DIR", mcps)

    errors = sync_to_db.validate_declared_env_names()

    assert len(errors) == 1
    assert "my-key" in errors[0]
    assert "mcp 'demo'" in errors[0]


# --------------------------------------------------------------------------- #
# Workflow manifest keys (scripts/sync_to_db.py)
# --------------------------------------------------------------------------- #
# A workflow config is an unvalidated registry document: a misspelled `limits` knob,
# an unknown `runtime` or a missing `entrypoint` used to sync happily and fail a
# scheduled run hours later. The sync refuses it before any write, like env names.


def _workflow_workspace(tmp_path, monkeypatch, config_text, *, pipeline=True):
    workspace = tmp_path / "workspace"
    wf = workspace / "workflows" / "demo"
    wf.mkdir(parents=True)
    if pipeline:
        (wf / "pipeline.py").write_text("print('{}')\n")
    (wf / "config.yaml").write_text(config_text)
    monkeypatch.setattr(sync_to_db, "WORKFLOWS_DIR", workspace / "workflows")
    # Keep the other validation passes out of the way.
    monkeypatch.setattr(sync_to_db, "TOOLS_DIR", workspace / "tools")
    monkeypatch.setattr(sync_to_db, "MCPS_DIR", workspace / "mcps")
    return workspace


GOOD_WORKFLOW = """\
name: demo
type: background_script
runtime: python
entrypoint: pipeline.py
network: egress
limits:
  memory_mb: 8192
"""


def test_a_bad_workflow_limits_key_fails_the_sync(tmp_path, monkeypatch, capsys):
    _workflow_workspace(
        tmp_path,
        monkeypatch,
        GOOD_WORKFLOW.replace("memory_mb: 8192", "memmory_mb: 8192"),
    )
    manager = FakeManager()
    monkeypatch.setattr(sync_to_db, "IdentityManager", lambda **_kwargs: manager)
    policy = tmp_path / "tool_access.yaml"
    policy.write_text("rules: []\n")
    monkeypatch.setattr(sync_to_db, "TOOL_ACCESS_POLICY_PATH", policy)

    assert sync_to_db.main([]) == 2

    out = capsys.readouterr().out
    assert "REFUSING TO SYNC" in out
    assert "memmory_mb" in out
    assert "memory_mb" in out
    # No workflow/agent config reached the registry: the sync aborted before the
    # write pass (only the policy, published earlier, was written).
    assert not [
        key for key, _value in manager.client.puts if "/registry/agents/" in key
    ]


def test_a_good_workflow_manifest_passes_validation(tmp_path, monkeypatch):
    _workflow_workspace(tmp_path, monkeypatch, GOOD_WORKFLOW)

    assert sync_to_db.validate_workflow_manifests() == []


@pytest.mark.parametrize(
    "old,new,expected",
    [
        ("runtime: python", "runtime: ts", "runtime 'ts'"),
        ("entrypoint: pipeline.py", "entrypoint: /etc/passwd", "plain relative path"),
        ("entrypoint: pipeline.py", "entrypoint: run.py", "does not exist"),
        ("network: egress", "network: internal-network", "network 'internal-network'"),
        ("memory_mb: 8192", "memory_mb: 512", "limits are invalid"),
    ],
)
def test_an_invalid_workflow_value_is_rejected(tmp_path, monkeypatch, old, new, expected):
    _workflow_workspace(tmp_path, monkeypatch, GOOD_WORKFLOW.replace(old, new))

    errors = sync_to_db.validate_workflow_manifests()

    assert len(errors) == 1
    assert expected in errors[0]
    assert errors[0].startswith("workflow 'demo'")


def test_a_legacy_workflow_network_alias_still_syncs(tmp_path, monkeypatch):
    """`internal`/`allow` mean egress since v0.7.1; deprecation is a warning, not a stop."""
    _workflow_workspace(
        tmp_path, monkeypatch, GOOD_WORKFLOW.replace("network: egress", "network: internal")
    )

    assert sync_to_db.validate_workflow_manifests() == []


def test_a_background_agent_is_not_held_to_container_keys(tmp_path, monkeypatch):
    """`runtime`/`entrypoint`/`limits` mean nothing to an LLM workflow."""
    _workflow_workspace(
        tmp_path,
        monkeypatch,
        "name: demo\ntype: background_agent\nruntime: nonsense\nlimits:\n  nope: 1\n",
    )

    assert sync_to_db.validate_workflow_manifests() == []


def test_an_allowed_tools_that_is_not_a_list_is_rejected(tmp_path, monkeypatch):
    _workflow_workspace(
        tmp_path,
        monkeypatch,
        GOOD_WORKFLOW + "allowed_tools: text_stats\n",
    )

    errors = sync_to_db.validate_workflow_manifests()

    assert len(errors) == 1
    assert "allowed_tools" in errors[0]
