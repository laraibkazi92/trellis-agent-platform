# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for core/routers/workflows.py's use of the shared discovery configuration-
readiness pipeline (see __spec_docs/completed/rules_engine_hardening_plan.md §2C).

Before this fix, `workflows_view()` computed `is_configured` for background_agent/
background_script workflows with its own hand-rolled logic that only looked at
`get_agent_required_secrets`/`get_agent_required_variables` -- it never checked
`secret_groups` at all, so a workflow whose only requirement was an unsatisfied
secret_group option (e.g. netctl's per-environment username/password picker) would
incorrectly render as configured on /workflows, disagreeing with
`discovery.is_agent_configured()`. Similarly, `configure_background_agent_secrets()`
(the "Secrets" modal's save handler) never resolved `secret_groups` at all, so a
group requirement could never actually be satisfied through that UI.

These tests exercise `workflows_view()` and `configure_background_agent_secrets()`
directly (matching the router-testing pattern in tests/test_marketplace_health_evaluation.py:
a fake IdentityManager plus a captured `templates.TemplateResponse` context), rather than
over HTTP.
"""
import asyncio
from types import SimpleNamespace

from core import discovery
from core.routers import workflows


NETCTL_LIKE_TOOL_CONFIG = {
    "name": "netctl",
    "secrets": [],
    "optional_secrets": [
        "EXAMPLE-API_STAGING_USERNAME", "EXAMPLE-API_STAGING_PASSWORD",
        "EXAMPLE-API_PRODUCTION_USERNAME", "EXAMPLE-API_PRODUCTION_PASSWORD",
    ],
    "secret_groups": [
        {
            "label": "Example API Environment Credentials",
            "select_label": "Environment",
            "options": [
                {"value": "staging", "label": "Staging", "fields": [
                    {"key": "EXAMPLE-API_STAGING_USERNAME", "label": "Username"},
                    {"key": "EXAMPLE-API_STAGING_PASSWORD", "label": "Password"},
                ]},
                {"value": "production", "label": "Production", "fields": [
                    {"key": "EXAMPLE-API_PRODUCTION_USERNAME", "label": "Username"},
                    {"key": "EXAMPLE-API_PRODUCTION_PASSWORD", "label": "Password"},
                ]},
            ],
        }
    ],
}

WORKFLOW_WITH_SECRET_GROUP_TOOL = {
    "name": "devops-workflow",
    "type": "background_agent",
    "description": "A devops workflow.",
    "allowed_tools": ["netctl"],
    "allowed_mcps": [],
}

PLAIN_SECRET_TOOL_CONFIG = {
    "name": "netctl",
    "secrets": ["SOME_REQUIRED_SECRET"],
    "optional_secrets": [],
    "secret_groups": [],
}

PLAIN_WORKFLOW = {
    "name": "plain-workflow",
    "type": "background_script",
    "description": "A plain workflow.",
    "allowed_tools": ["netctl"],
    "allowed_mcps": [],
}


class FakeIdentityManagerWorkflows:
    """Minimal fake covering every identity_mgr method workflows_view() /
    configure_background_agent_secrets() (and, transitively, discover_agents()) call."""

    def __init__(self, agent_configs=None, tool_configs=None, mcp_configs=None,
                 identity_secrets=None, identity_variables=None,
                 disabled_workflows=None, agent_runs=None):
        self._agent_configs = agent_configs or {}
        self._tool_configs = tool_configs or {}
        self._mcp_configs = mcp_configs or {}
        # keyed by Identity.id ("system" for the global identity)
        self._identity_secrets = {k: dict(v) for k, v in (identity_secrets or {}).items()}
        self._identity_variables = {k: dict(v) for k, v in (identity_variables or {}).items()}
        self._disabled_workflows = disabled_workflows or []
        self._agent_runs = agent_runs or {}

    # -- workflows_view --
    def list_agents(self):
        return list(self._agent_configs.keys())

    def get_disabled_workflows(self):
        return list(self._disabled_workflows)

    def get_agent_config(self, name):
        return self._agent_configs.get(name)

    def get_all_agent_configs(self):
        return dict(self._agent_configs)

    def list_mcps(self):
        return list(self._mcp_configs.keys())

    def get_agent_runs(self, name, limit=None):
        return list(self._agent_runs.get(name, []))

    # -- discover_agents / requirement resolution --
    def get_all_health_statuses(self, entity_type):
        return {}

    def get_all_agent_skills(self):
        return {}

    def get_all_tool_configs(self):
        return dict(self._tool_configs)

    def get_all_mcp_configs(self):
        return dict(self._mcp_configs)

    def get_tool_config(self, name):
        return self._tool_configs.get(name)

    def get_mcp_config(self, name):
        return self._mcp_configs.get(name)

    def get_identity_config(self, identity, category, keys=None):
        store = self._identity_secrets if category == "secrets" else self._identity_variables
        return dict(store.get(identity.id, {}))

    def save_identity_config(self, identity, category, data):
        store = self._identity_secrets if category == "secrets" else self._identity_variables
        store[identity.id] = dict(data)


async def _fake_get_current_user(request):
    return {"sub": "admin-1", "email": "admin@example.com"}


def _run_workflows_view(monkeypatch, fake_mgr):
    monkeypatch.setattr(workflows, "get_current_user", _fake_get_current_user)
    monkeypatch.setattr(workflows, "identity_mgr", fake_mgr)
    # discover_agents() is called via the name imported into workflows' namespace, but it
    # executes against the `identity_mgr` bound in core/discovery.py's own module globals --
    # patch that too (in production these are the same get_identity_manager() singleton).
    monkeypatch.setattr(discovery, "identity_mgr", fake_mgr)

    captured = {}

    def fake_template_response(request=None, name=None, context=None):
        captured["context"] = context
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(workflows.templates, "TemplateResponse", fake_template_response)

    request = SimpleNamespace(session={"user": {"sub": "admin-1", "email": "admin@example.com"}})
    asyncio.run(workflows.workflows_view(request))
    return captured["context"]["workflows_list"]


# --- workflows_view: is_configured now agrees with the shared discovery pipeline -----

def test_workflows_view_secret_groups_only_unsatisfied_is_not_configured(monkeypatch):
    """Regression: previously workflows_view() never checked secret_groups at all, so a
    workflow with zero fully-configured secret_group options would show as configured."""
    fake_mgr = FakeIdentityManagerWorkflows(
        agent_configs={"devops-workflow": WORKFLOW_WITH_SECRET_GROUP_TOOL},
        tool_configs={"netctl": NETCTL_LIKE_TOOL_CONFIG},
    )

    workflows_list = _run_workflows_view(monkeypatch, fake_mgr)

    assert len(workflows_list) == 1
    wf = workflows_list[0]
    assert wf["is_configured"] is False
    assert "EXAMPLE-API_STAGING_USERNAME" in wf["missing_secrets"]
    assert "EXAMPLE-API_PRODUCTION_USERNAME" in wf["missing_secrets"]
    assert wf["secret_groups"], "secret_groups must be passed through for the configure modal"


def test_workflows_view_one_secret_group_option_satisfied_is_configured(monkeypatch):
    fake_mgr = FakeIdentityManagerWorkflows(
        agent_configs={"devops-workflow": WORKFLOW_WITH_SECRET_GROUP_TOOL},
        tool_configs={"netctl": NETCTL_LIKE_TOOL_CONFIG},
        identity_secrets={
            "devops-workflow": {
                "EXAMPLE-API_PRODUCTION_USERNAME": "produser",
                "EXAMPLE-API_PRODUCTION_PASSWORD": "prodpass",
            }
        },
    )

    workflows_list = _run_workflows_view(monkeypatch, fake_mgr)

    wf = workflows_list[0]
    assert wf["is_configured"] is True
    assert wf["missing_secrets"] == []
    # The per-field is_set picker shape is preserved for the template.
    group = wf["secret_groups"][0]
    production_option = next(o for o in group["options"] if o["value"] == "production")
    assert all(f["is_set"] for f in production_option["fields"])


def test_workflows_view_plain_required_secret_unchanged(monkeypatch):
    """Non-regression: a workflow with only plain required secrets (no secret_groups
    involved) must behave exactly as before this fix."""
    fake_mgr = FakeIdentityManagerWorkflows(
        agent_configs={"plain-workflow": PLAIN_WORKFLOW},
        tool_configs={"netctl": PLAIN_SECRET_TOOL_CONFIG},
    )

    workflows_list = _run_workflows_view(monkeypatch, fake_mgr)

    wf = workflows_list[0]
    assert wf["is_configured"] is False
    assert wf["missing_secrets"] == ["SOME_REQUIRED_SECRET"]
    assert wf["required_secrets"] == ["SOME_REQUIRED_SECRET"]
    assert wf["secret_groups"] == []


# --- configure_background_agent_secrets: persists group keys, rejects unknown keys ---

def _run_configure_secrets(monkeypatch, fake_mgr, agent_name, form_data):
    monkeypatch.setattr(workflows, "get_current_user", _fake_get_current_user)
    monkeypatch.setattr(workflows, "is_admin", lambda request: True)
    monkeypatch.setattr(workflows, "identity_mgr", fake_mgr)
    monkeypatch.setattr(discovery, "identity_mgr", fake_mgr)

    class FakeRequest:
        def __init__(self):
            self.session = {"user": {"sub": "admin-1", "email": "admin@example.com"}}

        async def form(self):
            return form_data

    return asyncio.run(workflows.configure_background_agent_secrets(FakeRequest(), agent_name))


def test_configure_background_agent_secrets_persists_group_key_rejects_unknown(monkeypatch):
    fake_mgr = FakeIdentityManagerWorkflows(
        agent_configs={"devops-workflow": WORKFLOW_WITH_SECRET_GROUP_TOOL},
        tool_configs={"netctl": NETCTL_LIKE_TOOL_CONFIG},
    )
    form_data = {
        "csrf_token": "test-csrf-token",
        "EXAMPLE-API_PRODUCTION_USERNAME": "produser",
        "EXAMPLE-API_PRODUCTION_PASSWORD": "prodpass",
        "SOME_UNRELATED_KEY_NOT_IN_ANY_GROUP": "should-not-be-saved",
    }

    _run_configure_secrets(monkeypatch, fake_mgr, "devops-workflow", form_data)

    saved_secrets = fake_mgr._identity_secrets.get("devops-workflow", {})
    assert saved_secrets.get("EXAMPLE-API_PRODUCTION_USERNAME") == "produser"
    assert saved_secrets.get("EXAMPLE-API_PRODUCTION_PASSWORD") == "prodpass"
    assert "SOME_UNRELATED_KEY_NOT_IN_ANY_GROUP" not in saved_secrets


def test_configure_background_agent_secrets_plain_required_secret_unchanged(monkeypatch):
    """Non-regression: saving a plain required secret (no secret_groups involved) still
    works exactly as before this fix."""
    fake_mgr = FakeIdentityManagerWorkflows(
        agent_configs={"plain-workflow": PLAIN_WORKFLOW},
        tool_configs={"netctl": PLAIN_SECRET_TOOL_CONFIG},
    )
    form_data = {
        "csrf_token": "test-csrf-token",
        "SOME_REQUIRED_SECRET": "the-secret-value",
    }

    _run_configure_secrets(monkeypatch, fake_mgr, "plain-workflow", form_data)

    saved_secrets = fake_mgr._identity_secrets.get("plain-workflow", {})
    assert saved_secrets.get("SOME_REQUIRED_SECRET") == "the-secret-value"
