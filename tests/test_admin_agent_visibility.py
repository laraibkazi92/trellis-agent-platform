"""Tests for Phase 4 (Admin Panel & Agent Editor Configuration) — see
__spec_docs/internal_external_agents_spec.md.

Covers:
  - GET /editor/agent/{name} (editor_page) supplying the internal_agents map to the template
    context, and the rendered a2a_access <select> marking internal: False targets as disabled
    with an "[Internal Calling Disabled]" note.
  - POST /editor/agent/{name} (save_agent) persisting external=False / internal=False into the
    saved config dict.
  - POST /editor/agent/{name} dropping a2a_access targets whose config has internal=False, while
    keeping internal: True targets.
"""
import asyncio
from types import SimpleNamespace

from starlette.datastructures import FormData

from core.routers import admin


# --- Shared fakes --------------------------------------------------------------

class FakeIdentityManagerAdmin:
    def __init__(self, agent_configs, skills=None):
        self._agent_configs = agent_configs
        self._skills = skills or {}
        self.saved_configs = {}
        self.saved_skills = {}

    def get_agent_config(self, name):
        return self._agent_configs.get(name)

    def get_agent_skills(self, name):
        return self._skills.get(name, "")

    def list_agents(self):
        return list(self._agent_configs.keys())

    def get_all_agent_configs(self):
        return dict(self._agent_configs)

    def get_all_tool_configs(self):
        return {}

    def get_all_mcp_configs(self):
        return {}

    def list_mcps(self):
        return []

    def save_agent_config(self, name, config):
        self.saved_configs[name] = dict(config)

    def save_agent_skills(self, name, skills):
        self.saved_skills[name] = skills


class FakeRequest:
    def __init__(self, session=None, form_data=None):
        self.session = session if session is not None else {}
        self._form_data = form_data
        self.app = SimpleNamespace(state=SimpleNamespace(http_client=None))

    async def form(self):
        return self._form_data


def _admin_session():
    return {"user": {"email": "admin@example.com"}}


# --- editor_page (GET) ----------------------------------------------------------

def test_editor_page_supplies_internal_agents_map(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    agent_configs = {
        "triage-lead": {"name": "triage-lead", "description": "d", "a2a_access": []},
        "data-parser": {"name": "data-parser", "description": "worker", "internal": True},
        "front-door-bot": {"name": "front-door-bot", "description": "entry", "internal": False},
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    captured = {}

    def fake_template_response(request=None, name=None, context=None):
        captured["context"] = context
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(admin.templates, "TemplateResponse", fake_template_response)

    request = FakeRequest(session=_admin_session())
    asyncio.run(admin.editor_page(request, "agent", "triage-lead"))

    internal_agents = captured["context"]["internal_agents"]
    assert internal_agents["data-parser"] is True
    assert internal_agents["front-door-bot"] is False


def test_editor_page_renders_a2a_select_with_internal_false_disabled(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    agent_configs = {
        "triage-lead": {"name": "triage-lead", "description": "d", "a2a_access": []},
        "data-parser": {"name": "data-parser", "description": "worker", "internal": True},
        "front-door-bot": {"name": "front-door-bot", "description": "entry", "internal": False},
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    captured = {}
    real_template_response = admin.templates.TemplateResponse

    def capturing_template_response(request=None, name=None, context=None):
        captured["context"] = context
        return real_template_response(request=request, name=name, context=context)

    monkeypatch.setattr(admin.templates, "TemplateResponse", capturing_template_response)

    request = FakeRequest(session=_admin_session())
    asyncio.run(admin.editor_page(request, "agent", "triage-lead"))

    html = admin.templates.env.get_template("editor.html").render(**captured["context"])

    # internal: True target renders as a normal, enabled option.
    assert '<option value="data-parser"' in html
    data_parser_start = html.index('<option value="data-parser"')
    data_parser_end = html.index("</option>", data_parser_start)
    data_parser_option = html[data_parser_start:data_parser_end]
    assert "disabled" not in data_parser_option

    # internal: False target is disabled and annotated.
    assert '<option value="front-door-bot"' in html
    front_door_start = html.index('<option value="front-door-bot"')
    front_door_end = html.index("</option>", front_door_start)
    front_door_option = html[front_door_start:front_door_end]
    assert "disabled" in front_door_option
    assert "[Internal Calling Disabled]" in front_door_option


# --- save_agent (POST) -----------------------------------------------------------

def _form(pairs):
    return FormData(pairs)


def test_save_agent_persists_external_false_and_internal_false(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(admin, "GITHUB_REPO", "")
    monkeypatch.setattr(admin, "GITHUB_TOKEN", "")

    agent_configs = {
        "data-parser": {"name": "data-parser", "description": "worker"},
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("model", "gemini-3-flash-preview"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
        # external/internal checkboxes intentionally omitted -> unchecked -> False
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "data-parser"))

    saved = fake_identity.saved_configs["data-parser"]
    assert saved["external"] is False
    assert saved["internal"] is False


def test_save_agent_persists_external_true_and_internal_true_when_checked(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(admin, "GITHUB_REPO", "")
    monkeypatch.setattr(admin, "GITHUB_TOKEN", "")

    agent_configs = {
        "general-agent": {"name": "general-agent", "description": "general"},
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("model", "gemini-3-flash-preview"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "general"),
        ("skills_content", "do general work"),
        ("external", "true"),
        ("internal", "true"),
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "general-agent"))

    saved = fake_identity.saved_configs["general-agent"]
    assert saved["external"] is True
    assert saved["internal"] is True


def test_save_agent_drops_a2a_targets_with_internal_false(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(admin, "GITHUB_REPO", "")
    monkeypatch.setattr(admin, "GITHUB_TOKEN", "")

    agent_configs = {
        "triage-lead": {"name": "triage-lead", "description": "d"},
        "data-parser": {"name": "data-parser", "description": "worker", "internal": True},
        "front-door-bot": {"name": "front-door-bot", "description": "entry", "internal": False},
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("model", "gemini-3-flash-preview"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "d"),
        ("skills_content", "delegate"),
        ("external", "true"),
        ("internal", "true"),
        ("a2a_access", "data-parser"),
        ("a2a_access", "front-door-bot"),
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "triage-lead"))

    saved = fake_identity.saved_configs["triage-lead"]
    assert saved["a2a_access"] == ["data-parser"]


def test_save_agent_keeps_a2a_target_missing_from_registry_fail_open(monkeypatch):
    """A target that can't be resolved at all (e.g. race with a delete) has no signal to
    fail closed on — matches the fail-open-on-missing-config pattern used elsewhere in this
    spec (Phase 2/3), as opposed to fail-closed only on an explicit internal: False."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(admin, "GITHUB_REPO", "")
    monkeypatch.setattr(admin, "GITHUB_TOKEN", "")

    agent_configs = {
        "triage-lead": {"name": "triage-lead", "description": "d"},
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("model", "gemini-3-flash-preview"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "d"),
        ("skills_content", "delegate"),
        ("external", "true"),
        ("internal", "true"),
        ("a2a_access", "unknown-agent"),
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "triage-lead"))

    saved = fake_identity.saved_configs["triage-lead"]
    assert saved["a2a_access"] == ["unknown-agent"]
