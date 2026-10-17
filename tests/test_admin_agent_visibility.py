# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

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
import re
from types import SimpleNamespace

import pytest
import yaml
from starlette.datastructures import FormData

from core.llm_defaults import FrameworkDefaults
from core.routers import admin


@pytest.fixture(autouse=True)
def _stub_framework_defaults(monkeypatch):
    """Keep every editor_page render hermetic (no real etcd read for the defaults)."""
    monkeypatch.setattr(admin, "get_framework_defaults", lambda: FrameworkDefaults())


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


def test_editor_page_supplies_a2a_dependents_when_other_agents_delegate(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    agent_configs = {
        "data-parser": {"name": "data-parser", "description": "worker", "internal": True},
        "triage-lead": {
            "name": "triage-lead", "description": "d",
            "a2a_access": ["data-parser"],
        },
        "front-door-bot": {
            "name": "front-door-bot", "description": "entry",
            "a2a_access": ["data-parser"],
        },
        "unrelated-agent": {"name": "unrelated-agent", "description": "x", "a2a_access": []},
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    captured = {}

    def fake_template_response(request=None, name=None, context=None):
        captured["context"] = context
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(admin.templates, "TemplateResponse", fake_template_response)

    request = FakeRequest(session=_admin_session())
    asyncio.run(admin.editor_page(request, "agent", "data-parser"))

    a2a_dependents = captured["context"]["a2a_dependents"]
    assert set(a2a_dependents) == {"triage-lead", "front-door-bot"}


def test_editor_page_a2a_dependents_empty_when_no_agent_delegates(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    agent_configs = {
        "data-parser": {"name": "data-parser", "description": "worker", "internal": True},
        "triage-lead": {"name": "triage-lead", "description": "d", "a2a_access": []},
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    captured = {}

    def fake_template_response(request=None, name=None, context=None):
        captured["context"] = context
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(admin.templates, "TemplateResponse", fake_template_response)

    request = FakeRequest(session=_admin_session())
    asyncio.run(admin.editor_page(request, "agent", "data-parser"))

    assert captured["context"]["a2a_dependents"] == []


def test_editor_page_renders_a2a_dependents_warning_when_present(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    agent_configs = {
        "data-parser": {"name": "data-parser", "description": "worker", "internal": True},
        "triage-lead": {
            "name": "triage-lead", "description": "d",
            "a2a_access": ["data-parser"],
        },
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
    asyncio.run(admin.editor_page(request, "agent", "data-parser"))

    html = admin.templates.env.get_template("editor.html").render(**captured["context"])

    assert "delegate to this agent via a2a_access" in html
    assert "triage-lead" in html


def test_editor_page_no_a2a_dependents_warning_when_absent(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    agent_configs = {
        "data-parser": {"name": "data-parser", "description": "worker", "internal": True},
        "triage-lead": {"name": "triage-lead", "description": "d", "a2a_access": []},
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
    asyncio.run(admin.editor_page(request, "agent", "data-parser"))

    html = admin.templates.env.get_template("editor.html").render(**captured["context"])

    assert "delegate to this agent via a2a_access" not in html


def test_editor_page_renders_pending_flash_as_error(monkeypatch):
    """save_agent redirects here on a rejected provider/base_url, so the flash it sets
    must be visible on the standalone editor page rather than silently dropped."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeIdentityManagerAdmin(
        {"data-parser": {"name": "data-parser", "description": "worker"}}
    )
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    captured = {}
    real_template_response = admin.templates.TemplateResponse

    def capturing_template_response(request=None, name=None, context=None):
        captured["context"] = context
        return real_template_response(request=request, name=name, context=context)

    monkeypatch.setattr(admin.templates, "TemplateResponse", capturing_template_response)

    session = _admin_session()
    session["flash_msg"] = "Provider 'deepseek' does not accept a base_url; remove it."
    asyncio.run(admin.editor_page(FakeRequest(session=session), "agent", "data-parser"))

    html = admin.templates.env.get_template("editor.html").render(**captured["context"])
    assert "does not accept a base_url" in html
    assert "flash_msg" not in session


# --- save_agent (POST) -----------------------------------------------------------

def _form(pairs):
    return FormData(pairs)


def test_save_agent_persists_external_false_and_internal_false(monkeypatch):
    """A genuine browser submission of this form always includes the '_submitted'
    sentinel fields, regardless of checkbox state. When the sentinels are present but
    the checkbox fields themselves are absent, that represents a deliberate uncheck in
    the browser, and False should still be persisted."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

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
        # external/internal checkboxes omitted -> unchecked, but the sentinels are
        # present -> this is a genuine form submission with both boxes unchecked.
        ("external_submitted", "1"),
        ("internal_submitted", "1"),
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "data-parser"))

    saved = fake_identity.saved_configs["data-parser"]
    assert saved["external"] is False
    assert saved["internal"] is False


def test_save_agent_raw_post_without_sentinels_preserves_existing_values(monkeypatch):
    """A raw/scripted POST that predates (or doesn't know about) the external/internal
    fields omits both the checkbox fields AND the '_submitted' sentinels. This must NOT
    be treated as a deliberate uncheck -- it should preserve whatever external/internal
    value the agent already had persisted, rather than silently flipping to False."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    agent_configs = {
        "data-parser": {
            "name": "data-parser",
            "description": "worker",
            "external": True,
            "internal": False,
        },
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("model", "gemini-3-flash-preview"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
        # No "external"/"internal" and no "*_submitted" sentinels at all.
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "data-parser"))

    saved = fake_identity.saved_configs["data-parser"]
    # Existing persisted values are preserved, not flipped to False.
    assert saved["external"] is True
    assert saved["internal"] is False


def test_save_agent_raw_post_without_sentinels_preserves_default_true(monkeypatch):
    """Same as above, but for an agent with no persisted external/internal keys at all
    (legacy config predating the flags) -- the default of True must be preserved, not
    flipped to False."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    agent_configs = {
        "legacy-agent": {"name": "legacy-agent", "description": "worker"},
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("model", "gemini-3-flash-preview"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
        # No "external"/"internal" and no "*_submitted" sentinels at all.
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "legacy-agent"))

    saved = fake_identity.saved_configs["legacy-agent"]
    assert saved["external"] is True
    assert saved["internal"] is True


def test_save_agent_raw_post_without_sentinels_coerces_legacy_string_values(monkeypatch):
    """A legacy config.yaml entry that was YAML-quoted as a string (e.g. "false" instead
    of a real bool false) must be normalized to a genuine bool when preserved through the
    sentinel-absent branch, so downstream `is not False` identity checks work correctly."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    agent_configs = {
        "legacy-string-agent": {
            "name": "legacy-string-agent",
            "description": "worker",
            "external": "false",
            "internal": "true",
        },
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("model", "gemini-3-flash-preview"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
        # No "external"/"internal" and no "*_submitted" sentinels at all.
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "legacy-string-agent"))

    saved = fake_identity.saved_configs["legacy-string-agent"]
    assert saved["external"] is False
    assert saved["internal"] is True


def test_save_agent_persists_external_true_and_internal_true_when_checked(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

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
        ("external_submitted", "1"),
        ("external", "true"),
        ("internal_submitted", "1"),
        ("internal", "true"),
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "general-agent"))

    saved = fake_identity.saved_configs["general-agent"]
    assert saved["external"] is True
    assert saved["internal"] is True


def test_save_agent_drops_a2a_targets_with_internal_false(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

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


def test_save_agent_dual_writes_workspace_files(monkeypatch):
    """UI edits must persist to the workspace, not just etcd: scripts/sync_to_db.py
    re-applies the on-disk config on every rebuild, so an etcd-only save would be
    reverted. This is the local-file replacement for the old GitHub write-back."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    fake_identity = FakeIdentityManagerAdmin({"data-parser": {"name": "data-parser"}})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("model", "gemini-3-flash-preview"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "data-parser"))

    # conftest redirects workspace_io at a per-test tmp dir, so this never touches the repo.
    from core import workspace_io

    agent_dir = workspace_io.WORKSPACE_DIR / "agents" / "data-parser"
    assert yaml.safe_load((agent_dir / "config.yaml").read_text())["name"] == "data-parser"
    assert (agent_dir / "skills.md").read_text() == "do work"


# --- Registry-driven provider/model (llm-provider-expansion §11.7) --------------

_EXPECTED_PROVIDER_IDS = (
    "google", "openai", "anthropic", "deepseek", "fireworks", "together",
    "moonshotai", "vercel", "zai", "openrouter", "alibaba", "ollama",
    "litellm", "huggingface", "openai-compatible",
)


def test_save_agent_persists_deepseek_provider_and_model_to_etcd_and_workspace(monkeypatch):
    """A non-Google provider picked in the editor must survive both persistence
    layers: the etcd config dict and the workspace config.yaml that the next
    rebuild's registry sync re-applies."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    fake_identity = FakeIdentityManagerAdmin({"data-parser": {"name": "data-parser"}})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("provider", "deepseek"),
        ("model", "deepseek-chat"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    asyncio.run(admin.save_agent(request, "data-parser"))

    saved = fake_identity.saved_configs["data-parser"]
    assert saved["provider"] == "deepseek"
    assert saved["model"] == "deepseek-chat"

    from core import workspace_io

    agent_dir = workspace_io.WORKSPACE_DIR / "agents" / "data-parser"
    on_disk = yaml.safe_load((agent_dir / "config.yaml").read_text())
    assert on_disk["provider"] == "deepseek"
    assert on_disk["model"] == "deepseek-chat"


def test_save_agent_rejects_unknown_provider_with_flash_and_no_write(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    fake_identity = FakeIdentityManagerAdmin({"data-parser": {"name": "data-parser"}})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("provider", "not-a-provider"),
        ("model", "deepseek-chat"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    response = asyncio.run(admin.save_agent(request, "data-parser"))

    assert response.status_code == 303
    assert response.headers["location"] == "/editor/agent/data-parser"
    assert "Invalid provider 'not-a-provider'" in request.session["flash_msg"]
    assert fake_identity.saved_configs == {}

    from core import workspace_io

    assert not (workspace_io.WORKSPACE_DIR / "agents" / "data-parser" / "config.yaml").exists()


def test_save_agent_rejects_openai_compatible_without_base_url(monkeypatch):
    """A provider that requires an endpoint must not be saved without one."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    fake_identity = FakeIdentityManagerAdmin({"data-parser": {"name": "data-parser"}})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    form_data = _form([
        ("provider", "openai-compatible"),
        ("model", "llama3.2"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
    ])
    request = FakeRequest(session=_admin_session(), form_data=form_data)

    response = asyncio.run(admin.save_agent(request, "data-parser"))

    assert response.status_code == 303
    assert response.headers["location"] == "/editor/agent/data-parser"
    assert "requires a base_url" in request.session["flash_msg"]
    assert fake_identity.saved_configs == {}


def test_editor_page_renders_registry_driven_provider_model_and_thinking_fields(monkeypatch):
    """The rewritten agent editor branch renders the hidden model value, the
    registry-driven model/provider selects, the base_url container, and the
    thinking-level select, all fed by the llm_providers context processor."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    agent_configs = {
        "deepseek-agent": {
            "name": "deepseek-agent",
            "description": "d",
            "model": "deepseek-chat",
            "provider": "deepseek",
            "a2a_access": [],
        },
    }
    fake_identity = FakeIdentityManagerAdmin(agent_configs)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(session=_admin_session())
    response = asyncio.run(admin.editor_page(request, "agent", "deepseek-agent"))

    assert response.status_code == 200
    html = response.body.decode()

    for element_id in (
        "modelValue",
        "modelSelect",
        "modelCustomInput",
        "baseUrlField",
        "providerSelect",
        "thinkingLevelSelect",
    ):
        assert f'id="{element_id}"' in html

    # The inline JS payload is injected by core.dependencies.llm_providers_context.
    assert "window.LLM_PROVIDERS = " in html

    # Every registry provider is offered as an <option>.
    assert len(_EXPECTED_PROVIDER_IDS) == 15
    for provider_id in _EXPECTED_PROVIDER_IDS:
        assert f'<option value="{provider_id}"' in html

    # The saved deepseek selection drives the thinking-level style to "none"; the inline
    # JS reads that from the shared payload, not from a per-option data-* attribute.
    assert '<option value="deepseek"' in html
    assert re.search(r'\{"id": "deepseek",[^}]*"thinking_style": "none"', html)

    # The saved model is carried in the hidden field the POST actually submits.
    assert 'id="modelValue" value="deepseek-chat"' in html


def test_editor_page_renders_inherit_hint_for_an_unset_agent(monkeypatch):
    """Route-level: an agent with no provider/model shows the framework-default hint."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeIdentityManagerAdmin(
        {"blank-agent": {"name": "blank-agent", "description": "d", "a2a_access": []}}
    )
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)
    monkeypatch.setattr(
        admin, "get_framework_defaults",
        lambda: FrameworkDefaults("deepseek", "deepseek-chat", None),
    )

    response = asyncio.run(admin.editor_page(FakeRequest(session=_admin_session()), "agent", "blank-agent"))

    assert response.status_code == 200
    html = response.body.decode()
    assert 'id="inheritDefaultHint"' in html
    assert "Inherits framework default: DeepSeek / deepseek-chat" in html
    # Still not prefilled.
    assert 'id="modelValue" value=""' in html
    assert '<option value="deepseek" selected' not in html


def test_editor_page_renders_case_b_hint_for_a_provider_only_agent(monkeypatch):
    """Route-level: provider set + blank model shows the registry-default hint (case B)."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeIdentityManagerAdmin(
        {"provider-only": {
            "name": "provider-only", "description": "d",
            "provider": "deepseek", "model": "", "a2a_access": [],
        }}
    )
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)
    monkeypatch.setattr(admin, "get_framework_defaults", lambda: FrameworkDefaults())

    response = asyncio.run(admin.editor_page(FakeRequest(session=_admin_session()), "agent", "provider-only"))

    assert response.status_code == 200
    html = response.body.decode()
    assert 'id="inheritDefaultHint"' in html
    assert "Uses DeepSeek default: deepseek-chat" in html


def test_save_agent_empty_provider_stays_none(monkeypatch):
    """Auto/inferred provider must still save as None without tripping validation."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeIdentityManagerAdmin({"data-parser": {"name": "data-parser"}})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(session=_admin_session(), form_data=_form([
        ("provider", ""),
        ("model", "gemini-2.5-flash"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
    ]))
    asyncio.run(admin.save_agent(request, "data-parser"))

    assert fake_identity.saved_configs["data-parser"]["provider"] is None


def test_save_agent_rejects_base_url_for_provider_that_does_not_accept_one(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeIdentityManagerAdmin({"data-parser": {"name": "data-parser"}})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(session=_admin_session(), form_data=_form([
        ("provider", "deepseek"),
        ("model", "deepseek-chat"),
        ("base_url", "http://stale:1234"),
        ("thinking_level", "none"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
    ]))
    response = asyncio.run(admin.save_agent(request, "data-parser"))

    assert response.status_code == 303
    assert "does not accept a base_url" in request.session["flash_msg"]
    assert fake_identity.saved_configs == {}


def test_save_agent_auto_provider_accepts_base_url_for_inferred_model(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeIdentityManagerAdmin({"data-parser": {"name": "data-parser"}})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(session=_admin_session(), form_data=_form([
        ("provider", ""),
        ("model", "qwen2.5"),
        ("base_url", "http://box:11434"),
        ("thinking_level", "n/a"),
        ("version", "0.1.0"),
        ("description", "worker"),
        ("skills_content", "do work"),
    ]))
    asyncio.run(admin.save_agent(request, "data-parser"))

    saved = fake_identity.saved_configs["data-parser"]
    assert saved["provider"] is None
    assert saved["base_url"] == "http://box:11434"
