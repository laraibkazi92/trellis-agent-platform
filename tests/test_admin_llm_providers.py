# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for Admin -> LLM Providers (see __plan_docs/llm-provider-expansion.md §11.6).

Covers:
  - GET /admin/llm-providers rendering one card per registry provider, with the
    CONFIGURED badge driven by the etcd-backed key store and no key material rendered.
  - Anonymous GET redirecting to /login.
  - POST save persisting canonical keys and global base_url keys, with blank values
    keeping the stored value.
  - POST delete removing canonical/base_url keys and rejecting unknown names.
  - GET /admin/configuration listing tool secrets but no framework LLM key rows.

No etcd or network access: the identity manager and the template renderer are faked.
"""

import asyncio
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.datastructures import FormData
from starlette.responses import RedirectResponse

from core.llm_providers import FRAMEWORK_PROVIDER_KEY_ENV, provider_ui_specs
from core.routers import admin


# --- Shared fakes --------------------------------------------------------------

class FakeLLMIdentityManager:
    def __init__(self, llm_keys=None, tools=None, mcps=None, identity_configs=None):
        self.llm_keys = dict(llm_keys or {})
        self.saved_llm_keys = []
        self._tools = tools or {}
        self._mcps = mcps or {}
        self._identity_configs = identity_configs or {}

    # LLM provider key store

    def get_llm_provider_keys(self):
        return dict(self.llm_keys)

    def save_llm_provider_keys(self, keys):
        self.llm_keys = dict(keys)
        self.saved_llm_keys.append(dict(keys))

    # Tools / MCPs (used by /admin/configuration)

    def list_tools(self):
        return list(self._tools.keys())

    def list_mcps(self):
        return list(self._mcps.keys())

    def get_tool_config(self, name):
        return self._tools.get(name)

    def get_mcp_config(self, name):
        return self._mcps.get(name)

    def get_identity_config(self, identity, category):
        return dict(self._identity_configs.get(category, {}))

    def save_identity_config(self, identity, category, value):
        self._identity_configs[category] = dict(value)


class FakeRequest:
    def __init__(self, session=None, form_data=None):
        self.session = session if session is not None else {}
        self._form_data = form_data
        self.app = SimpleNamespace(state=SimpleNamespace(http_client=None))

    async def form(self):
        return self._form_data


def _admin_session():
    return {"user": {"email": "admin@example.com", "name": "Admin"}}


def _form(pairs):
    return FormData(pairs)


# --- Template rendering --------------------------------------------------------

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"

# base.html (and the LLM providers page) read these from context processors and the
# route context. The context processors are not available here, so supply benign
# defaults; the captured route context is merged on top.
_BASE_CONTEXT = {
    "app_name": "Trellis",
    "app_favicon_url": "",
    "app_logo_url": "",
    "app_accent_color": "#0055FF",
    "app_accent_color_dark": "#3377FF",
    "is_admin": True,
    "flash_msg": None,
    "csrf_token": "test-csrf",
    "llm_providers": list(provider_ui_specs()),
    "llm_providers_json": "[]",
    "request": SimpleNamespace(
        url=SimpleNamespace(path="/admin/llm-providers"),
        session={},
    ),
}


def _render(name, context):
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    render_context = dict(_BASE_CONTEXT)
    render_context.update(context or {})
    return env.get_template(name).render(**render_context)


def _capture_templates(monkeypatch, render=True):
    """Replace TemplateResponse, capturing the template name/context.

    When ``render`` is true the real template is rendered with Jinja2 so assertions
    run against the served HTML rather than the context dict.
    """
    captured = {}

    def fake_template_response(request=None, name=None, context=None):
        captured["name"] = name
        captured["context"] = context or {}
        if render and name:
            captured["html"] = _render(name, captured["context"])
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(admin.templates, "TemplateResponse", fake_template_response)
    return captured


def _card_html(html, provider_id):
    """Slice the rendered HTML for a single provider card (attribute order agnostic)."""
    marker = f'data-provider="{provider_id}"'
    start = html.index(marker)
    next_marker = html.find('data-provider="', start + len(marker))
    return html[start:] if next_marker == -1 else html[start:next_marker]


# --- GET /admin/llm-providers --------------------------------------------------

def test_admin_llm_providers_page_renders_all_providers(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    fake_identity = FakeLLMIdentityManager(llm_keys={
        "DEEPSEEK_API_KEY": "sk-secret-deepseek",
        "OLLAMA_BASE_URL": "http://secret-host:11434",
    })
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)
    captured = _capture_templates(monkeypatch)

    request = FakeRequest(session=_admin_session())
    response = asyncio.run(admin.admin_llm_providers_page(request))

    assert response.status_code == 200
    assert captured["name"] == "admin_llm_providers.html"

    html = captured["html"]
    expected_ids = [spec["id"] for spec in provider_ui_specs()]
    assert len(expected_ids) == 15

    for provider_id in expected_ids:
        assert provider_id in html
        assert f'data-provider="{provider_id}"' in html
    assert html.count('data-provider="') == len(expected_ids)

    # Every SDK is installed under the 2.57.0 extra set, so no card may be disabled.
    assert "SDK NOT INSTALLED" not in html

    # Secrets never reach the page. The ollama base_url is intentionally rendered as
    # the input's value (it is an endpoint, not a credential), so only the API key is
    # asserted absent.
    assert "sk-secret-deepseek" not in html

    assert "CONFIGURED" in _card_html(html, "deepseek")


def test_admin_llm_providers_page_marks_keyless_providers_for_the_unconfigured_filter(monkeypatch):
    """Ollama needs no credentials, so the "Only unconfigured" filter must not list it."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(admin, "identity_mgr", FakeLLMIdentityManager())
    captured = _capture_templates(monkeypatch)

    asyncio.run(admin.admin_llm_providers_page(FakeRequest(session=_admin_session())))

    html = captured["html"]
    assert 'data-provider="ollama"' in html
    assert 'data-keyless="1"' in _card_html(html, "ollama")
    assert 'data-keyless="0"' in _card_html(html, "deepseek")


def test_admin_llm_providers_page_redirects_anonymous_to_login(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(admin, "identity_mgr", FakeLLMIdentityManager())
    captured = _capture_templates(monkeypatch)

    response = asyncio.run(admin.admin_llm_providers_page(FakeRequest(session={})))

    assert isinstance(response, RedirectResponse)
    assert response.headers["location"] == "/login"
    assert "html" not in captured


# --- POST /admin/llm-providers -------------------------------------------------

def test_save_llm_providers_persists_key_and_base_url(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    fake_identity = FakeLLMIdentityManager()
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(
        session=_admin_session(),
        form_data=_form([
            ("DEEPSEEK_API_KEY", "sk-x"),
            ("OLLAMA_BASE_URL", "http://host:11434"),
        ]),
    )
    response = asyncio.run(admin.save_llm_providers(request))

    assert isinstance(response, RedirectResponse)
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/llm-providers"

    assert fake_identity.llm_keys["DEEPSEEK_API_KEY"] == "sk-x"
    assert fake_identity.llm_keys["OLLAMA_BASE_URL"] == "http://host:11434"
    assert fake_identity.saved_llm_keys[-1] == fake_identity.llm_keys


def test_save_llm_providers_blank_values_keep_stored_values(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    stored = {
        "DEEPSEEK_API_KEY": "sk-existing",
        "OLLAMA_BASE_URL": "http://host:11434",
    }
    fake_identity = FakeLLMIdentityManager(llm_keys=stored)
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(
        session=_admin_session(),
        form_data=_form([
            ("DEEPSEEK_API_KEY", ""),
            ("OLLAMA_BASE_URL", ""),
        ]),
    )
    response = asyncio.run(admin.save_llm_providers(request))

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/llm-providers"
    assert fake_identity.llm_keys == stored
    assert fake_identity.saved_llm_keys == []


# --- POST /admin/llm-providers/delete ------------------------------------------

def test_delete_llm_provider_key_removes_canonical_key(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    fake_identity = FakeLLMIdentityManager(llm_keys={
        "DEEPSEEK_API_KEY": "sk-x",
        "OLLAMA_BASE_URL": "http://host:11434",
    })
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(session=_admin_session())
    response = asyncio.run(
        admin.delete_llm_provider_key(request, key_name="DEEPSEEK_API_KEY")
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/llm-providers"
    assert "DEEPSEEK_API_KEY" not in fake_identity.llm_keys
    assert fake_identity.llm_keys["OLLAMA_BASE_URL"] == "http://host:11434"
    assert fake_identity.saved_llm_keys[-1] == fake_identity.llm_keys
    assert request.session["flash_msg"] == "'DEEPSEEK_API_KEY' removed."


def test_delete_llm_provider_key_rejects_unknown_key(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    fake_identity = FakeLLMIdentityManager(llm_keys={"DEEPSEEK_API_KEY": "sk-x"})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(session=_admin_session())
    response = asyncio.run(
        admin.delete_llm_provider_key(request, key_name="NOT_A_KEY")
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/llm-providers"
    assert fake_identity.llm_keys == {"DEEPSEEK_API_KEY": "sk-x"}
    assert fake_identity.saved_llm_keys == []
    assert request.session["flash_msg"] == "Unknown LLM provider key."


def test_delete_llm_provider_key_allows_base_url_key(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    fake_identity = FakeLLMIdentityManager(llm_keys={
        "DEEPSEEK_API_KEY": "sk-x",
        "OLLAMA_BASE_URL": "http://host:11434",
    })
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(session=_admin_session())
    response = asyncio.run(
        admin.delete_llm_provider_key(request, key_name="OLLAMA_BASE_URL")
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/llm-providers"
    assert "OLLAMA_BASE_URL" not in fake_identity.llm_keys
    assert fake_identity.llm_keys["DEEPSEEK_API_KEY"] == "sk-x"
    assert fake_identity.saved_llm_keys[-1] == fake_identity.llm_keys
    assert request.session["flash_msg"] == "'OLLAMA_BASE_URL' removed."


# --- GET /admin/configuration --------------------------------------------------

def test_admin_configuration_page_lists_tool_secrets_but_no_llm_rows(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")

    fake_identity = FakeLLMIdentityManager(
        tools={"demo-tool": {"secrets": ["TOOL_API_KEY"]}},
    )
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)
    captured = _capture_templates(monkeypatch, render=False)

    request = FakeRequest(session=_admin_session())
    response = asyncio.run(admin.admin_configuration_page(request))

    assert response.status_code == 200

    items = captured["context"]["items"]
    keys = {item["key"] for item in items}

    assert "TOOL_API_KEY" in keys
    assert keys.isdisjoint(FRAMEWORK_PROVIDER_KEY_ENV)
    assert all(item["label"] != "LLM" for item in items)


# --- Review-hardening cases -----------------------------------------------------

def test_delete_llm_provider_key_allows_alias_and_clear_targets_it(monkeypatch):
    """A legacy alias (GOOGLE_API_KEY) must be clearable and targeted by Clear."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeLLMIdentityManager(llm_keys={"GOOGLE_API_KEY": "legacy-key"})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)
    captured = _capture_templates(monkeypatch)

    asyncio.run(admin.admin_llm_providers_page(FakeRequest(session=_admin_session())))
    html = captured["html"]

    assert "CONFIGURED" in _card_html(html, "google")
    # The Clear button targets a hidden delete form outside the card.
    assert 'value="GOOGLE_API_KEY"' in html
    assert 'form="llm-provider-delete-google"' in _card_html(html, "google")

    request = FakeRequest(session=_admin_session())
    asyncio.run(admin.delete_llm_provider_key(request, key_name="GOOGLE_API_KEY"))
    assert fake_identity.llm_keys == {}
    assert request.session["flash_msg"] == "'GOOGLE_API_KEY' removed."


def test_delete_llm_provider_key_allows_openai_compatible_fallback_name(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeLLMIdentityManager(llm_keys={"OPENAI_API_KEY": "shared-key"})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    asyncio.run(admin.delete_llm_provider_key(FakeRequest(session=_admin_session()), key_name="OPENAI_API_KEY"))
    assert fake_identity.llm_keys == {}


def test_llm_providers_page_renders_sdk_not_installed_state(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(admin, "identity_mgr", FakeLLMIdentityManager())

    def fake_specs():
        specs = []
        for spec in provider_ui_specs():
            spec = dict(spec)
            if spec["id"] == "huggingface":
                spec["sdk_installed"] = False
            specs.append(spec)
        return tuple(specs)

    monkeypatch.setattr(admin, "provider_ui_specs", fake_specs)
    captured = _capture_templates(monkeypatch)

    asyncio.run(admin.admin_llm_providers_page(FakeRequest(session=_admin_session())))
    card = _card_html(captured["html"], "huggingface")
    assert "SDK NOT INSTALLED" in card
    assert "disabled" in card


def test_stale_provider_key_on_configuration_page_is_rejected_with_warning(monkeypatch):
    """A pre-upgrade tab POSTing a provider key must not look like a successful save."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeLLMIdentityManager(llm_keys={}, tools={"demo-tool": {"secrets": ["TOOL_API_KEY"]}})
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(
        session=_admin_session(),
        form_data=_form([
            ("TOOL_API_KEY", "tool-value"),
            ("DEEPSEEK_API_KEY", "sk-lost"),
        ]),
    )
    response = asyncio.run(admin.save_admin_configuration(request))

    assert response.status_code == 303
    assert fake_identity.llm_keys == {}
    assert fake_identity._identity_configs["secrets"] == {"TOOL_API_KEY": "tool-value"}
    flash = request.session["flash_msg"]
    assert "Admin -> LLM Providers" in flash
    assert "DEEPSEEK_API_KEY" in flash


# --- Rules Engine decider overrides -------------------------------------------

class FakeRulesIdentity(FakeLLMIdentityManager):
    def __init__(self):
        super().__init__()
        self.rules = {}

    def set_rules_evaluation_provider(self, value):
        self.rules["provider"] = value

    def set_rules_evaluation_base_url(self, value):
        self.rules["base_url"] = value

    def set_rules_evaluation_model(self, value):
        self.rules["model"] = value

    def set_rules_evaluation_timeout(self, value):
        self.rules["timeout"] = value

    def clear_config(self, key):
        self.rules.pop(key, None)


def test_rules_engine_known_model_pins_its_provider(monkeypatch):
    """A known but non-inferable id (llama3.2) must not be saved provider-less."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeRulesIdentity()
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(session=_admin_session())
    response = asyncio.run(admin.set_rules_engine_model(
        request, model="llama3.2", provider="", base_url="http://box:11434",
        confidence_threshold="",
    ))

    assert response.status_code == 303
    assert fake_identity.rules["provider"] == "ollama"
    assert fake_identity.rules["model"] == "llama3.2"
    assert fake_identity.rules["base_url"] == "http://box:11434"


def test_rules_engine_rejects_base_url_for_provider_that_rejects_it(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeRulesIdentity()
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(session=_admin_session())
    response = asyncio.run(admin.set_rules_engine_model(
        request, model="deepseek-chat", provider="deepseek", base_url="http://stale:1",
        confidence_threshold="",
    ))

    assert response.status_code == 303
    assert "does not accept a base_url" in request.session["flash_msg"]
    assert fake_identity.rules == {}


def test_rules_engine_blank_provider_and_model_keeps_base_url_override(monkeypatch):
    """Blank provider/model fall back to env defaults; a base_url override is valid."""
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    fake_identity = FakeRulesIdentity()
    monkeypatch.setattr(admin, "identity_mgr", fake_identity)

    request = FakeRequest(session=_admin_session())
    response = asyncio.run(admin.set_rules_engine_model(
        request, model="", provider="", base_url="http://gateway:4000",
        confidence_threshold="",
    ))

    assert response.status_code == 303
    assert fake_identity.rules["base_url"] == "http://gateway:4000"
    assert "provider" not in fake_identity.rules
    assert "model" not in fake_identity.rules
