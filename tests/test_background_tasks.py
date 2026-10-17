# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for Phase 5 (Cycle 4) Task 5.1 — fire-and-forget safety.

Both `core.hub` and `core.host` must expose a module-level `_background_tasks`
set and a `_spawn_background(coro, name)` helper that creates an asyncio task,
tracks it, discards it when it completes, and routes failures through the
module logger instead of swallowing them.

Also covers the LLM-provider-expansion Phase 5 workflow modal persistence:
`workflows.update_background_trigger` (via `AgentUpdateModel`) must validate and
persist a background_agent's `provider`/`base_url` to both etcd and the
workspace YAML, and the modal must render the registry-driven controls.
"""

import asyncio
import logging
import re
from types import SimpleNamespace

import pytest
import yaml
from starlette.datastructures import FormData

from core import host, hub, workspace_io
from core.dependencies import llm_providers_context, templates
from core.routers import workflows


@pytest.mark.parametrize("module", [hub, host], ids=["hub", "host"])
def test_spawn_background_logs_and_discards_on_exception(module, caplog):
    async def boom():
        raise RuntimeError("kaboom")

    async def scenario():
        task = module._spawn_background(boom(), "boom-task")
        try:
            await task
        except RuntimeError:
            pass
        await asyncio.sleep(0)
        return task

    with caplog.at_level(logging.ERROR):
        task = asyncio.run(scenario())

    assert "Background task boom-task failed" in caplog.text
    assert "kaboom" in caplog.text
    assert task not in module._background_tasks


@pytest.mark.parametrize("module", [hub, host], ids=["hub", "host"])
def test_spawn_background_ignores_cancellation(module, caplog):
    async def scenario():
        blocker = asyncio.Event()

        async def wait_forever():
            await blocker.wait()

        task = module._spawn_background(wait_forever(), "cancelled-task")
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await asyncio.sleep(0)
        return task

    with caplog.at_level(logging.ERROR):
        task = asyncio.run(scenario())

    assert "Background task" not in caplog.text
    assert task not in module._background_tasks


@pytest.mark.parametrize("module", [hub, host], ids=["hub", "host"])
def test_spawn_background_discards_on_success(module, caplog):
    async def fine():
        return "ok"

    async def scenario():
        task = module._spawn_background(fine(), "fine-task")
        result = await task
        await asyncio.sleep(0)
        return task, result

    with caplog.at_level(logging.ERROR):
        task, result = asyncio.run(scenario())

    assert result == "ok"
    assert task.done()
    assert task not in module._background_tasks
    assert [record for record in caplog.records if record.levelno >= logging.ERROR] == []


# --- Background workflow agent provider/base_url persistence (llm-provider-
# expansion §9.3). The /workflows config modal POST goes through
# workflows.update_background_trigger -> AgentUpdateModel, which must validate
# the provider/base_url pair and persist both to etcd and workspace YAML. ---

_AGENT_NAME = "nightly-report"


class FakeWorkflowsIdentityManager:
    def __init__(self, configs=None):
        self._configs = configs or {
            _AGENT_NAME: {"name": _AGENT_NAME, "type": "background_agent", "description": "report"}
        }
        self.saved_configs = {}
        self.saved_skills = {}

    def get_agent_config(self, name):
        return self._configs.get(name)

    def save_agent_config(self, name, config):
        self.saved_configs[name] = dict(config)

    def save_agent_skills(self, name, skills):
        self.saved_skills[name] = skills


class FakeWorkflowsRequest:
    def __init__(self, form_data):
        self.session = {"user": {"email": "admin@example.com"}}
        self._form_data = form_data
        self.app = SimpleNamespace(state=SimpleNamespace(http_client=None))

    async def form(self):
        return self._form_data


def _workflow_form(provider=None, model="deepseek-chat", base_url=None, **overrides):
    pairs = [
        ("agent_name", _AGENT_NAME),
        ("model", model),
        ("thinking_level", "none"),
        ("provider", provider if provider is not None else ""),
        ("version", "0.1.0"),
        ("description", "report"),
        ("skills_content", "do work"),
    ]
    if base_url is not None:
        pairs.append(("base_url", base_url))
    pairs.extend(overrides.items())
    return FormData(pairs)


def _run_workflow_update(monkeypatch, form_data, fake_mgr=None):
    fake_mgr = fake_mgr or FakeWorkflowsIdentityManager()

    async def fake_get_current_user(request):
        return {"sub": "admin-1", "email": "admin@example.com"}

    monkeypatch.setattr(workflows, "get_current_user", fake_get_current_user)
    monkeypatch.setattr(workflows, "is_admin", lambda request: True)
    monkeypatch.setattr(workflows, "identity_mgr", fake_mgr)

    request = FakeWorkflowsRequest(form_data)
    response = asyncio.run(workflows.update_background_trigger(request))
    return response, fake_mgr, request


def _persisted_config_yaml():
    path = workspace_io.WORKSPACE_DIR / "workflows" / _AGENT_NAME / "config.yaml"
    return yaml.safe_load(path.read_text())


def test_update_workflow_persists_deepseek_provider_to_etcd_and_workspace(monkeypatch):
    response, fake_mgr, _ = _run_workflow_update(
        monkeypatch, _workflow_form(provider="deepseek", model="deepseek-chat")
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/workflows"

    saved = fake_mgr.saved_configs[_AGENT_NAME]
    assert saved["provider"] == "deepseek"
    assert saved["model"] == "deepseek-chat"
    assert saved["base_url"] is None

    on_disk = _persisted_config_yaml()
    assert on_disk["provider"] == "deepseek"
    assert on_disk["model"] == "deepseek-chat"
    assert on_disk["base_url"] is None


def test_update_workflow_persists_ollama_base_url_to_etcd_and_workspace(monkeypatch):
    response, fake_mgr, _ = _run_workflow_update(
        monkeypatch,
        _workflow_form(provider="ollama", model="llama3.2", base_url="http://box:11434"),
    )

    assert response.status_code == 303
    saved = fake_mgr.saved_configs[_AGENT_NAME]
    assert saved["provider"] == "ollama"
    assert saved["base_url"] == "http://box:11434"

    on_disk = _persisted_config_yaml()
    assert on_disk["provider"] == "ollama"
    assert on_disk["base_url"] == "http://box:11434"


def test_update_workflow_empty_provider_saves_none_for_inference(monkeypatch):
    response, fake_mgr, _ = _run_workflow_update(
        monkeypatch, _workflow_form(provider="", model="gemini-2.5-flash")
    )

    assert response.status_code == 303
    assert fake_mgr.saved_configs[_AGENT_NAME]["provider"] is None
    assert _persisted_config_yaml()["provider"] is None


def test_update_workflow_rejects_unknown_provider_without_saving(monkeypatch):
    response, fake_mgr, request = _run_workflow_update(
        monkeypatch, _workflow_form(provider="bogus")
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/workflows"
    assert "Invalid provider 'bogus'" in request.session["flash_msg"]
    assert fake_mgr.saved_configs == {}
    assert fake_mgr.saved_skills == {}
    assert not (
        workspace_io.WORKSPACE_DIR / "workflows" / _AGENT_NAME / "config.yaml"
    ).exists()


def test_update_workflow_rejects_openai_compatible_without_base_url(monkeypatch):
    response, fake_mgr, request = _run_workflow_update(
        monkeypatch, _workflow_form(provider="openai-compatible", model="some-model")
    )

    assert response.status_code == 303
    assert "requires a base_url" in request.session["flash_msg"]
    assert fake_mgr.saved_configs == {}
    assert not (
        workspace_io.WORKSPACE_DIR / "workflows" / _AGENT_NAME / "config.yaml"
    ).exists()


def test_update_workflow_rejects_base_url_for_provider_that_does_not_support_it(monkeypatch):
    response, fake_mgr, request = _run_workflow_update(
        monkeypatch,
        _workflow_form(provider="deepseek", model="deepseek-chat", base_url="http://box:8000"),
    )

    assert response.status_code == 303
    assert "does not accept a base_url" in request.session["flash_msg"]
    assert fake_mgr.saved_configs == {}
    assert not (
        workspace_io.WORKSPACE_DIR / "workflows" / _AGENT_NAME / "config.yaml"
    ).exists()


def _render_workflows(agent_config, is_admin=True):
    workflow = {
        "name": _AGENT_NAME,
        "config": agent_config,
        "status": "active",
        "is_disabled": False,
        "description": agent_config.get("description", ""),
        "trigger": agent_config.get("trigger", {}),
        "is_configured": True,
        "required_secrets": [],
        "required_variables": [],
        "missing_secrets": [],
        "missing_variables": [],
        "current_variables": {},
        "secret_groups": [],
        "is_running": False,
        "run_stats": {"pending": 0, "processing": 0, "completed": 0, "failed": 0},
        "skills": "",
    }
    context = {
        "request": SimpleNamespace(
            url=SimpleNamespace(scheme="http", netloc="localhost:8000", path="/workflows")
        ),
        "user": {"name": "Test User", "sub": "test-user"},
        "is_admin": is_admin,
        "csrf_token": "test-csrf-token",
        "app_name": "Trellis",
        "app_accent_color": "#0055FF",
        "app_accent_color_dark": "#3377FF",
        "flash_msg": None,
        "workflows_list": [workflow],
        "all_agents": [_AGENT_NAME],
        "all_tools": [],
        "all_mcps": [],
        "queue": {"pending": [], "processing": [], "completed": [], "failed": []},
    }
    context.update(llm_providers_context(None))
    return templates.env.get_template("background_workflows.html").render(**context)


def test_workflows_modal_renders_provider_base_url_and_hidden_model_inputs():
    html = _render_workflows({
        "name": _AGENT_NAME,
        "type": "background_agent",
        "model": "deepseek-chat",
        "provider": "deepseek",
        "thinking_level": "none",
        "base_url": None,
        "version": "0.1.0",
        "description": "report",
        "allowed_tools": [],
        "a2a_access": [],
        "trigger": {},
    })

    assert 'name="provider"' in html
    assert 'name="base_url"' in html
    assert re.search(
        rf'<input type="hidden" name="model" id="modal-model-{_AGENT_NAME}"', html
    )
    # admin-only inline payload for the registry-driven model/provider JS
    assert "window.LLM_PROVIDERS" in html
    assert re.search(
        rf'<option value="deepseek"[^>]*>DeepSeek</option>', html
    )


def test_workflows_modal_keeps_thinking_level_posted_for_style_none_providers():
    """Providers with thinking_style 'none' (ollama/deepseek/…) disable the select, and a
    disabled control is not submitted -- the JS mirrors its value into a hidden input
    named thinking_level so the save POST still carries it."""
    html = _render_workflows({
        "name": _AGENT_NAME,
        "type": "background_agent",
        "model": "llama3.2",
        "provider": "ollama",
        "thinking_level": "none",
        "base_url": "http://box:11434",
        "version": "0.1.0",
        "description": "report",
        "allowed_tools": [],
        "a2a_access": [],
        "trigger": {},
    })

    assert re.search(r"<option value=\"ollama\"[^>]*data-style=\"none\"", html)
    assert "syncThinkingMirror" in html
    assert "mirror.name = 'thinking_level';" in html
    assert "if (style === 'none')" in html


def test_update_workflow_auto_provider_accepts_base_url_for_inferred_model(monkeypatch):
    """Auto + endpoint: validate against the provider the model implies."""
    response, fake_mgr, _ = _run_workflow_update(
        monkeypatch, _workflow_form(provider="", model="qwen2.5", base_url="http://box:11434")
    )

    assert response.status_code == 303
    saved = fake_mgr.saved_configs[_AGENT_NAME]
    assert saved["provider"] is None
    assert saved["base_url"] == "http://box:11434"
    assert _persisted_config_yaml()["base_url"] == "http://box:11434"


def test_update_workflow_auto_provider_rejects_uninferable_base_url(monkeypatch):
    response, fake_mgr, request = _run_workflow_update(
        monkeypatch, _workflow_form(provider="", model="some-model", base_url="http://box:11434")
    )

    assert response.status_code == 303
    assert "Cannot infer a provider" in request.session["flash_msg"]
    assert fake_mgr.saved_configs == {}


def test_workflows_modal_restores_saved_custom_model(monkeypatch):
    """The modal must prefill the custom input, else saving drops the model id."""
    from pathlib import Path as _Path
    source = (_Path(__file__).resolve().parents[1] / "templates" / "background_workflows.html").read_text()
    assert "customInput.value = saved;" in source
    assert "customInput.disabled = knownModel;" in source
