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
import json
import logging
import re
from types import SimpleNamespace

import pytest
import yaml
from starlette.datastructures import FormData

from core import host, hub, tasks, workspace_io
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


def test_workflows_modal_never_prefills_a_provider_default_endpoint():
    """A provider's registry default is a placeholder, never a value: pre-filling it would
    persist the endpoint on save and pin the workflow away from what it inherits."""
    html = _render_workflows({
        "name": _AGENT_NAME,
        "type": "background_agent",
        "model": None,
        "provider": "litellm",
        "thinking_level": "none",
        "base_url": None,
        "version": "0.1.0",
        "description": "report",
        "allowed_tools": [],
        "a2a_access": [],
        "trigger": {},
    })

    assert "modalAutoBaseUrls" not in html
    # The endpoint input is only ever given a placeholder, never a value.
    assert "input.value" not in html
    assert "input.placeholder = spec.base_url_placeholder || spec.default_base_url" in html


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

    payload_match = re.search(
        r"window\.LLM_PROVIDERS = (\[.*?\]);", html, re.DOTALL
    )
    assert payload_match, "window.LLM_PROVIDERS payload not found in background_workflows.html"
    payload = {p["id"]: p for p in json.loads(payload_match.group(1))}
    assert payload["ollama"]["thinking_style"] == "none"
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


# --- LLM defaults Phase 7 (A1): a background agent may be saved with a blank or
# absent model and then inherits the framework default at build time. ---


def test_agent_update_model_accepts_blank_and_absent_model():
    blank = workflows.AgentUpdateModel(model="", thinking_level="none")
    assert blank.model == ""

    absent = workflows.AgentUpdateModel(thinking_level="none")
    assert absent.model is None


def test_update_workflow_blank_model_persists_none_for_inheritance(monkeypatch):
    response, fake_mgr, _ = _run_workflow_update(monkeypatch, _workflow_form(model=""))

    assert response.status_code == 303
    assert fake_mgr.saved_configs[_AGENT_NAME]["model"] is None
    assert _persisted_config_yaml()["model"] is None


def test_update_workflow_whitespace_model_persists_none(monkeypatch):
    _run_workflow_update(monkeypatch, _workflow_form(model="   "))

    assert _persisted_config_yaml()["model"] is None


def test_update_workflow_stored_model_unchanged_when_resubmitted(monkeypatch):
    fake_mgr = FakeWorkflowsIdentityManager(
        configs={
            _AGENT_NAME: {
                "name": _AGENT_NAME,
                "type": "background_agent",
                "description": "report",
                "model": "deepseek-chat",
            }
        }
    )
    _, fake_mgr, _ = _run_workflow_update(
        monkeypatch,
        _workflow_form(provider="deepseek", model="deepseek-chat"),
        fake_mgr=fake_mgr,
    )

    assert fake_mgr.saved_configs[_AGENT_NAME]["model"] == "deepseek-chat"
    assert _persisted_config_yaml()["model"] == "deepseek-chat"


def test_update_workflow_blank_model_with_pinned_provider_is_preserved(monkeypatch):
    """Provider-only + inherit model: the provider is kept, the model persists as None."""
    response, fake_mgr, _ = _run_workflow_update(
        monkeypatch, _workflow_form(provider="google", model="")
    )

    assert response.status_code == 303
    saved = fake_mgr.saved_configs[_AGENT_NAME]
    assert saved["provider"] == "google"
    assert saved["model"] is None
    assert _persisted_config_yaml()["model"] is None


def test_workflows_modal_renders_inherit_model_option_and_hint():
    html = _render_workflows({
        "name": _AGENT_NAME,
        "type": "background_agent",
        "model": None,
        "provider": None,
        "thinking_level": "none",
        "base_url": None,
        "version": "0.1.0",
        "description": "report",
        "allowed_tools": [],
        "a2a_access": [],
        "trigger": {},
    })

    assert "Inherit framework default" in html
    assert "Leave blank to inherit the framework default model." in html


def test_workflows_modal_selects_inherit_for_a_blank_saved_model():
    """Source-level guard: a blank saved model must select the inherit option, not Custom."""
    from pathlib import Path as _Path
    source = (_Path(__file__).resolve().parents[1] / "templates" / "background_workflows.html").read_text()

    assert "inheritOption.value = '';" in source
    assert "if (!saved) {" in source
    assert "select.value = '';" in source


# --- background_script workflows execute in ONE runner container (v0.7.1 P6) --
#
# A script workflow used to be a plain subprocess of the taskiq worker: whole
# workspace mounted read-write, engine network reachable, worker environment
# inherited. It is now one `kind="workflow"` exec, and the worker's own job ends at
# "record the run, evaluate the guardrail, ask the runner". These tests pin the
# request the runner receives, the environment split and the failure surface.

WORKFLOW_NAME = "demo-inventory"
WORKFLOW_REL_PATH = "workspace/workflows/demo-inventory"
SCRIPT_TIMEOUT_S = 900.0


class FakeScriptIdentityManager:
    """Registry/runs/secrets fake for ``run_background_script`` (no etcd)."""

    def __init__(self, config, secrets=None, variables=None):
        self.config = config
        self.secrets = dict(secrets or {})
        self.variables = dict(variables or {})
        self.runs = {}
        self.events = []
        self.guardrail_hits = {}
        self.heartbeats = 0

    # -- registry --
    def get_agent_config(self, name):
        return self.config if name == WORKFLOW_NAME else None

    def get_disabled_workflows(self):
        return []

    def get_tool_config(self, name):
        return None

    def get_mcp_config(self, name):
        return None

    # -- run records / events --
    def get_agent_run(self, name, run_id):
        return self.runs.get(run_id)

    def record_agent_run_state(self, name, run_id, state, metadata):
        current = self.runs.get(run_id) or {"metadata": {}}
        if current.get("state") in ("completed", "failed", "cancelled"):
            return False
        self.runs[run_id] = {
            **current,
            "state": state,
            "metadata": {**current.get("metadata", {}), **metadata},
        }
        return True

    def append_run_event(self, name, run_id, event_type, payload=None):
        self.events.append((event_type, dict(payload or {})))
        return len(self.events)

    def record_run_heartbeat(self, name, run_id):
        self.heartbeats += 1

    def record_guardrail_hits(self, name, hits):
        self.guardrail_hits.update(hits)

    # -- scoped secrets/variables --
    def get_resolved_config(self, identity, category, keys=None):
        store = self.secrets if category == "secrets" else self.variables
        if not keys:
            return dict(store)
        return {key: value for key, value in store.items() if key in keys}


def _script_workflow(**extra):
    config = {
        "name": WORKFLOW_NAME,
        "type": "background_script",
        "runtime": "python",
        "rel_path": WORKFLOW_REL_PATH,
        "entrypoint": "pipeline.py",
    }
    config.update(extra)
    return config


def _patch_script_path(monkeypatch, mgr, runner, slot_wait=300.0, run_timeout=SCRIPT_TIMEOUT_S):
    """Wire the worker's script path onto a fake runner; refuse local subprocesses."""
    import core.discovery as discovery
    from core import auth, guardrails

    async def refuse_subprocess(*cmd, **kwargs):
        raise AssertionError("a background_script must never spawn a subprocess")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", refuse_subprocess)
    monkeypatch.setattr(tasks, "RunnerClient", lambda *args, **kwargs: runner)
    monkeypatch.setattr(tasks, "get_identity_manager", lambda: mgr)
    # The tool/MCP requirement lookups read this module's own binding.
    monkeypatch.setattr(discovery, "identity_mgr", mgr)
    monkeypatch.setattr(
        tasks,
        "resolve_tunable",
        lambda name: {
            "workflow_run_timeout": run_timeout,
            "workflow_slot_wait": slot_wait,
            "max_run_output_chars": 32768,
            "max_run_error_chars": 4096,
        }[name],
    )
    # Minting publishes the token to the contextvar the runner call reads.
    def fake_mint(agent_name, user_id, run_id=None, **kwargs):
        auth.agent_token_var.set(f"minted::{agent_name}::{run_id}")
        return f"minted::{agent_name}::{run_id}"

    monkeypatch.setattr(tasks, "mint_for_run", fake_mint)
    refreshed = {}

    def fake_refresh(token, **kwargs):
        refreshed["in"] = token
        return "refreshed-token"

    monkeypatch.setattr(tasks, "refresh", fake_refresh)
    # Framework-wide guardrail defaults come from the identity manager, not etcd.
    class _FrameworkRules:
        def get_guardrails_defaults(self):
            return {}

    monkeypatch.setattr(auth, "get_identity_manager", lambda: _FrameworkRules())
    guardrails.reset_framework_guardrails_cache()
    return SimpleNamespace(refreshed=refreshed)


def _run_script_workflow(mgr, prompt="<event_payload>run</event_payload>", run_id="run-script"):
    context = SimpleNamespace(message=SimpleNamespace(task_id=run_id))
    return asyncio.run(
        tasks.run_background_script.original_func(
            WORKFLOW_NAME, prompt, f"svc_agent_{WORKFLOW_NAME}", context,
        )
    )


def _runner_with(stdout="pipeline-ok\n", exit_code=0, stderr="", error=None):
    from fixtures.fake_runner import FakeRunnerClient

    return FakeRunnerClient(stdout=stdout, stderr=stderr, exit_code=exit_code, error=error)


def test_script_workflow_is_one_workflow_container(monkeypatch):
    """The exact request: one `kind="workflow"` exec, no subprocess anywhere."""
    mgr = FakeScriptIdentityManager(_script_workflow(
        allowed_tools=["text_stats"],
        network="none",
        limits={"memory_mb": 8192},
    ))
    runner = _runner_with()
    spies = _patch_script_path(monkeypatch, mgr, runner)

    result = _run_script_workflow(mgr, prompt="<event_payload>today</event_payload>")

    assert result == "pipeline-ok"
    assert len(runner.requests) == 1
    request = runner.requests[0]
    assert request.kind == "workflow"
    # `target` is the workflow NAME: the runner resolves workspace/workflows/<name>.
    assert request.target == WORKFLOW_NAME
    assert request.entrypoint == "pipeline.py"
    assert request.runtime == "python"
    assert request.args == []
    # `tools` is the workflow's allowlist: it decides both the mounted suites and
    # the token's scope.
    assert request.tools == ["text_stats"]
    assert request.network == "none"
    # Partial by design: unnamed knobs keep the workflow defaults.
    assert request.limits == {"memory_mb": 8192}
    # The prompt is the container's stdin (the runner writes the env preamble first).
    assert request.input == "<event_payload>today</event_payload>"
    assert request.deadline_ms == int(SCRIPT_TIMEOUT_S * 1000)
    # The run's token, refreshed at the boundary, is the only identity carrier.
    assert request.agent_token == "refreshed-token"
    assert spies.refreshed["in"] == f"minted::{WORKFLOW_NAME}::run-script"
    for field in ("agent", "user_id", "user_email", "run_id"):
        assert field not in request.model_dump(), field

    # The run is recorded exactly as before.
    assert mgr.runs["run-script"]["state"] == "completed"
    assert mgr.runs["run-script"]["metadata"]["output"] == "pipeline-ok"
    assert [event for event, _ in mgr.events] == ["run_started", "run_completed"]


def test_the_workflow_container_gets_the_workflow_name_for_its_reports(monkeypatch):
    """reports/<name>/ is mounted for the run; the name travels in the environment.

    A workflow container has no agent token, so the pipeline (and any tool it launches
    with its own environment) reads TRELLIS_AGENT_NAME to find ``reports/<name>``.
    """
    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = _runner_with()
    _patch_script_path(monkeypatch, mgr, runner)

    _run_script_workflow(mgr)

    assert runner.requests[0].env["TRELLIS_AGENT_NAME"] == WORKFLOW_NAME


def test_only_declared_secrets_and_variables_reach_the_container(monkeypatch):
    """Declared keys only: the worker's own environment is not inherited."""
    monkeypatch.setenv("SESSION_SECRET", "worker-session-secret")
    monkeypatch.setenv("WORKER_ONLY_SETTING", "worker-private-value")
    mgr = FakeScriptIdentityManager(
        _script_workflow(secrets=["REPORT_TOKEN"], variables=["REPORT_REGION"]),
        secrets={"REPORT_TOKEN": "declared-secret"},
        variables={"REPORT_REGION": "eu-west"},
    )
    runner = _runner_with()
    _patch_script_path(monkeypatch, mgr, runner)

    _run_script_workflow(mgr)

    env = runner.requests[0].env
    assert env["REPORT_TOKEN"] == "declared-secret"
    assert env["REPORT_REGION"] == "eu-west"
    # Neither an arbitrary worker variable nor a framework secret rides along.
    assert "WORKER_ONLY_SETTING" not in env
    assert "SESSION_SECRET" not in env
    # Identity/run id come from the token's claims in the runner, not from the body.
    for name in ("TRELLIS_USER_ID", "TRELLIS_USER_EMAIL", "TRELLIS_RUN_ID"):
        assert name not in env, name


def test_a_relative_entrypoint_is_normalized_for_the_runner(monkeypatch):
    """A config written as "./pipeline.py" still works: the runner wants a plain path."""
    mgr = FakeScriptIdentityManager(_script_workflow(entrypoint="./pipeline.py"))
    runner = _runner_with()
    _patch_script_path(monkeypatch, mgr, runner)

    _run_script_workflow(mgr)

    assert runner.requests[0].entrypoint == "pipeline.py"


def test_an_unknown_runtime_falls_back_to_running_the_entrypoint(monkeypatch):
    """v0.7 ran an unrecognized `runtime:` as a bare executable; keep that as `exec`."""
    mgr = FakeScriptIdentityManager(_script_workflow(runtime="ruby"))
    runner = _runner_with()
    _patch_script_path(monkeypatch, mgr, runner)

    _run_script_workflow(mgr)

    assert runner.requests[0].runtime == "exec"


def test_a_reserved_env_name_is_never_forwarded(monkeypatch):
    mgr = FakeScriptIdentityManager(
        _script_workflow(secrets=["PATH", "REPORT_TOKEN"]),
        secrets={"PATH": "/evil", "REPORT_TOKEN": "ok-value"},
    )
    runner = _runner_with()
    _patch_script_path(monkeypatch, mgr, runner)

    _run_script_workflow(mgr)

    env = runner.requests[0].env
    assert "PATH" not in env
    assert env["REPORT_TOKEN"] == "ok-value"


def test_every_reserved_control_plane_name_is_dropped_not_fatal(monkeypatch):
    """One reserved list, shared with the runner: the worker drops what it rejects.

    The worker used to filter seven names while the runner rejected thirteen, so a
    workflow declaring `SESSION_SECRET` synced, passed the worker, and then died at the
    runner -- one failed run at a time. Now the worker applies the runner's own set and
    the run proceeds without the reserved key (the v0.7 behaviour).
    """
    from core.execution.spec import RESTRICTED_ENV_VARS

    declared = sorted(RESTRICTED_ENV_VARS) + ["REPORT_TOKEN"]
    mgr = FakeScriptIdentityManager(
        _script_workflow(secrets=declared),
        secrets={name: f"value-of-{name}" for name in declared},
    )
    runner = _runner_with()
    _patch_script_path(monkeypatch, mgr, runner)

    _run_script_workflow(mgr)

    env = runner.requests[0].env
    assert sorted(set(env) & RESTRICTED_ENV_VARS) == []
    assert env["REPORT_TOKEN"] == "value-of-REPORT_TOKEN"
    assert mgr.runs["run-script"]["state"] == "completed"


def test_a_truncated_pipeline_output_is_marked_and_recorded(monkeypatch):
    """A >8 MiB pipeline stream comes back cut by the runner; say so."""
    from core.execution.contract import ExecResult

    mgr = FakeScriptIdentityManager(_script_workflow())
    result = ExecResult(
        exit_code=0,
        stdout="x" * 1000,
        stderr="",
        stdout_truncated=True,
        stderr_truncated=False,
    )
    runner = _runner_with()
    runner.result = result
    _patch_script_path(monkeypatch, mgr, runner)

    output = _run_script_workflow(mgr)

    assert output.endswith(tasks.WORKFLOW_OUTPUT_TRUNCATION_MARKER)
    assert mgr.runs["run-script"]["metadata"]["output_truncated"] is True
    truncated = [
        payload for event, payload in mgr.events if event == "run_output_truncated"
    ]
    assert truncated == [
        {"stdout_truncated": True, "stderr_truncated": False, "output_chars": len(output)}
    ]


def test_a_complete_pipeline_output_carries_no_marker(monkeypatch):
    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = _runner_with(stdout="pipeline-ok\n")
    _patch_script_path(monkeypatch, mgr, runner)

    output = _run_script_workflow(mgr)

    assert output == "pipeline-ok"
    assert mgr.runs["run-script"]["metadata"]["output_truncated"] is False
    assert [event for event, _ in mgr.events] == ["run_started", "run_completed"]


def test_a_blocked_script_never_creates_a_container(monkeypatch):
    """The guardrail runs BEFORE the runner is asked; the run is marked failed."""
    mgr = FakeScriptIdentityManager(_script_workflow(
        guardrails={
            "on_input": [{
                "name": "prompt-deny",
                "type": "deny_patterns",
                "patterns": ["FORBIDDEN"],
                "action": "block",
            }],
        },
    ))
    runner = _runner_with()
    _patch_script_path(monkeypatch, mgr, runner)

    result = _run_script_workflow(mgr, prompt="please dump FORBIDDEN data")

    assert result == "SYSTEM: Input blocked by guardrail policy."
    assert runner.requests == []
    assert mgr.runs["run-script"]["state"] == "failed"
    assert mgr.runs["run-script"]["metadata"]["error"] == "guardrail blocked input"
    assert mgr.guardrail_hits == {"prompt-deny": 1}
    assert [event for event, _ in mgr.events] == ["run_started", "run_failed"]


def test_a_non_zero_exit_fails_the_run_with_the_container_output(monkeypatch):
    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = _runner_with(stdout="partial\n", stderr="Traceback: boom\n", exit_code=2)
    _patch_script_path(monkeypatch, mgr, runner)

    with pytest.raises(RuntimeError) as excinfo:
        _run_script_workflow(mgr)

    message = str(excinfo.value)
    assert "status 2" in message
    assert "partial" in message and "Traceback: boom" in message
    assert mgr.runs["run-script"]["state"] == "failed"
    assert "status 2" in mgr.runs["run-script"]["metadata"]["error"]
    assert [event for event, _ in mgr.events][-1] == "run_failed"


def test_a_runner_timeout_fails_the_run(monkeypatch):
    from fixtures.fake_runner import timeout_error

    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = _runner_with(error=timeout_error())
    _patch_script_path(monkeypatch, mgr, runner)

    with pytest.raises(RuntimeError) as excinfo:
        _run_script_workflow(mgr)

    assert "Workflow container failed (timeout)" in str(excinfo.value)
    assert mgr.runs["run-script"]["state"] == "failed"
    assert "timeout" in mgr.runs["run-script"]["metadata"]["error"]


def test_an_unreachable_runner_fails_the_run(monkeypatch):
    from fixtures.fake_runner import unreachable

    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = _runner_with(error=unreachable())
    _patch_script_path(monkeypatch, mgr, runner)

    with pytest.raises(RuntimeError) as excinfo:
        _run_script_workflow(mgr)

    assert "Runner is unreachable" in str(excinfo.value)
    assert mgr.runs["run-script"]["state"] == "failed"
    assert "unreachable" in mgr.runs["run-script"]["metadata"]["error"]


def test_a_cancelled_run_stops_its_container(monkeypatch):
    """R3: the poller can now stop the container instead of waiting it out."""
    mgr = FakeScriptIdentityManager(_script_workflow())
    mgr.runs["run-script"] = {"state": "processing", "metadata": {}}
    runner = _runner_with(stdout="finished anyway\n")
    # Shorten the poller's interval through the module constant. Patching
    # ``asyncio.sleep`` here would slow-spin every other coroutine in the process
    # (event-loop stalls, and a whole-suite hang when another test awaits a real wait).
    monkeypatch.setattr(tasks, "CANCELLATION_POLL_INTERVAL_S", 0.01)
    real_sleep = asyncio.sleep

    async def exec_while_cancelled(request):
        # Cancelled while the container is running: the poller sees it and stops it.
        mgr.runs["run-script"]["state"] = "cancelled"
        for _ in range(10):
            # Real (tiny) waits: the poller's heartbeat and run read go through
            # asyncio.to_thread, which needs a moment to actually run.
            await real_sleep(0.02)
        return runner.result

    runner.exec = exec_while_cancelled
    _patch_script_path(monkeypatch, mgr, runner)

    result = _run_script_workflow(mgr)

    assert result == "Cancelled."
    # The stop names the run id the container is labelled with (the taskiq task id).
    assert runner.stops == ["run-script"]
    cancelled = [payload for event, payload in mgr.events if event == "run_cancelled"]
    assert cancelled == [
        {
            "reason": "cancelled_mid_run",
            "container_stopped": True,
            "containers_stopped": 1,
        }
    ]
    # A cancelled run is never re-marked completed.
    assert [event for event, _ in mgr.events if event == "run_completed"] == []
    assert mgr.runs["run-script"]["state"] == "cancelled"


def test_a_cancelled_run_whose_stop_fails_says_so_and_still_ends_cancelled(monkeypatch):
    """A stop failure is recorded against the run; it never becomes the run's error."""
    from fixtures.fake_runner import FakeRunnerClient, unreachable

    mgr = FakeScriptIdentityManager(_script_workflow())
    mgr.runs["run-script"] = {"state": "processing", "metadata": {}}
    runner = FakeRunnerClient(stop_error=unreachable())
    monkeypatch.setattr(tasks, "CANCELLATION_POLL_INTERVAL_S", 0.01)
    real_sleep = asyncio.sleep

    async def exec_while_cancelled(request):
        mgr.runs["run-script"]["state"] = "cancelled"
        for _ in range(10):
            await real_sleep(0.02)
        return runner.result

    runner.exec = exec_while_cancelled
    _patch_script_path(monkeypatch, mgr, runner)

    result = _run_script_workflow(mgr)

    assert result == "Cancelled."
    assert runner.stops == ["run-script"]
    cancelled = [payload for event, payload in mgr.events if event == "run_cancelled"]
    assert len(cancelled) == 1
    assert cancelled[0]["reason"] == "cancelled_mid_run"
    assert cancelled[0]["container_stopped"] is False
    assert "unreachable" in cancelled[0]["stop_error"]
    assert mgr.runs["run-script"]["state"] == "cancelled"


def test_a_run_that_already_ended_reports_nothing_stopped_with_a_reason(monkeypatch):
    """`stopped == 0` is success for the caller, but the event must not claim a stop.

    Nothing was left running, so there is nothing to stop -- and the record says so
    (``container_stopped: false`` plus the reason) instead of reading like a failure
    with no explanation.
    """
    from core.execution.contract import StopResult
    from fixtures.fake_runner import FakeRunnerClient

    mgr = FakeScriptIdentityManager(_script_workflow())
    mgr.runs["run-script"] = {"state": "processing", "metadata": {}}
    runner = FakeRunnerClient(stop_result=StopResult(run_id="run-script", stopped=0))
    monkeypatch.setattr(tasks, "CANCELLATION_POLL_INTERVAL_S", 0.01)
    real_sleep = asyncio.sleep

    async def exec_while_cancelled(request):
        mgr.runs["run-script"]["state"] = "cancelled"
        for _ in range(10):
            await real_sleep(0.02)
        return runner.result

    runner.exec = exec_while_cancelled
    _patch_script_path(monkeypatch, mgr, runner)

    assert _run_script_workflow(mgr) == "Cancelled."
    cancelled = [payload for event, payload in mgr.events if event == "run_cancelled"]
    assert cancelled[0]["container_stopped"] is False
    assert cancelled[0]["containers_stopped"] == 0
    assert "already exited" in cancelled[0]["stop_detail"]



def test_a_cancel_whose_exec_returns_first_still_records_the_stop(monkeypatch):
    """The container exiting is what makes ``exec`` return, so the poller's stop is
    still in flight when the worker resumes. Its outcome must not be discarded.

    Regression for the R3 blocker: the teardown used to cancel the monitor inside
    ``stop_run``, leaving the run event at ``container_stopped: false`` with no reason
    even though the container had just been stopped.
    """
    from fixtures.fake_runner import FakeRunnerClient

    mgr = FakeScriptIdentityManager(_script_workflow())
    mgr.runs["run-script"] = {"state": "processing", "metadata": {}}
    runner = FakeRunnerClient()
    monkeypatch.setattr(tasks, "CANCELLATION_POLL_INTERVAL_S", 0.01)
    real_sleep = asyncio.sleep

    async def exec_while_cancelled(request):
        mgr.runs["run-script"]["state"] = "cancelled"
        # Long enough for the poller to notice and enter stop_run, short enough that
        # the exec returns while the stop is still sleeping.
        await real_sleep(0.05)
        return runner.result

    async def slow_stop(run_id):
        runner.stops.append(run_id)
        await real_sleep(0.15)
        return runner.stop_result or __import__(
            "core.execution.contract", fromlist=["StopResult"]
        ).StopResult(run_id=run_id, stopped=1)

    runner.exec = exec_while_cancelled
    runner.stop_run = slow_stop
    _patch_script_path(monkeypatch, mgr, runner)

    assert _run_script_workflow(mgr) == "Cancelled."
    cancelled = [payload for event, payload in mgr.events if event == "run_cancelled"]
    assert cancelled[0]["container_stopped"] is True
    assert cancelled[0]["containers_stopped"] == 1
    assert "stop_detail" not in cancelled[0]


def test_a_cancel_while_queued_is_not_recorded_as_a_mid_run_cancel(monkeypatch):
    """A run cancelled before it ever got a slot says so; nothing was stopped."""
    from fixtures.fake_runner import FakeRunnerClient

    from core.execution.contract import StopResult

    mgr = FakeScriptIdentityManager(_script_workflow())
    mgr.runs["run-script"] = {"state": "processing", "metadata": {}}
    # Nothing was created yet, so the stop finds nothing -- the poller may still call
    # it, and that call is harmless by design.
    runner = FakeRunnerClient(
        capacity_until_call=1000, stop_result=StopResult(run_id="run-script", stopped=0)
    )
    monkeypatch.setattr(tasks, "CANCELLATION_POLL_INTERVAL_S", 0.01)
    _patch_slot_waits(monkeypatch, lambda seconds: _mark_cancelled(mgr, seconds))
    _patch_script_path(monkeypatch, mgr, runner, slot_wait=60.0)

    assert _run_script_workflow(mgr) == "Cancelled."
    cancelled = [payload for event, payload in mgr.events if event == "run_cancelled"]
    assert cancelled[0]["reason"] == "cancelled_while_waiting"
    assert cancelled[0]["container_stopped"] is False
    # The poller still asks the runner to stop (it cannot know whether a container
    # appeared in the last instant); nothing was there, so nothing was stopped.
    assert runner.stops == ["run-script"]
    assert cancelled[0]["containers_stopped"] == 0
    # No container was ever asked for after the cancel.
    assert len(runner.requests) == 1


def _mark_cancelled(mgr, _seconds):
    mgr.runs["run-script"]["state"] = "cancelled"


def _patch_slot_waits(monkeypatch, sleeper):
    async def fake_sleep(seconds):
        sleeper(seconds)
        # Real (short) sleep so the cancellation poller gets scheduled and its
        # thread-pooled run-record read actually completes during the wait.
        await asyncio.sleep(0.02)

    monkeypatch.setattr(tasks, "_slot_wait_sleep", fake_sleep)


def test_a_worker_deadline_stops_the_container_before_failing(monkeypatch):
    """R3: the runner's own deadline is minutes away -- end the container now."""
    from fixtures.fake_runner import timeout_error

    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = _runner_with(error=timeout_error())
    _patch_script_path(monkeypatch, mgr, runner)

    with pytest.raises(RuntimeError) as excinfo:
        _run_script_workflow(mgr)

    assert "Workflow container failed (timeout)" in str(excinfo.value)
    assert runner.stops == ["run-script"]
    stopped = [
        payload for event, payload in mgr.events if event == "run_container_stopped"
    ]
    assert stopped == [
        {
            "reason": "deadline_exceeded",
            "container_stopped": True,
            "containers_stopped": 1,
        }
    ]
    # The run itself still fails with the timeout, which stays the visible reason.
    assert mgr.runs["run-script"]["state"] == "failed"
    assert "timeout" in mgr.runs["run-script"]["metadata"]["error"]


def test_a_deadline_stop_failure_does_not_mask_the_timeout(monkeypatch):
    from fixtures.fake_runner import FakeRunnerClient, timeout_error, unreachable

    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = FakeRunnerClient(error=timeout_error(), stop_error=unreachable())
    _patch_script_path(monkeypatch, mgr, runner)

    with pytest.raises(RuntimeError) as excinfo:
        _run_script_workflow(mgr)

    assert "Workflow container failed (timeout)" in str(excinfo.value)
    stopped = [
        payload for event, payload in mgr.events if event == "run_container_stopped"
    ]
    assert stopped[0]["container_stopped"] is False
    assert "unreachable" in stopped[0]["stop_error"]
    assert "timeout" in mgr.runs["run-script"]["metadata"]["error"]


# --- runner capacity: a saturated pool is a wait, not a failure (v0.7.2 R4) ---


def _record_slot_waits(monkeypatch) -> list[float]:
    """Drive the retry loop without real time; returns the sleeps it asked for."""
    waits: list[float] = []

    async def record(seconds: float) -> None:
        waits.append(seconds)

    monkeypatch.setattr(tasks, "_slot_wait_sleep", record)
    return waits


def test_a_saturated_runner_pool_is_waited_out(monkeypatch):
    from fixtures.fake_runner import FakeRunnerClient

    monkeypatch.setattr(tasks, "SLOT_WAIT_JITTER", 0.0)
    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = FakeRunnerClient(stdout="pipeline-ok\n", capacity_until_call=2)
    waits = _record_slot_waits(monkeypatch)
    _patch_script_path(monkeypatch, mgr, runner)

    result = _run_script_workflow(mgr)

    assert result == "pipeline-ok"
    # Two 429s, then the run; every attempt carries the same run.
    assert len(runner.requests) == 3
    assert waits == [tasks.SLOT_WAIT_INITIAL_S, tasks.SLOT_WAIT_INITIAL_S * 2]
    events = [event for event, _ in mgr.events]
    assert events == ["run_started", "run_waiting", "run_slot_acquired", "run_completed"]

    waiting = [payload for event, payload in mgr.events if event == "run_waiting"][0]
    assert waiting["workflow"] == WORKFLOW_NAME
    assert waiting["reason"] == "capacity_exhausted"
    # The runner's own limits travel with the event; no secret is in it.
    assert "per-target limit" in waiting["detail"]
    assert waiting["slot_wait_s"] == 300.0

    acquired = [payload for event, payload in mgr.events if event == "run_slot_acquired"][0]
    assert acquired["waited_s"] == round(sum(waits), 1)
    assert mgr.runs["run-script"]["state"] == "completed"


def test_no_slot_within_the_window_fails_with_runner_capacity(monkeypatch):
    from fixtures.fake_runner import FakeRunnerClient

    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = FakeRunnerClient(capacity_until_call=1000)
    waits = _record_slot_waits(monkeypatch)
    _patch_script_path(monkeypatch, mgr, runner, slot_wait=0.05)

    with pytest.raises(RuntimeError) as excinfo:
        _run_script_workflow(mgr)

    message = str(excinfo.value)
    assert "runner_capacity" in message
    assert f"{sum(waits):.1f}s" in message
    assert "WORKFLOW_SLOT_WAIT_S" in message
    # The wait is bounded by the window, not by the number of attempts.
    assert sum(waits) <= 0.05
    assert [event for event, _ in mgr.events][:2] == ["run_started", "run_waiting"]
    assert [event for event, _ in mgr.events][-1] == "run_failed"
    assert "runner_capacity" in mgr.runs["run-script"]["metadata"]["error"]


def test_a_zero_window_fails_the_first_saturation_immediately(monkeypatch):
    """`WORKFLOW_SLOT_WAIT_S=0` keeps the pre-v0.7.2 behaviour (fail on the 429)."""
    from fixtures.fake_runner import FakeRunnerClient

    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = FakeRunnerClient(capacity_until_call=1000)
    waits = _record_slot_waits(monkeypatch)
    _patch_script_path(monkeypatch, mgr, runner, slot_wait=0.0)

    with pytest.raises(RuntimeError) as excinfo:
        _run_script_workflow(mgr)

    # The 429 is re-raised untouched: no wait, no event, the same error the worker
    # produced before the slot wait existed.
    assert "capacity_exhausted" in str(excinfo.value)
    assert "runner_capacity" not in str(excinfo.value)
    assert waits == []


def test_the_wait_eats_into_the_run_timeout(monkeypatch):
    """Every waited second is taken off the deadline the runner is given."""
    from fixtures.fake_runner import FakeRunnerClient

    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = FakeRunnerClient(stdout="ok\n", capacity_until_call=2)
    waits = _record_slot_waits(monkeypatch)
    _patch_script_path(monkeypatch, mgr, runner)

    _run_script_workflow(mgr)

    first, second, third = (request.deadline_ms for request in runner.requests)
    assert first == int(SCRIPT_TIMEOUT_S * 1000)
    assert second == first - int(waits[0] * 1000)
    assert third == first - int((waits[0] + waits[1]) * 1000)
    # Strictly shrinking is what makes the wait cost runtime, not add it.
    assert third < second < first


def test_the_slot_wait_backoff_is_capped(monkeypatch):
    """Backoff doubles to a ceiling and stops there: no unbounded growth."""
    from fixtures.fake_runner import FakeRunnerClient

    monkeypatch.setattr(tasks, "SLOT_WAIT_JITTER", 0.0)
    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = FakeRunnerClient(stdout="ok\n", capacity_until_call=10)
    waits = _record_slot_waits(monkeypatch)
    _patch_script_path(monkeypatch, mgr, runner, slot_wait=10_000.0)

    _run_script_workflow(mgr)

    assert waits == [
        tasks.SLOT_WAIT_INITIAL_S,
        2.0,
        4.0,
        8.0,
        16.0,
        tasks.SLOT_WAIT_MAX_S,
        tasks.SLOT_WAIT_MAX_S,
        tasks.SLOT_WAIT_MAX_S,
        tasks.SLOT_WAIT_MAX_S,
        tasks.SLOT_WAIT_MAX_S,
    ]
    assert max(waits) == tasks.SLOT_WAIT_MAX_S


def test_the_slot_wait_never_outlives_the_run_timeout(monkeypatch):
    """The run's own deadline can be the earlier ceiling: waiting cannot extend a run."""
    from fixtures.fake_runner import FakeRunnerClient

    # Jitter off: the retry steps are then deterministic, and this test is about the
    # deadline ceiling, not the shape of the backoff.
    monkeypatch.setattr(tasks, "SLOT_WAIT_JITTER", 0.0)
    mgr = FakeScriptIdentityManager(_script_workflow())
    runner = FakeRunnerClient(capacity_until_call=1000)
    waits = _record_slot_waits(monkeypatch)
    _patch_script_path(monkeypatch, mgr, runner, slot_wait=10_000.0, run_timeout=100.0)

    with pytest.raises(RuntimeError) as excinfo:
        _run_script_workflow(mgr)

    assert "runner_capacity" in str(excinfo.value)
    # It waited the whole run timeout and not a second of the larger slot window. (The
    # loop stops once less than SLOT_WAIT_MIN_DEADLINE_S would be left, so the ceiling
    # is a band, never a value above the deadline.)
    assert 100.0 - tasks.SLOT_WAIT_MIN_DEADLINE_S <= sum(waits) <= 100.0
    # The message names the budget that ran out, not just the window.
    assert "of the run's 100s deadline" in str(excinfo.value)


def test_a_run_cancelled_while_queued_never_starts_a_container(monkeypatch):
    """R3 + R4: waiting for a slot must not outlive the cancellation either."""
    from fixtures.fake_runner import FakeRunnerClient

    mgr = FakeScriptIdentityManager(_script_workflow())
    mgr.runs["run-script"] = {"state": "processing", "metadata": {}}
    runner = FakeRunnerClient(capacity_until_call=1000)
    monkeypatch.setattr(tasks, "SLOT_WAIT_JITTER", 0.0)
    monkeypatch.setattr(tasks, "CANCELLATION_POLL_INTERVAL_S", 0.01)
    real_sleep = asyncio.sleep
    waits: list[float] = []

    async def sleep_and_cancel(seconds: float) -> None:
        # The wait itself is where the cancel lands: the poller reads the record
        # while the worker is between attempts.
        waits.append(seconds)
        mgr.runs["run-script"]["state"] = "cancelled"
        for _ in range(5):
            await real_sleep(0.02)

    monkeypatch.setattr(tasks, "_slot_wait_sleep", sleep_and_cancel)
    _patch_script_path(monkeypatch, mgr, runner)

    result = _run_script_workflow(mgr)

    assert result == "Cancelled."
    # Queued, never ran: the 429 that got us here is the only exec attempt.
    assert len(runner.requests) == 1
    assert runner.stops == ["run-script"]
    assert [event for event, _ in mgr.events] == ["run_started", "run_waiting", "run_cancelled"]
    assert mgr.runs["run-script"]["state"] == "cancelled"
