# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for Phase 5 (Dashboard Catalog UI & Conditional Connection Modal) — see
__spec_docs/internal_external_agents_spec.md.

Renders the real templates/agents.html Jinja2 template (via the app's configured
Jinja2Templates environment, matching the pattern in tests/test_admin_agent_visibility.py)
against synthetic agent payloads with varied `external`/`internal` flags, and asserts:
  - The `INTERNAL ONLY` badge renders for `external: False` agents, and the `EXTERNAL`
    badge renders for `external: True` (or omitted) agents.
  - The connection modal's OpenAI API / MCP `use_agent` snippets are replaced by an
    advisory notice for `external: False` agents, and retained for `external: True`.
  - The A2A section renders the `a2a_access` snippet with the internal-only callout
    text for `external: False, internal: True` agents, the default caller-instructions
    text for `external: True, internal: True` agents, and — for any agent with
    `internal: False` (regardless of `external`) — a blocked-delegation advisory in
    place of the snippet, since such agents are silently skipped by the A2A loop.
"""
import json
import re

from core.dependencies import llm_providers_context, templates
from core.llm_defaults import FrameworkDefaults
from core.llm_providers import provider_ui_specs
from core.routers.admin import _inherit_hint, _provider_label


class _FakeURL:
    path = "/agents"


class _FakeRequest:
    url = _FakeURL()


def _base_agent(name, **overrides):
    agent = {
        "name": name,
        "version": "0.1.0",
        "author": "test-author",
        "description": "A test agent.",
        "is_disabled": False,
        "is_configured": True,
        "required_secrets": [],
        "required_variables": [],
        "secret_groups": [],
        "missing_secrets": [],
        "missing_variables": [],
        "health": {"status": "Online"},
    }
    agent.update(overrides)
    return agent


def _render(agents, is_admin=False):
    context = {
        "request": _FakeRequest(),
        "user": {"name": "Test User", "sub": "test-user"},
        "agents": agents,
        "flash_msg": None,
        "public_host_url": "http://localhost:8000",
        "public_mcp_url": "http://localhost:8002/mcp",
        "is_admin": is_admin,
        "csrf_token": "test-csrf-token",
        "app_name": "Trellis",
        "app_accent_color": "#0055FF",
        "app_accent_color_dark": "#3377FF",
    }
    return templates.env.get_template("agents.html").render(**context)


def _connect_modal_block(html, agent_name):
    marker = f'id="connect-{agent_name}"'
    start = html.index(marker)
    next_marker_pos = html.find('id="connect-', start + len(marker))
    end = next_marker_pos if next_marker_pos != -1 else html.index("<script>", start)
    return html[start:end]


def _card_block(html, agent_name):
    marker = f'data-agent-name="{agent_name}"'
    start = html.index(marker)
    end = html.index(f'id="connect-{agent_name}"', start)
    return html[start:end]


def _configure_modal_block(html, agent_name):
    marker = f'id="configure-{agent_name}"'
    start = html.index(marker)
    end = html.index(f'id="connect-{agent_name}"', start)
    return html[start:end]


def test_internal_only_badge_rendered_for_external_false():
    agents = [_base_agent("internal-worker", external=False, internal=True)]
    html = _render(agents)
    card = _card_block(html, "internal-worker")

    assert "INTERNAL ONLY" in card
    assert "EXTERNAL" not in card


def test_external_badge_rendered_when_external_true():
    agents = [_base_agent("general-agent", external=True, internal=True)]
    html = _render(agents)
    card = _card_block(html, "general-agent")

    assert "EXTERNAL" in card
    assert "INTERNAL ONLY" not in card


def test_external_badge_rendered_when_external_omitted():
    agents = [_base_agent("legacy-agent")]
    html = _render(agents)
    card = _card_block(html, "legacy-agent")

    assert "EXTERNAL" in card
    assert "INTERNAL ONLY" not in card


def test_curl_snippet_replaced_by_advisory_when_external_false():
    agents = [_base_agent("internal-worker", external=False, internal=True)]
    html = _render(agents)
    modal = _connect_modal_block(html, "internal-worker")

    assert "curl -X POST" not in modal
    assert "Direct API invocation disabled" in modal
    assert "internal-only" in modal
    assert "use_agent(agent_name=" not in modal
    assert "Gateway invocation disabled" in modal


def test_curl_snippet_present_when_external_true():
    agents = [_base_agent("general-agent", external=True, internal=True)]
    html = _render(agents)
    modal = _connect_modal_block(html, "general-agent")

    assert "curl -X POST" in modal
    assert "Direct API invocation disabled" not in modal
    assert 'use_agent(agent_name="general-agent"' in modal
    assert "Gateway invocation disabled" not in modal


def test_a2a_section_always_present_with_internal_callout_when_external_false():
    agents = [_base_agent("internal-worker", external=False, internal=True)]
    html = _render(agents)
    modal = _connect_modal_block(html, "internal-worker")

    assert 'a2a_access:\n  - "internal-worker"' in modal
    assert "designed to be invoked by other specialized agents" in modal


def test_a2a_section_present_without_internal_callout_when_external_true():
    agents = [_base_agent("general-agent", external=True, internal=True)]
    html = _render(agents)
    modal = _connect_modal_block(html, "general-agent")

    assert 'a2a_access:\n  - "general-agent"' in modal
    assert "designed to be invoked by other specialized agents" not in modal


def test_a2a_blocked_advisory_when_internal_false_external_true():
    agents = [_base_agent("entrypoint-agent", external=True, internal=False)]
    html = _render(agents)
    modal = _connect_modal_block(html, "entrypoint-agent")

    assert "cannot be invoked via" in modal
    assert "internal: false" in modal
    assert "To call this agent from another agent, add it to the caller's" not in modal
    assert 'a2a_access:\n  - "entrypoint-agent"' not in modal


def test_a2a_blocked_advisory_when_internal_false_external_false():
    agents = [_base_agent("private-agent", external=False, internal=False)]
    html = _render(agents)
    modal = _connect_modal_block(html, "private-agent")

    assert "cannot be invoked via" in modal
    assert "internal: false" in modal
    assert "To call this agent from another agent, add it to the caller's" not in modal
    assert "designed to be invoked by other specialized agents" not in modal
    assert 'a2a_access:\n  - "private-agent"' not in modal


def test_configure_button_highlighted_when_unconfigured_via_secret_groups_only():
    """Regression for a Phase C follow-up finding (rules_engine_hardening_plan.md §2C):
    an agent can now be is_configured=False purely because of an unsatisfied
    secret_groups option, with empty required_secrets/required_variables -- the
    Configure Agent button's orange highlight condition must account for that case too,
    not just the plain required_secrets/required_variables case."""
    agent = _base_agent(
        "example-agent",
        is_configured=False,
        required_secrets=[],
        required_variables=[],
        secret_groups=[{"label": "Environment", "select_label": "Option", "options": []}],
    )
    html = _render([agent])
    card = _card_block(html, "example-agent")

    assert "border-orange-500" in card


def test_multi_agent_render_scopes_badges_and_modals_independently():
    agents = [
        _base_agent("internal-worker", external=False, internal=True),
        _base_agent("general-agent", external=True, internal=True),
    ]
    html = _render(agents)

    internal_card = _card_block(html, "internal-worker")
    general_card = _card_block(html, "general-agent")
    assert "INTERNAL ONLY" in internal_card and "EXTERNAL" not in internal_card
    assert "EXTERNAL" in general_card and "INTERNAL ONLY" not in general_card

    internal_modal = _connect_modal_block(html, "internal-worker")
    general_modal = _connect_modal_block(html, "general-agent")
    assert "Direct API invocation disabled" in internal_modal
    assert "curl -X POST" not in internal_modal
    assert "Direct API invocation disabled" not in general_modal
    assert "curl -X POST" in general_modal


# --- Health status badges (Offline / Degraded / Half-Open) ------------------
#
# core/routers/marketplace.py's agents() route now decorates agent["health"]["status"]
# via core.health.compute_agent_operational_status (shared with core/host.py and
# core/gateway.py), which can return "Degraded" in addition to the pre-existing
# Offline/Half-Open/Online values -- see rules_engine_hardening_plan.md's review
# finding that the marketplace UI never surfaced Degraded, and its own prior note
# that Half-Open had no explicit on-page label at all (just the absence of the
# red Offline badge). "Half-Open" is intentionally relabeled "RECOVERING" here --
# the raw circuit-breaker term isn't meaningful to a non-admin end user.

def test_offline_badge_still_renders_as_error():
    agents = [_base_agent("broken-agent", health={"status": "Offline", "consecutive_failures": 12})]
    html = _render(agents)
    card = _card_block(html, "broken-agent")

    assert "ERROR" in card
    assert "DEGRADED" not in card
    assert "RECOVERING" not in card


def test_degraded_badge_renders_with_offline_tool_names():
    agents = [_base_agent("tool-dependent-agent", health={"status": "Degraded"}, offline_tools=["netctl"])]
    html = _render(agents)
    card = _card_block(html, "tool-dependent-agent")

    assert "DEGRADED" in card
    assert "netctl" in card
    assert "ERROR" not in card


def test_half_open_status_renders_as_recovering_not_raw_label():
    agents = [_base_agent("recovered-agent", health={"status": "Half-Open"})]
    html = _render(agents)
    card = _card_block(html, "recovered-agent")

    assert "RECOVERING" in card
    assert "Half-Open" not in card
    assert "Half Open" not in card
    assert "ERROR" not in card
    assert "DEGRADED" not in card


def test_online_agent_shows_no_health_badge():
    agents = [_base_agent("healthy-agent", health={"status": "Online"})]
    html = _render(agents)
    card = _card_block(html, "healthy-agent")

    assert "ERROR" not in card
    assert "DEGRADED" not in card
    assert "RECOVERING" not in card


def test_degraded_badge_uses_distinct_color_from_unconfigured_badge():
    """The DEGRADED badge and the pre-existing orange UNCONFIGURED badge render in the
    same row -- they must be visually distinguishable by more than reading the text,
    so DEGRADED deliberately uses violet, not amber (too close to orange)."""
    agents = [_base_agent(
        "needs-work-agent",
        is_configured=False,
        required_secrets=["API_KEY"],
        missing_secrets=["API_KEY"],
        health={"status": "Degraded"},
        offline_tools=["netctl"],
    )]
    html = _render(agents)
    card = _card_block(html, "needs-work-agent")

    assert "UNCONFIGURED" in card
    assert "DEGRADED" in card
    assert "border-orange-500" in card
    assert "bg-violet-100" in card
    assert "bg-amber-100" not in card


# --- Admin "Health Issues" panel (status-aware) ------------------------------
#
# The panel used to be one-size-fits-all ("Health Issues (Failures: N)") regardless
# of status. For a Degraded agent, N is the AGENT's own failure count, which is
# typically 0 -- the actual problem is a dependent TOOL being offline, which the old
# panel never mentioned at all. It's now split by status: Degraded shows which
# tool(s) are offline with a per-tool reset action; Half-Open ("Recovering") gets its
# own framing; Offline keeps the original agent-level failures/reset behavior.

def test_admin_panel_shows_offline_tools_and_reset_for_degraded():
    agents = [_base_agent(
        "tool-dependent-agent",
        health={"status": "Degraded", "consecutive_failures": 0},
        offline_tools=["netctl", "logs"],
    )]
    html = _render(agents, is_admin=True)
    modal = _configure_modal_block(html, "tool-dependent-agent")

    assert "Dependent Tool(s) Offline" in modal
    assert "netctl" in modal
    assert "logs" in modal
    assert '/reset-health/tool/netctl' in modal
    assert '/reset-health/tool/logs' in modal
    assert "Health Issues (Failures:" not in modal


def test_admin_panel_shows_recovering_framing_for_half_open():
    agents = [_base_agent(
        "recovered-agent",
        health={"status": "Half-Open", "consecutive_failures": 12, "last_error": "connection reset"},
    )]
    html = _render(agents, is_admin=True)
    modal = _configure_modal_block(html, "recovered-agent")

    assert "Recovering" in modal
    assert "connection reset" in modal
    assert '/reset-health/agent/recovered-agent' in modal
    assert "Dependent Tool(s) Offline" not in modal


def test_admin_panel_keeps_original_offline_behavior():
    agents = [_base_agent(
        "broken-agent",
        health={"status": "Offline", "consecutive_failures": 7, "last_error": "timeout"},
    )]
    html = _render(agents, is_admin=True)
    modal = _configure_modal_block(html, "broken-agent")

    assert "Health Issues (Failures: 7)" in modal
    assert "timeout" in modal
    assert '/reset-health/agent/broken-agent' in modal
    assert "Dependent Tool(s) Offline" not in modal
    assert "Recovering" not in modal


def test_admin_panel_hidden_for_online_agent():
    agents = [_base_agent("healthy-agent", health={"status": "Online"})]
    html = _render(agents, is_admin=True)
    modal = _configure_modal_block(html, "healthy-agent")

    assert "Health Issues" not in modal
    assert "Dependent Tool(s) Offline" not in modal
    assert "Recovering" not in modal


def test_admin_panel_not_shown_to_non_admin():
    agents = [_base_agent(
        "tool-dependent-agent",
        health={"status": "Degraded"},
        offline_tools=["netctl"],
        required_secrets=["API_KEY"],
    )]
    html = _render(agents, is_admin=False)
    modal = _configure_modal_block(html, "tool-dependent-agent")

    assert "Dependent Tool(s) Offline" not in modal


# --- Editor: registry-driven provider select (llm-provider-expansion §11.8) ---

def _editor_config(name="deepseek-agent", **overrides):
    config = {
        "name": name,
        "version": "0.1.0",
        "description": "A test agent.",
        "model": "deepseek-chat",
        "provider": "deepseek",
        "thinking_level": "none",
        "base_url": None,
        "a2a_access": [],
    }
    config.update(overrides)
    return config


def _render_editor(config, default_llm=None):
    default_llm_provider_label = _provider_label(default_llm.provider) if (default_llm and default_llm.provider) else None
    inherit_hint = _inherit_hint(
        config.get("provider"),
        config.get("model"),
        config.get("base_url"),
        default_llm,
        default_llm_provider_label,
    )
    context = {
        "request": _FakeRequest(),
        "user": {"name": "Test User", "sub": "test-user"},
        "type": "agent",
        "name": config["name"],
        "config": config,
        "skills_content": "",
        "all_agents": [config["name"]],
        "internal_agents": {config["name"]: True},
        "a2a_dependents": [],
        "all_tools": [],
        "all_mcps": [],
        "flash_msg": None,
        "is_admin": False,
        "csrf_token": "test-csrf-token",
        "app_name": "Trellis",
        "app_accent_color": "#0055FF",
        "app_accent_color_dark": "#3377FF",
        "inherit_hint": inherit_hint,
    }
    context.update(llm_providers_context(None))
    return templates.env.get_template("editor.html").render(**context)


def test_editor_renders_registry_provider_labels_and_llm_providers_payload():
    html = _render_editor(_editor_config(provider="deepseek", model="deepseek-chat"))

    # Server-rendered <option>s carry the registry label, not the raw id.
    assert re.search(r'<option value="deepseek"[^>]*>DeepSeek</option>', html)
    assert re.search(r'<option value="openrouter"[^>]*>OpenRouter</option>', html)
    # The saved provider is preselected.
    assert re.search(r'<option value="deepseek"\s+selected', html)

    # The inline payload the editor JS consumes parses as JSON with every provider.
    payload_match = re.search(
        r"window\.LLM_PROVIDERS = (\[.*\]);</script>", html, re.DOTALL
    )
    assert payload_match, "window.LLM_PROVIDERS payload not found in editor.html"

    providers = json.loads(payload_match.group(1))
    assert len(providers) == 15
    ids = {p["id"] for p in providers}
    assert {"deepseek", "openrouter", "google", "openai-compatible"} <= ids
    assert all("label" in p for p in providers)


# --- Editor: framework default inherit hint (llm-defaults §9, D10) -------------

def test_editor_shows_inherit_hint_when_unset_and_framework_default_present():
    config = _editor_config(provider=None, model=None)
    html = _render_editor(config, default_llm=FrameworkDefaults("deepseek", "deepseek-chat", None))

    assert 'id="inheritDefaultHint"' in html
    assert "Inherits framework default: DeepSeek / deepseek-chat" in html


def test_editor_hides_inherit_hint_when_agent_is_configured():
    config = _editor_config(provider="deepseek", model="deepseek-chat")
    # A *different* framework default must not leak into the configured agent's controls.
    html = _render_editor(config, default_llm=FrameworkDefaults("google", "gemini-2.5-flash", None))

    assert 'id="inheritDefaultHint"' not in html
    assert "Inherits framework default" not in html
    assert re.search(r'<option value="google"\s+selected', html) is None


def test_editor_inherit_hint_does_not_prefill_provider_or_model():
    config = _editor_config(provider=None, model=None)
    html = _render_editor(config, default_llm=FrameworkDefaults("deepseek", "deepseek-chat", None))

    assert 'id="inheritDefaultHint"' in html
    # Model stays empty in the submitted hidden field.
    assert re.search(r'<input type="hidden" name="model" id="modelValue" value="">', html)
    # Provider select keeps the blank "Auto" option selected.
    assert re.search(r'<option value=""\s+selected\s*>Auto \(infer from model\)</option>', html)
    assert re.search(r'<option value="deepseek"\s+selected', html) is None


def test_editor_hides_inherit_hint_when_no_framework_default():
    config = _editor_config(provider=None, model=None)
    # editor_page always passes a FrameworkDefaults instance (truthy); the .provider term
    # is what must gate the hint.
    html = _render_editor(config, default_llm=FrameworkDefaults())

    assert 'id="inheritDefaultHint"' not in html
    assert "Inherits framework default" not in html


# --- Editor: case B hint (provider set, blank model) --------------------------

def test_editor_case_b_hint_names_the_framework_default_when_provider_matches():
    config = _editor_config(provider="deepseek", model=None)
    html = _render_editor(config, default_llm=FrameworkDefaults("deepseek", "deepseek-chat", None))

    assert 'id="inheritDefaultHint"' in html
    assert "Inherits framework default: DeepSeek / deepseek-chat" in html


def test_editor_case_b_hint_names_the_registry_default_for_a_foreign_provider():
    config = _editor_config(provider="google", model=None)
    html = _render_editor(config, default_llm=FrameworkDefaults("deepseek", "deepseek-chat", None))

    assert 'id="inheritDefaultHint"' in html
    assert "Uses Google (Gemini) default: gemini-2.5-flash" in html
    assert "Inherits framework default" not in html


def test_editor_case_b_hint_names_the_registry_default_with_no_framework_default():
    config = _editor_config(provider="deepseek", model=None)
    html = _render_editor(config, default_llm=FrameworkDefaults())

    assert 'id="inheritDefaultHint"' in html
    assert "Uses DeepSeek default: deepseek-chat" in html


def test_editor_case_b_hint_does_not_prefill_the_model_field():
    config = _editor_config(provider="deepseek", model=None)
    html = _render_editor(config, default_llm=FrameworkDefaults("deepseek", "deepseek-chat", None))

    assert 'id="inheritDefaultHint"' in html
    assert re.search(r'<input type="hidden" name="model" id="modelValue" value="">', html)


def test_editor_hint_absent_for_an_unknown_provider():
    config = _editor_config(provider="nope", model=None)
    html = _render_editor(config, default_llm=FrameworkDefaults("deepseek", "deepseek-chat", None))

    assert 'id="inheritDefaultHint"' not in html


def test_editor_never_prefills_a_provider_default_endpoint():
    """A provider's registry default is a placeholder, never a value: writing it into the
    field would persist it on save and pin the agent away from the endpoint it inherits."""
    html = _render_editor(_editor_config(provider="litellm", model=None))

    # No auto-fill machinery, and nothing ever assigns into the endpoint input.
    assert "lastAutoBaseUrl" not in html
    assert "$input.val(" not in html
    # The stored value is empty and the registry default is only previewed.
    assert 'id="baseUrlInput" value=""' in html
    assert "spec.base_url_placeholder || spec.default_base_url" in html


def test_editor_provider_pill_reads_infer_from_model_not_model_name():
    html = _render_editor(_editor_config(provider="deepseek", model="deepseek-chat"))

    assert "Auto (infer from model)" in html
    assert "Auto (infer from model name)" not in html


# --- Admin -> Rules Engine card (llm-provider-expansion §9.2) ------------------

_RULES_ENGINE_CONTEXT = {
    "provider_default": "",
    "provider_override": None,
    "model_default": "gemini-2.5-flash",
    "model_override": None,
    "base_url_override": None,
    "confidence_default": 0.7,
    "confidence_override": None,
    "timeout_default": 3.0,
    "timeout_override": None,
    "effective_timeout": 3.0,
}


def _render_admin(rules_engine=None):
    context = {
        "request": _FakeRequest(),
        "user": {"name": "Test User", "sub": "test-user"},
        "is_admin": True,
        "csrf_token": "test-csrf-token",
        "app_name": "Trellis",
        "app_accent_color": "#0055FF",
        "app_accent_color_dark": "#3377FF",
        "users": [],
        "stats": {"total_users": 0, "total_keys": 0, "total_agents": 0},
        "feature_flags": {
            "agent_memory_enabled": False,
            "agent_memory_isolated_per_user": False,
        },
        "rules_engine": dict(rules_engine or _RULES_ENGINE_CONTEXT),
    }
    context.update(llm_providers_context(None))
    return templates.env.get_template("admin.html").render(**context)


def _rules_provider_select(html):
    marker = 'id="rulesProviderSelect"'
    marker_start = html.index(marker)
    start = html.index(">", marker_start) + 1
    end = html.index("</select>", start)
    open_start = html.rindex("<select", 0, marker_start)
    return html[open_start:end]


def _rules_model_datalist(html):
    marker = 'id="rulesModelDatalist"'
    start = html.index(marker)
    start = html.index(">", start) + 1
    end = html.index("</datalist>", start)
    return html[start:end]


def test_admin_rules_card_renders_every_provider_label_not_raw_ids():
    html = _render_admin()
    specs = provider_ui_specs()
    select = _rules_provider_select(html)

    assert len(specs) == 15
    for spec in specs:
        assert re.search(
            rf'<option\s+value="{re.escape(spec["id"])}"', select
        ), f'missing provider option for {spec["id"]}'
        assert re.search(
            rf'<option\s+value="{re.escape(spec["id"])}"[^>]*>{re.escape(spec["label"])}</option>',
            select,
        ), f'option {spec["id"]} does not render the registry label {spec["label"]!r}'

    # Regression: the dropdown used to show raw ids as the option text.
    option_texts = [text.strip() for text in re.findall(r"<option[^>]*>([^<]*)</option>", select)]
    raw_ids = {spec["id"] for spec in specs}
    assert all(text not in raw_ids for text in option_texts)


def test_admin_rules_card_first_option_is_the_inferred_default():
    html = _render_admin()
    select = _rules_provider_select(html)
    first_option = re.search(r"<option[^>]*>[^<]*</option>", select)
    assert first_option, "no provider options rendered"

    markup = first_option.group(0)
    assert 'value=""' in markup
    assert "default" in markup.lower()
    assert "infer from model" in markup.lower()


def test_admin_rules_card_model_datalist_covers_multiple_providers_without_duplicates():
    html = _render_admin()
    datalist = _rules_model_datalist(html)

    for model in ("gemini-2.5-pro", "gpt-5", "deepseek-chat", "llama3.2"):
        assert f'value="{model}"' in datalist, f"{model} missing from #rulesModelDatalist"

    values = re.findall(r'value="([^"]*)"', datalist)
    assert values, "datalist rendered no model options"
    assert len(values) == len(set(values)), "duplicate model values in #rulesModelDatalist"


def test_admin_rules_card_base_url_field_and_posted_field_names_preserved():
    html = _render_admin()

    assert 'id="rulesBaseUrlField"' in html
    assert 'id="rulesBaseUrlInput"' in html
    assert 'name="base_url"' in html

    # The save form contract must not change with the UI rework.
    assert 'action="/admin/rules-engine/model"' in html
    assert 'name="provider"' in _rules_provider_select(html)
    assert 'name="model"' in html
    assert 'name="confidence_threshold"' in html


def test_admin_rules_card_inline_script_consumes_shared_registry_payload():
    html = _render_admin()
    select = _rules_provider_select(html)

    # Options are plain labels; the inline script reads provider metadata from the shared
    # payload, not from per-option data-* attributes.
    assert 'value="deepseek"' in select
    assert "data-supports-url" not in select
    assert "window.LLM_PROVIDERS" in html
    assert "updateRulesProviderFields" in html


def test_admin_rules_card_never_prefills_a_provider_default_endpoint():
    """The rules base_url only ever *previews* the provider default as a placeholder, so
    switching ollama -> deepseek -> google can never resubmit ollama's URL."""
    html = _render_admin()

    # No auto-fill machinery, and nothing ever assigns into the endpoint input.
    assert "lastAutoBaseUrl" not in html
    assert "baseUrlInput.value" not in html
    assert "baseUrlInput.placeholder = spec.base_url_placeholder || spec.default_base_url" in html
