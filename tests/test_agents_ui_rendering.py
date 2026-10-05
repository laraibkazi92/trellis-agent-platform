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
from core.dependencies import templates


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
