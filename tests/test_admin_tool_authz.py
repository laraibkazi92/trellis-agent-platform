# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for Admin -> Tool Authorization (`/admin/tool-authz`), v0.7.1 read-only.

The page is a window onto the one evaluator (`core/tool_access`): the loaded group
rules and policy version, the `TOOL_ACCESS_MODE` switch, each agent's effective
allowlist and the shadow-denial ring. It must render all of that and must not write
anything -- the policy editor, the three per-surface mode switches, bootstrap,
clear-shadow and the principal-groups editor are gone, and their routes are gone with
them.

Rendering runs against a fake identity manager and stubbed evaluator reads (no etcd,
no network); the removed routes are probed through a real Starlette app so the
assertions are about the actual routing table, not a helper's name.
"""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.testclient import TestClient

from core import tool_access
from core.routers import admin

ADMIN_EMAIL = "admin@example.com"
SESSION_SECRET = "test-session-secret"


class FakeIdentityManager:
    """Only the reads the read-only page performs."""

    def __init__(self, agents=None, agents_error=None):
        self.agents = agents if agents is not None else {}
        self.agents_error = agents_error

    def get_all_agent_configs(self):
        if self.agents_error is not None:
            raise self.agents_error
        return self.agents


class _FakeURL:
    path = "/admin/tool-authz"


class FakeRequest:
    def __init__(self, session=None):
        self.session = session if session is not None else {}
        self.url = _FakeURL()
        self.app = SimpleNamespace(state=SimpleNamespace(http_client=None))


@pytest.fixture(autouse=True)
def _admin_users(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", ADMIN_EMAIL)


@pytest.fixture
def registry(monkeypatch):
    """Stub the evaluator reads; returns the fake identity manager for overrides."""
    fake = FakeIdentityManager(
        agents={
            "demo": {
                "type": "user_agent",
                "allowed_tools": ["text_stats", "execute"],
                "allowed_mcps": ["coralogix", "dc1__*"],
            },
            "nightly": {"type": "background_agent"},
        }
    )
    monkeypatch.setattr(admin, "identity_mgr", fake)
    monkeypatch.setattr(
        tool_access,
        "policy_snapshot",
        lambda: tool_access.PolicySnapshot(
            rules=(
                tool_access.GroupRule(
                    targets=("text_stats",), groups=frozenset({"platform-ops"})
                ),
                tool_access.GroupRule(
                    targets=("dc1__*", "mcp__coralogix__*"),
                    groups=frozenset({"edge-operators", "sre"}),
                    name="edge-and-mcp",
                ),
            ),
            version="42",
            loaded_at=1.0,
        ),
    )
    monkeypatch.setattr(tool_access, "tool_access_mode", lambda: "shadow")
    monkeypatch.setattr(tool_access, "recent_shadow_denials", lambda: [])
    return fake


def _admin_session():
    return {"user": {"email": ADMIN_EMAIL, "sub": "admin-sub"}}


def _render(session=None):
    response = asyncio.run(
        admin.admin_tool_authz_page(
            FakeRequest(session=_admin_session() if session is None else session)
        )
    )
    return response


def _html(response):
    assert response.status_code == 200
    return response.body.decode()


# --- GET /admin/tool-authz: what it shows -------------------------------------


def test_page_renders_the_loaded_rules_and_policy_version(registry):
    html = _html(_render())

    # Rule labels (explicit and derived from the target list).
    assert "platform-ops-only" not in html  # unnamed rule -> target list is the label
    assert "text_stats" in html
    assert "edge-and-mcp" in html
    # Targets and the groups each rule admits.
    assert "dc1__*" in html
    assert "mcp__coralogix__*" in html
    assert "edge-operators" in html
    assert "sre" in html
    assert "42" in html  # policy version
    assert "2 rules" in html


def test_page_shows_the_mode_and_the_env_var_that_owns_it(registry, monkeypatch):
    monkeypatch.setattr(tool_access, "tool_access_mode", lambda: "enforce")

    html = _html(_render())

    assert "CURRENT: enforce" in html
    assert "TOOL_ACCESS_MODE" in html
    assert "off, shadow, enforce" in html


def test_page_shows_each_agents_effective_allowlist(registry):
    html = _html(_render())

    assert "Effective allowlists" in html
    assert "2 agents" in html
    assert "demo" in html
    assert "nightly" in html
    # Resolved the way the evaluator resolves it: bare tools, MCP servers, wildcards,
    # and console names pulled out of `allowed_tools`.
    assert "coralogix" in html
    assert "dc1__*" in html
    assert "execute" in html


def test_page_renders_the_shadow_ring(registry, monkeypatch):
    monkeypatch.setattr(
        tool_access,
        "recent_shadow_denials",
        lambda: [
            {
                "ts": "2026-10-26T10:00:00+00:00",
                "agent": "supervisor",
                "target": "text_stats",
                "reason": "group_denied",
                "rule": "platform-ops-only",
                "groups": ["engineering"],
                "surface": "hub",
                "mode": "shadow",
            }
        ],
    )

    html = _html(_render())

    assert "2026-10-26T10:00:00+00:00" in html
    assert "supervisor" in html
    assert "group_denied" in html
    assert "platform-ops-only" in html
    assert "engineering" in html
    assert "hub" in html


def test_page_shows_load_warnings_for_inert_rule_targets(registry, monkeypatch):
    """A rule naming a console file tool decides nothing: the page must say so."""
    monkeypatch.setattr(
        tool_access,
        "policy_snapshot",
        lambda: tool_access.PolicySnapshot(
            rules=(
                tool_access.GroupRule(
                    targets=("read_file",), groups=frozenset({"ops"}), name="files"
                ),
            ),
            version="9",
            warnings=tuple(
                tool_access.policy_warnings(
                    {"rules": [{"name": "files", "targets": ["read_file"], "groups": ["ops"]}]}
                )
            ),
        ),
    )

    html = _html(_render())

    assert "console tool &#39;read_file&#39; is not covered" in html or (
        "console tool 'read_file' is not covered" in html
    )
    # The page also states which console tools rules DO cover.
    assert "console allowlist" in html
    assert "can never match" in html


def test_page_escapes_rule_and_group_names(registry, monkeypatch):
    monkeypatch.setattr(
        tool_access,
        "policy_snapshot",
        lambda: tool_access.PolicySnapshot(
            rules=(
                tool_access.GroupRule(
                    targets=("<script>alert('t')</script>",),
                    groups=frozenset({"<script>alert('g')</script>"}),
                    name="<b>rule</b>",
                ),
            ),
            version="7",
        ),
    )

    html = _html(_render())

    assert "<script>alert('t')</script>" not in html
    assert "<script>alert('g')</script>" not in html
    assert "<b>rule</b>" not in html
    assert "&lt;script&gt;" in html


def test_empty_states_are_explicit(registry, monkeypatch):
    monkeypatch.setattr(
        tool_access, "policy_snapshot", lambda: tool_access.PolicySnapshot(version="absent")
    )

    html = _html(_render())

    assert "No group rules loaded" in html
    assert "absent" in html


def test_no_agents_registered(registry):
    registry.agents = {}

    html = _html(_render())

    assert "No agents registered" in html


def test_registry_outage_still_renders_the_policy_state(registry):
    registry.agents_error = RuntimeError("etcd unreachable")

    html = _html(_render())

    assert "Agent records unavailable" in html
    assert "etcd unreachable" in html
    # The rules are the part that matters during an outage, so they still render.
    assert "edge-and-mcp" in html


# --- fail-closed policy state --------------------------------------------------


def test_unavailable_policy_is_shown_prominently(registry, monkeypatch):
    monkeypatch.setattr(
        tool_access,
        "policy_snapshot",
        lambda: tool_access.PolicySnapshot(error="policy read failed: etcd unreachable"),
    )

    html = _html(_render())

    assert "Policy unavailable" in html
    assert "failing closed" in html
    assert "policy read failed: etcd unreachable" in html
    assert "unknown" in html  # no version to report
    # No rules can be loaded, and the empty state must not claim the policy is empty.
    assert "No group rules loaded" in html
    assert "nothing is loaded" in html


# --- read-only: no forms, no POST routes ---------------------------------------


def test_page_has_no_forms_and_no_write_controls(registry):
    html = _html(_render())

    assert "<form" not in html
    assert "csrf_token" not in html
    for removed in (
        "/admin/tool-authz/policy",
        "/admin/tool-authz/mode",
        "/admin/tool-authz/bound-mode",
        "/admin/tool-authz/hub-mode",
        "/admin/tool-authz/bootstrap",
        "/admin/tool-authz/clear-shadow",
        "/admin/tool-authz/groups",
    ):
        assert removed not in html
    # The banner names where the knobs moved to instead.
    assert "This page does not write anything" in html
    assert "workspace/policies/tool_access.yaml" in html


@pytest.fixture
def client(registry):
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
    app.include_router(admin.router)

    @app.get("/__test/login")
    async def test_login(request: Request):
        request.session["user"] = {"email": ADMIN_EMAIL, "sub": "admin-sub"}
        return {"ok": True}

    @app.get("/__test/session")
    async def test_session(request: Request):
        return {"keys": sorted(request.session.keys())}

    return TestClient(app, follow_redirects=False)


@pytest.mark.parametrize(
    "path",
    [
        "/admin/tool-authz/policy",
        "/admin/tool-authz/mode",
        "/admin/tool-authz/bound-mode",
        "/admin/tool-authz/hub-mode",
        "/admin/tool-authz/bootstrap",
        "/admin/tool-authz/clear-shadow",
        "/admin/tool-authz/groups",
    ],
)
def test_removed_write_routes_are_gone(client, path):
    assert client.post(path, data={}).status_code == 404


def test_the_page_route_is_get_only(client):
    assert client.post("/admin/tool-authz").status_code == 405


def test_get_needs_no_csrf_token(client):
    """A read path must not depend on a CSRF token -- only writes ever did."""
    assert client.get("/__test/login").status_code == 200
    # The session carries a user and nothing else; the page renders anyway.
    assert client.get("/__test/session").json() == {"keys": ["user"]}

    response = client.get("/admin/tool-authz")

    assert response.status_code == 200
    assert "Tool Authorization" in response.text
    assert "csrf_token" not in response.text


# --- admin gate ----------------------------------------------------------------


def test_non_admin_cannot_see_the_page(registry):
    session = {"user": {"email": "someone@example.com"}}

    response = _render(session=session)

    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    assert session["flash_msg"] == "Unauthorized access."


def test_anonymous_visitor_is_sent_to_login(registry):
    response = _render(session={})

    assert response.status_code == 307
    assert response.headers["location"] == "/login"
