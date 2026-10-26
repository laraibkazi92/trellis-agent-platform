# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for Admin -> Tool Authorization (`/admin/tool-authz`).

Covers the bound-tools rollout form (v0.7.1 Phase 1) alongside the original
`use_tool` mode form: the page must render both current modes and the shared deny
ring's `surface` tag, and each POST must keep the "no change without confirmation"
rule. Everything runs against a fake identity manager and stubbed authz reads: no
etcd, no network, no template surprises.
"""

import asyncio
from types import SimpleNamespace

import pytest
from starlette.datastructures import FormData

from core import tool_authz
from core.routers import admin

ADMIN_EMAIL = "admin@example.com"


class FakeAuthzIdentityManager:
    """Registry stand-in recording the mode writes the routes perform."""

    def __init__(self):
        self.tool_authz_modes = []
        self.bound_tools_modes = []
        self.hub_call_modes = []
        self.saved_policies = []

    def set_tool_authz_mode(self, mode):
        self.tool_authz_modes.append(mode)

    def set_bound_tools_mode(self, mode):
        self.bound_tools_modes.append(mode)

    def set_hub_call_mode(self, mode):
        self.hub_call_modes.append(mode)

    def save_tool_policies(self, policy):
        self.saved_policies.append(policy)

    def get_principal_groups(self):
        return {}

    def get_all_tool_configs(self):
        return {}

    def get_all_mcp_configs(self):
        return {}

    def get_all_agent_configs(self):
        return {}


class _FakeURL:
    path = "/admin/tool-authz"


class FakeRequest:
    def __init__(self, session=None, form_data=None):
        self.session = session if session is not None else {}
        self._form_data = form_data
        self.url = _FakeURL()
        self.app = SimpleNamespace(state=SimpleNamespace(http_client=None))

    async def form(self):
        return self._form_data


@pytest.fixture(autouse=True)
def _admin_users(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", ADMIN_EMAIL)


@pytest.fixture
def authz(monkeypatch):
    """Stub the page reads and record cache resets; returns the fake manager."""
    fake = FakeAuthzIdentityManager()
    resets = []
    monkeypatch.setattr(admin, "identity_mgr", fake)
    monkeypatch.setattr(tool_authz, "load_policy", lambda: {"default_action": "deny", "rules": []})
    monkeypatch.setattr(tool_authz, "get_mode", lambda: "shadow")
    monkeypatch.setattr(tool_authz, "get_bound_tools_mode", lambda: "off")
    monkeypatch.setattr(tool_authz, "get_hub_call_mode", lambda: "off")
    monkeypatch.setattr(tool_authz, "shadow_denies", lambda: [])
    monkeypatch.setattr(tool_authz, "reset_cache", lambda: resets.append(1))
    fake.resets = resets
    return fake


def _admin_session():
    return {"user": {"email": ADMIN_EMAIL}}


def _form(pairs):
    return FormData(pairs)


# --- GET /admin/tool-authz ----------------------------------------------------

def test_page_renders_both_modes(authz):
    response = asyncio.run(admin.admin_tool_authz_page(FakeRequest(session=_admin_session())))

    assert response.status_code == 200
    html = response.body.decode()
    assert "/admin/tool-authz/mode" in html
    assert "/admin/tool-authz/bound-mode" in html
    assert "/admin/tool-authz/hub-mode" in html
    assert "Bound tools" in html
    assert "Direct hub calls" in html
    assert "CURRENT: shadow" in html
    assert "CURRENT: off" in html
    # The old "not gated yet" caveat must be gone now that the surface has a switch.
    assert "not gated yet" not in html


def test_page_shows_the_hub_call_mode(monkeypatch, authz):
    monkeypatch.setattr(tool_authz, "get_hub_call_mode", lambda: "enforcing")

    response = asyncio.run(admin.admin_tool_authz_page(FakeRequest(session=_admin_session())))

    html = response.body.decode()
    assert "CURRENT: enforcing" in html
    assert 'value="enforcing" class="peer sr-only" checked' in html


def test_page_shows_the_denial_surface(monkeypatch, authz):
    monkeypatch.setattr(tool_authz, "shadow_denies", lambda: [
        {
            "ts": "2026-10-26T10:00:00Z",
            "principal": "agent:supervisor",
            "tool": "opsctl",
            "scope": "tools:call",
            "mode": "shadow",
            "surface": "bound_tool",
        },
        {
            "ts": "2026-10-26T10:00:01Z",
            "principal": "user:alice",
            "tool": "netctl",
            "scope": "tools:call",
            "mode": "shadow",
        },
    ])

    response = asyncio.run(admin.admin_tool_authz_page(FakeRequest(session=_admin_session())))

    html = response.body.decode()
    assert "agent:supervisor" in html
    assert "bound_tool" in html
    # Legacy entries (no surface key) still render, labelled as the use_tool gate.
    assert "use_tool" in html


def test_non_admin_cannot_see_the_page(authz):
    session = {"user": {"email": "someone@example.com"}}

    response = asyncio.run(admin.admin_tool_authz_page(FakeRequest(session=session)))

    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    assert session["flash_msg"] == "Unauthorized access."


# --- POST /admin/tool-authz/bound-mode ---------------------------------------

def test_bound_mode_enforcing_needs_confirmation(authz):
    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form([("mode", "enforcing")]))

    response = asyncio.run(admin.save_bound_tools_mode(request))

    assert response.status_code == 303
    assert authz.bound_tools_modes == []
    assert authz.resets == []
    assert "Confirmation required" in session["flash_msg"]


def test_bound_mode_enforcing_with_confirmation_is_saved(authz):
    session = _admin_session()
    request = FakeRequest(
        session=session, form_data=_form([("mode", "enforcing"), ("confirm", "on")])
    )

    response = asyncio.run(admin.save_bound_tools_mode(request))

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/tool-authz"
    assert authz.bound_tools_modes == ["enforcing"]
    assert authz.resets == [1]  # the cached snapshot is dropped after the write
    assert "set to 'enforcing'" in session["flash_msg"]


@pytest.mark.parametrize("mode", ["shadow", "off"])
def test_bound_mode_shadow_and_off_need_no_confirmation(authz, mode):
    request = FakeRequest(session=_admin_session(), form_data=_form([("mode", mode)]))

    asyncio.run(admin.save_bound_tools_mode(request))

    assert authz.bound_tools_modes == [mode]


def test_bound_mode_rejects_an_unknown_value(authz):
    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form([("mode", "enforcin")]))

    asyncio.run(admin.save_bound_tools_mode(request))

    assert authz.bound_tools_modes == []
    assert "Unknown bound-tools mode" in session["flash_msg"]


def test_bound_mode_is_independent_of_the_use_tool_mode(authz):
    request = FakeRequest(
        session=_admin_session(), form_data=_form([("mode", "enforcing"), ("confirm", "on")])
    )

    asyncio.run(admin.save_bound_tools_mode(request))

    assert authz.bound_tools_modes == ["enforcing"]
    assert authz.tool_authz_modes == []


# --- POST /admin/tool-authz/hub-mode ----------------------------------------

def test_hub_mode_enforcing_needs_confirmation(authz):
    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form([("mode", "enforcing")]))

    response = asyncio.run(admin.save_hub_call_mode(request))

    assert response.status_code == 303
    assert authz.hub_call_modes == []
    assert authz.resets == []
    assert "Confirmation required" in session["flash_msg"]


def test_hub_mode_enforcing_with_confirmation_is_saved(authz):
    session = _admin_session()
    request = FakeRequest(
        session=session, form_data=_form([("mode", "enforcing"), ("confirm", "on")])
    )

    response = asyncio.run(admin.save_hub_call_mode(request))

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/tool-authz"
    assert authz.hub_call_modes == ["enforcing"]
    assert authz.resets == [1]  # the cached snapshot is dropped after the write
    assert "set to 'enforcing'" in session["flash_msg"]


@pytest.mark.parametrize("mode", ["shadow", "off"])
def test_hub_mode_shadow_and_off_need_no_confirmation(authz, mode):
    request = FakeRequest(session=_admin_session(), form_data=_form([("mode", mode)]))

    asyncio.run(admin.save_hub_call_mode(request))

    assert authz.hub_call_modes == [mode]


def test_hub_mode_rejects_an_unknown_value(authz):
    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form([("mode", "enforcin")]))

    asyncio.run(admin.save_hub_call_mode(request))

    assert authz.hub_call_modes == []
    assert "Unknown hub-call mode" in session["flash_msg"]


def test_hub_mode_is_independent_of_the_other_two_modes(authz):
    request = FakeRequest(
        session=_admin_session(), form_data=_form([("mode", "enforcing"), ("confirm", "on")])
    )

    asyncio.run(admin.save_hub_call_mode(request))

    assert authz.hub_call_modes == ["enforcing"]
    assert authz.tool_authz_modes == []
    assert authz.bound_tools_modes == []


# --- POST /admin/tool-authz/bootstrap ---------------------------------------

def test_bootstrap_includes_per_agent_bound_tool_rules(monkeypatch, authz):
    authz.get_all_tool_configs = lambda: {"text_stats": {"name": "text_stats", "public": False}}
    authz.get_all_mcp_configs = lambda: {}
    authz.get_all_agent_configs = lambda: {
        "demo": {"type": "user_agent", "allowed_tools": ["text_stats"]}
    }

    request = FakeRequest(session=_admin_session(), form_data=_form([("csrf_token", "t")]))
    response = asyncio.run(admin.bootstrap_tool_authz_policy(request))

    assert response.status_code == 303
    [policy] = authz.saved_policies
    assert {
        "tools": ["text_stats"],
        "allow_principals": ["agent:demo"],
        "scopes": list(tool_authz.SCOPES),
    } in policy["rules"]
    assert "bound tools" in request.session["flash_msg"].lower()
