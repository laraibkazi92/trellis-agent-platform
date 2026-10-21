# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for Admin -> Edges (trellis-proxy P1).

Covers the site lifecycle routes (list, create, update, rotate, revoke, delete) and the
read-only treatment of relay-managed tools in the tool editor. Everything runs against a
fake identity manager: no etcd, no relay, no network.
"""
import asyncio
from types import SimpleNamespace

import pytest
from starlette.datastructures import FormData

from core.routers import admin


ADMIN_EMAIL = "admin@example.com"
TOKEN = "edge_plant-floor_supersecrettoken"


# --- Shared fakes --------------------------------------------------------------

class FakeEdgeIdentityManager:
    """Edge + tool surface used by the routes under test."""

    def __init__(self, edges=None, statuses=None, tool_configs=None):
        self._edges = edges or {}
        self._statuses = statuses or {}
        self._tool_configs = tool_configs or {}
        self.created = []
        self.rotated = []
        self.revoked = []
        self.deleted = []
        self.saved_edge_configs = {}
        self.saved_tool_configs = {}

    # --- edges ---
    def list_edges(self):
        return list(self._edges.keys())

    def get_edge_config(self, name):
        config = self._edges.get(name)
        return dict(config) if config else None

    def get_edge_status(self, name):
        status = self._statuses.get(name)
        return dict(status) if status else None

    def create_edge(self, name, display_name, created_by, exports=None):
        if name in self._edges:
            raise ValueError(f"Edge '{name}' already exists.")
        self.created.append({
            "name": name,
            "display_name": display_name,
            "created_by": created_by,
            "exports": list(exports or []),
        })
        self._edges[name] = {
            "name": name,
            "display_name": display_name,
            "enabled": True,
            "exports": list(exports or []),
            "public": False,
            "public_tools": [],
            "token_hash": "hash-of-new-token",
            "token_preview": TOKEN[:12] + "…",
            "created_at": "2026-10-21T10:00:00Z",
            "created_by": created_by,
        }
        return TOKEN

    def rotate_edge_token(self, name, rotated_by):
        self.rotated.append({"name": name, "rotated_by": rotated_by})
        return f"edge_{name}_rotatedtoken"

    def revoke_edge_token(self, name):
        self.revoked.append(name)

    def delete_edge(self, name):
        self.deleted.append(name)
        self._edges.pop(name, None)

    def save_edge_config(self, name, config):
        self.saved_edge_configs[name] = dict(config)

    # --- tools (editor) ---
    def get_tool_config(self, name):
        config = self._tool_configs.get(name)
        return dict(config) if config else None

    def save_tool_config(self, name, config):
        self.saved_tool_configs[name] = dict(config)


class _FakeURL:
    path = "/admin/edges"


class FakeRequest:
    def __init__(self, session=None, form_data=None, query=None):
        self.session = session if session is not None else {}
        self._form_data = form_data
        self.query_params = query or {}
        self.url = _FakeURL()
        self.app = SimpleNamespace(state=SimpleNamespace(http_client=None))

    async def form(self):
        return self._form_data


def _admin_session():
    return {"user": {"email": ADMIN_EMAIL}}


def _form(pairs):
    return FormData(pairs)


def _without_csrf(pairs):
    """Admin POST handlers in tests bypass CSRFRoute, which is what strips the token."""
    return [(k, v) for k, v in pairs if k != "csrf_token"]


@pytest.fixture(autouse=True)
def _admin_users(monkeypatch):
    monkeypatch.setenv("ADMIN_USERS", ADMIN_EMAIL)


def _edge_config(name="plant-floor", **overrides):
    config = {
        "name": name,
        "display_name": "Plant floor",
        "enabled": True,
        "exports": ["boiler_status"],
        "public": False,
        "public_tools": [],
        "token_hash": "hash-abc",
        "token_preview": "edge_plant-fl…",
        "created_at": "2026-10-20T09:00:00Z",
        "created_by": ADMIN_EMAIL,
    }
    config.update(overrides)
    return config


# --- GET /admin/edges ----------------------------------------------------------

def test_non_admin_is_redirected_away(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _edge_config()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = {"user": {"email": "someone@example.com"}}
    response = asyncio.run(admin.admin_edges_page(FakeRequest(session=session)))

    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    assert session["flash_msg"] == "Unauthorized access."


def test_unauthenticated_is_redirected_to_login(monkeypatch):
    fake = FakeEdgeIdentityManager()
    monkeypatch.setattr(admin, "identity_mgr", fake)

    response = asyncio.run(admin.admin_edges_page(FakeRequest()))

    assert response.status_code == 307
    assert response.headers["location"] == "/login"


def test_empty_state_renders(monkeypatch):
    monkeypatch.setattr(admin, "identity_mgr", FakeEdgeIdentityManager())

    response = asyncio.run(admin.admin_edges_page(FakeRequest(session=_admin_session())))

    assert response.status_code == 200
    html = response.body.decode()
    assert "No edge nodes yet" in html
    assert "/docs/proxy" in html


def test_edge_is_listed_with_status_version_and_tools(monkeypatch):
    fake = FakeEdgeIdentityManager(
        edges={"plant-floor": _edge_config()},
        statuses={"plant-floor": {
            "connected": True,
            "connected_at": "2026-10-21T11:00:00Z",
            "edge_version": "0.3.0",
            "tools": ["boiler_status", "plant_readings"],
            "last_error": "",
        }},
    )
    monkeypatch.setattr(admin, "identity_mgr", fake)

    captured = {}
    real = admin.templates.TemplateResponse

    def capturing(request=None, name=None, context=None):
        captured["context"] = context
        return real(request=request, name=name, context=context)

    monkeypatch.setattr(admin.templates, "TemplateResponse", capturing)

    response = asyncio.run(admin.admin_edges_page(FakeRequest(session=_admin_session())))

    assert response.status_code == 200
    edge = captured["context"]["edges"][0]
    assert edge["name"] == "plant-floor"
    assert edge["connected"] is True
    assert edge["edge_version"] == "0.3.0"
    assert edge["tools"] == ["boiler_status", "plant_readings"]

    html = response.body.decode()
    assert "plant-floor" in html
    assert "Connected" in html
    assert "0.3.0" in html
    assert "boiler_status" in html
    assert "plant_readings" in html


def test_offline_edge_and_last_error_are_surfaced(monkeypatch):
    fake = FakeEdgeIdentityManager(
        edges={"plant-floor": _edge_config()},
        statuses={"plant-floor": {
            "connected": False,
            "tools": [],
            "last_error": "catalog rejected: bad schema",
        }},
    )
    monkeypatch.setattr(admin, "identity_mgr", fake)

    response = asyncio.run(admin.admin_edges_page(FakeRequest(session=_admin_session())))

    html = response.body.decode()
    assert "Offline" in html
    assert "catalog rejected: bad schema" in html


# --- POST /admin/edges/create --------------------------------------------------

def test_create_valid_edge_shows_token_once(monkeypatch):
    fake = FakeEdgeIdentityManager()
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("name", "plant-floor"),
        ("display_name", "Plant floor"),
        ("exports", "boiler_status, plant_readings"),
    ])))
    response = asyncio.run(admin.create_edge(request))

    assert response.status_code == 303
    assert fake.created == [{
        "name": "plant-floor",
        "display_name": "Plant floor",
        "created_by": ADMIN_EMAIL,
        "exports": ["boiler_status", "plant_readings"],
    }]
    assert "shown once" in session["flash_msg"]

    # The token is never in the redirect URL (access logs would record it): the
    # follow-up render claims whatever this process is holding.
    assert response.headers["location"] == "/admin/edges"
    follow_up = FakeRequest(session=_admin_session())
    captured = {}
    real = admin.templates.TemplateResponse

    def capturing(request=None, name=None, context=None):
        captured["context"] = context
        return real(request=request, name=name, context=context)

    monkeypatch.setattr(admin.templates, "TemplateResponse", capturing)
    rendered = asyncio.run(admin.admin_edges_page(follow_up))

    assert captured["context"]["new_tokens"] == [{"site": "plant-floor", "token": TOKEN}]
    html = rendered.body.decode()
    assert '<code id="newEdgeToken1"' in html
    assert TOKEN in html
    assert "shown once" in html.lower()

    # Second render: the one-shot value is gone, so it cannot leak later.
    monkeypatch.setattr(admin.templates, "TemplateResponse", real)
    second = asyncio.run(admin.admin_edges_page(FakeRequest()))
    assert TOKEN not in second.body.decode()


@pytest.mark.parametrize("bad_name", ["mcp", "a__b", "bad name!"])
def test_create_rejects_invalid_names(monkeypatch, bad_name):
    fake = FakeEdgeIdentityManager()
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("name", bad_name),
        ("display_name", "Bad"),
        ("exports", ""),
    ])))
    response = asyncio.run(admin.create_edge(request))

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/edges"
    assert fake.created == []
    assert session["flash_msg"]


def test_create_flashes_value_error_from_registry(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _edge_config()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("name", "plant-floor"),
        ("display_name", "Plant floor"),
        ("exports", ""),
    ])))
    response = asyncio.run(admin.create_edge(request))

    assert response.status_code == 303
    assert "already exists" in session["flash_msg"]


# --- POST /admin/edges/update --------------------------------------------------

def test_update_parses_exports_and_toggles_public(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _edge_config()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("name", "plant-floor"),
        ("display_name", "Plant floor (north)"),
        ("exports", " boiler_status , plant_readings ,, "),
        ("public", "true"),
        # Never editable: a hostile/stale form must not be able to change the token.
        ("token_hash", "attacker-supplied"),
        ("enabled", "false"),
    ])))
    response = asyncio.run(admin.update_edge(request))

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/edges"

    saved = fake.saved_edge_configs["plant-floor"]
    assert saved["display_name"] == "Plant floor (north)"
    assert saved["exports"] == ["boiler_status", "plant_readings"]
    assert saved["public"] is True
    assert saved["token_hash"] == "hash-abc"
    assert saved["enabled"] is True


def test_update_clears_public_when_unchecked(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _edge_config(public=True)})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    request = FakeRequest(session=_admin_session(), form_data=_form(_without_csrf([
        ("name", "plant-floor"),
        ("display_name", "Plant floor"),
        ("exports", ""),
    ])))
    asyncio.run(admin.update_edge(request))

    assert fake.saved_edge_configs["plant-floor"]["public"] is False
    assert fake.saved_edge_configs["plant-floor"]["exports"] == []


def test_update_unknown_edge_flashes_and_does_not_save(monkeypatch):
    fake = FakeEdgeIdentityManager()
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("name", "ghost"),
        ("display_name", "Ghost"),
        ("exports", ""),
    ])))
    response = asyncio.run(admin.update_edge(request))

    assert response.status_code == 303
    assert fake.saved_edge_configs == {}
    assert "not found" in session["flash_msg"]


# --- rotate / revoke / delete --------------------------------------------------

def test_rotate_issues_a_new_one_time_token(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _edge_config()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    response = asyncio.run(admin.rotate_edge(
        FakeRequest(session=session, form_data=_form(_without_csrf([("name", "plant-floor")])))
    ))

    assert response.status_code == 303
    assert fake.rotated == [{"name": "plant-floor", "rotated_by": ADMIN_EMAIL}]
    assert "shown once" in session["flash_msg"]

    assert response.headers["location"] == "/admin/edges"
    rendered = asyncio.run(
        admin.admin_edges_page(FakeRequest(session=_admin_session()))
    )
    assert "edge_plant-floor_rotatedtoken" in rendered.body.decode()


def test_revoke_flashes_handshake_and_socket_semantics(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _edge_config()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    response = asyncio.run(admin.revoke_edge(
        FakeRequest(session=session, form_data=_form(_without_csrf([("name", "plant-floor")])))
    ))

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/edges"
    assert fake.revoked == ["plant-floor"]
    assert "handshake" in session["flash_msg"]
    assert "socket closes" in session["flash_msg"]


def test_delete_removes_edge_and_confirms(monkeypatch):
    fake = FakeEdgeIdentityManager(
        edges={"plant-floor": _edge_config()},
        statuses={"plant-floor": {"connected": True, "tools": ["boiler_status"]}},
    )
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    response = asyncio.run(admin.delete_edge(
        FakeRequest(session=session, form_data=_form(_without_csrf([("name", "plant-floor")])))
    ))

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/edges"
    assert fake.deleted == ["plant-floor"]
    assert "plant-floor" in session["flash_msg"]


def test_delete_unknown_edge_does_not_call_registry(monkeypatch):
    fake = FakeEdgeIdentityManager()
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    response = asyncio.run(admin.delete_edge(
        FakeRequest(session=session, form_data=_form(_without_csrf([("name", "ghost")])))
    ))

    assert response.status_code == 303
    assert fake.deleted == []
    assert "not found" in session["flash_msg"]


# --- editor: relay-managed tools ----------------------------------------------

EDGE_TOOL = "plant-floor__boiler_status"


def _edge_tool_config():
    return {
        "name": EDGE_TOOL,
        "description": "Boiler status from the plant floor.",
        "runtime": "remote",
        "version": "1.0.0",
        "inputs": {"unit": {"type": "string", "description": "", "required": True}},
        "remote": {"site": "plant-floor", "tool": "boiler_status"},
        "managed_by": "edge-relay",
    }


def test_editor_page_renders_read_only_for_edge_tool(monkeypatch):
    fake = FakeEdgeIdentityManager(tool_configs={EDGE_TOOL: _edge_tool_config()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    response = asyncio.run(
        admin.editor_page(FakeRequest(session=_admin_session()), "tool", EDGE_TOOL)
    )

    assert response.status_code == 200
    html = response.body.decode()
    assert "managed by the edge relay" in html
    assert "runs on edge &lsquo;plant-floor&rsquo;" in html or "runs on edge" in html
    assert "edit the tool there and reconnect" in html
    # Read-only: no submit path rendered, inputs disabled.
    assert "Commit Changes" not in html
    assert "<fieldset disabled" in html


def test_editor_page_keeps_local_tool_editable(monkeypatch):
    local = {"name": "text_stats", "description": "Counts", "runtime": "python", "version": "1.0.0"}
    fake = FakeEdgeIdentityManager(tool_configs={"text_stats": local})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    response = asyncio.run(
        admin.editor_page(FakeRequest(session=_admin_session()), "tool", "text_stats")
    )

    html = response.body.decode()
    assert "Commit Changes" in html
    assert "managed by the edge relay" not in html


def test_save_tool_refuses_edge_managed_tool(monkeypatch):
    fake = FakeEdgeIdentityManager(tool_configs={EDGE_TOOL: _edge_tool_config()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("runtime", "python"),
        ("version", "9.9.9"),
        ("description", "hijacked"),
        ("entrypoint", "run.py"),
    ])))
    response = asyncio.run(admin.save_tool(request, EDGE_TOOL))

    assert response.status_code == 303
    assert response.headers["location"] == "/tools"
    assert fake.saved_tool_configs == {}
    assert "edge relay" in session["flash_msg"]


def test_save_tool_still_saves_local_tool(monkeypatch):
    local = {"name": "text_stats", "description": "Counts", "runtime": "python", "version": "1.0.0"}
    fake = FakeEdgeIdentityManager(tool_configs={"text_stats": local})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    request = FakeRequest(session=_admin_session(), form_data=_form(_without_csrf([
        ("runtime", "python"),
        ("version", "1.0.1"),
        ("description", "Counts text"),
        ("entrypoint", "run.py"),
    ])))
    response = asyncio.run(admin.save_tool(request, "text_stats"))

    assert response.status_code == 303
    assert fake.saved_tool_configs["text_stats"]["version"] == "1.0.1"


def test_save_tool_refuses_the_remote_runtime(monkeypatch):
    """`remote` is a registry pointer owned by the relay, never an operator choice.

    A local config marked remote has no `remote` block, fails ToolConfig validation,
    and would silently disappear from the hub at the next reconcile.
    """
    local = {"name": "text_stats", "description": "Counts", "runtime": "python", "version": "1.0.0"}
    fake = FakeEdgeIdentityManager(tool_configs={"text_stats": local})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("runtime", "remote"),
        ("version", "1.0.1"),
        ("description", "Counts text"),
        ("entrypoint", "run.py"),
    ])))
    response = asyncio.run(admin.save_tool(request, "text_stats"))

    assert response.status_code == 303
    assert response.headers["location"] == "/editor/tool/text_stats"
    assert fake.saved_tool_configs == {}
    assert "assigned by the edge relay" in session["flash_msg"]


# --- hardening: per-site rate limit + tunnel probe ---------------------------------


def test_update_stores_and_clears_the_rate_limit(monkeypatch):
    fake = FakeEdgeIdentityManager()
    fake.create_edge("plant-floor", "Plant floor", "admin@example.com")
    monkeypatch.setattr(admin, "identity_mgr", fake)

    request = FakeRequest(session=_admin_session(), form_data=_form(_without_csrf([
        ("name", "plant-floor"),
        ("display_name", "Plant floor"),
        ("exports", ""),
        ("rate_limit_per_min", "750"),
    ])))
    asyncio.run(admin.update_edge(request))
    assert fake.saved_edge_configs["plant-floor"]["rate_limit_per_min"] == 750

    request = FakeRequest(session=_admin_session(), form_data=_form(_without_csrf([
        ("name", "plant-floor"),
        ("display_name", "Plant floor"),
        ("exports", ""),
        ("rate_limit_per_min", ""),
    ])))
    asyncio.run(admin.update_edge(request))
    assert "rate_limit_per_min" not in fake.saved_edge_configs["plant-floor"]


class _FakeHealthResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class _FakeAsyncClient:
    payload = {"sites": {}}
    status = 200
    failure = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url):
        if self.failure:
            raise self.failure
        return _FakeHealthResponse(self.payload, self.status)


def test_check_tunnel_reports_a_connected_site(monkeypatch):
    _FakeAsyncClient.payload = {
        "status": "ok",
        "sites": {"plant-floor": {"connected": True, "tools": 3, "inflight": 1}},
    }
    _FakeAsyncClient.failure = None
    monkeypatch.setattr(admin.httpx, "AsyncClient", _FakeAsyncClient)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("name", "plant-floor"),
    ])))
    response = asyncio.run(admin.test_edge(request))

    assert response.status_code == 303
    assert "connected" in session["flash_msg"]
    assert "3 tool(s)" in session["flash_msg"]


def test_check_tunnel_reports_an_offline_site(monkeypatch):
    _FakeAsyncClient.payload = {"sites": {}}
    _FakeAsyncClient.failure = None
    monkeypatch.setattr(admin.httpx, "AsyncClient", _FakeAsyncClient)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("name", "plant-floor"),
    ])))
    asyncio.run(admin.test_edge(request))

    assert "offline" in session["flash_msg"]


def test_check_tunnel_reports_an_unreachable_relay(monkeypatch):
    _FakeAsyncClient.failure = RuntimeError("boom")
    monkeypatch.setattr(admin.httpx, "AsyncClient", _FakeAsyncClient)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("name", "plant-floor"),
    ])))
    asyncio.run(admin.test_edge(request))

    assert "Could not reach the edge relay" in session["flash_msg"]
