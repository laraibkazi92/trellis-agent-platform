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
import yaml
from starlette.datastructures import FormData

from core.routers import admin


ADMIN_EMAIL = "admin@example.com"
TOKEN = "edge_plant-floor_supersecrettoken"


# --- Shared fakes --------------------------------------------------------------

class FakeEdgeIdentityManager:
    """Edge + tool surface used by the routes under test."""

    def __init__(self, edges=None, statuses=None, tool_configs=None, mcp_configs=None,
                 agent_configs=None):
        self._edges = edges or {}
        self._statuses = statuses or {}
        self._tool_configs = tool_configs or {}
        self._mcp_configs = mcp_configs or {}
        self._agent_configs = agent_configs or {}
        self.created = []
        self.rotated = []
        self.revoked = []
        self.deleted = []
        self.saved_edge_configs = {}
        self.saved_tool_configs = {}
        self.saved_mcp_configs = {}
        self.saved_agent_configs = {}
        self.saved_agent_skills = {}

    # --- MCPs ---
    def get_mcp_config(self, name):
        config = self._mcp_configs.get(name)
        return dict(config) if config else None

    def save_mcp_config(self, name, config):
        self.saved_mcp_configs[name] = config

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

    # --- bulk reads (agent editor) ---
    def get_all_tool_configs(self):
        return {name: dict(config) for name, config in self._tool_configs.items()}

    def get_all_mcp_configs(self):
        return {name: dict(config) for name, config in self._mcp_configs.items()}

    def list_mcps(self):
        return list(self._mcp_configs)

    # --- agents (editor save) ---
    def get_agent_config(self, name):
        config = self._agent_configs.get(name)
        return dict(config) if config else None

    def save_agent_config(self, name, config):
        self.saved_agent_configs[name] = dict(config)

    def get_agent_skills(self, name):
        return ""

    def save_agent_skills(self, name, skills):
        self.saved_agent_skills[name] = skills

    def list_agents(self):
        return list(self._agent_configs)

    def get_all_agent_configs(self):
        return {name: dict(config) for name, config in self._agent_configs.items()}


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


# --- GET /admin/edges: MCP export summary (v0.5) -------------------------------

def _render_edges(monkeypatch, statuses):
    """Render the page and return (html, normalized edge dicts)."""
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _edge_config()}, statuses=statuses)
    monkeypatch.setattr(admin, "identity_mgr", fake)

    captured = {}
    real = admin.templates.TemplateResponse

    def capturing(request=None, name=None, context=None):
        captured["context"] = context
        return real(request=request, name=name, context=context)

    monkeypatch.setattr(admin.templates, "TemplateResponse", capturing)
    response = asyncio.run(admin.admin_edges_page(FakeRequest(session=_admin_session())))
    monkeypatch.setattr(admin.templates, "TemplateResponse", real)
    return response.body.decode(), captured["context"]["edges"][0]


def test_edge_mcps_proto_and_caps_are_rendered(monkeypatch):
    html, edge = _render_edges(monkeypatch, {"plant-floor": {
        "connected": True,
        "edge_version": "0.5.0",
        "proto": 2,
        "caps": ["tools", "mcp"],
        "tools": ["boiler_status"],
        "mcps": [
            {"name": "workload", "tools": 7, "transport": "stdio"},
            {"name": "inventory", "tools": 2, "transport": "sse"},
        ],
        "last_error": "",
    }})

    assert edge["mcps"] == [
        {"name": "workload", "tools": 7, "transport": "stdio"},
        {"name": "inventory", "tools": 2, "transport": "sse"},
    ]
    assert edge["proto"] == 2
    assert edge["caps"] == ["tools", "mcp"]
    assert edge["tools"] == ["boiler_status"]

    assert "MCP servers exported" in html
    assert "workload" in html
    assert "inventory" in html
    assert "stdio" in html
    assert "sse" in html
    assert "proto 2" in html
    assert "no MCPs exported" not in html


def test_v04_status_without_mcp_keys_renders(monkeypatch):
    html, edge = _render_edges(monkeypatch, {"plant-floor": {
        "connected": True,
        "edge_version": "0.4.0",
        "tools": ["boiler_status"],
    }})

    assert edge["mcps"] == []
    assert edge["proto"] is None
    assert edge["caps"] == ["tools"]

    assert "plant-floor" in html
    assert "boiler_status" in html
    assert "no MCPs exported" in html
    assert "MCP servers exported</h3>" in html  # section header always present
    assert "<table" not in html
    assert "proto 2" not in html


@pytest.mark.parametrize("raw_mcps, expected", [
    ("workload", []),
    (42, []),
    (None, []),
    ({"name": "workload", "tools": 3, "transport": "stdio"},
     [{"name": "workload", "tools": 3, "transport": "stdio"}]),
    (["workload"],
     [{"name": "workload", "tools": 0, "transport": ""}]),
    ([{"name": "a", "tools": "6", "transport": "stdio"}, "b"],
     [{"name": "a", "tools": 6, "transport": "stdio"},
      {"name": "b", "tools": 0, "transport": ""}]),
    ([None, 7, {"tools": 4}, {"name": ""}, {"name": "ok", "tools": "junk"}],
     [{"name": "ok", "tools": 0, "transport": ""}]),
])
def test_malformed_mcps_values_normalize(monkeypatch, raw_mcps, expected):
    html, edge = _render_edges(monkeypatch, {"plant-floor": {
        "connected": True,
        "tools": [],
        "mcps": raw_mcps,
    }})

    assert edge["mcps"] == expected
    assert edge["caps"] == ["tools"]
    if expected:
        assert "MCP servers exported" in html
        assert "no MCPs exported" not in html
    else:
        assert "no MCPs exported" in html
        assert "<table" not in html


@pytest.mark.parametrize("raw_proto, raw_caps, proto, caps", [
    ("2", ["tools", "mcp"], None, ["tools", "mcp"]),
    (True, "mcp", None, ["tools"]),
    (None, None, None, ["tools"]),
    (2, ["tools", 7, ""], 2, ["tools"]),
])
def test_malformed_proto_and_caps_normalize(monkeypatch, raw_proto, raw_caps, proto, caps):
    _, edge = _render_edges(monkeypatch, {"plant-floor": {
        "connected": True,
        "proto": raw_proto,
        "caps": raw_caps,
        "mcps": [],
    }})

    assert edge["proto"] == proto
    assert edge["caps"] == caps


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


@pytest.mark.parametrize("bad_name", ["mcp", "a__b", "bad name!", "plant-floor_"])
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


def test_save_mcp_refuses_edge_managed_mcp(monkeypatch):
    """An edge-published MCP is the relay's: a save here is overwritten on the next publish."""
    fake = FakeEdgeIdentityManager(
        mcp_configs={
            "plant-floor__devops-cli": {
                "name": "plant-floor__devops-cli",
                "transport": "remote",
                "managed_by": "edge-relay",
            }
        }
    )
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("transport", "stdio"),
        ("command", "node"),
        ("args", ""),
        ("secrets", ""),
    ])))
    response = asyncio.run(admin.save_mcp(request, "plant-floor__devops-cli"))

    assert response.status_code == 303
    assert response.headers["location"] == "/mcps"
    assert fake.saved_mcp_configs == {}
    assert "edge relay" in session["flash_msg"]


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


# --- credential-key approval ---------------------------------------------------

KEY_FP = "SHA256:" + "A" * 43
ROTATED_KEY_FP = "SHA256:" + "B" * 43


def _keyed_edge(**overrides):
    config = _edge_config(
        edge_pubkey="c3Braw==", edge_key_fp=KEY_FP, edge_key_id="KEYID0000000000"
    )
    config.update(overrides)
    return config


def _render_page(monkeypatch):
    return asyncio.run(admin.admin_edges_page(FakeRequest(session=_admin_session()))).body.decode()


def test_pending_key_renders_the_approve_action(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _keyed_edge()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    html = _render_page(monkeypatch)

    assert "Pending approval" in html
    assert KEY_FP in html
    assert 'action="/admin/edges/plant-floor/approve-key"' in html
    # CSRF-protected like every other admin POST.
    assert 'name="csrf_token"' in html


def test_approved_key_renders_its_approver_and_no_approve_action(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _keyed_edge(
        edge_key_approved=True,
        edge_key_approved_fp=KEY_FP,
        edge_key_approved_by=ADMIN_EMAIL,
        edge_key_approved_at="2026-10-26T12:00:00+00:00",
    )})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    html = _render_page(monkeypatch)

    assert "Approved" in html
    assert ADMIN_EMAIL in html
    assert "2026-10-26T12:00:00+00:00" in html
    assert "approve-key" not in html


def test_a_rotated_key_is_pending_next_to_the_still_approved_one(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _keyed_edge(
        edge_key_fp=ROTATED_KEY_FP,
        edge_key_id="ROTATED000000000",
        edge_key_approved=False,
        edge_key_approved_fp=KEY_FP,
        prev_edge_key_fp=KEY_FP,
        edge_key_fps=[KEY_FP],
    )})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    html = _render_page(monkeypatch)

    assert f'action="/admin/edges/plant-floor/approve-key"' in html
    assert ROTATED_KEY_FP in html
    # The old approved key is named so the operator knows what still seals today.
    assert KEY_FP in html
    assert "rotation overlap" in html


def test_approve_key_records_the_approver_and_the_timestamp(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _keyed_edge()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    response = asyncio.run(
        admin.approve_edge_key(FakeRequest(session=session), "plant-floor")
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/edges"
    saved = fake.saved_edge_configs["plant-floor"]
    assert saved["edge_key_approved"] is True
    assert saved["edge_key_approved_fp"] == KEY_FP
    assert saved["edge_key_approved_by"] == ADMIN_EMAIL
    assert saved["edge_key_approved_at"]
    assert KEY_FP in session["flash_msg"]
    assert "sealing is enabled" in session["flash_msg"]
    # Nothing but the approval fields changes.
    assert saved["token_hash"] == "hash-abc"
    assert saved["display_name"] == "Plant floor"


def test_approve_key_requires_an_admin_session(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _keyed_edge()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = {"user": {"email": "someone@example.com"}}
    response = asyncio.run(
        admin.approve_edge_key(FakeRequest(session=session), "plant-floor")
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    assert fake.saved_edge_configs == {}


def test_approve_key_requires_a_session(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _keyed_edge()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    response = asyncio.run(admin.approve_edge_key(FakeRequest(), "plant-floor"))

    assert response.status_code == 307
    assert response.headers["location"] == "/login"
    assert fake.saved_edge_configs == {}


def test_approve_key_without_a_published_key_flashes(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _edge_config()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    response = asyncio.run(
        admin.approve_edge_key(FakeRequest(session=session), "plant-floor")
    )

    assert response.status_code == 303
    assert fake.saved_edge_configs == {}
    assert "has not published a credential key yet" in session["flash_msg"]


def test_approve_key_for_an_unknown_site_flashes(monkeypatch):
    fake = FakeEdgeIdentityManager()
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    response = asyncio.run(admin.approve_edge_key(FakeRequest(session=session), "ghost"))

    assert response.status_code == 303
    assert fake.saved_edge_configs == {}
    assert "not found" in session["flash_msg"]


def test_approving_the_same_fingerprint_twice_keeps_the_original_audit(monkeypatch):
    fake = FakeEdgeIdentityManager(edges={"plant-floor": _keyed_edge(
        edge_key_approved=True,
        edge_key_approved_fp=KEY_FP,
        edge_key_approved_by="first-admin@example.com",
        edge_key_approved_at="2026-10-20T08:00:00+00:00",
    )})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    response = asyncio.run(
        admin.approve_edge_key(FakeRequest(session=session), "plant-floor")
    )

    assert response.status_code == 303
    assert fake.saved_edge_configs == {}
    assert "already approved" in session["flash_msg"]


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


# --- editor: relay-managed MCP servers ----------------------------------------

EDGE_MCP = "plant-floor__devops-cli"


def _edge_mcp_config():
    return {
        "name": EDGE_MCP,
        "description": "",
        "transport": "remote",
        "remote": {"site": "plant-floor", "mcp": "devops-cli"},
        "managed_by": "edge-relay",
        "public": False,
        "public_tools": [],
        "tools": [{"name": "tenant_account_tools", "description": "", "inputSchema": {}}],
    }


def test_editor_page_renders_read_only_for_edge_mcp(monkeypatch):
    fake = FakeEdgeIdentityManager(mcp_configs={EDGE_MCP: _edge_mcp_config()})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    response = asyncio.run(
        admin.editor_page(FakeRequest(session=_admin_session()), "mcp", EDGE_MCP)
    )

    assert response.status_code == 200
    html = response.body.decode()
    assert "managed by the edge relay" in html
    assert "runs on edge" in html
    # Read-only: no submit path rendered, inputs disabled.
    assert "Commit Changes" not in html
    assert "<fieldset disabled" in html


def test_editor_page_keeps_local_mcp_editable(monkeypatch):
    local = {"name": "local-mcp", "transport": "stdio", "command": "npx"}
    fake = FakeEdgeIdentityManager(mcp_configs={"local-mcp": local})
    monkeypatch.setattr(admin, "identity_mgr", fake)

    response = asyncio.run(
        admin.editor_page(FakeRequest(session=_admin_session()), "mcp", "local-mcp")
    )

    html = response.body.decode()
    assert "Commit Changes" in html
    assert "managed by the edge relay" not in html


def test_delete_mcp_refuses_edge_managed_mcp(monkeypatch):
    """Deleting a relay-owned entry would be undone by the next catalog publish."""
    fake = FakeEdgeIdentityManager(mcp_configs={EDGE_MCP: _edge_mcp_config()})
    fake.delete_mcp = lambda name: pytest.fail("an edge-managed MCP must not be deleted")
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    response = asyncio.run(
        admin.delete_mcp(
            FakeRequest(session=session, form_data=_form(_without_csrf([("name", EDGE_MCP)]))),
            name=EDGE_MCP,
        )
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/mcps"
    assert "managed by the edge relay" in session["flash_msg"]


def test_save_mcp_refuses_the_remote_transport(monkeypatch):
    """`remote` is written by the relay; a hand-written one has no routing block."""
    fake = FakeEdgeIdentityManager(
        mcp_configs={"local-mcp": {"name": "local-mcp", "transport": "stdio", "command": "npx"}}
    )
    monkeypatch.setattr(admin, "identity_mgr", fake)

    session = _admin_session()
    request = FakeRequest(session=session, form_data=_form(_without_csrf([
        ("transport", "remote"),
        ("command", "npx"),
        ("args", ""),
        ("secrets", ""),
    ])))
    response = asyncio.run(admin.save_mcp(request, "local-mcp"))

    assert response.status_code == 303
    assert response.headers["location"] == "/editor/mcp/local-mcp"
    assert fake.saved_mcp_configs == {}
    assert "assigned by the edge relay" in session["flash_msg"]


# --- agent editor save: allowlists the form cannot render ----------------------


def test_agent_save_keeps_allowlist_entries_without_a_checkbox(monkeypatch):
    """A `<site>__*` wildcard and a reference to a not-yet-connected edge MCP have no
    checkbox in the editor, so the form never submits them. The save must union instead
    of replace, or every edit silently deletes them from the registry *and* from
    `workspace/agents/<name>/config.yaml` through the dual write."""
    existing = {
        "name": "edge-agent",
        "model": "gemini-3-flash-preview",
        "allowed_mcps": ["local-mcp", "central-mcp", "plant-floor__*", "dc9__ghost"],
        "allowed_tools": ["text_stats", "mcp__dc9__ghost__chat"],
    }
    fake = FakeEdgeIdentityManager(
        agent_configs={"edge-agent": existing},
        tool_configs={"text_stats": {"name": "text_stats", "description": "Counts"}},
        mcp_configs={
            # `local-mcp` renders as an MCP checkbox *and* renders its one tool.
            "local-mcp": {
                "name": "local-mcp",
                "tools": [{"name": "mcp__local-mcp__list", "description": "List"}],
            },
            # Rendered as an MCP checkbox with no tools.
            "central-mcp": {"name": "central-mcp", "tools": []},
        },
    )
    monkeypatch.setattr(admin, "identity_mgr", fake)

    written = {}

    def _write_repo_file(rel_path, content):
        written[rel_path] = content
        return True

    monkeypatch.setattr(admin, "write_repo_file", _write_repo_file)

    request = FakeRequest(session=_admin_session(), form_data=_form(_without_csrf([
        ("model", "gemini-3-flash-preview"),
        ("version", "1.0.0"),
        ("description", "Edge agent"),
        ("allowed_mcps", "local-mcp"),   # rendered and checked
        ("allowed_tools", "text_stats"),  # rendered and checked
        ("skills_content", "# skills"),
    ])))
    response = asyncio.run(admin.save_agent(request, "edge-agent"))

    assert response.status_code == 303
    saved = fake.saved_agent_configs["edge-agent"]
    # Submitted first, then everything the editor had no checkbox for, in config order.
    assert saved["allowed_mcps"] == ["local-mcp", "plant-floor__*", "dc9__ghost"]
    assert saved["allowed_tools"] == ["text_stats", "mcp__dc9__ghost__chat"]
    # These WERE rendered and left unchecked: a deliberate removal, still honoured.
    assert "central-mcp" not in saved["allowed_mcps"]
    assert "mcp__local-mcp__list" not in saved["allowed_tools"]

    # The dual write carries the same lists, so a rebuild cannot resurrect the deletion.
    config_path = "workspace/agents/edge-agent/config.yaml"
    assert config_path in written
    on_disk = yaml.safe_load(written[config_path])
    assert on_disk["allowed_mcps"] == saved["allowed_mcps"]
    assert on_disk["allowed_tools"] == saved["allowed_tools"]
