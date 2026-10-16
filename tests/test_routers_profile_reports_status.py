# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Router tests for the profile, reports, and status UI pages.

Pattern follows tests/test_admin_agent_visibility.py: route handlers are invoked
directly with a FakeRequest carrying a plain-dict starlette session, the routers'
module-level identity_mgr / discovery / health_db dependencies are monkeypatched
(no live etcd, no network), and reports I/O is pointed at pytest's tmp_path.
Handlers render the REAL templates (profile.html / reports.html / report_list.html /
status.html via each router's Jinja2Templates instance), so both the template
context and the rendered HTML output are asserted.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from starlette.datastructures import FormData

from core.routers import profile, reports, status
from core.routers.auth import require_auth


# --- Shared fakes --------------------------------------------------------------

class FakeRequest:
    def __init__(self, session=None, query_params=None, form_data=None):
        self.session = session if session is not None else {}
        self.query_params = query_params if query_params is not None else {}
        self.form_data = form_data
        self.url = SimpleNamespace(path="/")
        self.app = SimpleNamespace(state=SimpleNamespace(http_client=None))

    async def form(self):
        return self.form_data


def _authed_request(email="user@example.com"):
    return FakeRequest(session={"user": {"sub": "user-1", "email": email, "name": "Test User"}})


def _async_return(value):
    async def _fn(*args, **kwargs):
        return value
    return _fn


def _iso_utc(days_ago):
    stamp = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return stamp.isoformat().replace("+00:00", "Z")


async def _collect_asgi_body(response):
    messages = []

    async def receive():
        # Model a real ASGI client: yield to the loop, then report the disconnect once the
        # body has been fully sent. FileResponse.__call__ (Starlette >= 1.8, legacy ASGI
        # path) loops on receive() watching for http.disconnect; a receive() that never
        # suspends spins that loop without ever letting the file-streaming task run, which
        # hangs the suite.
        await asyncio.sleep(0)
        last = messages[-1] if messages else None
        if last and last["type"] == "http.response.body" and not last.get("more_body"):
            return {"type": "http.disconnect"}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    await response(scope, receive, send)
    return b"".join(m.get("body", b"") for m in messages)


class FakeProfileIdentity:
    def __init__(self, global_usage=None, agent_usage=None, tool_usage=None, keys=None):
        self._global_usage = global_usage or {}
        self._agent_usage = agent_usage or {}
        self._tool_usage = tool_usage or {}
        self._keys = keys or []

    def get_user_usage(self, user_id):
        return self._global_usage

    def get_user_agent_usage(self, user_id):
        return self._agent_usage

    def get_user_tool_usage(self, user_id):
        return self._tool_usage

    def list_keys(self, user_id):
        return self._keys


# --- profile -------------------------------------------------------------------

def test_profile_page_redirects_to_login_when_unauthenticated():
    response = asyncio.run(profile.profile_page(FakeRequest()))

    assert response.status_code == 307
    assert response.headers["location"] == "/login"


def test_profile_page_renders_usage_metrics_and_created_counts(monkeypatch):
    user = {"sub": "user-1", "email": "user@example.com", "name": "Test User"}
    monkeypatch.setattr(profile, "identity_mgr", FakeProfileIdentity(
        global_usage={"input_tokens": 100, "output_tokens": 50, "total_requests": 7},
        agent_usage={"general-agent": {"total_requests": 5, "input_tokens": 80, "output_tokens": 40}},
        tool_usage={"tickets": 3},
        keys=[{"key_id": "key-1", "name": "ci-key", "key_masked": "tl_ab...cd"}],
    ))
    monkeypatch.setattr(profile, "discover_agents", _async_return([
        {"name": "general-agent", "author": "user@example.com"},
        {"name": "other-agent", "author": "someone@example.com"},
    ]))
    monkeypatch.setattr(profile, "discover_tools", _async_return([
        {"name": "tickets", "author": "user@example.com"},
    ]))

    response = asyncio.run(profile.profile_page(FakeRequest(session={"user": user})))

    assert response.status_code == 200
    html = response.body.decode()
    assert "general-agent" in html
    assert "tickets" in html
    assert "ci-key" in html
    assert "No agent usage recorded" not in html
    assert "No tool usage recorded" not in html
    assert "No active keys" not in html
    assert response.context["agents_created"] == 1
    assert response.context["tools_created"] == 1
    assert response.context["user"] == user


def test_profile_page_renders_empty_states_when_no_usage_or_keys(monkeypatch):
    monkeypatch.setattr(profile, "identity_mgr", FakeProfileIdentity(
        global_usage={"input_tokens": 0, "output_tokens": 0, "total_requests": 0},
    ))
    monkeypatch.setattr(profile, "discover_agents", _async_return([]))
    monkeypatch.setattr(profile, "discover_tools", _async_return([]))

    response = asyncio.run(profile.profile_page(_authed_request()))

    assert response.status_code == 200
    html = response.body.decode()
    assert "No agent usage recorded" in html
    assert "No tool usage recorded" in html
    assert "No active keys" in html
    assert response.context["agents_created"] == 0
    assert response.context["tools_created"] == 0


# --- reports: listing ----------------------------------------------------------

def test_list_reports_redirects_to_login_when_unauthenticated():
    response = asyncio.run(reports.list_reports(FakeRequest()))

    assert response.status_code == 307
    assert response.headers["location"] == "/login"


def test_list_reports_empty_directory_renders_empty_state(monkeypatch, tmp_path):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)

    response = asyncio.run(reports.list_reports(_authed_request()))

    assert response.status_code == 200
    html = response.body.decode()
    assert "No Agent Directories Found" in html
    assert "No reports have been generated in the workspace yet." in html
    assert response.context["folders_count"] == 0


def test_list_reports_lists_agent_folders_and_root_reports(monkeypatch, tmp_path):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    agent_dir = tmp_path / "general-agent"
    (agent_dir / "nested").mkdir(parents=True)
    (agent_dir / "report.html").write_text("<h1>one</h1>")
    (agent_dir / "nested" / "deep.html").write_text("<h1>two</h1>")
    (agent_dir / "notes.txt").write_text("not a report")
    (tmp_path / "empty-folder").mkdir()
    (tmp_path / "root-report.html").write_text("<h1>root</h1>")

    response = asyncio.run(reports.list_reports(_authed_request()))

    assert response.status_code == 200
    folders = {f["name"]: f for f in response.context["agent_folders"]}
    assert set(folders) == {"general-agent", "system-root"}
    assert folders["general-agent"]["report_count"] == 2  # .txt files and empty dirs are ignored
    assert folders["general-agent"].get("is_root") is None
    assert folders["system-root"]["is_root"] is True
    assert folders["system-root"]["report_count"] == 1
    html = response.body.decode()
    assert "general-agent" in html
    assert "SYSTEM ROOT" in html
    assert "empty-folder" not in html


def test_list_agent_reports_renders_files_with_admin_delete_controls(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    (tmp_path / "general-agent").mkdir()
    (tmp_path / "general-agent" / "report.html").write_text("<h1>Report</h1>")

    request = _authed_request(email="admin@example.com")
    response = asyncio.run(reports.list_agent_reports(request, "general-agent", page=1, limit=50))

    assert response.status_code == 200
    assert response.context["agent_name"] == "general-agent"
    assert response.context["reports_count"] == 1
    assert response.context["is_admin"] is True
    html = response.body.decode()
    assert "report.html" in html
    assert "/reports/view/general-agent/report.html" in html
    assert "/reports/delete" in html


def test_list_agent_reports_hides_delete_controls_for_non_admin(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    (tmp_path / "general-agent").mkdir()
    (tmp_path / "general-agent" / "report.html").write_text("<h1>Report</h1>")

    response = asyncio.run(reports.list_agent_reports(_authed_request(), "general-agent", page=1, limit=50))

    assert response.status_code == 200
    assert response.context["is_admin"] is False
    assert "/reports/delete" not in response.body.decode()


def test_list_agent_reports_unknown_agent_redirects(monkeypatch, tmp_path):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    request = _authed_request()

    response = asyncio.run(reports.list_agent_reports(request, "ghost-agent"))

    assert response.status_code == 303
    assert response.headers["location"] == "/reports"
    assert request.session["flash_msg"] == "Agent reports directory not found."


# --- reports: view / download --------------------------------------------------

def test_view_report_serves_html_with_csp(monkeypatch, tmp_path):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    (tmp_path / "general-agent").mkdir()
    (tmp_path / "general-agent" / "report.html").write_text("<h1>Report Body</h1>")

    response = asyncio.run(reports.view_report(_authed_request(), "general-agent/report.html"))

    assert response.status_code == 200
    assert response.path == tmp_path / "general-agent" / "report.html"
    assert response.media_type == "text/html"
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
    body = asyncio.run(_collect_asgi_body(response))
    assert b"Report Body" in body


def test_view_report_missing_file_redirects_with_flash(monkeypatch, tmp_path):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    request = _authed_request()

    response = asyncio.run(reports.view_report(request, "general-agent/missing.html"))

    assert response.status_code == 303
    assert response.headers["location"] == "/reports"
    assert request.session["flash_msg"] == "Error: Report file not found."


def test_view_report_blocks_path_traversal_and_absolute_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    request = _authed_request()

    for hostile_path in ("../outside.html", "../../etc/passwd", "/etc/passwd"):
        response = asyncio.run(reports.view_report(request, hostile_path))
        assert response.status_code == 303
        assert response.headers["location"] == "/reports"

    assert request.session["flash_msg"] == "Security Block: Invalid target path."


def test_view_report_redirects_to_login_when_unauthenticated():
    response = asyncio.run(reports.view_report(FakeRequest(), "x.html"))

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_download_report_serves_attachment(monkeypatch, tmp_path):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    (tmp_path / "general-agent").mkdir()
    (tmp_path / "general-agent" / "report.html").write_text("<h1>Report Body</h1>")

    response = asyncio.run(reports.download_report(_authed_request(), "general-agent/report.html"))

    assert response.status_code == 200
    assert response.headers["content-disposition"] == "attachment; filename=report.html"


# --- reports: delete -----------------------------------------------------------

def test_delete_report_admin_removes_file(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    target = tmp_path / "general-agent" / "report.html"
    target.parent.mkdir()
    target.write_text("<h1>Report</h1>")
    request = FakeRequest(
        session={"user": {"sub": "admin-1", "email": "admin@example.com", "name": "Admin"}},
        form_data=FormData([("path", "general-agent/report.html"), ("agent_name", "general-agent")]),
    )

    response = asyncio.run(reports.delete_report(request))

    assert response.status_code == 303
    assert response.headers["location"] == "/reports/dir/general-agent"
    assert not target.exists()
    assert request.session["flash_msg"] == "Report successfully deleted."


def test_delete_report_denies_non_admin(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    target = tmp_path / "general-agent" / "report.html"
    target.parent.mkdir()
    target.write_text("<h1>Report</h1>")
    request = FakeRequest(
        session={"user": {"sub": "user-1", "email": "user@example.com", "name": "User"}},
        form_data=FormData([("path", "general-agent/report.html"), ("agent_name", "general-agent")]),
    )

    response = asyncio.run(reports.delete_report(request))

    assert response.status_code == 303
    assert response.headers["location"] == "/reports"
    assert target.exists()
    assert request.session["flash_msg"] == "Access Denied: Only administrator accounts can delete report files."


def test_delete_report_blocks_path_traversal(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_USERS", "admin@example.com")
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    target = tmp_path / "general-agent" / "report.html"
    target.parent.mkdir()
    target.write_text("<h1>Report</h1>")
    request = FakeRequest(
        session={"user": {"sub": "admin-1", "email": "admin@example.com", "name": "Admin"}},
        form_data=FormData([("path", "../../etc/passwd"), ("agent_name", "general-agent")]),
    )

    response = asyncio.run(reports.delete_report(request))

    assert response.status_code == 303
    assert response.headers["location"] == "/reports/dir/general-agent"
    assert target.exists()
    assert request.session["flash_msg"] == "Security Block: Invalid target path."


def test_delete_report_redirects_to_login_when_unauthenticated():
    response = asyncio.run(reports.delete_report(FakeRequest()))

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# --- status: auth dependency ---------------------------------------------------

def test_require_auth_redirects_to_login_without_session():
    response = asyncio.run(require_auth(FakeRequest()))

    assert response.status_code == 307
    assert response.headers["location"] == "/login"


def test_require_auth_returns_session_user_when_not_banned(monkeypatch):
    import core.dependencies as dependencies

    class _FakeIdentity:
        def get_user(self, user_id):
            assert user_id == "user-1"
            return {"is_banned": False}

    monkeypatch.setattr(dependencies, "identity_mgr", _FakeIdentity())
    user = {"sub": "user-1", "email": "user@example.com", "name": "Test User"}

    result = asyncio.run(require_auth(FakeRequest(session={"user": user})))

    assert result == user


# --- status: page --------------------------------------------------------------

def test_status_page_renders_entity_statuses_and_partial_outage(monkeypatch):
    agents = [
        {"name": "broken-agent", "health": {"status": "Offline", "last_error": "connection reset"}},
        {"name": "healthy-agent", "health": {"status": "Online"}},
    ]
    tools = [{"name": "hub-tools", "health": {"status": "Online"}}]
    monkeypatch.setattr(status, "discover_agents", _async_return(agents))
    monkeypatch.setattr(status, "discover_tools", _async_return(tools))

    events = {("agent", "broken-agent"): [{"timestamp": _iso_utc(days_ago=2), "status": "Offline"}]}

    def fake_events(entity_type, name, days=30):
        return events.get((entity_type, name), [])

    monkeypatch.setattr(status.health_db, "get_events_for_entity", fake_events)

    user = {"sub": "user-1", "email": "user@example.com", "name": "Test User"}
    response = asyncio.run(status.status_page(FakeRequest(session={"user": user}), user=user))

    assert response.status_code == 200
    context = response.context
    assert context["total_entities"] == 3
    assert context["offline_count"] == 1
    assert context["overall_status"] == "Partial Outage"
    assert all(len(a["timeline"]) == 30 for a in context["agents"])
    assert all(len(t["timeline"]) == 30 for t in context["tools"])

    html = response.body.decode()
    assert "broken-agent" in html
    assert "healthy-agent" in html
    assert "hub-tools" in html
    assert "connection reset" in html

    # The outage logged 2 days ago is visible on that timeline slot (index 28 =
    # 2 days ago) and carried forward, while older days default to Online.
    broken = next(a for a in context["agents"] if a["name"] == "broken-agent")
    assert broken["timeline"][27]["status"] == "Offline"
    assert broken["timeline"][28]["status"] == "Offline"
    assert broken["timeline"][26]["status"] == "Online"


def test_status_page_all_entities_offline_is_major_outage(monkeypatch):
    monkeypatch.setattr(status, "discover_agents", _async_return([
        {"name": "broken-agent", "health": {"status": "Offline"}},
    ]))
    monkeypatch.setattr(status, "discover_tools", _async_return([
        {"name": "hub-tools", "health": {"status": "Offline"}},
    ]))
    monkeypatch.setattr(status.health_db, "get_events_for_entity", lambda entity_type, name, days=30: [])

    response = asyncio.run(status.status_page(_authed_request(), user={"sub": "user-1", "name": "Test User"}))

    assert response.status_code == 200
    assert response.context["total_entities"] == 2
    assert response.context["offline_count"] == 2
    assert response.context["overall_status"] == "Major Outage"
    html = response.body.decode()
    assert "broken-agent" in html
    assert "hub-tools" in html


def test_status_page_empty_registry_is_operational(monkeypatch):
    monkeypatch.setattr(status, "discover_agents", _async_return([]))
    monkeypatch.setattr(status, "discover_tools", _async_return([]))
    monkeypatch.setattr(status.health_db, "get_events_for_entity", lambda entity_type, name, days=30: [])

    response = asyncio.run(status.status_page(_authed_request(), user={"sub": "user-1", "name": "Test User"}))

    assert response.status_code == 200
    assert response.context["total_entities"] == 0
    assert response.context["offline_count"] == 0
    assert response.context["overall_status"] == "Operational"
    html = response.body.decode()
    assert "No agents registered." in html
    assert "No tools registered." in html


def test_status_page_today_timeline_reflects_current_status_without_events(monkeypatch):
    monkeypatch.setattr(status, "discover_agents", _async_return([
        {"name": "healthy-agent", "health": {"status": "Online"}},
    ]))
    monkeypatch.setattr(status, "discover_tools", _async_return([
        {"name": "flaky-tool", "health": {"status": "Offline"}},
    ]))
    monkeypatch.setattr(status.health_db, "get_events_for_entity", lambda entity_type, name, days=30: [])

    response = asyncio.run(status.status_page(_authed_request(), user={"sub": "user-1", "name": "Test User"}))

    assert response.status_code == 200
    agent = response.context["agents"][0]
    tool = response.context["tools"][0]
    assert agent["timeline"][-1]["status"] == "Online"
    assert agent["timeline"][0]["status"] == "Online"
    assert tool["timeline"][-1]["status"] == "Offline"
    assert tool["timeline"][0]["status"] == "Online"


# --- status: generate_30_day_timeline (pure function) --------------------------

def test_timeline_is_30_days_oldest_first_with_sequential_indices():
    timeline = status.generate_30_day_timeline([], {"status": "Online"})

    assert len(timeline) == 30
    assert timeline[0]["index"] == 1
    assert timeline[-1]["index"] == 30
    assert timeline[0]["day_label"] == (datetime.now(timezone.utc).date() - timedelta(days=29)).isoformat()
    assert timeline[-1]["day_label"] == datetime.now(timezone.utc).date().isoformat()
    assert all(day["status"] == "Online" for day in timeline)


def test_timeline_marks_outage_day_and_recovery():
    events = [
        {"timestamp": _iso_utc(days_ago=10), "status": "Offline"},
        {"timestamp": _iso_utc(days_ago=9), "status": "Online"},
    ]

    timeline = status.generate_30_day_timeline(events, {"status": "Online"})

    assert timeline[19]["status"] == "Offline"  # the day the outage was logged
    assert timeline[18]["status"] == "Online"   # before any event: defaults to Online
    assert timeline[20]["status"] == "Online"   # recovered on the following day


def test_timeline_carries_last_known_status_forward_until_today():
    events = [{"timestamp": _iso_utc(days_ago=5), "status": "Offline"}]

    timeline = status.generate_30_day_timeline(events, {"status": "Online"})

    assert timeline[24]["status"] == "Offline"  # 5 days ago: the event itself
    assert timeline[23]["status"] == "Online"   # before the event
    assert timeline[28]["status"] == "Offline"  # yesterday: still the last known status
    assert timeline[29]["status"] == "Online"   # today: overridden by current status


def test_timeline_current_status_overrides_today():
    events = [{"timestamp": _iso_utc(days_ago=0), "status": "Online"}]

    timeline = status.generate_30_day_timeline(events, {"status": "Offline"})

    assert timeline[-1]["status"] == "Offline"


def test_timeline_treats_naive_timestamps_as_utc():
    naive = (datetime.now(timezone.utc) - timedelta(days=3)).replace(tzinfo=None)
    events = [{"timestamp": naive.isoformat(), "status": "Offline"}]

    timeline = status.generate_30_day_timeline(events, {"status": "Online"})

    assert timeline[26]["status"] == "Offline"  # 3 days ago: the event itself
    assert timeline[28]["status"] == "Offline"  # yesterday: carried forward
    assert timeline[29]["status"] == "Online"   # today, via current status override


def test_timeline_skips_malformed_timestamps():
    events = [{"timestamp": "not-a-timestamp", "status": "Offline"}]

    timeline = status.generate_30_day_timeline(events, {"status": "Online"})

    assert len(timeline) == 30
    assert all(day["status"] == "Online" for day in timeline)
