# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Identity-provider groups claim -> user record (v0.7.1 Phase 3).

Covers the claim parser (`core.auth.normalize_groups` / `claim_groups`) and both login
callbacks in `core.routers.auth`: the groups claim is read from the userinfo, normalized
and stored on the user record; a missing or malformed claim never fails a login. The
OAuth client and the identity manager are faked -- no network, no etcd.
"""

import asyncio
from types import SimpleNamespace

import pytest

from core.auth import MAX_CLAIM_GROUPS, claim_groups, normalize_groups
from core.routers import auth as auth_router

ADMIN_EMAIL = "admin@example.com"


class FakeRequest:
    def __init__(self, session=None, headers=None):
        self.session = {} if session is None else session
        self.headers = headers if headers is not None else {"host": "testserver"}


class FakeIdentityManager:
    def __init__(self):
        self.users = {}

    def upsert_user(self, user_id, profile):
        self.users[user_id] = profile


class _OidcClient:
    def __init__(self, userinfo):
        self.userinfo = userinfo

    async def authorize_access_token(self, request):
        return {"userinfo": self.userinfo}


class _GithubResponse:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class _GithubClient:
    def __init__(self, userinfo, emails=None):
        self.userinfo = userinfo
        self.emails = emails or []
        self.paths = []

    async def authorize_access_token(self, request):
        return {"access_token": "gh-token"}

    async def get(self, path, token=None):
        self.paths.append(path)
        if path == "user":
            return _GithubResponse(self.userinfo)
        return _GithubResponse(self.emails)


@pytest.fixture(autouse=True)
def _open_domains(monkeypatch):
    """The callbacks gate on ALLOWED_DOMAINS; keep the tests domain-agnostic."""
    monkeypatch.setattr(auth_router, "ALLOWED_DOMAINS", [])
    monkeypatch.delenv("OIDC_GROUPS_CLAIM", raising=False)


@pytest.fixture
def identity(monkeypatch):
    fake = FakeIdentityManager()
    monkeypatch.setattr(auth_router, "identity_mgr", fake)
    return fake


def _login_oidc(monkeypatch, userinfo, session=None):
    monkeypatch.setattr(
        auth_router, "oauth", SimpleNamespace(oidc=_OidcClient(userinfo))
    )
    request = FakeRequest(session=session)
    response = asyncio.run(auth_router.auth_callback(request))
    return request, response


def _login_github(monkeypatch, userinfo, emails=None):
    client = _GithubClient(userinfo, emails)
    monkeypatch.setattr(auth_router, "oauth", SimpleNamespace(github=client))
    request = FakeRequest()
    response = asyncio.run(auth_router.auth_github_callback(request))
    return request, response, client


# --- claim parsing ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        pytest.param(["ops", "engineering"], ["engineering", "ops"], id="list"),
        pytest.param(["ops", "ops", " "], ["ops"], id="list-deduped"),
        pytest.param("ops,engineering", ["engineering", "ops"], id="comma-string"),
        pytest.param("All Staff", ["All Staff"], id="space-string-is-one-group"),
        pytest.param(" ops ,  oncall ,ops ", ["oncall", "ops"], id="messy-string"),
        pytest.param([], [], id="empty-list"),
        pytest.param("", [], id="empty-string"),
        pytest.param(None, [], id="missing"),
        pytest.param(7, [], id="wrong-type"),
        pytest.param({"ops": True}, [], id="mapping"),
        pytest.param(["ops", 3, None], ["ops"], id="mixed-list"),
    ],
)
def test_normalize_groups(raw, expected):
    assert normalize_groups(raw) == expected


def test_normalize_groups_caps_very_large_claims():
    groups = normalize_groups([f"g{i:04d}" for i in range(MAX_CLAIM_GROUPS + 50)])

    assert len(groups) == MAX_CLAIM_GROUPS
    assert groups == sorted(groups)


def test_claim_groups_reads_the_configured_claim(monkeypatch):
    userinfo = {"groups": ["from-groups"], "roles": "role-a,role-b"}

    assert claim_groups(userinfo) == ["from-groups"]

    monkeypatch.setenv("OIDC_GROUPS_CLAIM", "roles")
    assert claim_groups(userinfo) == ["role-a", "role-b"]

    # A configured claim that the IdP does not send is simply "no groups".
    monkeypatch.setenv("OIDC_GROUPS_CLAIM", "teams")
    assert claim_groups(userinfo) == []


def test_claim_groups_defaults_to_groups_when_the_env_is_blank(monkeypatch):
    monkeypatch.setenv("OIDC_GROUPS_CLAIM", "   ")

    assert claim_groups({"groups": ["ops"]}) == ["ops"]


def test_claim_groups_never_raises():
    class Exploding(dict):
        def get(self, key, default=None):
            raise RuntimeError("bad claim")

    assert claim_groups(Exploding()) == []
    assert claim_groups(None) == []


# --- OIDC login ---------------------------------------------------------------


def test_oidc_login_stores_the_normalized_groups(monkeypatch, identity):
    userinfo = {
        "sub": "oidc|alice",
        "email": "alice@example.com",
        "name": "Alice",
        "groups": "ops, engineering",
    }

    request, response = _login_oidc(monkeypatch, userinfo)

    assert response.headers["location"] == "/"
    # Groups live on the record only: the session is a signed cookie with a 4 KB
    # browser budget, and a large IdP claim must not break login.
    assert "groups" not in request.session["user"]
    assert identity.users["oidc|alice"]["groups"] == ["engineering", "ops"]


def test_oidc_login_without_a_groups_claim_still_succeeds(monkeypatch, identity):
    userinfo = {"sub": "oidc|bob", "email": "bob@example.com", "name": "Bob"}

    request, response = _login_oidc(monkeypatch, userinfo)

    assert response.headers["location"] == "/"
    assert identity.users["oidc|bob"]["groups"] == []


def test_oidc_login_honors_a_custom_claim_name(monkeypatch, identity):
    monkeypatch.setenv("OIDC_GROUPS_CLAIM", "roles")
    userinfo = {
        "sub": "oidc|carol",
        "email": "carol@example.com",
        "groups": ["ignored"],
        "roles": ["sre"],
    }

    _login_oidc(monkeypatch, userinfo)

    assert identity.users["oidc|carol"]["groups"] == ["sre"]


# --- GitHub login -------------------------------------------------------------


def test_github_login_stores_groups_from_a_mapped_claim(monkeypatch, identity):
    userinfo = {
        "id": 42,
        "login": "alice",
        "name": "Alice",
        "email": "alice@example.com",
        "groups": ["ops"],
    }

    request, _, _ = _login_github(monkeypatch, userinfo)

    assert request.session["user"]["sub"] == "github|42"
    assert identity.users["github|42"]["groups"] == ["ops"]


def test_github_login_without_groups_stores_an_empty_list(monkeypatch, identity):
    userinfo = {"id": 43, "login": "bob", "name": "Bob", "email": "bob@example.com"}

    _, _, _ = _login_github(monkeypatch, userinfo)

    assert identity.users["github|43"]["groups"] == []
