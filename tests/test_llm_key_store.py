# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the framework LLM provider key store.

The design hinges on one property: the framework's own LLM provider keys (used
for agents, the Rules Engine, and embeddings) live in a DEDICATED etcd category
(``/identities/system/system/llm_keys``) and are therefore never part of the
``secrets`` namespace that gets merged into a tool/workflow subprocess env
(``IdentityManager.get_resolved_config`` -> ``core.tasks``/``core.hub``).

These tests exercise the real ``IdentityManager`` against an in-memory fake etcd
client, so the encryption + path separation are the production code paths.
"""
import pytest

from core import auth
from core.auth import IdentityManager
from core.llm_factory import LLM_PROVIDER_KEY_NAMES
from core.llm_providers import PROVIDERS

_LLM_KEYS_PATH = "/identities/system/system/llm_keys"
# Credentials plus global endpoints (OLLAMA_BASE_URL) -- both live in the LLM
# category and must never surface in a tool/workflow secret namespace.
_LLM_KEY_NAMES = (
    {name for names in LLM_PROVIDER_KEY_NAMES.values() for name in names}
    | {name for spec in PROVIDERS.values() for name in spec.base_url_key_names}
)

# The extended credential set added by the provider-registry expansion.
_NEW_PROVIDER_KEYS = {
    "DEEPSEEK_API_KEY": "deepseek-secret",
    "OLLAMA_BASE_URL": "http://ollama.internal:11434",
    "OPENAI_COMPATIBLE_API_KEY": "compat-secret",
    "HF_TOKEN": "hf-secret",
}


class FakeEtcdClient:
    """Minimal in-memory stand-in for pyetcd's client (get/put only)."""

    def __init__(self):
        self.store = {}

    def get(self, path):
        return self.store.get(path), None

    def put(self, path, value):
        self.store[path] = value.encode("utf-8") if isinstance(value, str) else value


@pytest.fixture
def identity_mgr(monkeypatch):
    """Real IdentityManager over a fake etcd client, with a deterministic enc key."""
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    fake = FakeEtcdClient()
    monkeypatch.setattr(auth.pyetcd, "client", lambda host, port: fake)
    mgr = IdentityManager()
    mgr._fake_client = fake  # test-only handle for at-rest assertions
    return mgr


# --- store round-trip ----------------------------------------------------------

def test_llm_provider_keys_default_to_empty_when_unset(identity_mgr):
    assert identity_mgr.get_llm_provider_keys() == {}


def test_llm_provider_keys_round_trip(identity_mgr):
    keys = {"GEMINI_API_KEY": "gem-secret", "OPENAI_API_KEY": "oa-secret", **_NEW_PROVIDER_KEYS}
    identity_mgr.save_llm_provider_keys(keys)
    assert identity_mgr.get_llm_provider_keys() == keys


def test_llm_provider_keys_are_encrypted_at_rest(identity_mgr):
    keys = {
        "GEMINI_API_KEY": "plaintext-should-not-appear",
        "ANTHROPIC_API_KEY": "anthropic-plaintext",
        **_NEW_PROVIDER_KEYS,
    }
    identity_mgr.save_llm_provider_keys(keys)
    raw = identity_mgr._fake_client.store[_LLM_KEYS_PATH]
    for name, value in keys.items():
        assert name.encode() not in raw, f"plaintext key name {name} leaked at rest"
        assert value.encode() not in raw, f"plaintext value for {name} leaked at rest"


def test_llm_provider_keys_live_in_their_own_category(identity_mgr):
    identity_mgr.save_llm_provider_keys({"OPENAI_API_KEY": "oa-secret", **_NEW_PROVIDER_KEYS})
    # The dedicated store is NOT the system secrets category.
    assert identity_mgr.get_identity_config("system", "secrets") == {}


# --- the security property: no leakage into tool/workflow env ------------------

def test_resolved_secrets_never_include_llm_provider_keys(identity_mgr):
    identity_mgr.save_llm_provider_keys({
        "GEMINI_API_KEY": "gem-secret",
        "GOOGLE_API_KEY": "goog-secret",
        "OPENAI_API_KEY": "oa-secret",
        "ANTHROPIC_API_KEY": "anth-secret",
        **_NEW_PROVIDER_KEYS,
    })
    identity_mgr.save_identity_config("system", "secrets", {"SHARED_TOKEN": "sys-token"})
    identity_mgr.save_identity_config("user-1", "secrets", {"GITHUB_TOKEN": "gh-token"})

    resolved = identity_mgr.get_resolved_config("user-1", "secrets")

    assert resolved["GITHUB_TOKEN"] == "gh-token"
    assert resolved["SHARED_TOKEN"] == "sys-token"
    assert _LLM_KEY_NAMES.isdisjoint(resolved.keys())
    assert set(_NEW_PROVIDER_KEYS).isdisjoint(resolved.keys())


def test_llm_provider_base_urls_do_not_leak_into_system_secrets(identity_mgr):
    """OLLAMA_BASE_URL is a non-credential but still LLM-scoped: never a tool secret."""
    identity_mgr.save_llm_provider_keys({"OLLAMA_BASE_URL": "http://ollama.internal:11434"})
    identity_mgr.save_identity_config("system", "secrets", {"SHARED_TOKEN": "sys-token"})

    assert identity_mgr.get_resolved_config("system", "secrets") == {"SHARED_TOKEN": "sys-token"}
    assert identity_mgr.get_resolved_config("user-1", "secrets", keys=["OLLAMA_BASE_URL"]) == {}


def test_resolved_system_secrets_never_include_llm_provider_keys(identity_mgr):
    identity_mgr.save_llm_provider_keys({"OPENAI_API_KEY": "oa-secret", **_NEW_PROVIDER_KEYS})
    identity_mgr.save_identity_config("system", "secrets", {"SHARED_TOKEN": "sys-token"})

    resolved = identity_mgr.get_resolved_config("system", "secrets")
    assert resolved == {"SHARED_TOKEN": "sys-token"}


def test_requesting_an_llm_key_name_as_a_secret_returns_nothing(identity_mgr):
    """Even a tool that explicitly declares e.g. GOOGLE_API_KEY as a required secret
    must not receive the framework's stored key -- it is in a different category."""
    identity_mgr.save_llm_provider_keys({"GOOGLE_API_KEY": "goog-secret"})

    for name in _LLM_KEY_NAMES:
        assert identity_mgr.get_resolved_config("user-1", "secrets", keys=[name]) == {}


def test_simulated_subprocess_env_merge_excludes_llm_provider_keys(identity_mgr):
    """Reproduce core.tasks/core.hub's env merge and assert the LLM keys are absent."""
    identity_mgr.save_llm_provider_keys({
        "GEMINI_API_KEY": "gem-secret",
        "GOOGLE_API_KEY": "goog-secret",
        "OPENAI_API_KEY": "oa-secret",
        "ANTHROPIC_API_KEY": "anth-secret",
        **_NEW_PROVIDER_KEYS,
    })
    identity_mgr.save_identity_config("user-1", "secrets", {"GITHUB_TOKEN": "gh-token"})

    from core.tasks import RESTRICTED_ENV_VARS

    secrets = identity_mgr.get_resolved_config("user-1", "secrets", keys=list(_LLM_KEY_NAMES) + ["GITHUB_TOKEN"])
    env = {"PATH": "/usr/bin"}
    env.update({str(k): str(v) for k, v in secrets.items() if str(k).upper() not in RESTRICTED_ENV_VARS})

    assert env == {"PATH": "/usr/bin", "GITHUB_TOKEN": "gh-token"}
