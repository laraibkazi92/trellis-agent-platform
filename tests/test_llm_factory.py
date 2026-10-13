# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for core/llm_factory.py — multi-provider LLM resolution.

Provider keys now live in the encrypted etcd store, so every test drives them
through the ``llm_provider_keys`` seam (tests/_llm_key_seam.py) instead of env
vars — no test touches etcd. Model construction is offline-safe: pydantic-ai
providers validate keys eagerly but make no network calls, so tests assert on the
constructed Model/ModelSettings shapes and on which provider was asked for a key.
"""
from types import SimpleNamespace

import pytest

from core import llm_factory
from core import rules_engine
from core.llm_factory import (
    EFFORT_LEVELS,
    GEMINI_2_5_FLASH_BUDGETS,
    GEMINI_2_5_PRO_BUDGETS,
    ProviderConfigError,
    build_model_settings,
    infer_provider,
    resolve_model,
    resolve_provider,
)
from core.models import AgentConfig, ALLOWED_PROVIDERS

# Captured pre-fixture so the precedence test can exercise the real resolver
# (which reads IdentityManager) while the autouse seam is active.
_REAL_GET_PROVIDER_API_KEY = llm_factory.get_provider_api_key


@pytest.fixture(autouse=True)
def _dummy_provider_keys(llm_provider_keys):
    """Seed dummy keys for every test; individual tests may clear/override them."""
    return llm_provider_keys


# --- infer_provider ----------------------------------------------------------

@pytest.mark.parametrize("model,expected", [
    ("gemini-2.5-flash", "google"),
    ("gemini-3.1-pro-preview", "google"),
    ("Gemini-3-Flash-Preview", "google"),  # case-insensitive
    ("claude-sonnet-4-5", "anthropic"),
    ("CLAUDE-opus-4-6", "anthropic"),
    ("gpt-4o", "openai"),
    ("gpt-5-mini", "openai"),
    ("o1-preview", "openai"),
    ("o3-mini", "openai"),
    ("o4-mini", "openai"),
    ("chatgpt-4o-latest", "openai"),
    ("", "google"),   # empty keeps the historical Google default
    (None, "google"),
])
def test_infer_provider_prefix_rules(model, expected):
    assert infer_provider(model) == expected


@pytest.mark.parametrize("model", ["llama3.1", "mistral-large", "qwen2.5:7b", "some-model"])
def test_infer_provider_unknown_model_raises(model):
    with pytest.raises(ProviderConfigError, match="Cannot infer LLM provider"):
        infer_provider(model)


def test_resolve_provider_explicit_wins_and_is_normalized():
    assert resolve_provider("  OpenAI ", "gemini-2.5-flash") == "openai"
    assert resolve_provider(None, "gemini-2.5-flash") == "google"
    assert resolve_provider("", "gpt-4o") == "openai"


def test_resolve_provider_rejects_unknown_explicit_provider():
    with pytest.raises(ProviderConfigError, match="Unknown LLM provider 'bedrock'"):
        resolve_provider("bedrock", "gpt-4o")


# --- AgentConfig provider/base_url validation --------------------------------

def test_agent_config_rejects_invalid_provider():
    with pytest.raises(ValueError, match="Unknown provider 'groq-x'"):
        AgentConfig(name="a", model="gpt-4o", provider="groq-x")


def test_agent_config_allows_none_and_empty_provider():
    assert AgentConfig(name="a", model="gemini-2.5-flash").provider is None
    assert AgentConfig(name="a", model="gemini-2.5-flash", provider="").provider is None


@pytest.mark.parametrize("provider", ALLOWED_PROVIDERS)
def test_agent_config_accepts_every_valid_provider(provider):
    # openai-compatible is the only provider that requires a base_url at load time.
    base_url = "http://compat:8000/v1" if provider == "openai-compatible" else None
    assert AgentConfig(name="a", model="m", provider=provider, base_url=base_url).provider == provider


def test_agent_config_rejects_openai_compatible_without_base_url():
    with pytest.raises(ValueError, match="base_url"):
        AgentConfig(name="a", model="m", provider="openai-compatible")


def test_agent_config_normalizes_provider_and_base_url():
    cfg = AgentConfig(name="a", model="m", provider=" Google ", base_url="  http://x:1234/v1  ")
    assert cfg.provider == "google"
    assert cfg.base_url == "http://x:1234/v1"
    assert AgentConfig(name="a", base_url="   ").base_url is None


# --- resolve_model ------------------------------------------------------------

def test_resolve_model_google():
    from pydantic_ai.models.google import GoogleModel
    assert isinstance(resolve_model("google", "gemini-2.5-flash"), GoogleModel)


def test_resolve_model_openai():
    from pydantic_ai.models.openai import OpenAIChatModel
    assert isinstance(resolve_model("openai", "gpt-4o"), OpenAIChatModel)


def test_resolve_model_anthropic():
    from pydantic_ai.models.anthropic import AnthropicModel
    assert isinstance(resolve_model("anthropic", "claude-sonnet-4-5"), AnthropicModel)


def test_resolve_model_openai_compatible_base_url_reaches_provider():
    from pydantic_ai.models.openai import OpenAIChatModel
    m = resolve_model("openai-compatible", "my-local-model", "http://localhost:1234/v1")
    assert isinstance(m, OpenAIChatModel)
    assert str(m.client.base_url) == "http://localhost:1234/v1/"


def test_resolve_model_openai_compatible_requires_base_url():
    with pytest.raises(ProviderConfigError, match="requires a base_url"):
        resolve_model("openai-compatible", "my-local-model")


def test_resolve_model_openai_compatible_needs_no_key(llm_provider_keys):
    """A keyless compatible endpoint still resolves even when no key is stored."""
    from pydantic_ai.models.openai import OpenAIChatModel
    llm_provider_keys.clear()
    m = resolve_model("openai-compatible", "my-local-model", "http://localhost:1234/v1")
    assert isinstance(m, OpenAIChatModel)
    # It consulted only the compatible provider, which has no required key.
    assert llm_provider_keys.consulted == ["openai-compatible"]
    assert llm_provider_keys.get("openai-compatible") is None


def test_resolve_model_infers_provider_when_none():
    from pydantic_ai.models.anthropic import AnthropicModel
    assert isinstance(resolve_model(None, "claude-sonnet-4-5"), AnthropicModel)


# --- stored-key plumbing -------------------------------------------------------

@pytest.mark.parametrize("provider,model", [
    ("google", "gemini-2.5-flash"),
    ("openai", "gpt-4o"),
    ("anthropic", "claude-sonnet-4-5"),
])
def test_resolve_model_missing_key_raises_pointing_at_admin_ui(provider, model, llm_provider_keys):
    llm_provider_keys.clear()
    with pytest.raises(ProviderConfigError, match="Admin Dashboard -> Global Tool Configuration"):
        resolve_model(provider, model)


# Decoy credentials for every env var pydantic-ai/SDKs would otherwise fall back to.
# If any resolve_model path silently read the environment, these would satisfy it.
_DECOY_ENV_KEYS = {
    "GEMINI_API_KEY": "decoy-gemini-env",
    "GOOGLE_API_KEY": "decoy-google-env",
    "OPENAI_API_KEY": "decoy-openai-env",
    "ANTHROPIC_API_KEY": "decoy-anthropic-env",
}


@pytest.mark.parametrize("provider,model", [
    ("google", "gemini-2.5-flash"),
    ("openai", "gpt-4o"),
    ("anthropic", "claude-sonnet-4-5"),
])
def test_resolve_model_ignores_decoy_env_keys(provider, model, llm_provider_keys, monkeypatch):
    """With a decoy in *every* provider env var and an empty store, the remote
    providers must still refuse to build: the env fallback is unreachable."""
    for name, value in _DECOY_ENV_KEYS.items():
        monkeypatch.setenv(name, value)
    llm_provider_keys.clear()  # the etcd store reports no key for this provider

    with pytest.raises(ProviderConfigError, match=f"No API key configured for provider '{provider}'"):
        resolve_model(provider, model)


def test_resolve_model_openai_compatible_ignores_decoy_env_key(llm_provider_keys, monkeypatch):
    """A keyless compatible endpoint is handed a non-empty placeholder, so the
    OpenAI SDK cannot pick OPENAI_API_KEY up from the environment."""
    monkeypatch.setenv("OPENAI_API_KEY", _DECOY_ENV_KEYS["OPENAI_API_KEY"])
    llm_provider_keys.clear()

    m = resolve_model("openai-compatible", "some-model", "http://localhost:9999/v1")
    # pydantic-ai's OpenAIChatModel.client is the AsyncOpenAI SDK instance itself.
    assert m.client.api_key == "api-key-not-set"
    assert m.client.api_key != _DECOY_ENV_KEYS["OPENAI_API_KEY"]


def test_resolve_model_explicit_api_key_is_used_without_store_lookup(llm_provider_keys):
    """The prefetch ``api_key=`` param is passed straight to the provider and must
    not trigger another store read."""
    llm_provider_keys.clear()
    assert resolve_model("openai", "gpt-4o", api_key="explicit-openai").client.api_key == "explicit-openai"
    assert resolve_model(
        "anthropic", "claude-sonnet-4-5", api_key="explicit-anthropic"
    ).client.api_key == "explicit-anthropic"
    assert resolve_model(
        "google", "gemini-2.5-flash", api_key="explicit-google"
    ).client._api_client.api_key == "explicit-google"
    assert llm_provider_keys.consulted == []


def test_resolve_model_passes_stored_key_to_openai_provider(llm_provider_keys):
    llm_provider_keys["openai"] = "sk-from-etcd"
    m = resolve_model("openai", "gpt-4o")
    assert m.client.api_key == "sk-from-etcd"
    assert llm_provider_keys.consulted == ["openai"]


def test_resolve_model_passes_stored_key_to_google_provider(llm_provider_keys):
    llm_provider_keys["google"] = "goog-from-etcd"
    m = resolve_model("google", "gemini-2.5-flash")
    assert m.client._api_client.api_key == "goog-from-etcd"
    assert llm_provider_keys.consulted == ["google"]


def test_resolve_model_passes_stored_key_to_anthropic_provider(llm_provider_keys):
    llm_provider_keys["anthropic"] = "anth-from-etcd"
    m = resolve_model("anthropic", "claude-sonnet-4-5")
    assert m.client.api_key == "anth-from-etcd"
    assert llm_provider_keys.consulted == ["anthropic"]


def test_resolve_model_consults_store_for_inferred_provider(llm_provider_keys):
    """Provider inference (not just explicit providers) must hit the key store."""
    resolve_model(None, "gemini-2.5-flash")
    assert llm_provider_keys.consulted == ["google"]


def test_gemini_api_key_precedence_over_google_api_key(monkeypatch):
    """The real resolver (not the seam) must prefer GEMINI_API_KEY over GOOGLE_API_KEY."""
    from core import auth

    fake_mgr = SimpleNamespace(
        get_llm_provider_keys=lambda: {"GEMINI_API_KEY": "gemini-wins", "GOOGLE_API_KEY": "google-loses"},
    )
    monkeypatch.setattr(auth, "get_identity_manager", lambda: fake_mgr)
    llm_factory.reset_key_cache()
    try:
        assert _REAL_GET_PROVIDER_API_KEY("google") == "gemini-wins"
    finally:
        llm_factory.reset_key_cache()


# --- build_model_settings ------------------------------------------------------

def test_settings_google_pro_budgets():
    # Pinned literals: a silent change to the budget table must fail here.
    expected = {"low": 1024, "medium": 8192, "high": 16384}
    for level, budget in expected.items():
        s = build_model_settings("google", "gemini-2.5-pro", level)
        assert s["google_thinking_config"] == {"thinking_budget": budget, "include_thoughts": False}


def test_settings_google_flash_budgets():
    expected = {"low": 1024, "medium": 4096, "high": 8192}
    for level, budget in expected.items():
        s = build_model_settings("google", "gemini-2.5-flash", level)
        assert s["google_thinking_config"] == {"thinking_budget": budget, "include_thoughts": False}


def test_settings_google_unknown_level_falls_back_to_medium_budget():
    s = build_model_settings("google", "gemini-2.5-pro", "bogus")
    assert s["google_thinking_config"]["thinking_budget"] == 8192


def test_settings_google_gemini_3_levels():
    s = build_model_settings("google", "gemini-3.1-pro-preview", "High")
    assert s["google_thinking_config"] == {"thinking_level": "high", "include_thoughts": False}


@pytest.mark.parametrize("model", ["gemini-3.1-flash-lite-preview", "gemini-2.5-flash-lite"])
def test_settings_google_lite_models_never_think(model):
    assert build_model_settings("google", model, "high") is None


@pytest.mark.parametrize("level", ["none", "n/a", "", None])
def test_settings_disabled_or_missing_level_returns_none(level):
    assert build_model_settings("google", "gemini-2.5-pro", level) is None
    assert build_model_settings("anthropic", "claude-sonnet-4-5", level) is None
    assert build_model_settings("openai", "gpt-4o", level) is None


@pytest.mark.parametrize("level", EFFORT_LEVELS)
def test_settings_anthropic_maps_effort(level):
    s = build_model_settings("anthropic", "claude-sonnet-4-5", level)
    assert s["anthropic_effort"] == level


@pytest.mark.parametrize("level", EFFORT_LEVELS)
def test_settings_openai_maps_reasoning_effort(level):
    s = build_model_settings("openai", "gpt-4o", level)
    assert s["openai_reasoning_effort"] == level


def test_settings_anthropic_and_openai_reject_non_effort_levels():
    # "bogus" isn't in the providers' Literal effort sets — no settings, not a crash.
    assert build_model_settings("anthropic", "claude-sonnet-4-5", "bogus") is None
    assert build_model_settings("openai", "gpt-4o", "bogus") is None


def test_settings_openai_compatible_has_no_thinking_mapping():
    assert build_model_settings("openai-compatible", "m", "high") is None


# --- rules engine provider resolution -----------------------------------------

def test_rules_engine_provider_defaults_to_inference(monkeypatch):
    monkeypatch.setattr(rules_engine, "_cached_provider_override", None, raising=False)
    monkeypatch.setattr(rules_engine, "_model_overrides_checked_at", rules_engine.time.monotonic(), raising=False)
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_PROVIDER", "")
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_MODEL", "gemini-2.5-flash")
    assert rules_engine._resolve_evaluation_provider() == "google"

    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_MODEL", "gpt-4o-mini")
    assert rules_engine._resolve_evaluation_provider() == "openai"


def test_rules_engine_provider_env_then_etcd_precedence(monkeypatch):
    monkeypatch.setattr(rules_engine, "_cached_provider_override", None, raising=False)
    monkeypatch.setattr(rules_engine, "_cached_base_url_override", None, raising=False)
    monkeypatch.setattr(rules_engine, "_model_overrides_checked_at", rules_engine.time.monotonic(), raising=False)

    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_PROVIDER", "anthropic")
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_BASE_URL", "")
    assert rules_engine._resolve_evaluation_provider() == "anthropic"
    assert rules_engine._resolve_evaluation_base_url() is None

    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_BASE_URL", "http://env-host:4000/v1")
    assert rules_engine._resolve_evaluation_base_url() == "http://env-host:4000/v1"

    monkeypatch.setattr(rules_engine, "_cached_provider_override", "openai-compatible")
    monkeypatch.setattr(rules_engine, "_cached_base_url_override", "http://etcd-host:8000/v1")
    assert rules_engine._resolve_evaluation_provider() == "openai-compatible"
    assert rules_engine._resolve_evaluation_base_url() == "http://etcd-host:8000/v1"


def test_rules_engine_provider_uninferrable_model_raises(monkeypatch):
    """No vendor guessing: an uninferrable model must raise ProviderConfigError
    (evaluate_rules catches it and fails open) rather than silently egressing
    the query and rule catalog to a default provider."""
    monkeypatch.setattr(rules_engine, "_cached_provider_override", None, raising=False)
    monkeypatch.setattr(rules_engine, "_model_overrides_checked_at", rules_engine.time.monotonic(), raising=False)
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_PROVIDER", "")
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_MODEL", "llama3.1")

    with pytest.raises(ProviderConfigError):
        rules_engine._resolve_evaluation_provider()


def test_rules_engine_decider_pins_low_effort_for_reasoning_providers(monkeypatch):
    """OpenAI/Anthropic reasoning models default to medium effort, which would
    blow the sub-3s evaluation timeout — the decider must pin 'low'."""
    class FakeAgent:
        def __init__(self, model, **kwargs):
            self.model = model
            self.kwargs = kwargs

    monkeypatch.setattr(rules_engine, "Agent", FakeAgent)
    for provider in ("openai", "anthropic"):
        monkeypatch.setattr(rules_engine, "_cached_provider_override", provider, raising=False)
        monkeypatch.setattr(rules_engine, "_cached_base_url_override", None, raising=False)
        monkeypatch.setattr(rules_engine, "_model_overrides_checked_at", rules_engine.time.monotonic(), raising=False)
        monkeypatch.setattr(rules_engine, "RULES_EVALUATION_MODEL", "claude-sonnet-4-5" if provider == "anthropic" else "gpt-5.6-sol")

        agent = rules_engine._build_evaluation_agent()
        settings = agent.kwargs["model_settings"]
        assert settings is not None
        expected_key = "anthropic_effort" if provider == "anthropic" else "openai_reasoning_effort"
        assert settings[expected_key] == "low"


def test_rules_engine_build_evaluation_agent_uses_resolved_provider(monkeypatch):
    from pydantic_ai.models.openai import OpenAIChatModel

    class FakeAgent:
        def __init__(self, model, **kwargs):
            self.model = model
            self.kwargs = kwargs

    monkeypatch.setattr(rules_engine, "Agent", FakeAgent)
    monkeypatch.setattr(rules_engine, "_cached_provider_override", "openai-compatible", raising=False)
    monkeypatch.setattr(rules_engine, "_cached_base_url_override", "http://etcd-host:8000/v1", raising=False)
    monkeypatch.setattr(rules_engine, "_model_overrides_checked_at", rules_engine.time.monotonic(), raising=False)
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_MODEL", "some-model")

    agent = rules_engine._build_evaluation_agent()
    assert isinstance(agent.model, OpenAIChatModel)
    assert str(agent.model.client.base_url) == "http://etcd-host:8000/v1/"
    # Non-Google deciders carry no thinking settings.
    assert agent.kwargs["model_settings"] is None


def test_rules_engine_build_evaluation_agent_google_keeps_zero_thinking_budget(monkeypatch):
    from pydantic_ai.models.google import GoogleModel

    class FakeAgent:
        def __init__(self, model, **kwargs):
            self.model = model
            self.kwargs = kwargs

    monkeypatch.setattr(rules_engine, "Agent", FakeAgent)
    monkeypatch.setattr(rules_engine, "_cached_provider_override", None, raising=False)
    monkeypatch.setattr(rules_engine, "_model_overrides_checked_at", rules_engine.time.monotonic(), raising=False)
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_PROVIDER", "")
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_MODEL", "gemini-2.5-flash")

    agent = rules_engine._build_evaluation_agent()
    assert isinstance(agent.model, GoogleModel)
    assert agent.kwargs["model_settings"]["google_thinking_config"] == {
        "thinking_budget": 0, "include_thoughts": False
    }
