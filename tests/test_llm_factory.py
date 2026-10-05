# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for core/llm_factory.py — multi-provider LLM resolution.

All model constructions are offline-safe: pydantic-ai providers validate API keys
eagerly (from env) but make no network calls, so each test seeds dummy keys via
monkeypatch and asserts on the constructed Model/ModelSettings shapes.
"""
import pytest

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


@pytest.fixture(autouse=True)
def _dummy_provider_keys(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)


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


def test_resolve_model_ollama_defaults_and_custom_base_url():
    from pydantic_ai.models.ollama import OllamaModel
    m = resolve_model("ollama", "llama3.1")
    assert isinstance(m, OllamaModel)
    assert str(m.client.base_url) == "http://localhost:11434/v1/"
    custom = resolve_model("ollama", "llama3.1", "http://myhost:11434/v1")
    assert str(custom.client.base_url) == "http://myhost:11434/v1/"


def test_resolve_model_openai_compatible_base_url_reaches_provider():
    from pydantic_ai.models.openai import OpenAIChatModel
    m = resolve_model("openai-compatible", "my-local-model", "http://localhost:1234/v1")
    assert isinstance(m, OpenAIChatModel)
    assert str(m.client.base_url) == "http://localhost:1234/v1/"


def test_resolve_model_openai_compatible_requires_base_url():
    with pytest.raises(ProviderConfigError, match="requires a base_url"):
        resolve_model("openai-compatible", "my-local-model")


def test_resolve_model_infers_provider_when_none():
    from pydantic_ai.models.anthropic import AnthropicModel
    assert isinstance(resolve_model(None, "claude-sonnet-4-5"), AnthropicModel)


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


def test_settings_ollama_and_openai_compatible_have_no_thinking_mapping():
    assert build_model_settings("ollama", "llama3.1", "high") is None
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
