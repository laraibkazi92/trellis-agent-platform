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
from core.llm_providers import FRAMEWORK_PROVIDER_KEY_ENV, PROVIDERS
from core.models import AgentConfig, ALLOWED_PROVIDERS
from _llm_key_seam import DEFAULT_TEST_KEYS

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
    ("deepseek-chat", "deepseek"),
    ("deepseek-reasoner", "deepseek"),
    ("DeepSeek-Chat", "deepseek"),  # case-insensitive
    ("kimi-k2-0905-preview", "moonshotai"),
    ("Kimi-K2-0905-Preview", "moonshotai"),  # case-insensitive
    ("glm-4.6", "zai"),
    ("GLM-4.6", "zai"),  # case-insensitive
    ("qwen-max", "alibaba"),
    ("Qwen-Max", "alibaba"),  # case-insensitive
    ("qwen2.5:7b", "alibaba"),  # ollama-style tag still infers from the prefix
    ("", "google"),   # empty keeps the historical Google default
    (None, "google"),
])
def test_infer_provider_prefix_rules(model, expected):
    assert infer_provider(model) == expected


@pytest.mark.parametrize("model", ["llama3.1", "mistral-large", "some-model"])
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


# Expected Model class per registry id — pydantic-ai's dispatch, pinned so a
# pydantic-ai upgrade that silently changes the request shape fails here.
_EXPECTED_MODEL_CLASSES = {
    "google": "GoogleModel",
    "openai": "OpenAIChatModel",
    "anthropic": "AnthropicModel",
    "deepseek": "OpenAIChatModel",
    "fireworks": "OpenAIChatModel",
    "together": "OpenAIChatModel",
    "moonshotai": "OpenAIChatModel",
    "vercel": "OpenAIChatModel",
    "zai": "ZaiModel",
    "openrouter": "OpenRouterModel",
    "alibaba": "OpenAIChatModel",
    "ollama": "OllamaModel",
    "litellm": "OpenAIChatModel",
    "huggingface": "HuggingFaceModel",
    "openai-compatible": "OpenAIChatModel",
}


def test_expected_model_class_matrix_covers_every_provider():
    assert set(_EXPECTED_MODEL_CLASSES) == set(PROVIDERS)


@pytest.mark.parametrize("provider", list(PROVIDERS), ids=lambda provider: provider)
def test_resolve_model_per_provider(provider, llm_provider_keys):
    """Every registered provider resolves to a live Model and consults its own key."""
    spec = PROVIDERS[provider]
    model_name = spec.known_models[0] if spec.known_models else "m"
    base_url = "http://compat:1234/v1" if spec.requires_base_url else None

    model = resolve_model(provider, model_name, base_url)

    assert type(model).__name__ == _EXPECTED_MODEL_CLASSES[provider]
    assert provider in llm_provider_keys.consulted
    if base_url:
        assert str(model.client.base_url).rstrip("/") == base_url


def test_resolve_model_wraps_sdk_model_name_validation(llm_provider_keys):
    """SDK-level model-id validation must surface as ProviderConfigError, not a bare
    crash: openrouter rejects unprefixed ids and the host maps that to a 400."""
    with pytest.raises(ProviderConfigError, match="prefixed with the upstream provider"):
        resolve_model("openrouter", "gpt-4o")


def test_resolve_model_openai_stays_on_chat_completions(llm_provider_keys):
    """openai must keep dispatching to OpenAIChatModel, never OpenAIResponsesModel."""
    from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModel

    model = resolve_model("openai", "gpt-5")
    assert isinstance(model, OpenAIChatModel)
    assert not isinstance(model, OpenAIResponsesModel)


# --- stored-key plumbing -------------------------------------------------------

@pytest.mark.parametrize("provider,model", [
    ("google", "gemini-2.5-flash"),
    ("openai", "gpt-4o"),
    ("anthropic", "claude-sonnet-4-5"),
    ("deepseek", "deepseek-chat"),
])
def test_resolve_model_missing_key_raises_pointing_at_admin_ui(provider, model, llm_provider_keys):
    llm_provider_keys.clear()
    with pytest.raises(ProviderConfigError) as excinfo:
        resolve_model(provider, model)

    message = str(excinfo.value)
    assert f"provider '{provider}'" in message
    assert "Admin -> LLM Providers" in message
    for key_name in PROVIDERS[provider].key_names:
        assert key_name in message


# Decoy credentials/endpoints for every env var pydantic-ai/SDKs would otherwise
# fall back to. If any resolve_model path silently read the environment, these
# would satisfy it. Generated from the registry so a new provider can't be missed;
# OLLAMA_BASE_URL is included because 2.57 hard-errors without an explicit
# base_url and would otherwise reach for it.
_DECOY_ENV_VALUES = {name: f"from-env-{name}" for name in sorted(FRAMEWORK_PROVIDER_KEY_ENV)}
_DECOY_ENV_VALUES["OLLAMA_BASE_URL"] = "from-env-OLLAMA_BASE_URL"


def _apply_decoy_env(monkeypatch):
    for name, value in _DECOY_ENV_VALUES.items():
        monkeypatch.setenv(name, value)


def test_decoy_env_covers_every_registry_key_name():
    assert set(FRAMEWORK_PROVIDER_KEY_ENV) <= set(_DECOY_ENV_VALUES)
    assert "OLLAMA_BASE_URL" in _DECOY_ENV_VALUES


@pytest.mark.parametrize("provider,model", [
    ("google", "gemini-2.5-flash"),
    ("openai", "gpt-4o"),
    ("anthropic", "claude-sonnet-4-5"),
])
def test_resolve_model_ignores_decoy_env_keys(provider, model, llm_provider_keys, monkeypatch):
    """With a decoy in *every* provider env var and an empty store, the remote
    providers must still refuse to build: the env fallback is unreachable."""
    _apply_decoy_env(monkeypatch)
    llm_provider_keys.clear()  # the etcd store reports no key for this provider

    with pytest.raises(ProviderConfigError, match=f"No API key configured for provider '{provider}'"):
        resolve_model(provider, model)


@pytest.mark.parametrize(
    "spec",
    [spec for spec in PROVIDERS.values() if spec.requires_key],
    ids=lambda spec: spec.id,
)
def test_resolve_model_keyed_providers_never_read_env(spec, llm_provider_keys, monkeypatch):
    """No SDK env fallback exists for any keyed provider: an empty store raises
    with the Admin -> LLM Providers pointer and the provider's key names."""
    _apply_decoy_env(monkeypatch)
    llm_provider_keys.clear()

    with pytest.raises(ProviderConfigError) as excinfo:
        resolve_model(spec.id, spec.known_models[0])

    message = str(excinfo.value)
    assert "Admin -> LLM Providers" in message
    for key_name in spec.key_names:
        assert key_name in message
    for value in _DECOY_ENV_VALUES.values():
        assert value not in message, f"decoy env value {value!r} leaked into the error"


@pytest.mark.parametrize("provider,model,base_url,placeholder", [
    ("ollama", "llama3.2", None, "api-key-not-set"),
    ("litellm", "openai/gpt-4o", None, "litellm-placeholder"),
    ("openai-compatible", "m", "http://localhost:9999/v1", "api-key-not-set"),
])
def test_resolve_model_keyless_providers_use_placeholders_not_env(
    provider, model, base_url, placeholder, llm_provider_keys, monkeypatch
):
    """Keyless providers build with an explicit placeholder key -- never an env value."""
    _apply_decoy_env(monkeypatch)
    llm_provider_keys.clear()

    built = resolve_model(provider, model, base_url) if base_url else resolve_model(provider, model)

    assert built.client.api_key == placeholder
    assert built.client.api_key not in _DECOY_ENV_VALUES.values()


def test_resolve_model_openai_compatible_ignores_decoy_env_key(llm_provider_keys, monkeypatch):
    """A keyless compatible endpoint is handed a non-empty placeholder, so the
    OpenAI SDK cannot pick OPENAI_API_KEY up from the environment."""
    monkeypatch.setenv("OPENAI_API_KEY", _DECOY_ENV_VALUES["OPENAI_API_KEY"])
    llm_provider_keys.clear()

    m = resolve_model("openai-compatible", "some-model", "http://localhost:9999/v1")
    # pydantic-ai's OpenAIChatModel.client is the AsyncOpenAI SDK instance itself.
    assert m.client.api_key == "api-key-not-set"
    assert m.client.api_key != _DECOY_ENV_VALUES["OPENAI_API_KEY"]


@pytest.mark.parametrize("provider,model", [
    ("deepseek", "deepseek-chat"),
    ("openai", "gpt-4o"),
    ("anthropic", "claude-sonnet-4-5"),
])
def test_resolve_model_prefers_store_over_decoy_env(provider, model, llm_provider_keys, monkeypatch):
    """Decoy env present AND a store key present: the store key must win."""
    _apply_decoy_env(monkeypatch)

    model_instance = resolve_model(provider, model)

    assert model_instance.client.api_key == DEFAULT_TEST_KEYS[provider]
    assert model_instance.client.api_key not in _DECOY_ENV_VALUES.values()


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


# --- openai-compatible key fallback --------------------------------------------

def test_resolve_model_openai_compatible_uses_stored_key(llm_provider_keys):
    llm_provider_keys["openai-compatible"] = "compat-from-store"
    m = resolve_model("openai-compatible", "m", "http://x/v1")
    assert m.client.api_key == "compat-from-store"
    assert llm_provider_keys.consulted == ["openai-compatible"]


@pytest.mark.parametrize("store,expected", [
    ({"OPENAI_API_KEY": "legacy-openai"}, "legacy-openai"),
    ({"OPENAI_API_KEY": "legacy-openai", "OPENAI_COMPATIBLE_API_KEY": "compat-wins"}, "compat-wins"),
])
def test_resolve_model_openai_compatible_key_fallback(store, expected, monkeypatch):
    """The real resolver (not the seam) falls back to OPENAI_API_KEY and prefers
    OPENAI_COMPATIBLE_API_KEY when both are stored (registry precedence order)."""
    from core import auth

    fake_mgr = SimpleNamespace(get_llm_provider_keys=lambda: dict(store))
    monkeypatch.setattr(auth, "get_identity_manager", lambda: fake_mgr)
    monkeypatch.setattr(llm_factory, "get_provider_api_key", _REAL_GET_PROVIDER_API_KEY)
    llm_factory.reset_key_cache()
    try:
        m = resolve_model("openai-compatible", "m", "http://x/v1")
        assert m.client.api_key == expected
    finally:
        llm_factory.reset_key_cache()


# --- keyless endpoints ---------------------------------------------------------

def test_resolve_model_ollama_defaults_to_localhost_ignoring_env(llm_provider_keys, monkeypatch):
    from pydantic_ai.models.ollama import OllamaModel

    monkeypatch.setenv("OLLAMA_BASE_URL", "http://poisoned-env:11434")
    m = resolve_model("ollama", "llama3.2")

    assert isinstance(m, OllamaModel)
    assert str(m.client.base_url).rstrip("/") == "http://localhost:11434"
    assert "poisoned-env" not in str(m.client.base_url)


def test_resolve_model_ollama_uses_etcd_base_url_over_default(llm_provider_keys, monkeypatch):
    from pydantic_ai.models.ollama import OllamaModel

    monkeypatch.setenv("OLLAMA_BASE_URL", "http://poisoned-env:11434")
    llm_provider_keys.base_urls["ollama"] = "http://etcd-ollama:11434"
    m = resolve_model("ollama", "llama3.2")

    assert isinstance(m, OllamaModel)
    assert str(m.client.base_url).rstrip("/") == "http://etcd-ollama:11434"


def test_resolve_model_litellm_falls_back_to_its_local_endpoint(llm_provider_keys):
    """A litellm model with no endpoint used to fall through to the OpenAI SDK's
    default (https://api.openai.com/v1), carrying the gateway key with it."""
    m = resolve_model("litellm", "openai/gpt-4o")

    assert str(m.client.base_url).rstrip("/") == "http://localhost:4000"


def test_resolve_model_litellm_honours_an_explicit_endpoint(llm_provider_keys):
    m = resolve_model("litellm", "openai/gpt-4o", "http://litellm.internal:4000")

    assert str(m.client.base_url).rstrip("/") == "http://litellm.internal:4000"


def test_seam_install_accepts_base_urls(monkeypatch):
    """The seam's ``base_urls`` hook is how a global etcd endpoint is simulated."""
    from pydantic_ai.models.ollama import OllamaModel

    from _llm_key_seam import install_provider_keys

    install_provider_keys(monkeypatch, base_urls={"ollama": "http://seam-ollama:11434"})
    m = resolve_model("ollama", "llama3.2")

    assert isinstance(m, OllamaModel)
    assert str(m.client.base_url).rstrip("/") == "http://seam-ollama:11434"


def test_resolve_model_openai_compatible_keyless_uses_placeholder(llm_provider_keys):
    llm_provider_keys.clear()
    m = resolve_model("openai-compatible", "m", base_url="http://x/v1")
    assert m.client.api_key == "api-key-not-set"


# --- model-name hygiene --------------------------------------------------------

def test_resolve_model_strips_matching_provider_prefix(llm_provider_keys):
    model = resolve_model("openai", "openai:gpt-4o")
    assert model.model_name == "gpt-4o"


def test_resolve_model_rejects_remaining_colon(llm_provider_keys):
    with pytest.raises(ProviderConfigError, match="may not contain ':'"):
        resolve_model("openai", "a:b")


def test_resolve_model_rejects_base_url_for_providers_that_do_not_support_it(llm_provider_keys):
    with pytest.raises(ProviderConfigError, match="does not accept a base_url"):
        resolve_model("deepseek", "deepseek-chat", base_url="http://x")


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


@pytest.mark.parametrize("provider", [
    "deepseek",
    "zai",
    "openrouter",
    "ollama",
    "huggingface",
    "litellm",
    "openai-compatible",
    "together",
    "fireworks",
    "moonshotai",
    "alibaba",
])
def test_settings_none_style_providers_never_get_reasoning_effort(provider):
    """thinking_style='none' providers must never receive openai_reasoning_effort
    (generic OpenAI-compatible endpoints reject it with a 400)."""
    spec = PROVIDERS[provider]
    model = spec.known_models[0] if spec.known_models else "m"
    assert build_model_settings(provider, model, "high") is None


@pytest.mark.parametrize("level", EFFORT_LEVELS)
def test_settings_vercel_maps_reasoning_effort(level):
    s = build_model_settings("vercel", "openai/gpt-5", level)
    assert s["openai_reasoning_effort"] == level


def test_settings_google_and_anthropic_styles_are_unchanged():
    """Pinned regressions: google carries a thinking budget, anthropic an effort."""
    google = build_model_settings("google", "gemini-2.5-flash", "high")
    assert google["google_thinking_config"]["thinking_budget"] == GEMINI_2_5_FLASH_BUDGETS["high"]
    anthropic = build_model_settings("anthropic", "claude-sonnet-4-5", "high")
    assert anthropic["anthropic_effort"] == "high"
    assert "openai_reasoning_effort" not in anthropic


@pytest.mark.parametrize("provider,model", [
    ("deepseek", "deepseek-chat"),
    ("zai", "glm-4.6"),
    ("openrouter", "openai/gpt-5"),
    ("ollama", "llama3.2"),
    ("huggingface", "meta-llama/Llama-3.3-70B-Instruct"),
    ("litellm", "openai/gpt-4o"),
    ("openai-compatible", "m"),
    ("together", "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
    ("fireworks", "accounts/fireworks/models/llama-v3p3-70b-instruct"),
    ("moonshotai", "kimi-k2-0905-preview"),
    ("alibaba", "qwen-max"),
    ("vercel", "openai/gpt-5"),
])
@pytest.mark.parametrize("level", ["none", "n/a", ""])
def test_settings_none_or_na_level_returns_none_for_every_provider(provider, model, level):
    assert build_model_settings(provider, model, level) is None


# --- rules engine provider resolution -----------------------------------------

def test_rules_engine_provider_defaults_to_inference(monkeypatch):
    monkeypatch.setattr(rules_engine, "_cached_provider_override", None, raising=False)
    monkeypatch.setattr(rules_engine, "_cached_model_override", None, raising=False)
    monkeypatch.setattr(rules_engine, "_model_overrides_checked_at", rules_engine.time.monotonic(), raising=False)
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_PROVIDER", "")
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_MODEL", "gemini-2.5-flash")
    assert rules_engine._resolve_evaluation_provider() == "google"

    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_MODEL", "gpt-4o-mini")
    assert rules_engine._resolve_evaluation_provider() == "openai"


def test_rules_engine_provider_infers_from_the_resolved_model(monkeypatch):
    """The provider and model overrides refresh on independent cache cycles, so the
    inference must use the resolved model -- otherwise a cached ``deepseek-chat``
    pairs with the env default's Google endpoint and egresses there."""
    monkeypatch.setattr(rules_engine, "_cached_provider_override", None, raising=False)
    monkeypatch.setattr(rules_engine, "_cached_model_override", "deepseek-chat", raising=False)
    monkeypatch.setattr(rules_engine, "_model_overrides_checked_at", rules_engine.time.monotonic(), raising=False)
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_PROVIDER", "")
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_MODEL", "gemini-2.5-flash")

    assert rules_engine._resolve_evaluation_provider() == "deepseek"
    assert rules_engine._resolve_evaluation_settings()[:2] == ("deepseek", "deepseek-chat")


def test_rules_engine_provider_env_then_etcd_precedence(monkeypatch):
    monkeypatch.setattr(rules_engine, "_cached_provider_override", None, raising=False)
    monkeypatch.setattr(rules_engine, "_cached_model_override", None, raising=False)
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
    monkeypatch.setattr(rules_engine, "_cached_model_override", None, raising=False)
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


def test_rules_engine_build_evaluation_agent_uses_threaded_model_name(monkeypatch):
    """The decider must build the model the caller resolved, not re-read the cache
    (a refresh in between would pair one provider with another vendor's model)."""
    captured = {}

    class FakeAgent:
        def __init__(self, model, **kwargs):
            self.model = model

    def fake_resolve_model(provider, model, base_url, api_key=None):
        captured.update(provider=provider, model=model, base_url=base_url)
        return object()

    monkeypatch.setattr(rules_engine, "Agent", FakeAgent)
    monkeypatch.setattr(rules_engine, "resolve_model", fake_resolve_model)
    monkeypatch.setattr(rules_engine, "RULES_EVALUATION_MODEL", "gemini-2.5-flash")

    rules_engine._build_evaluation_agent(
        provider="deepseek", base_url=None, api_key="k", model_name="deepseek-chat"
    )

    assert captured == {"provider": "deepseek", "model": "deepseek-chat", "base_url": None}


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


# --- review hardening: inference ambiguity & openai-compatible model ids ------

@pytest.mark.parametrize("model", ["openai/gpt-5", "deepseek/deepseek-chat", "Qwen/Qwen2.5-72B-Instruct-Turbo"])
def test_infer_provider_rejects_vendor_prefixed_ids(model):
    """Aggregator ids are ambiguous between vendors; never guess a provider."""
    with pytest.raises(ProviderConfigError, match="Vendor-prefixed model ids"):
        infer_provider(model)


def test_openai_compatible_allows_colons_in_model_ids():
    """This path bypasses infer_model, so `llama3.2:3b` is a valid local id."""
    m = resolve_model("openai-compatible", "llama3.2:3b", "http://localhost:11434/v1")
    assert m.model_name == "llama3.2:3b"


def test_huggingface_ignores_decoy_hf_token(llm_provider_keys, monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "from-env-HF_TOKEN")
    model = resolve_model("huggingface", "meta-llama/Llama-3.3-70B-Instruct")
    assert model.client.token == llm_provider_keys["huggingface"]
    assert model.client.token != "from-env-HF_TOKEN"
