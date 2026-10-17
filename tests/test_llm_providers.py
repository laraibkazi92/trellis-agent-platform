# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for core/llm_providers.py — the provider registry.

Covers registry integrity, key-name parity with the derived maps, and the
``provider_ui_specs()`` projection the templates/inline JS consume. Everything
here is pure metadata: no SDK is built and no network or etcd access happens.
"""
import json
import re

import pytest

from core.llm_providers import (
    ALLOWED_PROVIDERS,
    FRAMEWORK_PROVIDER_KEY_ENV,
    LLM_PROVIDER_KEY_NAMES,
    PROVIDERS,
    ProviderConfigError,
    ProviderSpec,
    build_provider,
    default_model_for,
    provider_is_usable,
    provider_ui_specs,
    sdk_installed,
)
from _llm_key_seam import DEFAULT_TEST_KEYS

EXPECTED_PROVIDER_COUNT = 15
KEYLESS_PROVIDERS = {"ollama", "litellm", "openai-compatible"}
THINKING_STYLES = {"google", "anthropic", "openai-effort", "none"}

EXPECTED_SPEC_KEYS = (
    "id",
    "label",
    "pydantic_name",
    "requires_key",
    "supports_base_url",
    "requires_base_url",
    "base_url_placeholder",
    "default_base_url",
    "canonical_key",
    "key_names",
    "base_url_key",
    "thinking_style",
    "known_models",
    "default_model",
    "model_prefixes",
    "sdk_extra",
    "sdk_installed",
    "note",
)


def _scalars(value):
    """Yield every scalar (and dict key) nested inside ``value``."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _scalars(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _scalars(item)
    elif value is not None:
        yield value


# --- 1. Registry integrity ---------------------------------------------------

def test_registry_has_exactly_the_expected_providers():
    assert len(PROVIDERS) == EXPECTED_PROVIDER_COUNT
    ids = [spec.id for spec in PROVIDERS.values()]
    assert len(set(ids)) == len(ids), f"duplicate provider ids: {ids}"
    assert ALLOWED_PROVIDERS == tuple(PROVIDERS)


def test_spec_id_matches_dict_key_and_label_is_present():
    for key, spec in PROVIDERS.items():
        assert isinstance(spec, ProviderSpec)
        assert spec.id == key
        assert spec.label.strip(), f"provider '{key}' has an empty label"


def test_key_names_are_uppercase_env_style():
    for spec in PROVIDERS.values():
        for name in spec.key_names:
            assert re.fullmatch(r"[A-Z0-9_]+", name), f"{spec.id}: bad key name '{name}'"


def test_openai_uses_chat_dispatcher():
    assert PROVIDERS["openai"].pydantic_name == "openai-chat"


def test_only_openai_compatible_requires_a_base_url():
    requiring = {spec.id for spec in PROVIDERS.values() if spec.requires_base_url}
    assert requiring == {"openai-compatible"}


def test_only_ollama_reads_a_base_url_env_name():
    with_keys = {spec.id for spec in PROVIDERS.values() if spec.base_url_key_names}
    assert with_keys == {"ollama"}
    assert PROVIDERS["ollama"].base_url_key_names == ("OLLAMA_BASE_URL",)


def test_ollama_default_base_url():
    assert PROVIDERS["ollama"].default_base_url == "http://localhost:11434"


def test_litellm_has_a_default_base_url():
    assert PROVIDERS["litellm"].default_base_url == "http://localhost:4000"


def test_known_models_have_no_colon_qualifier():
    # Model ids are plain: the 'provider:model' form is rejected by model hygiene.
    for spec in PROVIDERS.values():
        for model in spec.known_models:
            assert ":" not in model, f"{spec.id}: model '{model}' contains ':'"


def test_thinking_style_is_known():
    for spec in PROVIDERS.values():
        assert spec.thinking_style in THINKING_STYLES, f"{spec.id}: {spec.thinking_style}"


def test_base_url_support_is_consistent_with_the_requirement():
    for spec in PROVIDERS.values():
        if not spec.supports_base_url:
            assert not spec.requires_base_url, f"{spec.id} requires an unsupported base_url"


# --- registry default models & usability -------------------------------------

def test_default_model_is_curated_or_none():
    for spec in PROVIDERS.values():
        if spec.default_model is not None:
            assert spec.default_model in spec.known_models, (
                f"{spec.id}: default_model {spec.default_model!r} is not in known_models"
            )


def test_only_openai_compatible_has_no_default_model():
    assert PROVIDERS["openai-compatible"].default_model is None
    without_default = {spec.id for spec in PROVIDERS.values() if spec.default_model is None}
    assert without_default == {"openai-compatible"}


def test_ui_specs_expose_default_model_matching_the_spec():
    for entry, spec in zip(provider_ui_specs(), PROVIDERS.values()):
        assert entry["default_model"] == spec.default_model, spec.id


def test_default_model_for_known_and_unknown_providers():
    assert default_model_for("google") == "gemini-2.5-flash"
    assert default_model_for("unknown") is None
    assert default_model_for("") is None


# The normative §5 table: a curated-but-wrong default (e.g. a pricier tier) must fail.
EXPECTED_DEFAULT_MODELS = {
    "google": "gemini-2.5-flash",
    "openai": "gpt-5-mini",
    "anthropic": "claude-haiku-4-5",
    "deepseek": "deepseek-chat",
    "fireworks": "accounts/fireworks/models/llama-v3p3-70b-instruct",
    "together": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "moonshotai": "kimi-latest",
    "vercel": "google/gemini-2.5-flash",
    "zai": "glm-4.5-air",
    "openrouter": "deepseek/deepseek-chat",
    "alibaba": "qwen-plus",
    "ollama": "llama3.2",
    "litellm": "openai/gpt-4o",
    "huggingface": "meta-llama/Llama-3.3-70B-Instruct",
    "openai-compatible": None,
}


def test_default_models_match_the_spec_table():
    assert {spec.id: spec.default_model for spec in PROVIDERS.values()} == EXPECTED_DEFAULT_MODELS


def test_provider_is_usable_requires_a_credential_for_keyed_providers():
    deepseek = PROVIDERS["deepseek"]
    assert sdk_installed(deepseek) is True
    assert provider_is_usable(deepseek, {}) is False
    assert provider_is_usable(deepseek, {"DEEPSEEK_API_KEY": "x"}) is True


def test_provider_is_usable_is_false_without_the_sdk(monkeypatch):
    import core.llm_providers as registry

    monkeypatch.setattr(registry, "sdk_installed", lambda spec: False)
    assert provider_is_usable(PROVIDERS["huggingface"], {"HF_TOKEN": "x"}) is False


def test_provider_is_usable_when_the_endpoint_is_supplied_inline():
    # ollama has a registry default endpoint; litellm/openai-compatible take one inline
    # with the default triple, so endpoint satisfiability is enforced at save time (§8).
    assert provider_is_usable(PROVIDERS["ollama"], {}) is True
    assert provider_is_usable(PROVIDERS["litellm"], {}) is True
    assert provider_is_usable(PROVIDERS["openai-compatible"], {}) is True


# --- 2. Key-name parity ------------------------------------------------------

def test_allowed_providers_and_key_names_cover_the_registry():
    assert ALLOWED_PROVIDERS == tuple(PROVIDERS)
    assert set(LLM_PROVIDER_KEY_NAMES) == set(PROVIDERS)
    for provider_id, spec in PROVIDERS.items():
        assert LLM_PROVIDER_KEY_NAMES[provider_id] == spec.key_names


def test_framework_provider_key_env_is_the_union_of_key_names():
    union = frozenset(name for spec in PROVIDERS.values() for name in spec.key_names)
    assert FRAMEWORK_PROVIDER_KEY_ENV == union


def test_legacy_key_names_keep_their_precedence():
    assert LLM_PROVIDER_KEY_NAMES["google"][0] == "GEMINI_API_KEY"
    assert "GOOGLE_API_KEY" in LLM_PROVIDER_KEY_NAMES["google"]
    assert LLM_PROVIDER_KEY_NAMES["anthropic"][0] == "ANTHROPIC_API_KEY"
    assert LLM_PROVIDER_KEY_NAMES["openai"][0] == "OPENAI_API_KEY"
    assert LLM_PROVIDER_KEY_NAMES["openai-compatible"][0] == "OPENAI_COMPATIBLE_API_KEY"
    assert "OPENAI_API_KEY" in LLM_PROVIDER_KEY_NAMES["openai-compatible"]


# --- 3. provider_ui_specs() --------------------------------------------------

def test_ui_specs_are_json_round_trippable():
    specs = provider_ui_specs()
    dumped = json.dumps(specs)
    round_tripped = json.loads(dumped)
    assert dumped == json.dumps(round_tripped)
    assert [entry["id"] for entry in round_tripped] == [spec["id"] for spec in specs]


def test_ui_specs_ids_follow_registry_order():
    specs = provider_ui_specs()
    assert len(specs) == EXPECTED_PROVIDER_COUNT
    assert [entry["id"] for entry in specs] == list(PROVIDERS)


def test_ui_specs_expose_the_expected_keys():
    for entry in provider_ui_specs():
        assert set(entry) == set(EXPECTED_SPEC_KEYS), entry["id"]


def test_ui_specs_canonical_and_base_url_keys_match_the_spec():
    for entry, spec in zip(provider_ui_specs(), PROVIDERS.values()):
        assert entry["canonical_key"] == (spec.key_names[0] if spec.key_names else None)
        assert entry["base_url_key"] == (spec.base_url_key_names[0] if spec.base_url_key_names else None)
        assert entry["key_names"] == list(spec.key_names)


def test_ui_specs_contain_metadata_only():
    secret_values = set(DEFAULT_TEST_KEYS.values())
    for entry in provider_ui_specs():
        assert "api_key" not in entry
        assert isinstance(entry["known_models"], list)
        assert isinstance(entry["key_names"], list)
        assert isinstance(entry["model_prefixes"], list)
        if entry["canonical_key"] is not None:
            assert re.fullmatch(r"[A-Z0-9_]+", entry["canonical_key"])
        for value in _scalars(entry):
            if isinstance(value, str):
                assert not value.startswith("sk-"), f"{entry['id']}: secret-like value {value!r}"
                assert value not in secret_values, f"{entry['id']}: leaked test key {value!r}"


def test_ui_specs_report_sdk_installation():
    for entry in provider_ui_specs():
        assert isinstance(entry["sdk_installed"], bool)


def test_huggingface_sdk_is_installed():
    entry = next(entry for entry in provider_ui_specs() if entry["id"] == "huggingface")
    assert PROVIDERS["huggingface"].sdk_extra == "huggingface_hub"
    assert entry["sdk_installed"] is True, (
        "The huggingface extra is expected to be installed by the 2.57.0 bump; "
        "run `pip install 'pydantic-ai-slim[huggingface]'` (or rebuild) to restore it."
    )


# --- Generated test-key seam -------------------------------------------------

def test_default_test_keys_cover_exactly_the_keyed_providers():
    keyed = {spec.id for spec in PROVIDERS.values() if spec.requires_key}
    assert set(DEFAULT_TEST_KEYS) == keyed
    assert KEYLESS_PROVIDERS.isdisjoint(DEFAULT_TEST_KEYS)
    for spec in PROVIDERS.values():
        if spec.requires_key:
            assert DEFAULT_TEST_KEYS[spec.id] == f"test-{spec.id}-key"


# --- build_provider ----------------------------------------------------------

@pytest.mark.parametrize("spec", list(PROVIDERS.values()), ids=lambda s: s.id)
def test_build_provider_constructs_every_spec(spec):
    """Offline construction matrix: every registry entry maps to a live provider."""
    import pydantic_ai.providers as providers

    base_url = "http://endpoint:1234/v1" if spec.requires_base_url else None
    provider = build_provider(spec, DEFAULT_TEST_KEYS.get(spec.id, ""), base_url)
    assert isinstance(provider, providers.Provider), spec.id


def test_build_provider_drops_base_url_for_providers_that_reject_it():
    """deepseek & friends take no base_url kwarg; forwarding one would TypeError."""
    provider = build_provider(PROVIDERS["deepseek"], "test-deepseek-key", "http://ignored:1234")
    assert provider is not None


def test_build_provider_keyless_openai_compatible_requires_base_url():
    with pytest.raises(ProviderConfigError, match="requires a base_url"):
        build_provider(PROVIDERS["openai-compatible"], None, None)


def test_build_provider_litellm_falls_back_to_its_default_endpoint(monkeypatch):
    """A litellm default stored with no endpoint now resolves to a concrete URL
    instead of leaving the SDK to fail opaquely at request time."""
    captured = {}

    class _FakeProvider:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(
        "pydantic_ai.providers.infer_provider_class", lambda name: _FakeProvider
    )
    build_provider(PROVIDERS["litellm"], None, None)

    assert captured["api_base"] == "http://localhost:4000"


def test_build_provider_litellm_keeps_an_explicit_endpoint(monkeypatch):
    captured = {}

    class _FakeProvider:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(
        "pydantic_ai.providers.infer_provider_class", lambda name: _FakeProvider
    )
    build_provider(PROVIDERS["litellm"], None, "http://litellm.internal:4000")

    assert captured["api_base"] == "http://litellm.internal:4000"


def test_build_provider_missing_sdk_raises_actionable_error(monkeypatch):
    import core.llm_providers as registry

    monkeypatch.setattr(registry, "sdk_installed", lambda spec: False)
    with pytest.raises(ProviderConfigError, match="huggingface_hub"):
        registry.build_provider(registry.PROVIDERS["huggingface"], "test-hf")


# --- key/base-url cache ------------------------------------------------------

def test_warm_key_cache_populates_keys_and_global_base_urls(monkeypatch):
    from core import llm_factory

    store = {
        "GEMINI_API_KEY": "stored-gemini",
        "DEEPSEEK_API_KEY": "stored-deepseek",
        "OLLAMA_BASE_URL": "http://ollama.internal:11434",
    }
    monkeypatch.setattr(llm_factory, "_read_llm_provider_keys", lambda: store)
    llm_factory.reset_key_cache()
    try:
        llm_factory.warm_key_cache()
        assert llm_factory.get_provider_api_key("google") == "stored-gemini"
        assert llm_factory.get_provider_api_key("deepseek") == "stored-deepseek"
        assert llm_factory.get_provider_api_key("anthropic") is None
        assert llm_factory.get_provider_base_url(PROVIDERS["ollama"]) == "http://ollama.internal:11434"
        assert llm_factory.get_provider_base_url(PROVIDERS["google"]) is None
    finally:
        llm_factory.reset_key_cache()


def test_reset_key_cache_drops_global_base_urls(monkeypatch):
    from core import llm_factory

    reads = {"count": 0}

    def fake_read():
        reads["count"] += 1
        return {"OLLAMA_BASE_URL": "http://first:11434"}

    monkeypatch.setattr(llm_factory, "_read_llm_provider_keys", fake_read)
    llm_factory.reset_key_cache()
    assert llm_factory.get_provider_base_url(PROVIDERS["ollama"]) == "http://first:11434"
    assert reads["count"] == 1
    # Cached: no second etcd read.
    assert llm_factory.get_provider_base_url(PROVIDERS["ollama"]) == "http://first:11434"
    assert reads["count"] == 1
    llm_factory.reset_key_cache()
    assert llm_factory.get_provider_base_url(PROVIDERS["ollama"]) == "http://first:11434"
    assert reads["count"] == 2


# --- env-sanitize parity -----------------------------------------------------

def test_env_sanitize_derives_provider_credentials_from_the_registry():
    """Phase 2 derives the subprocess denylist from the registry (not a literal)."""
    from core import env_sanitize

    assert FRAMEWORK_PROVIDER_KEY_ENV <= env_sanitize.FRAMEWORK_SECRET_ENV
    # OLLAMA_BASE_URL is an endpoint, not a credential: deliberately not scrubbed.
    assert "OLLAMA_BASE_URL" not in env_sanitize.FRAMEWORK_SECRET_ENV
    assert "OLLAMA_BASE_URL" not in FRAMEWORK_PROVIDER_KEY_ENV


# --- pydantic-ai 2.57 upgrade assertions (§11.2 #5/#6) -----------------------

def test_google_model_dispatch_with_current_google_genai(llm_provider_keys):
    """google-genai >= 2.30 must map 'google:' onto GoogleModel (the old pin broke it)."""
    from pydantic_ai.models.google import GoogleModel

    from core.llm_factory import resolve_model

    assert isinstance(resolve_model("google", "gemini-2.5-flash"), GoogleModel)


def test_anthropic_provider_constructs_directly_with_api_key():
    """No httpx2 fallback: api_key is accepted and the client is AsyncAnthropic."""
    from anthropic import AsyncAnthropic
    from pydantic_ai.providers.anthropic import AnthropicProvider

    provider = build_provider(PROVIDERS["anthropic"], "test-anthropic-key", None)

    assert isinstance(provider, AnthropicProvider)
    assert isinstance(provider.client, AsyncAnthropic)
    assert provider.client.api_key == "test-anthropic-key"


def test_openrouter_vendor_prefix_survives_resolution(llm_provider_keys):
    """2.57 rejects unprefixed OpenRouter ids; the vendor prefix must pass through."""
    from pydantic_ai.models.openrouter import OpenRouterModel

    from core.llm_factory import resolve_model

    model = resolve_model("openrouter", "openai/gpt-5")

    assert isinstance(model, OpenRouterModel)
    assert model.model_name == "openai/gpt-5"


def test_every_keyed_spec_has_an_env_fallback_placeholder_or_key():
    """Keyless specs need a placeholder; otherwise the SDK could read the env."""
    for spec in PROVIDERS.values():
        assert spec.requires_key or bool(spec.key_placeholder), spec.id
