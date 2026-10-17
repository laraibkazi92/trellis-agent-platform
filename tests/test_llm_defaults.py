# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for core/llm_defaults.py — the framework default resolution matrix.

Hermetic: ``_read_raw_defaults`` is monkeypatched where the cache/etcd read path
is exercised, so nothing here touches etcd. ``resolve_effective_llm_config`` is a
pure function and is tested with hand-built ``FrameworkDefaults``.
"""
import logging

import pytest

from core import llm_defaults
from core.llm_defaults import (
    FrameworkDefaults,
    get_framework_defaults,
    needs_framework_defaults,
    reset_defaults_cache,
    resolve_effective_llm_config,
    validate_defaults,
    warm_defaults_cache,
)
from core.llm_providers import PROVIDERS, ProviderConfigError


@pytest.fixture(autouse=True)
def _reset_defaults_state(monkeypatch):
    """Start every test from a cold cache and a clean invalid-dedupe slot."""
    monkeypatch.setattr(llm_defaults, "_last_logged_invalid", None)
    reset_defaults_cache()
    yield
    reset_defaults_cache()


# --- §4 resolution matrix ----------------------------------------------------

def test_row_a_explicit_pair_is_passed_through():
    eff = resolve_effective_llm_config("deepseek", "deepseek-chat", None, FrameworkDefaults())
    assert (eff.provider, eff.model, eff.base_url, eff.source) == (
        "deepseek",
        "deepseek-chat",
        None,
        "explicit",
    )


def test_row_a_explicit_pair_ignores_the_framework_default():
    defaults = FrameworkDefaults(provider="google", model="gemini-2.5-flash", base_url="http://gw:8080")
    eff = resolve_effective_llm_config("deepseek", "deepseek-reasoner", None, defaults)
    assert (eff.provider, eff.model, eff.base_url, eff.source) == (
        "deepseek",
        "deepseek-reasoner",
        None,
        "explicit",
    )


def test_row_b_same_framework_provider_inherits_model_and_base_url():
    defaults = FrameworkDefaults(provider="google", model="gemini-3-flash-preview", base_url="http://gw:8080")
    eff = resolve_effective_llm_config("google", "", None, defaults)
    assert eff.provider == "google"
    assert eff.model == "gemini-3-flash-preview"
    assert eff.base_url == "http://gw:8080"
    assert eff.source == "provider-default"


def test_row_b_same_framework_provider_keeps_an_agent_supplied_base_url():
    # §4 base_url precedence: agent-supplied > inherited framework default.
    defaults = FrameworkDefaults(provider="google", model="gemini-3-flash-preview", base_url="http://org:8080")
    eff = resolve_effective_llm_config("google", "", "http://agent:9090", defaults)
    assert eff.base_url == "http://agent:9090"


def test_row_b_different_framework_provider_uses_registry_default_only():
    defaults = FrameworkDefaults(provider="google", model="gemini-3-flash-preview", base_url="http://gw:8080")
    eff = resolve_effective_llm_config("deepseek", "", None, defaults)
    assert eff.provider == "deepseek"
    assert eff.model == "deepseek-chat"
    assert eff.base_url is None  # different provider inherits nothing but the model
    assert eff.source == "provider-default"


def test_row_b_different_provider_keeps_the_agent_base_url():
    defaults = FrameworkDefaults(provider="google", model="gemini-3-flash-preview", base_url="http://org:8080")
    eff = resolve_effective_llm_config("anthropic", "", "http://proxy:1", defaults)
    assert eff.base_url == "http://proxy:1"


def test_row_b_same_provider_without_default_model_uses_registry_default():
    defaults = FrameworkDefaults(provider="google", model=None, base_url=None)
    eff = resolve_effective_llm_config("google", "", None, defaults)
    assert eff.model == PROVIDERS["google"].default_model


def test_row_b_openai_compatible_without_a_registry_default_raises():
    with pytest.raises(ProviderConfigError, match="requires an explicit model"):
        resolve_effective_llm_config("openai-compatible", "", None, FrameworkDefaults())


def test_row_b_openai_compatible_with_a_matching_framework_model_resolves():
    defaults = FrameworkDefaults(provider="openai-compatible", model="llama3.2:3b", base_url="http://ep:11434/v1")
    eff = resolve_effective_llm_config("openai-compatible", "", None, defaults)
    assert eff.provider == "openai-compatible"
    assert eff.model == "llama3.2:3b"
    assert eff.base_url == "http://ep:11434/v1"
    assert eff.source == "provider-default"


def test_row_c_blank_provider_infers_from_the_model_name():
    eff = resolve_effective_llm_config(None, "claude-sonnet-4-5", None, FrameworkDefaults())
    assert (eff.provider, eff.model, eff.base_url, eff.source) == (
        "anthropic",
        "claude-sonnet-4-5",
        None,
        "inferred",
    )


def test_row_c_uninferable_model_raises():
    with pytest.raises(ProviderConfigError):
        resolve_effective_llm_config(None, "openai/gpt-5", None, FrameworkDefaults())


def test_row_d_both_blank_uses_the_framework_default():
    defaults = FrameworkDefaults(provider="deepseek", model="deepseek-chat", base_url=None)
    eff = resolve_effective_llm_config(None, None, None, defaults)
    assert (eff.provider, eff.model, eff.base_url, eff.source) == (
        "deepseek",
        "deepseek-chat",
        None,
        "framework",
    )


def test_row_d_openai_compatible_default_returns_its_endpoint():
    defaults = FrameworkDefaults(provider="openai-compatible", model="llama3.2:3b", base_url="http://ep:11434/v1")
    eff = resolve_effective_llm_config(None, None, None, defaults)
    assert eff.provider == "openai-compatible"
    assert eff.model == "llama3.2:3b"
    assert eff.base_url == "http://ep:11434/v1"
    assert eff.source == "framework"


def test_row_d_agent_base_url_wins_over_the_framework_base_url():
    defaults = FrameworkDefaults(provider="openai-compatible", model="llama3.2:3b", base_url="http://default:1/v1")
    eff = resolve_effective_llm_config(None, None, "http://agent:2/v1", defaults)
    assert eff.base_url == "http://agent:2/v1"


def test_row_e_no_defaults_falls_back_to_legacy_google():
    eff = resolve_effective_llm_config(None, None, None, None)
    assert eff.provider == "google"
    assert eff.model == PROVIDERS["google"].default_model
    assert eff.source == "legacy"


def test_row_e_empty_defaults_object_falls_back_to_legacy_google():
    eff = resolve_effective_llm_config(None, None, None, FrameworkDefaults())
    assert (eff.provider, eff.model, eff.source) == ("google", PROVIDERS["google"].default_model, "legacy")


def test_hand_built_defaults_without_a_model_falls_back_to_legacy_google():
    # A malformed defaults object must not produce EffectiveLLMConfig(model=None).
    eff = resolve_effective_llm_config(None, None, None, FrameworkDefaults(provider="deepseek"))
    assert (eff.provider, eff.source) == ("google", "legacy")


def test_base_url_dropped_with_a_warning_when_the_provider_rejects_it(caplog):
    with caplog.at_level(logging.WARNING, logger="core.llm_defaults"):
        eff = resolve_effective_llm_config("deepseek", "deepseek-chat", "http://ignored:1234", FrameworkDefaults())
    assert eff.base_url is None
    assert "Dropping base_url" in caplog.text


# --- needs_framework_defaults (D6) -------------------------------------------

@pytest.mark.parametrize(
    "provider,model,expected",
    [
        ("google", "gemini-2.5-flash", False),
        ("google", "", True),
        ("google", None, True),
        (None, "gemini-2.5-flash", True),
        (None, None, True),
        ("   ", "  ", True),
    ],
)
def test_needs_framework_defaults_truth_table(provider, model, expected):
    assert needs_framework_defaults(provider, model) is expected


# --- read/normalize path (hermetic) ------------------------------------------

def test_unset_triple_is_silent_and_empty(monkeypatch, caplog):
    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", lambda: (None, None, None))
    with caplog.at_level(logging.WARNING, logger="core.llm_defaults"):
        assert get_framework_defaults() == FrameworkDefaults()
    assert caplog.records == []


def test_normalize_defaults_fills_the_registry_default_model(monkeypatch):
    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", lambda: ("Google", "  ", None))
    assert get_framework_defaults() == FrameworkDefaults(provider="google", model="gemini-2.5-flash", base_url=None)


def test_unknown_stored_provider_is_dropped(monkeypatch):
    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", lambda: ("nonexistent", "whatever", None))
    assert get_framework_defaults() == FrameworkDefaults()


def test_unknown_stored_provider_falls_through_to_legacy_google_end_to_end(monkeypatch):
    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", lambda: ("nonexistent", "whatever", None))
    eff = resolve_effective_llm_config(None, None, None, get_framework_defaults())
    assert (eff.provider, eff.source) == ("google", "legacy")


def test_stored_non_curated_model_is_kept(monkeypatch):
    # D14: a model that left known_models must not demote the stored default.
    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", lambda: ("deepseek", "deepseek-ultra", None))
    assert get_framework_defaults() == FrameworkDefaults(provider="deepseek", model="deepseek-ultra")


def test_stored_curated_model_is_kept_verbatim(monkeypatch):
    # Guards against a regression that always replaces the model with spec.default_model.
    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", lambda: ("google", "gemini-2.5-pro", None))
    assert get_framework_defaults().model == "gemini-2.5-pro"


def test_unsupported_stored_base_url_is_dropped_not_demoted(monkeypatch, caplog):
    monkeypatch.setattr(
        llm_defaults, "_read_raw_defaults", lambda: ("deepseek", "deepseek-chat", "http://ignored:1")
    )
    with caplog.at_level(logging.WARNING, logger="core.llm_defaults"):
        assert get_framework_defaults() == FrameworkDefaults(
            provider="deepseek", model="deepseek-chat", base_url=None
        )
    assert "Ignoring unsupported base_url" in caplog.text


def test_stored_default_missing_a_required_base_url_is_dropped(monkeypatch):
    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", lambda: ("openai-compatible", "llama3.2:3b", None))
    assert get_framework_defaults() == FrameworkDefaults()


def test_stored_value_without_a_provider_is_dropped(monkeypatch):
    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", lambda: (None, "deepseek-chat", None))
    assert get_framework_defaults() == FrameworkDefaults()


def test_invalid_default_warns_once_per_raw_tuple(monkeypatch, caplog):
    raw = ("nonexistent", "whatever", None)
    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", lambda: raw)
    with caplog.at_level(logging.WARNING, logger="core.llm_defaults"):
        assert get_framework_defaults() == FrameworkDefaults()
        reset_defaults_cache()
        assert get_framework_defaults() == FrameworkDefaults()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1


def test_get_framework_defaults_fails_open_on_a_read_error(monkeypatch):
    def boom():
        raise RuntimeError("etcd down")

    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", boom)
    assert get_framework_defaults() == FrameworkDefaults()


# --- cache TTL + generation guard --------------------------------------------

def test_cache_ttl_and_reset_force_a_reread(monkeypatch):
    calls = {"count": 0}
    current = {"raw": ("google", "gemini-2.5-flash", None)}

    def fake_read():
        calls["count"] += 1
        return current["raw"]

    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", fake_read)

    first = get_framework_defaults()
    assert first.provider == "google"
    assert calls["count"] == 1

    # A second read inside the TTL returns the cached value without touching etcd.
    current["raw"] = ("deepseek", "deepseek-chat", None)
    second = get_framework_defaults()
    assert second == first
    assert calls["count"] == 1

    # A reset invalidates the cache; the next read picks up the new raw data.
    reset_defaults_cache()
    third = get_framework_defaults()
    assert third.provider == "deepseek"
    assert third.model == "deepseek-chat"
    assert calls["count"] == 2


def test_warm_defaults_cache_never_raises(monkeypatch):
    def boom():
        raise RuntimeError("etcd down")

    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", boom)
    warm_defaults_cache()  # must not raise


def test_warm_defaults_cache_swallows_a_getter_failure(monkeypatch):
    # Covers warm's own guard, not just get_framework_defaults' fail-open read.
    def boom():
        raise RuntimeError("boom")

    monkeypatch.setattr(llm_defaults, "get_framework_defaults", boom)
    warm_defaults_cache()  # must not raise


def test_cache_expires_after_the_ttl(monkeypatch):
    calls = {"n": 0}

    def fake_read():
        calls["n"] += 1
        return ("google", "gemini-2.5-flash", None)

    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", fake_read)

    get_framework_defaults()
    # Force expiry instead of sleeping 30s.
    llm_defaults._defaults_cache_expiry = 0.0
    get_framework_defaults()
    assert calls["n"] == 2


def test_a_reset_during_the_read_does_not_repopulate_the_cache(monkeypatch):
    calls = {"n": 0}

    def fake_read():
        calls["n"] += 1
        if calls["n"] == 1:
            # Simulate an admin save landing while the etcd read is in flight.
            reset_defaults_cache()
        return ("google", "gemini-2.5-flash", None)

    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", fake_read)

    get_framework_defaults()
    get_framework_defaults()
    # The first (pre-reset) value must not have been cached.
    assert calls["n"] == 2


# --- validate_defaults (§8 rows) ---------------------------------------------

def test_validate_defaults_blank_provider_is_always_valid():
    assert validate_defaults(None, "whatever", None) == []
    assert validate_defaults("", "", "") == []


def test_validate_defaults_unknown_provider():
    errors = validate_defaults("nonexistent", None, None)
    assert len(errors) == 1
    assert "Unknown LLM provider" in errors[0]


def test_validate_defaults_blank_model_with_no_registry_default():
    errors = validate_defaults("openai-compatible", "", None)
    assert any("requires an explicit model" in e for e in errors)


def test_validate_defaults_non_curated_model():
    assert validate_defaults("deepseek", "not-a-real-model", None) == [
        "Model 'not-a-real-model' is not one of the curated models for 'deepseek'."
    ]


def test_validate_defaults_curated_check_can_be_skipped():
    assert validate_defaults("deepseek", "not-a-real-model", None, check_curated=False) == []


def test_validate_defaults_base_url_on_a_provider_that_rejects_it():
    errors = validate_defaults("deepseek", "deepseek-chat", "http://ignored:1234")
    assert errors == [
        "Provider 'deepseek' does not accept a base_url; remove it and let the provider "
        "use its own endpoint."
    ]


def test_validate_defaults_missing_required_base_url():
    assert validate_defaults("openai-compatible", "llama3.2:3b", None) == [
        "Provider 'openai-compatible' requires a base_url pointing at the endpoint."
    ]


def test_validate_defaults_valid_triples_have_no_errors():
    assert validate_defaults("google", "gemini-2.5-flash", "http://gw:8080") == []
    assert validate_defaults("deepseek", "deepseek-chat", None) == []
    assert validate_defaults("openai-compatible", "llama3.2:3b", "http://ep/v1") == []
