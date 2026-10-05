# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Multi-provider LLM resolution.

Maps a (provider, model, base_url) configuration onto pydantic-ai Model
instances and provider-appropriate ModelSettings. API keys are never passed
explicitly: the pydantic-ai providers resolve them from the standard
environment variables (GEMINI_API_KEY/GOOGLE_API_KEY, OPENAI_API_KEY,
ANTHROPIC_API_KEY) at construction time. Ollama needs no key.
"""
import logging
from typing import Optional

from pydantic_ai.models import Model
from pydantic_ai.models.anthropic import AnthropicModel, AnthropicModelSettings
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings
from pydantic_ai.models.ollama import OllamaModel
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.ollama import OllamaProvider
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.settings import ModelSettings

from core.models import ALLOWED_PROVIDERS

logger = logging.getLogger(__name__)

# pydantic-ai's OllamaProvider refuses to construct without OLLAMA_BASE_URL or an
# explicit base_url; keep the conventional local-daemon default so `provider: ollama`
# works with no extra configuration.
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"

# Reasoning-effort levels the non-Google providers accept natively (Gemini keeps
# its own budget/level mapping below).
EFFORT_LEVELS = ("low", "medium", "high")

GEMINI_2_5_PRO_MODELS = {"gemini-2.5-pro"}
GEMINI_2_5_FLASH_MODELS = {"gemini-2.5-flash"}
LITE_MODELS = {"gemini-3.1-flash-lite-preview", "gemini-2.5-flash-lite"}
GEMINI_3_MODELS = {"gemini-3.1-pro-preview", "gemini-3-flash-preview"}

GEMINI_2_5_PRO_BUDGETS = {"low": 1024, "medium": 8192, "high": 16384}
GEMINI_2_5_FLASH_BUDGETS = {"low": 1024, "medium": 4096, "high": 8192}


class ProviderConfigError(ValueError):
    """Raised when a model configuration cannot be mapped to a known provider."""


def infer_provider(model: Optional[str]) -> str:
    """Infer the provider from a model-name prefix.

    An empty/None model keeps the historical Google default. Any unrecognized
    name raises: silently guessing a provider would route credentials to the
    wrong vendor.
    """
    name = (model or "").strip().lower()
    if not name:
        return "google"
    if name.startswith("gemini"):
        return "google"
    if name.startswith("claude"):
        return "anthropic"
    if name.startswith(("gpt-", "o1", "o3", "o4", "chatgpt")):
        return "openai"
    raise ProviderConfigError(
        f"Cannot infer LLM provider from model '{model}'. Set an explicit provider "
        f"(one of: {', '.join(ALLOWED_PROVIDERS)})."
    )


def resolve_provider(provider: Optional[str], model: Optional[str]) -> str:
    """Normalize an optional explicit provider, falling back to model-name inference."""
    normalized = (provider or "").strip().lower()
    if normalized:
        if normalized not in ALLOWED_PROVIDERS:
            raise ProviderConfigError(
                f"Unknown LLM provider '{provider}'. Valid providers: {', '.join(ALLOWED_PROVIDERS)}."
            )
        return normalized
    return infer_provider(model)


def resolve_model(provider: str, model: str, base_url: Optional[str] = None) -> Model:
    """Build the pydantic-ai Model instance for a provider/model/base_url combo.

    Construction is offline-safe: providers validate credentials eagerly but
    make no network calls.
    """
    resolved = resolve_provider(provider, model)
    if resolved == "google":
        return GoogleModel(model)
    if resolved == "openai":
        return OpenAIChatModel(model)
    if resolved == "anthropic":
        try:
            return AnthropicModel(model)
        except TypeError as e:
            # anthropic-sdk >= 1.11 moved to the httpx2 fork and rejects the stock
            # httpx client pydantic-ai 2.31.x builds by default. Fall back to the
            # SDK's own client, which reads ANTHROPIC_API_KEY from the environment.
            if "httpx2" not in str(e):
                raise
            from anthropic import AsyncAnthropic
            return AnthropicModel(model, provider=AnthropicProvider(anthropic_client=AsyncAnthropic()))
    if resolved == "ollama":
        return OllamaModel(model, provider=OllamaProvider(base_url=base_url or DEFAULT_OLLAMA_BASE_URL))
    if not (base_url or "").strip():
        raise ProviderConfigError(
            "Provider 'openai-compatible' requires a base_url pointing at the compatible endpoint."
        )
    return OpenAIChatModel(model, provider=OpenAIProvider(base_url=base_url.strip()))


def build_model_settings(
    provider: str,
    model: str,
    thinking_level: Optional[str],
) -> Optional[ModelSettings]:
    """Map a thinking_level onto provider-appropriate ModelSettings.

    None (or a level the provider can't express) means "no settings" — the model
    runs with its own defaults. The Google branch preserves the exact budgets
    this factory inherited from agent_factory._get_model_settings.
    """
    resolved = resolve_provider(provider, model)
    level = (thinking_level or "").strip().lower()
    if not level or level in ("none", "n/a"):
        return None

    if resolved == "google":
        if model in LITE_MODELS:
            return None
        if model in GEMINI_2_5_PRO_MODELS:
            budget = GEMINI_2_5_PRO_BUDGETS.get(level, 8192)
            return GoogleModelSettings(google_thinking_config={"thinking_budget": budget, "include_thoughts": False})
        if model in GEMINI_2_5_FLASH_MODELS:
            budget = GEMINI_2_5_FLASH_BUDGETS.get(level, 4096)
            return GoogleModelSettings(google_thinking_config={"thinking_budget": budget, "include_thoughts": False})
        if model in GEMINI_3_MODELS:
            return GoogleModelSettings(google_thinking_config={"thinking_level": level, "include_thoughts": False})
        return None

    if resolved == "anthropic":
        if level not in EFFORT_LEVELS:
            return None
        return AnthropicModelSettings(anthropic_effort=level)

    if resolved == "openai":
        if level not in EFFORT_LEVELS:
            return None
        return OpenAIChatModelSettings(openai_reasoning_effort=level)

    # ollama / openai-compatible: no thinking mapping.
    return None
