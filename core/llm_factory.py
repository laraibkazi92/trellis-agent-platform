# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Multi-provider LLM resolution.

Maps a (provider, model, base_url) configuration onto pydantic-ai Model
instances and provider-appropriate ModelSettings. API keys are read from the
admin-managed, encrypted etcd store (see ``IdentityManager.get_llm_provider_keys``)
and passed explicitly to the pydantic-ai providers, so the standard environment
variables (GEMINI_API_KEY/GOOGLE_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY)
are never consulted.
"""
import logging
import threading
import time
from typing import Dict, Optional, Tuple

from pydantic_ai.models import Model
from pydantic_ai.models.anthropic import AnthropicModel, AnthropicModelSettings
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.settings import ModelSettings

from core.models import ALLOWED_PROVIDERS

logger = logging.getLogger(__name__)

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


# etcd-stored key names each provider accepts, in precedence order (first hit wins,
# so GEMINI_API_KEY wins over GOOGLE_API_KEY for Google).
LLM_PROVIDER_KEY_NAMES: Dict[str, Tuple[str, ...]] = {
    "google": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "openai": ("OPENAI_API_KEY",),
    "openai-compatible": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
}

# Resolved keys are cached per provider so the hot build path avoids an etcd round-trip
# on every request; the short TTL bounds how long a rotated/deleted key stays live in a
# running process (the etcd watch in agent_factory clears this immediately on change).
_KEY_CACHE_TTL_SECONDS = 30.0
_key_cache: Dict[str, Tuple[float, Optional[str]]] = {}
# Guards read/write of _key_cache and the generation counter below: the etcd watch
# thread (reset_key_cache) races request threads that read-then-write.
_key_cache_lock = threading.Lock()
# Bumped by reset_key_cache. A lookup that started reading etcd before a rotation must
# not re-insert the pre-rotation key with a fresh TTL (which would shadow the rotation
# for the whole TTL window).
_key_cache_generation = 0


def reset_key_cache() -> None:
    """Drop the cached provider keys so the next lookup re-reads etcd."""
    global _key_cache_generation
    with _key_cache_lock:
        _key_cache_generation += 1
        _key_cache.clear()


def get_provider_api_key(provider: str) -> Optional[str]:
    """Return the admin-configured API key for ``provider``, or None when unset.

    Keys live in the encrypted etcd store (Admin Dashboard -> Global Tool
    Configuration), never in the environment. Results are cached for
    ``_KEY_CACHE_TTL_SECONDS``; ``reset_key_cache`` clears the cache. An
    unreachable etcd is allowed to propagate -- there is deliberately no
    environment fallback.
    """
    key_names = LLM_PROVIDER_KEY_NAMES.get(provider)
    if not key_names:
        return None

    now = time.monotonic()
    with _key_cache_lock:
        cached = _key_cache.get(provider)
        if cached is not None and now < cached[0]:
            return cached[1]
        generation = _key_cache_generation

    # Lazy import: core.auth imports core.models only, but keeping this local avoids
    # any future import cycle through the identity layer. Read outside the lock so a
    # slow/degraded etcd call doesn't serialize every provider lookup.
    from core.auth import get_identity_manager
    keys = get_identity_manager().get_llm_provider_keys() or {}
    value = next((keys[name] for name in key_names if keys.get(name)), None)

    with _key_cache_lock:
        # A rotation that landed while we were reading must not be shadowed by our
        # stale value; skip the write (the next lookup re-reads etcd).
        if _key_cache_generation == generation:
            _key_cache[provider] = (now + _KEY_CACHE_TTL_SECONDS, value)
    return value


def warm_key_cache() -> None:
    """Populate the resolved-key cache for every provider (best-effort).

    Called once at process startup (off the event loop) so the first request-path
    lookup is a cache hit instead of an etcd round-trip, which can block for ~20s
    under ``@retry_etcd`` degradation. Reads the store once and fans the values out
    to each provider; failures are logged and never raise.
    """
    with _key_cache_lock:
        generation = _key_cache_generation
    try:
        from core.auth import get_identity_manager
        keys = get_identity_manager().get_llm_provider_keys() or {}
    except Exception as e:
        logger.warning(f"Failed to warm LLM provider key cache: {e}")
        return

    expiry = time.monotonic() + _KEY_CACHE_TTL_SECONDS
    with _key_cache_lock:
        if _key_cache_generation != generation:
            return
        for provider, key_names in LLM_PROVIDER_KEY_NAMES.items():
            value = next((keys[name] for name in key_names if keys.get(name)), None)
            _key_cache[provider] = (expiry, value)


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


def _require_api_key(provider: str, api_key: Optional[str] = None) -> str:
    """Fetch the etcd-stored key for a provider, raising before any provider construction.

    Google/Anthropic/OpenAI providers silently fall back to their env vars when
    handed a falsy api_key, so this guard is what keeps the environment from ever
    being consulted. ``api_key``, when provided (e.g. prefetched off the event
    loop), is used directly instead of re-reading etcd.
    """
    key = api_key if api_key is not None else get_provider_api_key(provider)
    if not key:
        key_names = " or ".join(LLM_PROVIDER_KEY_NAMES.get(provider, ()))
        raise ProviderConfigError(
            f"No API key configured for provider '{provider}'. Set {key_names} in the "
            f"Admin Dashboard -> Global Tool Configuration. LLM provider keys are stored "
            f"in etcd, not the environment."
        )
    return key


def resolve_model(
    provider: str,
    model: str,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Model:
    """Build the pydantic-ai Model instance for a provider/model/base_url combo.

    Construction is offline-safe: providers validate credentials eagerly but
    make no network calls. Remote providers require an admin-configured API key;
    'openai-compatible' endpoints may be keyless.

    ``api_key`` lets an async caller prefetch the etcd-stored key off the event
    loop and pass it in; when None the key is read here (sync callers/tests are
    unchanged).
    """
    resolved = resolve_provider(provider, model)
    if resolved == "google":
        return GoogleModel(model, provider=GoogleProvider(api_key=_require_api_key(resolved, api_key)))
    if resolved == "openai":
        return OpenAIChatModel(model, provider=OpenAIProvider(api_key=_require_api_key(resolved, api_key)))
    if resolved == "anthropic":
        anthropic_key = _require_api_key(resolved, api_key)
        try:
            return AnthropicModel(model, provider=AnthropicProvider(api_key=anthropic_key))
        except TypeError as e:
            # anthropic-sdk >= 1.11 moved to the httpx2 fork and rejects the stock
            # httpx client pydantic-ai 2.31.x builds by default. Fall back to the
            # SDK's own client, passing the etcd key explicitly.
            if "httpx2" not in str(e):
                raise
            from anthropic import AsyncAnthropic
            return AnthropicModel(model, provider=AnthropicProvider(anthropic_client=AsyncAnthropic(api_key=anthropic_key)))
    if not (base_url or "").strip():
        raise ProviderConfigError(
            "Provider 'openai-compatible' requires a base_url pointing at the compatible endpoint."
        )
    # Residual: when a caller prefetches and the endpoint is keyless, ``api_key`` is
    # None -- indistinguishable from "not prefetched" -- so this re-reads the key.
    # It is normally a cache hit; only a concurrent reset_key_cache() can turn it into
    # a blocking etcd read on the event loop. Fixing it cleanly needs the prefetching
    # caller (agent_factory.build_agent) to signal "resolved to None", which would mean
    # extending this public signature; not done here to avoid changing call sites.
    compat_key = api_key if api_key is not None else get_provider_api_key("openai-compatible")
    # A keyless compatible endpoint must be handed a non-empty placeholder: the OpenAI
    # SDK reads OPENAI_API_KEY from the environment when given a falsy key, which would
    # break the "env is never consulted" invariant. Mirrors pydantic-ai's own fallback.
    return OpenAIChatModel(model, provider=OpenAIProvider(
        base_url=base_url.strip(), api_key=compat_key or "api-key-not-set"
    ))


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

    # openai-compatible: no thinking mapping.
    return None
