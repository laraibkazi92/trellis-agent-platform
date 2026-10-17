# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Multi-provider LLM resolution.

Maps a (provider, model, base_url) configuration onto pydantic-ai Model
instances and provider-appropriate ModelSettings. Provider credentials and
endpoints are read from the admin-managed, encrypted etcd store (see
``IdentityManager.get_llm_provider_keys`` and Admin -> LLM Providers) and passed
explicitly to the pydantic-ai providers; the environment is never consulted for
credentials.
"""
import logging
import threading
import time
from typing import Dict, Optional, Tuple

from pydantic_ai.models import Model, infer_model
from pydantic_ai.models.anthropic import AnthropicModelSettings
from pydantic_ai.models.google import GoogleModelSettings
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.settings import ModelSettings

from core.llm_providers import (
    ALLOWED_PROVIDERS,
    LLM_PROVIDER_KEY_NAMES,
    PROVIDERS,
    ProviderConfigError,
    ProviderSpec,
    build_provider,
    get_spec,
)

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
    """Drop the cached provider keys/endpoints so the next lookup re-reads etcd."""
    global _key_cache_generation
    with _key_cache_lock:
        _key_cache_generation += 1
        _key_cache.clear()


def _read_llm_provider_keys() -> Dict[str, str]:
    """Read the encrypted provider key/endpoint store once.

    Lazy import: core.auth imports core.models only, but keeping this local avoids
    any future import cycle through the identity layer. Callers read outside the
    cache lock so a slow/degraded etcd call doesn't serialize every lookup.
    """
    from core.auth import get_identity_manager
    return get_identity_manager().get_llm_provider_keys() or {}


def get_provider_api_key(provider: str) -> Optional[str]:
    """Return the admin-configured API key for ``provider``, or None when unset.

    Keys live in the encrypted etcd store (Admin -> LLM Providers), never in
    the environment. Results are cached for ``_KEY_CACHE_TTL_SECONDS``;
    ``reset_key_cache`` clears the cache. An unreachable etcd is allowed to
    propagate -- there is deliberately no environment fallback.
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

    keys = _read_llm_provider_keys()
    value = next((keys[name] for name in key_names if keys.get(name)), None)

    with _key_cache_lock:
        # A rotation that landed while we were reading must not be shadowed by our
        # stale value; skip the write (the next lookup re-reads etcd).
        if _key_cache_generation == generation:
            _key_cache[provider] = (now + _KEY_CACHE_TTL_SECONDS, value)
    return value


def get_provider_base_url(spec: ProviderSpec) -> Optional[str]:
    """Return the global endpoint configured for ``spec``, or None when it has none.

    Global endpoints (today only Ollama's ``OLLAMA_BASE_URL``) live in the same
    encrypted etcd store as the provider keys, never in the environment. Shares
    the TTL cache and generation guard with ``get_provider_api_key``.
    """
    if not spec.base_url_key_names:
        return None

    cache_key = f"{spec.id}:base_url"
    now = time.monotonic()
    with _key_cache_lock:
        cached = _key_cache.get(cache_key)
        if cached is not None and now < cached[0]:
            return cached[1]
        generation = _key_cache_generation

    keys = _read_llm_provider_keys()
    value = next((keys[name] for name in spec.base_url_key_names if keys.get(name)), None)

    with _key_cache_lock:
        if _key_cache_generation == generation:
            _key_cache[cache_key] = (now + _KEY_CACHE_TTL_SECONDS, value)
    return value


def warm_key_cache() -> None:
    """Populate the resolved-key/endpoint cache for every provider (best-effort).

    Called once at process startup (off the event loop) so the first request-path
    lookup is a cache hit instead of an etcd round-trip, which can block for ~20s
    under ``@retry_etcd`` degradation. Reads the store once and fans the values out
    to each provider (keys, plus base_urls for providers with a global endpoint);
    failures are logged and never raise.
    """
    with _key_cache_lock:
        generation = _key_cache_generation
    try:
        keys = _read_llm_provider_keys()
    except Exception as e:
        logger.warning(f"Failed to warm LLM provider key cache: {e}")
        return

    expiry = time.monotonic() + _KEY_CACHE_TTL_SECONDS
    with _key_cache_lock:
        if _key_cache_generation != generation:
            return
        for spec in PROVIDERS.values():
            key_value = next((keys[name] for name in spec.key_names if keys.get(name)), None)
            # Keyless providers (ollama) cache None harmlessly.
            _key_cache[spec.id] = (expiry, key_value)
            if spec.base_url_key_names:
                url_value = next((keys[name] for name in spec.base_url_key_names if keys.get(name)), None)
                _key_cache[f"{spec.id}:base_url"] = (expiry, url_value)


def infer_provider(model: Optional[str]) -> str:
    """Infer the provider from a model-name prefix.

    Prefixes come from the registry (``ProviderSpec.model_prefixes``) in
    registry order. An empty/None model keeps the historical Google default.
    Any unrecognized name raises: silently guessing a provider would route
    credentials to the wrong vendor.
    """
    name = (model or "").strip().lower()
    if not name:
        return "google"
    if "/" in name:
        # Vendor-prefixed ids (openrouter/vercel/together/HF seed lists) are
        # ambiguous between aggregators and direct vendors; requiring an explicit
        # provider here honours the never-guess contract.
        raise ProviderConfigError(
            f"Cannot infer LLM provider from model '{model}'. Vendor-prefixed model ids "
            f"require an explicit provider (one of: {', '.join(ALLOWED_PROVIDERS)})."
        )
    for spec in PROVIDERS.values():
        if any(name.startswith(prefix.lower()) for prefix in spec.model_prefixes):
            return spec.id
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


def _clean_model_name(model: str, spec: ProviderSpec) -> str:
    """Normalize a configured model id for ``infer_model``.

    Users habitually paste a prefixed id (``openai:gpt-4o``); a leading
    ``<pydantic_name>:`` or ``<id>:`` prefix matching this provider is stripped
    (case-insensitive on the prefix, remainder preserved verbatim).

    ``infer_model`` splits on the *first* ``:``, so any remaining colon would
    silently be read as a provider prefix -- reject it instead. This also
    rejects Ollama tags like ``llama3.2:3b`` by design. ``openai-compatible``
    bypasses ``infer_model`` entirely, so a colon there is just part of the
    model id (the documented local-endpoint pattern) and is allowed.
    """
    name = (model or "").strip()
    for prefix in (spec.pydantic_name, spec.id):
        marker = f"{prefix}:"
        if prefix and name.lower().startswith(marker.lower()):
            name = name[len(marker):]
            break
    if ":" in name and spec.build != "openai-compatible":
        raise ProviderConfigError(
            f"Model names may not contain ':' (got '{name}'); pass the bare model id."
        )
    return name


def resolve_model(
    provider: str,
    model: str,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Model:
    """Build the pydantic-ai Model instance for a provider/model/base_url combo.

    Construction is offline-safe: providers validate credentials eagerly but
    make no network calls. Remote providers require an API key configured in
    Admin -> LLM Providers; 'openai-compatible' endpoints may be keyless.
    ``ollama`` always receives an explicit base_url (its default) so the SDK
    can never fall back to ``OLLAMA_BASE_URL`` in the environment.

    ``api_key`` lets an async caller prefetch the etcd-stored key off the event
    loop and pass it in; when None the key is read here (sync callers/tests are
    unchanged).
    """
    resolved = resolve_provider(provider, model)
    spec = get_spec(resolved)
    model_name = _clean_model_name(model, spec)

    stripped_url = (base_url or "").strip()
    if spec.requires_base_url and not stripped_url:
        raise ProviderConfigError(
            f"Provider '{spec.id}' requires a base_url pointing at the endpoint."
        )
    if stripped_url and not spec.supports_base_url:
        raise ProviderConfigError(
            f"Provider '{spec.id}' does not accept a base_url; remove it and let "
            f"the provider use its own endpoint."
        )

    # Residual: when a caller prefetches and the provider is keyless (or the
    # endpoint is keyless), ``api_key`` is None -- indistinguishable from "not
    # prefetched" -- so this re-reads the key. It is normally a cache hit; only a
    # concurrent reset_key_cache() can turn it into a blocking etcd read on the
    # event loop. Fixing it cleanly needs the prefetching caller
    # (agent_factory.build_agent) to signal "resolved to None", which would mean
    # extending this public signature; not done here to avoid changing call sites.
    key = api_key if api_key is not None else get_provider_api_key(spec.id)
    if spec.requires_key and not key:
        raise ProviderConfigError(
            f"No API key configured for provider '{spec.id}'. Set "
            f"{' or '.join(spec.key_names)} in Admin -> LLM Providers. "
            f"LLM provider keys are stored in etcd, not the environment."
        )

    url = stripped_url or get_provider_base_url(spec) or spec.default_base_url
    try:
        if spec.build == "openai-compatible":
            return OpenAIChatModel(model_name, provider=build_provider(spec, key, url))
        return infer_model(
            f"{spec.pydantic_name}:{model_name}",
            provider_factory=lambda _name: build_provider(spec, key, url),
        )
    except ProviderConfigError:
        raise
    except Exception as e:
        # The SDK's own validation (e.g. "OpenRouter model names must be prefixed
        # with the upstream provider") is a configuration mistake, not a crash:
        # re-raise as ProviderConfigError so the caller gets an actionable message.
        raise ProviderConfigError(
            f"Cannot build model '{model_name}' for provider '{spec.id}': {e}"
        ) from e


def build_model_settings(
    provider: str,
    model: str,
    thinking_level: Optional[str],
) -> Optional[ModelSettings]:
    """Map a thinking_level onto provider-appropriate ModelSettings.

    The branch is selected by the provider registry's ``thinking_style``, so
    providers that can't express reasoning effort never receive an
    ``openai_reasoning_effort`` (which generic OpenAI-compatible endpoints
    reject with a 400). None (or a level the provider can't express) means "no
    settings" — the model runs with its own defaults. The Google branch
    preserves the exact budgets this factory inherited from
    agent_factory._get_model_settings.
    """
    spec = get_spec(resolve_provider(provider, model))
    level = (thinking_level or "").strip().lower()
    if not level or level in ("none", "n/a"):
        return None

    if spec.thinking_style == "google":
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

    if spec.thinking_style == "anthropic":
        if level not in EFFORT_LEVELS:
            return None
        return AnthropicModelSettings(anthropic_effort=level)

    if spec.thinking_style == "openai-effort":
        if level not in EFFORT_LEVELS:
            return None
        return OpenAIChatModelSettings(openai_reasoning_effort=level)

    return None
