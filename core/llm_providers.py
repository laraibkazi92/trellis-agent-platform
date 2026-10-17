# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Provider registry for the LLM layer.

A frozen ``ProviderSpec`` per selectable provider describes how to resolve its
credentials, endpoint and model metadata. This module is deliberately
stdlib-only at import scope: provider classes are imported lazily inside
``build_provider`` so importing the registry (directly or via ``core.models``)
never pulls an optional SDK into the process.
"""

import importlib.util
import logging
from dataclasses import dataclass
from typing import Mapping

logger = logging.getLogger(__name__)


class ProviderConfigError(ValueError):
    """Raised when a model configuration cannot be mapped to a known provider."""


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    id: str
    label: str
    pydantic_name: str
    build: str = "infer"
    key_names: tuple[str, ...] = ()
    base_url_key_names: tuple[str, ...] = ()
    requires_key: bool = True
    supports_base_url: bool = False
    requires_base_url: bool = False
    default_base_url: str | None = None
    base_url_placeholder: str | None = None
    base_url_kwarg: str = "base_url"
    key_placeholder: str | None = None
    thinking_style: str = "none"
    model_prefixes: tuple[str, ...] = ()
    known_models: tuple[str, ...] = ()
    default_model: str | None = None
    sdk_extra: str | None = None
    note: str = ""


PROVIDERS: dict[str, ProviderSpec] = {
    "google": ProviderSpec(
        id="google",
        label="Google (Gemini)",
        pydantic_name="google",
        key_names=("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        supports_base_url=True,
        thinking_style="google",
        model_prefixes=("gemini",),
        known_models=(
            "gemini-3.1-pro-preview",
            "gemini-3-flash-preview",
            "gemini-3.1-flash-lite-preview",
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-2.5-flash-lite",
        ),
        default_model="gemini-2.5-flash",
    ),
    "openai": ProviderSpec(
        id="openai",
        label="OpenAI",
        pydantic_name="openai-chat",
        key_names=("OPENAI_API_KEY",),
        supports_base_url=True,
        thinking_style="openai-effort",
        model_prefixes=("gpt-", "o1", "o3", "o4", "chatgpt"),
        known_models=("gpt-5", "gpt-5-mini", "gpt-4.1", "gpt-4o", "o3", "o4-mini"),
        default_model="gpt-5-mini",
    ),
    "anthropic": ProviderSpec(
        id="anthropic",
        label="Anthropic",
        pydantic_name="anthropic",
        key_names=("ANTHROPIC_API_KEY",),
        supports_base_url=True,
        thinking_style="anthropic",
        model_prefixes=("claude",),
        known_models=("claude-opus-4-6", "claude-sonnet-4-5", "claude-haiku-4-5"),
        default_model="claude-haiku-4-5",
    ),
    "deepseek": ProviderSpec(
        id="deepseek",
        label="DeepSeek",
        pydantic_name="deepseek",
        key_names=("DEEPSEEK_API_KEY",),
        model_prefixes=("deepseek",),
        known_models=("deepseek-chat", "deepseek-reasoner"),
        default_model="deepseek-chat",
    ),
    "fireworks": ProviderSpec(
        id="fireworks",
        label="Fireworks AI",
        pydantic_name="fireworks",
        key_names=("FIREWORKS_API_KEY",),
        known_models=(
            "accounts/fireworks/models/llama-v3p3-70b-instruct",
            "accounts/fireworks/models/deepseek-v3",
        ),
        default_model="accounts/fireworks/models/llama-v3p3-70b-instruct",
    ),
    "together": ProviderSpec(
        id="together",
        label="Together AI",
        pydantic_name="together",
        key_names=("TOGETHER_API_KEY",),
        known_models=("meta-llama/Llama-3.3-70B-Instruct-Turbo", "Qwen/Qwen2.5-72B-Instruct-Turbo"),
        default_model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
    ),
    "moonshotai": ProviderSpec(
        id="moonshotai",
        label="Moonshot AI (Kimi)",
        pydantic_name="moonshotai",
        key_names=("MOONSHOTAI_API_KEY",),
        model_prefixes=("kimi",),
        known_models=("kimi-k2-0905-preview", "kimi-latest"),
        default_model="kimi-latest",
    ),
    "vercel": ProviderSpec(
        id="vercel",
        label="Vercel AI Gateway",
        pydantic_name="vercel",
        key_names=("VERCEL_AI_GATEWAY_API_KEY",),
        thinking_style="openai-effort",
        known_models=("openai/gpt-5", "anthropic/claude-sonnet-4.5", "google/gemini-2.5-flash"),
        default_model="google/gemini-2.5-flash",
    ),
    "zai": ProviderSpec(
        id="zai",
        label="Z.AI (GLM)",
        pydantic_name="zai",
        key_names=("ZAI_API_KEY",),
        model_prefixes=("glm",),
        known_models=("glm-4.6", "glm-4.5-air"),
        default_model="glm-4.5-air",
    ),
    "openrouter": ProviderSpec(
        id="openrouter",
        label="OpenRouter",
        pydantic_name="openrouter",
        key_names=("OPENROUTER_API_KEY",),
        known_models=(
            "openai/gpt-5",
            "anthropic/claude-sonnet-4.5",
            "deepseek/deepseek-chat",
            "meta-llama/llama-3.3-70b-instruct",
        ),
        default_model="deepseek/deepseek-chat",
        note="Model names must be vendor-prefixed (e.g. openai/gpt-5); unprefixed ids are rejected.",
    ),
    "alibaba": ProviderSpec(
        id="alibaba",
        label="Alibaba (DashScope/Qwen)",
        pydantic_name="alibaba",
        key_names=("DASHSCOPE_API_KEY", "ALIBABA_API_KEY"),
        supports_base_url=True,
        model_prefixes=("qwen",),
        known_models=("qwen-max", "qwen-plus", "qwen3-max", "qwen-turbo"),
        default_model="qwen-plus",
    ),
    "ollama": ProviderSpec(
        id="ollama",
        label="Ollama (local)",
        pydantic_name="ollama",
        base_url_key_names=("OLLAMA_BASE_URL",),
        requires_key=False,
        supports_base_url=True,
        default_base_url="http://localhost:11434",
        base_url_placeholder="http://localhost:11434",
        key_placeholder="api-key-not-set",
        known_models=("llama3.2", "qwen2.5", "mistral", "gemma3"),
        default_model="llama3.2",
        note=(
            "Keyless and local. A base_url is mandatory and defaults to http://localhost:11434; "
            "it is always passed explicitly, so pydantic-ai never reads OLLAMA_BASE_URL."
        ),
    ),
    "litellm": ProviderSpec(
        id="litellm",
        label="LiteLLM",
        pydantic_name="litellm",
        key_names=("LITELLM_API_KEY",),
        requires_key=False,
        supports_base_url=True,
        base_url_placeholder="http://localhost:4000",
        base_url_kwarg="api_base",
        key_placeholder="litellm-placeholder",
        known_models=("openai/gpt-4o", "anthropic/claude-sonnet-4-5", "ollama/llama3.2"),
        default_model="openai/gpt-4o",
        note=(
            "LITELLM_API_KEY is the gateway credential only; LiteLLM resolves sub-provider keys "
            "from its own environment (a scoped exception to the no-env rule)."
        ),
    ),
    "huggingface": ProviderSpec(
        id="huggingface",
        label="Hugging Face",
        pydantic_name="huggingface",
        key_names=("HF_TOKEN",),
        known_models=("meta-llama/Llama-3.3-70B-Instruct", "Qwen/Qwen2.5-72B-Instruct"),
        default_model="meta-llama/Llama-3.3-70B-Instruct",
        sdk_extra="huggingface_hub",
    ),
    "openai-compatible": ProviderSpec(
        id="openai-compatible",
        label="OpenAI-compatible endpoint",
        pydantic_name="",
        build="openai-compatible",
        key_names=("OPENAI_COMPATIBLE_API_KEY", "OPENAI_API_KEY"),
        requires_key=False,
        supports_base_url=True,
        requires_base_url=True,
        base_url_placeholder="http://localhost:11434/v1",
        key_placeholder="api-key-not-set",
        note="Any OpenAI-compatible endpoint; base_url is required.",
    ),
}

ALLOWED_PROVIDERS: tuple[str, ...] = tuple(PROVIDERS)
LLM_PROVIDER_KEY_NAMES: dict[str, tuple[str, ...]] = {pid: spec.key_names for pid, spec in PROVIDERS.items()}
FRAMEWORK_PROVIDER_KEY_ENV: frozenset[str] = frozenset(name for spec in PROVIDERS.values() for name in spec.key_names)


def get_spec(provider_id: str) -> ProviderSpec:
    """Return the spec for ``provider_id`` (case/whitespace insensitive)."""
    normalized = (provider_id or "").strip().lower()
    spec = PROVIDERS.get(normalized)
    if spec is None:
        raise ProviderConfigError(
            f"Unknown LLM provider '{provider_id}'. Valid providers: {', '.join(ALLOWED_PROVIDERS)}."
        )
    return spec


def key_names_for(provider_id: str) -> tuple[str, ...]:
    """Return the credential names for ``provider_id`` in precedence order."""
    return get_spec(provider_id).key_names


def provider_requires_base_url(provider_id: str | None) -> bool:
    """True when ``provider_id`` mandates a base_url; unknown/empty ids are False."""
    if not (provider_id or "").strip():
        return False
    try:
        return get_spec(provider_id).requires_base_url
    except ProviderConfigError:
        return False


def provider_accepts_base_url(provider_id: str | None) -> bool:
    """True when ``provider_id`` accepts a base_url; unknown/empty ids are False."""
    if not (provider_id or "").strip():
        return False
    try:
        return get_spec(provider_id).supports_base_url
    except ProviderConfigError:
        return False


def sdk_installed(spec: ProviderSpec) -> bool:
    """True when the provider's optional SDK extra is importable."""
    if spec.sdk_extra is None:
        return True
    try:
        return importlib.util.find_spec(spec.sdk_extra) is not None
    except Exception as e:
        logger.debug("SDK probe for provider '%s' failed: %s", spec.id, e)
        return False


def default_model_for(provider_id: str | None) -> str | None:
    """Registry default model for ``provider_id``; None when it has none or is unknown."""
    try:
        return get_spec(provider_id).default_model
    except ProviderConfigError:
        return None


def provider_is_usable(spec: ProviderSpec, keys: Mapping[str, str]) -> bool:
    """True when a framework default could actually serve traffic with what is stored.

    Checks the two things knowable from the registry plus the stored secrets: the
    provider's optional SDK extra is importable, and its required credential (if any)
    is present. Endpoint satisfiability is enforced at save time by the admin route
    (§8) -- the keyless gateways (``ollama``/``litellm``/``openai-compatible``) have no
    global endpoint key, so their base_url is supplied inline with the default triple
    and cannot be checked here.
    """
    keys = keys or {}
    if not sdk_installed(spec):
        return False
    if spec.requires_key and not any(keys.get(name) for name in spec.key_names):
        return False
    return True


def provider_ui_specs() -> tuple[dict, ...]:
    """JSON-serializable projection of the registry for templates and inline JS."""
    return tuple(
        {
            "id": spec.id,
            "label": spec.label,
            "pydantic_name": spec.pydantic_name,
            "requires_key": spec.requires_key,
            "supports_base_url": spec.supports_base_url,
            "requires_base_url": spec.requires_base_url,
            "base_url_placeholder": spec.base_url_placeholder,
            "default_base_url": spec.default_base_url,
            "canonical_key": spec.key_names[0] if spec.key_names else None,
            "key_names": list(spec.key_names),
            "base_url_key": spec.base_url_key_names[0] if spec.base_url_key_names else None,
            "thinking_style": spec.thinking_style,
            "known_models": list(spec.known_models),
            "default_model": spec.default_model,
            "model_prefixes": list(spec.model_prefixes),
            "sdk_extra": spec.sdk_extra,
            "sdk_installed": sdk_installed(spec),
            "note": spec.note,
        }
        for spec in PROVIDERS.values()
    )


def build_provider(
    spec: ProviderSpec,
    api_key: str | None = None,
    base_url: str | None = None,
):
    """Construct the pydantic-ai provider for ``spec``.

    Pure: the caller resolves the key and base_url (from etcd) and passes them
    in. Credentials are always handed to the SDK explicitly -- including
    placeholders for keyless providers -- so the SDK never falls back to its
    environment variables. (An endpoint env var may still apply when no base_url
    is configured for a provider that supports one; see the registry notes.)
    """
    if not sdk_installed(spec):
        raise ProviderConfigError(
            f"Provider '{spec.id}' requires the '{spec.sdk_extra}' package. "
            f"Install it (pip install {spec.sdk_extra}) and rebuild the container."
        )

    key = (api_key or "").strip()
    if spec.requires_key and not key:
        raise ProviderConfigError(
            f"No API key configured for provider '{spec.id}'. Set "
            f"{' or '.join(spec.key_names)} in Admin -> LLM Providers. "
            f"LLM provider keys are stored in etcd, not the environment."
        )

    if spec.build == "openai-compatible":
        url = (base_url or "").strip()
        if spec.requires_base_url and not url:
            raise ProviderConfigError(
                f"Provider '{spec.id}' requires a base_url pointing at the endpoint."
            )
        from pydantic_ai.providers.openai import OpenAIProvider

        return OpenAIProvider(base_url=url, api_key=key or spec.key_placeholder)

    from pydantic_ai.providers import infer_provider_class

    cls = infer_provider_class(spec.pydantic_name)
    kwargs = {}
    if key or spec.key_placeholder:
        kwargs["api_key"] = key or spec.key_placeholder
    if spec.supports_base_url:
        url = (base_url or "").strip() or spec.default_base_url
        if url:
            kwargs[spec.base_url_kwarg] = url
    return cls(**kwargs)
