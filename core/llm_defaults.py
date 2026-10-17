# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Framework-level default LLM provider/model/base_url resolution.

One snapshot of the admin-configured default triple drives the whole resolution
matrix; ``core.agent_factory.build_agent`` is the only consumer. The module keeps
``core.llm_factory.resolve_model``/``resolve_provider`` pure: the etcd read lives
here behind a short TTL cache.
"""
import logging
import threading
import time
from dataclasses import dataclass
from typing import Literal

from core.llm_factory import infer_provider
from core.llm_providers import (
    PROVIDERS,
    ProviderConfigError,
    get_spec,
    provider_accepts_base_url,
)

logger = logging.getLogger(__name__)

DEFAULTS_CACHE_TTL_SECONDS = 30.0


@dataclass(frozen=True, slots=True)
class FrameworkDefaults:
    provider: str | None = None
    model: str | None = None
    base_url: str | None = None


@dataclass(frozen=True, slots=True)
class EffectiveLLMConfig:
    provider: str
    model: str
    base_url: str | None
    source: Literal["explicit", "provider-default", "inferred", "framework", "legacy"]


_defaults_cache: FrameworkDefaults | None = None
_defaults_cache_expiry: float = 0.0
_defaults_generation = 0
_defaults_lock = threading.Lock()
_last_logged_invalid: tuple[str | None, str | None, str | None] | None = None


def reset_defaults_cache() -> None:
    """Drop the cached framework defaults so the next lookup re-reads etcd."""
    global _defaults_cache, _defaults_cache_expiry, _defaults_generation
    with _defaults_lock:
        _defaults_generation += 1
        _defaults_cache = None
        _defaults_cache_expiry = 0.0


def _read_raw_defaults() -> tuple[str | None, str | None, str | None]:
    """Read the raw default triple from etcd.

    Lazy import: core.auth imports core.models only, but keeping this local avoids
    any future import cycle through the identity layer (mirrors
    ``llm_factory._read_llm_provider_keys``).
    """
    from core.auth import get_identity_manager

    manager = get_identity_manager()
    return (
        manager.get_default_llm_provider(),
        manager.get_default_llm_model(),
        manager.get_default_llm_base_url(),
    )


def validate_defaults(
    provider: str | None,
    model: str | None,
    base_url: str | None,
    *,
    check_curated: bool = True,
) -> list[str]:
    """Structural errors for a proposed framework default triple (§8).

    A blank provider means "clear/revert" and is always valid. ``check_curated``
    is disabled by the read path so a stored model that has since dropped out of
    ``known_models`` is kept, not dropped (D14). Provider *usability* (credential /
    endpoint / SDK present) is the admin route's job via ``provider_is_usable`` --
    this function only sees the registry.
    """
    p = (provider or "").strip().lower()
    m = (model or "").strip()
    b = (base_url or "").strip()

    if not p:
        return []

    try:
        spec = get_spec(p)
    except ProviderConfigError as e:
        return [str(e)]

    errors: list[str] = []
    if not m and not spec.default_model:
        errors.append(f"Provider '{p}' requires an explicit model; it has no registry default.")
    if check_curated and m and spec.known_models and m not in spec.known_models:
        errors.append(f"Model '{m}' is not one of the curated models for '{p}'.")
    if b and not spec.supports_base_url:
        errors.append(
            f"Provider '{p}' does not accept a base_url; remove it and let the provider "
            f"use its own endpoint."
        )
    if spec.requires_base_url and not b:
        errors.append(f"Provider '{p}' requires a base_url pointing at the endpoint.")
    return errors


def _normalize_defaults(raw: tuple[str | None, str | None, str | None]) -> FrameworkDefaults:
    """Normalize the raw stored triple, dropping any structurally invalid state.

    "Unset" is silent; "invalid" logs once per raw tuple so the 30s refresh cannot
    spam (§6/A6). A stored model is checked with ``check_curated=False`` so a
    once-curated model that has left ``known_models`` is kept (D14).
    """
    global _last_logged_invalid
    p_raw, m_raw, b_raw = raw
    p = (p_raw or "").strip().lower()
    m = (m_raw or "").strip()
    b = (b_raw or "").strip() or None

    if not p and not m and not b:
        return FrameworkDefaults()

    def invalid(reason: str) -> FrameworkDefaults:
        global _last_logged_invalid
        if raw != _last_logged_invalid:
            logger.warning("Ignoring invalid framework LLM default %r: %s", raw, reason)
            _last_logged_invalid = raw
        return FrameworkDefaults()

    if not p:
        return invalid("model/base_url set without a provider")

    try:
        spec = get_spec(p)
    except ProviderConfigError as e:
        return invalid(str(e))

    if not m:
        m = spec.default_model
        if not m:
            return invalid(f"provider '{p}' has no default model")

    # A base_url the provider does not accept is dropped, not treated as invalid:
    # silently demoting the whole triple to case E would move org traffic to Google.
    if b and not spec.supports_base_url:
        logger.warning(
            "Ignoring unsupported base_url %r on framework default provider '%s'.", b, p
        )
        b = None

    errors = validate_defaults(p, m, b, check_curated=False)
    if errors:
        return invalid("; ".join(errors))

    return FrameworkDefaults(provider=p, model=m, base_url=b)


def get_framework_defaults() -> FrameworkDefaults:
    """Return the cached, normalized framework defaults (TTL + generation guard).

    Reads etcd outside the cache lock; fails open to an empty ``FrameworkDefaults``
    on any error so a degraded etcd never breaks an agent build.
    """
    global _defaults_cache, _defaults_cache_expiry
    now = time.monotonic()
    with _defaults_lock:
        if _defaults_cache is not None and now < _defaults_cache_expiry:
            return _defaults_cache
        generation = _defaults_generation

    try:
        raw = _read_raw_defaults()
    except Exception as e:
        logger.warning("Failed to read framework LLM defaults: %s", e)
        return FrameworkDefaults()

    defaults = _normalize_defaults(raw)

    with _defaults_lock:
        # A reset that landed while we were reading must not be shadowed by our
        # stale value; skip the write (the next lookup re-reads etcd).
        if _defaults_generation == generation:
            _defaults_cache = defaults
            _defaults_cache_expiry = time.monotonic() + DEFAULTS_CACHE_TTL_SECONDS
    return defaults


def warm_defaults_cache() -> None:
    """Populate the defaults cache once at startup (best-effort, never raises)."""
    try:
        get_framework_defaults()
    except Exception as e:
        logger.warning("Failed to warm framework LLM default cache: %s", e)


def needs_framework_defaults(provider: str | None, model: str | None) -> bool:
    """False when both provider and model are set (D6); the build short-circuits."""
    return not ((provider or "").strip() and (model or "").strip())


def resolve_effective_llm_config(
    provider: str | None,
    model: str | None,
    base_url: str | None,
    defaults: FrameworkDefaults | None,
) -> EffectiveLLMConfig:
    """Resolve the effective (provider, model, base_url) from the §4 matrix.

    Pure: ``defaults`` is passed in, so the whole matrix is unit-testable without
    etcd. Raises ``ProviderConfigError`` only where resolution genuinely cannot
    proceed (unknown/inferable provider, or a provider with no model at all); a
    missing *required* base_url is left to ``resolve_model``'s canonical message.
    """
    p = (provider or "").strip().lower()
    m = (model or "").strip()
    b = (base_url or "").strip() or None
    has_defaults = bool(defaults and defaults.provider and defaults.model)
    inherited_url = False

    if p and m:
        eff_provider, eff_model, url = p, m, b
        source: Literal["explicit", "provider-default", "inferred", "framework", "legacy"] = "explicit"
    elif p and not m:
        spec = get_spec(p)
        if has_defaults and defaults.provider == p:
            eff_model = defaults.model or spec.default_model
            # §4 precedence: an agent-supplied endpoint always beats the inherited one.
            url = b or defaults.base_url
            inherited_url = not b and bool(defaults.base_url)
        else:
            eff_model = spec.default_model
            url = b
        if not eff_model:
            raise ProviderConfigError(
                f"Provider '{p}' requires an explicit model; it has no registry default."
            )
        eff_provider = p
        source = "provider-default"
    elif not p and m:
        eff_provider = infer_provider(m)
        eff_model = m
        url = b
        source = "inferred"
    elif has_defaults:
        eff_provider = defaults.provider
        eff_model = defaults.model
        url = b or defaults.base_url
        inherited_url = not b and bool(defaults.base_url)
        source = "framework"
    else:
        eff_provider = "google"
        eff_model = PROVIDERS["google"].default_model
        url = b
        source = "legacy"

    # Only an inherited endpoint is dropped silently. An agent-supplied one is passed
    # through so resolve_model raises its canonical error (G4: fully-specified agents
    # keep their previous behaviour).
    if inherited_url and url and not provider_accepts_base_url(eff_provider):
        logger.warning("Dropping inherited base_url for provider '%s': it does not accept one.", eff_provider)
        url = None

    return EffectiveLLMConfig(provider=eff_provider, model=eff_model, base_url=url, source=source)
