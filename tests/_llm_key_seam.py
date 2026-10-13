# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Test seam for the etcd-backed framework LLM provider keys.

Production resolves provider keys via ``core.llm_factory.get_provider_api_key``,
which reads the encrypted etcd store (``IdentityManager.get_llm_provider_keys``).
There is deliberately no environment fallback, so a test that builds a real
pydantic-ai model without a reachable etcd would block for ~20s per call on
``@retry_etcd`` and then fail.

``install_provider_keys`` swaps the two module-level resolvers that consume the
store (``core.llm_factory`` and ``core.embeddings``) for an in-memory fake, so no
test ever touches etcd. The returned ``ProviderKeySeam`` is a dict mapping
provider -> key (defaults seeded so agent construction works offline); tests may
clear or override entries, and ``.consulted`` records which providers were asked
for a key so callers can assert the store was queried for the right provider.
"""
from typing import Dict, Optional

# Provider -> dummy key. `openai-compatible` is intentionally absent: it needs no key.
DEFAULT_TEST_KEYS: Dict[str, str] = {
    "google": "test-google-key",
    "openai": "test-openai-key",
    "anthropic": "test-anthropic-key",
}


class ProviderKeySeam(dict):
    """Mutable provider->key map that records key lookups in ``consulted``."""

    def __init__(self, keys: Optional[Dict[str, str]] = None):
        super().__init__(DEFAULT_TEST_KEYS)
        if keys:
            self.update(keys)
        self.consulted: list = []


def install_provider_keys(monkeypatch, keys: Optional[Dict[str, str]] = None) -> ProviderKeySeam:
    """Patch the LLM key resolvers with an in-memory seam; return it.

    Patching ``core.llm_factory.get_provider_api_key`` (and the by-value import in
    ``core.embeddings``) is the seam production's ``resolve_model``/embeddings
    client consume, so this covers every key read without involving etcd.
    """
    from core import embeddings, llm_factory

    seam = ProviderKeySeam(keys)

    def fake_get_provider_api_key(provider: str) -> Optional[str]:
        seam.consulted.append(provider)
        return seam.get(provider)

    monkeypatch.setattr(llm_factory, "get_provider_api_key", fake_get_provider_api_key)
    monkeypatch.setattr(embeddings, "get_provider_api_key", fake_get_provider_api_key)

    # The fake bypasses both caches entirely; reset them so a stale real key/client
    # from an earlier test cannot shadow the seam.
    llm_factory.reset_key_cache()
    embeddings.reset_client_cache()
    return seam
