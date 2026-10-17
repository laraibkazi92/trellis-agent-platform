# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Test seam for the etcd-backed framework LLM provider keys and endpoints.

Production resolves provider credentials via ``core.llm_factory.get_provider_api_key``
and global endpoints via ``core.llm_factory.get_provider_base_url``, both reading
the encrypted etcd store (``IdentityManager.get_llm_provider_keys``). There is
deliberately no environment fallback, so a test that builds a real pydantic-ai
model without a reachable etcd would block for ~20s per call on ``@retry_etcd``
and then fail.

``install_provider_keys`` swaps the resolvers that consume the store
(``core.llm_factory.get_provider_api_key``, ``core.llm_factory.get_provider_base_url``
and the by-value import in ``core.embeddings``) for in-memory fakes, so no test
ever touches etcd. The returned ``ProviderKeySeam`` is a dict mapping
provider -> key (``DEFAULT_TEST_KEYS`` seeds one per registry entry that requires
a key, so agent construction works offline) and carries a ``base_urls`` map
(provider -> global endpoint, e.g. ``{"ollama": "http://etcd-ollama:11434"}``)
so the etcd-backed base_url path can be exercised without etcd. Tests may clear
or override entries, and ``.consulted`` records which providers were asked for a
key so callers can assert the store was queried for the right provider.
"""
from typing import Dict, Optional

from core.llm_providers import PROVIDERS, ProviderSpec

# Provider -> dummy key, generated from the registry so a newly added provider can
# never be forgotten. Keyless providers (ollama, litellm, openai-compatible) are
# absent by design: they build without a key.
DEFAULT_TEST_KEYS: Dict[str, str] = {
    spec.id: f"test-{spec.id}-key" for spec in PROVIDERS.values() if spec.requires_key
}


class ProviderKeySeam(dict):
    """Mutable provider->key map that records key lookups in ``consulted``.

    ``base_urls`` is the parallel provider->global-endpoint map (only providers
    with ``base_url_key_names``, i.e. ollama, are consulted for one).
    """

    def __init__(
        self,
        keys: Optional[Dict[str, str]] = None,
        base_urls: Optional[Dict[str, str]] = None,
    ):
        super().__init__(DEFAULT_TEST_KEYS)
        if keys:
            self.update(keys)
        self.base_urls: Dict[str, str] = dict(base_urls or {})
        self.consulted: list = []


def install_provider_keys(
    monkeypatch,
    keys: Optional[Dict[str, str]] = None,
    base_urls: Optional[Dict[str, str]] = None,
) -> ProviderKeySeam:
    """Patch the LLM key/endpoint resolvers with an in-memory seam; return it.

    Patching ``core.llm_factory.get_provider_api_key`` / ``get_provider_base_url``
    (plus the by-value key import in ``core.embeddings``) is the seam production's
    ``resolve_model``/embeddings client consume, so this covers every credential
    and endpoint read without involving etcd.
    """
    from core import embeddings, llm_factory, llm_defaults

    seam = ProviderKeySeam(keys, base_urls)

    def fake_get_provider_api_key(provider: str) -> Optional[str]:
        seam.consulted.append(provider)
        return seam.get(provider)

    def fake_get_provider_base_url(spec: ProviderSpec) -> Optional[str]:
        return seam.base_urls.get(spec.id)

    monkeypatch.setattr(llm_factory, "get_provider_api_key", fake_get_provider_api_key)
    monkeypatch.setattr(llm_factory, "get_provider_base_url", fake_get_provider_base_url)
    monkeypatch.setattr(embeddings, "get_provider_api_key", fake_get_provider_api_key)

    # The framework-default read is a second etcd path (core/llm_defaults._read_raw_defaults);
    # neutralize it so a build-path test never touches a real etcd (or picks up a dev box's
    # configured default). Tests that exercise the defaults matrix patch it themselves.
    monkeypatch.setattr(llm_defaults, "_read_raw_defaults", lambda: (None, None, None))
    llm_defaults.reset_defaults_cache()

    # The fake bypasses both caches entirely; reset them so a stale real key/client
    # from an earlier test cannot shadow the seam.
    llm_factory.reset_key_cache()
    embeddings.reset_client_cache()
    return seam
