# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for core.embeddings (Gemini-backed text embeddings).

The google-genai client is faked at the module boundary (``core.embeddings._client``
/ ``_get_client``), so no network is touched. ``cosine`` is pure math and gets
known-answer tests. The module intentionally fails open: unavailable SDK/key or
a failed request makes ``embed_text`` return None so callers fall back to
keyword matching.
"""

import logging
from types import SimpleNamespace

import pytest

import core.embeddings as embeddings
from core import tunables

_VECTOR = [0.1, 0.2, 0.3]


class _FakeModels:
    """Stands in for google-genai's client.models with embed_content recording."""

    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def embed_content(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return SimpleNamespace(embeddings=[SimpleNamespace(values=list(_VECTOR))])


def _patch_client(monkeypatch, models):
    monkeypatch.setattr(embeddings, "_client", SimpleNamespace(models=models))


# --- embed_text ----------------------------------------------------------------

def test_embed_text_returns_vector_list(monkeypatch):
    models = _FakeModels()
    _patch_client(monkeypatch, models)

    result = embeddings.embed_text("rotate the tls certificates")

    assert result == _VECTOR
    assert isinstance(result, list)
    assert all(isinstance(v, float) for v in result)


def test_embed_text_passes_model_contents_and_default_task_type(monkeypatch):
    models = _FakeModels()
    _patch_client(monkeypatch, models)

    embeddings.embed_text("hello")

    (call,) = models.calls
    assert call["model"] == tunables.resolve("agent_embedding_model")
    assert call["contents"] == "hello"
    assert call["config"].task_type == "retrieval_document"


def test_embed_text_forwards_task_type(monkeypatch):
    models = _FakeModels()
    _patch_client(monkeypatch, models)

    embeddings.embed_text("hello", task_type="retrieval_query")

    assert models.calls[0]["config"].task_type == "retrieval_query"


def test_embed_text_blank_input_returns_none_without_calling_model(monkeypatch):
    models = _FakeModels()
    _patch_client(monkeypatch, models)

    assert embeddings.embed_text("") is None
    assert embeddings.embed_text("   ") is None
    assert models.calls == []


def test_embed_text_returns_none_when_client_unavailable(monkeypatch):
    monkeypatch.setattr(embeddings, "_get_client", lambda: None)
    assert embeddings.embed_text("hello") is None


def test_embed_text_fails_open_on_request_error(monkeypatch, caplog):
    _patch_client(monkeypatch, _FakeModels(error=RuntimeError("api down")))

    with caplog.at_level(logging.WARNING, logger="core.embeddings"):
        result = embeddings.embed_text("hello")

    assert result is None
    assert "Embedding request failed" in caplog.text


# --- _get_client ---------------------------------------------------------------

def test_get_client_none_without_api_key(monkeypatch, llm_provider_keys):
    llm_provider_keys.clear()
    embeddings.reset_client_cache()
    assert embeddings._get_client() is None
    assert llm_provider_keys.consulted == ["google"]


def test_get_client_constructs_and_caches(monkeypatch, llm_provider_keys):
    llm_provider_keys["google"] = "test-key"
    embeddings.reset_client_cache()
    created = []

    class _FakeGenaiClient:
        def __init__(self, **kwargs):
            created.append(kwargs)

    monkeypatch.setattr("google.genai.Client", _FakeGenaiClient)

    first = embeddings._get_client()
    second = embeddings._get_client()

    assert first is second
    assert created == [{"api_key": "test-key"}]


# --- cosine --------------------------------------------------------------------

def test_cosine_identical_vectors_is_one():
    assert embeddings.cosine([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == pytest.approx(1.0)


def test_cosine_scaled_vectors_is_one():
    assert embeddings.cosine([3.0, 4.0], [6.0, 8.0]) == pytest.approx(1.0)


def test_cosine_orthogonal_vectors_is_zero():
    assert embeddings.cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_cosine_opposite_vectors_is_minus_one():
    assert embeddings.cosine([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0)


def test_cosine_known_value():
    # dot=1*2+2*3+3*4=20, |a|=sqrt(14), |b|=sqrt(29)
    expected = 20.0 / (14 ** 0.5 * 29 ** 0.5)
    assert embeddings.cosine([1.0, 2.0, 3.0], [2.0, 3.0, 4.0]) == pytest.approx(expected)


def test_cosine_zero_for_missing_mismatched_or_zero_vectors():
    assert embeddings.cosine(None, [1.0]) == 0.0
    assert embeddings.cosine([1.0], None) == 0.0
    assert embeddings.cosine([], [1.0]) == 0.0
    assert embeddings.cosine([1.0, 2.0], [1.0, 2.0, 3.0]) == 0.0
    assert embeddings.cosine([0.0, 0.0], [1.0, 2.0]) == 0.0
