# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Lightweight text-embedding helper backed by Google Gemini.

Used to power semantic agent discovery (see ``core.agent_search``). Embeddings are
computed at sync time for each agent and at query time for search requests.

Degrades gracefully: if the Gemini SDK or ``GEMINI_API_KEY`` is unavailable,
``embed_text`` returns ``None`` so callers can fall back to keyword matching.
"""
import os
import math
import logging
from typing import List, Optional

from core.tunables import resolve as resolve_tunable

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    """Return a configured google.genai Client, or None if unavailable."""
    global _client
    if _client is not None:
        return _client
    try:
        from google import genai
    except ImportError:
        logger.warning("google-genai not installed; embeddings disabled.")
        return None

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        logger.warning("GEMINI_API_KEY not set; embeddings disabled.")
        return None

    _client = genai.Client(api_key=api_key)
    return _client


def embed_text(text: str, task_type: str = "retrieval_document") -> Optional[List[float]]:
    """Embed a single string. Returns the vector, or None if embeddings are unavailable.

    Use ``task_type="retrieval_document"`` when indexing agents and
    ``task_type="retrieval_query"`` when embedding a search query.
    """
    client = _get_client()
    if client is None or not text or not text.strip():
        return None
    try:
        from google.genai import types
        response = client.models.embed_content(
            model=resolve_tunable("agent_embedding_model"),
            contents=text,
            config=types.EmbedContentConfig(task_type=task_type),
        )
        return list(response.embeddings[0].values)
    except Exception as e:
        logger.warning(f"Embedding request failed: {e}")
        return None


def cosine(a: Optional[List[float]], b: Optional[List[float]]) -> float:
    """Cosine similarity in [-1, 1]. Returns 0.0 for missing/mismatched vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)
