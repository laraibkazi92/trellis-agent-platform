# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tool registry writes shared by the filesystem sync and the edge relay.

Both writers produce the same shape for a tool: the config under
``/registry/tools/<name>/config`` and, when the tool is public, a description
embedding under ``/registry/tools/<name>/embedding`` used by semantic tool search
(``core/tool_search.py``). Keeping the text shape in one place is what stops an
edge tool and a local tool with the same description from ranking differently.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.embeddings import embed_text

logger = logging.getLogger(__name__)


def embedding_text(name: str, description: str, inputs: Optional[Dict[str, Any]]) -> str:
    """The document string an embedding is built from.

    Mirrors what ``core/tool_search.search_tools`` searches over: the name, the
    description, and the input keys with their types. Input descriptions are not
    included because agents query by capability, not by parameter docs.
    """
    input_keys = ", ".join(
        f"{key}:{spec.get('type', 'any')}" if isinstance(spec, dict) else str(key)
        for key, spec in (inputs or {}).items()
    )
    return "\n".join(part for part in (name, description, input_keys) if part)


def index_tool(
    identity_mgr: Any,
    name: str,
    description: str,
    inputs: Optional[Dict[str, Any]] = None,
    *,
    embedding_name: Optional[str] = None,
) -> bool:
    """Index one tool's embedding. Returns False when embeddings are unavailable.

    ``embedding_name`` lets MCP tools keep their ``mcp__{server}__{tool}`` lookup
    key while the document text is built the same way as for a local tool.
    """
    vector = embed_text(
        embedding_text(name, description, inputs), task_type="retrieval_document"
    )
    if not vector:
        return False
    identity_mgr.save_tool_embedding(embedding_name or name, vector)
    return True


def delete_tool(identity_mgr: Any, name: str) -> None:
    """Remove a tool's config and embedding.

    Always both: a config without an embedding disappears from semantic search but
    stays executable, and an embedding without a config surfaces as a ghost hit.
    """
    identity_mgr.client.delete(f"/registry/tools/{name}/config")
    identity_mgr.client.delete(f"/registry/tools/{name}/embedding")
