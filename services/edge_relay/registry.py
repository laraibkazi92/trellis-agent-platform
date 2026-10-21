# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Registry writes owned by the edge relay.

The relay is the sole writer of ``/registry/tools/<site>__<tool>``: those tools never
exist on the central disk, and ``managed_by: "edge-relay"`` is the marker that makes
``sync_to_db``'s prune skip them and the tool editor read-only. The relay also owns
each site's ``/registry/edges/<site>/status``, which is what makes an offline edge show
up as an unconfigured tool rather than a mysterious failure.

Everything here is synchronous etcd I/O; callers run it via ``asyncio.to_thread``.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.health import HealthMonitor
from core.tool_index import delete_tool, index_tool
from services.edge_relay.protocol import EdgeTool, tool_name

logger = logging.getLogger(__name__)

TOOLS_PREFIX = "/registry/tools/"
MANAGED_BY = "edge-relay"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def tool_registry_name(site: str, tool: str) -> str:
    """Registry name for one edge tool (``<site>__<tool>``); the site is the routing key."""
    return tool_name(site, tool)


def _site_tool_configs(identity_mgr: Any, site: str) -> Dict[str, Dict]:
    """Existing ``<site>__*`` configs in one prefix fetch.

    A value that is not a JSON object is stored as ``{}`` -- i.e. "not ours" -- so both
    the collision check and the prune leave it alone instead of guessing at ownership.
    """
    prefix = f"{TOOLS_PREFIX}{site}__"
    configs: Dict[str, Dict] = {}
    for value, metadata in identity_mgr.client.get_prefix(prefix):
        key = metadata.key.decode("utf-8")
        if not key.startswith(prefix) or not key.endswith("/config"):
            continue
        name = key[len(TOOLS_PREFIX):-len("/config")]
        try:
            parsed = json.loads(value.decode("utf-8")) if value else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            parsed = None
        configs[name] = parsed if isinstance(parsed, dict) else {}
    return configs


def _dev_site_config(site: str) -> Optional[Dict[str, Any]]:
    """Synthetic enrollment record for the DEV_MODE tunnel hatch.

    Without it the hatch authenticates a handshake and then dies on publish, which
    is worse than not having the hatch: `.env.example` advertises the shortcut.
    """
    if os.getenv("DEV_MODE", "false").lower() not in ("1", "true", "yes"):
        return None
    if site != (os.getenv("EDGE_DEV_SITE") or "dev-edge"):
        return None
    return {
        "name": site,
        "display_name": "dev edge",
        "enabled": True,
        "exports": [],
        "public": False,
        "public_tools": [],
    }


def effective_site_config(identity_mgr: Any, site: str) -> Optional[Dict[str, Any]]:
    """The site's registry record, or the synthetic DEV_MODE record when enabled.

    Single resolver so the handshake, the catalog publish, and the heartbeat
    revalidation cannot disagree about whether a dev-hatch site exists.
    """
    return identity_mgr.get_edge_config(site) or _dev_site_config(site)


def _embedding_changed(previous: Dict[str, Any], current: Dict[str, Any]) -> bool:
    """True when the text an embedding is built from actually changed."""
    return (
        previous.get("description") != current.get("description")
        or previous.get("inputs") != current.get("inputs")
    )


def _tool_config(site: str, tool: EdgeTool, site_config: Dict[str, Any]) -> Dict[str, Any]:
    """The registry shape of one remote tool.

    Deliberately no ``secrets``, ``variables``, ``entrypoint`` or ``rel_path``: the
    tool executes on the edge with the edge's own credentials, and there is no local
    artifact for either field to point at.
    """
    return {
        "name": tool_name(site, tool.name),
        "description": tool.description,
        "runtime": "remote",
        "inputs": tool.inputs,
        "remote": {"site": site, "tool": tool.name},
        "managed_by": MANAGED_BY,
        # tool_search only honours `public` for non-mcp tools, so a per-tool
        # whitelist entry has to be folded into the flag to mean anything.
        "public": bool(site_config.get("public")) or tool.name in (site_config.get("public_tools") or []),
        "public_tools": site_config.get("public_tools", []),
        # A dropped call cannot be replayed safely: the caller may already have
        # caused a side effect on the edge.
        "retry_on_transient": False,
        "version": "0.1.0",
    }


def publish_catalog(
    identity_mgr: Any,
    site: str,
    tools: List[EdgeTool],
    edge_version: str,
    *,
    allow_empty: bool = False,
) -> List[str]:
    """Write a site's published catalog to the registry and refresh its status.

    Raises ``ValueError`` when the site is gone or disabled: the handshake validated
    the token, but a site can be deleted or revoked between the upgrade and this write.

    ``allow_empty`` guards the destructive case: a handshake that publishes nothing
    (a mistyped ``tools_dir``, a workspace volume that was not mounted) would otherwise
    prune the site's entire central inventory. An admin narrowing ``exports`` to nothing
    is an explicit intent and passes ``allow_empty=True``.
    """
    site_config = effective_site_config(identity_mgr, site)
    if site_config and not identity_mgr.get_edge_config(site):
        logger.warning(
            "DEV_MODE: publishing a catalog for dev edge '%s' with no registry record", site
        )
    if not site_config or not site_config.get("enabled", True):
        raise ValueError(f"edge '{site}' is not registered or is disabled")

    # A non-empty `exports` is an admin-side allowlist that overrides the edge. Empty
    # means "accept whatever the edge published": the edge already enforces its own
    # local allowlist, and forcing admins to duplicate it would make a freshly
    # installed edge silently publish nothing.
    exports = site_config.get("exports") or []
    catalog = [tool for tool in tools if not exports or tool.name in exports]

    existing = _site_tool_configs(identity_mgr, site)
    # Local sync only embeds tools the gateway exposes (`public`), so an internal
    # edge tool must not pay a provider call for a vector search will never rank.
    published: List[str] = []
    for tool in catalog:
        name = tool_name(site, tool.name)
        current = existing.get(name)
        if current is not None and current.get("managed_by") != MANAGED_BY:
            # A local tool wins: an edge must never shadow one by publishing its name.
            logger.warning(
                "edge '%s' tool '%s' collides with an existing non-edge tool; skipped",
                site,
                tool.name,
            )
            continue
        config = _tool_config(site, tool, site_config)
        identity_mgr.save_tool_config(name, config)
        if config["public"]:
            # The relay owns these embeddings; sync never sees the tool on disk and
            # would otherwise leave a removed tool's vector ranking in search forever.
            # Re-index only when the text changed: a flapping edge must not rebuild
            # the whole catalog's vectors on every reconnect.
            # Also re-index on a visibility *promotion*: a tool that was private on
            # the first publish has no vector, and search would rank it last forever.
            if not current or current.get("public") is not True or _embedding_changed(current, config):
                if not index_tool(identity_mgr, name, tool.description, tool.inputs):
                    # Usually a decryptable LLM key is missing (ENCRYPTION_KEY on the
                    # relay). The tool still works; it just cannot be found by search.
                    logger.warning(
                        "could not index tool '%s' for search (embeddings unavailable); "
                        "it will rank last in tool search",
                        name,
                    )
        published.append(name)

    owned = {
        name for name, config in existing.items() if config.get("managed_by") == MANAGED_BY
    }
    if not published and owned and not allow_empty:
        logger.error(
            "edge '%s' published an empty catalog; keeping %d existing tool(s) instead of "
            "pruning them. Check exports/tools_dir on the edge (an admin export change "
            "still prunes).",
            site,
            len(owned),
        )
        identity_mgr.save_edge_status(
            site,
            {
                "connected": True,
                "connected_at": _now_iso(),
                "edge_version": edge_version,
                "tools": sorted(owned),
                "last_error": (
                    "the edge published an empty catalog; existing tools were kept. "
                    "Check exports/tools_dir on the site."
                ),
            },
        )
        return sorted(owned)

    for name, config in existing.items():
        if name in published:
            continue
        if config.get("managed_by") != MANAGED_BY:
            continue
        delete_tool(identity_mgr, name)
        logger.info("edge '%s' pruned tool '%s' (no longer in its catalog)", site, name)

    identity_mgr.save_edge_status(
        site,
        {
            "connected": True,
            "connected_at": _now_iso(),
            "edge_version": edge_version,
            "tools": published,
            "last_error": None,
        },
    )
    # Connectivity is back: clear the Offline state a disconnect (or a failed call
    # while the edge was down) left behind, otherwise a healthy tool keeps showing
    # as offline until its next successful call.
    try:
        monitor = HealthMonitor(identity_mgr)
        for name in published:
            monitor.record_event("tool", name, True)
    except Exception as exc:
        logger.warning("could not reset health for site=%s: %s", site, exc)
    logger.info(
        "edge catalog published site=%s version=%s tools=%d", site, edge_version, len(published)
    )
    return published


def mark_disconnected(identity_mgr: Any, site: str, reason: str) -> None:
    """Record that a site's tunnel is gone, without deleting what it published.

    The tool configs stay: the edge may just be restarting, and removing them would
    erase the inventory an admin needs to see (and the names agents already reference).
    Losing connectivity is a health event per tool, which is what stops the hub from
    treating an offline edge's tools as merely unlucky.
    """
    previous = identity_mgr.get_edge_status(site) or {}
    tools = previous.get("tools") or []
    identity_mgr.save_edge_status(
        site,
        {
            "connected": False,
            "connected_at": previous.get("connected_at"),
            "disconnected_at": _now_iso(),
            "edge_version": previous.get("edge_version"),
            "tools": tools,
            "last_error": reason,
        },
    )

    monitor = HealthMonitor(identity_mgr)
    for name in tools:
        monitor.record_event("tool", name, False, f"edge '{site}' disconnected: {reason}")
    logger.info("edge marked disconnected site=%s tools=%d reason=%s", site, len(tools), reason)
