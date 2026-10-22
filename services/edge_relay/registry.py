# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Registry writes owned by the edge relay.

The relay is the sole writer of ``/registry/tools/<site>__<tool>`` and
``/registry/mcps/<site>__<mcp>``: those never exist on the central disk, and
``managed_by: "edge-relay"`` is the marker that makes ``sync_to_db``'s prune skip them
(and the tool editor read-only). The relay also owns each site's
``/registry/edges/<site>/status``, which is what makes an offline edge show up as an
unconfigured tool rather than a mysterious failure.

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
from services.edge_relay.protocol import EdgeMcp, EdgeTool, tool_name

logger = logging.getLogger(__name__)

TOOLS_PREFIX = "/registry/tools/"
MCPS_PREFIX = "/registry/mcps/"
MANAGED_BY = "edge-relay"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def tool_registry_name(site: str, tool: str) -> str:
    """Registry name for one edge tool (``<site>__<tool>``); the site is the routing key."""
    return tool_name(site, tool)


def mcp_registry_name(site: str, mcp: str) -> str:
    """Registry name for one edge MCP server. Same ``<site>__<name>`` rule as tools."""
    return tool_name(site, mcp)


def _configs_under(identity_mgr: Any, base: str, prefix: str) -> Dict[str, Dict]:
    """Existing configs under one name prefix, keyed by registry name.

    A value that is not a JSON object is stored as ``{}`` -- i.e. "not ours" -- so both
    the collision check and the prune leave it alone instead of guessing at ownership.
    """
    configs: Dict[str, Dict] = {}
    for value, metadata in identity_mgr.client.get_prefix(prefix):
        key = metadata.key.decode("utf-8")
        if not key.startswith(prefix) or not key.endswith("/config"):
            continue
        name = key[len(base):-len("/config")]
        try:
            parsed = json.loads(value.decode("utf-8")) if value else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            parsed = None
        configs[name] = parsed if isinstance(parsed, dict) else {}
    return configs


def _site_tool_configs(identity_mgr: Any, site: str) -> Dict[str, Dict]:
    """Existing ``<site>__*`` tool configs in one prefix fetch."""
    return _configs_under(identity_mgr, TOOLS_PREFIX, f"{TOOLS_PREFIX}{site}__")


def _site_mcp_configs(identity_mgr: Any, site: str) -> Dict[str, Dict]:
    """Existing ``<site>__*`` MCP configs in one prefix fetch."""
    return _configs_under(identity_mgr, MCPS_PREFIX, f"{MCPS_PREFIX}{site}__")


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


def _save_status(
    identity_mgr: Any,
    site: str,
    *,
    edge_version: str,
    tools: List[str],
    mcps: Optional[List[Dict[str, Any]]],
    proto: Optional[int],
    caps: Optional[List[str]],
    warning: Optional[str],
) -> None:
    """One authoritative "connected" status write.

    Tools and MCP catalogs are published by two consecutive calls; a value the caller
    did not supply is kept from the record already there so the second write cannot
    erase the first. ``None`` is dropped rather than stored: a v0.4 relay never wrote
    ``proto``/``mcps``, and an empty key would read as "unknown" in the admin UI.
    """
    previous = identity_mgr.get_edge_status(site) or {}
    # Tools and MCPs are published by two consecutive writes; the second must not move
    # the connect time the first one just set, or the admin page shows a site that
    # reconnected a second ago on every catalog change while it stays connected.
    connected_at = previous.get("connected_at") if previous.get("connected") else None
    status: Dict[str, Any] = {
        "connected": True,
        "connected_at": connected_at or _now_iso(),
        "edge_version": edge_version,
        "tools": tools,
        "last_error": warning,
    }
    for key, value in (
        ("mcps", mcps if mcps is not None else previous.get("mcps")),
        ("proto", proto if proto is not None else previous.get("proto")),
        ("caps", caps if caps is not None else previous.get("caps")),
    ):
        if value is not None:
            status[key] = value
    identity_mgr.save_edge_status(site, status)


def _mcp_status_entries(mcps: List[EdgeMcp]) -> List[Dict[str, Any]]:
    """The status view of an MCP catalog: name, tool count, the edge's real transport."""
    return [
        {"name": mcp.name, "tools": len(mcp.tools), "transport": mcp.transport}
        for mcp in mcps
    ]


def _mcp_status_from_configs(
    existing: Dict[str, Dict], names: List[str]
) -> List[Dict[str, Any]]:
    """The same view, rebuilt from the registry for a catalog that was kept, not sent."""
    entries: List[Dict[str, Any]] = []
    for name in names:
        config = existing.get(name) or {}
        entries.append(
            {
                "name": name.split("__", 1)[-1],
                "tools": len(config.get("tools") or []),
                "transport": config.get("edge_transport") or "",
            }
        )
    return entries


def publish_catalog(
    identity_mgr: Any,
    site: str,
    tools: List[EdgeTool],
    edge_version: str,
    *,
    allow_empty: bool = False,
    mcps: Optional[List[EdgeMcp]] = None,
    proto: Optional[int] = None,
    caps: Optional[List[str]] = None,
) -> List[str]:
    """Write a site's published tool catalog to the registry and refresh its status.

    Raises ``ValueError`` when the site is gone or disabled: the handshake validated
    the token, but a site can be deleted or revoked between the upgrade and this write.

    ``allow_empty`` guards the destructive case: a handshake that publishes nothing
    (a mistyped ``tools_dir``, a workspace volume that was not mounted) would otherwise
    prune the site's entire central inventory. An admin narrowing ``exports`` to nothing
    is an explicit intent and passes ``allow_empty=True``.

    ``mcps``/``proto``/``caps`` are status-only: they let one write carry the whole
    handshake, so the admin page never shows a connected site with its MCP half missing.
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
    empty_catalog_warning = None
    if not published and owned and not allow_empty:
        logger.error(
            "edge '%s' published an empty catalog; keeping %d existing tool(s) instead of "
            "pruning them. Check exports/tools_dir on the edge (an admin export change "
            "still prunes).",
            site,
            len(owned),
        )
        published = sorted(owned)
        empty_catalog_warning = (
            "the edge published an empty catalog; existing tools were kept. "
            "Check exports/tools_dir on the site."
        )
    else:
        for name, config in existing.items():
            if name in published:
                continue
            if config.get("managed_by") != MANAGED_BY:
                continue
            delete_tool(identity_mgr, name)
            logger.info("edge '%s' pruned tool '%s' (no longer in its catalog)", site, name)

    _save_status(
        identity_mgr,
        site,
        edge_version=edge_version,
        tools=published,
        mcps=_mcp_status_entries(mcps) if mcps is not None else None,
        proto=proto,
        caps=caps,
        warning=empty_catalog_warning,
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


def _mcp_visibility(
    site: str, mcp: EdgeMcp, site_config: Dict[str, Any]
) -> tuple[bool, List[str]]:
    """``(public, public_tools)`` for one edge MCP server, derived like an edge tool's.

    A site marked public opts every MCP server it exports in as well. Otherwise the
    site's ``public_tools`` may name this server's tools in any documented reference
    form -- ``mcp__<site>__<mcp>__<tool>``, ``<site>__<mcp>__<tool>``, or the whole
    server as ``mcp__<site>__<mcp>`` / ``<site>__<mcp>``. Only the **bare** tool names
    are stored, because ``core.tool_search`` compares them against each tool's own name.
    """
    if site_config.get("public") is True:
        return True, []
    entries = site_config.get("public_tools") or []
    if not isinstance(entries, list):
        return False, []
    refs = [entry for entry in entries if isinstance(entry, str)]
    known = [tool.name for tool in mcp.tools]
    if any(ref in (f"mcp__{site}__{mcp.name}", f"{site}__{mcp.name}") for ref in refs):
        return False, sorted(known)
    selected: List[str] = []
    for ref in refs:
        for prefix in (f"mcp__{site}__{mcp.name}__", f"{site}__{mcp.name}__"):
            if not ref.startswith(prefix):
                continue
            bare = ref[len(prefix):]
            if bare in known and bare not in selected:
                selected.append(bare)
            break
    return False, selected


def _mcp_config(site: str, mcp: EdgeMcp, site_config: Dict[str, Any]) -> Dict[str, Any]:
    """The registry shape of one remote MCP server.

    ``tools`` carries each tool's ``inputSchema`` verbatim (L6: root-level ``oneOf`` and
    friends must survive mcp.yaml -> hello -> registry byte-identical). Deliberately no
    ``command``/``args``/``env``/``secrets``/``variables``: the server runs on the edge
    with the edge's own credentials, and central has nothing to launch.

    Visibility comes from the site record, never from the edge: an edge must not be able
    to widen its own public surface by publishing a flag.
    """
    public, public_tools = _mcp_visibility(site, mcp, site_config)
    return {
        "name": mcp_registry_name(site, mcp.name),
        # EdgeMcp carries no server description yet; keep the key populated for the
        # day it does, and for readers that assume a central-shaped config.
        "description": getattr(mcp, "description", "") or "",
        # "remote" is the routing kind central acts on; the edge's own transport
        # (stdio/http/sse) is display-only and kept under `edge_transport`.
        "transport": "remote",
        "tools": [tool.as_dict() for tool in mcp.tools],
        "remote": {"site": site, "mcp": mcp.name},
        "managed_by": MANAGED_BY,
        "public": public,
        "public_tools": public_tools,
        "edge_transport": mcp.transport,
        "version": "0.1.0",
    }


def _index_mcp_tools(
    identity_mgr: Any,
    site: str,
    mcp: EdgeMcp,
    previous: Optional[Dict[str, Any]],
) -> None:
    """Description-only embeddings for one server's tools.

    ``inputs=None`` is what keeps this affordable: an MCP tool schema is up to 128 KiB
    of discriminated union, and embedding it would cost a large payload for text a
    searcher never ranks by. Re-index only a new or re-described tool -- a flapping
    edge re-publishes its whole catalog on every reconnect.

    Indexed even while the server is private: a later promotion then needs no
    re-embedding, and ``search_tools`` filters on ``public`` at query time.
    """
    previous_descriptions = {
        entry.get("name"): entry.get("description")
        for entry in (previous or {}).get("tools") or []
        if isinstance(entry, dict)
    }
    for tool in mcp.tools:
        name = f"mcp__{site}__{mcp.name}__{tool.name}"
        if tool.name in previous_descriptions and previous_descriptions[tool.name] == tool.description:
            continue
        if not index_tool(identity_mgr, name, tool.description, None, embedding_name=name):
            # Usually a missing LLM key on the relay. The tool still works; it just
            # cannot be found by search.
            logger.warning(
                "could not index mcp tool '%s' for search (embeddings unavailable); "
                "it will rank last in tool search",
                name,
            )


def _delete_mcp(identity_mgr: Any, name: str) -> None:
    """Remove one MCP's config and every tool embedding indexed under its name."""
    identity_mgr.client.delete(f"{MCPS_PREFIX}{name}/config")
    # `mcp__<site>__<mcp>__<tool>` embeddings live under this prefix; without this
    # they outlive the config and keep ranking in tool search as ghost hits.
    identity_mgr.client.delete_prefix(f"/registry/tools/mcp__{name}__")


def publish_mcp_catalog(
    identity_mgr: Any,
    site: str,
    mcps: List[EdgeMcp],
    edge_version: str,
    *,
    allow_empty: bool = False,
    proto: Optional[int] = None,
    caps: Optional[List[str]] = None,
) -> List[str]:
    """Write a site's exported MCP servers and their tool embeddings.

    Mirrors ``publish_catalog`` on purpose: same site guard, same shadow refusal (a
    local MCP with the same name wins, an edge may never hijack one), same empty-catalog
    guard. The status record keeps the tool half written by the preceding
    ``publish_catalog`` call, so the pair reads as one handshake.
    """
    site_config = effective_site_config(identity_mgr, site)
    if site_config and not identity_mgr.get_edge_config(site):
        logger.warning(
            "DEV_MODE: publishing MCPs for dev edge '%s' with no registry record", site
        )
    if not site_config or not site_config.get("enabled", True):
        raise ValueError(f"edge '{site}' is not registered or is disabled")

    existing = _site_mcp_configs(identity_mgr, site)
    published: List[str] = []
    for mcp in mcps:
        name = mcp_registry_name(site, mcp.name)
        current = existing.get(name)
        if current is not None and current.get("managed_by") != MANAGED_BY:
            logger.warning(
                "edge '%s' mcp '%s' collides with an existing non-edge MCP; skipped",
                site,
                mcp.name,
            )
            continue
        identity_mgr.save_mcp_config(name, _mcp_config(site, mcp, site_config))
        _index_mcp_tools(identity_mgr, site, mcp, current)
        published.append(name)

    owned = {
        name for name, config in existing.items() if config.get("managed_by") == MANAGED_BY
    }
    empty_catalog_warning = None
    if not published and owned and not allow_empty:
        logger.error(
            "edge '%s' published no MCPs; keeping %d existing one(s) instead of pruning "
            "them. Check export_mcps on the edge (an admin change still prunes).",
            site,
            len(owned),
        )
        published = sorted(owned)
        empty_catalog_warning = (
            "the edge published no MCPs; existing MCPs were kept. "
            "Check export_mcps on the site."
        )
    else:
        for name, config in existing.items():
            if name in published or config.get("managed_by") != MANAGED_BY:
                continue
            _delete_mcp(identity_mgr, name)
            logger.info("edge '%s' pruned mcp '%s' (no longer in its catalog)", site, name)

    previous = identity_mgr.get_edge_status(site) or {}
    if empty_catalog_warning:
        entries = _mcp_status_from_configs(existing, published)
    else:
        sent = {mcp_registry_name(site, mcp.name): mcp for mcp in mcps}
        entries = _mcp_status_entries([sent[name] for name in published])
    _save_status(
        identity_mgr,
        site,
        edge_version=edge_version,
        tools=previous.get("tools") or [],
        mcps=entries,
        proto=proto,
        caps=caps,
        # Keep a tool-side warning (empty tools catalog) unless this write has its own.
        warning=empty_catalog_warning or previous.get("last_error"),
    )
    logger.info(
        "edge MCP catalog published site=%s version=%s mcps=%d",
        site,
        edge_version,
        len(published),
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
    status: Dict[str, Any] = {
        "connected": False,
        "connected_at": previous.get("connected_at"),
        "disconnected_at": _now_iso(),
        "edge_version": previous.get("edge_version"),
        "tools": tools,
        "last_error": reason,
    }
    # The MCP half of the inventory survives for the same reason the tools do, and
    # `proto`/`caps` stay so the admin page keeps describing the site that was there.
    # No health event is recorded per MCP tool: an edge MCP's readiness is derived from
    # this status (`core.discovery._remote_tool_configuration_status`), not from
    # `/health/tool` entries, so there is nothing to reset or invalidate here.
    for key in ("mcps", "proto", "caps"):
        if key in previous:
            status[key] = previous[key]
    identity_mgr.save_edge_status(site, status)

    monitor = HealthMonitor(identity_mgr)
    for name in tools:
        monitor.record_event("tool", name, False, f"edge '{site}' disconnected: {reason}")
    logger.info("edge marked disconnected site=%s tools=%d reason=%s", site, len(tools), reason)
