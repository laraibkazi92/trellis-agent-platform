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

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.health import HealthMonitor
from core.tool_index import delete_tool, index_tool
from services.edge_relay import protocol
from services.edge_relay.protocol import EdgeCredentials, EdgeMcp, EdgeTool, tool_name

logger = logging.getLogger(__name__)

TOOLS_PREFIX = "/registry/tools/"
MCPS_PREFIX = "/registry/mcps/"
MANAGED_BY = "edge-relay"
# Display-only rotation trail (the overlap set that gates writes is ``edge_key_fps``).
MAX_KEY_HISTORY = 10


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


def tool_visibility(site_config: Dict[str, Any], tool_name: str) -> bool:
    """Is one edge tool exposed to callers with no agent record?

    The site record is the only source: a site marked ``public`` publishes every tool
    it exports, otherwise ``public_tools`` names the individual ones. The edge itself
    never widens this (it publishes no exposure flag).
    """
    if site_config.get("public") is True:
        return True
    entries = site_config.get("public_tools") or []
    return isinstance(entries, list) and tool_name in entries


def _tool_config(
    site: str,
    tool: EdgeTool,
    site_config: Dict[str, Any],
    *,
    lazy_catalog: bool = False,
) -> Dict[str, Any]:
    """The registry shape of one remote tool.

    Deliberately no ``secrets``, ``variables``, ``entrypoint`` or ``rel_path``: the
    tool executes on the edge with the edge's own credentials, and there is no local
    artifact for either field to point at.
    """
    config: Dict[str, Any] = {
        "name": tool_name(site, tool.name),
        "description": tool.description,
        "runtime": "remote",
        "inputs": tool.inputs,
        "remote": {"site": site, "tool": tool.name},
        "managed_by": MANAGED_BY,
        # tool_search only honours `public` for non-mcp tools, so a per-tool
        # whitelist entry has to be folded into the flag to mean anything.
        "public": tool_visibility(site_config, tool.name),
        "public_tools": site_config.get("public_tools", []),
        # A dropped call cannot be replayed safely: the caller may already have
        # caused a side effect on the edge.
        "retry_on_transient": False,
        "version": "0.1.0",
    }
    # `detail` says whether this record can be executed from as-is. Only a lazy edge
    # can publish a summary (`inputs` omitted), so only a lazy publish writes the key:
    # without the cap the record keeps the exact shape earlier relays wrote, and an
    # absent key reads as "full" (those edges always sent their inputs).
    if lazy_catalog:
        config["detail"] = "lazy" if not tool.inputs else "full"
    return config


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
    lazy_catalog: bool = False,
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

    ``lazy_catalog`` is the caller's reading of the ``lazy_catalog`` capability: when
    set, the edge may publish summaries and the record says so in ``detail``. Any stale
    full detail is *replaced* by this write -- a republish is the cache invalidation.
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
        if tool.name.endswith("_"):
            # No `<site>__<tool>` reference can end in `_` (see core/models.py): the
            # tool would be callable by nobody. Refuse to write it rather than publish
            # an entry every manifest is unable to name.
            logger.warning(
                "edge '%s' tool '%s' ends with '_' and has no reference form; skipped",
                site,
                tool.name,
            )
            continue
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
        config = _tool_config(site, tool, site_config, lazy_catalog=lazy_catalog)
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


def mcp_visibility(
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


def _mcp_config(
    site: str,
    mcp: EdgeMcp,
    site_config: Dict[str, Any],
    *,
    lazy_catalog: bool = False,
) -> Dict[str, Any]:
    """The registry shape of one remote MCP server.

    ``tools`` carries each tool's ``inputSchema`` verbatim (L6: root-level ``oneOf`` and
    friends must survive mcp.yaml -> hello -> registry byte-identical). Deliberately no
    ``command``/``args``/``env``/``secrets``/``variables``: the server runs on the edge
    with the edge's own credentials, and central has nothing to launch.

    Visibility comes from the site record, never from the edge: an edge must not be able
    to widen its own public surface by publishing a flag.
    """
    public, public_tools = mcp_visibility(site, mcp, site_config)
    config: Dict[str, Any] = {
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
    # Same rule as the tool half, one level up: the flag is present (and "lazy") only
    # when a lazy edge actually withheld a schema. A full server is stored exactly as
    # published, and a missing key reads as "full" for records written before the cap.
    if lazy_catalog:
        missing_schema = any(not tool.input_schema for tool in mcp.tools)
        config["detail"] = "lazy" if missing_schema else "full"
    return config


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
    lazy_catalog: bool = False,
) -> List[str]:
    """Write a site's exported MCP servers and their tool embeddings.

    Mirrors ``publish_catalog`` on purpose: same site guard, same shadow refusal (a
    local MCP with the same name wins, an edge may never hijack one), same empty-catalog
    guard. The status record keeps the tool half written by the preceding
    ``publish_catalog`` call, so the pair reads as one handshake.

    ``lazy_catalog`` is passed through to ``_mcp_config``; a republish replaces any
    cached tool detail the same way the tool half does.
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
        if mcp.name.endswith("_"):
            # Same rule as the tool half: `allowed_mcps: ["<site>__<mcp>"]` cannot
            # name a segment that ends in `_`, so the server would be unreachable by
            # reference. (<site>__* still reaches nothing it cannot name.)
            logger.warning(
                "edge '%s' mcp '%s' ends with '_' and has no reference form; skipped",
                site,
                mcp.name,
            )
            continue
        name = mcp_registry_name(site, mcp.name)
        current = existing.get(name)
        if current is not None and current.get("managed_by") != MANAGED_BY:
            logger.warning(
                "edge '%s' mcp '%s' collides with an existing non-edge MCP; skipped",
                site,
                mcp.name,
            )
            continue
        identity_mgr.save_mcp_config(
            name, _mcp_config(site, mcp, site_config, lazy_catalog=lazy_catalog)
        )
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


# --- lazy detail cache -------------------------------------------------------------
#
# A ``lazy_catalog`` edge publishes summaries and answers ``tool_detail`` /
# ``mcp_tool_detail`` frames on demand. There is no separate cache to invalidate: the
# detail is merged into the record the publish wrote, and the next publish replaces
# that record wholesale with a fresh summary. A site that reconnects therefore starts
# lazy again, which is correct -- its catalog may have changed while it was away.


def get_tool_detail(identity_mgr: Any, site: str, tool: str) -> Optional[Dict[str, Any]]:
    """The stored record of one edge tool when it is complete, else ``None``."""
    config = identity_mgr.get_tool_config(tool_registry_name(site, tool))
    if not config or config.get("managed_by") != MANAGED_BY:
        return None
    # A missing key is a record from before lazy publishing; those edges always sent
    # their inputs, so it counts as complete.
    return config if config.get("detail", "full") == "full" else None


def store_tool_detail(
    identity_mgr: Any, site: str, tool: str, entry: Dict[str, Any]
) -> Dict[str, Any]:
    """Merge one tool's full detail into its record and return the saved config.

    The merge is additive on purpose: a lazy record already carries everything a caller
    needs to route a call (``remote``, ``public``, ``retry_on_transient``); only its
    description and inputs were withheld. The edge's description can be richer than the
    catalog summary, so the embedding is rebuilt when the text actually changed.
    """
    detail = protocol.validate_tool_detail(entry)
    if detail.name != tool:
        raise ValueError(
            f"edge answered detail for {detail.name!r}, expected {tool!r}"
        )
    name = tool_registry_name(site, tool)
    previous = identity_mgr.get_tool_config(name)
    config = dict(previous or {})
    config.setdefault("name", name)
    config.setdefault("remote", {"site": site, "tool": tool})
    config.setdefault("runtime", "remote")
    config.setdefault("managed_by", MANAGED_BY)
    config["description"] = detail.description
    config["inputs"] = detail.inputs
    config["detail"] = "full"
    identity_mgr.save_tool_config(name, config)
    if config.get("public") and (not previous or _embedding_changed(previous, config)):
        if not index_tool(identity_mgr, name, detail.description, detail.inputs):
            logger.warning(
                "could not re-index tool '%s' after a detail fetch (embeddings "
                "unavailable); it will rank last in tool search",
                name,
            )
    return config


def _mcp_tool_entry(
    config: Optional[Dict[str, Any]], tool: str
) -> Optional[Dict[str, Any]]:
    for entry in (config or {}).get("tools") or []:
        if isinstance(entry, dict) and entry.get("name") == tool:
            return entry
    return None


def get_mcp_tool_detail(
    identity_mgr: Any, site: str, mcp: str, tool: str
) -> Optional[Dict[str, Any]]:
    """The cached full entry of one MCP tool, or ``None`` while it is a summary.

    Gated twice: the server flag (written by the publish) and the entry itself. The
    flag flips to "full" after the *first* per-tool store, so on its own it would let a
    still-lazy sibling be served with an empty schema -- ``detail_tools`` is what marks
    the entries that were really fetched.
    """
    config = identity_mgr.get_mcp_config(mcp_registry_name(site, mcp))
    if not config or config.get("managed_by") != MANAGED_BY:
        return None
    entry = _mcp_tool_entry(config, tool)
    if entry is None:
        return None
    if "detail" not in config:
        # A record from before lazy publishing always carried its schemas -- an empty
        # one is legal for a schema-less tool, so it counts as complete here. Treating
        # it as a miss would send a detail frame to an edge that cannot decode it.
        return entry
    if config.get("detail") == "lazy":
        return None
    if tool in (config.get("detail_tools") or []):
        return entry
    return entry if entry.get("inputSchema") else None


def store_mcp_tool_detail(
    identity_mgr: Any, site: str, mcp: str, entry: Dict[str, Any]
) -> Dict[str, Any]:
    """Replace/insert one MCP tool entry with its full detail and return the config.

    ``detail_tools`` is relay bookkeeping, not catalog data: it records which entries
    have a real schema so one fetch cannot make the server's other lazy entries look
    complete. The next publish drops it with the rest of the record.
    """
    detail = protocol.validate_mcp_tool_detail(entry)
    tool = str(detail.get("name") or "")
    name = mcp_registry_name(site, mcp)
    previous = identity_mgr.get_mcp_config(name)
    config = dict(previous or {})
    config.setdefault("name", name)
    config.setdefault("remote", {"site": site, "mcp": mcp})
    config.setdefault("transport", "remote")
    config.setdefault("managed_by", MANAGED_BY)

    tools = [dict(item) for item in (config.get("tools") or []) if isinstance(item, dict)]
    replaced = False
    for index, item in enumerate(tools):
        if item.get("name") == tool:
            tools[index] = {**item, **detail}
            replaced = True
            break
    if not replaced:
        tools.append(dict(detail))
    config["tools"] = tools
    config["detail"] = "full"
    fetched = [
        str(item) for item in (config.get("detail_tools") or []) if isinstance(item, str)
    ]
    if tool and tool not in fetched:
        fetched.append(tool)
    config["detail_tools"] = fetched
    identity_mgr.save_mcp_config(name, config)

    description = str(detail.get("description") or "")
    previous_entry = _mcp_tool_entry(previous, tool) if tool else None
    if tool and (previous_entry is None or previous_entry.get("description") != description):
        embedding_name = f"mcp__{site}__{mcp}__{tool}"
        if not index_tool(
            identity_mgr, embedding_name, description, None, embedding_name=embedding_name
        ):
            logger.warning(
                "could not re-index mcp tool '%s' after a detail fetch (embeddings "
                "unavailable); it will rank last in tool search",
                embedding_name,
            )
    return config


def _tool_detail_payload(config: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "detail": config.get("inputs") or {},
        "description": config.get("description") or "",
        "detail_state": "full",
    }


def _mcp_detail_payload(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "detail": entry.get("inputSchema") or {},
        "description": entry.get("description") or "",
        "detail_state": "full",
    }


async def _read_cached_detail(
    identity_mgr: Any, site: str, tool: str, mcp: Optional[str]
) -> Optional[Dict[str, Any]]:
    """The servable detail already in the registry, or ``None``."""
    if mcp is None:
        config = await asyncio.to_thread(get_tool_detail, identity_mgr, site, tool)
        return _tool_detail_payload(config) if config else None
    entry = await asyncio.to_thread(get_mcp_tool_detail, identity_mgr, site, mcp, tool)
    return _mcp_detail_payload(entry) if entry else None


async def fetch_tool_detail(
    identity_mgr: Any,
    site: str,
    tool: str,
    requester: Any,
    *,
    mcp: Optional[str] = None,
) -> Dict[str, Any]:
    """Serve one tool's full detail from the cached record, else from the edge.

    ``requester(mcp_or_none, tool)`` is awaited and may raise anything (offline edge,
    timeout, refusal). A degraded edge is a *payload*, never an exception: the caller
    gets the stale cached detail when one survives, otherwise ``unavailable``.

    Returns ``{detail, description, detail_state, cached[, stale]}`` on success and
    ``{detail: None, unavailable: True, reason}`` when the edge could not answer.
    """
    payload = await _read_cached_detail(identity_mgr, site, tool, mcp)
    if payload is not None:
        return {**payload, "cached": True}

    try:
        entry = await requester(mcp, tool)
        if isinstance(entry, dict) and entry.get("name") not in (None, tool):
            raise ValueError(
                f"edge answered detail for {entry.get('name')!r}, expected {tool!r}"
            )
        if mcp is not None and isinstance(entry, dict) and not entry.get("name"):
            # The frame already named the tool; the entry may be the bare schema.
            entry = {**entry, "name": tool}
        if mcp is None:
            config = await asyncio.to_thread(
                store_tool_detail, identity_mgr, site, tool, entry
            )
            payload = _tool_detail_payload(config)
        else:
            config = await asyncio.to_thread(
                store_mcp_tool_detail, identity_mgr, site, mcp, entry
            )
            stored = _mcp_tool_entry(config, tool)
            payload = _mcp_detail_payload(stored) if stored else None
    except Exception as exc:  # noqa: BLE001 - a degraded edge must not raise here
        reason = f"{type(exc).__name__}: {exc}".strip()[:200]
        logger.warning(
            "edge detail unavailable site=%s mcp=%s tool=%s (%s)", site, mcp, tool, reason
        )
        stale = await _read_cached_detail(identity_mgr, site, tool, mcp)
        if stale is not None:
            return {**stale, "cached": True, "stale": True}
        return {
            "detail": None,
            "description": "",
            "detail_state": "unavailable",
            "unavailable": True,
            "reason": reason,
        }

    if payload is None:
        return {
            "detail": None,
            "description": "",
            "detail_state": "unavailable",
            "unavailable": True,
            "reason": "the edge returned no usable detail for this tool",
        }
    return {**payload, "cached": False}


def publish_edge_credentials(
    identity_mgr: Any, site: str, credentials: EdgeCredentials, *, now: Optional[str] = None
) -> bool:
    """Merge an edge's hello credential material into its site record.

    The relay owns ``/registry/edges/<site>/config`` only for these fields; every
    admin-editable field is preserved. ``edge_key_fps`` is the **overlap** set -- the
    fingerprints a blob may still be sealed to -- so a key the edge stopped reporting
    (``--drop-old-key``) stops accepting writes; the cumulative rotation trail goes to
    ``edge_key_history`` for display. ``credential_keys`` is names only: the browser
    seal form reads declared key names from here because ``<site>__<name>`` configs
    deliberately omit ``secrets``/``variables``.

    Returns whether the record changed. A site with no registry record (the DEV_MODE
    hatch) is not written: it has no config to merge into.
    """
    record = identity_mgr.get_edge_config(site)
    if not record:
        return False

    incoming = credentials.as_record()
    if not incoming:
        return False

    stamp = now or _now_iso()
    updated = dict(record)
    changed = False

    for key, value in incoming.items():
        if key in ("prev_edge_key_fp", "edge_key_fps", "edge_key_history", "edge_key_rotated_at"):
            continue
        if updated.get(key) != value:
            updated[key] = value
            changed = True

    new_fp = incoming.get("edge_key_fp")
    prev_fp = incoming.get("prev_edge_key_fp")
    if not new_fp:
        # The edge lost or deleted its key: stop advertising a public key central
        # can no longer be decrypted with. The old fp stays in the history.
        for stale in ("edge_pubkey", "edge_key_fp", "edge_key_id"):
            if stale in updated:
                updated.pop(stale)
                changed = True
    if new_fp:
        old_fp = record.get("edge_key_fp")
        if old_fp and old_fp != new_fp:
            updated["edge_key_rotated_at"] = stamp
            changed = True

        overlap = [prev_fp] if prev_fp and prev_fp != new_fp else []
        if updated.get("edge_key_fps") != overlap:
            updated["edge_key_fps"] = overlap
            changed = True
        if "prev_edge_key_fp" in record and prev_fp is None:
            updated.pop("prev_edge_key_fp", None)
            changed = True
        elif prev_fp is not None and record.get("prev_edge_key_fp") != prev_fp:
            updated["prev_edge_key_fp"] = prev_fp
            changed = True

        history = _key_history_entries(record.get("edge_key_history"))
        for candidate, retired_at in ((old_fp, updated.get("edge_key_rotated_at")), (prev_fp, stamp)):
            if candidate and candidate != new_fp and candidate not in {entry["fp"] for entry in history}:
                history.append({"fp": candidate, "retired_at": retired_at or stamp})
                changed = True
        history = [entry for entry in history if entry["fp"] != new_fp][-MAX_KEY_HISTORY:]
        if updated.get("edge_key_history") != history:
            updated["edge_key_history"] = history
            changed = True

    if not changed:
        return False
    identity_mgr.save_edge_config(site, updated)
    logger.info(
        "edge credential material recorded site=%s key_fp=%s overlap=%d targets=%d",
        site,
        new_fp or "",
        len(updated.get("edge_key_fps") or []),
        len(updated.get("credential_keys") or {}),
    )
    return True


def _key_history_entries(raw: Any) -> List[Dict[str, str]]:
    """Normalize a stored history list to ``[{fp, retired_at}]`` (best effort)."""
    entries: List[Dict[str, str]] = []
    if not isinstance(raw, (list, tuple)):
        return entries
    for item in raw:
        if isinstance(item, str) and item:
            entries.append({"fp": item, "retired_at": ""})
        elif isinstance(item, dict):
            fp = item.get("fp") or item.get("fingerprint")
            if isinstance(fp, str) and fp:
                entries.append({"fp": fp, "retired_at": str(item.get("retired_at") or "")})
    return entries


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
