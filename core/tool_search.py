# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Semantic tool discovery for Direct Tool Gateway Execution (see ``core.gateway.search_tools``).

Mirrors ``core.agent_search``: ranks publicly-whitelisted tools via Gemini embeddings
cached in etcd at sync time (see ``scripts/sync_to_db.py``), falling back to keyword
matching when embeddings are unavailable. Only tools/MCP tools explicitly marked
``public`` are ever considered candidates — internal tools are never returned
regardless of query, per the secure-by-default whitelisting model.
"""
import os
import re
import asyncio
import logging
from typing import List, Dict, Any, Optional

import httpx

from core.auth import get_identity_manager
from core import allowlist
from core.embeddings import embed_text, cosine
from core.discovery import is_tool_configured, resolve_edge_mcp_target
from core.tunables import resolve as resolve_tunable

logger = logging.getLogger(__name__)

identity_mgr = get_identity_manager()

RELAY_URL_ENV = "EDGE_RELAY_URL"
_DEFAULT_RELAY_URL = "http://edge-relay:8100"
# A schema read is a small, interactive lookup: a slow relay must not hold an agent
# turn open the way a tool call's own timeout allows.
_DETAIL_TIMEOUT = 5.0


def _relay_url() -> str:
    """Base URL of the in-cluster edge relay (same contract as ``core.remote_mcp``)."""
    return os.getenv(RELAY_URL_ENV, _DEFAULT_RELAY_URL).rstrip("/")


def _keyword_rank_tools(query: str, candidates: List[Dict]) -> List[Dict]:
    """Fallback ranking: count query-term hits across name/description."""
    terms = [t for t in re.split(r"\W+", query.lower()) if t]

    def score(c: Dict) -> int:
        haystack = f"{c['name']} {c['description']}".lower()
        return sum(1 for t in terms if t in haystack)

    return sorted(candidates, key=lambda c: (-score(c), c["name"].lower()))


def _local_tool_parameters(config: Dict) -> Dict[str, Any]:
    """Local tool.yaml `inputs` are already shaped as {name: {type, description, required}}."""
    parameters = {}
    for key, spec in (config.get("inputs") or {}).items():
        if isinstance(spec, dict):
            parameters[key] = {
                "type": spec.get("type", "any"),
                "description": spec.get("description", ""),
                "required": spec.get("required", False),
            }
        else:
            parameters[key] = {"type": "any", "description": "", "required": False}
    return parameters


def _mcp_tool_parameters(input_schema: Dict) -> Dict[str, Any]:
    """MCP tools describe parameters via a JSON-Schema `inputSchema`."""
    parameters = {}
    properties = (input_schema or {}).get("properties", {})
    required = (input_schema or {}).get("required", [])
    for prop_name, prop_details in properties.items():
        parameters[prop_name] = {
            "type": prop_details.get("type", "string"),
            "description": prop_details.get("description", ""),
            "required": prop_name in required,
        }
    return parameters


def _mcp_tool_entry(config: Optional[Dict], tool: str) -> Optional[Dict]:
    """The ``tools`` entry named ``tool`` in one MCP server's registry config."""
    for entry in (config or {}).get("tools") or []:
        if isinstance(entry, dict) and entry.get("name") == tool:
            return entry
    return None


def _mcp_tool_is_lazy(mcp_config: Dict, entry: Dict) -> bool:
    """True when one MCP tool entry is a summary the edge withheld the schema for.

    The server flag alone is not enough: it flips to ``"full"`` after the first
    per-tool fetch, so an entry without a schema and not listed in ``detail_tools``
    is still summary-only. A record from before lazy publishing has no ``detail``
    key at all and always carries its schema.
    """
    if "detail" not in mcp_config:
        return False
    if (entry or {}).get("inputSchema"):
        return False
    fetched = mcp_config.get("detail_tools") or []
    return not (isinstance(fetched, list) and entry.get("name") in fetched)


def _unavailable(name: str, reason: str) -> Dict[str, Any]:
    """The single failure shape every ``describe_tool_entry`` path returns."""
    return {"name": name, "unavailable": True, "reason": reason or "edge_unavailable"}


def _relay_error_code(body: Any) -> str:
    """``error.code`` from a relay error body (``{"error": {"code": ...}}``)."""
    if not isinstance(body, dict):
        return ""
    error = body.get("error")
    if not isinstance(error, dict):
        return ""
    code = error.get("code")
    return code if isinstance(code, str) and code else ""


async def _post_relay_detail(path: str, payload: Dict[str, Any]) -> tuple[Optional[Dict], str]:
    """POST one detail request; ``(body, "")`` on success, ``(None, reason)`` otherwise.

    Never raises: a schema read is best-effort for the caller's next step, so an
    unreachable/broken relay degrades to a reason code. Only the endpoint label and the
    exception class are logged -- never the payload or the schema itself.
    """
    url = f"{_relay_url()}{path}"
    label = path.rsplit("/", 1)[-1]
    try:
        async with httpx.AsyncClient(timeout=_DETAIL_TIMEOUT) as client:
            response = await client.post(url, json=payload)
    except Exception as exc:
        logger.warning("Edge %s request failed (%s)", label, type(exc).__name__)
        return None, "edge_unavailable"

    try:
        body = response.json()
    except Exception:
        body = None

    if response.status_code != 200:
        logger.info("Edge %s request returned HTTP %s", label, response.status_code)
        return None, _relay_error_code(body) or "edge_unavailable"
    if not isinstance(body, dict):
        return None, "edge_unavailable"
    return body, ""


async def _describe_edge_tool(
    name: str, site: str, tool: str, *, config: Optional[Dict] = None
) -> Dict[str, Any]:
    """Full detail of one ``<site>__<tool>`` edge tool, from the registry or the relay."""
    if config and config.get("detail") == "full":
        return {
            "name": name,
            "description": config.get("description", ""),
            "parameters": _local_tool_parameters(config),
            "source": "local",
            "detail": "full",
            "cached": True,
        }
    body, reason = await _post_relay_detail(
        f"/v1/sites/{site}/tool_detail", {"tool": tool}
    )
    detail = (body or {}).get("detail")
    if reason or not isinstance(detail, dict):
        if config and config.get("inputs"):
            # Relay unreachable: the already-fetched schema beats "unavailable".
            return {
                "name": name,
                "description": config.get("description", ""),
                "parameters": _local_tool_parameters(config),
                "source": "local",
                "detail": "full",
                "cached": True,
                "stale": True,
            }
        return _unavailable(name, reason)
    # The relay payload's `detail` is the inputs mapping itself, not a full entry.
    return {
        "name": name,
        "description": (body or {}).get("description") or "",
        "parameters": _local_tool_parameters({"inputs": detail}),
        "source": "local",
        "detail": "full",
    }


async def _describe_edge_mcp_tool(
    name: str, site: str, mcp: str, tool: str, *, config: Optional[Dict] = None
) -> Dict[str, Any]:
    """Full detail of one ``mcp__<site>__<mcp>__<tool>`` tool, cached or via the relay."""
    entry = _mcp_tool_entry(config, tool) if config else None
    if entry is not None and config is not None and not _mcp_tool_is_lazy(config, entry):
        return {
            "name": name,
            "description": entry.get("description", "") or config.get("description", ""),
            "parameters": _mcp_tool_parameters(entry.get("inputSchema") or {}),
            "source": f"{site}__{mcp}",
            "detail": "full",
            "cached": True,
        }
    body, reason = await _post_relay_detail(
        f"/v1/sites/{site}/mcp_tool_detail", {"mcp": mcp, "tool": tool}
    )
    detail = (body or {}).get("detail")
    if reason or not isinstance(detail, dict):
        if entry is not None and entry.get("inputSchema"):
            return {
                "name": name,
                "description": entry.get("description", ""),
                "parameters": _mcp_tool_parameters(entry["inputSchema"]),
                "source": f"{site}__{mcp}",
                "detail": "full",
                "cached": True,
                "stale": True,
            }
        return _unavailable(name, reason)
    # The relay payload's `detail` is the MCP `inputSchema` itself.
    return {
        "name": name,
        "description": (body or {}).get("description") or "",
        "parameters": _mcp_tool_parameters(detail),
        "source": f"{site}__{mcp}",
        "detail": "full",
    }


async def _edge_tool_from_name(mgr: Any, name: str) -> Optional[tuple[str, str]]:
    """``(site, tool)`` when ``name`` is ``<site>__<tool>`` and ``site`` is a known edge.

    Only a fallback for a name the tool registry holds no config for: the registry
    record (checked by the caller) is the authoritative signal, and this catches a
    reference that still reaches a registered site.
    """
    if name.startswith("mcp__") or "__" not in name:
        return None
    site, _, tool = name.partition("__")
    if not site or not tool:
        return None
    try:
        edge = await asyncio.to_thread(mgr.get_edge_config, site)
    except Exception:
        logger.debug("Could not read edge config for site %r", site, exc_info=True)
        return None
    return (site, tool) if edge else None


async def describe_tool_entry(
    name: str,
    user_id: Optional[str] = None,
    *,
    identity_manager=None,
) -> Dict[str, Any]:
    """Return the full schema of exactly one tool, whichever surface owns it.

    Accepts the same name forms as ``use_tool``: ``<tool>`` (local, or an edge
    ``<site>__<tool>`` record), ``mcp__<server>__<tool>`` (central MCP) and
    ``mcp__<site>__<mcp>__<tool>`` (edge MCP). The registry decides which reading
    applies -- a name is an edge reference only when its record carries a ``remote``
    block -- exactly as :func:`core.discovery.resolve_edge_mcp_target` does for
    execution.

    Local and central tools answer from the registry. Edge tools ask the relay for the
    detail a lazy publish withheld (``tool_detail`` / ``mcp_tool_detail``). Failures are
    values, never exceptions: every unsuccessful path returns
    ``{"name", "unavailable": True, "reason": ...}`` so a caller can keep its summary
    card instead of failing its turn.
    """
    mgr = identity_manager or identity_mgr

    try:
        config = await asyncio.to_thread(mgr.get_tool_config, name)
    except Exception:
        logger.warning("Could not read the tool config for %r", name, exc_info=True)
        config = None

    if config:
        remote = config.get("remote")
        if isinstance(remote, dict) and remote.get("site"):
            # Registry-backed edge tool: the remote block names the bare tool, which
            # is what the relay's routes take (the registry key is `<site>__<tool>`).
            site = str(remote["site"])
            tool = str(remote.get("tool") or name.partition("__")[2] or name)
            return await _describe_edge_tool(name, site, tool, config=config)
        return {
            "name": name,
            "description": config.get("description", ""),
            "parameters": _local_tool_parameters(config),
            "source": "local",
            "detail": "full",
        }

    if name.startswith("mcp__"):
        try:
            target = await resolve_edge_mcp_target(name, mgr)
        except Exception:
            logger.warning("Could not resolve the MCP target for %r", name, exc_info=True)
            target = None
        if target:
            site, mcp, tool = target
            try:
                mcp_config = await asyncio.to_thread(mgr.get_mcp_config, f"{site}__{mcp}")
            except Exception:
                mcp_config = None
            return await _describe_edge_mcp_tool(
                name, site, mcp, tool, config=mcp_config
            )

        parts = name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            server, tool = parts[1], parts[2]
            try:
                mcp_config = await asyncio.to_thread(mgr.get_mcp_config, server)
            except Exception:
                logger.warning("Could not read the MCP config for %r", server, exc_info=True)
                mcp_config = None
            entry = _mcp_tool_entry(mcp_config, tool)
            if entry is not None:
                return {
                    "name": name,
                    "description": entry.get("description", "")
                    or (mcp_config or {}).get("description", ""),
                    "parameters": _mcp_tool_parameters(entry.get("inputSchema") or {}),
                    "source": server,
                    "detail": "full",
                }
        return _unavailable(name, "unknown_tool")

    edge = await _edge_tool_from_name(mgr, name)
    if edge:
        return await _describe_edge_tool(name, *edge)
    return _unavailable(name, "unknown_tool")


def _missing_configuration_labels(status: Dict[str, Any]) -> List[str]:
    """Shape-safe flattening of a readiness status's missing_* fields for display.

    A bare string is a single label (not a character sequence); non-iterable
    values (e.g. a malformed int) degrade to no labels instead of raising, and
    non-string entries are stringified so the join can't fail.
    """
    labels: List[str] = []
    for key in ("missing_secrets", "missing_variables"):
        value = status.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            labels.append(value)
            continue
        try:
            labels.extend(str(m) for m in value)
        except TypeError:
            continue
    return labels


async def search_tools(
    query: str,
    limit: Optional[int] = None,
    user_id: Optional[str] = None,
    detail: bool = False,
) -> List[Dict[str, Any]]:
    """Return up to ``limit`` publicly-whitelisted tools most relevant to ``query``.

    Each result is a Tool Card: ``{"name", "description", "parameters", "configured",
    "status", "source"}``. Local tools are included only if their ``tool.yaml`` sets
    ``public: true``. MCP tools are included only if the owning MCP config sets
    ``public: true`` or lists the tool name in ``public_tools``; their returned
    ``name`` is the ``mcp__{server}__{tool}`` form so it can be passed straight to
    ``use_tool`` for execution. Internal (non-whitelisted) tools are never returned,
    regardless of how well they match the query.

    If ``user_id`` is provided, each result's configuration status is resolved via
    ``is_tool_configured``; unconfigured tools get ``configured: False`` and their
    description gains a trailing note naming the missing secrets/variables.

    Candidates the caller's token groups may not use are dropped before ranking
    (``TOOL_ACCESS_MODE``; ``shadow`` logs the would-be denial and keeps the card).
    Groups come from the run's verified token only.

    Pass ``limit <= 0`` to get the full ranked list (mirrors ``search_agents``).
    ``limit=None`` (the default) resolves to the admin-tunable ``tool_search_limit``
    (env ``TOOL_SEARCH_LIMIT``, default 8).

    A lazy edge card (``detail: "lazy"``) is summary-only: its description is kept but
    its ``parameters`` were withheld by the edge, so the card carries ``{}``. The
    ``detail`` key is only present on edge records whose catalog publish wrote it --
    local and central tools never gain it. With ``detail=True``, the parameters of just
    the selected lazy cards are fetched in one batch (see :func:`describe_tool_entry`),
    bounded by the card count; a failed fetch leaves the card summary-only.
    """
    if limit is None:
        limit = resolve_tunable("tool_search_limit")
    tool_configs = await asyncio.to_thread(identity_mgr.get_all_tool_configs)
    mcp_configs = await asyncio.to_thread(identity_mgr.get_all_mcp_configs)
    embeddings = await asyncio.to_thread(identity_mgr.get_all_tool_embeddings)
    try:
        health = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "tool")
    except Exception:
        health = {}

    candidates: List[Dict] = []

    for name, config in tool_configs.items():
        # Re-check visibility at query time (not just embedding presence) since a tool
        # may have been demoted to internal after being indexed — embeddings are only
        # pruned on deletion, not on demotion. Strict `is True` (not truthy) since these
        # are unvalidated raw etcd dicts and this is a secure-by-default whitelist: a
        # malformed `public: "false"` must fail closed, not leak the tool.
        if config.get("public") is not True:
            continue
        card = {
            "name": config.get("name", name),
            "description": config.get("description", ""),
            "parameters": _local_tool_parameters(config),
            "status": (health.get(name) or {}).get("status", "Online"),
            "source": "local",
            "_vec": embeddings.get(name),
        }
        # Only a lazy-publishing edge writes `detail`; an absent key means a full
        # record (including every central tool), which must not gain the key.
        if "detail" in config:
            card["detail"] = "lazy" if config.get("detail") == "lazy" else "full"
            if card["detail"] == "lazy":
                card["parameters"] = {}
        candidates.append(card)

    for mcp_name, mcp_config in mcp_configs.items():
        mcp_public = mcp_config.get("public") is True
        public_tools_raw = mcp_config.get("public_tools", [])
        public_tools = set(public_tools_raw) if isinstance(public_tools_raw, list) else set()
        for t in mcp_config.get("tools", []) or []:
            tool_name = t.get("name", "")
            if not tool_name or not (mcp_public or tool_name in public_tools):
                continue
            prefixed_name = f"mcp__{mcp_name}__{tool_name}"
            card = {
                "name": prefixed_name,
                "description": t.get("description", ""),
                "parameters": _mcp_tool_parameters(t.get("inputSchema", {})),
                "status": "Online",
                "source": mcp_name,
                # Indexed at sync time (scripts/sync_to_db.py sync_mcp) under this same
                # prefixed name — the `use_tool` execution form — so MCP tools rank by
                # cosine like local tools; a missing/stale vector degrades to 0.0.
                "_vec": embeddings.get(prefixed_name),
            }
            # Same rule one level down: only a lazy publish wrote `detail` on the
            # server record, and only the entries that still lack a schema are lazy.
            if "detail" in mcp_config:
                card["detail"] = "full" if not _mcp_tool_is_lazy(mcp_config, t) else "lazy"
                if card["detail"] == "lazy":
                    card["parameters"] = {}
            candidates.append(card)

    if not candidates:
        return []

    # Group-rule filter. The catalog above is already the *public* one, so what is
    # left to decide is the group half: `may_discover` applies exactly that half and
    # nothing else (no allowlist narrowing -- a search may show a tool this run cannot
    # call, execution is gated elsewhere). `off` skips it; `shadow` logs and keeps the
    # card. A failure here is fail-closed: no tools at all.
    #
    # No verified token means no group claims, and a group rule evaluated against an
    # empty group set would hide cards from the very users who do hold the group (the
    # search runs on the front door, before any run minted a token). So the read filter
    # applies only to an agent run; execution still enforces the rule when the tool is
    # actually called.
    try:
        from core import tool_access
        from core.tool_gate import current_claims

        claims = current_claims()

        def _filter_readable(cands: List[Dict]) -> List[Dict]:
            if claims is None:
                return cands
            return [
                c
                for c in cands
                if tool_access.enforce(
                    tool_access.may_discover(claims, target=c["name"], surface="host"),
                    agent=getattr(claims, "agent", None),
                    groups=getattr(claims, "groups", ()) or (),
                    target=c["name"],
                    surface="host",
                ).allowed
            ]

        candidates = await asyncio.to_thread(_filter_readable, candidates)
    except Exception:
        logger.exception("Tool authorization filter failed; returning no tools")
        return []

    if not candidates:
        return []

    query_vec = await asyncio.to_thread(embed_text, query, "retrieval_query")
    if query_vec:
        ranked = sorted(candidates, key=lambda c: cosine(query_vec, c.get("_vec")), reverse=True)
    else:
        logger.warning("Embeddings unavailable; using keyword fallback for tool search.")
        ranked = _keyword_rank_tools(query, candidates)

    selected = ranked if limit <= 0 else ranked[:limit]

    # Schema fetch for the selected lazy cards only: post-limit, so a broad query can
    # never fan out relay reads. Failures (values, not exceptions) leave the card as
    # the summary the search already had.
    if detail and selected:
        # `limit <= 0` means "the full ranked list": cap the fan-out to one search page
        # so a broad query cannot turn into a relay read per catalog entry.
        window = selected if limit and limit > 0 else selected[: max(1, resolve_tunable("tool_search_limit"))]
        lazy_cards = [c for c in window if c.get("detail") == "lazy"]
        if lazy_cards:
            described = await asyncio.gather(
                *(
                    describe_tool_entry(c["name"], user_id, identity_manager=identity_mgr)
                    for c in lazy_cards
                ),
                return_exceptions=True,
            )
            for card, info in zip(lazy_cards, described):
                if isinstance(info, BaseException):
                    logger.warning("Detail fetch failed for tool %r: %s", card["name"], info)
                    continue
                if not isinstance(info, dict) or info.get("unavailable"):
                    continue
                card["parameters"] = info.get("parameters") or {}
                if isinstance(info.get("description"), str) and info["description"]:
                    card["description"] = info["description"]
                card["detail"] = info.get("detail") or "full"

    statuses = [None] * len(selected)
    if user_id is not None:
        statuses = await asyncio.gather(
            *(is_tool_configured(c["name"], user_id) for c in selected),
            return_exceptions=True,
        )

    results = []
    for c, status in zip(selected, statuses):
        description = c["description"]
        configured = True
        if isinstance(status, BaseException):
            logger.warning("Configuration check failed for tool %r: %s", c["name"], status)
        elif status is not None:
            if not isinstance(status, dict):
                logger.warning("Malformed configuration status for tool %r: %r", c["name"], status)
            else:
                configured = bool(status.get("configured"))
                if not configured:
                    missing = _missing_configuration_labels(status)
                    missing_text = ", ".join(missing) if missing else "required configuration"
                    description = f"{description}\n\n[Missing configuration: {missing_text}. Configure at /configuration]"
        card = {
            "name": c["name"],
            "description": description,
            "parameters": c["parameters"],
            "configured": configured,
            "status": c["status"],
            "source": c["source"],
        }
        if "detail" in c:
            card["detail"] = c["detail"]
        results.append(card)
    return results


async def published_exposure(tool_name: str, identity_manager: Optional[Any] = None) -> bool:
    """Is this tool/MCP tool exposed for direct execution by a caller with no record?

    This is the ``public=`` input of the one evaluator (:mod:`core.tool_access`) for
    the external front door: a gateway client has no agent record, so the tool's own
    published exposure replaces the allowlist half. Fails closed on anything
    unexpected (unknown tool, malformed ``mcp__`` name, non-``True`` ``public`` value,
    non-list ``public_tools``) — mirrors the secure-by-default checks already applied
    in ``is_tool_configured``/``search_tools``.

    MCP tool names resolve through ``resolve_edge_mcp_target``: a name is an
    edge-exported server only when its ``<site>__<mcp>`` key is a registered config with
    a ``remote`` block; every other ``mcp__`` name is a central server. That keeps
    ``mcp__srv__do__thing`` (central server ``srv``, tool ``do__thing``) working exactly
    as before instead of being denied as an edge name.

    Anything malformed (too few parts, missing server) fails closed.
    """
    mgr = identity_manager or identity_mgr
    if tool_name.startswith("mcp__"):
        target = await resolve_edge_mcp_target(tool_name, mgr)
        if target:
            server_key = f"{target[0]}__{target[1]}"
            sub_tool_name = target[2]
        else:
            parts = tool_name.split("__", 2)
            if len(parts) < 3 or not parts[1]:
                return False
            _, server_key, sub_tool_name = parts
        config = await asyncio.to_thread(mgr.get_mcp_config, server_key)
        if not config:
            return False
        public_tools_raw = config.get("public_tools", [])
        public_tools = set(public_tools_raw) if isinstance(public_tools_raw, list) else set()
        return config.get("public") is True or sub_tool_name in public_tools

    config = await asyncio.to_thread(mgr.get_tool_config, tool_name)
    if not config:
        return False
    return config.get("public") is True


def _edge_tool_output(result: Any) -> Any:
    """Map ``call_edge_mcp``'s hub-shaped dict onto the raw value a direct caller
    expects, mirroring :func:`extract_tool_output` (structured value > content text).
    """
    if not isinstance(result, dict):
        return result
    if "error" in result:
        return f"SYSTEM: {result['error']}"
    structured = result.get("structuredContent")
    if structured is not None:
        return structured
    texts = [
        block["text"]
        for block in (result.get("content") or [])
        if isinstance(block, dict) and isinstance(block.get("text"), str)
    ]
    if texts:
        return "\n".join(texts)
    return None


def _current_agent_token():
    """The run's agent token, when executing inside an agent turn."""
    try:
        from core.auth import agent_token_var

        return agent_token_var.get()
    except Exception:
        return None


async def execute_whitelisted_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    user_id: Optional[str],
    *,
    identity_manager=None,
    is_configured=is_tool_configured,
    get_hub_client_fn=None,
    get_external_mcp_client_fn=None,
    call_edge_mcp_fn=None,
) -> Any:
    """Shared use_tool execution flow: authorization -> configuration check -> dispatch -> output extraction.

    Returns the raw structured tool output, or a 'SYSTEM: ...' error string. Callers inject
    their own module-level seams (`is_configured`, hub/external client getters, the edge
    MCP caller) so existing monkeypatch targets keep working; `identity_manager` defaults
    to this module's `identity_mgr` (the `is_configured` default binds this module's name
    at def time).

    Authorization is the one evaluator (:mod:`core.tool_access`): the agent and its
    groups come from the run's verified token, the allowlist from that agent's record.
    A caller with no agent record (the external gateway front door) is granted by the
    target's own published exposure instead. Any failure of the evaluator fails closed
    (the call is denied) because this is a security boundary, not observability.
    """
    mgr = identity_manager or identity_mgr
    from core import tool_access
    from core.tool_gate import current_claims

    claims = current_claims()
    agent = getattr(claims, "agent", None)
    groups = getattr(claims, "groups", ()) or ()
    record = (
        await asyncio.to_thread(mgr.get_agent_config, agent) if agent else None
    )

    try:
        exposure = False if record else await published_exposure(tool_name, mgr)
        decision = await tool_access.enforce_async(
            await tool_access.authorize_claims_async(
                claims,
                target=tool_name,
                allowed=allowlist.resolve(record) if record else None,
                public=exposure,
                surface="host",
            ),
            agent=agent,
            groups=groups,
            target=tool_name,
            surface="host",
        )
    except Exception:
        logger.exception("Tool authorization check failed for %r", tool_name)
        return f"SYSTEM: Error checking tool access for '{tool_name}'. Please try again later."
    if not decision.allowed:
        logger.warning("use_tool: denied %r: %s", tool_name, decision.message)
        if not record and decision.reason in {
            tool_access.REASON_NOT_IN_ALLOWLIST,
            tool_access.REASON_UNKNOWN_TARGET,
        }:
            return (
                f"SYSTEM: Access denied. Tool '{tool_name}' is internal and not "
                "exposed for direct execution."
            )
        return (
            f"SYSTEM: Access denied. Tool '{tool_name}' is not permitted "
            "for this principal."
        )

    try:
        status = await is_configured(tool_name, user_id)
    except Exception as e:
        logger.error("Error checking configuration for tool %r: %s", tool_name, e, exc_info=True)
        return f"SYSTEM: Error checking configuration for tool '{tool_name}'. Please try again later."
    if not isinstance(status, dict):
        logger.error("Malformed configuration status for tool %r: %r", tool_name, status)
        return f"SYSTEM: Error checking configuration for tool '{tool_name}'. Please try again later."
    if not status.get("configured"):
        missing = _missing_configuration_labels(status)
        missing_text = ", ".join(missing) if missing else "required configuration"
        return f"SYSTEM: Tool '{tool_name}' requires configuration before it can be used. Missing: {missing_text}. Configure at /configuration"

    edge_parts: Optional[tuple] = None
    try:
        edge_parts = await resolve_edge_mcp_target(tool_name, mgr)
        if edge_parts:
            if call_edge_mcp_fn is None:
                logger.error("Edge MCP tool %r dispatched without an edge caller seam", tool_name)
                return f"SYSTEM: Error executing tool '{tool_name}'. Please try again later."
            site, mcp_name, sub_tool_name = edge_parts
            result = await call_edge_mcp_fn(
                site, mcp_name, sub_tool_name, arguments, user_id,
                agent_token=_current_agent_token(),
            )
        elif tool_name.startswith("mcp__"):
            _, server_name, sub_tool_name = tool_name.split("__", 2)
            client = await get_external_mcp_client_fn(server_name, user_id)
            result = await client.call_tool(sub_tool_name, arguments, raise_on_error=False)
        else:
            client = await get_hub_client_fn()
            result = await client.call_tool(
                tool_name,
                {
                    **arguments,
                    "__user_id": user_id,
                    "__agent_token": _current_agent_token(),
                },
                raise_on_error=False,
            )
    except Exception as e:
        logger.error("Error executing tool %r: %s", tool_name, e, exc_info=True)
        return f"SYSTEM: Error executing tool '{tool_name}'. Please try again later."

    try:
        return _edge_tool_output(result) if edge_parts else extract_tool_output(result)
    except Exception as e:
        logger.error("Error extracting output for tool %r: %s", tool_name, e, exc_info=True)
        return f"SYSTEM: Error executing tool '{tool_name}'. Please try again later."


def extract_tool_output(result: Any) -> Any:
    """Unwrap a fastmcp `CallToolResult` into the raw structured value a direct caller
    expects, preserving full stdout/JSON/error codes rather than pydantic-ai's
    agent-facing `.content` (a list of MCP content blocks).
    """
    if result.data is not None:
        return result.data
    if result.structured_content is not None:
        return result.structured_content
    texts = [c.text for c in (result.content or []) if hasattr(c, "text")]
    if texts:
        return "\n".join(texts)
    return None
