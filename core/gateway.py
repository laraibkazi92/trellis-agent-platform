# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import json
import uuid
import os
import logging
import httpx
import yaml
import asyncio
from typing import Any, Dict, List, Optional
import uvicorn
from contextlib import asynccontextmanager
from asyncache import cached
from cachetools import TTLCache
from fastmcp import FastMCP, Context
from mcp.types import ToolAnnotations
from core.auth import (
    AuthMiddleware,
    agent_token_var,
    auth_token_var,
    get_identity_manager,
    user_id_var,
    DEV_MODE_AUTH_TOKEN,
)
from core import agent_token
from core.agent_token import mint_for_run
from core.caller_identity import resolve_mint_identity
from core.devmode import configure_cors, enforce_dev_mode_safety
from core.discovery import discover_agents, is_agent_configured, is_tool_configured
from core.agent_search import search_agents as _search_agents_ranked
from core.tool_search import (
    describe_tool_entry,
    search_tools as _search_tools_ranked,
    execute_whitelisted_tool,
)
from core.agent_factory import get_hub_client, get_external_mcp_client
from core.remote_mcp import call_edge_mcp
from core.models import is_agent_external, is_routable_agent_type
from core.health import compute_agent_operational_status

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app):
    enforce_dev_mode_safety("gateway")
    from core import tool_access

    try:
        tool_access.install_watch()
    except Exception:
        logger.exception("Failed to install the tool-access watch; continuing startup")
    app.state.http_client = httpx.AsyncClient(timeout=30.0)
    yield
    try:
        tool_access.cancel_watch()
    except Exception:
        logger.exception("Failed to cancel the tool-access watch")
    await app.state.http_client.aclose()

# Initialize FastMCP server with host and port
mcp = FastMCP("Agent Gateway")

# FastMCP underlying FastAPI app
if hasattr(mcp, "_app"):
    app = mcp._app
    app.router.lifespan_context = lifespan

    configure_cors(app)

identity_mgr = get_identity_manager()

# HOST_URL is resolved from etcd at call time (never frozen at import), but a
# short TTL keeps every liveness ping / outbound call from re-reading etcd.
_host_url_cache = TTLCache(maxsize=1, ttl=60)


@cached(cache=_host_url_cache)
async def _resolve_host_url() -> str:
    """Resolve HOST_URL etcd-first at call time, falling back to the env default.

    Mirrors the call-time resolution already used by core/hub.py and
    core/tasks.py, so a runtime HOST_URL change no longer requires a restart.
    """
    default = os.getenv("HOST_URL", "http://localhost:8000")
    try:
        return await asyncio.to_thread(identity_mgr.get_config, "HOST_URL", default)
    except Exception as e:
        logger.warning(f"Failed to resolve HOST_URL from etcd, using {default}: {e}")
        return default


async def _check_host_liveness_error() -> Optional[Dict]:
    host_url = await _resolve_host_url()
    try:
        if hasattr(app, "state") and hasattr(app.state, "http_client"):
            resp = await app.state.http_client.get(f"{host_url}/health", timeout=5.0)
        else:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{host_url}/health", timeout=5.0)
        if resp.status_code != 200:
            return {"name": "Error", "description": f"Host API unreachable (HTTP {resp.status_code})"}
    except Exception as e:
        logger.error(f"Error checking Host liveness: {e}", exc_info=True)
        return {"name": "Error", "description": "Host API temporarily unreachable. Please try again later."}
    return None

async def _decorate_visible_subset(
    names: List[str],
    user_id: Optional[str],
    disabled_agents,
    agent_configs: Dict,
    agent_healths: Dict,
    tool_healths: Dict,
) -> List[Dict]:
    """Ranked-subset-only decoration path (no catalog discovery, bulk skills, or
    identity-secret fetches). Names failing the catalog checks are omitted. Per-name
    readiness failures fail open with ``configured=True``, and skills for agents with
    empty config descriptions are fetched concurrently with per-name fail-soft: one
    agent's skills-fetch exception no longer bubbles to the caller's ``Failed to verify
    agent configurations`` sentinel and instead falls back to
    ``"No description available."`` for that name only.
    """
    surviving = []
    for name in names:
        cfg = agent_configs.get(name)
        if not cfg:
            continue
        if name in disabled_agents:
            continue
        if not is_routable_agent_type(name, cfg):
            continue
        if not is_agent_external(cfg):
            continue
        surviving.append(name)

    if not surviving:
        return []

    statuses = await asyncio.gather(
        *(is_agent_configured(n, user_id) for n in surviving),
        return_exceptions=True,
    )

    needs_skills = [name for name in surviving if not (agent_configs.get(name) or {}).get("description")]
    skills_by_name: Dict[str, str] = {}
    if needs_skills:
        skill_results = await asyncio.gather(
            *(asyncio.to_thread(identity_mgr.get_agent_skills, n) for n in needs_skills),
            return_exceptions=True,
        )
        for name, skills in zip(needs_skills, skill_results):
            if isinstance(skills, Exception):
                logger.warning(f"Error fetching skills for agent '{name}': {skills}")
            elif isinstance(skills, str) and skills:
                skills_by_name[name] = skills

    agents = []
    for name, status in zip(surviving, statuses):
        cfg = agent_configs.get(name) or {}
        description = cfg.get("description")
        if not description:
            skills = skills_by_name.get(name)
            paragraphs = [p.strip() for p in (skills or "").split("\n\n") if p.strip() and not p.strip().startswith("#")]
            if paragraphs:
                description = paragraphs[0]
        if not description:
            description = "No description available."

        if isinstance(status, Exception) or not isinstance(status, dict):
            logger.warning(f"Error checking configuration for agent '{name}': {status}")
            configured = True
        else:
            configured = status.get("configured", True)
            if not configured:
                missing = []
                if status.get("missing_secrets"):
                    missing.append(f"secrets: {', '.join(status['missing_secrets'])}")
                if status.get("missing_variables"):
                    missing.append(f"variables: {', '.join(status['missing_variables'])}")
                config_note = f" [NOT CONFIGURED — missing {'; '.join(missing)}. Configure at /agents/{name}/configure]" if missing else f" [NOT CONFIGURED — configure at /agents/{name}/configure]"
                description += config_note

        if configured:
            operational = compute_agent_operational_status(cfg, agent_healths.get(name), tool_healths)
            status_str = operational["status"]
            if status_str == "Offline":
                description += " [STATUS: OFFLINE - DO NOT ROUTE REQUESTS HERE]"
                configured = False
            elif status_str == "Degraded":
                description += f" [STATUS: DEGRADED - Offline tools: {', '.join(operational['offline_tools'])}]"

        agents.append({
            "name": name,
            "description": description,
            "configured": configured,
        })

    return agents

async def _get_visible_agents(names: Optional[List[str]] = None) -> List[Dict]:
    """Internal: agents visible to the current user, with health-decorated descriptions.

    Applies the same filtering the old public ``list_agents`` tool did (disabled /
    offline / background / unconfigured), scoped to the calling user. No longer exposed
    as an MCP tool — clients use ``search_agents`` instead to avoid dumping every agent.

    Per Phase D of the Trellis Rules Engine hardening plan, per-agent status/decoration is no
    longer derived from the Host's ``/health`` JSON body — it's computed directly here
    from etcd via the same Phase A/B/C shared helpers Host's own ``/health`` handler
    uses (``is_routable_agent_type``, ``is_agent_external``, ``discover_agents``'s
    configuration-readiness fields, ``evaluate_health_status``). A cheap
    status-code-only ping to Host's ``/health`` is still done, purely as a liveness
    gate: Host and Gateway are separate processes, and if Host is down that must still
    fail loudly and clearly here, exactly as before — only the JSON body is no longer
    parsed or depended on.

    The bulk etcd fetch below (``agent_configs``/``agent_healths``) runs once and is
    handed into ``discover_agents()`` instead of each doing its own independent bulk
    fetch of the same whole-catalog data — this used to be two non-atomic snapshots of
    overlapping etcd state per call (see rules_engine_hardening_plan.md §2D.4a's "double
    bulk-fetch" note); collapsing it to one also means this etcd read now happens before
    the Host liveness ping rather than after. That reorder is benign: if etcd itself is
    down, the previous code already surfaced that via ``discover_agents()``'s own
    internal fetch failing *before* the liveness ping ever ran (``discover_agents()`` was
    already the first thing this function did), so "etcd down" was never actually
    guaranteed to be caught by the liveness check first. The only observable difference
    is the exact error string returned when Host is unreachable but etcd is fine (a few
    extra etcd reads now happen first) — every failure path still returns the same
    ``[{"name": "Error", ...}]`` shape immediately, with no partial/decorated data ever
    returned.

    When ``names`` is provided, only those agents are decorated — the cheap ranked-subset
    path used by ``search_agents``: it skips ``discover_agents``, the bulk skills fetch,
    and identity secret fetches entirely. Names failing the catalog checks (unknown,
    disabled, non-routable, internal) are omitted; the caller's "decorate, never
    re-exclude" fallback handles them. A per-agent ``is_agent_configured`` failure fails
    open with ``configured=True`` rather than returning the all-or-nothing Error sentinel.
    """
    user_id = user_id_var.get()

    try:
        disabled_agents = await asyncio.to_thread(identity_mgr.get_disabled_standard_agents)
        agent_configs = await asyncio.to_thread(identity_mgr.get_all_agent_configs)
        agent_healths = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "agent")
        tool_healths = await asyncio.to_thread(identity_mgr.get_all_health_statuses, "tool")
    except Exception as e:
        logger.error(f"Error computing agent status from etcd: {e}", exc_info=True)
        return [{"name": "Error", "description": "Failed to compute agent status. Please try again later."}]

    if names is not None:
        liveness_error = await _check_host_liveness_error()
        if liveness_error:
            return [liveness_error]
        try:
            return await _decorate_visible_subset(
                names, user_id, disabled_agents, agent_configs, agent_healths, tool_healths
            )
        except Exception as e:
            logger.error(f"Error decorating ranked agent subset: {e}", exc_info=True)
            return [{"name": "Error", "description": "Failed to verify agent configurations. Please try again later."}]

    try:
        discovered_agents = await discover_agents(user_id=user_id, agent_configs=agent_configs, agent_health=agent_healths)
    except Exception as e:
        logger.error(f"Error checking agent configurations: {e}", exc_info=True)
        return [{"name": "Error", "description": "Failed to verify agent configurations. Please try again later."}]

    liveness_error = await _check_host_liveness_error()
    if liveness_error:
        return [liveness_error]

    agents = []

    for agent_dict in discovered_agents:
        agent_name = agent_dict["name"]

        if agent_name in disabled_agents:
            continue
        if not is_routable_agent_type(agent_name, agent_dict):
            continue
        if not is_agent_external(agent_dict):
            continue

        is_configured = agent_dict.get("is_configured", False)

        description = agent_dict.get("description") or "No description available."

        if not description or description == "No description available.":
            skills = agent_dict.get("skills", "")
            paragraphs = [p.strip() for p in skills.split("\n\n") if p.strip() and not p.strip().startswith("#")]
            if paragraphs:
                description = paragraphs[0]

        if not is_configured:
            missing = []
            if agent_dict.get("missing_secrets"):
                missing.append(f"secrets: {', '.join(agent_dict['missing_secrets'])}")
            if agent_dict.get("missing_variables"):
                missing.append(f"variables: {', '.join(agent_dict['missing_variables'])}")
            config_note = f" [NOT CONFIGURED — missing {'; '.join(missing)}. Configure at /agents/{agent_name}/configure]" if missing else f" [NOT CONFIGURED — configure at /agents/{agent_name}/configure]"
            description += config_note
        else:
            # Shared with core/host.py's /health handler -- see
            # core/health.py:compute_agent_operational_status.
            cfg = agent_configs.get(agent_name) or {}
            operational = compute_agent_operational_status(cfg, agent_healths.get(agent_name), tool_healths)
            status = operational["status"]
            if status == "Offline":
                description += " [STATUS: OFFLINE - DO NOT ROUTE REQUESTS HERE]"
                is_configured = False
            elif status == "Degraded":
                description += f" [STATUS: DEGRADED - Offline tools: {', '.join(operational['offline_tools'])}]"

        agents.append({
            "name": agent_name,
            "description": description,
            "configured": is_configured,
        })

    return agents

@mcp.tool(
    title="Search Agents",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True),
)
async def search_agents(ctx: Context, query: str, limit: Optional[int] = None) -> List[Dict]:
    """Find the agents most relevant to a request.

    Use this to discover which specialized agent(s) can handle a task, then call the
    chosen one with `use_agent`. Returns a short, ranked list of
    `{name, description, configured}` — not the full catalog — so it scales to large
    numbers of agents. If the Trellis Rules Engine deterministically locks onto an
    agent for this query, exactly one result is returned regardless of `limit`.

    Unconfigured agents are included with `configured: false` and a note in their
    description listing the missing credentials and a configure URL. Only call
    `use_agent` on agents where `configured` is true.

    Args:
        query: Natural-language description of the task or topic to find agents for.
        limit: Maximum number of agents to return (default: agent_search_limit tunable; env AGENT_SEARCH_LIMIT, 8 if unset).
    """
    await ctx.report_progress(0, 2, message=f"Searching agents for: '{query}'")

    # Per Phase E of the Trellis Rules Engine hardening plan (E4), _search_agents_ranked is called
    # directly with the caller's real limit -- nothing downstream re-excludes on it
    # anymore, so the old limit=0-then-intersect-then-truncate dance is no longer
    # needed. _get_visible_agents() is used purely to annotate results (the
    # `configured` flag and any richer status text) -- never to drop a result that
    # search_agents already decided to return.
    ranked = await _search_agents_ranked(query, limit=limit, include_disabled=False)
    if not ranked:
        await ctx.report_progress(2, 2, message="No agents are currently available.")
        return []

    await ctx.report_progress(1, 2, message="Annotating results...")
    visible = await _get_visible_agents(names=[r["name"] for r in ranked])
    if len(visible) == 1 and visible[0].get("name") == "Error":
        # Host is unreachable or etcd decoration failed -- surface that clearly rather
        # than silently falling back to undecorated ranked results.
        await ctx.report_progress(2, 2, message=visible[0]["description"])
        return visible
    visible_by_name = {a["name"]: a for a in visible}

    results: List[Dict] = []
    for r in ranked:
        agent = visible_by_name.get(r["name"])

        if r.get("unavailable_match"):
            # search_agents()'s crafted "unavailable match" note (Phase E, E1/E3) --
            # its description is already a final, self-contained sentence explaining
            # why the routing-policy match was skipped. The matched agent's own name
            # still resolves in `visible` (it isn't disabled/internal/background), so
            # naively decorating this the same way as a real candidate would silently
            # overwrite that sentence with the agent's own catalog description. Because
            # the agent is currently unavailable (offline or not configured), its
            # `configured` flag is set to False so MCP clients and LLMs never attempt
            # to route requests to it.
            results.append({
                "name": r["name"],
                "description": r["description"],
                "configured": False,
            })
        elif agent:
            results.append({
                "name": agent["name"],
                "description": agent["description"],
                "configured": agent.get("configured", True),
            })
        else:
            # Decorate, never re-exclude: a name search_agents already decided to
            # return but that's absent from the visibility/decoration source (e.g. a
            # momentarily inconsistent bulk etcd read) still comes back, using its own
            # name/description/status rather than being silently dropped.
            results.append({
                "name": r["name"],
                "description": r["description"],
                "configured": False if r.get("status") == "Offline" else True,
            })

    names = [r["name"] for r in results]
    await ctx.report_progress(2, 2, message=f"Found {len(results)} agent(s): {', '.join(names) if names else 'none'}")
    return results

@mcp.tool(
    title="Use Agent",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False),
)
async def use_agent(ctx: Context, agent_name: str, prompt: str) -> str:
    """Call a specific agent with a prompt and return its response.

    Always call `search_agents` first to confirm the agent name and that it is
    configured. Do not guess agent names.

    Args:
        agent_name: Exact name of the agent to call (from `search_agents`).
        prompt: The full, self-contained request to send to the agent.
    """
    token = auth_token_var.get()
    user_id = user_id_var.get()

    prompt_preview = prompt[:150] + "..." if len(prompt) > 150 else prompt
    await ctx.report_progress(1, 3, message=f"Routing to agent: {agent_name} — \"{prompt_preview}\"")

    cfg = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    if cfg and not is_agent_external(cfg):
        return f"SYSTEM: Access denied. Agent '{agent_name}' is internal and cannot be called directly."

    if agent_name != "supervisor":
        try:
            status = await is_agent_configured(agent_name, user_id)
            if not status["configured"]:
                parts = [f"SYSTEM: Agent '{agent_name}' requires configuration before it can be used."]
                if status["missing_secrets"]:
                    parts.append(f"Missing secrets: {', '.join(status['missing_secrets'])}.")
                if status["missing_variables"]:
                    parts.append(f"Missing variables: {', '.join(status['missing_variables'])}.")
                parts.append(f"Configure it at: /agents/{agent_name}/configure")
                return " ".join(parts)
        except Exception as e:
            logger.error(f"Error checking agent configuration for '{agent_name}': {e}", exc_info=True)
            return f"SYSTEM: Error checking agent configuration for '{agent_name}'. Please try again later."

    # DEV_MODE_AUTH_TOKEN is a marker, not a credential -- forwarding it makes the host
    # reject the call with 401 (see core.auth). Omit the header so the host's own
    # DEV_MODE bypass applies instead.
    headers = {}
    if token and token != DEV_MODE_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {token}"

    await ctx.report_progress(2, 3, message=f"Calling {agent_name}...")

    try:
        req_kwargs = {
            "json": {
                "model": agent_name,
                "messages": [{"role": "user", "content": prompt}],
                "stream": True
            },
            "headers": headers,
            "timeout": httpx.Timeout(600.0, connect=10.0)
        }

        async def _consume_stream(client_obj):
            host_url = await _resolve_host_url()
            async with client_obj.stream("POST", f"{host_url}/v1/chat/completions", **req_kwargs) as response:
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError:
                    # raise_for_status() leaves a streaming response's body unread, so
                    # the handler below could not log it (reading .text raised
                    # httpx.ResponseNotRead, masking the real status). Buffer it here,
                    # while the stream is still open. The body is only ever logged, so a
                    # failed read must not replace the status that was just raised.
                    try:
                        await response.aread()
                    except Exception:
                        pass
                    raise
                async for line in response.aiter_lines():
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        if data.get("status") == "processing":
                            await ctx.report_progress(2, 3, message=f"Agent '{agent_name}' is thinking...")
                        elif data.get("status") == "tool_call":
                            await ctx.report_progress(2, 3, message=f"Agent '{agent_name}' is calling tool: {data.get('tool')}...")
                        elif "choices" in data:
                            return data["choices"][0]["message"]["content"]
                        elif "error" in data:
                            return f"SYSTEM: Agent '{agent_name}' execution failed: {data['error']}"
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON from agent stream: {e}. Raw line: {line}")
            return f"SYSTEM: Agent '{agent_name}' returned no content."

        if hasattr(app, "state") and hasattr(app.state, "http_client"):
            content = await _consume_stream(app.state.http_client)
        else:
            async with httpx.AsyncClient() as client:
                content = await _consume_stream(client)

        if not content.startswith("SYSTEM:"):
            await ctx.report_progress(3, 3, message=f"Agent '{agent_name}' responded ({len(content)} chars)")
        return content
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 503:
            return f"SYSTEM: The agent '{agent_name}' is currently offline due to technical failures and cannot process requests."
        if e.response.status_code == 404:
            return f"SYSTEM: The agent '{agent_name}' was not found or is disabled."
        error_body = e.response.text[:2048]
        logger.error(f"Error calling agent '{agent_name}' (HTTP {e.response.status_code}): {error_body}", exc_info=True)
        return f"SYSTEM: Error calling agent '{agent_name}'. Please try again later."
    except Exception as e:
        logger.error(f"Failed to connect to agent '{agent_name}': {str(e)}", exc_info=True)
        return f"SYSTEM: Failed to connect to agent '{agent_name}'. Please try again later."


@mcp.tool(
    title="Search Tools",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True),
)
async def search_tools(ctx: Context, query: str, limit: Optional[int] = None) -> List[Dict]:
    """Find deterministic tools available for direct execution.

    Use this to discover which whitelisted tool can handle a request — a CLI lookup,
    status check, or single deterministic operation — then call `use_tool` to execute
    it directly, with no intermediate agent hop.

    Returns a short, ranked list of Tool Cards: `{name, description, parameters,
    configured, status, source}`. A card carrying `detail: "lazy"` (with an empty
    `parameters` map) is an edge tool that published only a summary — call
    `describe_tool` for its real schema before `use_tool`. Unconfigured tools are
    included with `configured: false` and a note in their description listing the
    missing secrets/variables. Only call `use_tool` on tools where `configured` is true.

    Args:
        query: Natural-language description of the command or lookup to find a tool for.
        limit: Maximum number of tools to return (default: tool_search_limit tunable; env TOOL_SEARCH_LIMIT, 8 if unset).
    """
    user_id = user_id_var.get()
    await ctx.report_progress(0, 1, message=f"Searching tools for: '{query}'")

    results = await _search_tools_ranked(
        query=query,
        limit=limit,
        user_id=user_id,
    )

    names = [r["name"] for r in results]
    await ctx.report_progress(1, 1, message=f"Found {len(results)} tool(s): {', '.join(names) if names else 'none'}")
    return results


@mcp.tool(
    title="Describe Tool",
    annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True),
)
async def describe_tool(ctx: Context, tool_name: str) -> Dict:
    """Return the full schema (parameters, description) for exactly one tool.

    Use this after `search_tools` when a card is summary-only (`detail: "lazy"`) or when
    the schema is needed without ranking. Takes the same name forms as `use_tool`:
    a local name, a central MCP tool's `mcp__{server}__{name}`, or an edge tool's
    `<site>__{tool}` / `mcp__{site}__{mcp}__{name}` form. Never executes the tool.

    Returns `{name, description, parameters, source, detail}`, or `{name, unavailable:
    true, reason}` when the tool is unknown or an edge could not answer.

    Args:
        tool_name: Exact name of the tool to describe, as returned by `search_tools`.
    """
    result = await describe_tool_entry(tool_name, user_id_var.get())
    await ctx.report_progress(1, 1, message=f"Described tool: {tool_name}")
    return result


@mcp.tool(
    title="Use Tool",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False),
)
async def use_tool(ctx: Context, tool_name: str, arguments: Dict[str, Any]) -> Any:
    """Directly execute a whitelisted deterministic tool with arguments.

    Bypasses all agent hops and returns the raw structured output. Always call
    `search_tools` first to confirm the exact tool name, its parameter schema, and
    that it is configured — do not guess.

    Args:
        tool_name: Exact name of the tool (e.g. 'opsctl', 'netctl', a central MCP
            tool's 'mcp__{server}__{name}', or an edge MCP tool's
            'mcp__{site}__{mcp}__{name}' form as returned by `search_tools`).
        arguments: Dictionary of arguments matching the tool's input schema.
    """
    user_id = user_id_var.get()
    if agent_token.verify_or_none(agent_token_var.get()) is None:
        # Direct tool use acts for the external caller, so the token names the
        # `gateway` agent and carries that caller's identity (read once here). It is
        # an ordinary agent token: no elevated principal, so the hub/relay resolve the
        # front door's exposure from the tool's own `public` flag like anyone else's.
        mint_identity = await resolve_mint_identity(identity_mgr, user_id)
        mint_for_run(
            "gateway",
            user_id,
            user_email=mint_identity["user_email"],
            groups=mint_identity["groups"],
            run_id=uuid.uuid4().hex,
        )

    await ctx.report_progress(0, 3, message=f"Checking access for: {tool_name}")
    await ctx.report_progress(1, 3, message=f"Checking configuration for: {tool_name}")
    await ctx.report_progress(2, 3, message=f"Executing {tool_name}...")
    output = await execute_whitelisted_tool(
        tool_name,
        arguments,
        user_id,
        identity_manager=identity_mgr,
        is_configured=is_tool_configured,
        get_hub_client_fn=get_hub_client,
        get_external_mcp_client_fn=get_external_mcp_client,
        call_edge_mcp_fn=call_edge_mcp,
    )
    if not (isinstance(output, str) and output.startswith("SYSTEM:")):
        await ctx.report_progress(3, 3, message=f"Tool '{tool_name}' execution complete.")
    return output


if __name__ == "__main__":
    from core.agent_token import require_secret
    from core.log_redaction import install as install_redaction

    install_redaction()
    require_secret("gateway")
    app = mcp.http_app()
    app.add_middleware(AuthMiddleware, identity_mgr=identity_mgr)
    uvicorn.run(app, host=os.getenv("BIND_HOST", "0.0.0.0"), port=8002)
