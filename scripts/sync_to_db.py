# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import argparse
import asyncio
import os
import sys


import yaml
from pathlib import Path

# Add the parent directory to sys.path to import core
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import tool_access
from core.auth import IdentityManager
from core.embeddings import embed_text
from core.models import (
    BACKGROUND_AGENT_TYPES,
    EDGE_MCP_REF_RE,
    EDGE_MCP_TOOL_REF_RE,
    EDGE_MCP_WILDCARD_RE,
    coerce_bool_flag,
    AgentRule,
    GlobalRule,
    RoutingRulesConfig,
)
from core.tool_index import delete_tool, index_tool

BASE_DIR = Path(__file__).parent.parent
WORKSPACE_DIR = BASE_DIR / "workspace"

AGENTS_DIR = WORKSPACE_DIR / "agents"
WORKFLOWS_DIR = WORKSPACE_DIR / "workflows"
TOOLS_DIR = WORKSPACE_DIR / "tools"
POLICIES_DIR = WORKSPACE_DIR / "policies"
TOOL_ACCESS_POLICY_PATH = POLICIES_DIR / "tool_access.yaml"


def _warn_unknown_rule_keys(model_cls, raw_rules, context):
    """Warn (don't fail) when a raw rule dict has a key the model doesn't know about --
    these models don't set extra="forbid", so a typo like `when_to_use` instead of
    `use_when` is otherwise silently dropped and produces a rule that never matches
    anything, with no other signal to the author."""
    known = set(model_cls.model_fields.keys())
    for i, item in enumerate(raw_rules or []):
        if isinstance(item, dict):
            unknown = sorted(set(item.keys()) - known)
            if unknown:
                print(
                    f"  WARNING: {context} rule #{i} has unrecognized field(s) {unknown} "
                    f"(known fields: {sorted(known)}) — check for a typo; unrecognized "
                    "fields are silently dropped, not an error."
                )
MCPS_DIR = WORKSPACE_DIR / "mcps"

# Hard budget for live-discovering one MCP server's tools at sync time: generous
# enough for a first-run `npx` download, short enough that one unreachable server
# can't stall the whole registry sync.
MCP_DISCOVERY_TIMEOUT_SECONDS = 20

# Supervisor is an internal core agent
SUPERVISOR_DIR = BASE_DIR / "core" / "assets" / "supervisor"

def _edge_ref_kind(entry):
    """``("site"|"mcp"|"pair", key)`` when ``entry`` names an edge resource, else ``None``.

    ``site`` is a ``<site>__*`` wildcard (any MCP that site exports), ``mcp`` is the
    registry key behind a 4-part ``mcp__<site>__<mcp>__<tool>`` name, and ``pair`` is a
    2-part ``<site>__<name>`` -- which is an edge MCP *or* an edge tool, so the registry
    decides. Everything central (a bare tool name, a 3-part ``mcp__<server>__<tool>``)
    returns ``None``: sync must stay silent about references it cannot judge.
    """
    if not isinstance(entry, str):
        return None
    if EDGE_MCP_WILDCARD_RE.fullmatch(entry):
        return "site", entry[: -len("__*")]
    if EDGE_MCP_TOOL_REF_RE.fullmatch(entry):
        _prefix, site, mcp, _tool = entry.split("__", 3)
        return "mcp", f"{site}__{mcp}"
    if EDGE_MCP_REF_RE.fullmatch(entry):
        # `core.models.EDGE_TOOL_REF_RE` is the same pattern -- same `<site>__<name>`
        # shape and segment language, just a different registry prefix -- so one match
        # decides both readings.
        return "pair", entry
    return None


def _edge_refs_of(name, config):
    """Edge references an agent/workflow declares, as warning-ready tuples.

    Scanned while the config is being synced (before the registry is authoritative),
    but only *resolved* after the MCP pass -- a reference to an MCP defined in this
    same workspace must not warn just because this is the first run that persists it.
    """
    label = "workflow" if config.get("type") in BACKGROUND_AGENT_TYPES else "agent"
    refs = []
    seen = set()
    for entry in list(config.get("allowed_mcps") or []) + list(config.get("allowed_tools") or []):
        if not isinstance(entry, str) or entry in seen:
            continue
        seen.add(entry)
        found = _edge_ref_kind(entry)
        if found:
            refs.append((label, name, entry, found[0], found[1]))
    return refs


def _warn_unresolved_edge_refs(refs, known_mcps, known_tools):
    """One ``WARNING`` per edge reference the registry cannot resolve yet; never fails.

    An edge that has not dialled in yet (or whose catalog the relay has not published
    yet) is a normal bring-up state: the same manifest starts working the moment it
    connects, because the reference is resolved at runtime, not at sync time. So this
    is a warning rather than an error, and neither the exit code nor the prune pass is
    affected.

    ``known_mcps`` maps every registered MCP name to its config. A 4-part name also
    resolves when its *central* reading does (a central server whose tool name contains
    ``__`` produces the same shape -- see ``discovery.resolve_edge_mcp_target``), so this
    check never second-guesses the runtime's registry-first split.
    """
    for label, name, entry, kind, key in refs:
        if kind == "site":
            resolved = any(mcp.startswith(f"{key}__") for mcp in known_mcps)
        elif kind == "mcp":
            resolved = key in known_mcps or key.split("__", 1)[0] in known_mcps
        else:
            resolved = key in known_mcps or key in known_tools
        if resolved:
            continue
        print(
            f"  WARNING: {label} '{name}' references edge resource '{entry}', which has no "
            "registry entry yet — edge not connected / catalog not published yet. "
            "The reference starts working once that edge connects; the sync continues."
        )


def read_tool_access_policy(path=None):
    """``(document, errors)`` for the workspace group-rule file.

    ``(None, [])`` means the file does not exist -- not an error, but also not an
    instruction to clear the registry (see ``sync_tool_access_policy``).
    """
    path = path or TOOL_ACCESS_POLICY_PATH
    if not path.exists():
        return None, []
    try:
        with open(path, "r") as f:
            document = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        return None, [f"{path}: {e}"]
    errors = tool_access.validate_policy(document)
    return (None if errors else document), errors


def sync_tool_access_policy(identity_mgr, path=None) -> int:
    """Publish ``workspace/policies/tool_access.yaml`` into the registry.

    Returns 0 on success (or when the file does not exist) and 2 when the file is
    invalid: nothing is written, so a typo never replaces a good policy with a
    permissive one, and the non-zero exit stops the sync loudly. A *missing* file
    leaves the registry untouched and warns -- deleting the file must not silently
    drop every group rule.

    db-sync runs this on every rebuild; ``trellis sync`` re-runs it while the stack
    is up. From etcd the document reaches every enforcing process through its watch,
    so a policy edit needs no restart.
    """
    document, errors = read_tool_access_policy(path)
    resolved = path or TOOL_ACCESS_POLICY_PATH
    if errors:
        print(f"\nINVALID tool-access policy: {resolved}")
        for error in errors:
            print(f"  ERROR: {error}")
        print(
            "  Refusing to sync it. Fix workspace/policies/tool_access.yaml and "
            "re-run; the registry still holds the last valid policy."
        )
        return 2
    if document is None:
        print(
            f"\nWARNING: no {resolved} found — the registry keeps whatever "
            "tool-access policy it already has (workspace layout: create "
            "workspace/policies/tool_access.yaml with `rules: []` for no group rules)."
        )
        return 0
    for warning in tool_access.policy_warnings(document):
        print(f"  WARNING: {warning}")
    try:
        tool_access.publish_policy(document, client=identity_mgr.client)
    except tool_access.PolicyInvalid as e:  # pragma: no cover - validate_policy above
        print(f"\nINVALID tool-access policy: {e}")
        return 2
    except Exception as e:
        print(f"\nERROR: could not publish the tool-access policy: {e}")
        return 1
    rules = len(document.get("rules") or [])
    print(
        f"  Saved tool-access policy ({rules} group rule"
        f"{'' if rules == 1 else 's'}) for {tool_access.POLICY_PATH}"
    )
    return 0


def sync_agent(identity_mgr, agent_dir, name=None, default_type=None, edge_refs=None):
    if not name:
        name = agent_dir.name
        
    config_path = agent_dir / "config.yaml"
    skills_path = agent_dir / "skills.md"
    
    if config_path.exists():
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
            
        # Registry key always wins: discover_agents()/Gateway's etcd lookups (health,
        # config, use_agent()) are all keyed by this directory/registry name, so a
        # config-internal name: that silently diverges from it causes a lookup miss --
        # wrong-key decoration defaulting to "Online"/no-missing-secrets at search time,
        # then a real failure at use_agent() invocation time (see
        # rules_engine_hardening_plan.md §2D.3 item 1 / §2D.4a item 3). Backfilling an
        # absent name: stays silent (the normal case); overriding a genuine mismatch is
        # loud, not silent.
        existing_name = config.get("name")
        if existing_name and existing_name != name:
            print(
                f"  WARNING: agent '{name}' config.yaml sets name: '{existing_name}', which does not "
                f"match its directory/registry key '{name}'. Overriding to '{name}' so discover_agents()/"
                f"health lookups stay keyed consistently (see rules_engine_hardening_plan.md §2D.3 item 1 / "
                f"§2D.4a item 3)."
            )
        config["name"] = name
        
        if "allowed_tools" not in config:
            config["allowed_tools"] = []

        if not config.get("type") and default_type:
            config["type"] = default_type

        config["external"] = coerce_bool_flag(config.get("external"), True)
        config["internal"] = coerce_bool_flag(config.get("internal"), True)

        if edge_refs is not None:
            edge_refs.extend(_edge_refs_of(name, config))

        # Validate declarative routing rules before persisting; drop the raw
        # value rather than crash the whole sync if a config.yaml is malformed.
        raw_rules = config.get("rules", [])
        _warn_unknown_rule_keys(AgentRule, raw_rules, f"agent '{name}'")
        try:
            config["rules"] = [rule.model_dump() for rule in [AgentRule(**r) for r in raw_rules]]
        except Exception as e:
            print(f"  WARNING: invalid rules for agent {name}, dropping rules: {e}")
            config["rules"] = []

        # For script types, we need the rel_path so the engine knows where to run it
        try:
            rel_path = agent_dir.relative_to(BASE_DIR)
            config["rel_path"] = str(rel_path)
        except ValueError:
            # If agent_dir is outside BASE_DIR, just use the absolute path or ignore
            pass
            
        identity_mgr.save_agent_config(name, config)
        rule_count = len(config.get("rules") or [])
        rules_suffix = f", with {rule_count} rules" if rule_count else ""
        print(f"  Saved config for agent: {name} (Type: {config.get('type')}{rules_suffix})")

        # Index the agent for semantic search. Skipped for background agents/scripts
        # and the supervisor, which are never returned by search_agents.
        if config.get("type") not in ("background_agent", "background_script") and name != "supervisor":
            parts = [config.get("name", name), config.get("description", "")]
            tags = config.get("tags") or []
            if tags:
                parts.append(" ".join(str(t) for t in tags))
            vector = embed_text("\n".join(p for p in parts if p), task_type="retrieval_document")
            if vector:
                identity_mgr.save_agent_embedding(name, vector)
                print(f"  Indexed embedding for agent: {name}")
            else:
                print(f"  Skipped embedding for agent: {name} (embeddings unavailable)")

    if skills_path.exists():
        with open(skills_path, "r") as f:
            skills = f.read()
        identity_mgr.save_agent_skills(name, skills)
        print(f"  Saved skills for agent: {name}")
        
    return name

def _discover_mcp_tools(config):
    """Live-discover an MCP server's tool catalog from the sync environment.

    Mirrors the runtime discovery in ``core/agent_factory.discover_external_mcps``
    (not the user-scoped ``get_external_mcp_client``, which injects user secrets the
    sync environment doesn't have): a stdio config spawns the command with its raw
    args/env; http/sse configs connect to ``command`` as a URL. Returns a plain list
    of ``{name, description, inputSchema}`` dicts ready to persist under the config's
    ``tools`` key, or ``None`` when the transport is unusable or the server can't be
    reached within MCP_DISCOVERY_TIMEOUT_SECONDS -- sync must never fail hard on
    this, the runtime still discovers live as a fallback.
    """
    # Lazy so the script's import cost is unchanged when every config declares tools.
    from fastmcp import Client as FastMCPClient
    from fastmcp.client import StdioTransport, SSETransport, StreamableHttpTransport

    name = config.get("name")
    command = config.get("command")
    if not command:
        return None

    transport_type = (config.get("transport") or "stdio").lower()
    if transport_type == "stdio":
        # The MCP SDK merges this env over the safe inherited defaults (PATH etc.).
        transport = StdioTransport(
            command=command, args=config.get("args") or [], env=config.get("env") or {}, keep_alive=False
        )
    elif transport_type in ("http", "streamable-http"):
        transport = StreamableHttpTransport(url=command, headers=config.get("env") or {})
    elif transport_type == "sse":
        transport = SSETransport(url=command, headers=config.get("env") or {})
    else:
        print(f"  WARNING: MCP '{name}' has unsupported transport '{transport_type}'; skipping tool discovery.")
        return None

    async def _list_tools():
        client = FastMCPClient(transport)
        async with client:
            tools = await client.list_tools()
        # MCP SDK v2 exposes the schema as `input_schema`; older versions only as
        # `inputSchema` (a deprecated property on v2 that warns when read). Probe
        # the modern name first.
        return [
            {
                "name": tool.name,
                "description": tool.description or "",
                "inputSchema": getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None) or {},
            }
            for tool in tools
        ]

    try:
        return asyncio.run(asyncio.wait_for(_list_tools(), timeout=MCP_DISCOVERY_TIMEOUT_SECONDS))
    except Exception as e:
        print(
            f"  WARNING: could not discover tools for MCP '{name}' within "
            f"{MCP_DISCOVERY_TIMEOUT_SECONDS}s ({e}); saving config without a tools "
            "list and skipping MCP tool embeddings. The runtime will still discover "
            "this server live."
        )
        return None

def sync_mcp(identity_mgr, config):
    """Persist one MCP config and index an embedding per tool it declares.

    Tool embeddings are saved under the ``mcp__{server}__{tool}`` prefixed name --
    the same ``use_tool`` execution form ``core/tool_search.py`` looks embeddings up
    by -- so MCP tools rank via cosine exactly like local workspace tools.

    No registration path (mcp.yaml, marketplace add_mcp, admin save_mcp) persists a
    ``tools`` list, so when it's absent we live-discover the server's catalog and
    persist it back into the config. Later syncs index straight from it, and the
    runtime's discovery fast-path (``discover_external_mcps``' ``if config.tools:``)
    skips reconnecting. Discovery failure is non-fatal: the config is saved
    unchanged and embeddings are simply skipped.
    """
    name = config["name"]
    if "__" in name:
        # `mcp__<server>__<tool>` has to split unambiguously, and `<site>__<mcp>` keys
        # belong to the edge relay. Warn and skip: one bad directory must not abort the
        # whole sync (nor poison the registry with an unsplittable key).
        print(
            f"  Skipping MCP '{name}': its name may not contain '__' "
            f"(reserved for edge '<site>__<mcp>' registry keys)."
        )
        return
    if name.endswith("_"):
        # Same class of problem: every reference segment must end with a letter, digit
        # or '-', so a name ending in `_` can be published but never referenced.
        print(
            f"  Skipping MCP '{name}': its name may not end with '_' "
            f"(no unambiguous reference form)."
        )
        return

    if not config.get("tools"):
        discovered = _discover_mcp_tools(config)
        if discovered:
            config["tools"] = discovered
            print(f"  Discovered and persisted {len(discovered)} tools for MCP: {name}")

    identity_mgr.save_mcp_config(name, config)
    print(f"  Saved config for MCP: {name}")

    for tool in config.get("tools") or []:
        tool_name = tool.get("name", "")
        if not tool_name:
            continue
        properties = (tool.get("inputSchema") or {}).get("properties") or {}
        input_keys = ", ".join(
            f"{key}:{spec.get('type', 'string')}" if isinstance(spec, dict) else str(key)
            for key, spec in properties.items()
        )
        parts = [tool_name, tool.get("description", ""), input_keys]
        embedding_name = f"mcp__{name}__{tool_name}"
        vector = embed_text("\n".join(p for p in parts if p), task_type="retrieval_document")
        if vector:
            identity_mgr.save_tool_embedding(embedding_name, vector)
            print(f"  Indexed embedding for MCP tool: {embedding_name}")
        else:
            print(f"  Skipped embedding for MCP tool: {embedding_name} (embeddings unavailable)")


def prune_obsolete_mcps(identity_mgr, existing_mcps, seen_mcps):
    """Delete registry entries for MCPs that no longer exist under workspace/mcps/.

    Alongside the config, prefix-delete the ``mcp__{name}__*`` tool embeddings
    sync_mcp indexed for the server (via IdentityManager.delete_mcp_tool_embeddings)
    -- otherwise the vectors outlive the config and keep surfacing in tool search
    as ghost hits for a server nobody can call anymore."""
    for mcp in existing_mcps - seen_mcps:
        print(f"  Deleting obsolete MCP: {mcp}")
        identity_mgr.client.delete(f"/registry/mcps/{mcp}/config")
        identity_mgr.delete_mcp_tool_embeddings(mcp)

def _registry_would_be_wiped(existing_by_category, seen_by_category) -> bool:
    """True when sync saw NOTHING anywhere in the workspace, yet etcd still has entries.

    That shape almost always means the workspace was not mounted (a mis-pointed
    TRELLIS_WORKSPACE_DIR, a missing bind mount) rather than that every author deleted
    their work in one commit. Used to gate the prune pass in main().

    Deliberately *global*, not per-category: a single empty category alongside a
    populated one is indistinguishable from ordinary pruning (an org with agents but no
    tools of its own yet), so blocking it would break the documented first-run flow of
    deleting the demo content. Only a total blank counts as an unmounted workspace.
    """
    return any(existing_by_category) and not any(seen_by_category)


def _force_prune_requested(argv=None) -> bool:
    """True when the prune guard should be bypassed: ``--force-prune`` or SYNC_FORCE_PRUNE.

    The env form exists because the compose ``db-sync`` init container runs this
    script with no arguments -- an operator sets SYNC_FORCE_PRUNE=true in .env rather
    than editing the container command.
    """
    parser = argparse.ArgumentParser(
        prog="sync_to_db.py",
        description="Sync workspace/ (agents, workflows, tools, mcps) into the etcd registry.",
    )
    parser.add_argument(
        "--force-prune",
        action="store_true",
        help=(
            "Allow pruning the whole registry when the workspace syncs nothing at all "
            "(it looks unmounted). Equivalent to SYNC_FORCE_PRUNE=true."
        ),
    )
    args = parser.parse_args(argv)
    if args.force_prune:
        return True
    return os.getenv("SYNC_FORCE_PRUNE", "").strip().lower() in {"1", "true", "yes", "on"}


def main(argv=None):
    force_prune = _force_prune_requested(argv)
    identity_mgr = IdentityManager(
        host=os.getenv("ETCD_HOST", "127.0.0.1"),
        port=int(os.getenv("ETCD_PORT", 2379))
    )

    # 0. Tool-access group rules. Validated and published FIRST: an invalid file must
    #    stop the sync before any other write, never leave a stale policy behind.
    print("Syncing tool-access policy to etcd...")
    policy_status = sync_tool_access_policy(identity_mgr)
    if policy_status:
        print("\nREFUSING TO SYNC: nothing else was written to the registry.")
        return policy_status
    
    # 1. Fetch current items from etcd
    existing_agents = set(identity_mgr._get_all_configs_by_prefix("/registry/agents/").keys())
    # Tool configs (not just names): the prune needs `managed_by` to tell a
    # workspace tool from an edge-registered one. A config that fails to decode is
    # absent from this dict and therefore never enters the delete loop at all --
    # fail-closed, exactly like an unreadable edge config should be.
    existing_tool_configs = identity_mgr._get_all_configs_by_prefix("/registry/tools/")
    existing_tools = set(existing_tool_configs)
    # Same reason as tools: the prune needs `managed_by` to tell a workspace MCP from
    # one the edge relay published for a `<site>__<mcp>` that never exists on disk.
    existing_mcp_configs = identity_mgr._get_all_configs_by_prefix("/registry/mcps/")
    existing_mcps = set(existing_mcp_configs)
    
    seen_agents = set()
    seen_tools = set()
    seen_mcps = set()
    # Edge references are collected per agent/workflow during the sync and resolved
    # after the MCP pass -- one prefix read per run, and no false warning for an MCP
    # this very run is about to persist for the first time.
    edge_refs = []
    
    print("Syncing agents to etcd...")
    if AGENTS_DIR.exists():
        for agent_dir in AGENTS_DIR.iterdir():
            if not agent_dir.is_dir() or agent_dir.name == "supervisor":
                continue
            name = sync_agent(identity_mgr, agent_dir, default_type="user_agent", edge_refs=edge_refs)
            if name:
                seen_agents.add(name)
                
    print("\nSyncing workflows to etcd...")
    if WORKFLOWS_DIR.exists():
        for agent_dir in WORKFLOWS_DIR.iterdir():
            if not agent_dir.is_dir():
                continue
            name = sync_agent(identity_mgr, agent_dir, default_type="background_agent", edge_refs=edge_refs)
            if name:
                seen_agents.add(name)
    
    print("\nSyncing supervisor to etcd...")
    if SUPERVISOR_DIR.exists():
        name = sync_agent(identity_mgr, SUPERVISOR_DIR, name="supervisor", default_type="user_agent")
        if name:
            seen_agents.add(name)

    print("\nSyncing tools to etcd...")
    if TOOLS_DIR.exists():
        for tool_yaml in TOOLS_DIR.glob("**/tool.yaml"):
            tool_dir = tool_yaml.parent
            with open(tool_yaml, "r") as f:
                data = yaml.safe_load(f)
                
            # Support both single tool and list of tools
            tool_configs = data if isinstance(data, list) else [data]
            
            for config in tool_configs:
                if not config.get("name"):
                    config["name"] = tool_dir.name
                    
                # Add relative path so Hub knows where to execute it
                rel_path = tool_dir.relative_to(BASE_DIR)
                config["rel_path"] = str(rel_path)
                
                name = config["name"]
                identity_mgr.save_tool_config(name, config)
                seen_tools.add(name)
                print(f"  Saved config for tool: {name}")

                # Index the embedding only for tools exposed publicly via the gateway.
                if config.get("public"):
                    if index_tool(
                        identity_mgr,
                        name,
                        config.get("description", ""),
                        config.get("inputs") or {},
                    ):
                        print(f"  Indexed embedding for tool: {name}")
                    else:
                        print(f"  Skipped embedding for tool: {name} (embeddings unavailable)")

    print("\nSyncing routing rules to etcd...")
    routing_rules_path = WORKSPACE_DIR / "routing_rules.yaml"
    if routing_rules_path.exists():
        with open(routing_rules_path, "r") as f:
            raw_routing_rules = yaml.safe_load(f) or {}
        _warn_unknown_rule_keys(GlobalRule, raw_routing_rules.get("global_rules", []), "global")
        try:
            routing_rules = RoutingRulesConfig(**raw_routing_rules)
        except Exception as e:
            print(f"  WARNING: invalid workspace/routing_rules.yaml, skipping: {e}")
        else:
            for rule in routing_rules.global_rules:
                if rule.target_agent not in seen_agents:
                    print(
                        f"  WARNING: global rule '{rule.rule_id}' targets unknown agent "
                        f"'{rule.target_agent}' — check for a typo against a real agent name; "
                        "this rule will never match anything."
                    )
            identity_mgr.save_routing_rules(routing_rules.model_dump())
            print(f"  Saved routing rules from workspace/routing_rules.yaml ({len(routing_rules.global_rules)} global rules)")
    else:
        print("  No workspace/routing_rules.yaml found, skipping.")

    print("\nSyncing MCPs to etcd...")
    if MCPS_DIR.exists():
        for mcp_yaml in MCPS_DIR.glob("**/mcp.yaml"):
            mcp_dir = mcp_yaml.parent
            with open(mcp_yaml, "r") as f:
                data = yaml.safe_load(f)
                
            mcp_configs = data if isinstance(data, list) else [data]
            
            for config in mcp_configs:
                if not config.get("name"):
                    config["name"] = mcp_dir.name
                 
                sync_mcp(identity_mgr, config)
                seen_mcps.add(config["name"])

    # Edge references that still resolve to nothing: warn (the edge is not connected
    # yet, so the relay has published no catalog). Runs after the MCP pass because a
    # reference may name an MCP from this same workspace.
    known_mcps = dict(existing_mcp_configs)
    known_mcps.update({name: {} for name in seen_mcps})
    _warn_unresolved_edge_refs(edge_refs, known_mcps, existing_tools | seen_tools)

    # 2. Prune obsolete items
    #
    # Guard first: refuse when sync saw NOTHING anywhere in the workspace while the
    # registry still has entries. That is the signature of an unmounted or mis-pointed
    # workspace, and silently wiping a registry on a typo is the worst failure mode
    # this script has. The check is deliberately global (all three categories blank),
    # not per-category, so a legitimately empty category -- an org with agents but no
    # tools of its own yet -- prunes normally instead of blocking the stack.
    # supervisor is excluded because it is synced from the image
    # (core/assets/supervisor), not the workspace, so it would always be "seen" and
    # mask an otherwise empty workspace/agents/.
    #
    # (Aborting skips the WHOLE prune pass, not just one category, so nothing is
    # half-pruned before the operator fixes the mount.)
    categories = ("agents", "tools", "mcps")
    seen_user_agents = seen_agents - {"supervisor"}
    existing_user_agents = existing_agents - {"supervisor"}
    existing_by_category = (existing_user_agents, existing_tools, existing_mcps)
    seen_by_category = (seen_user_agents, seen_tools, seen_mcps)

    if not force_prune and _registry_would_be_wiped(existing_by_category, seen_by_category):
        print(f"\nREFUSING TO PRUNE: sync found no agents, no tools, and no MCPs under {WORKSPACE_DIR} --")
        print("the workspace looks unmounted (wrong TRELLIS_WORKSPACE_DIR, or a missing bind mount),")
        print("or all of its content was removed at once.")
        for category, existing in zip(categories, existing_by_category):
            if existing:
                count = len(existing)
                print(f"  - {category}: {count} entr{'y' if count == 1 else 'ies'} still in etcd")
        print("Nothing was deleted. To resolve:")
        print("  - fix TRELLIS_WORKSPACE_DIR / the bind mount and re-run, or")
        print("  - if you really did remove all workspace content (e.g. every demo directory),")
        print("    re-run once with --force-prune (or SYNC_FORCE_PRUNE=true).")
        return 1

    print("\nPruning obsolete entries from etcd...")

    # Ownership: the edge relay is the sole writer of `<site>__<tool>` and
    # `<site>__<mcp>` entries and marks them `managed_by: edge-relay`. They never exist
    # on the central disk, so without this carve-out every rebuild would delete every
    # remote tool and exported MCP server. The carve-out deliberately ignores
    # --force-prune: that flag bypasses the wiped-workspace guard, never ownership.
    protected_tools = {
        tool
        for tool, config in existing_tool_configs.items()
        if config.get("managed_by") == "edge-relay"
    }
    if protected_tools:
        print(
            f"  Keeping {len(protected_tools)} edge-managed tool(s): "
            f"{', '.join(sorted(protected_tools))}"
        )

    protected_mcps = {
        mcp
        for mcp, config in existing_mcp_configs.items()
        if config.get("managed_by") == "edge-relay"
    }
    if protected_mcps:
        print(
            f"  Keeping {len(protected_mcps)} edge-managed MCP(s): "
            f"{', '.join(sorted(protected_mcps))}"
        )

    for agent in existing_agents - seen_agents:
        print(f"  Deleting obsolete agent: {agent}")
        identity_mgr.client.delete(f"/registry/agents/{agent}/config")
        identity_mgr.client.delete(f"/registry/agents/{agent}/skills")
        identity_mgr.client.delete(f"/registry/agents/{agent}/embedding")

    for tool in existing_tools - seen_tools - protected_tools:
        print(f"  Deleting obsolete tool: {tool}")
        delete_tool(identity_mgr, tool)

    prune_obsolete_mcps(identity_mgr, existing_mcps - protected_mcps, seen_mcps)

    print("\nSync complete.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
