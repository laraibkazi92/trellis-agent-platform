import os
import sys


import yaml
from pathlib import Path

# Add the parent directory to sys.path to import core
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth import IdentityManager
from core.embeddings import embed_text
from core.models import coerce_bool_flag, AgentRule, GlobalRule, RoutingRulesConfig

BASE_DIR = Path(__file__).parent.parent
WORKSPACE_DIR = BASE_DIR / "workspace"

AGENTS_DIR = WORKSPACE_DIR / "agents"
WORKFLOWS_DIR = WORKSPACE_DIR / "workflows"
TOOLS_DIR = WORKSPACE_DIR / "tools"


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

# Supervisor is an internal core agent
SUPERVISOR_DIR = BASE_DIR / "core" / "assets" / "supervisor"

def sync_agent(identity_mgr, agent_dir, name=None, default_type=None):
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

def main():
    identity_mgr = IdentityManager(
        host=os.getenv("ETCD_HOST", "127.0.0.1"),
        port=int(os.getenv("ETCD_PORT", 2379))
    )
    
    # 1. Fetch current items from etcd
    existing_agents = set(identity_mgr._get_all_configs_by_prefix("/registry/agents/").keys())
    existing_tools = set(identity_mgr._get_all_configs_by_prefix("/registry/tools/").keys())
    existing_mcps = set(identity_mgr._get_all_configs_by_prefix("/registry/mcps/").keys())
    
    seen_agents = set()
    seen_tools = set()
    seen_mcps = set()
    
    print("Syncing agents to etcd...")
    if AGENTS_DIR.exists():
        for agent_dir in AGENTS_DIR.iterdir():
            if not agent_dir.is_dir() or agent_dir.name == "supervisor":
                continue
            name = sync_agent(identity_mgr, agent_dir, default_type="user_agent")
            if name:
                seen_agents.add(name)
                
    print("\nSyncing workflows to etcd...")
    if WORKFLOWS_DIR.exists():
        for agent_dir in WORKFLOWS_DIR.iterdir():
            if not agent_dir.is_dir():
                continue
            name = sync_agent(identity_mgr, agent_dir, default_type="background_agent")
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
                    inputs = config.get("inputs") or {}
                    input_keys = ", ".join(
                        f"{key}:{spec.get('type', 'any')}" if isinstance(spec, dict) else str(key)
                        for key, spec in inputs.items()
                    )
                    parts = [name, config.get("description", ""), input_keys]
                    vector = embed_text("\n".join(p for p in parts if p), task_type="retrieval_document")
                    if vector:
                        identity_mgr.save_tool_embedding(name, vector)
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
                
                name = config["name"]
                identity_mgr.save_mcp_config(name, config)
                seen_mcps.add(name)
                print(f"  Saved config for MCP: {name}")

    # 2. Prune obsolete items
    print("\nPruning obsolete entries from etcd...")
    
    for agent in existing_agents - seen_agents:
        print(f"  Deleting obsolete agent: {agent}")
        identity_mgr.client.delete(f"/registry/agents/{agent}/config")
        identity_mgr.client.delete(f"/registry/agents/{agent}/skills")
        identity_mgr.client.delete(f"/registry/agents/{agent}/embedding")
        
    for tool in existing_tools - seen_tools:
        print(f"  Deleting obsolete tool: {tool}")
        identity_mgr.client.delete(f"/registry/tools/{tool}/config")
        identity_mgr.client.delete(f"/registry/tools/{tool}/embedding")
        
    for mcp in existing_mcps - seen_mcps:
        print(f"  Deleting obsolete MCP: {mcp}")
        identity_mgr.client.delete(f"/registry/mcps/{mcp}/config")

    print("\nSync complete.")

if __name__ == "__main__":
    main()
