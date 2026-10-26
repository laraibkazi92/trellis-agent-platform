#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Operational script to prune bloated run history in etcd.

Usage:
  python scripts/prune_etcd_runs.py --agent ticket-triage --keep 50
  python scripts/prune_etcd_runs.py --all --keep 50
  python scripts/prune_etcd_runs.py --all --dry-run
"""

import os
import sys
import json
import argparse
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth import IdentityManager


def prune_agent(identity_mgr: IdentityManager, agent_name: str, keep: int, dry_run: bool = False):
    print(f"\n--- Checking run records for '{agent_name}' ---")
    prefix = f"/runs/{agent_name}/"
    client = identity_mgr.client
    
    records = []
    total_bytes = 0
    
    try:
        for value, metadata in client.get_prefix(prefix):
            key_str = metadata.key.decode("utf-8")
            # A run record is exactly /runs/{agent}/{run_id}; events and the
            # heartbeat live deeper and must never be counted or deleted as records.
            if "/" in key_str[len(prefix):]:
                continue
            val_len = len(value) if value else 0
            total_bytes += val_len
            ts = ""
            if value:
                try:
                    parsed = json.loads(value.decode("utf-8"))
                    ts = parsed.get("updated_at", parsed.get("timestamp", ""))
                except Exception:
                    pass
            records.append((key_str, ts, val_len))
    except Exception as e:
        print(f"Error fetching prefix {prefix}: {e}")
        return

    record_count = len(records)
    mb_size = total_bytes / (1024 * 1024)
    print(f"Found {record_count} records ({mb_size:.2f} MB total).")

    if record_count <= keep:
        print(f"No pruning needed (count {record_count} <= keep limit {keep}).")
        return

    # Sort newest first
    records.sort(key=lambda x: x[1], reverse=True)
    to_delete = records[keep:]

    delete_bytes = sum(r[2] for r in to_delete)
    delete_mb = delete_bytes / (1024 * 1024)
    print(f"Identified {len(to_delete)} records to prune ({delete_mb:.2f} MB).")

    if dry_run:
        print("[DRY-RUN] Skipping deletion.")
        return

    deleted = 0
    for key_str, _, _ in to_delete:
        try:
            client.delete(key_str)
            # Trailing slash: a bare prefix delete would also hit sibling runs
            # whose id starts with this one's.
            client.delete_prefix(f"{key_str}/")
            deleted += 1
        except Exception as err:
            print(f"Failed to delete {key_str}: {err}")

    print(f"Successfully pruned {deleted} records from '{agent_name}'.")


def main():
    parser = argparse.ArgumentParser(description="Prune etcd workflow run history")
    parser.add_argument("--agent", type=str, help="Specific agent name to prune")
    parser.add_argument("--all", action="store_true", help="Prune all agents/workflows")
    parser.add_argument("--keep", type=int, default=50, help="Number of latest runs to retain per agent (default: 50)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate pruning without deleting keys")
    args = parser.parse_args()

    if not args.agent and not args.all:
        parser.error("Must specify either --agent <name> or --all")

    host = os.getenv("ETCD_HOST", "127.0.0.1")
    port = int(os.getenv("ETCD_PORT", "2379"))
    identity_mgr = IdentityManager(host=host, port=port)

    if args.agent:
        prune_agent(identity_mgr, args.agent, args.keep, args.dry_run)
    elif args.all:
        agent_names = set(identity_mgr.list_agents())
        # Also discover any orphaned or legacy run prefixes under /runs/
        try:
            for _, metadata in identity_mgr.client.get_prefix("/runs/"):
                key_str = metadata.key.decode("utf-8")
                parts = key_str.strip("/").split("/")
                if len(parts) >= 2 and parts[0] == "runs":
                    agent_names.add(parts[1])
        except Exception as e:
            print(f"Warning: Could not scan /runs/ prefix for orphaned workflows: {e}")

        sorted_names = sorted(agent_names)
        print(f"Found {len(sorted_names)} workflow/agent targets to check.")
        for name in sorted_names:
            prune_agent(identity_mgr, name, args.keep, args.dry_run)


if __name__ == "__main__":
    main()
