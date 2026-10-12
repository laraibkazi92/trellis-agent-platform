#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0
"""Example background-script workflow.

Unlike a tool, a script workflow does not speak the stdin/stdout JSON protocol —
it is just a normal Python process (see docs/workflows.md). Whatever it prints
to stdout is recorded as the run output and shown under Workflows in the
dashboard.

This one prints a Markdown inventory of the workspace so a fresh install has a
visible, successful run out of the box.
"""

from pathlib import Path

# pipeline.py lives at workspace/workflows/demo-inventory/pipeline.py, so the
# workspace root is two directories up.
WORKSPACE = Path(__file__).resolve().parents[2]

SECTIONS = [
    ("Agents", "agents"),
    ("Tools", "tools"),
    ("Workflows", "workflows"),
    ("MCP servers", "mcps"),
]


def list_entries(subdir: str) -> list:
    path = WORKSPACE / subdir
    if not path.is_dir():
        return []
    return sorted(
        entry.name
        for entry in path.iterdir()
        if entry.is_dir() and not entry.name.startswith((".", "__"))
    )


def main() -> None:
    print("# Workspace inventory\n")
    print(f"Workspace root: `{WORKSPACE}`\n")
    for label, subdir in SECTIONS:
        entries = list_entries(subdir)
        print(f"## {label} ({len(entries)})")
        if entries:
            print("\n".join(f"- {name}" for name in entries))
        else:
            print("- _(none yet)_")
        print()


if __name__ == "__main__":
    main()
