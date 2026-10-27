#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0
"""Example background-script workflow.

Unlike a tool, a script workflow does not speak the stdin/stdout JSON protocol —
it is just a normal Python process (see docs/workflows.md). Whatever it prints
to stdout is recorded as the run output and shown under Workflows in the
dashboard.

Since v0.7.1 the pipeline runs inside ONE sandboxed `runner` container per run, so
it can only see the paths that container mounts: its own workflow directory,
`shared/`, the tool suites its `allowed_tools` names, `output/<name>/` and
`reports/<name>/`. This sample prints what is actually visible there — the honest
version of a workspace inventory from inside the container.
"""

import os
from pathlib import Path

# pipeline.py lives at /app/workspace/workflows/demo-inventory/pipeline.py, so the
# workspace root is two directories up (inside the container, that is /app/workspace).
WORKSPACE = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = Path(__file__).resolve().parent
WORKFLOW_NAME = WORKFLOW_DIR.name

# What a workflow container may see, and what is deliberately absent.
VISIBLE = [
    ("Workflow directory (read-only)", f"workflows/{WORKFLOW_NAME}"),
    ("Shared code (read-only)", "shared"),
    ("Declared tool suites (read-only)", "tools"),
    ("Reports (read-write)", f"reports/{WORKFLOW_NAME}"),
    ("Output (read-write)", f"output/{WORKFLOW_NAME}"),
]
ABSENT = ("agents", "mcps", "policies")


def list_entries(path: Path) -> list:
    if not path.is_dir():
        return []
    return sorted(
        entry.name
        for entry in path.iterdir()
        if not entry.name.startswith((".", "__"))
    )


def main() -> None:
    print(f"# Workflow inventory: {WORKFLOW_NAME}\n")
    print(f"Workspace root inside the container: `{WORKSPACE}`\n")
    for label, subdir in VISIBLE:
        entries = list_entries(WORKSPACE / subdir)
        print(f"## {label} ({len(entries)})")
        print(f"`/app/workspace/{subdir}`")
        if entries:
            print("\n".join(f"- {name}" for name in entries))
        else:
            print("- _(empty)_")
        print()

    print("## Not visible")
    print(
        "This container has no `agents/`, `mcps/`, `policies/` or other workflow's "
        "tree — a declared `allowed_tools` list is the only thing that puts a tool "
        "suite on the filesystem.\n"
    )

    names = sorted(os.environ)
    identity = [name for name in names if name.startswith("TRELLIS_")]
    print(f"## Environment ({len(names)} names)")
    print("Identity/run: " + (", ".join(f"`{name}`" for name in identity) or "- _(none)_"))
    print(
        f"Plus {len(names) - len(identity)} more: the process basics and the secrets/"
        "variables this workflow declared. Values are never printed, and nothing is "
        "inherited from the taskiq worker."
    )


if __name__ == "__main__":
    main()
