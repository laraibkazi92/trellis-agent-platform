# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Direct workspace-file persistence for registry edits.

The ``workspace/`` directory is bind-mounted read-write into every service (see
docker-compose.yml), and ``scripts/sync_to_db.py`` reconciles etcd from those files on
every ``docker compose up``. So whenever the UI (admin editor, workflow editor,
marketplace) changes a config, it must ALSO write the matching file here -- otherwise
the next rebuild re-applies the old file over the etcd change, or prunes an entity that
exists only in etcd. The same applies to the tool-access group rules in
``workspace/policies/tool_access.yaml`` (see :func:`write_tool_access_policy`).

This replaces the old GitHub-API write-back (``commit_to_github``): a local write needs
no token, applies immediately, and leaves version control to the operator (the workspace
is usually a normal git checkout they can commit whenever they like).

Writes are fail-soft: a read-only or misconfigured mount must not break a save that
already succeeded against etcd -- callers get ``False`` and surface a warning.
"""
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Repo root: core/ -> parent. Matches scripts/sync_to_db.py's BASE_DIR so both agree on
# where workspace/ lives (in-container this resolves to /app).
BASE_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = BASE_DIR / "workspace"


def _resolve(rel_path: str) -> Optional[Path]:
    """Resolve a repo-root-relative path, refusing anything that escapes BASE_DIR."""
    candidate = (BASE_DIR / rel_path).resolve()
    if not candidate.is_relative_to(BASE_DIR):
        return None
    return candidate


def write_repo_file(rel_path: str, content: str) -> bool:
    """Atomically write text to a repo-root-relative path, creating parent dirs.

    Returns False (and logs) when the path escapes the repo root or the write fails,
    e.g. on a read-only mount -- the caller's etcd change still stands.
    """
    target = _resolve(rel_path)
    if target is None:
        logger.error("Refusing to write outside the repo root: %s", rel_path)
        return False

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename so the registry sync never reads a half-written file.
        tmp = target.with_name(f".{target.name}.tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, target)
        return True
    except OSError as e:
        logger.warning("Could not write workspace file %s: %s", rel_path, e)
        return False


def delete_repo_path(rel_path: str) -> bool:
    """Delete a repo-root-relative file, then prune any parent dirs left empty.

    Removing the config file is enough for the registry sync to stop re-adding an
    entity; pruning the dirs it emptied keeps the tree tidy without touching sibling
    assets (bundles, node_modules). Never removes BASE_DIR or workspace/ themselves.
    """
    target = _resolve(rel_path)
    if target is None:
        logger.error("Refusing to delete outside the repo root: %s", rel_path)
        return False

    try:
        if target.exists():
            target.unlink()

        parent = target.parent
        while parent not in (BASE_DIR, WORKSPACE_DIR) and parent.is_dir():
            try:
                parent.rmdir()  # only succeeds when empty
            except OSError:
                break
            parent = parent.parent
        return True
    except OSError as e:
        logger.warning("Could not delete workspace file %s: %s", rel_path, e)
        return False


# --- tool-access policy ------------------------------------------------------ #

TOOL_ACCESS_POLICY_REL = "workspace/policies/tool_access.yaml"


def write_tool_access_policy(text: str) -> bool:
    """Dual-write the tool-access group-rule file (``workspace/policies/``).

    ``core.tool_access`` reads the *etcd* copy at runtime, so a writer must update the
    registry first and the file second: the next rebuild's sync re-applies the file
    over etcd, and a file left behind silently reverts the change. The v0.7.1 admin
    page is read-only, so nothing calls this yet -- it is the write half an editor (or
    a CLI) needs, and it shares the fail-soft contract of :func:`write_repo_file`.
    """
    return write_repo_file(TOOL_ACCESS_POLICY_REL, text)
