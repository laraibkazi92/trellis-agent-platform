"""A stateful FastMCP stdio server for the edge session tests.

State lives in ``$HOME/state.json``, so a test can assert per-session isolation on
disk; ``$HOME/pid`` records the server process, so a test can assert a retired
session actually terminated it. Kept dependency-light on purpose: fastmcp is the
only import.
"""

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

mcp = FastMCP("stateful")


def _home() -> Path:
    home = Path(os.environ.get("HOME") or ".")
    home.mkdir(parents=True, exist_ok=True)
    return home


def _state_path() -> Path:
    return _home() / "state.json"


def _load() -> dict:
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    _state_path().write_text(json.dumps(data), encoding="utf-8")


@mcp.tool
def set_value(key: str, value: Any) -> str:
    """Store a raw JSON value under key; the schema is deliberately permissive."""
    data = _load()
    data[key] = value
    _save(data)
    return "ok"


@mcp.tool
def get_value(key: str) -> Any:
    """Read key back from this session's HOME."""
    return _load().get(key)


@mcp.tool
def get_home() -> str:
    """The HOME this server process sees: one per (mcp, user) session."""
    return str(_state_path().parent)


@mcp.tool
def env_dump() -> dict:
    """The environment this server process actually received."""
    return dict(os.environ)


@mcp.tool
async def slow(seconds: float = 5.0) -> str:
    """Sleep, counting the invocation first: an edge timeout must not replay it."""
    data = _load()
    data["slow_calls"] = data.get("slow_calls", 0) + 1
    _save(data)
    await asyncio.sleep(seconds)
    return "done"


# Written at startup, before the first request: the test needs a pid to watch.
(_home() / "pid").write_text(str(os.getpid()), encoding="utf-8")

if __name__ == "__main__":
    mcp.run(transport="stdio")
