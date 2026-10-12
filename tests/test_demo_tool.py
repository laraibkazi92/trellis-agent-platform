# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Smoke tests for the shipped example tool (workspace/tools/demo).

The demo tool is documentation users copy, so it has to keep working. These
tests run the entrypoint the same way the Hub does — JSON on stdin, JSON on
stdout — and validate its tool.yaml against the real ToolConfig model, so the
example can't silently drift from the schema.
"""

import json
import subprocess
import sys
from pathlib import Path

import yaml

from core.models import ToolConfig

TOOL_DIR = Path(__file__).resolve().parents[1] / "workspace" / "tools" / "demo"
ENTRYPOINT = TOOL_DIR / "text_stats.py"


def run_tool(payload: dict) -> dict:
    proc = subprocess.run(
        [sys.executable, str(ENTRYPOINT)],
        input=json.dumps(payload).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout.decode())


def test_tool_yaml_matches_schema():
    data = yaml.safe_load((TOOL_DIR / "tool.yaml").read_text())
    configs = data if isinstance(data, list) else [data]
    config = ToolConfig(**configs[0])

    assert config.name == "text_stats"
    assert config.runtime == "python"
    assert config.entrypoint == "text_stats.py"
    assert (TOOL_DIR / config.entrypoint).is_file()


def test_text_stats_counts():
    text = "the cat and the dog\nsat"
    result = run_tool({"text": text})

    assert result["characters"] == len(text)
    assert result["words"] == 6
    assert result["lines"] == 2
    assert result["top_words"][0] == {"word": "the", "count": 2}


def test_text_stats_respects_top_n():
    result = run_tool({"text": "a b b c c c", "top_n": 2})

    assert result["top_words"] == [{"word": "c", "count": 3}, {"word": "b", "count": 2}]


def test_text_stats_missing_text_returns_error():
    assert "error" in run_tool({})
