#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0
"""Example tool: text statistics.

Implements the Trellis tool protocol (see docs/tools.md): read one JSON object
from stdin, write one JSON object to stdout, and keep anything else on stderr.
Standard library only — no secrets, no third-party packages, no network.
"""

import json
import re
import sys
from collections import Counter

_WORD_RE = re.compile(r"[A-Za-z0-9']+")


def top_words(text: str, top_n: int) -> list:
    counts = Counter(_WORD_RE.findall(text.lower()))
    return [{"word": word, "count": count} for word, count in counts.most_common(top_n)]


def build_result(args: dict) -> dict:
    text = args.get("text")
    if not isinstance(text, str):
        return {"error": "input 'text' is required and must be a string"}

    try:
        top_n = int(args.get("top_n", 5))
    except (TypeError, ValueError):
        top_n = 5

    return {
        "characters": len(text),
        "words": len(text.split()),
        "lines": len(text.splitlines()),
        "top_words": top_words(text, max(0, top_n)),
    }


def main() -> None:
    json.dump(build_result(json.load(sys.stdin)), sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 — keep the contract: JSON on stdout, detail on stderr
        print(f"text_stats failed: {exc}", file=sys.stderr)
        json.dump({"error": str(exc)}, sys.stdout)
