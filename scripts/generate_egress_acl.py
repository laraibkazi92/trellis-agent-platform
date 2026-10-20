#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Generate the tool egress allowlist from ``workspace/tools/**/tool.yaml``.

Each tool entry may declare::

    egress:
      - api.example.com
      - "*.vendor.example"

Canonical form
--------------
Entries are stored as a **plain lowercase DNS suffix**: ``api.example.com``.
That suffix permits the name itself and every subdomain
(``*.api.example.com``). An input ``*.api.example.com`` is accepted and
normalized to ``api.example.com``; this is exactly the form
``scripts/egress_proxy.py`` matches against, so the generated file can be fed
to the proxy verbatim.

Rejected: schemes, paths, ports, whitespace, ``*`` anywhere but a single
leading ``*.``, bare top-level domains (no dot), IP literals, non-ASCII, labels
longer than 63 characters, and entries longer than 253 characters. Any invalid
entry is fatal -- the generator never omits one silently.

Parents are dropped: ``api.example.com`` is removed when ``example.com`` is
already present, so the output is a minimal union. An empty result writes an
empty file (the proxy then denies everything); it is never an allow-all.

Usage::

    python scripts/generate_egress_acl.py                    # union on stdout
    python scripts/generate_egress_acl.py --out /run/egress/allowlist
    python scripts/generate_egress_acl.py --check            # validate only

The union itself is printed on stdout (the audit trail when no ``--out`` is
given), and a one-line summary goes to stderr at generation time.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from typing import Iterable

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_WORKSPACE = BASE_DIR / "workspace"
MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class InvalidEntry(ValueError):
    """A declared egress domain is not a plain DNS suffix."""


def normalize_entry(raw) -> str:
    """Return the canonical plain-suffix form of one declared domain."""
    if not isinstance(raw, str):
        raise InvalidEntry(f"expected a string, got {type(raw).__name__}")

    value = raw.strip()
    if not value:
        raise InvalidEntry("empty entry")
    if "://" in value:
        raise InvalidEntry("schemes are not allowed; use a bare domain")
    if "/" in value:
        raise InvalidEntry("paths are not allowed")
    if any(character.isspace() for character in value):
        raise InvalidEntry("whitespace is not allowed")

    if value.startswith("*."):
        value = value[2:]
    if "*" in value:
        raise InvalidEntry("only a single leading '*.' wildcard is allowed")

    value = value.lower().rstrip(".")
    if not value:
        raise InvalidEntry("empty entry")
    if len(value) > MAX_DOMAIN_LENGTH:
        raise InvalidEntry(f"longer than {MAX_DOMAIN_LENGTH} characters")

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise InvalidEntry("IP literals are not allowed; use a DNS name")

    if ":" in value:
        raise InvalidEntry("ports are not allowed; the proxy fixes EGRESS_PORTS")

    labels = value.split(".")
    if len(labels) < 2:
        raise InvalidEntry("bare top-level domains are not allowed; add a dot")
    for label in labels:
        if not label:
            raise InvalidEntry("empty label")
        if len(label) > MAX_LABEL_LENGTH:
            raise InvalidEntry(f"label {label!r} is longer than {MAX_LABEL_LENGTH}")
        if not _LABEL_RE.match(label):
            raise InvalidEntry(
                f"label {label!r} must be ASCII letters, digits, or inner hyphens"
            )
    return value


def minimize(entries: Iterable[str]) -> list[str]:
    """Dedupe and drop entries already covered by a shorter parent suffix."""
    kept: list[str] = []
    for candidate in sorted(set(entries), key=lambda item: (item.count("."), len(item), item)):
        if any(candidate == parent or candidate.endswith("." + parent) for parent in kept):
            continue
        kept.append(candidate)
    return sorted(kept)


def collect(workspace: Path, errors: list[str]) -> set[str]:
    """Read every ``tool.yaml`` under ``<workspace>/tools`` and union ``egress:``."""
    tools_dir = workspace / "tools"
    entries: set[str] = set()
    if not tools_dir.is_dir():
        # An empty result is legitimate (and fail-closed); the caller warns.
        print(f"egress-acl: WARNING: {tools_dir} does not exist", file=sys.stderr)
        return entries

    for tool_yaml in sorted(tools_dir.glob("**/tool.yaml")):
        try:
            data = yaml.safe_load(tool_yaml.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{tool_yaml}: cannot read: {type(exc).__name__}: {exc}")
            continue
        if data is None:
            continue
        tool_entries = data if isinstance(data, list) else [data]
        for index, entry in enumerate(tool_entries):
            if not isinstance(entry, dict):
                errors.append(f"{tool_yaml}: entry {index} is not a mapping")
                continue
            declared = entry.get("egress")
            if declared is None:
                continue
            label = entry.get("name") or f"entry {index}"
            if not isinstance(declared, list):
                errors.append(f"{tool_yaml} [{label}]: egress must be a list of domains")
                continue
            for raw in declared:
                try:
                    entries.add(normalize_entry(raw))
                except InvalidEntry as exc:
                    errors.append(f"{tool_yaml} [{label}]: {raw!r}: {exc}")
    return entries


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate the tool egress allowlist (plain DNS suffixes, union of tool.yaml)."
    )
    parser.add_argument(
        "--workspace",
        default=str(DEFAULT_WORKSPACE),
        metavar="PATH",
        help="Workspace root containing tools/ (default: <repo>/workspace).",
    )
    parser.add_argument(
        "--out",
        default=None,
        metavar="PATH",
        help="Write the sorted allowlist here (default: stdout).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate every declared entry and exit non-zero on any error; writes nothing.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    workspace = Path(args.workspace)

    errors: list[str] = []
    entries = collect(workspace, errors)
    if errors:
        for message in errors:
            print(f"egress-acl: ERROR: {message}", file=sys.stderr)
        print(
            f"egress-acl: {len(errors)} error(s); refusing to generate an allowlist",
            file=sys.stderr,
        )
        return 1

    allowlist = minimize(entries)
    union = ", ".join(allowlist) if allowlist else "(none)"
    print(
        f"egress-acl: {len(entries)} unique domain(s) declared -> {len(allowlist)} "
        f"allowlist entr{'y' if len(allowlist) == 1 else 'ies'}: {union}",
        file=sys.stderr,
    )

    if not allowlist:
        print(
            "egress-acl: WARNING: no tool declares `egress:` domains -- writing an "
            "EMPTY allowlist, which DENIES all egress (never allow-all).",
            file=sys.stderr,
        )

    if args.check:
        print(f"egress-acl: OK ({len(allowlist)} domains)", file=sys.stderr)
        return 0

    content = "".join(f"{entry}\n" for entry in allowlist)
    if args.out:
        target = Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        print(f"egress-acl: wrote {target}", file=sys.stderr)
    else:
        sys.stdout.write(content)
    return 0


if __name__ == "__main__":
    sys.exit(main())
