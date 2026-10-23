#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Compose-level runner preflight: run the startup gates without uvicorn.

The runner refuses to start when one of its gates fails, which is correct but
unhelpful inside a restart loop. This CLI imports the same gate functions, so an
operator (or a compose ``healthcheck``/``depends_on`` step) can see exactly which
gate failed before the service is running. It needs the same environment as the
runner (image, runtime, ``TRELLIS_HOST_WORKSPACE``) and therefore the Docker socket.

Output: one JSON object per check, then a final ``{"ok": ...}`` line. Exit code is
0 only when every gate passed (skipped gates count as passed) and 1 otherwise.
"""

import asyncio
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.execution import runner  # noqa: E402
from core.execution.backend import get_backend  # noqa: E402


async def _checks():
    backend = get_backend()
    try:
        return await runner.full_preflight(backend)
    finally:
        try:
            await backend.close()
        except Exception:  # a failed close must not mask the check verdict
            pass


def _report(check) -> None:
    print(
        json.dumps(
            {
                "check": check.name,
                "ok": check.ok,
                "skipped": check.skipped,
                "message": check.message,
            }
        )
    )


def main() -> int:
    try:
        checks = asyncio.run(_checks())
    except Exception as exc:  # backend unavailable (no Docker socket, no daemon)
        print(json.dumps({"check": "backend", "ok": False, "skipped": False, "message": str(exc)}))
        print(json.dumps({"ok": False}))
        return 1

    for check in checks:
        _report(check)
    ok = runner.startup_ready(checks)
    print(json.dumps({"ok": ok}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
