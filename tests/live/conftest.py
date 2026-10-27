# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Fixtures for the live (real Docker + runsc) tests.

These tests are skipped unless they run next to a real runner: they need the
runner's Unix socket and the workspace it serves, both of which are mounted into
the app image. The CI job that runs them is described in the plan's §7
(``docker-compose.ci-isolation.yml``); on a deployment they are usually run as::

    docker compose run --rm --entrypoint sh hub -c \
      "pip install -q pytest && python -m pytest tests/live -m runsc"

Every test installs its own tool suite and agent manifest in the workspace and
removes them again, so a live deployment's registry is not polluted.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import uuid
from pathlib import Path

import pytest

WORKSPACE = Path(os.environ.get("WORKSPACE_ROOT", "/app/workspace"))
SOCKET = os.environ.get("RUNNER_SOCKET", "/run/trellis/runner.sock")
FIXTURES = Path(__file__).parent / "fixtures"
AGENT = "zz-live-probe"

AGENT_CONFIG = f"""\
name: {AGENT}
version: 0.1.0
author: live-test@example.com
description: "Installed by tests/live to own the probe tool containers; removed afterwards."
model: deepseek-chat
provider: deepseek
thinking_level: none
external: true
internal: true
allowed_tools: []
allowed_mcps: []
"""

AGENT_SKILLS = "Live-test fixture. Never registered outside a live test run.\n"

SUITE_MANIFEST = """\
- name: probe_none
  version: 0.1.0
  author: live-test@example.com
  description: "Live probe: reports filesystem, identity, env and network visibility."
  runtime: python
  entrypoint: probe.py
  rel_path: tools/{suite}
  network: none
  output_dirs: [output]
  timeout_seconds: 60

- name: probe_egress
  version: 0.1.0
  author: live-test@example.com
  description: "Live probe with ordinary Docker egress (the default bridge)."
  runtime: python
  entrypoint: probe.py
  rel_path: tools/{suite}
  network: egress
  timeout_seconds: 60

- name: probe_limits
  version: 0.1.0
  author: live-test@example.com
  description: "Allocates past a 64 MB cgroup limit."
  runtime: python
  entrypoint: memhog.py
  rel_path: tools/{suite}
  network: none
  timeout_seconds: 60
  limits:
    memory_mb: 64
    cpus: 0.5
    pids: 64
    tmpfs_mb: 16

- name: probe_sleep
  version: 0.1.0
  author: live-test@example.com
  description: "Sleeps, so a concurrent call spans another container's OOM kill."
  runtime: python
  entrypoint: sleep.py
  rel_path: tools/{suite}
  network: none
  timeout_seconds: 60

- name: probe_echo
  version: 0.1.0
  author: live-test@example.com
  description: "Echoes its stdin object plus a few facts about its environment."
  runtime: python
  entrypoint: echo.py
  rel_path: tools/{suite}
  network: none
  timeout_seconds: 60
  variables:
    - PROBE_MARKER
"""


class Live:
    """Resolver + token for one test session against a real runner."""

    def __init__(self, suite: str, agent: str, token: str, uid: int, gid: int) -> None:
        self.suite = suite
        self.agent = agent
        self.token = token
        # The workspace owner: the uid/gid every tool container must run as.
        self.uid = uid
        self.gid = gid

    def request(self, name: str, payload: dict, *, deadline_ms: int = 60_000, env: dict | None = None):
        from core.execution import runner as runner_module
        from core.execution.contract import ExecRequest
        from core.execution.spec import manifest_digest

        target = runner_module.resolve_target(name)
        assert target is not None, f"runner cannot resolve {name!r}"
        return ExecRequest(
            kind="tool",
            target=name,
            manifest_digest=manifest_digest(target.config),
            # Identity is the token's claims (v0.7.1 Phase 2): no body fields.
            agent_token=self.token,
            env=env or {},
            input=json.dumps(payload),
            deadline_ms=deadline_ms,
        )

    def call(self, name: str, payload: dict | None = None, *, deadline_ms: int = 60_000, env: dict | None = None):
        return asyncio.run(self.acall(name, payload, deadline_ms=deadline_ms, env=env))

    async def acall(self, name: str, payload: dict | None = None, *, deadline_ms: int = 60_000, env: dict | None = None):
        from core.execution.client import RunnerClient

        async with RunnerClient() as client:
            return await client.exec(
                self.request(name, payload or {}, deadline_ms=deadline_ms, env=env)
            )


def _require_runner() -> None:
    if not Path(SOCKET).exists():
        pytest.skip(f"no runner socket at {SOCKET}; live tests need a running runner")
    if not (WORKSPACE / "tools").is_dir():
        pytest.skip(f"{WORKSPACE}/tools is missing; run these inside the app image")


@pytest.fixture(scope="session")
def live() -> Live:
    _require_runner()
    from core import agent_token

    os.environ.setdefault("WORKSPACE_ROOT", str(WORKSPACE))
    suite = f"zz-live-{uuid.uuid4().hex[:8]}"
    tools = WORKSPACE / "tools" / suite
    agent_dir = WORKSPACE / "agents" / AGENT

    tools.mkdir(parents=True)
    for name in ("probe.py", "memhog.py", "sleep.py", "echo.py"):
        shutil.copyfile(FIXTURES / name, tools / name)
        os.chmod(tools / name, 0o755)
    (tools / "tool.yaml").write_text(SUITE_MANIFEST.format(suite=suite), encoding="utf-8")
    os.chmod(tools, 0o777)

    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "config.yaml").write_text(AGENT_CONFIG, encoding="utf-8")
    (agent_dir / "skills.md").write_text(AGENT_SKILLS, encoding="utf-8")

    try:
        token = agent_token.mint(AGENT, user_id="live-probe")
    except agent_token.AgentTokenError as exc:
        shutil.rmtree(tools, ignore_errors=True)
        shutil.rmtree(agent_dir, ignore_errors=True)
        pytest.skip(f"cannot mint an agent token ({exc.code}): set AGENT_TOKEN_SECRET")

    owner = WORKSPACE.stat()
    yield Live(suite, AGENT, token, owner.st_uid, owner.st_gid)

    shutil.rmtree(tools, ignore_errors=True)
    shutil.rmtree(agent_dir, ignore_errors=True)
