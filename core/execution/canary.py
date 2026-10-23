# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Host-path canary: prove the workspace bind mount points where we think it does.

``TRELLIS_HOST_WORKSPACE`` is a *host* path handed to the Docker daemon, while the
runner itself reads the same directory through its own container mount. If the two
disagree, every tool silently runs against the wrong files -- the kind of mistake
that only shows up as "the tool sees an empty suite". The runner therefore writes a
random marker, asks a throwaway container to read it back through the host path, and
refuses new calls when the bytes do not match.

Cheap on purpose: one file, one container, no workspace content is ever read.
"""

import logging
import os
import secrets
from dataclasses import dataclass
from typing import Optional

from core.execution.backend import ContainerBackend
from core.execution.spec import ContainerSpec, Mount

logger = logging.getLogger(__name__)

CANARY_TIMEOUT_S = 30.0


@dataclass(frozen=True)
class CanaryResult:
    ok: bool
    detail: str = ""


_last_result: Optional[CanaryResult] = None


def last_result() -> Optional[CanaryResult]:
    return _last_result


def _remediation(detail: str, host_workspace: str, container_workspace: str) -> str:
    return (
        f"{detail}. TRELLIS_HOST_WORKSPACE={host_workspace!r} must be the HOST path of the "
        f"workspace (the directory that is mounted at {container_workspace} inside the runner); "
        f"pointing it at a container path makes every bind mount resolve to the wrong files."
    )


def _spec(name: str, *, image: str, runtime: str, host_workspace: str,
          container_workspace: str) -> ContainerSpec:
    return ContainerSpec(
        image=image,
        runtime=runtime,
        cmd=["sh", "-c", f"cat /canary/{name}"],
        working_dir=container_workspace,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp"},
        mounts=[Mount(host_workspace, "/canary", True)],
        tmpfs={},
        memory_mb=128,
        cpus=0.5,
        pids=64,
        network_mode="none",
        labels={
            "trellis.install": os.getenv("TRELLIS_INSTALL_ID", "default"),
            "trellis.kind": "canary",
        },
        kind="canary",
    )


async def _probe(
    backend: ContainerBackend,
    *,
    path: str,
    name: str,
    payload: bytes,
    image: str,
    runtime: str,
    host_workspace: str,
    container_workspace: str,
) -> CanaryResult:
    try:
        with open(path, "wb") as handle:
            handle.write(payload)
    except OSError as exc:
        return CanaryResult(
            False,
            _remediation(
                f"cannot write the canary file into the workspace: {exc}",
                host_workspace,
                container_workspace,
            ),
        )

    container_spec = _spec(
        name,
        image=image,
        runtime=runtime,
        host_workspace=host_workspace,
        container_workspace=container_workspace,
    )
    try:
        raw = await backend.run(container_spec, b"", CANARY_TIMEOUT_S)
    except Exception as exc:  # a backend failure is a failed canary, not a crash
        logger.error("host-path canary container failed: %s", exc)
        return CanaryResult(
            False,
            _remediation(
                f"the canary container did not run: {exc}",
                host_workspace,
                container_workspace,
            ),
        )

    if raw.exit_code == 0 and raw.stdout == payload:
        return CanaryResult(
            True, f"container read {len(payload)} canary bytes back through the host path"
        )
    return CanaryResult(
        False,
        _remediation(
            f"the canary container read {len(raw.stdout)} of {len(payload)} expected "
            f"bytes (exit {raw.exit_code})",
            host_workspace,
            container_workspace,
        ),
    )


async def run(
    backend: ContainerBackend,
    *,
    host_workspace: str,
    image: str,
    runtime: str,
    workspace_root: Optional[str] = None,
    container_workspace: str = "/app/workspace",
) -> CanaryResult:
    """Write a marker through the runner's view, read it back through the host path.

    ``workspace_root`` is where the RUNNER writes the marker (its own mount);
    ``host_workspace`` is what the throwaway container binds. They are different
    paths in every real deployment; conflating them is exactly the bug this check
    exists to catch.
    """
    global _last_result

    name = f".runner-canary-{secrets.token_hex(4)}"
    path = os.path.join(workspace_root or host_workspace, name)
    payload = secrets.token_bytes(32)
    try:
        result = await _probe(
            backend,
            path=path,
            name=name,
            payload=payload,
            image=image,
            runtime=runtime,
            host_workspace=host_workspace,
            container_workspace=container_workspace,
        )
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    _last_result = result
    return result


def reset_for_tests() -> None:
    global _last_result
    _last_result = None
