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

from core.execution import env
from core.execution.backend import ContainerBackend
from core.execution.spec import ContainerSpec, InvalidRequest, Mount, _require_user

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


# Bounded so a chatty container cannot turn a one-line diagnostic into a wall of
# text; the canary's own stderr is a `sh` error, never tool output.
_STDERR_EXCERPT_BYTES = 240


def _stderr_excerpt(stderr: bytes) -> str:
    """``(stderr: ...)`` for a diagnostic, or ``''`` when there is nothing to add."""
    text = (stderr or b"")[:_STDERR_EXCERPT_BYTES].decode("utf-8", "replace").strip()
    if not text:
        return ""
    return f" (stderr: {' '.join(text.split())})"


def _shim_missing_detail(image: str, evidence: str = "") -> str:
    """The failure that is NOT a workspace problem: an image without the shim.

    Every container now starts through ``/usr/local/bin/trellis-exec``, so a runner
    image older than v0.7.1 fails to start anything at all (exit 126/127, or a
    docker ``exec: "/usr/local/bin/trellis-exec": stat ...: no such file`` error on
    start). Reporting that as a ``TRELLIS_HOST_WORKSPACE`` mistake sends the
    operator after the wrong thing entirely, so it gets its own detail.
    """
    return (
        f"the runner image has no {env.EXEC_SHIM} — RUNNER_IMAGE must be built from "
        f"v0.7.1 or newer (image {image!r} cannot start any tool container: this "
        f"release runs every command through that shim){evidence}"
    )


def _looks_like_missing_shim(exit_code: Optional[int], text: str) -> bool:
    """True when a failed probe points at the shim rather than at the mounts.

    126/127 from this canary cannot be the read command going missing (it is plain
    ``sh -c cat``), so it is the entrypoint that failed. Docker more often fails
    *start* instead, whose message names the missing path.
    """
    if exit_code in (126, 127):
        return True
    return "trellis-exec" in (text or "").lower()


def _spec(name: str, *, image: str, runtime: str, host_workspace: str,
          container_workspace: str) -> ContainerSpec:
    # The canary runs as the SAME non-root identity every tool container runs as
    # (``spec._require_user()``, the one place that identity is resolved). Leaving
    # ``user`` unset made it the only container in the system started as the image
    # default -- root in the engine image -- so it proved the mount works while
    # proving nothing about the boundary the mounts exist to enforce. It also means
    # a passing canary now covers "the tool user can traverse and read the
    # workspace", which is what every real tool needs anyway.
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
        user=_require_user(),
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

    try:
        container_spec = _spec(
            name,
            image=image,
            runtime=runtime,
            host_workspace=host_workspace,
            container_workspace=container_workspace,
        )
    except InvalidRequest as exc:
        # A canary that cannot resolve the tool identity is a FAILED CHECK, not a
        # traceback: it runs from the startup preflight, from the SIGHUP handler and
        # from the periodic re-check, and none of those may die on a misconfigured
        # environment. The identity gate's own wording is passed through, so the
        # operator sees the same instruction here as from
        # ``runner._check_tool_identity``. (``run`` still unlinks the marker in its
        # ``finally``, so this early return leaves nothing behind.)
        logger.error("host-path canary cannot resolve the tool identity: %s", exc)
        return CanaryResult(
            False, f"the canary container cannot run as the tool user: {exc}"
        )
    try:
        raw = await backend.run(
            container_spec,
            # Every container starts through the trellis-exec shim, so the canary
            # sends the (empty) preamble line too: no env needs applying here.
            env.with_preamble(container_spec.preamble_env, b""),
            CANARY_TIMEOUT_S,
        )
    except Exception as exc:  # a backend failure is a failed canary, not a crash
        logger.error("host-path canary container failed: %s", exc)
        if _looks_like_missing_shim(None, str(exc)):
            return CanaryResult(False, _shim_missing_detail(image))
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
    stderr_text = (raw.stderr or b"").decode("utf-8", "replace")
    if _looks_like_missing_shim(raw.exit_code, stderr_text):
        return CanaryResult(
            False,
            _shim_missing_detail(
                image,
                _stderr_excerpt(raw.stderr) or f" (exit {raw.exit_code})",
            ),
        )
    return CanaryResult(
        False,
        _remediation(
            f"the canary container read {len(raw.stdout)} of {len(payload)} expected "
            f"bytes (exit {raw.exit_code}){_stderr_excerpt(raw.stderr)}",
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
