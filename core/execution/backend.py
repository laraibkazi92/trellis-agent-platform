# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Container backend interface.

Only one implementation ships (``docker_backend``), but the runner talks to this
Protocol so the whole control plane is testable without a Docker daemon: tests
inject a fake through ``set_backend()``.

The interface is intentionally low-level (create/attach/start/kill/list) rather
than "run this image", so every hardening flag lives in ``spec.py`` and cannot be
overridden by a caller.
"""

from typing import Any, Mapping, Optional, Protocol, runtime_checkable

from dataclasses import dataclass

from core.execution.spec import ContainerSpec


@dataclass
class ExecRaw:
    """Outcome of one one-shot container run, before JSON decoding."""

    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    duration_ms: int = 0
    container_id: str = ""



class BackendError(RuntimeError):
    """A backend operation failed; ``code`` maps onto a runner error code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


@runtime_checkable
class AttachHandle(Protocol):
    """A live stdin/stdout/stderr attachment to one container."""

    async def write(self, data: bytes) -> None:
        """Send bytes to the container's stdin."""

    async def close_stdin(self) -> None:
        """Half-close stdin (EOF for the process)."""

    async def read_frame(self) -> Optional[tuple[int, bytes]]:
        """Next frame as ``(stream, payload)``; ``1``=stdout, ``2``=stderr.

        ``None`` means EOF (the container closed the stream).
        """

    async def close(self) -> None:
        """Close the attachment (the container itself is untouched)."""


@runtime_checkable
class ContainerBackend(Protocol):
    async def create(self, spec: ContainerSpec) -> str:
        """Create (not start) a container and return its id."""

    async def attach(
        self, container_id: str, *, stdin: bool = True
    ) -> AttachHandle:
        """Attach before ``start`` so no output is lost."""

    async def start(self, container_id: str) -> None: ...

    async def kill(self, container_id: str) -> None: ...

    async def remove(self, container_id: str) -> None:
        """Remove the container; never raises when it is already gone."""

    async def inspect(self, container_id: str) -> Mapping[str, Any]:
        """Docker inspect payload (at least ``State``)."""

    async def list_containers(
        self, labels: Mapping[str, str]
    ) -> list[Mapping[str, Any]]:
        """Containers (running or not) carrying every given label."""

    async def has_runtime(self, name: str) -> bool: ...

    async def has_image(self, image: str) -> bool: ...

    async def close(self) -> None: ...


_backend: Optional[ContainerBackend] = None


def get_backend() -> ContainerBackend:
    """Process-wide backend, created lazily (Docker import stays off the hot path)."""
    global _backend
    if _backend is None:
        from core.execution.docker_backend import DockerBackend

        _backend = DockerBackend()
    return _backend


def set_backend(backend: Optional[ContainerBackend]) -> None:
    """Test seam: install a fake backend, or ``None`` to restore the real one."""
    global _backend
    _backend = backend
