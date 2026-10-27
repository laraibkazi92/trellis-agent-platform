# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""In-memory container backend used by the unit tests.

No Docker daemon, no runsc. The runner's HTTP surface and the spec derivation are
what these tests pin; the backend only has to behave like a container.
"""

import asyncio
from typing import Any, Mapping, Optional

from core.execution.spec import ContainerSpec


class RawExec:
    def __init__(
        self,
        exit_code: int = 0,
        stdout: bytes = b"{}",
        stderr: bytes = b"",
        stdout_truncated: bool = False,
        stderr_truncated: bool = False,
    ) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated


class FakeAttach:
    def __init__(self, backend: "FakeBackend", container_id: str) -> None:
        self._backend = backend
        self.container_id = container_id
        self.frames: asyncio.Queue = asyncio.Queue()
        self.written = bytearray()
        self.stdin_closed = asyncio.Event()
        self.closed = False

    async def write(self, data: bytes) -> None:
        self.written.extend(data)
        self._backend.stdin.append((self.container_id, data))

    async def close_stdin(self) -> None:
        self.stdin_closed.set()

    async def read_frame(self) -> Optional[tuple[int, bytes]]:
        frame = await self.frames.get()
        return frame

    async def close(self) -> None:
        self.closed = True


class FakeHandle:
    def __init__(self, container_id: str) -> None:
        self.id = container_id
        self.state = "created"
        self.exit_code: Optional[int] = None
        self.labels: dict[str, str] = {}

    def inspect(self) -> dict:
        return {
            "Id": self.id,
            "Config": {"Labels": dict(self.labels)},
            "State": {
                "Status": self.state,
                "Running": self.state == "running",
                "ExitCode": self.exit_code or 0,
            },
        }


class FakeBackend:
    def __init__(self) -> None:
        self.specs: list[ContainerSpec] = []
        self.stdin: list[tuple[str, bytes]] = []
        self.results: list[RawExec] = []
        self.containers: dict[str, FakeHandle] = {}
        self.attaches: dict[str, FakeAttach] = {}
        self.started: list[str] = []
        self.removed: list[str] = []
        self.runtimes = {"runsc", "runc"}
        self.images = {"trellis-agent-platform:test"}
        self.fail_run: Optional[Exception] = None
        self._next = 0
        self.closed = False
        # Set to false to simulate a missing profile rule set.
        self.rules_ok = True

    # --- test helpers -------------------------------------------------------

    def queue(self, result: RawExec) -> None:
        self.results.append(result)

    def push(self, container_id: str, tag: int, data: bytes) -> None:
        self.attaches[container_id].frames.put_nowait((tag, data))

    def finish(self, container_id: str, exit_code: int = 0) -> None:
        handle = self.containers[container_id]
        handle.exit_code = exit_code
        handle.state = "exited"
        self.attaches[container_id].frames.put_nowait(None)

    # --- ContainerBackend ---------------------------------------------------

    async def run(self, spec: ContainerSpec, stdin: bytes, timeout_s: float):
        from core.execution.backend import BackendError

        self.specs.append(spec)
        self.stdin.append(("run", stdin))
        if self.fail_run is not None:
            raise self.fail_run
        if not self.results:
            raise BackendError("internal", "fake backend has no queued result")
        return self.results.pop(0)

    async def create(self, spec: ContainerSpec) -> str:
        self.specs.append(spec)
        self._next += 1
        cid = f"fake-{self._next}"
        handle = FakeHandle(cid)
        handle.labels = dict(spec.labels)
        self.containers[cid] = handle
        self.attaches[cid] = FakeAttach(self, cid)
        return cid

    async def attach(self, container_id: str, *, stdin: bool = True) -> FakeAttach:
        return self.attaches[container_id]

    async def start(self, container_id: str) -> None:
        self.started.append(container_id)
        self.containers[container_id].state = "running"

    async def kill(self, container_id: str) -> None:
        handle = self.containers.get(container_id)
        if handle is not None and handle.state == "running":
            handle.state = "exited"

    async def remove(self, container_id: str) -> None:
        self.removed.append(container_id)
        self.containers.pop(container_id, None)
        attach = self.attaches.pop(container_id, None)
        if attach is not None:
            attach.closed = True

    async def inspect(self, container_id: str) -> Mapping[str, Any]:
        return self.containers[container_id].inspect()

    async def list_containers(self, labels: Mapping[str, str]) -> list[Mapping[str, Any]]:
        """``GET /containers/json`` shape: top-level ``Labels``, no ``Config``.

        Docker's list endpoint is what the runner's reaper and ``/v1/stop`` read, and
        its label location differs from ``inspect`` (``Config.Labels``). Returning the
        inspect shape here would make a label reader that only knows the list shape
        pass in tests and find nothing in production.
        """
        out = []
        for handle in self.containers.values():
            if all(handle.labels.get(k) == v for k, v in labels.items()):
                out.append(
                    {
                        "Id": handle.id,
                        "Labels": dict(handle.labels),
                        "State": handle.state,
                    }
                )
        return out

    async def has_runtime(self, name: str) -> bool:
        return name in self.runtimes

    async def has_image(self, image: str) -> bool:
        return image in self.images

    async def close(self) -> None:
        self.closed = True
