# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Wire contract between the runner client and the runner service.

Shared by both sides on purpose: the client (hub, edge proxy) and the server
(``core.execution.runner``) import these models, so a field cannot mean different
things on the two ends of the socket.

Callers describe *what* to run (a registered target) and the bytes for its stdin.
They never describe an image, mount, capability, runtime or network: the runner
derives all of that from the manifest on disk (``core.execution.spec``).
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field

# ``tool``      one-shot tool run (stdin JSON -> stdout JSON)
# ``console``   ``bash -lc <command>`` in a scratch workspace
# ``mcp_session`` long-lived stdio MCP server, driven over /sessions/{id}
# ``discovery`` one-shot MCP discovery (same transport, torn down after)
ExecKind = Literal["tool", "console", "mcp_session", "discovery"]

RunnerErrorCode = Literal[
    "capacity_exhausted",
    "unknown_target",
    "manifest_stale",
    "invalid_request",
    "runtime_missing",
    "image_missing",
    "daemon_unavailable",
    "runner_path_mismatch",
    "session_not_found",
    "session_streaming",
    "mcp_session_lost",
    "timeout",
    "internal",
]


class ExecRequest(BaseModel):
    """One blocking execution: a tool call or an ``execute`` console command.

    Carries NO identity fields: the caller's user id, email, groups, agent name and
    run id all come from the verified ``agent_token`` (v0.7.1 Phase 2). The runner
    derives them itself, so a forged body cannot name another caller.
    """

    kind: ExecKind = "tool"
    # Registry name for ``tool``; literal "console" for ``console``.
    target: str
    # sha256 of the canonical manifest; the runner re-derives it from disk and
    # refuses a mismatch so a stale registration cannot run new code silently.
    manifest_digest: str = ""
    # Declared keys only; the runner intersects with the manifest and rejects
    # anything it does not declare.
    env: dict[str, str] = Field(default_factory=dict)
    # stdin payload (utf-8 JSON for tools, unused for console).
    input: str = ""
    # console only: the shell command to run.
    command: Optional[str] = None
    deadline_ms: int = 300_000
    # Short-lived HMAC token minted by the agent runtime; the runner verifies it and
    # takes every identity attribute from its claims.
    agent_token: Optional[str] = None


class ExecResult(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    duration_ms: int = 0
    container_id: str = ""


class RunnerError(BaseModel):
    code: RunnerErrorCode
    message: str
    retryable: bool = False


class SessionCreateRequest(BaseModel):
    """Open a long-lived MCP session (or a throwaway discovery run).

    Like :class:`ExecRequest`, identity comes only from the verified
    ``agent_token``: there are no ``user_id``/``user_email``/``agent`` fields.
    """

    kind: Literal["mcp_session", "discovery"] = "mcp_session"
    target: str
    manifest_digest: str = ""
    # 32 hex chars, chosen by the caller; stamped on the container label so a
    # leaked container can be traced back to a client-side session.
    session_key: str = Field(pattern=r"^[0-9a-f]{32}$")
    env: dict[str, str] = Field(default_factory=dict)
    deadline_ms: int = 900_000
    agent_token: Optional[str] = None


class SessionInfo(BaseModel):
    session_id: str
    container_id: str = ""
    created_at: float = 0.0
    state: str = "running"
    exit_code: Optional[int] = None
    bytes_out: int = 0
    idle_s: float = 0.0


class HealthInfo(BaseModel):
    ok: bool
    runtime: str = ""
    image: str = ""
    install_id: str = "default"
    active_sessions: int = 0
    detail: str = ""
