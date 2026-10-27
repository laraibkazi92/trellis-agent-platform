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

from typing import Any, Literal, Mapping, Optional, get_args

from pydantic import BaseModel, Field, field_validator, model_validator

from core.models import normalize_network_policy

# ``tool``      one-shot tool run (stdin JSON -> stdout JSON)
# ``console``   ``bash -lc <command>`` in a scratch workspace
# ``mcp_session`` long-lived stdio MCP server, driven over /sessions/{id}
# ``discovery`` one-shot MCP discovery (same transport, torn down after)
# ``workflow``  one ``background_script`` pipeline in a sandboxed container
ExecKind = Literal["tool", "console", "mcp_session", "discovery", "workflow"]

# How a workflow's entrypoint is started inside its container. ``exec`` runs the
# file as given (a shebang script or a binary) -- the v0.7 worker's fallback for an
# unknown runtime, kept as an explicit choice instead of a silent default.
#
# This Literal is the ONE definition of the vocabulary; ``WORKFLOW_RUNTIMES`` below is
# derived from it, so the runner's argv map (``core.execution.spec``) and the worker's
# config check (``core.tasks``) import the same names instead of keeping copies that
# drift (the pre-release docs advertised python/ts/go/bash, none of which runner
# containers start).
WorkflowRuntime = Literal["python", "node", "bash", "exec"]
WORKFLOW_RUNTIMES: tuple[str, ...] = get_args(WorkflowRuntime)

# The cgroup knobs a workflow run may override. The values *not* overridden come
# from ``core.models.workflow_limits()`` -- a workflow container runs a whole
# pipeline, so its defaults are deliberately larger than a tool's.
WORKFLOW_LIMIT_KEYS = frozenset({"memory_mb", "cpus", "pids", "tmpfs_mb"})

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


class RunIdentity(BaseModel):
    """Who a run is for, as derived by whoever verified the caller's token.

    Two producers, one shape:

    * a **central** runner derives this from the verified ``agent_token`` claims --
      the request body never carries one, so a forged body cannot name another
      caller;
    * an **edge** runner (``RUNNER_ROLE=edge``) receives it from the edge proxy,
      which got it from the relay's frame. The relay is the only verifier on that
      path, and the tunnel plus the runner bearer token authenticate the sender.

    The field names mirror :class:`core.agent_token.Claims`, so runner code reads
    ``identity.agent`` / ``identity.user_id`` / ``identity.run_id`` exactly as it
    read claims before.
    """

    agent: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    groups: list[str] = Field(default_factory=list)
    run_id: Optional[str] = None
    parent_run_id: Optional[str] = None

    @classmethod
    def from_frame(
        cls, identity: Optional[Mapping[str, Any]]
    ) -> Optional["RunIdentity"]:
        """A relay call frame's identity as this model, or ``None``.

        The edge proxy holds one mapping per call (``core.proxy._frame_identity``) and
        hands it to two consumers -- the tool runtime and the MCP stdio transport -- so
        the translation lives here instead of in both. Two details matter:

        * the frame calls the caller's id ``user`` (the ``TRELLIS_USER_*`` vocabulary
          the edge env builder already reads); the model calls it ``user_id``;
        * a frame that names no agent (tokens off, or a relay older than the field) has
          no identity to carry. It is sent as ``None`` rather than padded: the edge
          runner then refuses with its own actionable message.
        """
        if not identity or not identity.get("agent"):
            return None
        return cls(
            agent=str(identity["agent"]),
            user_id=identity.get("user"),
            user_email=identity.get("user_email"),
            groups=list(identity.get("groups") or []),
            run_id=identity.get("run_id"),
            parent_run_id=identity.get("parent_run_id"),
        )


class ExecRequest(BaseModel):
    """One blocking execution: a tool call, an ``execute`` console command, or one
    ``background_script`` workflow run.

    Identity comes from the verified ``agent_token`` on a central runner (v0.7.1
    Phase 2) or from ``identity`` on an edge runner (v0.7.2 R1) -- never both: each
    role rejects the other's form, so neither deployment can be talked into trusting
    a body it does not verify itself.

    The ``workflow`` fields describe *what the pipeline is* (its directory, its
    entrypoint, the credentials it declared, its network policy and limits). They
    never describe the container: image, mounts, runtime, user and isolation are the
    runner's own derivation from its workspace view (``core.execution.spec``).
    """

    kind: ExecKind = "tool"
    # Registry name for ``tool``; literal "console" for ``console``; the workflow
    # name (its directory under ``workspace/workflows``) for ``workflow``.
    target: str
    # sha256 of the canonical manifest; the runner re-derives it from disk and
    # refuses a mismatch so a stale registration cannot run new code silently.
    # Unused for ``workflow``: a pipeline has no manifest digest, the runner checks
    # the entrypoint on disk instead.
    manifest_digest: str = ""
    # Declared keys only; the runner intersects with the manifest and rejects
    # anything it does not declare. For a workflow it rejects reserved names and
    # otherwise takes them as given: the workflow's declared set lives in the
    # caller (``core.tasks`` resolves it from the registry), not on disk.
    env: dict[str, str] = Field(default_factory=dict)
    # stdin payload: utf-8 JSON for tools, the rendered prompt/event for a
    # workflow, unused for console. The runner prefixes the environment preamble
    # line, so a workflow's stdin is (preamble, then this).
    input: str = ""
    # console only: the shell command to run.
    command: Optional[str] = None
    deadline_ms: int = 300_000
    # Short-lived HMAC token minted by the agent runtime; a **central** runner
    # verifies it and takes every identity attribute from its claims. An edge runner
    # ignores it (it holds no signing key) and uses ``identity`` instead.
    agent_token: Optional[str] = None
    # Relay-derived identity for an **edge** runner (``RUNNER_ROLE=edge``). A central
    # runner refuses a request that carries one.
    identity: Optional[RunIdentity] = None

    # --- kind="workflow" ------------------------------------------------------
    # Plain relative path inside ``workspace/workflows/<target>/``.
    entrypoint: Optional[str] = None
    # Interpreter for the entrypoint. None means ``python`` (the pre-container
    # default), so an older workflow config keeps running unchanged.
    runtime: Optional[WorkflowRuntime] = None
    # Extra argv appended after the entrypoint.
    args: list[str] = Field(default_factory=list)
    # The workflow's ``allowed_tools``: only suites of *local* tools in this list are
    # mounted, and a tool that is not listed is not on the filesystem at all. An
    # edge tool or an MCP tool has no directory here, so it mounts nothing -- a
    # workflow may still declare it (that is its token allowlist, not a mount).
    tools: list[str] = Field(default_factory=list)
    # None means ``egress`` -- the v0.7.1 default for tools, MCP sessions and
    # workflows alike. Legacy profile names are normalized (one warning each).
    network: Optional[str] = None
    # Partial cgroup overrides; a field left out keeps the workflow default from
    # ``core.models.workflow_limits()``, never a tool's 512 MiB.
    limits: Optional[dict[str, float]] = None

    @field_validator("network")
    @classmethod
    def _normalize_network(cls, value: Optional[str]) -> Optional[str]:
        """Accept the manifest vocabulary (``none``/``egress``) on the wire.

        A workflow config is a raw registry document, not a validated model, so a
        legacy ``internal``/``allow`` value must not become a 422 here: it
        normalizes to ``egress`` with the same once-per-value warning a tool
        manifest gets.
        """
        if value is None:
            return None
        return normalize_network_policy(value, "workflow")

    @field_validator("limits")
    @classmethod
    def _known_limit_keys(cls, value: Optional[dict]) -> Optional[dict]:
        """Refuse a misspelled limit instead of silently ignoring it.

        ``ContainerLimits`` ignores unknown keys, so ``memmory_mb`` would otherwise
        leave the pipeline on the default with no signal at all.
        """
        if value is None:
            return None
        unknown = sorted(str(key) for key in value if str(key) not in WORKFLOW_LIMIT_KEYS)
        if unknown:
            raise ValueError(
                f"unknown workflow limit(s): {', '.join(unknown)} "
                f"(expected {', '.join(sorted(WORKFLOW_LIMIT_KEYS))})"
            )
        return value

    @model_validator(mode="after")
    def _workflow_fields_match_the_kind(self) -> "ExecRequest":
        """Keep the two request shapes disjoint and complete.

        A workflow field on a tool/console call, or a workflow call with nothing to
        run, is a caller bug; both are louder as a 422 than as a container that
        starts and does something surprising.
        """
        workflow_only = {
            "entrypoint": self.entrypoint,
            "runtime": self.runtime,
            "args": self.args,
            "tools": self.tools,
            "network": self.network,
            "limits": self.limits,
        }
        if self.kind != "workflow":
            stray = sorted(name for name, value in workflow_only.items() if value)
            if stray:
                raise ValueError(
                    f"{', '.join(stray)} only apply to kind='workflow' "
                    f"(got kind={self.kind!r})"
                )
            return self
        if not (self.entrypoint or "").strip():
            raise ValueError("kind='workflow' requires the workflow's entrypoint")
        if self.command:
            raise ValueError(
                "kind='workflow' runs its entrypoint; `command` is console-only"
            )
        return self


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

    Like :class:`ExecRequest`, identity comes from the verified ``agent_token`` on a
    central runner and from ``identity`` on an edge runner (v0.7.2 R1): there are no
    top-level ``user_id``/``user_email``/``agent`` fields.
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
    identity: Optional[RunIdentity] = None


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
