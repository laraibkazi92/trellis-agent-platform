# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge-side MCP export: ``mcp.yaml`` loading, catalog building, per-user sessions.

An edge publishes the MCP servers it exports and executes their ``tools/call``
locally, one long-lived session per ``(mcp, user identity)`` -- the mirror of
central's ``get_external_mcp_client(mcp_name, user_id)``, except the state stays on
the edge. Sessions are owned by :class:`McpSessionManager`, not by the tunnel
socket, so a reconnect re-publishes the catalog without losing state.

Enforcement is edge-local (plan §2.3): the published catalog is the name authority,
``exclude_tools`` refuses even a name that is listed, and no MCP call is ever
replayed -- a dead session is reported in that call's result and respawned on the
next one.

Credentials come from edge-local files (``core.edge_user_secrets``) through the
export's ``credential_mode``. They are resolved **once, at session creation**: editing
a file does not touch a live session (its env/HOME are already fixed), so the new value
arrives with the next session -- after TTL expiry, eviction, a **SIGHUP** (which retires
every live session and reopens it on the next call), or a restart. ``per_user_required``
with no file for the caller fails closed (``missing_credentials``) before any process is
spawned, and a declared key the file does not define is never taken from the process
environment.

Edge-only by design, like ``core.edge_env``: no etcd, no FastAPI, no
``core.discovery``. The only shared contracts are ``core.models.MCPConfig`` and
``services.edge_relay.protocol``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

import yaml

from core import edge_env, edge_user_secrets, sandbox
from core.models import MCPConfig
from core.tool_runtime import MAX_RESULT_CHARS
from services.edge_relay import protocol

logger = logging.getLogger(__name__)

MAX_SESSIONS_PER_MCP = 8
MAX_SESSIONS_EDGE = 32
DEFAULT_SESSION_TTL_MINUTES = 30
DISCOVERY_TIMEOUT_S = 20
# One-shot "your session died" markers are kept bounded: a long-lived edge with
# many users would otherwise grow the set without limit. FIFO eviction only drops
# the oldest marker, and a marker still fires exactly once.
MAX_SESSION_TOMBS = 1024
# JSON-RPC code the MCP SDK raises when its own read timeout expires
# (``Request 'tools/call' timed out``). A deadline expiry is not a crash: the
# session must stay usable, and the call must not be replayed.
MCP_REQUEST_TIMEOUT_CODE = -32001

_CREDENTIAL_MODES = edge_user_secrets.CREDENTIAL_MODES
_EXPORT_KEYS = frozenset(
    {"name", "include_tools", "exclude_tools", "credential_mode", "session_ttl_minutes", "max_sessions"}
)

# name -> (export signature, discovered tools). SIGHUP drops it (see
# ``clear_discovery_cache``) so a changed ``mcp.yaml`` or a new server build is seen.
_DISCOVERY_CACHE: Dict[str, Tuple[tuple, List[Dict[str, Any]]]] = {}


class McpCallError(Exception):
    """A refused or failed MCP call. ``code`` becomes ``result.error.code``."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _is_timeout(exc: BaseException) -> bool:
    """Whether ``exc`` is the client giving up at the call's deadline.

    The MCP SDK reports its own read timeout as ``MCPError(-32001)``, not as
    ``TimeoutError``; treating that as a crash would retire a healthy session (and
    lose the user's login state) on every slow call.
    """
    if isinstance(exc, TimeoutError):
        return True
    return getattr(exc, "code", None) == MCP_REQUEST_TIMEOUT_CODE



@dataclass(frozen=True)
class McpExport:
    """One exported MCP server plus the operator's edge-local policy for it."""

    name: str
    config: MCPConfig
    directory: Path
    include_tools: Tuple[str, ...] = ()
    exclude_tools: Tuple[str, ...] = ()
    credential_mode: str = "shared"
    session_ttl_minutes: int = DEFAULT_SESSION_TTL_MINUTES
    max_sessions: int = MAX_SESSIONS_PER_MCP

    def signature(self) -> tuple:
        """What a live session is bound to; a change kills sessions on reload.

        TTL and caps are absent on purpose: they are policy applied in memory, not
        part of the server a session talks to.
        """
        return (
            self.name,
            self.config.transport,
            self.config.command,
            tuple(self.config.args or ()),
            tuple(sorted((self.config.env or {}).items())),
            self.config.network,
            _tools_digest(self.config.tools),
            self.include_tools,
            self.exclude_tools,
            self.credential_mode,
        )


# ---------------------------------------------------------------- configuration


@dataclass(frozen=True)
class _ExportOptions:
    name: str
    include_tools: Tuple[str, ...] = ()
    exclude_tools: Tuple[str, ...] = ()
    credential_mode: str = "shared"
    session_ttl_minutes: int = DEFAULT_SESSION_TTL_MINUTES
    max_sessions: int = MAX_SESSIONS_PER_MCP


def _valid_name(name: Any) -> bool:
    return isinstance(name, str) and bool(protocol.NAME_RE.match(name)) and "__" not in name


def _name_list(value: Any, field: str) -> Tuple[str, ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"export_mcps {field} must be a list of tool names")
    return tuple(item.strip() for item in value if item.strip())


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"export_mcps {field} must be a positive integer")
    return value


def _export_options(entry: Any) -> _ExportOptions:
    """Parse one ``export_mcps`` entry (bare name or mapping). Raises ``ValueError``."""
    if isinstance(entry, str):
        name, options = entry, {}
    elif isinstance(entry, Mapping):
        options = dict(entry)
        unknown = set(options) - _EXPORT_KEYS
        if unknown:
            raise ValueError(
                f"export_mcps entry {options.get('name')!r} has unknown key(s) "
                f"{', '.join(sorted(map(str, unknown)))}"
            )
        name = options.get("name")
    else:
        raise ValueError(
            f"export_mcps entries must be a name or a mapping, got {type(entry).__name__}"
        )

    name = name.strip() if isinstance(name, str) else name
    if not _valid_name(name):
        raise ValueError(
            f"export_mcps has an invalid name {name!r} (see protocol.NAME_RE; no '__')"
        )

    mode = options.get("credential_mode") or "shared"
    if not isinstance(mode, str) or mode.strip().lower() not in _CREDENTIAL_MODES:
        raise ValueError(
            f"export_mcps {name!r} credential_mode must be one of "
            f"{', '.join(sorted(_CREDENTIAL_MODES))}"
        )

    return _ExportOptions(
        name=name,
        include_tools=_name_list(options.get("include_tools"), "include_tools"),
        exclude_tools=_name_list(options.get("exclude_tools"), "exclude_tools"),
        credential_mode=mode.strip().lower(),
        session_ttl_minutes=_positive_int(
            options.get("session_ttl_minutes", DEFAULT_SESSION_TTL_MINUTES),
            "session_ttl_minutes",
        ),
        max_sessions=_positive_int(
            options.get("max_sessions", MAX_SESSIONS_PER_MCP), "max_sessions"
        ),
    )


def validate_export_mcps(raw: Any) -> List[Any]:
    """Check a whole ``export_mcps`` block at config load, before any file is read.

    ``load_config`` calls this so a typo is a startup error with the offending entry
    named, instead of an MCP server that silently never publishes.
    """
    if raw in (None, []):
        return []
    if not isinstance(raw, list):
        raise ValueError("proxy config: 'export_mcps' must be a list of names or mappings")
    for entry in raw:
        try:
            _export_options(entry)
        except ValueError as exc:
            raise ValueError(f"proxy config: {exc}") from exc
    return list(raw)


def load_mcps(mcps_dir: Path, export_mcps: List[Any]) -> Dict[str, McpExport]:
    """Load the MCP servers this edge is allowed to publish.

    ``export_mcps`` is the operator's allowlist and is enforced here, not at the
    relay. An empty allowlist exports nothing -- the safe default, matching
    ``core.proxy.load_tools``. Anything the relay would refuse (bad name, bad
    transport, oversized schema) is dropped with a warning so one broken server
    cannot break the publish.
    """
    mcps_dir = Path(mcps_dir)
    requested: Dict[str, _ExportOptions] = {}
    for raw in export_mcps or []:
        try:
            options = _export_options(raw)
        except ValueError as exc:
            logger.warning("Skipping export_mcps entry: %s", exc)
            continue
        requested[options.name] = options

    if not requested:
        logger.warning(
            "proxy export_mcps is empty: publishing no MCP servers "
            "(list them under export_mcps: in proxy.yaml)"
        )
        return {}

    exports: Dict[str, McpExport] = {}
    known: set[str] = set()

    for mcp_yaml in sorted(mcps_dir.glob("**/mcp.yaml")):
        try:
            data = yaml.safe_load(mcp_yaml.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            logger.warning("Skipping %s: %s", mcp_yaml, exc)
            continue

        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            if not isinstance(entry, dict):
                logger.warning("Skipping %s: entry is not a mapping", mcp_yaml)
                continue

            entry = dict(entry)
            name = str(entry.get("name") or mcp_yaml.parent.name).strip()
            entry["name"] = name
            known.add(name)

            # Checked before the allowlist: a manifest the relay could never accept
            # is worth reporting even before someone exports it.
            transport = str(entry.get("transport") or "stdio").strip().lower()
            if transport not in protocol.SUPPORTED_MCP_TRANSPORTS:
                logger.warning(
                    "Skipping mcp %r: transport %r is not supported on an edge (expected one of %s)",
                    name,
                    transport,
                    ", ".join(sorted(protocol.SUPPORTED_MCP_TRANSPORTS)),
                )
                continue
            entry["transport"] = transport
            if not _valid_name(name):
                logger.warning("Skipping mcp %r: name is not publishable (see protocol.NAME_RE)", name)
                continue
            if name not in requested:
                continue

            if not entry.get("command"):
                logger.warning("Skipping mcp %r: no command/URL configured", name)
                continue
            if name in exports:
                logger.warning("Skipping duplicate mcp %r in %s", name, mcp_yaml)
                continue

            try:
                config = MCPConfig(**entry)
            except Exception as exc:  # pydantic ValidationError
                logger.warning("Skipping mcp %r: invalid mcp.yaml (%s)", name, exc)
                continue

            # Static catalogs are checked now so the relay can never be the first to
            # refuse one. Discovery-based servers are checked in ``build_catalog``.
            if config.tools:
                try:
                    protocol.validate_mcps([_catalog_payload(name, config.transport, config.tools)])
                except protocol.ProtocolError as exc:
                    logger.warning("Skipping mcp %r: %s", name, exc)
                    continue

            options = requested[name]
            exports[name] = McpExport(
                name=name,
                config=config,
                directory=mcp_yaml.parent.resolve(),
                include_tools=options.include_tools,
                exclude_tools=options.exclude_tools,
                credential_mode=options.credential_mode,
                session_ttl_minutes=options.session_ttl_minutes,
                max_sessions=options.max_sessions,
            )

    for missing in sorted(set(requested) - known):
        logger.warning(
            "export_mcps lists %r but no matching mcp.yaml was found under %s", missing, mcps_dir
        )
    return _enforce_mcp_cap(exports)


def _enforce_mcp_cap(exports: Dict[str, McpExport]) -> Dict[str, McpExport]:
    """Keep at most ``protocol.MAX_MCPS`` servers (plan §3.3, aggregate hello limit).

    The relay refuses a hello above the cap outright; publishing one would put the
    edge in a ``CLOSE_MALFORMED`` reconnect loop that takes the tools down with it.
    Names are kept in sorted order so the same subset survives every reload.
    """
    if len(exports) <= protocol.MAX_MCPS:
        return exports
    kept = sorted(exports)[: protocol.MAX_MCPS]
    for name in sorted(set(exports) - set(kept)):
        logger.warning(
            "MCP %r: not exporting it -- the edge already exports the maximum of %d "
            "MCP servers (MAX_MCPS); raise the cap or export fewer",
            name,
            protocol.MAX_MCPS,
        )
    return {name: exports[name] for name in kept}


# ---------------------------------------------------------------- catalog


def _tools_digest(tools: Any) -> str:
    if not tools:
        return ""
    payload = [_tool_dict(tool) for tool in tools]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _tool_dict(tool: Any) -> Dict[str, Any]:
    """One catalog tool as plain data. ``inputSchema`` is never touched (L6)."""
    if isinstance(tool, Mapping):
        schema = tool.get("input_schema")
        if schema is None:
            schema = tool.get("inputSchema")
        description = tool.get("description") or ""
        name = tool.get("name")
    else:
        name = getattr(tool, "name", None)
        description = getattr(tool, "description", None) or ""
        # The MCP SDK exposes ``input_schema``; reading the v2-deprecated
        # ``inputSchema`` alias first would warn on every catalogue build.
        schema = getattr(tool, "input_schema", None)
        if schema is None:
            schema = getattr(tool, "inputSchema", None)
    return {"name": name, "description": description, "inputSchema": schema or {}}


def _catalog_payload(name: str, transport: str, tools: List[Any]) -> Dict[str, Any]:
    return {
        "name": name,
        "transport": transport,
        "tools": [_tool_dict(tool) for tool in tools],
    }


def is_published(entry: McpExport, tool: str) -> bool:
    """Whether ``tool`` is in this server's published catalog (edge name authority)."""
    if entry.include_tools and tool not in entry.include_tools:
        return False
    return tool not in entry.exclude_tools


def clear_discovery_cache() -> None:
    """Drop live-discovery results; SIGHUP calls this so a changed server is re-read."""
    _DISCOVERY_CACHE.clear()


def _fastmcp():
    """Lazy import: a tools-only edge never loads the MCP client stack."""
    from fastmcp import Client
    from fastmcp.client import SSETransport, StdioTransport, StreamableHttpTransport

    return Client, StdioTransport, StreamableHttpTransport, SSETransport


def build_stdio_argv(entry: McpExport, home_dir: Path, backend: Any = None) -> List[str]:
    """Sandboxed argv for one stdio server.

    Module-level (not a method) so tests can substitute ``[sys.executable, fixture]``
    and run the suite without a sandbox backend. ``backend`` defaults to the
    selected one so callers never have to pass it.
    """
    if not entry.config.command:
        raise McpCallError("mcp_session_lost", f"mcp {entry.name!r} has no command to run")
    uid, gid = sandbox.sandbox_preflight.resolve_sandbox_identity()
    return sandbox.build_cmd(
        backend or sandbox.select_backend(),
        [entry.config.command, *(entry.config.args or [])],
        entry.directory,
        Path(home_dir),
        uid,
        gid,
        network=entry.config.network,
    )


def _session_root() -> Path:
    return sandbox.writable_root() / "mcp-sessions"


def _private_dir(directory: Path) -> Path:
    """Create ``directory`` 0700: a session (or discovery) HOME holds login state."""
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        # mkdir's mode is masked by umask and ignored when the dir already exists.
        os.chmod(directory, 0o700)
    except OSError:
        logger.debug("Could not chmod MCP directory %s", directory, exc_info=True)
    return directory


def _session_dir(mcp: str, user_key: str) -> Path:
    """Per-(mcp, user) state dir, 0700: this is what isolates two users' logins."""
    digest = hashlib.sha256(user_key.encode("utf-8")).hexdigest()[:16]
    return _private_dir(_session_root() / mcp / digest)


def _discovery_dir(mcp: str) -> Path:
    """Throwaway HOME for a discovery client: still 0700, it sees the real creds."""
    return _private_dir(_session_root() / "_discovery" / mcp)


def _identity_key(identity: Optional[Mapping[str, Any]]) -> str:
    """Session key: email first, then user id, then anonymous (plan §3.4).

    The email is normalized (``core.edge_user_secrets.normalize_email``, edge-only) for
    the same reason the credential file is: ``Ops@Example.com`` and ``ops@example.com``
    are one person, and two spellings must not get two sessions (two server processes,
    two ``HOME`` dirs, two logins). ``user`` and ``"anonymous"`` are passed through.
    """
    email = (identity or {}).get("user_email")
    if isinstance(email, str) and email.strip():
        return edge_user_secrets.normalize_email(email)
    user = (identity or {}).get("user")
    if isinstance(user, str) and user.strip():
        return user.strip()
    return "anonymous"


def _http_headers(
    entry: McpExport, env: Mapping[str, str], token_env: Optional[str] = None
) -> Dict[str, str]:
    """Credentials for a remote transport: only what the manifest declares.

    An http/sse endpoint is a *remote origin*, so it must not receive the scoped
    process environment as headers: that leaked the caller identity
    (``TRELLIS_USER_*``), the session's ``HOME``/``TMPDIR``/``PATH`` and (with
    passthrough) the operator's whole env to a third party -- and one non-latin-1
    value breaks httpx outright. Declared keys plus the manifest's literal ``env:``
    values are the only things a remote server can legitimately need.

    ``env`` is the already-resolved environment for this session, so the headers come
    from the same credential chain the stdio transport gets (a per-user file included)
    rather than from the raw process env. ``token_env`` matters because a host that
    renames the enrollment token would otherwise hand it to the endpoint when a
    manifest happens to declare that name.

    A literal ``mcp.yaml`` ``env:`` value is applied for names the manifest does **not**
    declare, and a resolved credential for the declared ones: a stale literal must never
    shadow the caller's file (nor reach an origin under ``per_user_required`` when the
    file does not define the key).
    """
    reserved = edge_env.RESERVED_ENV_NAMES | {
        edge_env.DEFAULT_TOKEN_ENV,
        token_env or edge_env.DEFAULT_TOKEN_ENV,
    }
    declared = edge_env.declared_keys_for(entry.config)
    headers = {
        key: str(value)
        for key, value in (entry.config.env or {}).items()
        if isinstance(key, str) and key.upper() not in reserved and key not in declared
    }
    headers.update(
        {
            key: env[key]
            for key in sorted(declared)
            if key in env and key.upper() not in reserved
        }
    )
    return headers


def _transport(
    entry: McpExport, home_dir: Path, env: Dict[str, str], token_env: Optional[str] = None
):
    """A client for one server. Only stdio spawns a process, so only it is sandboxed.

    ``keep_alive=False`` is not optional: a session enters its client once and holds
    it for the session's whole lifetime, so keeping the transport alive past
    ``__aexit__`` buys nothing -- and it is exactly what made every retired session
    leak an OS process. Closing the client must terminate the server.
    """
    Client, StdioTransport, StreamableHttpTransport, SSETransport = _fastmcp()
    if entry.config.transport == "stdio":
        argv = build_stdio_argv(entry, home_dir, None)
        return Client(
            StdioTransport(
                command=argv[0],
                args=argv[1:],
                env=env,
                # Same cwd as a tool subprocess: a relative config/asset path in the
                # server's own manifest resolves against its directory.
                cwd=str(entry.directory),
                keep_alive=False,
            )
        )
    headers = _http_headers(entry, env, token_env)
    url = entry.config.command or ""
    if entry.config.transport in ("http", "streamable-http"):
        return Client(StreamableHttpTransport(url=url, headers=headers))
    return Client(SSETransport(url=url, headers=headers))


def resolve_credentials(
    entry: McpExport,
    identity: Optional[Mapping[str, Any]],
    *,
    credentials: Optional[edge_user_secrets.CredentialStore] = None,
    site: Optional[str] = None,
) -> Dict[str, str]:
    """The declared credentials for this session, via the entry's ``credential_mode``.

    Raises ``edge_user_secrets.MissingCredentials`` under ``per_user_required``; the
    caller turns that into ``missing_credentials``. Runs once per session, at creation:
    an edited file never changes a live session (plan §7 Phase 5).
    """
    store = credentials or edge_user_secrets.CredentialStore.from_config(None)
    email = (identity or {}).get("user_email")
    return store.resolve(
        entry.config,
        name=entry.name,
        email=email if isinstance(email, str) else None,
        site=site or "",
        mode=entry.credential_mode,
    )


def _server_env(
    entry: McpExport,
    home_dir: Path,
    identity: Optional[Mapping[str, Any]],
    *,
    passthrough: bool,
    token_env: Optional[str],
    credentials: Optional[edge_user_secrets.CredentialStore] = None,
    site: Optional[str] = None,
    credential_env: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """Declared keys + literal ``mcp.yaml`` env + session HOME + caller identity.

    Order matters: the scoped process env first, then the manifest's literal ``env:``,
    then the **resolved credentials last**, so a stale literal value can never shadow
    a credential file (which would defeat ``per_user_required`` whenever the caller's
    file happens to define the key). Under ``per_user_required`` a declared key the
    file does not define is then removed outright, even with ``passthrough``.
    """
    resolved = (
        credential_env
        if credential_env is not None
        else resolve_credentials(entry, identity, credentials=credentials, site=site)
    )
    env = edge_env.scoped_env(
        (),
        passthrough=passthrough,
        secret_env_names={edge_env.DEFAULT_TOKEN_ENV, token_env or edge_env.DEFAULT_TOKEN_ENV},
    )
    env.update(
        {
            key: str(value)
            for key, value in (entry.config.env or {}).items()
            if isinstance(key, str)
        }
    )
    # Credentials from the store win over the process env and over a literal ``env:``
    # (``shared`` mode's point, and the only source under ``per_user_required``).
    env.update(resolved)
    edge_user_secrets.enforce_per_user_required(
        env, entry.config, resolved, entry.credential_mode
    )
    # Neither a credential file nor a literal env: may reintroduce a control-plane name.
    edge_env.strip_framework_names(env, token_env=token_env)
    # Identity is per frame: never inherit a stale one from ``TRELLIS_*``.
    env.pop("TRELLIS_USER_ID", None)
    env.pop("TRELLIS_USER_EMAIL", None)
    home = str(home_dir)
    env.update({"HOME": home, "TMPDIR": home, "TMP": home, "TEMP": home})
    for var, field in (("TRELLIS_USER_ID", "user"), ("TRELLIS_USER_EMAIL", "user_email")):
        value = (identity or {}).get(field)
        if isinstance(value, str) and value:
            env[var] = value
    return env


async def _discover(
    entry: McpExport,
    *,
    passthrough: bool,
    token_env: Optional[str],
    credentials: Optional[edge_user_secrets.CredentialStore] = None,
    site: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Live ``list_tools()`` against a throwaway client; cached per export signature."""
    signature = entry.signature()
    cached = _DISCOVERY_CACHE.get(entry.name)
    if cached is not None and cached[0] == signature:
        return cached[1]

    directory = _discovery_dir(entry.name)
    try:
        env = _server_env(
            entry,
            directory,
            None,
            passthrough=passthrough,
            token_env=token_env,
            credentials=credentials,
            site=site,
        )
    except edge_user_secrets.MissingCredentials as exc:
        # Discovery runs without a caller, so a per-user-only server has no identity to
        # resolve against. Static `tools:` catalogs need no discovery at all.
        raise McpCallError(
            "mcp_unavailable",
            f"mcp {entry.name!r} needs per-user credentials to discover its tools; "
            "declare a static 'tools:' catalog in mcp.yaml",
        ) from exc
    client = _transport(entry, directory, env, token_env)

    async def _list() -> List[Any]:
        async with client:
            return await client.list_tools()

    try:
        tools = await asyncio.wait_for(_list(), timeout=DISCOVERY_TIMEOUT_S)
    except Exception as exc:
        # Not fatal: the server is skipped from the catalog, the edge keeps serving.
        reason = (
            f"did not answer tools/list within {DISCOVERY_TIMEOUT_S}s"
            if isinstance(exc, asyncio.TimeoutError)
            else f"tool discovery failed ({type(exc).__name__})"
        )
        raise McpCallError("mcp_unavailable", f"mcp {entry.name!r} {reason}") from exc

    discovered = [_tool_dict(tool) for tool in tools]
    _DISCOVERY_CACHE[entry.name] = (signature, discovered)
    return discovered


async def build_catalog(
    entry: McpExport,
    *,
    passthrough: bool = False,
    token_env: Optional[str] = None,
    credentials: Optional[edge_user_secrets.CredentialStore] = None,
    site: Optional[str] = None,
) -> protocol.EdgeMcp:
    """The published catalog for one server: static ``tools:`` verbatim, else discovery.

    Raises ``McpCallError`` when the server cannot be read or its catalog would not
    survive ``protocol.validate_mcps`` -- the caller skips it with a log.
    """
    tools = list(entry.config.tools or [])
    if not tools:
        tools = await _discover(
            entry,
            passthrough=passthrough,
            token_env=token_env,
            credentials=credentials,
            site=site,
        )

    catalog_tools = [_tool_dict(tool) for tool in tools]
    published = [tool for tool in catalog_tools if is_published(entry, tool["name"])]
    try:
        return protocol.validate_mcps(
            [_catalog_payload(entry.name, entry.config.transport, published)]
        )[0]
    except protocol.ProtocolError as exc:
        raise McpCallError(
            "mcp_unavailable", f"mcp {entry.name!r} catalog is not publishable: {exc}"
        ) from exc


# ---------------------------------------------------------------- results


def _encode(payload: Any) -> bytes:
    return json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")


def _content_blocks(result: Any) -> List[Dict[str, Any]]:
    blocks: List[Dict[str, Any]] = []
    for block in getattr(result, "content", None) or []:
        if hasattr(block, "model_dump"):
            blocks.append(block.model_dump(mode="json", exclude_none=True))
        elif isinstance(block, Mapping):
            blocks.append(dict(block))
        else:
            blocks.append({"type": "text", "text": str(block)})
    return blocks


def map_result(result: Any) -> Dict[str, Any]:
    """Map an MCP ``CallToolResult`` onto the protocol's result payload (§3.1)."""
    structured = getattr(result, "structured_content", None)
    payload: Dict[str, Any] = {
        "content": _content_blocks(result),
        "isError": bool(getattr(result, "is_error", False)),
    }
    if structured is not None:
        payload["structuredContent"] = structured
    return _truncate(payload)


def _truncate(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Fit an oversized result into the frame budget, marking the loss.

    A 96k-char safety net (``core.tool_runtime``) already applies to tool results;
    an MCP server can return far more, and failing the frame would lose the call.

    The budget is on the **encoded** bytes, not characters: JSON escaping doubles
    quotes, backslashes and newlines, so slicing ``text[:budget]`` can still emit a
    frame well over the cap. The prefix is therefore found by binary search over
    the encoded payload.
    """
    size = len(_encode(payload))
    if size <= MAX_RESULT_CHARS:
        return payload

    marker = f"... [truncated by edge: original {size} bytes]"
    blocks = payload.get("content") or []
    others = [block for block in blocks if block.get("type") != "text"]
    text = "\n".join(
        block.get("text") or "" for block in blocks if block.get("type") == "text"
    )
    shell: Dict[str, Any] = {
        "content": others + [{"type": "text", "text": marker}],
        "isError": payload.get("isError", False),
    }
    if len(_encode(shell)) > MAX_RESULT_CHARS:
        # structuredContent (or the non-text blocks) alone blew the budget.
        return {"content": [{"type": "text", "text": marker}], "isError": shell["isError"]}

    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        shell["content"] = others + [{"type": "text", "text": text[:middle] + marker}]
        if len(_encode(shell)) <= MAX_RESULT_CHARS:
            low = middle
        else:
            high = middle - 1
    shell["content"] = others + [{"type": "text", "text": text[:low] + marker}]
    return shell


# ---------------------------------------------------------------- sessions


class _ServerSession:
    """One live MCP client for one ``(mcp, user)`` pair."""

    def __init__(self, mcp: str, client: Any) -> None:
        self.mcp = mcp
        self.client = client
        # Calls are serialized per session (plan §3.4); the client multiplexes
        # across servers, the server itself does not need concurrent calls.
        self.lock = asyncio.Lock()
        self.last_used = time.monotonic()


class McpSessionManager:
    """Owns every MCP session on this edge, independent of the tunnel socket."""

    def __init__(
        self,
        *,
        passthrough: bool = False,
        token_env: Optional[str] = None,
        credentials: Optional[edge_user_secrets.CredentialStore] = None,
        site: Optional[str] = None,
    ) -> None:
        self.passthrough = passthrough
        self.token_env = token_env
        # Where per-user/shared credential files live, and the site named in a
        # fail-closed message. Both are restart-required (see proxy._Session.reload).
        self.credentials = credentials or edge_user_secrets.CredentialStore.from_config(None)
        self.site = site
        self._entries: Dict[str, McpExport] = {}
        self._tools: Dict[str, Dict[str, protocol.EdgeMcpTool]] = {}
        # Ordered by last use: the left end is the LRU eviction candidate.
        self._sessions: "OrderedDict[Tuple[str, str], _ServerSession]" = OrderedDict()
        # Detached but not yet closed; reap() owns the await.
        self._retired: List[_ServerSession] = []
        # One-shot tombstones: a swept/evicted session reports itself once, then a
        # later call starts a fresh one. FIFO-bounded (MAX_SESSION_TOMBS).
        self._tombs: "OrderedDict[Tuple[str, str], None]" = OrderedDict()
        # Serializes session creation. Without it two concurrent first calls for
        # the same key each spawn a server, the second overwrites the first in
        # ``_sessions`` (so it is never tracked or reaped), and the two callers
        # hold different per-session locks.
        self._create_lock = asyncio.Lock()

    def set_entries(
        self, entries: Dict[str, McpExport], catalogs: Dict[str, protocol.EdgeMcp]
    ) -> None:
        """Install the current exports/catalogs and retire sessions that no longer match."""
        for name, entry in entries.items():
            previous = self._entries.get(name)
            if previous is not None and previous.signature() != entry.signature():
                logger.info("MCP %r changed; closing its sessions", name)
                self._retire_mcp(name, tombstone=True)
        for name in set(self._entries) - set(entries):
            logger.info("MCP %r is no longer exported; closing its sessions", name)
            self._retire_mcp(name, tombstone=False)

        self._entries = dict(entries)
        self._tools = {
            name: {tool.name: tool for tool in catalog.tools}
            for name, catalog in catalogs.items()
            if name in entries
        }

    async def call(
        self,
        mcp: str,
        tool: str,
        args: Dict[str, Any],
        identity: Dict[str, Any],
        deadline_ms: int,
    ) -> Dict[str, Any]:
        """Execute one MCP ``tools/call`` and return the mapped payload.

        Refusals and crashes raise ``McpCallError``; the caller turns that into a
        ``result`` frame. Nothing here ever retries a call.
        """
        entry = self._entries.get(mcp)
        if entry is None:
            raise McpCallError("unknown_mcp", f"mcp {mcp!r} is not exported by this edge")
        if tool not in self._tools.get(mcp, {}) or not is_published(entry, tool):
            raise McpCallError(
                "unknown_tool", f"tool {tool!r} is not published for mcp {mcp!r}"
            )

        user_key = _identity_key(identity)
        key = (mcp, user_key)
        await self._sweep()

        if key in self._tombs:
            self._tombs.pop(key, None)
            raise McpCallError(
                "mcp_session_lost",
                f"the session for this caller on mcp {mcp!r} was closed (idle timeout "
                "or capacity eviction); retry to start a new one",
            )

        session = self._sessions.get(key)
        if session is None:
            async with self._create_lock:
                session = self._sessions.get(key)
                if session is None:
                    # Resolved before eviction/creation: a fail-closed refusal must not
                    # retire a live session or spawn a process it cannot serve.
                    credential_env = self._credential_env(entry, identity)
                    self._evict_for(entry)
                    await self.reap()
                    session = await self._open(entry, user_key, identity, credential_env)

        async with session.lock:
            session.last_used = time.monotonic()
            self._sessions.move_to_end(key)
            try:
                result = await session.client.call_tool(
                    tool,
                    args,
                    raise_on_error=False,
                    timeout=max(1.0, deadline_ms / 1000.0),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if _is_timeout(exc):
                    # At the deadline the relay has already stopped waiting; the
                    # session stays (a timeout is not a crash) and nothing replays.
                    raise McpCallError(
                        "edge_timeout", "mcp call exceeded its deadline"
                    ) from exc
                logger.error(
                    "MCP %r session for a caller failed, dropping it (%s)",
                    mcp,
                    type(exc).__name__,
                )
                # No tombstone: a crash is reported once and the next call respawns.
                self._retire(key, tombstone=False)
                await self.reap()
                raise McpCallError(
                    "mcp_session_lost",
                    f"the server for mcp {mcp!r} crashed; the session will restart on "
                    "the next call",
                ) from exc

        return map_result(result)

    async def kill_all(self) -> None:
        """Close every session; used on process exit."""
        for key in list(self._sessions):
            self._retire(key, tombstone=False)
        self._tombs.clear()
        await self.reap()

    def retire_all(self) -> None:
        """Retire every live session (SIGHUP): the next call reopens with fresh credentials.

        Credentials are resolved once, at creation, so a signal is the only way an
        edited credential file reaches a live session before its TTL. No tombstone:
        this is a requested reopen, not a lost session, so the next call must start a
        fresh server instead of answering ``mcp_session_lost``. The caller owns the
        ``reap()`` (``_Session.refresh_mcps``).
        """
        for key in list(self._sessions):
            self._retire(key, tombstone=False)

    async def sweep(self) -> None:
        """The periodic idle sweep (plan §3.4 D2): TTL expiry plus its reap."""
        await self._sweep()
        await self.reap()

    async def reap(self) -> None:
        """Close sessions detached by eviction, sweep, or a reload.

        Cancellation-safe: a ``CancelledError`` in the middle of the loop puts the
        session that was being closed (and the ones after it) back on the retired
        list, so a later reap still terminates every child process instead of
        leaking the tail.
        """
        pending, self._retired = self._retired, []
        try:
            while pending:
                session = pending[0]
                try:
                    await session.client.__aexit__(None, None, None)
                except Exception:
                    logger.debug("Failed to close an MCP session", exc_info=True)
                pending = pending[1:]
        finally:
            if pending:
                self._retired[:0] = pending

    def installed_entry(self, name: str) -> Optional[McpExport]:
        """The export live sessions are currently bound to (``None`` if not installed)."""
        return self._entries.get(name)

    def _credential_env(
        self, entry: McpExport, identity: Mapping[str, Any]
    ) -> Dict[str, str]:
        """This session's credentials, or a ``missing_credentials`` refusal.

        Read once here, at creation: a live session keeps the credentials it started
        with until its TTL, a SIGHUP that retires it, or a restart (documented in
        ``proxy._Session.reload``).
        """
        try:
            return resolve_credentials(
                entry, identity, credentials=self.credentials, site=self.site
            )
        except edge_user_secrets.MissingCredentials as exc:
            logger.warning("MCP %r: %s", entry.name, exc.message)
            raise McpCallError(exc.code, exc.message) from exc

    async def _open(
        self,
        entry: McpExport,
        user_key: str,
        identity: Mapping[str, Any],
        credential_env: Mapping[str, str],
    ) -> _ServerSession:
        directory = _session_dir(entry.name, user_key)
        env = _server_env(
            entry,
            directory,
            identity,
            passthrough=self.passthrough,
            token_env=self.token_env,
            credential_env=credential_env,
        )
        try:
            # keep_alive=False inside: closing the client kills the server process.
            client = _transport(entry, directory, env, self.token_env)
            await client.__aenter__()
        except Exception as exc:
            # Type only: an http/sse transport's message can echo the endpoint URL.
            logger.error(
                "MCP %r: could not start a session (%s); the endpoint or command may "
                "be unreachable or misconfigured",
                entry.name,
                type(exc).__name__,
            )
            raise McpCallError(
                "mcp_session_lost",
                f"mcp {entry.name!r} failed to start; it will be retried on the next call",
            ) from exc

        session = _ServerSession(entry.name, client)
        self._sessions[(entry.name, user_key)] = session
        return session

    async def _sweep(self) -> None:
        """Retire sessions idle past their server's TTL (skipping ones in use)."""
        now = time.monotonic()
        dropped = False
        for key, session in list(self._sessions.items()):
            if session.lock.locked():
                continue
            entry = self._entries.get(session.mcp)
            ttl_minutes = (
                entry.session_ttl_minutes if entry else DEFAULT_SESSION_TTL_MINUTES
            )
            if now - session.last_used >= ttl_minutes * 60:
                logger.info("MCP %r: closing an idle session", session.mcp)
                self._retire(key, tombstone=True)
                dropped = True
        if dropped:
            await self.reap()

    def _evict_for(self, entry: McpExport) -> None:
        """Make room for a new session under the per-server and edge-wide caps."""
        same = [key for key in self._sessions if key[0] == entry.name]
        while len(same) >= entry.max_sessions:
            victim = self._victim(same)
            logger.info("MCP %r is at its session cap; evicting the least recently used", entry.name)
            self._retire(victim, tombstone=True)
            same.remove(victim)
        while len(self._sessions) >= MAX_SESSIONS_EDGE:
            victim = self._victim(list(self._sessions))
            logger.info("Edge is at its MCP session cap; evicting the least recently used")
            self._retire(victim, tombstone=True)

    def _victim(self, keys: List[Tuple[str, str]]) -> Tuple[str, str]:
        for key in keys:  # LRU order; prefer an idle session over one mid-call
            session = self._sessions.get(key)
            if session is not None and not session.lock.locked():
                return key
        return keys[0]

    def _retire_mcp(self, mcp: str, *, tombstone: bool) -> None:
        for key in [key for key in self._sessions if key[0] == mcp]:
            self._retire(key, tombstone=tombstone)

    def _retire(self, key: Tuple[str, str], *, tombstone: bool) -> None:
        session = self._sessions.pop(key, None)
        if session is None:
            return
        self._retired.append(session)
        if tombstone:
            self._add_tomb(key)

    def _add_tomb(self, key: Tuple[str, str]) -> None:
        """Record a one-shot tombstone, keeping the map bounded (FIFO eviction)."""
        self._tombs[key] = None
        self._tombs.move_to_end(key)
        while len(self._tombs) > MAX_SESSION_TOMBS:
            self._tombs.popitem(last=False)

