# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge entrypoint for the trellis-proxy tool tunnel.

Runs on a customer VM that can dial out but accepts no inbound connections. It
loads a local ``proxy.yaml`` plus ``tool.yaml`` files, publishes their catalog to
the central relay over a WebSocket, and executes the ``call`` frames the relay
forwards. Execution goes through ``core.tool_runtime`` -- the same sandboxed
subprocess path the hub uses.

Deliberately independent of the framework's control plane: no etcd, no FastMCP,
no identity manager. The only shared contracts are ``services.edge_relay.protocol``
and ``core.tool_runtime``. Importing this module must stay side-effect free.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import logging
import os
import random
import signal
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

import yaml

from core import sandbox, tool_runtime
from core.env_sanitize import sanitized_env
from core.models import ToolConfig
from services.edge_relay import protocol

logger = logging.getLogger(__name__)

PROTO_VERSION = protocol.PROTO
SUBPROTOCOL = protocol.SUBPROTOCOL
MAX_INFLIGHT = protocol.MAX_INFLIGHT

# Runtimes this edge can actually spawn. ``remote`` is a central-side pointer to
# another edge, never something an edge executes itself. ``go`` is absent on
# purpose: the hub precompiles Go tools into ``tool_dir/.bin``, and an edge has
# no compile step, so a published go
# tool would fail every call with FileNotFoundError.
EDGE_RUNTIMES = frozenset({"python", "ts", "bash"})

CONFIG_ENV = "TRELLIS_EDGE_CONFIG"
DEFAULT_CONFIG_PATH = Path("proxy.yaml")

# A site named ``mcp`` names its tools ``mcp__<tool>``, the prefix
# core/tool_search.py already reserves for external MCP servers, so the floor
# registry name would be ambiguous.
RESERVED_SITE_NAMES = frozenset({"mcp"})

_SITE_RE = protocol.NAME_RE
_WS_PREFIXES = ("ws://", "wss://")
_VALID_SANDBOX_BACKENDS = frozenset({"auto", "bwrap", "landlock"})


def _installed_version() -> str:
    """The version reported in ``hello``, for protocol diagnostics.

    The image installs requirements only (no project metadata), so the normal path is
    ``TRELLIS_VERSION`` from the deployment, then "0.0.0" -- not an error worth
    surfacing. Central operators use the Admin -> Edges column to spot a stale proxy.
    """
    from_env = os.getenv("TRELLIS_VERSION", "").strip()
    if from_env:
        return from_env
    try:
        from importlib.metadata import version

        return version("trellis-agent-platform")
    except Exception:  # PackageNotFoundError, or unreadable metadata
        return "0.0.0"


EDGE_VERSION = _installed_version()

# Reconnect backoff bounds (design §6.2).
_BACKOFF_MIN_S = 1.0
_BACKOFF_MAX_S = 60.0
# A session up for this long was healthy: the next disconnect starts a fresh
# backoff streak instead of inheriting the previous failure's delay.
_BACKOFF_STABLE_S = 30.0
# Kept back from the caller's deadline_ms so the edge's structured error frame
# reaches the relay before the relay's own wait expires.
_DEADLINE_GRACE_S = 0.25
# Retrying these can never help; see _next_backoff.
_TERMINAL_CLOSE_CODES = frozenset({protocol.CLOSE_REVOKED, protocol.CLOSE_SUPERSEDED})

# Set while ``run()`` is active so the SIGHUP handler can reach the session and
# the loop it must schedule on (signal handlers run synchronously, in the main
# thread, between bytecodes).
_active_session: Optional["_Session"] = None
_active_loop: Optional[asyncio.AbstractEventLoop] = None


@dataclass(frozen=True)
class ProxyConfig:
    """Everything the edge needs, resolved from YAML plus env overrides."""

    site: str
    server_url: str
    token_env: str = "TRELLIS_EDGE_TOKEN"
    # Preferred over ``token_env``: a file is not part of the exec environment, so it
    # never shows up in /proc/<pid>/environ where a tool running as the same uid can
    # read it. Read once, then unlinked when the mount allows it.
    token_file: Optional[str] = None
    tools_dir: Path = Path("workspace/tools")
    exports: List[str] = field(default_factory=list)
    sandbox: str = "auto"
    # Optional mutual TLS: the relay's CA plus this edge's client certificate.
    # Without these, a relay that enforces EDGE_MTLS_CA rejects every handshake.
    tls_ca_file: Optional[str] = None
    tls_cert_file: Optional[str] = None
    tls_key_file: Optional[str] = None


# ---------------------------------------------------------------- configuration


def _config_path(path: str | Path | None) -> Tuple[Path, bool]:
    """Resolve where the config should come from, and whether it was explicit."""
    if path is not None:
        return Path(path).expanduser(), True
    from_env = os.getenv(CONFIG_ENV, "").strip()
    if from_env:
        return Path(from_env).expanduser(), True
    return DEFAULT_CONFIG_PATH, False


def load_config(path: str | Path | None = None) -> ProxyConfig:
    """Load ``proxy.yaml`` and apply the env overrides on top.

    Env wins over the file so a container can be re-pointed without editing a
    mounted config. A missing *implicit* file is tolerated (env-only deploys);
    a missing explicit one is an operator error.
    """
    config_path, explicit = _config_path(path)
    raw: Dict[str, Any] = {}
    if config_path.exists():
        try:
            loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"proxy config: cannot read {config_path}: {exc}") from exc
        if loaded is not None and not isinstance(loaded, dict):
            raise ValueError(f"proxy config: {config_path} must contain a mapping")
        raw = dict(loaded or {})
    elif explicit:
        raise ValueError(f"proxy config: file not found: {config_path}")

    site = os.getenv("TRELLIS_EDGE_SITE") or raw.get("site")
    server_url = os.getenv("TRELLIS_SERVER_URL") or raw.get("server_url")
    tools_dir = os.getenv("TRELLIS_EDGE_TOOLS_DIR") or raw.get("tools_dir")

    if not site:
        raise ValueError(
            f"proxy config: 'site' is required (set site: in {config_path} or TRELLIS_EDGE_SITE)"
        )
    site = str(site).strip()
    try:
        site = protocol.validate_site_name(site)
    except protocol.ProtocolError as exc:
        raise ValueError(
            f"proxy config: invalid site name {site!r} ({exc}); expected "
            "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ with no '__', because the site "
            "becomes half of the '<site>__<tool>' registry name"
        ) from exc
    if site in RESERVED_SITE_NAMES:
        raise ValueError(
            f"proxy config: invalid site name {site!r}: reserved, its tools would be "
            "named 'mcp__<tool>' which core.tool_search.py uses for external MCP servers"
        )

    if not server_url:
        raise ValueError(
            f"proxy config: 'server_url' is required "
            f"(set server_url: in {config_path} or TRELLIS_SERVER_URL)"
        )
    server_url = str(server_url).strip()
    if not server_url.startswith(_WS_PREFIXES):
        raise ValueError(
            f"proxy config: server_url must start with ws:// or wss:// (got {server_url!r})"
        )

    exports = raw.get("exports") or []
    if not isinstance(exports, list) or not all(isinstance(name, str) for name in exports):
        raise ValueError("proxy config: 'exports' must be a list of tool names")
    exports = [name.strip() for name in exports if name.strip()]

    sandbox = str(raw.get("sandbox") or "auto").strip().lower()
    if sandbox not in _VALID_SANDBOX_BACKENDS:
        raise ValueError(
            f"proxy config: sandbox must be one of {sorted(_VALID_SANDBOX_BACKENDS)} (got {sandbox!r})"
        )

    token_env = str(raw.get("token_env") or "TRELLIS_EDGE_TOKEN").strip() or "TRELLIS_EDGE_TOKEN"
    token_file = os.getenv("TRELLIS_EDGE_TOKEN_FILE") or raw.get("token_file")
    token_file = str(token_file).strip() if token_file else None

    tls_ca_file = os.getenv("TRELLIS_EDGE_TLS_CA") or raw.get("tls_ca_file")
    tls_cert_file = os.getenv("TRELLIS_EDGE_TLS_CERT") or raw.get("tls_cert_file")
    tls_key_file = os.getenv("TRELLIS_EDGE_TLS_KEY") or raw.get("tls_key_file")
    if bool(tls_cert_file) != bool(tls_key_file):
        raise ValueError(
            "proxy config: tls_cert_file and tls_key_file must be set together "
            "(a client certificate without its key cannot be presented)"
        )
    if tls_ca_file or tls_cert_file:
        # Both of these fail only at connect time otherwise, which turns a typo into
        # an endless reconnect loop with a generic "connection failed" line.
        if not server_url.startswith("wss://"):
            raise ValueError(
                "proxy config: TLS files require a wss:// server_url "
                f"(got {server_url!r}); websockets rejects ssl with ws://"
            )
        for label, value in (
            ("tls_ca_file", tls_ca_file),
            ("tls_cert_file", tls_cert_file),
            ("tls_key_file", tls_key_file),
        ):
            if value and not Path(str(value)).expanduser().is_file():
                raise ValueError(f"proxy config: {label} not found: {value}")

    return ProxyConfig(
        site=site,
        server_url=server_url,
        token_env=token_env,
        token_file=token_file or None,
        tools_dir=Path(tools_dir).expanduser() if tools_dir else Path("workspace/tools"),
        exports=exports,
        sandbox=sandbox,
        tls_ca_file=str(tls_ca_file) if tls_ca_file else None,
        tls_cert_file=str(tls_cert_file) if tls_cert_file else None,
        tls_key_file=str(tls_key_file) if tls_key_file else None,
    )


def load_tools(tools_dir: Path, exports: List[str]) -> Dict[str, Tuple[ToolConfig, Path]]:
    """Load the tools this edge is allowed to publish.

    ``exports`` is the operator's allowlist and is enforced here, not just at the
    relay: a compromised relay must not be able to invoke a tool the edge never
    agreed to expose. An empty allowlist publishes nothing -- the edge is then a
    no-op until someone lists tools, which is the safe default for a file that
    ships as an example.
    """
    tools_dir = Path(tools_dir)
    allow = {name.strip() for name in exports if str(name).strip()}
    if not allow:
        logger.warning(
            "proxy exports is empty: publishing no tools (list them under exports: in proxy.yaml)"
        )
        return {}

    configs: Dict[str, Tuple[ToolConfig, Path]] = {}
    known: set[str] = set()

    for tool_yaml in sorted(tools_dir.glob("**/tool.yaml")):
        try:
            data = yaml.safe_load(tool_yaml.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            logger.warning("Skipping %s: %s", tool_yaml, exc)
            continue

        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            if not isinstance(entry, dict):
                logger.warning("Skipping %s: entry is not a mapping", tool_yaml)
                continue

            entry = dict(entry)
            name = str(entry.get("name") or tool_yaml.parent.name).strip()
            entry["name"] = name
            known.add(name)

            if name not in allow:
                continue

            runtime = str(entry.get("runtime") or "").strip()
            if runtime == "remote":
                logger.warning("Skipping tool %r: runtime 'remote' is a central-side pointer", name)
                continue
            if runtime == "go":
                logger.warning(
                    "Skipping tool %r: go tools must be pre-built and cannot run on an edge yet "
                    "(the hub compiles them into .bin; an edge has no compile step and the "
                    "workspace is read-only). Publish it from the hub instead.",
                    name,
                )
                continue
            if runtime not in EDGE_RUNTIMES:
                logger.warning(
                    "Skipping tool %r: runtime %r is not executable on an edge (expected one of %s)",
                    name,
                    runtime,
                    ", ".join(sorted(EDGE_RUNTIMES)),
                )
                continue
            if not _SITE_RE.match(name):
                logger.warning("Skipping tool %r: name is not publishable (see protocol.NAME_RE)", name)
                continue
            if name in configs:
                logger.warning("Skipping duplicate tool %r in %s", name, tool_yaml)
                continue

            try:
                config = ToolConfig(**entry)
            except Exception as exc:  # pydantic ValidationError
                logger.warning("Skipping tool %r: invalid tool.yaml (%s)", name, exc)
                continue

            # Reject a catalog entry the relay would refuse, now, so one bad
            # input schema cannot break the whole publish.
            try:
                protocol.validate_tools([_catalog_entry(config)])
            except protocol.ProtocolError as exc:
                logger.warning("Skipping tool %r: %s", name, exc)
                continue

            # Resolved so core.tool_runtime's entrypoint containment check
            # compares two absolute paths.
            configs[name] = (config, tool_yaml.parent.resolve())

    for missing in sorted(allow - known):
        logger.warning("exports lists %r but no matching tool.yaml was found under %s", missing, tools_dir)

    return configs


# ---------------------------------------------------------------- execution


# Names stripped from every tool's environment. The tunnel credential authenticates
# this *site*; a tool that read it could dial the relay, supersede the real edge, and
# answer forwarded calls with forged results.
_SECRET_ENV_NAMES: set[str] = set()


def build_env(tool_dir: Path) -> Dict[str, str]:
    """Sanitized environment with this tool's own ``bin/`` prepended to PATH.

    Built per call, like the hub, so each tool only sees its own helper binaries.
    The proxy's own credentials are removed even if something re-adds them to the
    process environment.
    """
    env = sanitized_env()
    for secret in _SECRET_ENV_NAMES:
        env.pop(secret, None)
    tool_bin = str((Path(tool_dir) / "bin").resolve())
    env["PATH"] = f"{tool_bin}{os.pathsep}{env.get('PATH', '')}"
    return env


def _catalog_entry(config: ToolConfig) -> Dict[str, Any]:
    return {
        "name": config.name,
        "description": config.description,
        "inputs": config.inputs or {},
    }


def _edge_tool(config: ToolConfig) -> protocol.EdgeTool:
    """The tool as published -- i.e. with the relay's input-schema cleaning applied."""
    return protocol.validate_tools([_catalog_entry(config)])[0]


def hello_frame(config_map: Mapping[str, Tuple[ToolConfig, Path]]) -> Dict[str, Any]:
    """The catalog frame. Entries go through the same cleaning the relay applies,
    so the schema the relay publishes is byte-for-byte what the edge validates
    arguments against."""
    return {
        "t": "hello",
        "proto": PROTO_VERSION,
        "edge_version": EDGE_VERSION,
        "tools": [
            _edge_tool(config).as_dict()
            for _, (config, _dir) in sorted(config_map.items())
        ],
    }


def _result_frame(
    call_id: str,
    ms: int,
    *,
    result: Any = None,
    error: Optional[Tuple[str, str]] = None,
) -> Dict[str, Any]:
    frame: Dict[str, Any] = {"t": "result", "id": call_id, "ok": error is None, "ms": ms}
    if error is None:
        frame["result"] = result
    else:
        frame["error"] = {"code": error[0], "message": error[1]}
    return frame


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


async def handle_call(
    config_map: Mapping[str, Tuple[ToolConfig, Path]],
    message: Dict[str, Any],
) -> Dict[str, Any]:
    """Turn one ``call`` frame into a ``result`` frame.

    Never raises: a bad frame or a crashing tool becomes an error result so the
    receive loop survives it. Arguments are re-validated against the published
    schema, independently of whatever the relay already checked.
    """
    started = time.monotonic()
    raw_id = message.get("id")
    fallback_id = raw_id if isinstance(raw_id, str) else ""

    try:
        call = protocol.validate_call(message)
    except protocol.ProtocolError as exc:
        return _result_frame(fallback_id, _elapsed_ms(started), error=("invalid_arguments", str(exc)))

    entry = config_map.get(call["tool"])
    if entry is None:
        return _result_frame(
            call["id"],
            _elapsed_ms(started),
            error=("unknown_tool", f"tool {call['tool']!r} is not exported by this edge"),
        )

    config, tool_dir = entry
    try:
        arguments = protocol.args_for_tool(_edge_tool(config), call["args"])
    except protocol.ProtocolError as exc:
        return _result_frame(call["id"], _elapsed_ms(started), error=("invalid_arguments", str(exc)))

    try:
        # The tool's own timeout (core.tool_runtime) governs; the relay's
        # deadline_ms only bounds its wait for this result.
        result = await tool_runtime.execute_tool(
            config,
            tool_dir,
            arguments,
            env=build_env(tool_dir),
            on_health=None,
        )
    except Exception as exc:
        logger.exception("Tool %r failed on the edge", call["tool"])
        return _result_frame(
            call["id"],
            _elapsed_ms(started),
            error=("tool_error", str(exc) or type(exc).__name__),
        )

    return _result_frame(call["id"], _elapsed_ms(started), result=result)


async def _call_with_deadline(
    config_map: Mapping[str, Tuple[ToolConfig, Path]],
    frame: Dict[str, Any],
) -> Dict[str, Any]:
    """Run one call, aborting it when the caller's ``deadline_ms`` expires.

    The relay stops waiting at ``deadline_ms`` and reports a 504 to its own
    caller. If the edge kept running anyway, an abandoned call would hold one of
    ``MAX_INFLIGHT`` slots for the tool's full timeout (300 s by default).
    Cancelling is safe: ``core.tool_runtime.execute_tool`` kills the child's
    whole process group on ``CancelledError`` (``_kill_process_tree``) and
    re-raises, so nothing survives the cancellation.
    """
    started = time.monotonic()
    try:
        deadline_ms = protocol.validate_call(frame)["deadline_ms"]
    except protocol.ProtocolError:
        # handle_call reports the malformed frame itself; no tool will run, so
        # there is nothing to bound.
        return await handle_call(config_map, frame)

    # The grace makes the edge lose the race on purpose: its error frame reaches
    # the relay just before the relay's own deadline expires, so the caller sees
    # ``edge_timeout`` instead of a bare gateway timeout.
    timeout = max(0.0, deadline_ms / 1000.0 - _DEADLINE_GRACE_S)
    try:
        return await asyncio.wait_for(handle_call(config_map, frame), timeout=timeout)
    except asyncio.TimeoutError:
        call_id = frame.get("id")
        logger.warning("Edge cancelled call %r at its %d ms deadline", call_id, deadline_ms)
        return _result_frame(
            call_id if isinstance(call_id, str) else "",
            _elapsed_ms(started),
            error=("edge_timeout", "edge cancelled the call at its deadline"),
        )


# ---------------------------------------------------------------- transport


class _Session:
    """Catalog plus connection state shared by the serve loop and SIGHUP."""

    def __init__(self, config: ProxyConfig, config_path: Optional[Path] = None) -> None:
        self.config = config
        self.config_path = config_path
        self.tools: Dict[str, Tuple[ToolConfig, Path]] = {}
        self.reconnect = asyncio.Event()
        self.connection: Any = None
        # Set once the relay answered our hello with a welcome: ``--once`` uses it to
        # tell "connected, then the relay hung up" from "never accepted".
        self.accepted = False
        # Set by a ``drain`` frame: a pause the relay asked for, honoured by the
        # reconnect wait in run(). Sleeping here would block in-flight results
        # from being sent while the socket is still open.
        self.reconnect_delay: float = 0.0

    def reload(self) -> None:
        """Re-read proxy.yaml (exports/tools_dir) and rebuild the catalog.

        Re-reading is what makes ``SIGHUP`` useful after editing ``exports``: a
        tool file alone would be filtered out by the in-memory allowlist. Fields that
        cannot be applied to a live tunnel (identity, destination, credentials, the
        sandbox backend) are reported rather than half-applied.
        """
        fresh: Optional[ProxyConfig] = None
        if self.config_path is not None and self.config_path.exists():
            try:
                fresh = load_config(self.config_path)
            except Exception:
                logger.exception(
                    "SIGHUP: could not re-read %s; using the current allowlist",
                    self.config_path,
                )

        if fresh is None:
            self.tools = load_tools(self.config.tools_dir, self.config.exports)
            return

        for name in (
            "site",
            "server_url",
            "token_env",
            "token_file",
            "sandbox",
            "tls_ca_file",
            "tls_cert_file",
            "tls_key_file",
        ):
            if getattr(fresh, name) != getattr(self.config, name):
                logger.warning(
                    "SIGHUP: %s changes need a restart; keeping the current value", name
                )

        # Build the catalog first: if it raises, handle_sighup keeps the old one and
        # the config must still describe what is actually published.
        candidate = replace(
            self.config, exports=fresh.exports, tools_dir=fresh.tools_dir
        )
        new_tools = load_tools(candidate.tools_dir, candidate.exports)
        self.config = candidate
        self.tools = new_tools

    def request_reconnect(self, reason: str = "") -> None:
        """Republish by reconnecting: closing the socket makes the loop redial."""
        self.reconnect.set()
        connection = self.connection
        if connection is None:
            return
        logger.info("Reconnecting (%s)", reason or "requested")

        async def _close() -> None:
            try:
                await connection.close(code=1000, reason=(reason or "reconnect")[:120])
            except Exception:
                logger.debug("Failed to close the edge connection", exc_info=True)

        asyncio.create_task(_close())


def handle_sighup(signum: int = None, frame: Any = None) -> None:
    """Reload the tool catalog from disk and republish it.

    The relay keys its registry from the ``hello`` frame, so a reconnect is the
    simplest correct republish: no merge logic, no partial catalogs.
    """
    session = _active_session
    if session is None:
        logger.warning("SIGHUP received before the edge session started; ignoring")
        return

    logger.info("SIGHUP: reloading tools from %s", session.config.tools_dir)
    try:
        session.reload()
    except Exception:
        # Keep serving the previous catalog rather than dropping every tool.
        logger.exception("SIGHUP: tool reload failed; keeping the current catalog")
        return

    loop = _active_loop
    if loop is not None and loop.is_running():
        loop.call_soon_threadsafe(session.request_reconnect, "SIGHUP")
    else:
        session.reconnect.set()


def _install_signal_handlers() -> None:
    if threading.current_thread() is not threading.main_thread():
        logger.debug("Not the main thread; SIGHUP reload disabled")
        return
    if not hasattr(signal, "SIGHUP"):
        return
    signal.signal(signal.SIGHUP, handle_sighup)


def _connect_factory():
    """Resolve the websockets client lazily (keeps module import side-effect free)."""
    try:
        from websockets.asyncio.client import connect
    except ImportError:  # websockets < 13
        from websockets.client import connect
    return connect


def _header_kwarg(connect) -> str:
    """websockets renamed ``extra_headers`` to ``additional_headers`` in 14."""
    parameters = inspect.signature(connect).parameters
    if "additional_headers" in parameters:
        return "additional_headers"
    if "extra_headers" in parameters:
        return "extra_headers"
    return ""


def _resolve_and_forget_token(config: ProxyConfig) -> str:
    """Read the enrollment token, then take it out of the process environment.

    Tools inherit ``os.environ`` through ``sanitized_env``; the token has no business
    there once the handshake owns it.
    """
    token = _resolve_token(config)
    _SECRET_ENV_NAMES.add(config.token_env)
    os.environ.pop(config.token_env, None)
    return token


def _consume_token_file(path: Path) -> None:
    """Remove the token file once the handshake owns its value.

    A docker secret or a copy in a writable tmpfs can be unlinked, which is the point:
    a tool running as the proxy's uid can read ``/proc/<pid>/environ`` but not the
    heap of a process it may not ptrace. A bind-mounted file cannot be unlinked --
    warn rather than fail the handshake.
    """
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.warning(
            "token file %s could not be removed after reading (%s); a tool running as "
            "the same uid may still read it -- mount it as a docker secret",
            path,
            exc,
        )
    else:
        logger.info(
            "token file %s was removed after reading; re-provision it before restarting "
            "the proxy (a read-only secret mount is left in place instead)",
            path,
        )


def _resolve_token(config: ProxyConfig) -> str:
    path_value = (os.getenv("TRELLIS_EDGE_TOKEN_FILE") or config.token_file or "").strip()
    if path_value:
        path = Path(path_value).expanduser()
        try:
            token = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError(f"proxy config: cannot read token_file {path}: {exc}") from exc
        if not token:
            raise ValueError(f"proxy config: token_file {path} is empty")
        _consume_token_file(path)
        return token

    token = os.getenv(config.token_env, "").strip()
    if not token:
        raise ValueError(
            "proxy config: edge token is not set (set token_file: / a TRELLIS_EDGE_TOKEN_FILE, "
            f"or the {config.token_env!r} environment variable)"
        )
    return token


def _connect_kwargs(config: ProxyConfig, token: str, *, connect=None) -> Dict[str, Any]:
    """Keyword arguments for the websockets client's ``connect()``.

    ``max_size`` is not optional: the client default is 1 MiB, while a legal
    ``call`` frame can exceed that (``MAX_ARGS_BYTES`` is 1 MiB on its own, plus
    the envelope), and the client would close the connection with 1009 instead
    of running the call.
    """
    connect = connect or _connect_factory()
    header_kwarg = _header_kwarg(connect)
    if not header_kwarg:
        # Failing silently here means no Authorization header at all: the relay
        # rejects every attempt and the operator sees an endless 401 loop.
        raise ValueError(
            "proxy: the installed websockets client exposes neither additional_headers "
            "nor extra_headers; upgrade websockets (>= 14)"
        )
    kwargs: Dict[str, Any] = {
        "subprotocols": [SUBPROTOCOL],
        "max_size": protocol.MAX_FRAME_BYTES,
        header_kwarg: {"Authorization": f"Bearer {token}"},
    }
    ssl_context = _build_ssl_context(config)
    if ssl_context is not None:
        kwargs["ssl"] = ssl_context
    return kwargs


def _build_ssl_context(config: ProxyConfig) -> Any:
    """Client TLS context for mTLS, or None for a plain CA-verified connection.

    ``websockets`` builds a default context from ``SSL_CERT_FILE``, which covers a
    custom CA but has no env hook for a *client certificate*. Presenting one needs an
    explicit ``load_cert_chain`` passed as ``ssl=``.
    """
    if not (config.tls_ca_file or config.tls_cert_file):
        return None

    import ssl

    context = ssl.create_default_context(cafile=config.tls_ca_file or None)
    if config.tls_cert_file and config.tls_key_file:
        context.load_cert_chain(config.tls_cert_file, config.tls_key_file)
    return context


def _next_backoff(current: float, uptime_s: float, close_code: Optional[int]) -> float:
    """Backoff for the next reconnect, from this attempt's outcome.

    * A session that stayed up for ``_BACKOFF_STABLE_S`` resets to the minimum:
      a healthy connection that later dropped is not a failure streak.
    * 4403 (revoked) and 4409 (superseded) cannot be retried away, so they jump
      straight to the maximum instead of hammering the relay once a second.
    * Anything else doubles, capped at the maximum.
    """
    if close_code in _TERMINAL_CLOSE_CODES:
        return _BACKOFF_MAX_S
    if uptime_s >= _BACKOFF_STABLE_S:
        return _BACKOFF_MIN_S
    return min(max(current, _BACKOFF_MIN_S) * 2, _BACKOFF_MAX_S)


def _terminal_close_message(close_code: int, site: str) -> str:
    """One operator-facing line explaining a close we should not retry fast."""
    if close_code == protocol.CLOSE_REVOKED:
        return (
            f"Edge {site!r} was closed by the relay (code {close_code}, revoked): the token "
            f"is no longer valid and an operator must issue a new one. Retrying only at the "
            f"maximum backoff ({_BACKOFF_MAX_S:.0f}s)."
        )
    return (
        f"Edge {site!r} was closed by the relay (code {close_code}, superseded): another "
        f"instance is probably connected with this site's token. Retrying only at the "
        f"maximum backoff ({_BACKOFF_MAX_S:.0f}s)."
    )


async def _serve(session: _Session, ws) -> None:
    """Handshake, then pump frames until the connection closes."""
    await ws.send(protocol.encode(hello_frame(session.tools)))

    first = protocol.decode(await ws.recv(), protocol.RELAY_FRAMES)
    if first.get("t") != "welcome":
        raise protocol.ProtocolError(f"expected 'welcome', got {first.get('t')!r}")
    welcome_site = first.get("site")
    if welcome_site and welcome_site != session.config.site:
        logger.warning(
            "Relay identified this edge as site %r but proxy.yaml declares %r: the token "
            "probably belongs to another site",
            welcome_site,
            session.config.site,
        )
    session.accepted = True
    logger.info(
        "Welcome from relay: site=%s heartbeat=%ss inflight=%s",
        welcome_site,
        first.get("heartbeat_s", protocol.HEARTBEAT_S),
        first.get("max_inflight", MAX_INFLIGHT),
    )

    inflight = asyncio.Semaphore(MAX_INFLIGHT)
    tasks: set[asyncio.Task] = set()

    async def _run_call(frame: Dict[str, Any]) -> None:
        try:
            result = await _call_with_deadline(session.tools, frame)
            await ws.send(protocol.encode(result))
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Failed to answer a call frame")
        finally:
            inflight.release()

    try:
        async for raw in ws:
            try:
                frame = protocol.decode(raw, protocol.RELAY_FRAMES)
            except protocol.ProtocolError as exc:
                logger.warning("Closing edge connection: %s", exc)
                await ws.close(code=exc.close_code, reason=str(exc)[:120])
                raise

            frame_type = frame["t"]

            if frame_type == "ping":
                # Deliberately ignored: answering app-level pings made the edge
                # and the relay echo each other forever. Liveness is the
                # WebSocket control-frame ping/pong, not this.
                continue
            if frame_type == "welcome":
                continue  # a repeated welcome is harmless
            if frame_type == "catalog":
                # Force a re-publish by reconnecting, same as SIGHUP.
                session.reconnect.set()
                await ws.close(code=1000, reason="catalog")
                return
            if frame_type == "drain":
                reconnect_after = frame.get("reconnect_after_s", 0)
                try:
                    delay = max(0.0, min(float(reconnect_after), _BACKOFF_MAX_S))
                except (TypeError, ValueError):
                    delay = 0.0
                logger.info("Relay requested drain; reconnecting in %.1fs", delay)
                # Close now, pause in the reconnect wait: sleeping here would
                # keep the socket open but let no in-flight result through.
                session.reconnect_delay = delay
                session.reconnect.set()
                await ws.close(code=1000, reason="drain")
                return

            # Only "call" is left: the closed set was validated by decode().
            if inflight.locked():
                await ws.send(
                    protocol.encode(
                        _result_frame(
                            frame.get("id") if isinstance(frame.get("id"), str) else "",
                            0,
                            error=("edge_overloaded", f"edge is at {MAX_INFLIGHT} in-flight calls"),
                        )
                    )
                )
                continue

            await inflight.acquire()
            task = asyncio.create_task(_run_call(frame))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


async def run(
    config: ProxyConfig, *, once: bool = False, config_path: Optional[Path] = None
) -> None:
    """Connect, serve, and reconnect with jittered exponential backoff.

    ``once`` performs a single attempt and re-raises its failure, which is what
    ``trellis-proxy --once`` and diagnostics need.
    """
    global _active_session, _active_loop

    if config.sandbox != "auto":
        os.environ.setdefault("SANDBOX_BACKEND", config.sandbox)

    token = _resolve_and_forget_token(config)
    connect = _connect_factory()

    # Tells shared core modules (core/tunables) not to look for etcd: an edge is a
    # standalone install and the failed refresh would log forever.
    os.environ.setdefault("TRELLIS_EDGE_MODE", "1")

    writable = sandbox.writable_root()
    if not writable.exists():
        # Every landlock-sandboxed call binds this path. A tools-only mount (or a
        # read-only workspace) otherwise fails with an opaque "Sandbox unavailable".
        logger.warning(
            "sandbox writable root %s does not exist; mount the workspace at that path "
            "(see deploy/proxy/docker-compose.yml)",
            writable,
        )

    session = _Session(config, config_path)
    session.reload()
    _active_session = session
    _active_loop = asyncio.get_running_loop()

    backoff = _BACKOFF_MIN_S
    attempt = 0
    logged_failure = False
    reported_terminal: set[int] = set()

    try:
        while True:
            connected = False
            uptime = 0.0
            close_code: Optional[int] = None
            ws = None
            try:
                async with connect(
                    config.server_url,
                    **_connect_kwargs(config, token, connect=connect),
                ) as ws:
                    connected = True
                    connected_at = time.monotonic()
                    session.connection = ws
                    logged_failure = False
                    logger.info(
                        "Connected to %s as site %r (%d tool(s))",
                        config.server_url,
                        config.site,
                        len(session.tools),
                    )
                    try:
                        await _serve(session, ws)
                    finally:
                        # Measured here, not inferred later: a close code is
                        # only meaningful together with how long the session
                        # actually stayed up.
                        uptime = time.monotonic() - connected_at
                        close_code = getattr(ws, "close_code", None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if once:
                    raise
                if close_code in _TERMINAL_CLOSE_CODES:
                    # Log once per reason: a revoked token or a duplicate site
                    # redials every minute and must not repeat this every time.
                    if close_code not in reported_terminal:
                        reported_terminal.add(close_code)
                        logger.error(_terminal_close_message(close_code, config.site))
                elif connected:
                    logger.warning("Edge %r disconnected: %s", config.site, exc)
                elif not logged_failure:
                    logger.warning("Edge %r connection failed: %s", config.site, exc)
                logged_failure = True
            finally:
                session.connection = None

            if once:
                if not session.accepted:
                    raise RuntimeError(
                        "edge session ended before the relay accepted the catalog "
                        f"(close code {close_code}); see the log above"
                    )
                return

            # A stable session was a success, not a failure streak: start the
            # next wait from the minimum instead of inheriting the old delay.
            if uptime >= _BACKOFF_STABLE_S:
                attempt = 0
            attempt += 1
            backoff = _next_backoff(backoff, uptime, close_code)

            requested_delay = session.reconnect_delay
            session.reconnect_delay = 0.0
            delay = requested_delay or backoff * (0.5 + random.random())
            try:
                if requested_delay:
                    # A drain asked for this pause: honour it even though the
                    # reconnect event is already set, so the relay's rolling
                    # restart is not thundered by every edge at once.
                    await asyncio.sleep(delay)
                    logger.info("Reconnecting after drain in %.1fs", delay)
                else:
                    # A reload/nudge wakes the wait, so an operator does not
                    # have to wait out the backoff to republish.
                    await asyncio.wait_for(session.reconnect.wait(), timeout=delay)
                    logger.info("Reconnecting immediately")
            except asyncio.TimeoutError:
                logger.info("Reconnect attempt %d in %.1fs", attempt, delay)
            finally:
                session.reconnect.clear()
    finally:
        _active_session = None
        _active_loop = None


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="trellis-proxy",
        description="Expose local Trellis tools to the central relay over an outbound WebSocket.",
    )
    parser.add_argument("--config", help=f"path to proxy.yaml (default: ${CONFIG_ENV} or ./proxy.yaml)")
    parser.add_argument(
        "--once",
        action="store_true",
        help="single connection attempt; exit non-zero on failure (diagnostics)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # The websockets client logs every request header, Authorization included, at
    # DEBUG. A troubleshooting session must not write the site credential to the logs.
    logging.getLogger("websockets").setLevel(
        max(logging.INFO, logging.getLogger().level)
    )

    config = load_config(args.config)
    _install_signal_handlers()
    resolved = _config_path(args.config)
    # Pass the path whenever it exists, not only when it was spelled out: the implicit
    # ./proxy.yaml must be just as reloadable as an explicit --config.
    asyncio.run(
        run(
            config,
            once=args.once,
            config_path=resolved[0] if resolved[0].exists() else None,
        )
    )


if __name__ == "__main__":
    main()
