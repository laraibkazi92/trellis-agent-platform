# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge entrypoint for the trellis-proxy tool tunnel.

Runs on a customer VM that can dial out but accepts no inbound connections. It
loads a local ``proxy.yaml`` plus ``tool.yaml`` files, publishes their catalog to
the central relay over a WebSocket, and executes the ``call`` frames the relay
forwards. Execution goes through ``core.tool_runtime`` -- the same sandboxed
subprocess path the hub uses.

Deliberately independent of the framework's control plane: no etcd, no FastAPI,
no identity manager. The only shared contracts are ``services.edge_relay.protocol``
and ``core.tool_runtime``. Importing this module must stay side-effect free.

MCP export (``export_mcps``) lives in ``core.proxy_mcp``; the MCP client stack is
imported lazily there, so a tools-only edge never loads it. Credentials for both
tools and MCP servers are resolved by ``core.edge_user_secrets``: one shared,
edge-local file per export, plus per-user sets that central stores only as
ciphertext sealed to this edge's public key (``core.edge_crypto``). Nothing here
sends a credential value to central, and the private key never leaves this VM.

Trust (v0.7.2): no process on this host verifies an agent token and none holds
``AGENT_TOKEN_SECRET``. The relay authenticated the caller, verified the token and
built the frame identity from its claims; this process trusts that identity over the
authenticated tunnel and passes it on to the edge runner, which does the same over the
``RUNNER_TOKEN``-authenticated socket.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import logging
import os
import random
import signal
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

import yaml

from core import (
    edge_crypto,
    edge_env,
    edge_keypair,
    edge_secrets_central,
    edge_user_secrets,
    proxy_mcp,
    tool_runtime,
)
from core.edge_keypair import EdgeKey, EdgeKeyError
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

# The default enrollment-token variable. Kept in ``core.edge_env`` so stripping it is
# intrinsic to the env scoper; re-exported here because callers of this module name it.
DEFAULT_TOKEN_ENV = edge_env.DEFAULT_TOKEN_ENV


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
# Retrying these can never help on their own: each needs an operator action, so they
# jump straight to the maximum backoff and get one diagnostic line instead of a
# "disconnected" warning per retry. See _next_backoff / _terminal_close_message.
_TERMINAL_CLOSE_CODES = frozenset({
    protocol.CLOSE_REVOKED,
    protocol.CLOSE_SUPERSEDED,
    # 4001: this edge speaks a newer tunnel protocol than the relay. Nothing the edge
    # can do -- central has to be upgraded first (docs/upgrading.md).
    protocol.CLOSE_VERSION,
})

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
    token_env: str = DEFAULT_TOKEN_ENV
    # Preferred over ``token_env``: a file is not part of the exec environment, so it
    # never shows up in /proc/<pid>/environ where a tool running as the same uid can
    # read it. Read once, then unlinked when the mount allows it.
    token_file: Optional[str] = None
    tools_dir: Path = Path("workspace/tools")
    exports: List[str] = field(default_factory=list)
    # Credential mode per exported tool, from a mapping ``exports`` entry. Kept apart
    # from ``exports`` so the allowlist stays a plain list of names everywhere.
    export_modes: Dict[str, str] = field(default_factory=dict)
    # MCP servers are a second, independent allowlist: an entry is a bare name or a
    # mapping with include_tools/exclude_tools/credential_mode/session settings.
    mcps_dir: Path = Path("workspace/mcps")
    export_mcps: List[Any] = field(default_factory=list)
    # Edge-local shared credential store (never sent to central, never in etcd): one
    # ``<tool-or-mcp>.env`` per exported item. Per-user credentials are sealed blobs
    # fetched from central and opened with the edge key below.
    secrets_dir: Path = edge_user_secrets.DEFAULT_SECRETS_DIR
    # Opt-out of the edge env allowlist: true restores the v0.4 denylist
    # (sanitized_env) for tools that cannot declare every key they read.
    env_passthrough: bool = False
    # Control socket of this edge's runner (the only component with a container
    # daemon). Every tool call and stdio MCP session goes through it.
    runner_socket: str = "/run/trellis/runner.sock"
    # Optional mutual TLS: the relay's CA plus this edge's client certificate.
    # Without these, a relay that enforces EDGE_MTLS_CA rejects every handshake.
    tls_ca_file: Optional[str] = None
    tls_cert_file: Optional[str] = None
    tls_key_file: Optional[str] = None
    # Publish summaries (no tool ``inputs``, no MCP ``inputSchema``) and answer the
    # relay's ``tool_detail`` / ``mcp_tool_detail`` reads from the local catalog.
    # A big catalog otherwise costs the relay a multi-hundred-KB hello every reconnect.
    lazy_catalog: bool = False


# ---------------------------------------------------------------- configuration


def _config_path(path: str | Path | None) -> Tuple[Path, bool]:
    """Resolve where the config should come from, and whether it was explicit."""
    if path is not None:
        return Path(path).expanduser(), True
    from_env = os.getenv(CONFIG_ENV, "").strip()
    if from_env:
        return Path(from_env).expanduser(), True
    return DEFAULT_CONFIG_PATH, False


_TRUE_FLAGS = frozenset({"1", "true", "yes", "on"})
_FALSE_FLAGS = frozenset({"0", "false", "no", "off"})


def _path_setting(
    raw: Mapping[str, Any], yaml_key: str, env_name: str, default: Path
) -> Path:
    """One directory setting: env wins over the file, then the built-in default."""
    value = os.getenv(env_name) or raw.get(yaml_key)
    return Path(str(value)).expanduser() if value else default


def _parse_exports(raw: Any) -> Tuple[List[str], Dict[str, str]]:
    """Normalize the ``exports`` block into names plus each tool's credential mode.

    An entry is a bare name (``shared``) or ``{name, credential_mode}`` -- the mode
    decides which credential file a tool call reads (plan §7 Phase 5). Both forms
    validate at load: a typo must be a startup error naming the entry, not a tool
    that silently reads the wrong store.
    """
    if raw in (None, []):
        return [], {}
    if not isinstance(raw, list):
        raise ValueError(
            "proxy config: 'exports' must be a list of tool names or {name, credential_mode} mappings"
        )

    names: List[str] = []
    modes: Dict[str, str] = {}
    for entry in raw:
        if isinstance(entry, str):
            name, mode = entry.strip(), edge_user_secrets.DEFAULT_MODE
            if not name:
                continue
        elif isinstance(entry, Mapping):
            options = dict(entry)
            unknown = set(options) - {"name", "credential_mode"}
            if unknown:
                raise ValueError(
                    f"proxy config: exports entry {options.get('name')!r} has unknown "
                    f"key(s) {', '.join(sorted(map(str, unknown)))}"
                )
            raw_name = options.get("name")
            name = raw_name.strip() if isinstance(raw_name, str) else raw_name
            mode = str(options.get("credential_mode") or edge_user_secrets.DEFAULT_MODE)
            mode = mode.strip().lower()
            if mode not in edge_user_secrets.CREDENTIAL_MODES:
                raise ValueError(
                    f"proxy config: exports entry {name!r} credential_mode must be one "
                    f"of {', '.join(sorted(edge_user_secrets.CREDENTIAL_MODES))}"
                )
        else:
            raise ValueError(
                "proxy config: exports entries must be a name or a mapping, "
                f"got {type(entry).__name__}"
            )
        if not isinstance(name, str) or not name:
            raise ValueError("proxy config: every exports entry needs a non-empty 'name'")
        names.append(name)
        modes[name] = mode
    return names, modes


def _flag(value: Any, source: str) -> bool:
    """Parse a YAML boolean; an unrecognised value keeps the safe default (off)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _TRUE_FLAGS:
            return True
        if normalized in _FALSE_FLAGS:
            return False
    if value is None or value == "":
        return False
    logger.warning("proxy config: %s is not a boolean (got %r); using false", source, value)
    return False


def _env_passthrough(default: bool) -> bool:
    """``TRELLIS_EDGE_ENV_PASSTHROUGH`` mirrors ``env_passthrough:`` for env-only deploys.

    An unparseable value is ignored rather than a startup failure: it is a policy
    toggle, and falling back to the file keeps the edge serving.
    """
    raw = (os.getenv("TRELLIS_EDGE_ENV_PASSTHROUGH") or "").strip()
    if not raw:
        return default
    normalized = raw.lower()
    if normalized in _TRUE_FLAGS:
        return True
    if normalized in _FALSE_FLAGS:
        return False
    logger.warning(
        "TRELLIS_EDGE_ENV_PASSTHROUGH=%r is not a boolean; keeping env_passthrough: %s",
        raw,
        str(default).lower(),
    )
    return default


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
    mcps_dir = os.getenv("TRELLIS_EDGE_MCPS_DIR") or raw.get("mcps_dir")

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

    exports, export_modes = _parse_exports(raw.get("exports"))

    export_mcps = proxy_mcp.validate_export_mcps(raw.get("export_mcps"))

    # v0.7.1: the runner is the only execution path, so an edge `proxy.yaml` that
    # still carries the v0.6 selector is accepted and ignored rather than rejected
    # -- an unreadable config would take every exported tool offline on upgrade.
    if "sandbox" in raw:
        logger.warning(
            "proxy config: the 'sandbox' setting is ignored; the edge always runs "
            "tools via the runner. Remove it from %s.",
            config_path,
        )

    env_passthrough = _env_passthrough(_flag(raw.get("env_passthrough"), "env_passthrough"))
    lazy_catalog = _flag(raw.get("lazy_catalog"), "lazy_catalog")

    token_env = str(raw.get("token_env") or DEFAULT_TOKEN_ENV).strip() or DEFAULT_TOKEN_ENV
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
        export_modes=export_modes,
        mcps_dir=Path(mcps_dir).expanduser() if mcps_dir else Path("workspace/mcps"),
        export_mcps=export_mcps,
        secrets_dir=_path_setting(
            raw, "secrets_dir", "TRELLIS_EDGE_SECRETS_DIR", edge_user_secrets.DEFAULT_SECRETS_DIR
        ),
        env_passthrough=env_passthrough,
        runner_socket=str(
            os.getenv("RUNNER_SOCKET")
            or raw.get("runner_socket")
            or "/run/trellis/runner.sock"
        ),
        tls_ca_file=str(tls_ca_file) if tls_ca_file else None,
        tls_cert_file=str(tls_cert_file) if tls_cert_file else None,
        tls_key_file=str(tls_key_file) if tls_key_file else None,
        lazy_catalog=lazy_catalog,
    )


def _invalid_declared_keys(config: Any) -> List[str]:
    """Declared ``secrets``/``variables`` names that are not usable env identifiers.

    The relay validates ``hello.credential_keys`` against ``^[A-Za-z_][A-Za-z0-9_]*$``
    and closes a tunnel that carries anything else -- and the edge would then redial
    with the same frame forever, taking **every** healthy export offline. So the edge
    checks its own catalog first and skips only the offending manifest (v0.7.1).
    """
    return sorted(
        key
        for key in edge_env.declared_keys_for(config)
        if len(key) > protocol.MAX_ENV_NAME_CHARS or not protocol.ENV_NAME_RE.match(key)
    )


def _skip_invalid_declared_keys(kind: str, name: str, config: Any) -> bool:
    """Log and report whether this export must be skipped for its declared names."""
    invalid = _invalid_declared_keys(config)
    if not invalid:
        return False
    logger.warning(
        "Skipping %s %r: declared key(s) %s are not valid environment variable names "
        "(expected ^[A-Za-z_][A-Za-z0-9_]*$). The relay refuses a credential list "
        "carrying them, so publishing this export would close the tunnel for every "
        "other export. Rename the key(s) in the manifest.",
        kind,
        name,
        ", ".join(repr(key) for key in invalid),
    )
    return True


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
            catalog_entry = protocol.validate_tools([_catalog_entry(config)])
            if not catalog_entry:
                logger.warning(
                    "Skipping tool %r: %s", name, catalog_entry.errors[0].describe()
                )
                continue
            # Same rule for the declared credential names: a name the relay's
            # credential-key validator refuses would close the tunnel for everything.
            if _skip_invalid_declared_keys("tool", name, config):
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


def _manifest_name(config: Any, tool_dir: Optional[Path] = None) -> str:
    """The shared-credential file stem for a manifest: its name, else its directory."""
    name = None
    if isinstance(config, Mapping):
        name = config.get("name")
    elif config is not None:
        name = getattr(config, "name", None)
    if isinstance(name, str) and name.strip():
        return name.strip()
    return Path(tool_dir).name if tool_dir else ""


def _credential_store(config: Optional["ProxyConfig"]) -> edge_user_secrets.CredentialStore:
    """The edge's stores for this call; defaults when no config was threaded through."""
    return edge_user_secrets.CredentialStore.from_config(config)


# One warning per process for a missing key: the edge still serves shared-credential
# tools, so a reconnect loop must not repeat it.
_NO_EDGE_KEY_WARNED = False


def _load_edge_keys() -> Tuple[Optional[EdgeKey], Optional[EdgeKey]]:
    """Load the current edge key plus the rotation overlap, if either exists.

    A missing or unusable key does not stop the edge: tools with shared credentials
    still work. It does mean every sealed per-user call is refused, with one warning
    naming the fix (``trellis-proxy edge-keygen``).
    """
    global _NO_EDGE_KEY_WARNED
    try:
        current = edge_keypair.load()
    except (EdgeKeyError, OSError) as exc:
        if not _NO_EDGE_KEY_WARNED:
            _NO_EDGE_KEY_WARNED = True
            logger.warning(
                "No usable edge credential key: browser-sealed per-user credentials "
                "will be refused until one exists. Run `trellis-proxy edge-keygen` "
                "(or set EDGE_PRIVATE_KEY_PATH). Reason: %s",
                exc,
            )
        return None, None
    try:
        previous = edge_keypair.load_old()
    except (EdgeKeyError, OSError) as exc:
        logger.warning("Ignoring the retained edge key: %s", exc)
        previous = None
    return current, previous


def _resolve_edge_keys(
    edge_key: Optional[EdgeKey], prev_edge_key: Optional[EdgeKey]
) -> Tuple[Optional[EdgeKey], Optional[EdgeKey]]:
    """Prefer the caller-supplied keys; fall back to the files for the ones omitted."""
    if edge_key is not None and prev_edge_key is not None:
        return edge_key, prev_edge_key
    current, previous = _load_edge_keys()
    return edge_key or current, prev_edge_key or previous


def _open_for_call(
    call: Mapping[str, Any],
    *,
    site: str,
    kind: str,
    name: str,
    edge_key: Optional[EdgeKey],
    prev_edge_key: Optional[EdgeKey],
) -> Optional[Dict[str, str]]:
    """Open this call's sealed blob for exactly one ``(site, kind, name, identity)``.

    ``None`` means the caller has no sealed blob (the shared/per-user-shared path).
    A rotation keeps the previous key readable for the overlap window, so a blob the
    browser sealed before the rotation still opens -- but only as that same target and
    identity, which is what the AAD enforces. A refusal is never retried against a
    different target.
    """
    blob = call.get("sealed")
    if blob is None:
        return None

    identity = edge_secrets_central.sealed_identity(call.get("user"), call.get("user_email"))
    if edge_key is None:
        raise edge_crypto.SealedError(
            edge_crypto.CREDENTIAL_REJECTED,
            "this edge has no credential key configured; sealed credentials are unusable",
        )

    # Pick the key that actually owns the blob instead of trying the current key and
    # falling back on any failure. The fingerprint is public; comparing it first keeps
    # the rotation overlap working, gives a retired key a message the user can act on
    # ("re-enter the credentials"), and never runs an RSA unwrap against a key that
    # cannot own the ciphertext.
    edge_crypto.validate_blob(blob)
    key_fp = blob["key_fp"]
    owner = next(
        (
            candidate
            for candidate in (edge_key, prev_edge_key)
            if candidate is not None and candidate.fingerprint == key_fp
        ),
        None,
    )
    if owner is None:
        raise edge_crypto.SealedError(
            edge_crypto.CREDENTIAL_REJECTED,
            "sealed credential belongs to an edge key this edge no longer holds; "
            "re-enter the credential set",
        )
    return edge_crypto.open_sealed(
        blob, owner, site=site, kind=kind, name=name, identity=identity
    )


def build_env(
    tool_dir: Path,
    config: Optional[ToolConfig] = None,
    identity: Optional[Mapping[str, Optional[str]]] = None,
    *,
    passthrough: bool = False,
    token_env: Optional[str] = None,
    credentials: Optional[edge_user_secrets.CredentialStore] = None,
    credential_mode: str = edge_user_secrets.DEFAULT_MODE,
    email: Optional[str] = None,
    site: Optional[str] = None,
    sealed: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """Scoped environment with this tool's own ``bin/`` prepended to PATH.

    Built per call, like the hub, so each tool only sees its own helper binaries and
    the env names its ``tool.yaml`` declares -- not whatever the edge container
    carries. Declared keys come from the credential chain
    (``core.edge_user_secrets``): a caller's sealed blob when there is one, else the
    shared file -- for a declared **secret** the shared file is the only non-sealed
    source (v0.7.1: the process environment is not read for one), while a declared
    **variable** falls back to the process env. An empty/whitespace file value counts
    as unset (so it cannot mask a real one). ``passthrough`` restores the v0.4
    denylist for a tool whose keys are not all declared; the tunnel credential is
    dropped in both modes, even if something re-adds it to the process environment.

    ``credential_mode`` is the operator's policy for this tool and may raise
    ``MissingCredentials`` (``per_user_required``): callers must turn that into a
    ``missing_credentials`` error result **without** running the tool.

    ``sealed`` is the decrypted per-user mapping (``None`` = no blob). When it is not
    None the per-user branch is all-or-nothing: only the secret names it carries reach
    the env. Either way a declared secret the resolved set omits is removed from the
    inherited env even with ``passthrough`` -- the process environment and the shared
    file never fill the gap. Declared ``variables`` keep coming from the shared
    file / process env.

    ``identity`` carries the caller the hub resolved centrally; an absent or empty
    value is dropped rather than exported as ``""`` so a tool can test presence.
    """
    store = credentials or _credential_store(None)
    decided_mode = edge_user_secrets.DEFAULT_MODE if credential_mode is None else credential_mode
    resolved = store.resolve(
        config,
        name=_manifest_name(config, tool_dir),
        email=email if email is not None else (identity or {}).get("user_email"),
        site=site or "",
        mode=decided_mode,
        sealed=sealed,
    )

    env = edge_env.scoped_env(
        (),
        passthrough=passthrough,
        secret_env_names={edge_env.DEFAULT_TOKEN_ENV, token_env or edge_env.DEFAULT_TOKEN_ENV}
        | _SECRET_ENV_NAMES,
    )
    # Declared credentials win over the process env (``shared`` mode's whole point);
    # only declared names are ever in ``resolved``.
    env.update(resolved)
    # A declared secret is never read from the edge process env -- not under
    # ``passthrough`` and not in ``shared`` mode: a key the store (or the caller's
    # sealed set) did not supply must stay absent instead of silently surviving from
    # the container environment.
    for key in edge_user_secrets.declared_secret_keys(config):
        if key not in resolved:
            env.pop(key, None)
    # A credential file must not reintroduce a framework control-plane name.
    edge_env.strip_framework_names(env, token_env=token_env)
    # Caller identity is per frame: never inherit a stale one from ``TRELLIS_*``.
    env.pop("TRELLIS_USER_ID", None)
    env.pop("TRELLIS_USER_EMAIL", None)
    if identity:
        for var, key in (
            ("TRELLIS_USER_ID", "user"),
            ("TRELLIS_USER_EMAIL", "user_email"),
        ):
            value = identity.get(key)
            if isinstance(value, str) and value:
                env[var] = value
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
    catalog = protocol.validate_tools([_catalog_entry(config)])
    if not catalog:
        # The loader already dropped an unpackable manifest; reaching this means a
        # caller built a ToolConfig in memory that the relay would refuse.
        raise protocol.ProtocolError(catalog.errors[0].describe())
    return catalog[0]


def _hello_tool_entry(config: ToolConfig, *, lazy_catalog: bool) -> Dict[str, Any]:
    """One ``hello.tools`` entry: full schema, or the summary a lazy catalog sends."""
    tool = _edge_tool(config)
    if not lazy_catalog:
        return tool.as_dict()
    return {
        "name": tool.name,
        "description": tool.description[: protocol.MAX_TOOL_SUMMARY_CHARS],
    }


def _hello_mcp_entry(
    catalog: protocol.EdgeMcp, *, lazy_catalog: bool
) -> Dict[str, Any]:
    """One ``hello.mcps`` entry; a lazy catalog drops every ``inputSchema``."""
    entry = catalog.as_dict()
    if lazy_catalog:
        for tool in entry["tools"]:
            tool.pop("inputSchema", None)
    return entry


def _credential_key_lists(config: Any) -> Dict[str, List[str]]:
    """The names a manifest exposes to the browser's seal form.

    ``secret_keys`` are the only names a user may seal; ``variable_keys`` are shown
    read-only because endpoints come from the edge's own config (plan §6 invariant 10).
    This is the same split the central write gate applies, so a blob accepted there
    can always be resolved here.
    """
    return {
        "secret_keys": sorted(edge_user_secrets.declared_secret_keys(config)),
        "variable_keys": sorted(edge_user_secrets.declared_variable_keys(config)),
    }


def credential_keys(
    config_map: Mapping[str, Tuple[ToolConfig, Path]],
    mcp_entries: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Dict[str, List[str]]]:
    """``{export_name: {secret_keys, variable_keys}}`` for every exported target.

    The relay publishes ``<site>__<name>`` configs without ``secrets``/``variables``
    (the edge owns them), so this hello field is what lets central's pubkey endpoint
    render the right inputs. Names are the bare export names, not registry names.

    Last gate before the frame leaves: a target whose declared names are not valid env
    identifiers is omitted with a log rather than published, because the relay closes
    the tunnel over one bad name and the edge would redial into the same refusal
    forever (v0.7.1). The loaders already skip such an export, so this only fires when
    a caller bypasses them.
    """
    keys: Dict[str, Dict[str, List[str]]] = {}
    for name, (config, _dir) in config_map.items():
        if _skip_invalid_declared_keys("tool", name, config):
            continue
        keys[name] = _credential_key_lists(config)
    for name, entry in (mcp_entries or {}).items():
        config = getattr(entry, "config", entry)
        if _skip_invalid_declared_keys("mcp", name, config):
            continue
        keys[name] = _credential_key_lists(config)
    return keys


def hello_frame(
    config_map: Mapping[str, Tuple[ToolConfig, Path]],
    mcp_catalogs: Optional[Mapping[str, protocol.EdgeMcp]] = None,
    *,
    mcp_entries: Optional[Mapping[str, Any]] = None,
    edge_key: Optional[EdgeKey] = None,
    prev_edge_key: Optional[EdgeKey] = None,
    lazy_catalog: bool = False,
) -> Dict[str, Any]:
    """The catalog frame. Entries go through the same cleaning the relay applies,
    so the schema the relay publishes is byte-for-byte what the edge validates
    arguments against.

    ``caps`` always states what this edge can serve: ``["tools"]``, plus ``mcp`` when
    any MCP server is exported and ``lazy_catalog`` when summaries are published. A
    relay older than v0.7.2 reads the frame as tools-only and is refused at the
    handshake anyway (proto 3), so the caps are informational on this side.
    MCP ``inputSchema`` payloads are carried verbatim (L6).

    ``lazy_catalog`` publishes summaries instead: no tool ``inputs``, a description
    cut to ``MAX_TOOL_SUMMARY_CHARS``, and no MCP ``inputSchema``. The relay then
    fetches each entry with a ``tool_detail`` / ``mcp_tool_detail`` read, which this
    edge answers from the same catalog -- so the schema the agent sees is still the
    cleaned one, just later and only for the tools actually used.

    ``edge_pubkey`` / ``edge_key_fp`` / ``prev_edge_key_fp`` are the public half of the
    key central seals per-user credentials to; the relay pins them in the site record
    so the browser form knows which key to encrypt to. They are omitted when this edge
    has no key (a shared-credential-only install still publishes its catalog).
    """
    catalogs = mcp_catalogs or {}
    if edge_key is None and prev_edge_key is None:
        edge_key, prev_edge_key = _load_edge_keys()
    caps = ["tools"]
    if catalogs:
        caps.append("mcp")
    if lazy_catalog:
        caps.append("lazy_catalog")
    frame: Dict[str, Any] = {
        "t": "hello",
        "proto": PROTO_VERSION,
        "edge_version": EDGE_VERSION,
        "caps": caps,
        "tools": [
            _hello_tool_entry(config, lazy_catalog=lazy_catalog)
            for _, (config, _dir) in sorted(config_map.items())
        ],
        "mcps": [
            _hello_mcp_entry(catalog, lazy_catalog=lazy_catalog)
            for _, catalog in sorted(catalogs.items())
        ],
        "credential_keys": credential_keys(config_map, mcp_entries),
    }
    if edge_key is not None:
        frame["edge_pubkey"] = edge_key.spki_b64
        frame["edge_key_fp"] = edge_key.fingerprint
        frame["prev_edge_key_fp"] = prev_edge_key.fingerprint if prev_edge_key else None
    return frame


def _fit_hello_budget(
    config_map: Mapping[str, Tuple[ToolConfig, Path]],
    catalogs: Mapping[str, protocol.EdgeMcp],
    *,
    mcp_entries: Optional[Mapping[str, Any]] = None,
    edge_key: Optional[EdgeKey] = None,
    prev_edge_key: Optional[EdgeKey] = None,
    lazy_catalog: bool = False,
) -> Dict[str, protocol.EdgeMcp]:
    """Drop MCP catalogs until the whole hello fits ``MAX_FRAME_BYTES`` (plan §2.3).

    The relay validates the aggregate hello and closes the connection with
    ``CLOSE_MALFORMED`` when it is too large; the edge would then redial and send
    the same frame forever, taking *every* tool down with it. Dropping the largest
    MCP exports degrades visibly (tools keep working) instead of entering that loop.
    """
    remaining = dict(catalogs)
    if not remaining:
        return remaining

    def frame_size(present: Mapping[str, protocol.EdgeMcp]) -> int:
        return len(
            protocol.encode(
                hello_frame(
                    config_map,
                    present,
                    mcp_entries=mcp_entries,
                    edge_key=edge_key,
                    prev_edge_key=prev_edge_key,
                    lazy_catalog=lazy_catalog,
                )
            ).encode("utf-8")
        )

    empty = frame_size({})
    marginal = {
        name: frame_size({name: catalog}) - empty
        for name, catalog in remaining.items()
    }

    while remaining:
        # Cheap estimate first (+1 separator per entry); the real encode only runs
        # when the frame should fit, so a pathological catalog set costs one pass.
        estimate = empty + sum(marginal[name] for name in remaining) + len(remaining)
        if (
            estimate <= protocol.MAX_FRAME_BYTES
            and frame_size(remaining) <= protocol.MAX_FRAME_BYTES
        ):
            break
        largest = max(remaining, key=lambda name: marginal[name])
        logger.error(
            "MCP %r: not exporting it -- the hello frame (tools + all MCP catalogs) "
            "would exceed MAX_FRAME_BYTES (%d bytes); the relay would close the "
            "connection with code %d and the edge would retry it forever. Export "
            "fewer or smaller MCP servers.",
            largest,
            protocol.MAX_FRAME_BYTES,
            protocol.CLOSE_MALFORMED,
        )
        remaining.pop(largest)

    if empty > protocol.MAX_FRAME_BYTES:
        logger.error(
            "The tool catalog alone exceeds MAX_FRAME_BYTES (%d bytes); the relay will "
            "keep refusing this edge's hello until fewer tools are exported",
            protocol.MAX_FRAME_BYTES,
        )
    return remaining


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


def _frame_identity(call: Mapping[str, Any]) -> Dict[str, Any]:
    """The caller identity a validated call frame carries, keyed the edge's way.

    The relay is the only verifier on this path (v0.7.2 R1): it derived every field
    from the verified token's claims and no longer sends the token, because the edge
    holds no key that could check one. The keys stay as ``user``/``user_email`` --
    what ``build_env``, ``_server_env`` and the sealed-blob owner check already read
    -- so one mapping feeds the env, the sealed envelope and the runner request.
    Only the frame is a source: nothing here merges a body, a config or the process
    environment into it.
    """
    return {
        "user": call.get("user"),
        "user_email": call.get("user_email"),
        "agent": call.get("agent"),
        "groups": call.get("groups") or [],
        "run_id": call.get("run_id"),
        "parent_run_id": call.get("parent_run_id"),
    }


def _timeout_frame(frame: Dict[str, Any], deadline_ms: int, started: float) -> Dict[str, Any]:
    """The frame the edge sends when it loses the race with the relay's deadline."""
    call_id = frame.get("id")
    logger.warning("Edge cancelled call %r at its %d ms deadline", call_id, deadline_ms)
    return _result_frame(
        call_id if isinstance(call_id, str) else "",
        _elapsed_ms(started),
        error=("edge_timeout", "edge cancelled the call at its deadline"),
    )


async def handle_call(
    config_map: Mapping[str, Tuple[ToolConfig, Path]],
    message: Dict[str, Any],
    *,
    proxy_config: Optional[ProxyConfig] = None,
    credential_modes: Optional[Mapping[str, str]] = None,
    edge_key: Optional[EdgeKey] = None,
    prev_edge_key: Optional[EdgeKey] = None,
) -> Dict[str, Any]:
    """Turn one ``call`` frame into a ``result`` frame.

    Never raises: a bad frame or a crashing tool becomes an error result so the
    receive loop survives it. Arguments are re-validated against the published
    schema, independently of whatever the relay already checked.

    ``proxy_config`` supplies the edge's env policy (allowlist vs passthrough, the
    token variable to strip, and where the shared credential store lives). Without it
    the allowlist and the default token name still apply -- a caller cannot
    accidentally widen the env.

    ``credential_modes`` carries the operator's per-tool ``credential_mode`` from the
    live ``_Session`` (default ``shared``); when it is omitted, the ``proxy_config``'s
    own ``export_modes`` is used. A caller that passes a ``proxy_config`` -- as the
    serve loop does -- therefore cannot silently downgrade a ``per_user_required`` tool
    to ``shared``; with no ``proxy_config`` at all there is nothing to read and the
    default mode applies. Under ``per_user_required`` a caller with no sealed blob
    short-circuits to a ``missing_credentials`` result: the tool is never executed.

    ``message["sealed"]`` is the caller's ciphertext for exactly this
    ``(site, tool, identity)``. It is opened here (current key, then the rotation
    overlap) and the plaintext mapping travels only into the container env; a
    ``SealedError`` -- another target, another user, another site, a retired key --
    becomes ``credential_rejected`` and the tool never runs.

    The frame's caller identity is **trusted**: the relay built it from the verified
    agent token's claims and nothing on the edge re-checks a token (v0.7.1). As of
    v0.7.2 the frame carries no token at all -- the relay is the only verifier and
    sends the claims it derived. That identity is what travels to the runner (over
    the ``RUNNER_TOKEN``-authenticated socket), which is also why the edge runner
    takes it from the body instead of verifying anything itself.
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

    if credential_modes is None:
        credential_modes = proxy_config.export_modes if proxy_config else {}
    identity = _frame_identity(call)
    site = proxy_config.site if proxy_config else None
    if call.get("sealed") is not None and (edge_key is None or prev_edge_key is None):
        edge_key, prev_edge_key = _resolve_edge_keys(edge_key, prev_edge_key)
    try:
        sealed = _open_for_call(
            call,
            site=site or "",
            kind="tool",
            name=call["tool"],
            edge_key=edge_key,
            prev_edge_key=prev_edge_key,
        )
    except edge_crypto.SealedError as exc:
        # Never retried against another target, and the message carries no value.
        logger.warning("Refusing call %r: sealed credential rejected (%s)", call["id"], exc)
        return _result_frame(
            call["id"],
            _elapsed_ms(started),
            error=(edge_crypto.CREDENTIAL_REJECTED, str(exc) or "sealed credential rejected"),
        )
    try:
        env = build_env(
            tool_dir,
            config,
            identity,
            passthrough=bool(proxy_config and proxy_config.env_passthrough),
            token_env=proxy_config.token_env if proxy_config else None,
            credentials=_credential_store(proxy_config),
            credential_mode=(credential_modes or {}).get(
                call["tool"], edge_user_secrets.DEFAULT_MODE
            ),
            email=identity["user_email"],
            site=site,
            sealed=sealed,
        )
    except edge_user_secrets.MissingCredentials as exc:
        # Fail closed: nothing is spawned and no credential is invented. The message
        # names the caller and the site, never a value.
        logger.warning("Refusing call %r: %s", call["id"], exc.message)
        return _result_frame(call["id"], _elapsed_ms(started), error=(exc.code, exc.message))

    try:
        # The tool's own timeout (core.tool_runtime) governs; the relay's
        # deadline_ms only bounds its wait for this result. The caller's identity
        # rides the request as data: an edge runner has no token to verify.
        result = await tool_runtime.execute_tool(
            config,
            tool_dir,
            arguments,
            env=env,
            on_health=None,
            identity=identity,
        )
    except Exception as exc:
        logger.exception("Tool %r failed on the edge", call["tool"])
        return _result_frame(
            call["id"],
            _elapsed_ms(started),
            error=("tool_error", str(exc) or type(exc).__name__),
        )

    return _result_frame(call["id"], _elapsed_ms(started), result=result)


async def handle_mcp_call(
    manager: proxy_mcp.McpSessionManager,
    message: Dict[str, Any],
    *,
    edge_key: Optional[EdgeKey] = None,
    prev_edge_key: Optional[EdgeKey] = None,
) -> Dict[str, Any]:
    """Turn one ``kind:"mcp"`` call frame into a ``result`` frame.

    Never raises, for the same reason ``handle_call`` does not: a refusal or a dead
    server must not take the receive loop down. ``args`` are passed through as-is --
    the target server owns their schema, and coercing would rewrite a union branch.

    A sealed blob is opened here (kind ``mcp``, the server's name, the caller's
    identity) and the decrypted mapping is handed to the session manager, which uses
    it only when it opens (or reopens) the session. The identity is the frame's, i.e.
    the claims the relay derived from the token it verified; no token is verified --
    or even sent -- here (v0.7.2 R1).
    """
    started = time.monotonic()
    raw_id = message.get("id")
    fallback_id = raw_id if isinstance(raw_id, str) else ""

    try:
        call = protocol.validate_call(message)
    except protocol.ProtocolError as exc:
        return _result_frame(fallback_id, _elapsed_ms(started), error=("invalid_arguments", str(exc)))

    if call.get("sealed") is not None and (edge_key is None or prev_edge_key is None):
        edge_key, prev_edge_key = _resolve_edge_keys(edge_key, prev_edge_key)
    try:
        sealed = _open_for_call(
            call,
            site=getattr(manager, "site", "") or "",
            kind="mcp",
            name=call["mcp"],
            edge_key=edge_key,
            prev_edge_key=prev_edge_key,
        )
    except edge_crypto.SealedError as exc:
        logger.warning("Refusing MCP call %r: sealed credential rejected (%s)", call["id"], exc)
        return _result_frame(
            call["id"],
            _elapsed_ms(started),
            error=(edge_crypto.CREDENTIAL_REJECTED, str(exc) or "sealed credential rejected"),
        )

    try:
        result = await manager.call(
            call["mcp"],
            call["tool"],
            call["args"],
            _frame_identity(call),
            call["deadline_ms"],
            sealed=sealed,
        )
    except proxy_mcp.McpCallError as exc:
        return _result_frame(call["id"], _elapsed_ms(started), error=(exc.code, exc.message))
    except Exception as exc:
        logger.exception("MCP call for %r failed on the edge", call.get("mcp"))
        return _result_frame(
            call["id"],
            _elapsed_ms(started),
            error=("tool_error", str(exc) or type(exc).__name__),
        )

    return _result_frame(call["id"], _elapsed_ms(started), result=result)


async def _call_mcp_with_deadline(
    manager: proxy_mcp.McpSessionManager,
    frame: Dict[str, Any],
    *,
    edge_key: Optional[EdgeKey] = None,
    prev_edge_key: Optional[EdgeKey] = None,
) -> Dict[str, Any]:
    """``_call_with_deadline`` for MCP: same grace, same semaphore slot upstream.

    An abandoned call is cancelled, never retried: replaying an MCP call could run a
    state-changing action twice.
    """
    started = time.monotonic()
    try:
        deadline_ms = protocol.validate_call(frame)["deadline_ms"]
    except protocol.ProtocolError:
        return await handle_mcp_call(
            manager, frame, edge_key=edge_key, prev_edge_key=prev_edge_key
        )

    timeout = max(0.0, deadline_ms / 1000.0 - _DEADLINE_GRACE_S)
    try:
        return await asyncio.wait_for(
            handle_mcp_call(manager, frame, edge_key=edge_key, prev_edge_key=prev_edge_key),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return _timeout_frame(frame, deadline_ms, started)


async def _call_with_deadline(
    config_map: Mapping[str, Tuple[ToolConfig, Path]],
    frame: Dict[str, Any],
    *,
    proxy_config: Optional[ProxyConfig] = None,
    credential_modes: Optional[Mapping[str, str]] = None,
    edge_key: Optional[EdgeKey] = None,
    prev_edge_key: Optional[EdgeKey] = None,
) -> Dict[str, Any]:
    """Run one call, aborting it when the caller's ``deadline_ms`` expires.

    The relay stops waiting at ``deadline_ms`` and reports a 504 to its own
    caller. If the edge kept running anyway, an abandoned call would hold one of
    ``MAX_INFLIGHT`` slots for the tool's full timeout (300 s by default).
    Cancelling is safe: the call is owned by the runner (one container per
    call), so this process holds no child process that could outlive it.
    """
    started = time.monotonic()
    try:
        deadline_ms = protocol.validate_call(frame)["deadline_ms"]
    except protocol.ProtocolError:
        # handle_call reports the malformed frame itself; no tool will run, so
        # there is nothing to bound.
        return await handle_call(
            config_map,
            frame,
            proxy_config=proxy_config,
            credential_modes=credential_modes,
            edge_key=edge_key,
            prev_edge_key=prev_edge_key,
        )

    # The grace makes the edge lose the race on purpose: its error frame reaches
    # the relay just before the relay's own deadline expires, so the caller sees
    # ``edge_timeout`` instead of a bare gateway timeout.
    timeout = max(0.0, deadline_ms / 1000.0 - _DEADLINE_GRACE_S)
    try:
        return await asyncio.wait_for(
            handle_call(
                config_map,
                frame,
                proxy_config=proxy_config,
                credential_modes=credential_modes,
                edge_key=edge_key,
                prev_edge_key=prev_edge_key,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return _timeout_frame(frame, deadline_ms, started)


# ---------------------------------------------------------------- transport


class _Session:
    """Catalog plus connection state shared by the serve loop and SIGHUP.

    MCP sessions live in ``self.mcp`` (the manager), not on the socket: a reconnect
    republishes the catalog and leaves every live server process untouched.
    """

    def __init__(self, config: ProxyConfig, config_path: Optional[Path] = None) -> None:
        self.config = config
        self.config_path = config_path
        self.tools: Dict[str, Tuple[ToolConfig, Path]] = {}
        # Per-tool credential policy (``shared`` unless the operator asked otherwise);
        # live-replaced by SIGHUP together with ``exports``.
        self.credential_modes: Dict[str, str] = dict(config.export_modes)
        self.mcps: Dict[str, proxy_mcp.McpExport] = {}
        self.mcp_catalogs: Dict[str, protocol.EdgeMcp] = {}
        self.mcp = proxy_mcp.McpSessionManager(
            passthrough=config.env_passthrough,
            token_env=config.token_env,
            credentials=edge_user_secrets.CredentialStore.from_config(config),
            site=config.site,
        )
        # The edge keypair: the only copy of the private half, loaded once per process.
        # ``prev`` is the rotation overlap (``edge-key.old``), used to open blobs the
        # browser sealed before the rotation.
        self.edge_key, self.prev_edge_key = _load_edge_keys()
        self.reconnect = asyncio.Event()
        self.connection: Any = None
        # Set once the relay answered our hello with a welcome: ``--once`` uses it to
        # tell "connected, then the relay hung up" from "never accepted".
        self.accepted = False
        # Set by a ``drain`` frame: a pause the relay asked for, honoured by the
        # reconnect wait in run(). Sleeping here would block in-flight results
        # from being sent while the socket is still open.
        self.reconnect_delay: float = 0.0
        # Bumped by every reload: an in-flight catalog rebuild that finishes after a
        # newer reload must not install its already-superseded entries.
        self.mcps_generation = 0

    def reload(self) -> None:
        """Re-read proxy.yaml and rebuild the tool + MCP export lists.

        Re-reading is what makes ``SIGHUP`` useful after editing ``exports`` or
        ``export_mcps``: a directory entry alone would be filtered out by the
        in-memory allowlist. Fields that cannot be applied to a live tunnel
        (identity, destination, the token, the env policy and
        the credential store *locations*) are reported rather than half-applied.

        Credential *content* needs no signal for tools: ``secrets_dir`` is read per
        call (and a sealed blob arrives with each call), so a change applies to the
        next tool call. MCP sessions are the exception -- they resolve credentials
        once, at creation -- so ``refresh_mcps`` retires every live session on SIGHUP;
        without the signal a changed credential would wait for the TTL or a restart.
        Moving the directory needs a restart: the manager and the proxy must agree on
        where the files live.

        MCP *catalogs* are rebuilt asynchronously (``refresh_mcps``) because a server
        without a static ``tools:`` list is discovered live. The manager keeps
        serving the previous entries and catalogs until the new ones are installed
        atomically, so an MCP call is never refused during the rebuild.
        """
        fresh: Optional[ProxyConfig] = None
        # Re-read the keypair too: a rotation (`edge-keygen --rotate`) only becomes
        # visible to central once hello publishes the new fingerprint, and SIGHUP is
        # the republish path. Cheap: two 0400 PEM reads.
        self.edge_key, self.prev_edge_key = _load_edge_keys()
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
            self.credential_modes = dict(self.config.export_modes)
            self._reload_mcps(self.config)
            return

        for name in (
            "site",
            "server_url",
            "token_env",
            "token_file",
            "env_passthrough",
            "secrets_dir",
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
            self.config,
            exports=fresh.exports,
            export_modes=fresh.export_modes,
            tools_dir=fresh.tools_dir,
            # mcps_dir/export_mcps are live-reloadable: they only feed the next publish.
            mcps_dir=fresh.mcps_dir,
            export_mcps=fresh.export_mcps,
            # Publishing policy too: the SIGHUP path republishes the hello, so a
            # switch to lazy summaries applies without a restart.
            lazy_catalog=fresh.lazy_catalog,
        )
        new_tools = load_tools(candidate.tools_dir, candidate.exports)
        self.config = candidate
        self.tools = new_tools
        self.credential_modes = dict(candidate.export_modes)
        self._reload_mcps(candidate)

    def _reload_mcps(self, config: ProxyConfig) -> None:
        """Re-read the export list and the manifests; catalogs are built later.

        Deliberately does not touch the manager: installing the new entries before
        their catalogs exist made every MCP call answer ``unknown_tool`` for the
        whole discovery window (up to 20 s per server), and a rebuild that then
        failed left the manager refusing for good. ``refresh_mcps`` installs the
        two together.

        A server whose manifest declares a key the relay's credential-key validator
        refuses is dropped here (logged), so it cannot take the tunnel -- and every
        other export -- down with it.
        """
        loaded = proxy_mcp.load_mcps(config.mcps_dir, config.export_mcps)
        self.mcps = {
            name: entry
            for name, entry in loaded.items()
            if not _skip_invalid_declared_keys("mcp", name, entry.config)
        }
        self.mcps_generation += 1

    async def refresh_mcps(self) -> None:
        """Build the published MCP catalogs, then install entries + catalogs at once.

        Async because a server without a static ``tools:`` list is discovered live;
        the servers are discovered **concurrently** so the rebuild costs the slowest
        server, not their sum. The discovery cache is dropped first: SIGHUP must
        re-read a changed server.

        Every live session is retired once the new entries are installed (no tombstone:
        the next call just reopens), which is what lets an edited credential file --
        or a rotated secret on the target -- reach a session without waiting out its
        TTL (plan §7 Phase 5: "does not affect live sessions until TTL expiry/SIGHUP").

        A server that cannot be read keeps its previously published catalog when its
        configuration did not change -- a transient discovery failure must not take
        a working MCP server (and every session on it) out of the catalog.

        A reload that lands while this one is discovering bumps the generation, so
        the older result is discarded rather than installed over the newer one.
        """
        generation = self.mcps_generation
        proxy_mcp.clear_discovery_cache()
        entries = self.mcps
        names = sorted(entries)
        previous_catalogs = self.mcp_catalogs
        built = await asyncio.gather(
            *(
                proxy_mcp.build_catalog(
                    entries[name],
                    passthrough=self.config.env_passthrough,
                    token_env=self.config.token_env,
                    credentials=self.mcp.credentials,
                    site=self.mcp.site,
                )
                for name in names
            ),
            return_exceptions=True,
        )

        catalogs: Dict[str, protocol.EdgeMcp] = {}
        for name, outcome in zip(names, built):
            if isinstance(outcome, BaseException):
                previous = self.mcp.installed_entry(name)
                if (
                    name in previous_catalogs
                    and previous is not None
                    and previous.signature() == entries[name].signature()
                ):
                    logger.error(
                        "MCP %r: catalog unavailable (%s); keeping the previously "
                        "published catalog",
                        name,
                        outcome,
                    )
                    catalogs[name] = previous_catalogs[name]
                else:
                    logger.error(
                        "MCP %r: catalog unavailable, not exporting it (%s)", name, outcome
                    )
                continue
            catalogs[name] = outcome

        # One atomic install: the top-level publisher and the manager see the same
        # entries/catalogs, so a call can never land in between.
        if generation != self.mcps_generation:
            logger.info(
                "MCP catalog rebuild superseded by a newer reload; discarding it"
            )
            return
        self.mcp_catalogs = _fit_hello_budget(
            self.tools,
            catalogs,
            mcp_entries=entries,
            edge_key=self.edge_key,
            prev_edge_key=self.prev_edge_key,
            lazy_catalog=self.config.lazy_catalog,
        )
        self.mcp.set_entries(entries, self.mcp_catalogs)
        # A SIGHUP is the operator's escape hatch for credentials: sessions resolve
        # them once at creation, so retiring them here is what makes a new shared
        # file -- or the next caller's sealed blob -- reach a session without waiting
        # out the TTL. No tombstone: this is a requested reopen, not a lost session,
        # so the next call starts a fresh server rather than answering
        # ``mcp_session_lost``. A tunnel reconnect never runs this (sessions survive).
        self.mcp.retire_all()
        # Sessions retired by the reload (removed/changed server) and by the above are
        # closed here.
        await self.mcp.reap()

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
    """Reload the tool + MCP catalogs from disk and republish them.

    The relay keys its registry from the ``hello`` frame, so a reconnect is the
    simplest correct republish: no merge logic, no partial catalogs. MCP catalogs
    are rebuilt in the loop (live discovery is async) and the reconnect is requested
    only afterwards, so the new hello already carries them.
    """
    session = _active_session
    if session is None:
        logger.warning("SIGHUP received before the edge session started; ignoring")
        return

    logger.info(
        "SIGHUP: reloading tools from %s and MCP servers from %s",
        session.config.tools_dir,
        session.config.mcps_dir,
    )
    try:
        session.reload()
    except Exception:
        # Keep serving the previous catalog rather than dropping every tool.
        logger.exception("SIGHUP: reload failed; keeping the current catalog")
        return

    loop = _active_loop
    if loop is not None and loop.is_running():
        loop.call_soon_threadsafe(_republish, session)
    else:
        session.reconnect.set()


def _republish(session: _Session) -> None:
    """Rebuild MCP catalogs, then ask for the reconnect that republishes them."""
    asyncio.ensure_future(_republish_async(session))


async def _republish_async(session: _Session) -> None:
    try:
        await session.refresh_mcps()
    except Exception:
        logger.exception("SIGHUP: MCP catalog rebuild failed; republishing without them")
    session.request_reconnect("SIGHUP")


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

    Tools inherit a scoped copy of ``os.environ``; the token has no business
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
    * The terminal codes -- 4403 (revoked), 4409 (superseded) and 4001 (version
      mismatch, `_TERMINAL_CLOSE_CODES`) -- cannot be retried away, so they jump
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
    if close_code == protocol.CLOSE_VERSION:
        return (
            f"Edge {site!r} was closed by the relay (code {close_code}, version mismatch): "
            f"the relay speaks an older tunnel protocol; upgrade central first (a v0.5 edge "
            f"needs a v0.5 relay). Retrying only at the maximum backoff "
            f"({_BACKOFF_MAX_S:.0f}s)."
        )
    return (
        f"Edge {site!r} was closed by the relay (code {close_code}, superseded): another "
        f"instance is probably connected with this site's token. Retrying only at the "
        f"maximum backoff ({_BACKOFF_MAX_S:.0f}s)."
    )


def _detail_frame(frame: Dict[str, Any], session: "_Session") -> Dict[str, Any]:
    """Answer a ``tool_detail`` / ``mcp_tool_detail`` frame from the local catalog.

    A pure local read: no inflight slot, no runner, no MCP session. The payload is
    the full entry the hello summary left out, and the relay re-validates it with
    ``protocol.validate_tool_detail`` / ``validate_mcp_tool_detail``.
    """
    started = time.monotonic()
    frame_id = frame.get("id") if isinstance(frame.get("id"), str) else ""
    if frame.get("t") == "tool_detail":
        found = session.tools.get(frame.get("tool"))
        if found is None:
            return _result_frame(
                frame_id,
                _elapsed_ms(started),
                error=("unknown_tool", f"unknown tool: {frame.get('tool')!r}"),
            )
        reply = _result_frame(frame_id, _elapsed_ms(started))
        reply["detail"] = _catalog_entry(found[0])
        return reply

    catalog = session.mcp_catalogs.get(frame.get("mcp"))
    if catalog is None:
        return _result_frame(
            frame_id,
            _elapsed_ms(started),
            error=("unknown_mcp", f"unknown mcp server: {frame.get('mcp')!r}"),
        )
    tool = next((t for t in catalog.tools if t.name == frame.get("tool")), None)
    if tool is None:
        return _result_frame(
            frame_id,
            _elapsed_ms(started),
            error=(
                "unknown_tool",
                f"unknown mcp tool: {frame.get('mcp')!r}/{frame.get('tool')!r}",
            ),
        )
    reply = _result_frame(frame_id, _elapsed_ms(started))
    reply["detail"] = tool.as_dict()
    return reply


async def _serve(session: _Session, ws) -> None:
    """Handshake, then pump frames until the connection closes."""
    await ws.send(
        protocol.encode(
            hello_frame(
                session.tools,
                session.mcp_catalogs,
                mcp_entries=session.mcps,
                edge_key=session.edge_key,
                prev_edge_key=session.prev_edge_key,
                lazy_catalog=session.config.lazy_catalog,
            )
        )
    )

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
            if frame.get("kind") == "mcp":
                result = await _call_mcp_with_deadline(
                    session.mcp,
                    frame,
                    edge_key=session.edge_key,
                    prev_edge_key=session.prev_edge_key,
                )
            else:
                result = await _call_with_deadline(
                    session.tools,
                    frame,
                    proxy_config=session.config,
                    credential_modes=session.credential_modes,
                    edge_key=session.edge_key,
                    prev_edge_key=session.prev_edge_key,
                )
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

            if frame_type in ("tool_detail", "mcp_tool_detail"):
                # A lazy-catalog read, answered inline from memory: no inflight
                # slot is taken (nothing executes) and a bad lookup replies with an
                # error frame rather than closing the tunnel.
                try:
                    detail_reply = _detail_frame(frame, session)
                except Exception:
                    logger.exception("Failed to answer a %s frame", frame_type)
                    detail_reply = _result_frame(
                        frame.get("id") if isinstance(frame.get("id"), str) else "",
                        0,
                        error=("edge_error", "edge could not read the catalog entry"),
                    )
                await ws.send(protocol.encode(detail_reply))
                continue

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


# How often ``run()`` sweeps idle MCP sessions (plan §3.4: 30 min default TTL).
MCP_SWEEP_INTERVAL_S = 60.0


async def _sweep_mcp_sessions(
    session: "_Session", interval: float = MCP_SWEEP_INTERVAL_S
) -> None:
    """Retire TTL-expired MCP sessions while the edge is idle (spec D2).

    Without a periodic sweep a session is only reaped by the next call that happens
    to land on the same manager, so an idle edge would hold a user's login session
    (and its server process) alive indefinitely. Started by ``run()``; tests call
    ``McpSessionManager.sweep()`` directly instead of starting a live edge process.
    """
    while True:
        await asyncio.sleep(interval)
        try:
            await session.mcp.sweep()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.debug("MCP idle sweep failed", exc_info=True)


def _disable_core_dumps() -> None:
    """PR_SET_DUMPABLE=0: a decrypted credential must not reach a core file.

    Best effort and Linux-only; an edge on another platform simply keeps its
    default. Called once, before the first key is loaded. A failure is a real
    (if modest) exposure -- a core file could capture a decrypted credential -- so
    it is logged at WARNING, never DEBUG.
    """
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
            logger.warning(
                "Could not set PR_SET_DUMPABLE=0 (errno %s); a core file could capture "
                "a decrypted credential",
                ctypes.get_errno(),
            )
    except Exception:
        logger.warning(
            "Could not set PR_SET_DUMPABLE=0; a core file could capture a decrypted "
            "credential",
            exc_info=True,
        )


async def run(
    config: ProxyConfig, *, once: bool = False, config_path: Optional[Path] = None
) -> None:
    """Connect, serve, and reconnect with jittered exponential backoff.

    ``once`` performs a single attempt and re-raises its failure, which is what
    ``trellis-proxy --once`` and diagnostics need.
    """
    global _active_session, _active_loop

    # Every edge call runs through this edge's runner: the socket is the one
    # execution path.
    os.environ.setdefault("RUNNER_SOCKET", config.runner_socket)

    _disable_core_dumps()
    # No agent-token gate: an edge verifies nothing (v0.7.1). The relay verified the
    # token and derived the frame identity; AGENT_TOKEN_SECRET is not needed here.
    token = _resolve_and_forget_token(config)
    connect = _connect_factory()

    # Tells shared core modules (core/tunables) not to look for etcd: an edge is a
    # standalone install and the failed refresh would log forever.
    os.environ.setdefault("TRELLIS_EDGE_MODE", "1")

    session = _Session(config, config_path)
    session.reload()
    await session.refresh_mcps()
    _active_session = session
    _active_loop = asyncio.get_running_loop()
    # Idle sessions are retired by this task, not only by the next call.
    sweeper = asyncio.create_task(_sweep_mcp_sessions(session))

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
                        "Connected to %s as site %r (%d tool(s), %d MCP server(s))",
                        config.server_url,
                        config.site,
                        len(session.tools),
                        len(session.mcp_catalogs),
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
                    # Log once per reason: a revoked token, a duplicate site or an
                    # un-upgraded relay redials every minute and must not repeat
                    # this -- or be mistaken for a generic disconnect -- each time.
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
        try:
            # Sessions are owned by the manager, not the socket: nothing else will
            # stop these server processes when the edge exits.
            await session.mcp.kill_all()
        except Exception:
            logger.debug("Failed to close MCP sessions on exit", exc_info=True)
        sweeper.cancel()
        await asyncio.gather(sweeper, return_exceptions=True)


# ---------------------------------------------------------------- CLI

_EDGE_KEYGEN = "edge-keygen"


def main(argv: Optional[List[str]] = None) -> None:
    args_list = list(sys.argv[1:] if argv is None else argv)
    # Subcommand first: the default (no subcommand) behaviour is the serve loop, and
    # the argparse below has no positionals. `edge-keygen` delegates wholesale so the
    # keypair module owns its own flags (--rotate/--drop-old-key/--show/--path).
    if args_list and args_list[0] == _EDGE_KEYGEN:
        raise SystemExit(edge_keypair.main(args_list[1:]))

    parser = argparse.ArgumentParser(
        prog="trellis-proxy",
        description="Expose local Trellis tools to the central relay over an outbound WebSocket.",
        epilog=(
            "Per-user credentials are sealed in the central UI and opened here with the "
            "edge key. Manage that key with 'trellis-proxy edge-keygen "
            "{--keygen,--rotate,--drop-old-key,--show} [--path PATH]'."
        ),
    )
    parser.add_argument("--config", help=f"path to proxy.yaml (default: ${CONFIG_ENV} or ./proxy.yaml)")
    parser.add_argument(
        "--once",
        action="store_true",
        help="single connection attempt; exit non-zero on failure (diagnostics)",
    )
    args = parser.parse_args(args_list)

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
