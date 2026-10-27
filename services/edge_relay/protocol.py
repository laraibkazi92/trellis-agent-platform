# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Frame contract for the trellis-proxy edge tunnel.

Shared by both ends: ``services/edge_relay`` (central) and ``core/proxy`` (edge).
One JSON object per WebSocket message. The set of frame types is closed in each
direction -- an unknown ``t`` closes the connection, so a peer cannot smuggle
messages the other side does not understand.

This module deliberately has no framework imports (no FastAPI, no etcd): it is
the part of the tunnel that is cheapest to test and most important to keep
identical on both sides.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from core import edge_crypto
from core.edge_keypair import fingerprint as spki_fingerprint

PROTO = 2
# A proto-1 edge is the v0.4 tools-only edge: it degrades cleanly, never gets
# an MCP call, and the relay keeps publishing its tool catalog exactly as before.
SUPPORTED_PROTOS = frozenset({1, 2})
SUBPROTOCOL = "trellis.edge.v1"

# WebSocket close codes (4000-4999 is the application-private range).
CLOSE_MALFORMED = 4000
CLOSE_VERSION = 4001
CLOSE_UNKNOWN_TYPE = 4400
CLOSE_REVOKED = 4403
CLOSE_SUPERSEDED = 4409

# Caps. The relay enforces these on the way in; the edge re-checks on the way out.
MAX_FRAME_BYTES = 10 * 1024 * 1024
MAX_ARGS_BYTES = 1 * 1024 * 1024
MAX_TOOLS = 200
MAX_TOOL_NAME = 64
# A lazy-catalog hello carries a short summary per tool: the full input schema is
# fetched later with a ``tool_detail`` round trip. A longer summary is refused
# rather than silently shortened, so the edge and the registry agree on what was
# published.
MAX_TOOL_SUMMARY_CHARS = 120
MAX_INFLIGHT = 16
MAX_DEADLINE_MS = 3_600_000
# MCP catalogs ride the same hello frame, so every cap here is also bounded by
# MAX_FRAME_BYTES. The reference workload is ~92 KB total / ~26 KB per schema.
MAX_MCPS = 50
MAX_MCP_TOOLS_PER_SERVER = 256
MAX_MCP_SCHEMA_BYTES = 131_072
MAX_MCP_DESC_CHARS = 8_192
# RFC 5321 caps a forward path at 256 bytes including the angle brackets.
MAX_USER_EMAIL_CHARS = 254
# A t1 token is a few hundred bytes; the cap only bounds what the relay will
# validate and forward to the edge. R1 keeps this check for wire tolerance (an older
# relay still sends the token) but nothing on the edge consumes it any more.
MAX_AGENT_TOKEN_CHARS = 4096
# The claims-derived run attribution a call frame carries. Every value is signed into
# the token, so these only bound what the edge will accept and parse; a longer one is a
# malformed claim, not something to accommodate.
MAX_AGENT_NAME_CHARS = 128
MAX_RUN_ID_CHARS = 128
MAX_GROUPS = 256
MAX_GROUP_NAME_CHARS = 254
# Slightly above the hub's default tool timeout (300 s) so the edge's own,
# structured timeout wins the race and the caller gets the tool's error instead
# of a bare relay 504.
DEFAULT_DEADLINE_MS = 330_000
# Liveness is a WebSocket control-frame ping/pong (uvicorn server side,
# websockets client side). The app-level ``ping`` frame is kept for peers that
# open a tunnel through a proxy which needs application-level keepalive bytes,
# but neither side answers it -- echoing produced an unbounded frame storm.
HEARTBEAT_S = 20

EDGE_FRAMES = frozenset({"hello", "result", "ping"})
# `drain` is sent on relay shutdown (best effort: uvicorn may close first) so edges
# reconnect promptly instead of waiting out their backoff. `catalog` is RESERVED (force a republish without reconnecting):
# accepted and handled, but no sender emits it yet -- do not build runbooks on it.
# `tool_detail` / `mcp_tool_detail` are lazy-catalog reads: the edge answers them with
# an ordinary `result` frame whose payload is a validated `detail` object, so they ride
# the same id correlation as a call (``EdgeConn.inflight``).
RELAY_FRAMES = frozenset(
    {"welcome", "call", "ping", "catalog", "drain", "tool_detail", "mcp_tool_detail"}
)

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# hello.credential_keys is a name -> {secret_keys, variable_keys} map for every
# export. Both halves are bounded by the catalog caps, and one manifest with hundreds
# of fields is a misconfiguration rather than a working tool.
MAX_CREDENTIAL_TARGETS = MAX_TOOLS + MAX_MCPS
MAX_DECLARED_KEYS = 256
MAX_ENV_NAME_CHARS = 128
# The seal format is RSA-OAEP; a different modulus size is not something central's
# browser form can produce, so a hello claiming one is refused rather than pinned.
EDGE_KEY_BITS = 3072

# hello.caps: what the edge can serve. Tools-only is the v0.4 default.
# `lazy_catalog` means the hello carries summaries only (no tool `inputs`, no MCP
# `inputSchema`); the relay must then ask for each entry before calling it.
SUPPORTED_CAPS = frozenset({"tools", "mcp", "lazy_catalog"})
# mcp.yaml transports the relay is willing to store; the edge owns the actual client.
SUPPORTED_MCP_TRANSPORTS = frozenset({"stdio", "http", "streamable-http", "sse"})


def _check_namespace(name: str, what: str) -> None:
    """Reject ``__`` in either half of a ``<site>__<tool>`` registry name.

    ``site="a__b", tool="c"`` and ``site="a", tool="b__c"`` would both produce
    ``a__b__c``; the registry is flat, so the collision has to be impossible
    rather than merely unlikely.
    """
    if "__" in name:
        raise ProtocolError(f"{what} may not contain '__': {name!r}")

# tool.yaml input types the hub handler understands (core/hub.py:register_tools).
_INPUT_TYPES = frozenset({"string", "integer", "boolean", "array", "object", "number"})


class ProtocolError(Exception):
    """A frame violated the contract. ``close_code`` is the WS close code to send."""

    def __init__(self, message: str, close_code: int = CLOSE_MALFORMED):
        super().__init__(message)
        self.close_code = close_code


def encode(frame: Dict[str, Any]) -> str:
    return json.dumps(frame, separators=(",", ":"))


def decode(raw: Any, allowed: Iterable[str]) -> Dict[str, Any]:
    """Parse and type-check one incoming frame.

    ``allowed`` is ``EDGE_FRAMES`` on the relay and ``RELAY_FRAMES`` on the edge:
    direction is part of the contract, so a ``call`` arriving at the relay is as
    invalid as garbage bytes.
    """
    if isinstance(raw, (bytes, bytearray, memoryview)):
        if len(raw) > MAX_FRAME_BYTES:
            raise ProtocolError(f"frame exceeds {MAX_FRAME_BYTES} bytes")
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError("frame is not valid UTF-8") from exc
    elif isinstance(raw, str):
        if len(raw.encode("utf-8")) > MAX_FRAME_BYTES:
            raise ProtocolError(f"frame exceeds {MAX_FRAME_BYTES} bytes")
        text = raw
    else:
        raise ProtocolError(f"unsupported frame payload: {type(raw).__name__}")

    try:
        frame = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError("frame is not JSON") from exc

    if not isinstance(frame, dict):
        raise ProtocolError("frame must be a JSON object")

    frame_type = frame.get("t")
    if frame_type not in allowed:
        raise ProtocolError(f"unexpected frame type: {frame_type!r}", CLOSE_UNKNOWN_TYPE)
    return frame


@dataclass(frozen=True)
class CatalogSkip:
    """One catalog entry the validator dropped, and why.

    A hello is validated per entry, not as one blob: a single unusable manifest must
    cost that export, never the tunnel (an edge closed at the handshake redials with
    the same frame forever, taking every healthy export down with it).
    """

    name: Optional[str]
    reason: str

    def describe(self) -> str:
        return f"{self.name!r}: {self.reason}" if self.name else self.reason


class ValidatedCatalog(list):
    """The entries that passed, plus the per-entry ``CatalogSkip`` errors.

    A plain ``list`` subclass (the ``HelloValidation`` idiom) so every existing
    unpacking -- ``(tool,) = validate_tools([...])``, ``validate_mcps(...)[0]`` --
    keeps working; callers that publish a catalog read ``.errors`` and log each one.
    """

    def __init__(self, entries: Iterable[Any] = (), errors: Iterable[CatalogSkip] = ()) -> None:
        super().__init__(entries)
        self.errors: List[CatalogSkip] = list(errors)


@dataclass(frozen=True)
class EdgeCredentials:
    """The credential key material an edge publishes in ``hello``.

    ``credential_keys`` is ``{export_name: {secret_keys, variable_keys}}``: names only,
    so central can render the browser seal form for a target whose relay-published
    ``<site>__<name>`` config deliberately omits ``secrets``/``variables``. The
    optional key fields are absent for a v0.5 edge (shared credentials only).
    """

    edge_pubkey: Optional[str] = None
    edge_key_fp: Optional[str] = None
    prev_edge_key_fp: Optional[str] = None
    credential_keys: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)

    @property
    def key_id(self) -> Optional[str]:
        fp = self.edge_key_fp
        return fp[7:23] if isinstance(fp, str) and fp else None

    def as_record(self) -> Dict[str, Any]:
        """The subset the relay pins in ``/registry/edges/<site>/config``."""
        record: Dict[str, Any] = {}
        if self.edge_pubkey is not None:
            record["edge_pubkey"] = self.edge_pubkey
        if self.edge_key_fp is not None:
            record["edge_key_fp"] = self.edge_key_fp
            record["edge_key_id"] = self.key_id
        if self.prev_edge_key_fp is not None:
            record["prev_edge_key_fp"] = self.prev_edge_key_fp
        if self.credential_keys:
            record["credential_keys"] = self.credential_keys
        return record


class HelloValidation(tuple):
    """The v0.5 five-tuple, plus ``credentials`` and the per-entry ``errors``.

    Existing unpackers (``proto, version, tools, mcps, caps = ...``) keep working
    unchanged; the relay reads the new material from ``.credentials`` and logs every
    entry it had to skip from ``.errors``.
    """

    def __new__(
        cls,
        proto: int,
        version: str,
        tools: List[EdgeTool],
        mcps: List[EdgeMcp],
        caps: List[str],
        credentials: EdgeCredentials,
        errors: Iterable[CatalogSkip] = (),
    ) -> "HelloValidation":
        instance = super().__new__(cls, (proto, version, tools, mcps, caps))
        instance.credentials = credentials
        instance.errors: List[CatalogSkip] = list(errors)
        return instance


def _validate_edge_pubkey(raw: Any) -> str:
    """Validate a hello ``edge_pubkey`` and return the fingerprint it must match."""
    if not isinstance(raw, str) or not raw:
        raise ProtocolError("hello.edge_pubkey must be a base64 SPKI string")
    try:
        der = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise ProtocolError("hello.edge_pubkey is not valid base64") from None
    try:
        public_key = serialization.load_der_public_key(der)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ProtocolError("hello.edge_pubkey is not a DER SubjectPublicKeyInfo") from None
    if not isinstance(public_key, RSAPublicKey):
        raise ProtocolError("hello.edge_pubkey is not an RSA key")
    if public_key.key_size != EDGE_KEY_BITS:
        raise ProtocolError(
            f"hello.edge_pubkey is {public_key.key_size}-bit; the seal format requires "
            f"{EDGE_KEY_BITS}"
        )
    return spki_fingerprint(der)


def _validate_fingerprint(raw: Any, field_name: str) -> str:
    if not isinstance(raw, str) or not raw.startswith("SHA256:") or len(raw) < 10:
        raise ProtocolError(f"hello.{field_name} must be a SHA256: fingerprint")
    return raw


def _validate_key_list(raw: Any, field_name: str) -> List[str]:
    if raw is None:
        # An export that declares only secrets (or only variables) omits the other
        # half; that is not an error.
        return []
    if not isinstance(raw, list):
        raise ProtocolError(f"hello.credential_keys[].{field_name} must be a list")
    if len(raw) > MAX_DECLARED_KEYS:
        raise ProtocolError(
            f"hello.credential_keys[].{field_name} exceeds {MAX_DECLARED_KEYS} names"
        )
    names: List[str] = []
    for name in raw:
        if (
            not isinstance(name, str)
            or len(name) > MAX_ENV_NAME_CHARS
            or not ENV_NAME_RE.match(name)
        ):
            raise ProtocolError(
                f"hello.credential_keys[].{field_name} has an invalid env name: {name!r}"
            )
        if name in names:
            raise ProtocolError(
                f"hello.credential_keys[].{field_name} lists {name!r} twice"
            )
        names.append(name)
    return names


def _validate_credential_keys(
    raw: Any,
) -> Tuple[Dict[str, Dict[str, List[str]]], List[CatalogSkip]]:
    """Names only: every entry must be ``{secret_keys: [...], variable_keys: [...]}``.

    Per target, not per hello: a manifest that declares a key an edge cannot export
    (the key name is the operator's, and a hyphen in it is an easy mistake) costs that
    target's seal form, never the tunnel. Each dropped target is reported so the relay
    can log the name and the reason.
    """
    if raw in (None, {}):
        return {}, []
    if not isinstance(raw, dict):
        raise ProtocolError("hello.credential_keys must be an object")
    if len(raw) > MAX_CREDENTIAL_TARGETS:
        raise ProtocolError(
            f"hello.credential_keys exceeds {MAX_CREDENTIAL_TARGETS} targets"
        )
    cleaned: Dict[str, Dict[str, List[str]]] = {}
    skips: List[CatalogSkip] = []
    for name, entry in raw.items():
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ProtocolError(f"invalid hello.credential_keys target: {name!r}")
        _check_namespace(name, "credential_keys target")

        def _drop(reason: str) -> None:
            skips.append(CatalogSkip(name, reason))

        if not isinstance(entry, dict):
            _drop("credential_keys entry must be an object")
            continue
        unknown = set(entry) - {"secret_keys", "variable_keys"}
        if unknown:
            _drop(f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")
            continue
        try:
            secret = _validate_key_list(entry.get("secret_keys"), "secret_keys")
            variable = _validate_key_list(entry.get("variable_keys"), "variable_keys")
        except ProtocolError as exc:
            _drop(str(exc))
            continue
        # A name in both lists is ambiguous; the write gate treats it as a variable,
        # so the edge must not advertise it as a sealable secret.
        overlap = sorted(set(secret) & set(variable))
        if overlap:
            _drop(f"lists {overlap[0]!r} as both a secret and a variable")
            continue
        cleaned[name] = {
            "secret_keys": sorted(secret),
            "variable_keys": sorted(variable),
        }
    return cleaned, skips


def _validate_edge_credentials(
    frame: Dict[str, Any],
) -> Tuple[EdgeCredentials, List[CatalogSkip]]:
    """Parse the optional key/credential block; a v0.5 edge has none of it.

    The key/fingerprint half stays fatal (bad public material must never be pinned in
    the registry); the per-export declared-key half is per target.
    """
    raw_keys = frame.get("credential_keys")
    credential_keys, skips = _validate_credential_keys(raw_keys)

    pubkey = frame.get("edge_pubkey")
    fingerprint = frame.get("edge_key_fp")
    previous = frame.get("prev_edge_key_fp")
    if pubkey is None and fingerprint is None and previous is None:
        return EdgeCredentials(credential_keys=credential_keys), skips

    if pubkey is None or fingerprint is None:
        raise ProtocolError(
            "hello.edge_pubkey and hello.edge_key_fp must be present together"
        )
    fp = _validate_fingerprint(fingerprint, "edge_key_fp")
    computed = _validate_edge_pubkey(pubkey)
    if not hmac.compare_digest(computed.encode("utf-8"), fp.encode("utf-8")):
        raise ProtocolError("hello.edge_key_fp does not match hello.edge_pubkey")
    prev_fp: Optional[str] = None
    if previous is not None:
        prev_fp = _validate_fingerprint(previous, "prev_edge_key_fp")
        if hmac.compare_digest(prev_fp.encode("utf-8"), fp.encode("utf-8")):
            raise ProtocolError("hello.prev_edge_key_fp must differ from edge_key_fp")
    return (
        EdgeCredentials(
            edge_pubkey=pubkey,
            edge_key_fp=fp,
            prev_edge_key_fp=prev_fp,
            credential_keys=credential_keys,
        ),
        skips,
    )


@dataclass(frozen=True)
class EdgeTool:
    """One tool published by an edge. ``inputs`` uses the tool.yaml input schema."""

    name: str
    description: str = ""
    inputs: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "description": self.description, "inputs": self.inputs}


def _validate_inputs(raw: Any) -> Dict[str, Any]:
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict):
        raise ProtocolError("tool inputs must be an object")
    cleaned: Dict[str, Any] = {}
    for key, spec in raw.items():
        if not isinstance(key, str) or not NAME_RE.match(key):
            raise ProtocolError(f"invalid input name: {key!r}")
        if spec is None:
            spec = {}
        if not isinstance(spec, dict):
            raise ProtocolError(f"input {key!r} spec must be an object")
        input_type = spec.get("type", "string")
        if input_type not in _INPUT_TYPES:
            raise ProtocolError(f"input {key!r} has unsupported type {input_type!r}")
        cleaned[key] = {
            "type": input_type,
            "required": bool(spec.get("required", False)),
        }
        if "description" in spec and isinstance(spec["description"], str):
            cleaned[key]["description"] = spec["description"][:500]
        if "enum" in spec and isinstance(spec["enum"], list):
            cleaned[key]["enum"] = [str(v) for v in spec["enum"]][:100]
    return cleaned


def validate_tools(raw_tools: Any, *, lazy_catalog: bool = False) -> ValidatedCatalog:
    """Validate a published catalog. Names must be unique and namespace-safe.

    With the ``lazy_catalog`` capability an entry is a *summary*: ``inputs`` is
    deferred to a ``tool_detail`` round trip, and the description is capped at
    ``MAX_TOOL_SUMMARY_CHARS`` (refused, not truncated -- a hello that silently
    lost half of a description would publish a catalog the operator never wrote).

    Validation is **per entry**: an unusable tool is dropped with a ``CatalogSkip``
    naming it and the reason, and the remaining exports are published. Only a
    frame-level violation (not a list, or more entries than ``MAX_TOOLS``) refuses
    the whole hello, because then there is no catalog to salvage.
    """
    if raw_tools in (None, []):
        return ValidatedCatalog()
    if not isinstance(raw_tools, list):
        raise ProtocolError("hello.tools must be a list")
    if len(raw_tools) > MAX_TOOLS:
        raise ProtocolError(f"catalog exceeds {MAX_TOOLS} tools")

    tools: List[EdgeTool] = []
    skips: List[CatalogSkip] = []
    seen = set()
    for raw in raw_tools:
        if not isinstance(raw, dict):
            skips.append(CatalogSkip(None, "tool entries must be objects"))
            continue
        name = raw.get("name")
        label = name if isinstance(name, str) and name else None
        if not isinstance(name, str) or not NAME_RE.match(name):
            skips.append(CatalogSkip(label, f"invalid tool name: {name!r}"))
            continue
        if "__" in name:
            skips.append(
                CatalogSkip(name, f"tool name may not contain '__': {name!r}")
            )
            continue
        if name in seen:
            skips.append(CatalogSkip(name, f"duplicate tool name: {name}"))
            continue
        description = raw.get("description") or ""
        if not isinstance(description, str):
            skips.append(
                CatalogSkip(name, f"tool {name!r} description must be a string")
            )
            continue
        if lazy_catalog and len(description) > MAX_TOOL_SUMMARY_CHARS:
            skips.append(
                CatalogSkip(
                    name,
                    f"tool {name!r} description is {len(description)} chars; a "
                    f"lazy_catalog hello carries at most {MAX_TOOL_SUMMARY_CHARS} "
                    "per tool",
                )
            )
            continue
        if not lazy_catalog:
            description = description[:2000]
        try:
            inputs = _validate_inputs(raw.get("inputs"))
        except ProtocolError as exc:
            skips.append(CatalogSkip(name, str(exc)))
            continue
        # Only a published entry reserves its name: a malformed first entry must not
        # shadow a valid later one with the same name.
        seen.add(name)
        tools.append(
            EdgeTool(name=name, description=description, inputs=inputs)
        )
    return ValidatedCatalog(tools, skips)


def validate_tool_detail(entry: Dict[str, Any]) -> EdgeTool:
    """Validate one full tool entry -- the ``tool_detail`` reply payload.

    This is the strict counterpart of a ``lazy_catalog`` hello entry: the summary
    omitted ``inputs``, so the detail must carry them. Names are checked exactly as
    in ``validate_tools`` (same regex, same ``__`` ban) and the description is
    truncated to the catalog limit rather than refused: a too-long detail is a cost,
    not an ambiguity.
    """
    if not isinstance(entry, dict):
        raise ProtocolError("tool detail must be an object")
    name = entry.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ProtocolError(f"invalid tool name: {name!r}")
    _check_namespace(name, "tool name")
    if not isinstance(entry.get("description"), str):
        raise ProtocolError(f"tool {name!r} detail must carry a string description")
    if "inputs" not in entry:
        raise ProtocolError(f"tool {name!r} detail must carry inputs")
    return EdgeTool(
        name=name,
        description=entry["description"][:2000],
        inputs=_validate_inputs(entry.get("inputs")),
    )


@dataclass(frozen=True)
class EdgeMcpTool:
    """One tool of an edge-exported MCP server.

    ``input_schema`` is the MCP server's own JSON Schema, carried **verbatim**
    (root-level ``oneOf``/``anyOf``/``$ref`` included): the wire catalog, the
    registry and the agent-facing tool must all see the same bytes.
    """

    name: str
    description: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


@dataclass(frozen=True)
class EdgeMcp:
    """An MCP server an edge exports. ``transport`` is the edge's, not the relay's."""

    name: str
    transport: str = "stdio"
    tools: List[EdgeMcpTool] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "transport": self.transport,
            "tools": [tool.as_dict() for tool in self.tools],
        }


def _validate_mcp_schema(tool: str, raw: Any) -> Dict[str, Any]:
    """Size-check an input schema without touching it.

    No key cleaning and no truncation: a flattened or re-typed schema silently
    changes what the model is allowed to send (L6).
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProtocolError(f"mcp tool {tool!r} inputSchema must be an object")
    if (
        len(json.dumps(raw, separators=(",", ":")).encode("utf-8"))
        > MAX_MCP_SCHEMA_BYTES
    ):
        raise ProtocolError(
            f"mcp tool {tool!r} inputSchema exceeds {MAX_MCP_SCHEMA_BYTES} bytes"
        )
    return raw


def _validate_mcp_tools(server: str, raw_tools: Any) -> List[EdgeMcpTool]:
    if raw_tools in (None, []):
        return []
    if not isinstance(raw_tools, list):
        raise ProtocolError(f"mcp {server!r} tools must be a list")
    if len(raw_tools) > MAX_MCP_TOOLS_PER_SERVER:
        raise ProtocolError(
            f"mcp {server!r} exceeds {MAX_MCP_TOOLS_PER_SERVER} tools"
        )

    tools: List[EdgeMcpTool] = []
    seen = set()
    for raw in raw_tools:
        if not isinstance(raw, dict):
            raise ProtocolError("mcp tool entries must be objects")
        name = raw.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ProtocolError(f"invalid mcp tool name: {name!r}")
        _check_namespace(name, "mcp tool name")
        if name in seen:
            raise ProtocolError(f"duplicate mcp tool name: {name}")
        description = raw.get("description") or ""
        if not isinstance(description, str):
            raise ProtocolError(f"mcp tool {name!r} description must be a string")
        # Only an entry that survives every check reserves its name (same rule as
        # ``validate_tools``): a malformed first entry must not mask a valid later one.
        seen.add(name)
        tools.append(
            EdgeMcpTool(
                name=name,
                # Truncated, not rejected: a long description costs an integer's
                # worth of tokens in every prompt, and refusal would drop the
                # whole server from the catalog.
                description=description[:MAX_MCP_DESC_CHARS],
                input_schema=_validate_mcp_schema(name, raw.get("inputSchema")),
            )
        )
    return tools


def validate_mcp_tool_detail(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Validate one full MCP tool entry -- the ``mcp_tool_detail`` reply payload.

    Returns the entry as a plain dict (``name``/``description``/``inputSchema``)
    because an MCP schema must stay byte-identical to what the server published:
    rebuilding it into ``EdgeMcpTool`` would be no different, but a dict is what the
    relay has to hand to the registry anyway. ``inputSchema`` goes through the same
    ``MAX_MCP_SCHEMA_BYTES`` check as the catalog, so a detail cannot smuggle in a
    schema a hello would have refused.
    """
    if not isinstance(entry, dict):
        raise ProtocolError("mcp tool detail must be an object")
    name = entry.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ProtocolError(f"invalid mcp tool name: {name!r}")
    _check_namespace(name, "mcp tool name")
    if not isinstance(entry.get("description"), str):
        raise ProtocolError(f"mcp tool {name!r} detail must carry a description")
    if "inputSchema" not in entry:
        raise ProtocolError(f"mcp tool {name!r} detail must carry inputSchema")
    return {
        "name": name,
        "description": entry["description"][:MAX_MCP_DESC_CHARS],
        "inputSchema": _validate_mcp_schema(name, entry.get("inputSchema")),
    }


def validate_mcps(raw_mcps: Any) -> ValidatedCatalog:
    """Validate an edge's MCP catalog. Names must be unique and namespace-safe.

    Per server, like ``validate_tools``: one unreadable or unsafe server is dropped
    with its reason and the rest are published.
    """
    if raw_mcps in (None, []):
        return ValidatedCatalog()
    if not isinstance(raw_mcps, list):
        raise ProtocolError("hello.mcps must be a list")
    if len(raw_mcps) > MAX_MCPS:
        raise ProtocolError(f"hello.mcps exceeds {MAX_MCPS} servers")

    mcps: List[EdgeMcp] = []
    skips: List[CatalogSkip] = []
    seen = set()
    for raw in raw_mcps:
        if not isinstance(raw, dict):
            skips.append(CatalogSkip(None, "mcp entries must be objects"))
            continue
        name = raw.get("name")
        label = name if isinstance(name, str) and name else None
        if not isinstance(name, str) or not NAME_RE.match(name):
            skips.append(CatalogSkip(label, f"invalid mcp name: {name!r}"))
            continue
        if "__" in name:
            skips.append(CatalogSkip(name, f"mcp name may not contain '__': {name!r}"))
            continue
        if name in seen:
            skips.append(CatalogSkip(name, f"duplicate mcp name: {name}"))
            continue
        transport = raw.get("transport", "stdio")
        if transport is None:
            transport = "stdio"
        if transport not in SUPPORTED_MCP_TRANSPORTS:
            skips.append(
                CatalogSkip(name, f"mcp {name!r} has unsupported transport {transport!r}")
            )
            continue
        try:
            tools = _validate_mcp_tools(name, raw.get("tools"))
        except ProtocolError as exc:
            skips.append(CatalogSkip(name, str(exc)))
            continue
        # As in ``validate_tools``: only a published server reserves its name, so a
        # malformed first entry cannot shadow a valid later one with the same name.
        seen.add(name)
        mcps.append(EdgeMcp(name=name, transport=transport, tools=tools))
    return ValidatedCatalog(mcps, skips)


def _validate_caps(raw: Any) -> List[str]:
    """Parse ``hello.caps``; absent means the v0.4 tools-only edge."""
    if raw is None:
        return ["tools"]
    if not isinstance(raw, list):
        raise ProtocolError("hello.caps must be a list")
    caps: List[str] = []
    for cap in raw:
        if not isinstance(cap, str) or cap not in SUPPORTED_CAPS:
            raise ProtocolError(f"unknown capability: {cap!r}")
        if cap in caps:
            raise ProtocolError(f"duplicate capability: {cap}")
        caps.append(cap)
    return caps


def validate_hello(
    frame: Dict[str, Any],
) -> Tuple[int, str, List[EdgeTool], List[EdgeMcp], List[str]]:
    """Parse a hello frame, returning ``(proto, version, tools, mcps, caps)``.

    ``proto`` is the peer's actual version (1 or 2), not the module default, so
    callers can key behaviour on what the edge speaks rather than on what this
    relay prefers.

    The returned object is that five-tuple with the validated credential material on
    ``.credentials`` (``EdgeCredentials``): the edge's public key, its fingerprint,
    the rotation-overlap fingerprint and the per-export declared key names. The key
    block is optional (a v0.5 edge has none), but when present it is fully checked --
    an unparsable SPKI, a non-3072-bit key or a fingerprint that does not match the
    key closes the connection rather than pinning bad material in the registry.

    A ``lazy_catalog`` edge publishes summaries: tool entries carry no ``inputs``
    (and at most ``MAX_TOOL_SUMMARY_CHARS`` of description), MCP tool entries carry
    no ``inputSchema``. Both omissions are legal in a full hello too -- an MCP
    server with no declared schema publishes ``{}`` -- so the cap only tightens the
    tool description. Without the cap the frame is validated exactly as before.

    Entries are validated one by one: an unusable tool/MCP/credential target is
    dropped and reported on ``.errors`` (``CatalogSkip``) instead of refusing the
    hello, so one bad manifest costs that export and nothing else. The frame-level
    rules (proto, caps, an MCP catalog without the ``mcp`` capability, the key
    material) are still fatal.
    """
    proto = frame.get("proto")
    # bool is an int subclass: a JSON ``true`` must not read as proto 1.
    if (
        isinstance(proto, bool)
        or not isinstance(proto, int)
        or proto not in SUPPORTED_PROTOS
    ):
        raise ProtocolError(
            f"protocol mismatch: peer={proto!r} relay={PROTO}", CLOSE_VERSION
        )
    version = frame.get("edge_version") or ""
    if not isinstance(version, str):
        raise ProtocolError("edge_version must be a string")
    caps = _validate_caps(frame.get("caps"))
    raw_mcps = frame.get("mcps")
    if "mcp" not in caps and raw_mcps:
        # An edge that publishes catalogs it did not claim is not understood by
        # this relay; refusing beats silently dropping them.
        raise ProtocolError("hello.mcps requires the 'mcp' capability")
    mcps = validate_mcps(raw_mcps) if "mcp" in caps else ValidatedCatalog()
    credentials, credential_skips = _validate_edge_credentials(frame)
    tools = validate_tools(frame.get("tools"), lazy_catalog="lazy_catalog" in caps)
    return HelloValidation(
        proto,
        version[:64],
        tools,
        mcps,
        caps,
        credentials,
        errors=[*getattr(tools, "errors", ()), *getattr(mcps, "errors", ()), *credential_skips],
    )


def validate_identity(
    user: Any, user_email: Any
) -> Tuple[Optional[str], Optional[str]]:
    """Validate one frame's caller identity, returning ``(user, user_email)``.

    The identity is **derived**, never supplied: the relay builds it from the verified
    agent token's claims (``u``/``e``) and the edge trusts it over the authenticated
    tunnel. Checked on both ends because the email is forwarded verbatim into the
    edge's tool environment, so a newline or NUL must not get in -- and checked at the
    relay *before* the frame is sent, because the edge reports a bad value as a
    tool_error rather than the 400 this path promises.
    """
    if user is not None and not isinstance(user, str):
        raise ProtocolError("call.user must be a string or null")

    if user_email is not None:
        if not isinstance(user_email, str):
            raise ProtocolError("call.user_email must be a string or null")
        if len(user_email) > MAX_USER_EMAIL_CHARS:
            raise ProtocolError(
                f"call.user_email exceeds {MAX_USER_EMAIL_CHARS} characters"
            )
        if any(ord(char) < 32 for char in user_email):
            raise ProtocolError("call.user_email must not contain control characters")
    return user, user_email


def _identity_string(value: Any, field: str, limit: int) -> Optional[str]:
    """One optional identity string: type, length and control-character rules.

    Shared by the identity validators so the relay's pre-send check and the edge's
    on-arrival check cannot drift (a mismatch costs the tunnel: the edge closes it).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProtocolError(f"call.{field} must be a string or null")
    if len(value) > limit:
        raise ProtocolError(f"call.{field} exceeds {limit} characters")
    if any(ord(char) < 32 for char in value):
        raise ProtocolError(f"call.{field} must not contain control characters")
    return value


def _identity_groups(value: Any) -> List[str]:
    """The caller's groups: a bounded list of non-empty, control-character-free names."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ProtocolError("call.groups must be a list of strings or null")
    if len(value) > MAX_GROUPS:
        raise ProtocolError(f"call.groups exceeds {MAX_GROUPS} entries")
    names: List[str] = []
    for name in value:
        if not isinstance(name, str) or not name:
            raise ProtocolError("call.groups must contain non-empty strings")
        if len(name) > MAX_GROUP_NAME_CHARS:
            raise ProtocolError(f"call.groups entry exceeds {MAX_GROUP_NAME_CHARS} characters")
        if any(ord(char) < 32 for char in name):
            raise ProtocolError("call.groups entries must not contain control characters")
        names.append(name)
    return names


def validate_run_identity(
    agent: Any = None,
    groups: Any = None,
    run_id: Any = None,
    parent_run_id: Any = None,
) -> Dict[str, Any]:
    """Validate one frame's run attribution, returning only the keys to send.

    R1 removed the agent token from the call frame, so these four keys (named as in
    ``core.execution.contract.RunIdentity``) are the whole of what the edge learns
    about the run behind a call. Every one is derived by the relay from the verified
    token's claims, never from a request body, and the edge trusts them over the
    authenticated tunnel.

    Absent values are dropped rather than sent as nulls: a token-less caller produces
    ``{}``, and an older edge then sees a frame shaped exactly as before. Called by the
    relay *before* sending (so a malformed claim is a ``400``, not a closed tunnel) and
    by :func:`validate_call` on arrival.
    """
    out: Dict[str, Any] = {}
    agent = _identity_string(agent, "agent", MAX_AGENT_NAME_CHARS)
    if agent is not None:
        out["agent"] = agent
    names = _identity_groups(groups)
    if names:
        out["groups"] = names
    run_id = _identity_string(run_id, "run_id", MAX_RUN_ID_CHARS)
    if run_id is not None:
        out["run_id"] = run_id
    parent_run_id = _identity_string(parent_run_id, "parent_run_id", MAX_RUN_ID_CHARS)
    if parent_run_id is not None:
        out["parent_run_id"] = parent_run_id
    return out


def validate_call(frame: Dict[str, Any]) -> Dict[str, Any]:
    call_id = frame.get("id")
    if not isinstance(call_id, str) or not call_id or len(call_id) > 128:
        raise ProtocolError("call.id must be a non-empty string")

    # Absent means a v0.4 tool call: the frame shape predates MCP routing.
    kind = frame.get("kind") or "tool"
    if kind not in ("tool", "mcp"):
        raise ProtocolError(f"invalid call.kind: {kind!r}")

    mcp: Optional[str] = None
    if kind == "mcp":
        mcp = frame.get("mcp")
        if not isinstance(mcp, str) or not NAME_RE.match(mcp):
            raise ProtocolError(f"invalid call.mcp: {mcp!r}")
        _check_namespace(mcp, "call.mcp")

    tool = frame.get("tool")
    if not isinstance(tool, str) or not NAME_RE.match(tool):
        raise ProtocolError(f"invalid call.tool: {tool!r}")

    # object + size only. MCP arguments are validated by the target server (its
    # schemas are discriminated unions); coercing here would rewrite the caller's
    # payload and rejecting unknown keys would break every union branch.
    args = frame.get("args") or {}
    if not isinstance(args, dict):
        raise ProtocolError("call.args must be an object")
    if len(encode(args).encode("utf-8")) > MAX_ARGS_BYTES:
        raise ProtocolError(f"call.args exceeds {MAX_ARGS_BYTES} bytes")

    deadline = frame.get("deadline_ms", DEFAULT_DEADLINE_MS)
    if not isinstance(deadline, int) or isinstance(deadline, bool):
        raise ProtocolError("call.deadline_ms must be an integer")
    deadline = max(1_000, min(deadline, MAX_DEADLINE_MS))

    # Caller identity, derived by the relay from the verified agent token's claims
    # (``u``/``e``) and never taken from a request body. The edge trusts it over the
    # authenticated tunnel and does not re-verify any token.
    user, user_email = validate_identity(frame.get("user"), frame.get("user_email"))

    # The agent token is no longer sent (R1): the relay is the only verifier, so the
    # edge receives the identity it resolved instead of a credential it would have to
    # hold a signing key for. Accepted here only for wire tolerance with an older relay
    # -- nothing on the edge consumes it, and only its shape is checked because it would
    # cross the tunnel verbatim.
    agent_token = frame.get("agent_token")
    if agent_token is not None:
        if not isinstance(agent_token, str):
            raise ProtocolError("call.agent_token must be a string or null")
        if len(agent_token) > MAX_AGENT_TOKEN_CHARS:
            raise ProtocolError(
                f"call.agent_token exceeds {MAX_AGENT_TOKEN_CHARS} characters"
            )
        if any(ord(char) < 32 for char in agent_token):
            raise ProtocolError(
                "call.agent_token must not contain control characters"
            )

    # Run attribution, from the same claims-derived identity as ``user``/``user_email``.
    run_identity = validate_run_identity(
        frame.get("agent"),
        frame.get("groups"),
        frame.get("run_id"),
        frame.get("parent_run_id"),
    )

    # The sealed per-user credential envelope is opaque to the relay: shape and size
    # only (``edge_crypto.validate_blob``), never decryptability. Central may have
    # sealed it to a key the edge has since rotated, so requiring the *current* key id
    # here would reject a blob the edge can still open during the overlap.
    sealed = frame.get("sealed")
    if sealed is not None:
        try:
            edge_crypto.validate_blob(sealed)
        except edge_crypto.SealedError as exc:
            raise ProtocolError(f"call.sealed is invalid: {exc}") from None

    return {
        "id": call_id,
        "kind": kind,
        "mcp": mcp,
        "tool": tool,
        "args": args,
        "deadline_ms": deadline,
        "user": user,
        "user_email": user_email,
        "agent_token": agent_token,
        # agent/groups/run_id/parent_run_id: only the ones the relay resolved.
        **run_identity,
        "sealed": sealed,
    }


def validate_result(frame: Dict[str, Any]) -> Dict[str, Any]:
    call_id = frame.get("id")
    if not isinstance(call_id, str) or not call_id:
        raise ProtocolError("result.id must be a non-empty string")

    ok = frame.get("ok")
    if not isinstance(ok, bool):
        raise ProtocolError("result.ok must be a boolean")

    if ok:
        result: Dict[str, Any] = {
            "id": call_id,
            "ok": True,
            "result": frame.get("result"),
        }
        if "detail" in frame:
            # The lazy-catalog reply. Only the shape is checked here; the caller
            # validates the entry with validate_tool_detail / validate_mcp_tool_detail.
            detail = frame["detail"]
            if not isinstance(detail, dict):
                raise ProtocolError("result.detail must be an object")
            result["detail"] = detail
        return result

    error = frame.get("error")
    if not isinstance(error, dict):
        raise ProtocolError("result.error must be an object when ok is false")
    code = error.get("code") or "tool_error"
    message = error.get("message") or "tool failed"
    if not isinstance(code, str) or not isinstance(message, str):
        raise ProtocolError("result.error.code/message must be strings")
    return {
        "id": call_id,
        "ok": False,
        "error": {"code": code[:64], "message": message[:2000]},
    }


def coerce_arg(value: Any, spec: Dict[str, Any], key: str) -> Any:
    """Validate one argument against its tool.yaml input spec, coercing as the hub does.

    The hub stringifies string inputs before handing them to a tool
    (``core/hub.py:handler``); the edge applies the same rule so a remote tool
    sees exactly what a local one would. Numeric strings are accepted for
    integer/number inputs for the same reason: an MCP client that sends ``"5"``
    succeeds against a local tool through pydantic's lax coercion, so it must
    not start failing just because the tool moved to an edge.
    """
    input_type = spec.get("type", "string")
    if input_type == "string":
        coerced = value if isinstance(value, str) else str(value)
        enum = spec.get("enum")
        if enum and coerced not in enum:
            raise ProtocolError(f"argument {key!r} must be one of {enum}")
        return coerced
    if input_type == "integer":
        if isinstance(value, bool):
            raise ProtocolError(f"argument {key!r} must be an integer")
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value)
        raise ProtocolError(f"argument {key!r} must be an integer")
    if input_type == "number":
        if isinstance(value, bool):
            raise ProtocolError(f"argument {key!r} must be a number")
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                pass
        raise ProtocolError(f"argument {key!r} must be a number")
    if input_type == "boolean":
        if not isinstance(value, bool):
            raise ProtocolError(f"argument {key!r} must be a boolean")
        return value
    if input_type == "array":
        if not isinstance(value, list):
            raise ProtocolError(f"argument {key!r} must be an array")
        return value
    if input_type == "object":
        if not isinstance(value, dict):
            raise ProtocolError(f"argument {key!r} must be an object")
        return value
    raise ProtocolError(f"argument {key!r} has unsupported type {input_type!r}")


def args_for_tool(tool: EdgeTool, args: Dict[str, Any]) -> Dict[str, Any]:
    """Strict argument check against the tool's published schema.

    Unknown keys are rejected, not ignored: accepting extras would let a caller
    slip unvalidated kwargs into the tool subprocess. Both ends run this, so a
    compromised relay cannot widen the surface.
    """
    unknown = set(args) - set(tool.inputs)
    if unknown:
        raise ProtocolError(f"unknown arguments: {', '.join(sorted(unknown))}")

    cleaned: Dict[str, Any] = {}
    for key, spec in tool.inputs.items():
        if key in args and args[key] is not None:
            cleaned[key] = coerce_arg(args[key], spec, key)
        elif spec.get("required"):
            raise ProtocolError(f"missing required argument: {key}")
    return cleaned


def tool_name(site: str, tool: str) -> str:
    """Registry name for a remote tool. The site prefix is also the routing key."""
    return f"{site}__{tool}"


def validate_site_name(site: Any) -> str:
    """Site ids become half of a registry key, so they obey the same rules."""
    if not isinstance(site, str) or not NAME_RE.match(site):
        raise ProtocolError(f"invalid site name: {site!r}")
    _check_namespace(site, "site name")
    return site


def split_tool_name(name: str) -> Optional[Tuple[str, str]]:
    if "__" not in name:
        return None
    site, tool = name.split("__", 1)
    if site and tool:
        return site, tool
    return None
