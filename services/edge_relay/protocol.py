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

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

PROTO = 1
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
MAX_INFLIGHT = 16
MAX_DEADLINE_MS = 3_600_000
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
RELAY_FRAMES = frozenset({"welcome", "call", "ping", "catalog", "drain"})

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


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


def validate_tools(raw_tools: Any) -> List[EdgeTool]:
    """Validate a published catalog. Names must be unique and namespace-safe."""
    if raw_tools in (None, []):
        return []
    if not isinstance(raw_tools, list):
        raise ProtocolError("hello.tools must be a list")
    if len(raw_tools) > MAX_TOOLS:
        raise ProtocolError(f"catalog exceeds {MAX_TOOLS} tools")

    tools: List[EdgeTool] = []
    seen = set()
    for raw in raw_tools:
        if not isinstance(raw, dict):
            raise ProtocolError("tool entries must be objects")
        name = raw.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ProtocolError(f"invalid tool name: {name!r}")
        _check_namespace(name, "tool name")
        if name in seen:
            raise ProtocolError(f"duplicate tool name: {name}")
        seen.add(name)
        description = raw.get("description") or ""
        if not isinstance(description, str):
            raise ProtocolError(f"tool {name!r} description must be a string")
        tools.append(
            EdgeTool(
                name=name,
                description=description[:2000],
                inputs=_validate_inputs(raw.get("inputs")),
            )
        )
    return tools


def validate_hello(frame: Dict[str, Any]) -> Tuple[int, str, List[EdgeTool]]:
    proto = frame.get("proto")
    if proto != PROTO:
        raise ProtocolError(
            f"protocol mismatch: peer={proto!r} relay={PROTO}", CLOSE_VERSION
        )
    version = frame.get("edge_version") or ""
    if not isinstance(version, str):
        raise ProtocolError("edge_version must be a string")
    return PROTO, version[:64], validate_tools(frame.get("tools"))


def validate_call(frame: Dict[str, Any]) -> Dict[str, Any]:
    call_id = frame.get("id")
    if not isinstance(call_id, str) or not call_id or len(call_id) > 128:
        raise ProtocolError("call.id must be a non-empty string")

    tool = frame.get("tool")
    if not isinstance(tool, str) or not NAME_RE.match(tool):
        raise ProtocolError(f"invalid call.tool: {tool!r}")

    args = frame.get("args") or {}
    if not isinstance(args, dict):
        raise ProtocolError("call.args must be an object")
    if len(encode(args).encode("utf-8")) > MAX_ARGS_BYTES:
        raise ProtocolError(f"call.args exceeds {MAX_ARGS_BYTES} bytes")

    deadline = frame.get("deadline_ms", DEFAULT_DEADLINE_MS)
    if not isinstance(deadline, int) or isinstance(deadline, bool):
        raise ProtocolError("call.deadline_ms must be an integer")
    deadline = max(1_000, min(deadline, MAX_DEADLINE_MS))

    user = frame.get("user")
    if user is not None and not isinstance(user, str):
        raise ProtocolError("call.user must be a string or null")

    return {
        "id": call_id,
        "tool": tool,
        "args": args,
        "deadline_ms": deadline,
        "user": user,
    }


def validate_result(frame: Dict[str, Any]) -> Dict[str, Any]:
    call_id = frame.get("id")
    if not isinstance(call_id, str) or not call_id:
        raise ProtocolError("result.id must be a non-empty string")

    ok = frame.get("ok")
    if not isinstance(ok, bool):
        raise ProtocolError("result.ok must be a boolean")

    if ok:
        return {"id": call_id, "ok": True, "result": frame.get("result")}

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
