# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Contract tests for the edge tunnel frame protocol.

Both ends share ``services/edge_relay/protocol.py``; a change here silently
breaks the other side, so these pin the closed-set frame rules, the close codes
and the argument coercion the hub already applies to local tools.
"""

import json

import pytest

from services.edge_relay import protocol


def test_unknown_frame_type_closes_with_4400():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.decode('{"t":"wat"}', protocol.EDGE_FRAMES)
    assert exc.value.close_code == protocol.CLOSE_UNKNOWN_TYPE


def test_direction_is_enforced():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.decode('{"t":"call","id":"1"}', protocol.EDGE_FRAMES)
    assert exc.value.close_code == protocol.CLOSE_UNKNOWN_TYPE

    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.decode('{"t":"result","id":"1","ok":true}', protocol.RELAY_FRAMES)
    assert exc.value.close_code == protocol.CLOSE_UNKNOWN_TYPE


@pytest.mark.parametrize(
    "raw",
    ["not json", "[]", '"string"', b"\xff\xfe"],
)
def test_malformed_frames_are_rejected(raw):
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.decode(raw, protocol.EDGE_FRAMES)
    assert exc.value.close_code == protocol.CLOSE_MALFORMED


def test_oversize_frame_is_rejected(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_FRAME_BYTES", 16)
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.decode(b"x" * 17, protocol.EDGE_FRAMES)
    assert "exceeds" in str(exc.value)

    with pytest.raises(protocol.ProtocolError):
        protocol.decode("x" * 17, protocol.EDGE_FRAMES)


def test_missing_frame_type_is_rejected():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.decode("{}", protocol.EDGE_FRAMES)
    assert exc.value.close_code == protocol.CLOSE_UNKNOWN_TYPE


def test_encode_decode_roundtrip():
    frame = {"t": "ping"}
    assert protocol.decode(protocol.encode(frame), protocol.EDGE_FRAMES) == frame


def test_hello_version_mismatch_closes_with_4001():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_hello({"proto": protocol.PROTO + 1, "edge_version": "1.0"})
    assert exc.value.close_code == protocol.CLOSE_VERSION


def test_hello_accepts_and_trims_catalog():
    proto, version, tools, mcps, caps = protocol.validate_hello(
        {
            "proto": protocol.PROTO,
            "edge_version": "x" * 100,
            "tools": [{"name": "boiler_status", "description": "d" * 4000}],
        }
    )
    assert proto == protocol.PROTO
    assert len(version) == 64
    assert [tool.name for tool in tools] == ["boiler_status"]
    assert len(tools[0].description) == 2000
    assert mcps == []
    assert caps == ["tools"]


def _skips(catalog) -> str:
    """The reasons a per-entry validator dropped entries, joined for assertions."""
    return " | ".join(skip.describe() for skip in catalog.errors)


def test_duplicate_tool_names_are_skipped_not_fatal():
    """Per-entry validation: the duplicate is dropped, the first one is published."""
    catalog = protocol.validate_tools([{"name": "dup"}, {"name": "dup"}])

    assert [tool.name for tool in catalog] == ["dup"]
    assert "duplicate" in _skips(catalog)


def test_a_malformed_entry_does_not_shadow_a_valid_one_with_the_same_name():
    """``seen`` is reserved by the successful append, not by the name check.

    Otherwise a bad first entry would consume "a", the second (valid) entry would be
    dropped as a duplicate, and the template would publish nothing while reporting
    only the schema error.
    """
    catalog = protocol.validate_tools(
        [{"name": "a", "description": 123}, {"name": "a", "description": "ok"}]
    )

    assert [tool.name for tool in catalog] == ["a"]
    assert len(catalog.errors) == 1
    assert "description must be a string" in _skips(catalog)


@pytest.mark.parametrize("name", ["", "has space", "starts.with.dot", "x" * 65])
def test_invalid_tool_names_are_skipped(name):
    catalog = protocol.validate_tools([{"name": "good"}, {"name": name}])

    assert [tool.name for tool in catalog] == ["good"]
    assert _skips(catalog)


def test_catalog_cap_is_enforced(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_TOOLS", 2)
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_tools([{"name": "a"}, {"name": "b"}, {"name": "c"}])
    assert "exceeds" in str(exc.value)


def test_input_specs_are_normalized():
    tools = protocol.validate_tools(
        [
            {
                "name": "t",
                "inputs": {
                    "q": {"type": "string", "required": True, "description": "d"},
                    "mode": {"type": "string", "enum": ["a", 1]},
                    "plain": None,
                },
            }
        ]
    )
    inputs = tools[0].inputs
    assert inputs["q"] == {"type": "string", "required": True, "description": "d"}
    assert inputs["mode"]["enum"] == ["a", "1"]
    assert inputs["plain"] == {"type": "string", "required": False}


def test_unsupported_input_type_skips_that_tool_only():
    catalog = protocol.validate_tools(
        [{"name": "t", "inputs": {"q": {"type": "decimal"}}}, {"name": "ok"}]
    )

    assert [tool.name for tool in catalog] == ["ok"]
    assert "unsupported type" in _skips(catalog)


def _tool():
    return protocol.EdgeTool(
        name="echo",
        inputs={
            "q": {"type": "string", "required": True},
            "n": {"type": "integer"},
            "ratio": {"type": "number"},
            "loud": {"type": "boolean"},
            "tags": {"type": "array"},
            "extra": {"type": "object"},
            "mode": {"type": "string", "enum": ["fast", "slow"]},
        },
    )


def test_args_reject_unknown_keys():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.args_for_tool(_tool(), {"q": "x", "sneaky": 1})
    assert "unknown arguments" in str(exc.value)
    assert "sneaky" in str(exc.value)


def test_args_enforce_required():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.args_for_tool(_tool(), {})
    assert "missing required argument: q" in str(exc.value)

    with pytest.raises(protocol.ProtocolError):
        protocol.args_for_tool(_tool(), {"q": None})


def test_args_coerce_strings_like_the_hub():
    assert protocol.args_for_tool(_tool(), {"q": 5}) == {"q": "5"}


def test_args_coerce_numeric_strings():
    cleaned = protocol.args_for_tool(_tool(), {"q": "x", "n": "5", "ratio": "1.5"})
    assert cleaned == {"q": "x", "n": 5, "ratio": 1.5}


def test_args_reject_wrong_integer_types():
    for bad in (1.5, True, "abc"):
        with pytest.raises(protocol.ProtocolError) as exc:
            protocol.args_for_tool(_tool(), {"q": "x", "n": bad})
        assert "must be an integer" in str(exc.value)


def test_args_reject_wrong_number_and_boolean_types():
    with pytest.raises(protocol.ProtocolError):
        protocol.args_for_tool(_tool(), {"q": "x", "ratio": True})
    with pytest.raises(protocol.ProtocolError):
        protocol.args_for_tool(_tool(), {"q": "x", "loud": 1})


def test_args_reject_wrong_collection_types():
    with pytest.raises(protocol.ProtocolError):
        protocol.args_for_tool(_tool(), {"q": "x", "tags": {"a": 1}})
    with pytest.raises(protocol.ProtocolError):
        protocol.args_for_tool(_tool(), {"q": "x", "extra": [1]})


def test_args_enforce_enum():
    assert protocol.args_for_tool(_tool(), {"q": "x", "mode": "fast"})["mode"] == "fast"
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.args_for_tool(_tool(), {"q": "x", "mode": "turbo"})
    assert "must be one of" in str(exc.value)


def test_args_drop_null_optionals():
    assert protocol.args_for_tool(_tool(), {"q": "x", "n": None}) == {"q": "x"}


def test_tool_name_roundtrip():
    name = protocol.tool_name("plant-floor", "boiler_status")
    assert name == "plant-floor__boiler_status"
    assert protocol.split_tool_name(name) == ("plant-floor", "boiler_status")


def test_namespace_separator_is_reserved():
    catalog = protocol.validate_tools([{"name": "a__b"}, {"name": "fine"}])

    assert [tool.name for tool in catalog] == ["fine"]
    assert "'__'" in _skips(catalog)


def test_validate_site_name_rules():
    assert protocol.validate_site_name("plant-floor") == "plant-floor"
    for bad in ("", "has space", "bad__site", None, 7):
        with pytest.raises(protocol.ProtocolError):
            protocol.validate_site_name(bad)


def test_split_tool_name_rejects_unnamespaced():
    assert protocol.split_tool_name("boiler_status") is None
    assert protocol.split_tool_name("__tool") is None
    assert protocol.split_tool_name("site__") is None


def test_split_tool_name_keeps_double_underscore_in_tool():
    assert protocol.split_tool_name("site__a__b") == ("site", "a__b")


def test_result_success_is_normalized():
    parsed = protocol.validate_result(
        {"t": "result", "id": "c1", "ok": True, "result": {"x": 1}, "ms": 3}
    )
    assert parsed == {"id": "c1", "ok": True, "result": {"x": 1}}


def test_result_failure_requires_error():
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_result({"t": "result", "id": "c1", "ok": False})

    parsed = protocol.validate_result(
        {"t": "result", "id": "c1", "ok": False, "error": {"code": "boom", "message": "m"}}
    )
    assert parsed == {"id": "c1", "ok": False, "error": {"code": "boom", "message": "m"}}


def test_result_defaults_missing_error_fields():
    parsed = protocol.validate_result({"id": "c1", "ok": False, "error": {}})
    assert parsed["error"] == {"code": "tool_error", "message": "tool failed"}


@pytest.mark.parametrize(
    "frame",
    [
        {"id": "", "ok": True},
        {"id": "c1", "ok": "yes"},
        {"ok": True},
        {"id": "c1", "ok": False, "error": "boom"},
    ],
)
def test_result_rejects_bad_shapes(frame):
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_result(frame)


def test_validate_call_clamps_deadline_and_keeps_args():
    parsed = protocol.validate_call(
        {"t": "call", "id": "c1", "tool": "echo", "args": {"q": "x"}, "deadline_ms": 1}
    )
    assert parsed["deadline_ms"] == 1_000
    assert parsed["args"] == {"q": "x"}

    parsed = protocol.validate_call(
        {"id": "c1", "tool": "echo", "deadline_ms": protocol.MAX_DEADLINE_MS + 1}
    )
    assert parsed["deadline_ms"] == protocol.MAX_DEADLINE_MS


def test_validate_call_defaults_above_the_hub_timeout():
    assert protocol.DEFAULT_DEADLINE_MS == 330_000
    parsed = protocol.validate_call({"id": "c1", "tool": "echo"})
    assert parsed["deadline_ms"] == protocol.DEFAULT_DEADLINE_MS


def test_validate_call_rejects_boolean_deadline():
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_call({"id": "c1", "tool": "echo", "deadline_ms": True})


def test_validate_call_rejects_oversize_args(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_ARGS_BYTES", 8)
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_call({"id": "c1", "tool": "echo", "args": {"q": "x" * 20}})
    assert "exceeds" in str(exc.value)


def test_validate_call_accepts_null_user():
    parsed = protocol.validate_call({"id": "c1", "tool": "echo", "user": None, "args": {}})
    assert parsed["user"] is None
    assert json.loads(protocol.encode(parsed))["tool"] == "echo"


def test_validate_call_keeps_user_email():
    parsed = protocol.validate_call(
        {"id": "c1", "tool": "echo", "user_email": "ann@example.com"}
    )
    assert parsed["user_email"] == "ann@example.com"


def test_validate_call_user_email_defaults_to_none():
    assert protocol.validate_call({"id": "c1", "tool": "echo"})["user_email"] is None
    assert (
        protocol.validate_call({"id": "c1", "tool": "echo", "user_email": None})["user_email"]
        is None
    )


@pytest.mark.parametrize(
    "value",
    [123, 1.5, True, ["a@b"], {"email": "a@b"}],
    ids=["int", "float", "bool", "list", "dict"],
)
def test_validate_call_rejects_non_string_user_email(value):
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_call({"id": "c1", "tool": "echo", "user_email": value})
    assert "call.user_email must be a string or null" in str(exc.value)


def test_validate_call_rejects_oversize_user_email():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_call(
            {"id": "c1", "tool": "echo", "user_email": "a" * (protocol.MAX_USER_EMAIL_CHARS + 1)}
        )
    assert "exceeds" in str(exc.value)

    at_cap = "a" * protocol.MAX_USER_EMAIL_CHARS
    assert protocol.validate_call({"id": "c1", "tool": "echo", "user_email": at_cap})[
        "user_email"
    ] == at_cap


@pytest.mark.parametrize("value", ["ann@example.com\n", "\x00", "a\rb", "tab\there"])
def test_validate_call_rejects_control_chars_in_user_email(value):
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_call({"id": "c1", "tool": "echo", "user_email": value})
    assert "control characters" in str(exc.value)


def _validate_call_v04(frame):
    """The v0.4 ``validate_call`` shape: reads known keys, ignores extras.

    Frozen here on purpose. Adding ``user_email`` must not require a proto bump,
    which only holds while the old parser keeps accepting frames that carry it.
    """
    call_id = frame.get("id")
    tool = frame.get("tool")
    args = frame.get("args") or {}
    deadline = frame.get("deadline_ms", protocol.DEFAULT_DEADLINE_MS)
    user = frame.get("user")
    return {
        "id": call_id,
        "tool": tool,
        "args": args,
        "deadline_ms": max(1_000, min(deadline, protocol.MAX_DEADLINE_MS)),
        "user": user,
    }


def test_v04_parser_ignores_a_v05_user_email():
    """v0.5 central → v0.4 edge: the extra key is tolerated, the call still runs."""
    parsed = _validate_call_v04(
        {
            "t": "call",
            "id": "c1",
            "tool": "echo",
            "args": {"text": "hi"},
            "user": "user-1",
            "user_email": "ann@example.com",
        }
    )

    assert parsed["user"] == "user-1"
    assert parsed["tool"] == "echo"
    assert "user_email" not in parsed


# --- v0.5: MCP export (proto 2) ---------------------------------------------


def _meta_tool_schema(branches: int = 38) -> dict:
    """The workload's shape: a root-level ``oneOf`` with no top-level properties."""
    return {
        "type": "object",
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "action": {"const": f"action_{index}"},
                    "params": {
                        "type": "object",
                        "properties": {
                            f"param_{slot}": {"type": "string", "description": "x" * 64}
                            for slot in range(6)
                        },
                    },
                },
                "required": ["action", "params"],
            }
            for index in range(branches)
        ],
    }


def _mcp_entry(schema=None, **overrides):
    entry = {
        "name": "devops-cli",
        "transport": "stdio",
        "tools": [
            {
                "name": "tenant_account_tools",
                "description": "meta",
                "inputSchema": schema if schema is not None else {"type": "object"},
            }
        ],
    }
    entry.update(overrides)
    return entry


def test_proto_is_two_and_v1_is_still_accepted():
    assert protocol.PROTO == 2
    assert protocol.SUPPORTED_PROTOS == {1, 2}


def test_mcp_caps_are_the_documented_values():
    assert protocol.MAX_MCPS == 50
    assert protocol.MAX_MCP_TOOLS_PER_SERVER == 256
    assert protocol.MAX_MCP_SCHEMA_BYTES == 131_072
    assert protocol.MAX_MCP_DESC_CHARS == 8_192


def test_validate_mcps_accepts_empty_catalogs():
    assert protocol.validate_mcps(None) == []
    assert protocol.validate_mcps([]) == []


def test_a_bad_credential_key_target_is_skipped_not_fatal():
    """A hyphenated key costs that target's seal form, not the tunnel (v0.7.1)."""
    hello = protocol.validate_hello(
        {
            "proto": protocol.PROTO,
            "tools": [{"name": "boiler_status"}],
            "credential_keys": {
                "boiler_status": {"secret_keys": ["DEVOPS_PASSWORD"]},
                "node_ssh": {"secret_keys": ["my-api-key"]},
            },
        }
    )

    assert hello.credentials.credential_keys == {
        "boiler_status": {"secret_keys": ["DEVOPS_PASSWORD"], "variable_keys": []}
    }
    (skip,) = hello.errors
    assert skip.name == "node_ssh"
    assert "my-api-key" in skip.reason


def test_an_ambiguous_credential_key_target_is_skipped():
    hello = protocol.validate_hello(
        {
            "proto": protocol.PROTO,
            "credential_keys": {
                "ok": {"secret_keys": ["A"]},
                "both": {"secret_keys": ["X"], "variable_keys": ["X"]},
                "odd": {"secret_keys": ["A"], "unknown_key": []},
            },
        }
    )

    assert list(hello.credentials.credential_keys) == ["ok"]
    assert sorted(skip.name for skip in hello.errors) == ["both", "odd"]


def test_bad_key_material_is_still_fatal():
    """The crypto half stays all-or-nothing: it is pinned in the registry."""
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_hello(
            {
                "proto": protocol.PROTO,
                "edge_pubkey": "bm90LWEta2V5",
                "edge_key_fp": "SHA256:whatever",
            }
        )


@pytest.mark.parametrize("raw", ["srv", 7, True, {"name": "srv"}])
def test_validate_mcps_requires_a_list(raw):
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_mcps(raw)
    assert "must be a list" in str(exc.value)


def test_validate_mcps_carries_a_root_union_schema_verbatim():
    schema = _meta_tool_schema()
    size = len(json.dumps(schema, separators=(",", ":")).encode("utf-8"))
    assert 25_000 < size < 40_000

    (mcp,) = protocol.validate_mcps([_mcp_entry(schema)])

    assert mcp.name == "devops-cli"
    assert mcp.transport == "stdio"
    tool = mcp.tools[0]
    # By reference: no key cleaning, no re-serialization.
    assert tool.input_schema is schema
    assert json.dumps(tool.input_schema, sort_keys=True) == json.dumps(schema, sort_keys=True)
    assert mcp.as_dict() == {
        "name": "devops-cli",
        "transport": "stdio",
        "tools": [
            {"name": "tenant_account_tools", "description": "meta", "inputSchema": schema}
        ],
    }


def test_mcp_schema_survives_the_wire_byte_identically():
    schema = _meta_tool_schema()
    frame = {
        "t": "hello",
        "proto": 2,
        "edge_version": "0.5.0",
        "caps": ["tools", "mcp"],
        "tools": [],
        "mcps": [_mcp_entry(schema)],
    }
    encoded = protocol.encode(frame)
    assert len(encoded.encode("utf-8")) <= protocol.MAX_FRAME_BYTES

    _, _, _, mcps, _ = protocol.validate_hello(
        protocol.decode(encoded, protocol.EDGE_FRAMES)
    )

    assert json.dumps(mcps[0].tools[0].input_schema, sort_keys=True) == json.dumps(
        schema, sort_keys=True
    )


def test_mcp_server_cap_is_enforced(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_MCPS", 2)
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_mcps([{"name": name} for name in ("a", "b", "c")])
    assert "exceeds" in str(exc.value)


@pytest.mark.parametrize("name", ["", "has space", "x" * 65, 7, None])
def test_invalid_mcp_names_are_skipped(name):
    catalog = protocol.validate_mcps([{"name": name}, {"name": "good"}])

    assert [mcp.name for mcp in catalog] == ["good"]
    assert _skips(catalog)


def test_mcp_names_cannot_contain_the_namespace_separator():
    catalog = protocol.validate_mcps([{"name": "devops__cli"}, {"name": "cli"}])

    assert [mcp.name for mcp in catalog] == ["cli"]
    assert "'__'" in _skips(catalog)


def test_duplicate_mcp_names_are_skipped_not_fatal():
    catalog = protocol.validate_mcps([{"name": "dup"}, {"name": "dup"}])

    assert [mcp.name for mcp in catalog] == ["dup"]
    assert "duplicate" in _skips(catalog)


def test_a_malformed_mcp_entry_does_not_shadow_a_valid_one_with_the_same_name():
    """Same rule as ``validate_tools``: only a published server reserves its name."""
    catalog = protocol.validate_mcps(
        [{"name": "srv", "transport": "websocket"}, {"name": "srv"}]
    )

    assert [mcp.name for mcp in catalog] == ["srv"]
    assert len(catalog.errors) == 1
    assert "unsupported transport" in _skips(catalog)


@pytest.mark.parametrize("transport", ["stdio", "http", "streamable-http", "sse"])
def test_supported_mcp_transports_are_accepted(transport):
    (mcp,) = protocol.validate_mcps([{"name": "srv", "transport": transport}])
    assert mcp.transport == transport


def test_mcp_transport_defaults_to_stdio():
    assert protocol.validate_mcps([{"name": "srv"}])[0].transport == "stdio"


@pytest.mark.parametrize("transport", ["websocket", "", 7])
def test_unknown_mcp_transport_skips_that_server(transport):
    catalog = protocol.validate_mcps(
        [{"name": "srv", "transport": transport}, {"name": "good"}]
    )

    assert [mcp.name for mcp in catalog] == ["good"]
    assert "transport" in _skips(catalog)


def test_mcp_tool_cap_skips_that_server(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_MCP_TOOLS_PER_SERVER", 2)
    catalog = protocol.validate_mcps(
        [
            {"name": "srv", "tools": [{"name": name} for name in ("a", "b", "c")]},
            {"name": "good"},
        ]
    )

    assert [mcp.name for mcp in catalog] == ["good"]
    assert "exceeds" in _skips(catalog)


def test_duplicate_mcp_tool_names_skip_that_server():
    catalog = protocol.validate_mcps(
        [
            {"name": "srv", "tools": [{"name": "dup"}, {"name": "dup"}]},
            {"name": "good"},
        ]
    )

    assert [mcp.name for mcp in catalog] == ["good"]
    assert "duplicate" in _skips(catalog)


def test_mcp_tool_names_skip_the_server_on_a_reserved_separator():
    catalog = protocol.validate_mcps(
        [
            {"name": "srv", "tools": [{"name": "a__b"}]},
            {"name": "good"},
        ]
    )

    assert [mcp.name for mcp in catalog] == ["good"]
    assert "'__'" in _skips(catalog)


@pytest.mark.parametrize("schema", ["{}", 7, ["oneOf"], True])
def test_non_object_input_schema_skips_that_server(schema):
    catalog = protocol.validate_mcps(
        [
            {"name": "srv", "tools": [{"name": "t", "inputSchema": schema}]},
            {"name": "good"},
        ]
    )

    assert [mcp.name for mcp in catalog] == ["good"]
    assert "inputSchema must be an object" in _skips(catalog)


def test_oversize_input_schema_skips_that_server():
    schema = {"type": "object", "description": "x" * protocol.MAX_MCP_SCHEMA_BYTES}
    catalog = protocol.validate_mcps(
        [
            {"name": "srv", "tools": [{"name": "t", "inputSchema": schema}]},
            {"name": "good"},
        ]
    )

    assert [mcp.name for mcp in catalog] == ["good"]
    assert "exceeds" in _skips(catalog)


def test_long_mcp_description_is_truncated_not_rejected():
    tool = protocol.validate_mcps(
        [{"name": "srv", "tools": [{"name": "t", "description": "d" * 20_000}]}]
    )[0].tools[0]
    assert len(tool.description) == protocol.MAX_MCP_DESC_CHARS


def test_proto1_hello_is_tools_only():
    proto, _, tools, mcps, caps = protocol.validate_hello(
        {"proto": 1, "edge_version": "0.4.1", "tools": [{"name": "echo"}]}
    )

    assert proto == 1
    assert [tool.name for tool in tools] == ["echo"]
    assert mcps == []
    assert caps == ["tools"]


def test_proto2_hello_carries_mcps_and_caps():
    proto, _, _, mcps, caps = protocol.validate_hello(
        {
            "proto": 2,
            "edge_version": "0.5.0",
            "caps": ["tools", "mcp"],
            "tools": [],
            "mcps": [{"name": "devops-cli", "tools": [{"name": "tenant_account_tools"}]}],
        }
    )

    assert proto == 2
    assert caps == ["tools", "mcp"]
    assert [mcp.name for mcp in mcps] == ["devops-cli"]


def test_proto3_hello_closes_with_4001():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_hello({"proto": 3, "edge_version": "0.6.0"})
    assert exc.value.close_code == protocol.CLOSE_VERSION


@pytest.mark.parametrize("proto", ["2", 2.0, True, None, 0])
def test_hello_proto_must_be_a_supported_integer(proto):
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_hello({"proto": proto})
    assert exc.value.close_code == protocol.CLOSE_VERSION


@pytest.mark.parametrize("caps", [["tools", "ssh"], ["TOOLS"], [1], "tools", {"tools": 1}])
def test_invalid_caps_are_rejected(caps):
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_hello({"proto": 2, "caps": caps})


def test_duplicate_caps_are_rejected():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_hello({"proto": 2, "caps": ["tools", "tools"]})
    assert "duplicate capability" in str(exc.value)


def test_mcps_without_the_mcp_capability_are_rejected():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_hello(
            {"proto": 2, "caps": ["tools"], "mcps": [{"name": "srv"}]}
        )
    assert "capability" in str(exc.value)


def test_validate_call_defaults_to_the_tool_kind():
    """v0.4 frames carry no ``kind``: the tool path is unchanged."""
    parsed = protocol.validate_call({"id": "c1", "tool": "echo", "args": {"q": 5}})

    assert parsed["kind"] == "tool"
    assert parsed["mcp"] is None
    # validate_call never coerced args; args_for_tool still owns that for tools.
    assert parsed["args"] == {"q": 5}


def test_validate_call_accepts_an_mcp_frame():
    parsed = protocol.validate_call(
        {
            "t": "call",
            "id": "c1",
            "kind": "mcp",
            "mcp": "devops-cli",
            "tool": "tenant_account_tools",
            "args": {"n": "5"},
            "user_email": "ops@example.com",
        }
    )

    assert parsed["kind"] == "mcp"
    assert parsed["mcp"] == "devops-cli"
    assert parsed["tool"] == "tenant_account_tools"
    assert parsed["user_email"] == "ops@example.com"
    # Un-coerced: the target server's schema decides, not the relay.
    assert parsed["args"] == {"n": "5"}
    assert isinstance(parsed["args"]["n"], str)


def test_mcp_call_args_are_not_shape_checked():
    """Unknown keys must survive to the server: union branches need them."""
    args = {"action": "list_actions", "extra": {"nested": True}}
    parsed = protocol.validate_call(
        {"id": "c1", "kind": "mcp", "mcp": "srv", "tool": "meta", "args": args}
    )
    assert parsed["args"] == args


def test_mcp_call_args_are_still_size_capped(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_ARGS_BYTES", 8)
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_call(
            {
                "id": "c1",
                "kind": "mcp",
                "mcp": "srv",
                "tool": "meta",
                "args": {"q": "x" * 20},
            }
        )
    assert "exceeds" in str(exc.value)


@pytest.mark.parametrize("kind", ["server", "MCP", "tool_call", 1, ["mcp"]])
def test_invalid_call_kind_is_rejected(kind):
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_call({"id": "c1", "kind": kind, "tool": "echo"})
    assert "call.kind" in str(exc.value)


@pytest.mark.parametrize("mcp", [None, "", "bad__mcp", "has space", 7])
def test_mcp_calls_require_a_namespaced_server_name(mcp):
    frame = {"id": "c1", "kind": "mcp", "tool": "meta"}
    if mcp is not None:
        frame["mcp"] = mcp
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_call(frame)
    assert "call.mcp" in str(exc.value)


def test_mcp_calls_still_validate_the_tool_name():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_call(
            {"id": "c1", "kind": "mcp", "mcp": "srv", "tool": "has space"}
        )
    assert "call.tool" in str(exc.value)


# --- sealed per-user credentials (Phase 4) -----------------------------------


def _sealed(ciphertext="AAAA"):
    return {
        "v": 1,
        "alg": "RSA-OAEP-256/AES-256-GCM",
        "key_fp": "SHA256:" + "A" * 43,
        "key_id": "abcdefghijklmnop",
        "aad": "v1|dc1|tool|echo|alice@example.com|abcdefghijklmnop",
        "wrapped_key": "AAAA",
        "iv": "AAAA",
        "ciphertext": ciphertext,
        "keys": ["DEVOPS_PASSWORD"],
    }


def test_a_call_may_carry_an_opaque_sealed_blob():
    blob = _sealed()

    validated = protocol.validate_call({"id": "c1", "tool": "echo", "sealed": blob})

    assert validated["sealed"] == blob


def test_a_call_without_sealed_carries_none():
    assert protocol.validate_call({"id": "c1", "tool": "echo"})["sealed"] is None


def test_a_malformed_sealed_blob_is_rejected():
    with pytest.raises(protocol.ProtocolError, match="call.sealed"):
        protocol.validate_call({"id": "c1", "tool": "echo", "sealed": {"v": 1}})

    with pytest.raises(protocol.ProtocolError, match="call.sealed"):
        protocol.validate_call({"id": "c1", "tool": "echo", "sealed": ["not", "an", "object"]})


def test_an_oversized_sealed_blob_is_rejected():
    from core.edge_crypto import MAX_SEALED_BYTES

    with pytest.raises(protocol.ProtocolError, match="call.sealed"):
        protocol.validate_call(
            {"id": "c1", "tool": "echo", "sealed": _sealed("A" * (MAX_SEALED_BYTES + 4))}
        )


# --- lazy catalogs (P6) ------------------------------------------------------


def _summary_entry(description=None, **overrides):
    """One lazy-catalog tool entry: a name, a short summary, no ``inputs``."""
    entry = {
        "name": "boiler_status",
        "description": "Read the boiler status." if description is None else description,
    }
    entry.update(overrides)
    return entry


def test_lazy_hello_accepts_a_summary_entry_without_inputs():
    _, _, tools, _, caps = protocol.validate_hello(
        {
            "proto": protocol.PROTO,
            "edge_version": "0.6.2",
            "caps": ["tools", "lazy_catalog"],
            "tools": [_summary_entry("s" * protocol.MAX_TOOL_SUMMARY_CHARS)],
        }
    )

    assert caps == ["tools", "lazy_catalog"]
    assert tools[0].name == "boiler_status"
    # The schema is deferred to a tool_detail read, so the entry carries none.
    assert tools[0].inputs == {}
    assert tools[0].description == "s" * protocol.MAX_TOOL_SUMMARY_CHARS


def test_lazy_hello_accepts_mcp_tools_without_an_input_schema():
    _, _, _, mcps, caps = protocol.validate_hello(
        {
            "proto": protocol.PROTO,
            "edge_version": "0.6.2",
            "caps": ["tools", "mcp", "lazy_catalog"],
            "mcps": [
                {
                    "name": "devops-cli",
                    "tools": [
                        {"name": "tenant_account_tools", "description": "manage tenants"}
                    ],
                }
            ],
        }
    )

    assert "lazy_catalog" in caps
    assert mcps[0].tools[0].input_schema == {}


def test_without_the_cap_a_summary_entry_validates_exactly_as_before():
    (tool,) = protocol.validate_tools([_summary_entry()])

    assert tool.inputs == {}
    assert tool.description == "Read the boiler status."


def test_without_the_cap_a_summary_length_description_is_not_rejected():
    """The 120-char cap only applies to a lazy hello; a full catalog keeps today's rule."""
    description = "d" * (protocol.MAX_TOOL_SUMMARY_CHARS + 80)

    (tool,) = protocol.validate_tools([_summary_entry(description)])

    assert tool.description == description


def test_a_lazy_hello_over_the_summary_cap_skips_that_tool():
    """One over-long summary costs that tool, not the tunnel (v0.7.1)."""
    description = "d" * (protocol.MAX_TOOL_SUMMARY_CHARS + 1)

    hello = protocol.validate_hello(
        {
            "proto": protocol.PROTO,
            "caps": ["tools", "lazy_catalog"],
            "tools": [_summary_entry(description), {"name": "boiler_ok"}],
        }
    )

    assert [tool.name for tool in hello[2]] == ["boiler_ok"]
    (skip,) = hello.errors
    assert skip.name == "boiler_status"
    assert "lazy_catalog" in skip.reason
    assert str(protocol.MAX_TOOL_SUMMARY_CHARS) in skip.reason


def test_validate_tool_detail_accepts_a_full_entry():
    tool = protocol.validate_tool_detail(
        {
            "name": "boiler_status",
            "description": "Read the boiler status.",
            "inputs": {"q": {"type": "string", "required": True}},
        }
    )

    assert tool == protocol.EdgeTool(
        name="boiler_status",
        description="Read the boiler status.",
        inputs={"q": {"type": "string", "required": True}},
    )


def test_validate_tool_detail_requires_a_name_and_inputs():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_tool_detail({"description": "d", "inputs": {}})
    assert "invalid tool name" in str(exc.value)

    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_tool_detail({"name": "echo", "description": "d"})
    assert "must carry inputs" in str(exc.value)


def test_validate_tool_detail_rejects_non_object_inputs():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_tool_detail(
            {"name": "echo", "description": "d", "inputs": ["q"]}
        )

    assert "inputs must be an object" in str(exc.value)


def test_validate_tool_detail_truncates_a_long_description_like_a_catalog():
    """Same 2000-char rule as ``validate_tools``: cut, not refused."""
    tool = protocol.validate_tool_detail(
        {"name": "echo", "description": "d" * 5000, "inputs": {}}
    )

    assert len(tool.description) == 2000

    (catalog_tool,) = protocol.validate_tools(
        [{"name": "echo", "description": "d" * 5000}]
    )
    assert catalog_tool.description == tool.description


def test_validate_mcp_tool_detail_accepts_the_entry_verbatim():
    schema = {
        "type": "object",
        "oneOf": [{"properties": {"action": {"const": "list_actions"}}}],
    }

    detail = protocol.validate_mcp_tool_detail(
        {
            "name": "tenant_account_tools",
            "description": "manage tenants",
            "inputSchema": schema,
        }
    )

    assert detail == {
        "name": "tenant_account_tools",
        "description": "manage tenants",
        "inputSchema": schema,
    }
    assert detail["inputSchema"] is schema


def test_validate_mcp_tool_detail_requires_the_schema():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_mcp_tool_detail(
            {"name": "tenant_account_tools", "description": "d"}
        )

    assert "must carry inputSchema" in str(exc.value)


def test_validate_mcp_tool_detail_enforces_the_schema_size_cap():
    schema = {"type": "object", "description": "x" * protocol.MAX_MCP_SCHEMA_BYTES}

    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_mcp_tool_detail(
            {"name": "tenant_account_tools", "description": "d", "inputSchema": schema}
        )

    assert f"exceeds {protocol.MAX_MCP_SCHEMA_BYTES} bytes" in str(exc.value)


def test_result_carries_a_detail_object_through():
    detail = {
        "name": "boiler_status",
        "description": "Read the boiler status.",
        "inputs": {"q": {"type": "string"}},
    }

    parsed = protocol.validate_result(
        {"t": "result", "id": "d1", "ok": True, "result": None, "detail": detail}
    )

    assert parsed == {"id": "d1", "ok": True, "result": None, "detail": detail}
    assert parsed["detail"] is detail


def test_result_rejects_a_non_object_detail():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_result(
            {"id": "d1", "ok": True, "detail": ["not", "an", "object"]}
        )

    assert "result.detail must be an object" in str(exc.value)


def test_result_without_detail_is_unchanged():
    assert protocol.validate_result({"id": "d1", "ok": True, "result": {}}) == {
        "id": "d1",
        "ok": True,
        "result": {},
    }


@pytest.mark.parametrize("frame_type", ["tool_detail", "mcp_tool_detail"])
def test_relay_only_detail_frames_are_not_edge_frames(frame_type):
    """The relay asks; the edge answers with an ordinary validated ``result``."""
    assert frame_type in protocol.RELAY_FRAMES
    assert frame_type not in protocol.EDGE_FRAMES

    raw = protocol.encode({"t": frame_type, "id": "d1", "tool": "echo"})
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.decode(raw, protocol.EDGE_FRAMES)

    assert exc.value.close_code == protocol.CLOSE_UNKNOWN_TYPE
