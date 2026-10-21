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
    proto, version, tools = protocol.validate_hello(
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


def test_duplicate_tool_names_are_rejected():
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_tools([{"name": "dup"}, {"name": "dup"}])
    assert "duplicate" in str(exc.value)


@pytest.mark.parametrize("name", ["", "has space", "starts.with.dot", "x" * 65])
def test_invalid_tool_names_are_rejected(name):
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_tools([{"name": name}])


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


def test_unsupported_input_type_is_rejected():
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_tools([{"name": "t", "inputs": {"q": {"type": "decimal"}}}])


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
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.validate_tools([{"name": "a__b"}])
    assert "'__'" in str(exc.value)


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
