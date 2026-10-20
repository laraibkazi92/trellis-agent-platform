# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Generator rules for scripts/generate_egress_acl.py."""

import pytest
import yaml

from scripts.generate_egress_acl import (
    InvalidEntry,
    collect,
    main,
    minimize,
    normalize_entry,
)


def _write_tool(workspace, directory, entries):
    tool_dir = workspace / "tools" / directory
    tool_dir.mkdir(parents=True, exist_ok=True)
    (tool_dir / "tool.yaml").write_text(
        yaml.safe_dump(entries, sort_keys=False), encoding="utf-8"
    )
    (tool_dir / "main.py").write_text("", encoding="utf-8")
    return tool_dir


def _tool(name, egress=None):
    entry = {
        "name": name,
        "description": f"fixture {name}",
        "runtime": "python",
        "entrypoint": "main.py",
    }
    if egress is not None:
        entry["egress"] = egress
    return entry


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("api.example.com", "api.example.com"),
        ("API.Example.COM", "api.example.com"),
        ("api.example.com.", "api.example.com"),
        ("*.api.example.com", "api.example.com"),
        ("*.Example.Com.", "example.com"),
        ("  example.org  ", "example.org"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
    ],
)
def test_normalize_entry_accepts_domains_and_wildcards(raw, expected):
    assert normalize_entry(raw) == expected


@pytest.mark.parametrize(
    "raw, message",
    [
        ("https://example.com", "schemes"),
        ("example.com/path", "paths"),
        ("example.com:443", "ports"),
        ("two words.com", "whitespace"),
        ("*example.com", "wildcard"),
        ("api.*.example.com", "wildcard"),
        ("com", "bare top-level"),
        ("127.0.0.1", "IP literals"),
        ("::1", "IP literals"),
        ("[::1]", "ports"),
        ("", "empty"),
        ("a" * 254 + ".com", "253"),
        ("foo..bar", "empty label"),
        ("-foo.example.com", "label"),
        ("foo-.example.com", "label"),
        ("bücher.example", "label"),
        (123, "string"),
    ],
)
def test_normalize_entry_rejects_invalid_entries(raw, message):
    with pytest.raises(InvalidEntry, match=message):
        normalize_entry(raw)


def test_minimize_drops_parent_covered_entries():
    assert minimize(["api.example.com", "example.com"]) == ["example.com"]
    assert minimize(["a.x.com", "b.x.com", "x.com"]) == ["x.com"]


def test_minimize_keeps_sibling_suffixes_and_sorts():
    assert minimize(["b.example.com", "a.example.com"]) == [
        "a.example.com",
        "b.example.com",
    ]


def test_minimize_does_not_confuse_partial_labels():
    # notexample.com must not be treated as covered by example.com.
    assert minimize(["notexample.com", "example.com"]) == [
        "example.com",
        "notexample.com",
    ]


def test_collect_unions_tools_and_normalizes_wildcards(tmp_path):
    _write_tool(tmp_path, "alpha", [_tool("alpha", ["*.API.example.com", "example.org"])])
    _write_tool(tmp_path, "beta", [_tool("beta", ["api.example.com"]), _tool("beta2", ["vendor.test"])])
    _write_tool(tmp_path, "gamma", [_tool("gamma")])  # no egress: ignored

    errors = []
    entries = collect(tmp_path, errors)

    assert errors == []
    assert entries == {"api.example.com", "example.org", "vendor.test"}


def test_main_writes_minimal_sorted_allowlist(tmp_path, capsys):
    _write_tool(tmp_path, "alpha", [_tool("alpha", ["*.api.example.com", "example.org"])])
    _write_tool(tmp_path, "beta", [_tool("beta", ["api.example.com"])])
    out = tmp_path / "nested" / "allowlist"

    assert main(["--workspace", str(tmp_path), "--out", str(out)]) == 0

    assert out.read_text(encoding="utf-8") == "api.example.com\nexample.org\n"
    stderr = capsys.readouterr().err
    assert "2 unique domain(s) declared -> 2 allowlist entries" in stderr
    assert "api.example.com, example.org" in stderr


def test_main_prints_union_to_stdout_by_default(tmp_path, capsys):
    _write_tool(tmp_path, "alpha", [_tool("alpha", ["example.org"])])

    assert main(["--workspace", str(tmp_path)]) == 0

    assert capsys.readouterr().out == "example.org\n"


def test_check_mode_is_clean_for_valid_entries(tmp_path, capsys):
    _write_tool(tmp_path, "alpha", [_tool("alpha", ["example.org"])])

    assert main(["--workspace", str(tmp_path), "--check"]) == 0
    assert "OK (1 domains)" in capsys.readouterr().err


def test_check_mode_exits_nonzero_and_writes_nothing_on_invalid_entry(tmp_path, capsys):
    _write_tool(tmp_path, "alpha", [_tool("alpha", ["https://example.org"])])
    out = tmp_path / "allowlist"

    assert main(["--workspace", str(tmp_path), "--check", "--out", str(out)]) == 1

    assert not out.exists()
    stderr = capsys.readouterr().err
    assert "ERROR" in stderr
    assert "schemes are not allowed" in stderr
    assert "refusing to generate" in stderr


def test_generation_also_fails_closed_on_invalid_entry(tmp_path):
    _write_tool(tmp_path, "alpha", [_tool("alpha", ["10.0.0.1"])])

    assert main(["--workspace", str(tmp_path)]) == 1


def test_empty_workspace_writes_an_empty_file_and_warns(tmp_path, capsys):
    _write_tool(tmp_path, "alpha", [_tool("alpha")])
    out = tmp_path / "allowlist"

    assert main(["--workspace", str(tmp_path), "--out", str(out)]) == 0

    assert out.exists()
    assert out.read_text(encoding="utf-8") == ""
    assert "EMPTY allowlist" in capsys.readouterr().err


def test_missing_tools_directory_is_empty_not_allow_all(tmp_path, capsys):
    out = tmp_path / "allowlist"

    assert main(["--workspace", str(tmp_path / "absent"), "--out", str(out)]) == 0

    assert out.read_text(encoding="utf-8") == ""
    stderr = capsys.readouterr().err
    assert "does not exist" in stderr
    assert "EMPTY allowlist" in stderr


def test_egress_must_be_a_list(tmp_path, capsys):
    _write_tool(tmp_path, "alpha", [_tool("alpha", "example.org")])

    assert main(["--workspace", str(tmp_path), "--check"]) == 1
    assert "egress must be a list" in capsys.readouterr().err
