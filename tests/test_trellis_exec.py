# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""``trellis-exec``: the stdin env preamble shim installed in the engine image.

Every tool / MCP-session container is started through this script, so these tests
drive the real file as a subprocess (shebang and executable bit included) rather
than importing it: the wire contract is about fd 0 and exit codes, not about
internals. The one property that cannot be observed from the outside cheaply --
"never read past the first newline" -- is pinned both by the byte-exact
passthrough tests and by leaving bytes unread in a pipe for the parent to drain.
"""

import json
import os
import random
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIM = REPO_ROOT / "docker" / "trellis-exec"
DOCKERFILE = REPO_ROOT / "Dockerfile"

INSTALL_PATH = "/usr/local/bin/trellis-exec"
EX_CONFIG = 78
# Mirrors docker/trellis-exec: the total line cap and the per-value cap, both sized
# for what execve actually accepts (see the comment in the shim).
MAX_PREAMBLE_BYTES = 64 * 1024
MAX_VALUE_BYTES = 16 * 1024


def preamble(**env: str) -> bytes:
    """The first stdin line, without its terminator."""
    return json.dumps({"env": env}).encode("utf-8")


def run_shim(args, stdin: bytes = b"", **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(SHIM), *args], input=stdin, capture_output=True, **kwargs
    )


def sentinel_child(path: Path) -> list[str]:
    """A command that leaves proof it ran."""
    return [sys.executable, "-c", f"open({str(path)!r}, 'w').write('ran')"]


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_preamble_env_is_applied_and_the_child_reads_the_rest_of_stdin(
    tmp_path: Path,
) -> None:
    rest = b"the child's own stdin, byte for byte"
    child = (
        "import os, sys; print(os.environ['TRELLIS_PROBE']); "
        "print(sys.stdin.buffer.read().decode())"
    )

    result = run_shim(
        [sys.executable, "-c", child],
        stdin=preamble(TRELLIS_PROBE="hello") + b"\n" + rest,
        # A preamble value must win over an inherited one (runner-side values the
        # container config still carries are base env, not authority).
        env={**os.environ, "TRELLIS_PROBE": "inherited"},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == b"hello\n" + rest + b"\n"
    assert result.stderr == b""


def test_stdin_after_the_newline_is_passed_through_byte_exact() -> None:
    rng = random.Random(20261026)
    # Binary, NULs, newlines and multi-byte UTF-8 all survive untouched: the shim
    # must hand over a stream, not a decoded string.
    payload = (
        rng.randbytes(512)
        + b"\n"
        + b"\x00\x00\x00"
        + "smørhul — ✓ 日本語".encode("utf-8")
        + rng.randbytes(256)
        + b"\n"
    )
    assert b"\n" in payload and b"\x00" in payload

    result = run_shim(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
        stdin=preamble(TRELLIS_PROBE="hello") + b"\n" + payload,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == payload


def test_crlf_terminated_first_line_is_accepted() -> None:
    child = (
        "import os, sys; print(os.environ['TRELLIS_PROBE']); "
        "sys.stdout.write(sys.stdin.read())"
    )
    result = run_shim(
        [sys.executable, "-c", child],
        stdin=preamble(TRELLIS_PROBE="hello") + b"\r\n" + b"payload after CRLF\n",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == b"hello\npayload after CRLF\n"


def test_preamble_just_under_the_cap_is_accepted() -> None:
    # A realistic "big" preamble is many ordinary-sized secrets, not one giant value
    # (the per-value cap below is separate).
    keys = 280
    env = {f"TRELLIS_KEY_{i:04d}": "p" * 200 for i in range(keys)}
    line = json.dumps({"env": env}).encode("utf-8")
    assert MAX_PREAMBLE_BYTES * 9 // 10 < len(line) <= MAX_PREAMBLE_BYTES

    result = run_shim(
        [
            sys.executable,
            "-c",
            "import os; print(sum(1 for k in os.environ if k.startswith('TRELLIS_KEY_')))",
        ],
        stdin=line + b"\n",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{keys}\n".encode()


def test_preamble_without_a_payload_gives_the_child_empty_stdin() -> None:
    # Calls with no arguments still get the preamble line, then EOF.
    result = run_shim(
        [sys.executable, "-c", "import sys; print(repr(sys.stdin.buffer.read()))"],
        stdin=preamble(TRELLIS_PROBE="hello") + b"\n",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == b"b''\n"


def test_unknown_top_level_keys_in_the_preamble_are_ignored() -> None:
    document = json.dumps({"env": {"TRELLIS_PROBE": "hello"}, "version": 1})

    result = run_shim(
        [sys.executable, "-c", "import os; print(os.environ['TRELLIS_PROBE'])"],
        stdin=document.encode("utf-8") + b"\n",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == b"hello\n"


# --------------------------------------------------------------------------- #
# Malformed preamble: exit 78, nothing executed, nothing echoed
# --------------------------------------------------------------------------- #


MALFORMED_PREAMBLES = [
    # (id, first line bytes, markers that must not appear on stderr). The markers
    # are deliberately distinctive: a reason string may legitimately say "value".
    ("not-json", b"ZQ7VALUE not json at all", [b"ZQ7VALUE"]),
    ("json-array", b'[{"env": {"ZQ7KEY": "ZQ7VALUE"}}]', [b"ZQ7KEY", b"ZQ7VALUE"]),
    ("json-string", b'"ZQ7VALUE"', [b"ZQ7VALUE"]),
    ("env-missing", b'{"nope": {"ZQ7KEY": "ZQ7VALUE"}}', [b"ZQ7KEY", b"ZQ7VALUE"]),
    ("env-not-object", b'{"env": ["ZQ7KEY", "ZQ7VALUE"]}', [b"ZQ7KEY", b"ZQ7VALUE"]),
    ("bad-key-charset", b'{"env": {"ZQ7-KEY": "ZQ7VALUE"}}', [b"ZQ7-KEY", b"ZQ7VALUE"]),
    ("bad-key-leading-digit", b'{"env": {"7ZQKEY": "ZQ7VALUE"}}', [b"7ZQKEY", b"ZQ7VALUE"]),
    ("bad-key-empty", b'{"env": {"": "ZQ7VALUE"}}', [b"ZQ7VALUE"]),
    ("value-not-string", b'{"env": {"ZQ7KEY": 42}}', [b"ZQ7KEY"]),
    (
        "value-object",
        b'{"env": {"ZQ7KEY": {"ZQ7NESTED": "ZQ7VALUE"}}}',
        [b"ZQ7KEY", b"ZQ7NESTED", b"ZQ7VALUE"],
    ),
    ("value-null", b'{"env": {"ZQ7KEY": null}}', [b"ZQ7KEY"]),
    (
        "value-has-nul",
        b'{"env": {"ZQ7KEY": "ZQ7VALUE\\u0000ZQ7TAIL"}}',
        [b"ZQ7KEY", b"ZQ7VALUE", b"ZQ7TAIL"],
    ),
]


@pytest.mark.parametrize(
    "first_line, markers",
    [(f, m) for _, f, m in MALFORMED_PREAMBLES],
    ids=[i for i, _, _ in MALFORMED_PREAMBLES],
)
def test_malformed_preamble_exits_78_without_running_anything(
    tmp_path: Path, first_line: bytes, markers: list[bytes]
) -> None:
    sentinel = tmp_path / "child-ran"

    result = run_shim(sentinel_child(sentinel), stdin=first_line + b"\npayload")

    assert result.returncode == EX_CONFIG
    assert not sentinel.exists()
    assert result.stdout == b""
    # Reason strings only: no key name and no value may reach stderr.
    for marker in markers:
        assert marker not in result.stderr


def test_stdin_ending_before_the_preamble_exits_78(tmp_path: Path) -> None:
    sentinel = tmp_path / "child-ran"

    result = run_shim(sentinel_child(sentinel), stdin=b"")

    assert result.returncode == EX_CONFIG
    assert not sentinel.exists()
    assert b"trellis-exec:" in result.stderr


def test_empty_first_line_exits_78(tmp_path: Path) -> None:
    sentinel = tmp_path / "child-ran"

    result = run_shim(sentinel_child(sentinel), stdin=b"\npayload")

    assert result.returncode == EX_CONFIG
    assert not sentinel.exists()


def test_oversized_preamble_exits_78_without_running_anything(tmp_path: Path) -> None:
    env = {f"TRELLIS_KEY_{i:04d}": "p" * 200 for i in range(600)}
    line = json.dumps({"env": env}).encode("utf-8")
    assert len(line) > MAX_PREAMBLE_BYTES
    sentinel = tmp_path / "child-ran"

    result = run_shim(sentinel_child(sentinel), stdin=line + b"\n")

    assert result.returncode == EX_CONFIG
    assert not sentinel.exists()
    assert str(MAX_PREAMBLE_BYTES).encode() in result.stderr
    assert b"TRELLIS_KEY_" not in result.stderr


def test_oversized_single_value_exits_78_naming_the_size_not_the_value(
    tmp_path: Path,
) -> None:
    # Far below the total cap, far above the per-value cap. Without the per-value
    # check this reaches execve and dies as E2BIG, reported to the caller as a
    # generic "cannot execute" with no clue that one secret was too large.
    value = "SECRETVALUE" * ((MAX_VALUE_BYTES // len("SECRETVALUE")) + 1)
    assert len(value) > MAX_VALUE_BYTES
    line = preamble(TRELLIS_KEY=value)
    assert len(line) < MAX_PREAMBLE_BYTES
    sentinel = tmp_path / "child-ran"

    result = run_shim(sentinel_child(sentinel), stdin=line + b"\n")

    assert result.returncode == EX_CONFIG
    assert not sentinel.exists()
    assert str(MAX_VALUE_BYTES).encode() in result.stderr
    assert b"SECRETVALUE" not in result.stderr
    assert b"TRELLIS_KEY" not in result.stderr


def test_a_value_just_under_the_per_value_cap_is_applied() -> None:
    value = "v" * MAX_VALUE_BYTES

    result = run_shim(
        [sys.executable, "-c", "import os; print(len(os.environ['TRELLIS_KEY']))"],
        stdin=preamble(TRELLIS_KEY=value) + b"\n",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{MAX_VALUE_BYTES}\n".encode()


def test_values_that_only_just_fit_execve_are_accepted() -> None:
    # The cap exists because the kernel rejects huge environment strings; prove a
    # value at the cap still reaches execve rather than being refused over-eagerly.
    value = "e" * MAX_VALUE_BYTES
    result = run_shim(
        [sys.executable, "-c", "print('exec ok')"],
        stdin=preamble(TRELLIS_BIG=value) + b"\n",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == b"exec ok\n"


# --------------------------------------------------------------------------- #
# The producer (core.execution.env) and this consumer agree on the wire format
# --------------------------------------------------------------------------- #


def test_spec_preamble_is_accepted_by_the_shim_and_reaches_the_tool(
    tmp_path: Path, monkeypatch
) -> None:
    """The one join no other test makes: what the runner writes is what the shim reads."""
    from core.execution import env as exec_env
    from core.execution.spec import build_spec
    from core.models import ToolConfig

    root = tmp_path / "workspace"
    suite = root / "tools" / "demo"
    suite.mkdir(parents=True)
    (suite / "demo.py").write_text("print('{}')\n", encoding="utf-8")
    monkeypatch.setenv("RUNNER_IMAGE", "trellis-agent-platform:test")
    monkeypatch.setenv("TRELLIS_UID", "1000")
    monkeypatch.setenv("TRELLIS_GID", "1000")
    monkeypatch.setenv("CONTAINER_DEFAULT_RUNTIME", "runc")

    config = ToolConfig(
        name="demo",
        description="d",
        runtime="python",
        entrypoint="demo.py",
        secrets=["DEMO_API_KEY"],
    )
    container_spec = build_spec(
        config,
        kind="tool",
        suite_rel="tools/demo",
        target="demo",
        env={"DEMO_API_KEY": "sk-test-value", "TRELLIS_USER_ID": "u-1"},
        host_workspace=str(root),
    )
    # The secret is not container configuration; it is in the preamble. The identity
    # pair is configuration (documented tool contract), so it is not.
    assert "DEMO_API_KEY" not in container_spec.env
    assert container_spec.preamble_env["DEMO_API_KEY"] == "sk-test-value"
    assert container_spec.env["TRELLIS_USER_ID"] == "u-1"
    assert "TRELLIS_USER_ID" not in container_spec.preamble_env

    result = subprocess.run(
        [
            str(SHIM),
            sys.executable,
            "-c",
            "import os; print(os.environ['DEMO_API_KEY'])",
        ],
        input=exec_env.with_preamble(container_spec.preamble_env, b""),
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [b"sk-test-value"]


def test_missing_command_is_a_usage_error_and_runs_nothing() -> None:
    result = run_shim([], stdin=preamble(TRELLIS_PROBE="hello") + b"\n")

    assert result.returncode != 0
    assert result.stdout == b""
    assert b"usage: trellis-exec" in result.stderr


# --------------------------------------------------------------------------- #
# No read-ahead: the bytes after the newline stay in fd 0 for the child
# --------------------------------------------------------------------------- #


def test_shim_does_not_consume_past_the_first_newline() -> None:
    """The child never reads stdin; whatever it did not read must still be there.

    A buffered reader inside the shim would have pulled the payload into
    userspace, where ``execvpe`` destroys it -- the bytes below would be gone.
    """
    payload = b'{"jsonrpc": "2.0", "id": 1, "method": "initialize"}\n'
    read_fd, write_fd = os.pipe()
    os.write(write_fd, preamble(TRELLIS_PROBE="hello") + b"\n" + payload)
    os.close(write_fd)  # EOF for the reader once the payload is drained
    try:
        result = subprocess.run(
            [str(SHIM), sys.executable, "-c", "pass"],
            stdin=read_fd,
            capture_output=True,
        )
        remaining = b""
        while True:
            chunk = os.read(read_fd, 4096)
            if not chunk:
                break
            remaining += chunk
    finally:
        os.close(read_fd)

    assert result.returncode == 0, result.stderr
    assert remaining == payload


# --------------------------------------------------------------------------- #
# Install contract: the image (and every derived image) carries the shim
# --------------------------------------------------------------------------- #


def _dockerfile_instructions() -> list[str]:
    return [
        line.strip()
        for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_dockerfile_copies_the_shim_into_the_image_and_makes_it_executable() -> None:
    instructions = _dockerfile_instructions()

    copies = [
        line
        for line in instructions
        if line.upper().startswith("COPY") and "docker/trellis-exec" in line
    ]
    assert len(copies) == 1, "the shim must be COPYed exactly once into the image"
    assert copies[0].split() == ["COPY", "docker/trellis-exec", INSTALL_PATH]

    chmods = [
        line
        for line in instructions
        if line.upper().startswith("RUN")
        and "chmod" in line
        and INSTALL_PATH in line
    ]
    assert chmods, "the shim must be chmod +x, or derived images drop it"


def test_shim_source_is_executable_stdlib_python_with_the_contract_shebang() -> None:
    mode = SHIM.stat().st_mode
    assert stat.S_ISREG(mode)
    assert mode & stat.S_IXUSR

    source = SHIM.read_text(encoding="utf-8")
    assert source.splitlines()[0] == "#!/usr/bin/env python3"
    # Positive pin on the no-read-ahead mechanism (the passthrough tests are the
    # behavioural half of the same contract).
    assert "os.read(0, 1)" in source
    compile(source, str(SHIM), "exec")
