# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Tests for framework secret env-sanitization of spawned subprocesses.

Covers:
  - core.env_sanitize.sanitized_env(): strips every reserved framework secret var
    (case-insensitively) while preserving operator-set vars, both from os.environ
    and from an explicit base mapping.
  - core.console_backend.SanitizedLocalBackend: injects the sanitized env into the
    shell subprocess for both execute() and async_execute().
"""

import asyncio
import os

from core.console_backend import SanitizedLocalBackend
from core.env_sanitize import FRAMEWORK_SECRET_ENV, sanitized_env


def test_sanitized_env_strips_every_framework_secret(monkeypatch):
    for name in FRAMEWORK_SECRET_ENV:
        monkeypatch.setenv(name, f"decoy-{name}")

    result = sanitized_env()

    for name in FRAMEWORK_SECRET_ENV:
        assert name not in result


def test_sanitized_env_is_case_insensitive(monkeypatch):
    monkeypatch.setenv("session_secret", "decoy")
    monkeypatch.setenv("oIdC_client_id", "decoy")

    result = sanitized_env()

    assert "session_secret" not in result
    assert "oIdC_client_id" not in result


def test_sanitized_env_preserves_operator_vars(monkeypatch):
    monkeypatch.setenv("TRELLIS_CUSTOM_VAR", "keep-me")

    result = sanitized_env()

    assert "PATH" in result
    assert result["PATH"] == os.environ["PATH"]
    assert result["TRELLIS_CUSTOM_VAR"] == "keep-me"


def test_sanitized_env_base_mapping():
    base = {"PATH": "/usr/bin", "Session_Secret": "decoy", "KEEP": "yes"}

    result = sanitized_env(base)

    assert result == {"PATH": "/usr/bin", "KEEP": "yes"}
    # The base mapping must not be mutated in place.
    assert base["Session_Secret"] == "decoy"


def test_sanitized_local_backend_execute_strips_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "decoy-secret")
    monkeypatch.setenv("TRELLIS_OPERATOR_VAR", "operator-value")
    backend = SanitizedLocalBackend(root_dir=str(tmp_path), enable_execute=True)

    result = backend.execute(
        'printf "SECRET=[%s] OPERATOR=[%s]\\n" '
        '"${SESSION_SECRET:-unset}" "${TRELLIS_OPERATOR_VAR:-unset}"'
    )

    assert result.exit_code == 0
    assert "SECRET=[unset]" in result.output
    assert "decoy-secret" not in result.output
    assert "OPERATOR=[operator-value]" in result.output


def test_sanitized_local_backend_async_execute_strips_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "decoy-secret")
    backend = SanitizedLocalBackend(root_dir=str(tmp_path), enable_execute=True)

    async def scenario():
        return await backend.async_execute('echo "SECRET=${SESSION_SECRET:-unset}"')

    result = asyncio.run(scenario())

    assert result.exit_code == 0
    assert "SECRET=unset" in result.output
    assert "decoy-secret" not in result.output


def test_grep_ripgrep_uses_sanitized_env(tmp_path, monkeypatch):
    """The ripgrep grep path is a spawned process too: its env must be sanitized."""
    monkeypatch.setenv("SESSION_SECRET", "decoy-secret")
    captured = {}

    def fake_run(argv, **kwargs):
        captured.update(kwargs)

        class _Result:
            stdout = ""
            returncode = 0

        return _Result()

    monkeypatch.setattr("core.console_backend.subprocess.run", fake_run)
    backend = SanitizedLocalBackend(root_dir=str(tmp_path))

    result = backend._grep_ripgrep("needle", tmp_path, None, True)

    assert result == []
    assert "env" in captured
    assert "SESSION_SECRET" not in captured["env"]
    assert "PATH" in captured["env"]
