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
from core.llm_providers import FRAMEWORK_PROVIDER_KEY_ENV

# Non-provider names FRAMEWORK_SECRET_ENV must keep alongside the registry-derived
# provider credential set.
_NON_PROVIDER_SECRETS = {
    "SESSION_SECRET", "ENCRYPTION_KEY",
    "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET",
    "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_METADATA_URL",
    "ADMIN_USERS", "ALLOWED_DOMAINS",
    "HINDSIGHT_API_LLM_API_KEY", "HINDSIGHT_LLM_API_KEY",
    "HINDSIGHT_API_EMBEDDINGS_GEMINI_API_KEY",
}


def test_sanitized_env_strips_every_framework_secret(monkeypatch):
    for name in FRAMEWORK_SECRET_ENV:
        monkeypatch.setenv(name, f"decoy-{name}")

    result = sanitized_env()

    for name in FRAMEWORK_SECRET_ENV:
        assert name not in result


def test_sanitized_env_strips_every_registry_provider_key_name():
    """Every credential name the registry knows is scrubbed, not just the legacy 4."""
    base = {**os.environ, **{name: "x" for name in FRAMEWORK_PROVIDER_KEY_ENV}}

    result = sanitized_env(base)

    for name in FRAMEWORK_PROVIDER_KEY_ENV:
        assert name not in result
    # Case-insensitive, like the rest of the denylist.
    lower = {name.lower(): "x" for name in FRAMEWORK_PROVIDER_KEY_ENV}
    assert sanitized_env({**os.environ, **lower}).keys().isdisjoint(lower)


def test_sanitized_env_does_not_strip_ollama_base_url():
    """Documented decision: OLLAMA_BASE_URL is an endpoint, not a credential."""
    base = {**os.environ, "OLLAMA_BASE_URL": "http://localhost:11434"}

    result = sanitized_env(base)

    assert "OLLAMA_BASE_URL" not in FRAMEWORK_SECRET_ENV
    assert result["OLLAMA_BASE_URL"] == "http://localhost:11434"


def test_framework_secret_env_derives_provider_names_but_keeps_the_rest():
    assert FRAMEWORK_PROVIDER_KEY_ENV <= FRAMEWORK_SECRET_ENV
    assert _NON_PROVIDER_SECRETS <= FRAMEWORK_SECRET_ENV
    assert FRAMEWORK_SECRET_ENV - FRAMEWORK_PROVIDER_KEY_ENV == _NON_PROVIDER_SECRETS
    # The 12 new provider credential names are present, a spot check of each vendor.
    for name in ("DEEPSEEK_API_KEY", "DASHSCOPE_API_KEY", "HF_TOKEN", "ZAI_API_KEY",
                 "OPENROUTER_API_KEY", "MOONSHOTAI_API_KEY", "TOGETHER_API_KEY",
                 "FIREWORKS_API_KEY", "VERCEL_AI_GATEWAY_API_KEY", "OPENAI_COMPATIBLE_API_KEY"):
        assert name in FRAMEWORK_SECRET_ENV


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
