# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Scoped edge environment (L4): base allowlist + declared keys, token always gone.

The edge replaces the hub's denylist with an allowlist. What must hold: an operator's
unrelated process env is invisible; a key the manifest declares is injected; the
tunnel credential is absent whatever the mode; and ``env_passthrough: true`` restores
v0.4 semantics for legacy tools without re-exposing the token.
"""

import asyncio
import logging
import os

import pytest
import yaml

from core import edge_env, proxy, proxy_mcp
from core.models import MCPConfig, ToolConfig

TOKEN = "edge_site_supersecret"

SAMPLE_ENV = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/home/edge",
    "LANG": "C.UTF-8",
    "TZ": "UTC",
    "TMPDIR": "/tmp",
    "HTTP_PROXY": "http://proxy.example:3128",
    "HTTPS_PROXY": "https://proxy.example:3128",
    "NO_PROXY": "localhost,127.0.0.1",
    "SSL_CERT_FILE": "/etc/ssl/certs/corp.pem",
    "LC_ALL": "en_US.UTF-8",
    "TRELLIS_EDGE_SITE": "plant-floor",
    "SUSPICIOUS": "1",
    "DEVOPS_PASSWORD": "hunter2",
    "TRELLIS_EDGE_TOKEN": TOKEN,
}

BASE_KEYS = (
    "PATH",
    "HOME",
    "LANG",
    "TZ",
    "TMPDIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
)


@pytest.fixture(autouse=True)
def _clean_edge_env(monkeypatch):
    """Edge config/token vars must not leak in from the developer's shell."""
    for var in (
        "TRELLIS_EDGE_CONFIG",
        "TRELLIS_EDGE_SITE",
        "TRELLIS_SERVER_URL",
        "TRELLIS_EDGE_TOOLS_DIR",
        "TRELLIS_EDGE_TOKEN",
        "TRELLIS_EDGE_ENV_PASSTHROUGH",
        "TRELLIS_USER_ID",
        "TRELLIS_USER_EMAIL",
        "CUSTOM_EDGE_TOKEN",
        "SESSION_SECRET",
        "ENCRYPTION_KEY",
        "SUSPICIOUS",
        "DEVOPS_PASSWORD",
        "DEVOPS_URL",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def process_env(monkeypatch):
    """A controlled process env: base plumbing plus an operator-only secret."""
    for key, value in SAMPLE_ENV.items():
        monkeypatch.setenv(key, value)
    return SAMPLE_ENV


def tool_config(name="devops", **kwargs):
    return ToolConfig(
        name=name,
        description=f"{name} tool",
        runtime="python",
        entrypoint="main.py",
        **kwargs,
    )


# --- default (allowlist) mode -------------------------------------------------------


def test_base_allowlist_and_prefixes_survive(process_env, monkeypatch):
    # Lowercase variants are part of the exact base set; SAMPLE_ENV has none, so
    # without these they could be deleted from BASE_ENV_KEYS unnoticed.
    monkeypatch.setenv("path", "/lower/bin")
    monkeypatch.setenv("http_proxy", "http://lower-proxy:3128")

    env = edge_env.scoped_env(set())

    for key in BASE_KEYS:
        assert env[key] == SAMPLE_ENV[key]
    assert env["LC_ALL"] == "en_US.UTF-8"
    assert env["TRELLIS_EDGE_SITE"] == "plant-floor"
    # Exact set: every surviving name is a base key or an LC_/TRELLIS_ prefix match,
    # and nothing else from the process env rides along.
    assert all(
        key in edge_env.BASE_ENV_KEYS or key.startswith(edge_env.BASE_ENV_PREFIXES)
        for key in env
    )
    assert "SUSPICIOUS" not in env
    assert "DEVOPS_PASSWORD" not in env


def test_undeclared_process_vars_are_invisible(process_env):
    env = edge_env.scoped_env(set())

    assert "SUSPICIOUS" not in env
    assert "DEVOPS_PASSWORD" not in env


def test_a_declared_key_present_in_the_process_env_is_injected(process_env):
    env = edge_env.scoped_env({"DEVOPS_PASSWORD"})

    assert env["DEVOPS_PASSWORD"] == "hunter2"
    assert "SUSPICIOUS" not in env


def test_a_declared_key_that_is_absent_is_simply_absent(process_env):
    env = edge_env.scoped_env({"DEVOPS_PASSWORD", "NOT_SET_ANYWHERE"})

    assert "NOT_SET_ANYWHERE" not in env
    assert env["DEVOPS_PASSWORD"] == "hunter2"


def test_scoped_env_is_a_fresh_dict_and_never_mutates_the_process_env(process_env):
    env = edge_env.scoped_env({"DEVOPS_PASSWORD"})
    env["INJECTED"] = "x"
    env.pop("HOME")

    assert "INJECTED" not in os.environ
    assert os.environ["HOME"] == SAMPLE_ENV["HOME"]


# --- the tunnel token ---------------------------------------------------------------


@pytest.mark.parametrize("passthrough", [False, True])
def test_the_tunnel_token_is_stripped_by_default_and_in_both_modes(process_env, passthrough):
    """No caller has to remember to name the token: it is stripped intrinsically."""
    env = edge_env.scoped_env({"TRELLIS_EDGE_TOKEN"}, passthrough=passthrough)

    assert "TRELLIS_EDGE_TOKEN" not in env


@pytest.mark.parametrize("passthrough", [False, True])
def test_a_custom_token_name_is_stripped_in_both_modes(process_env, passthrough, monkeypatch):
    monkeypatch.setenv("CUSTOM_EDGE_TOKEN", TOKEN)

    env = edge_env.scoped_env(
        {"CUSTOM_EDGE_TOKEN"},
        passthrough=passthrough,
        secret_env_names={"CUSTOM_EDGE_TOKEN"},
    )

    assert "CUSTOM_EDGE_TOKEN" not in env


@pytest.mark.parametrize("passthrough", [False, True])
def test_reserved_framework_names_are_stripped_in_both_modes(process_env, passthrough, monkeypatch):
    """Declaring SESSION_SECRET must not be a way to read it back out of the host."""
    monkeypatch.setenv("SESSION_SECRET", "framework-session")
    monkeypatch.setenv("ENCRYPTION_KEY", "framework-key")

    env = edge_env.scoped_env(
        {"SESSION_SECRET", "ENCRYPTION_KEY"}, passthrough=passthrough
    )

    assert "SESSION_SECRET" not in env
    assert "ENCRYPTION_KEY" not in env


def test_provider_api_keys_are_still_injectable(process_env, monkeypatch):
    """An edge tool that calls an LLM declares its provider key; that must work."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-edge")

    env = edge_env.scoped_env({"OPENAI_API_KEY"})

    assert env["OPENAI_API_KEY"] == "sk-edge"


# --- opt-out mode -------------------------------------------------------------------


def test_passthrough_restores_the_denylist_behavior(process_env, monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "framework-session")
    monkeypatch.setenv("ENCRYPTION_KEY", "framework-key")

    env = edge_env.scoped_env(set(), passthrough=True, secret_env_names={"TRELLIS_EDGE_TOKEN"})

    assert env["SUSPICIOUS"] == "1"
    assert "SESSION_SECRET" not in env
    assert "ENCRYPTION_KEY" not in env
    assert "TRELLIS_EDGE_TOKEN" not in env


# --- declared_keys_for --------------------------------------------------------------


def test_declared_keys_for_a_list_shaped_manifest():
    config = tool_config(
        secrets=["DEVOPS_URL"],
        optional_secrets=["CORALOGIX_API_KEY"],
        variables=["CORALOGIX_DOMAIN"],
    )

    assert edge_env.declared_keys_for(config) == {
        "DEVOPS_URL",
        "CORALOGIX_API_KEY",
        "CORALOGIX_DOMAIN",
    }


def test_declared_keys_for_a_dict_shaped_manifest_takes_every_bucket():
    config = tool_config(
        secrets={"general": ["EVERYONE"], "user": ["USER_ONLY"], "background": ["BACKGROUND_ONLY"]},
        variables={"general": ["VAR_EVERYONE"], "background": ["VAR_BACKGROUND"]},
    )

    keys = edge_env.declared_keys_for(config)

    assert keys == {
        "EVERYONE",
        "USER_ONLY",
        "BACKGROUND_ONLY",
        "VAR_EVERYONE",
        "VAR_BACKGROUND",
    }


def test_declared_keys_for_flattens_secret_groups():
    config = tool_config(
        optional_secrets=["NETCTL_USER", "NETCTL_PASSWORD"],
        secret_groups=[
            {
                "label": "Environment",
                "options": [
                    {"value": "prod", "fields": [{"key": "NETCTL_USER"}, {"key": "NETCTL_PASSWORD"}]},
                    {"value": "lab", "fields": [{"key": "NETCTL_LAB_USER"}]},
                ],
            }
        ],
    )

    keys = edge_env.declared_keys_for(config)

    assert keys == {"NETCTL_USER", "NETCTL_PASSWORD", "NETCTL_LAB_USER"}


def test_declared_keys_for_an_mcp_config():
    config = MCPConfig(
        name="devops-cli",
        command="node",
        secrets=["DEVOPS_PASSWORD"],
        variables=["CORALOGIX_DOMAIN"],
    )

    assert edge_env.declared_keys_for(config) == {"DEVOPS_PASSWORD", "CORALOGIX_DOMAIN"}


def test_declared_keys_for_nothing_declared():
    assert edge_env.declared_keys_for(tool_config()) == set()
    assert edge_env.declared_keys_for(None) == set()


# --- through core.proxy.build_env ---------------------------------------------------


def test_build_env_scopes_the_env_and_keeps_the_tool_bin_first(tmp_path, process_env):
    config = tool_config(secrets=["DEVOPS_PASSWORD"])

    env = proxy.build_env(
        tmp_path, config, {"user": "u1", "user_email": "u1@corp.example"}
    )

    assert env["DEVOPS_PASSWORD"] == "hunter2"
    assert "SUSPICIOUS" not in env
    assert env["PATH"].split(os.pathsep)[0] == str((tmp_path / "bin").resolve())
    assert env["TRELLIS_USER_ID"] == "u1"
    assert env["TRELLIS_USER_EMAIL"] == "u1@corp.example"
    assert "TRELLIS_EDGE_TOKEN" not in env


def test_build_env_honors_passthrough_and_still_drops_the_token(tmp_path, process_env):
    config = tool_config()

    env = proxy.build_env(tmp_path, config, passthrough=True, token_env="TRELLIS_EDGE_TOKEN")

    assert env["SUSPICIOUS"] == "1"
    assert "TRELLIS_EDGE_TOKEN" not in env


def test_build_env_never_inherits_a_stale_identity(tmp_path, process_env, monkeypatch):
    monkeypatch.setenv("TRELLIS_USER_ID", "someone-else")
    monkeypatch.setenv("TRELLIS_USER_EMAIL", "someone-else@corp.example")

    env = proxy.build_env(tmp_path, tool_config())

    assert "TRELLIS_USER_ID" not in env
    assert "TRELLIS_USER_EMAIL" not in env


def test_build_env_strips_the_configured_token_env_name(tmp_path, process_env, monkeypatch):
    monkeypatch.setenv("CUSTOM_EDGE_TOKEN", TOKEN)

    env = proxy.build_env(tmp_path, tool_config(), token_env="CUSTOM_EDGE_TOKEN")

    assert "CUSTOM_EDGE_TOKEN" not in env


def test_handle_call_applies_the_proxy_config_policy(tmp_path, process_env, monkeypatch):
    seen = {}

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None):
        seen.update(env)
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    config_map = {"devops": (tool_config(secrets=["DEVOPS_PASSWORD"]), tmp_path)}
    frame = {"t": "call", "id": "c1", "tool": "devops", "args": {}, "deadline_ms": 1000}

    result = asyncio.run(
        proxy.handle_call(
            config_map,
            frame,
            proxy_config=proxy.ProxyConfig(site="plant-floor", server_url="ws://relay/x"),
        )
    )

    assert result["ok"] is True
    assert seen["DEVOPS_PASSWORD"] == "hunter2"
    assert "SUSPICIOUS" not in seen
    assert "TRELLIS_EDGE_TOKEN" not in seen


def test_call_with_deadline_threads_passthrough_into_the_tool_env(
    tmp_path, process_env, monkeypatch
):
    """The opt-out must survive the real dispatch path, not just ``build_env``."""
    seen = {}

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None):
        seen.update(env)
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    config_map = {"devops": (tool_config(), tmp_path)}
    frame = {"t": "call", "id": "c1", "tool": "devops", "args": {}, "deadline_ms": 1000}

    asyncio.run(
        proxy._call_with_deadline(
            config_map,
            frame,
            proxy_config=proxy.ProxyConfig(
                site="plant-floor", server_url="ws://relay/x", env_passthrough=True
            ),
        )
    )

    assert seen["SUSPICIOUS"] == "1"
    assert "TRELLIS_EDGE_TOKEN" not in seen


def test_call_with_deadline_strips_the_configured_token(
    tmp_path, process_env, monkeypatch
):
    seen = {}

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None):
        seen.update(env)
        return {"ok": True}

    monkeypatch.setenv("CUSTOM_EDGE_TOKEN", TOKEN)
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    config_map = {"devops": (tool_config(secrets=["CUSTOM_EDGE_TOKEN"]), tmp_path)}
    frame = {"t": "call", "id": "c1", "tool": "devops", "args": {}, "deadline_ms": 1000}

    asyncio.run(
        proxy._call_with_deadline(
            config_map,
            frame,
            proxy_config=proxy.ProxyConfig(
                site="plant-floor",
                server_url="ws://relay/x",
                token_env="CUSTOM_EDGE_TOKEN",
            ),
        )
    )

    assert "CUSTOM_EDGE_TOKEN" not in seen


# --- MCP transports: stdio gets the env, http/sse get credentials only --------------


class _RecordingTransports:
    """Capture the kwargs each transport class is built with."""

    def __init__(self):
        self.calls = {}

    def install(self, monkeypatch):
        calls = self.calls

        class FakeClient:
            def __init__(self, transport):
                self.transport = transport

        def transport_class(kind):
            def build(**kwargs):
                calls[kind] = kwargs
                return kwargs

            return build

        monkeypatch.setattr(
            proxy_mcp,
            "_fastmcp",
            lambda: (
                FakeClient,
                transport_class("stdio"),
                transport_class("http"),
                transport_class("sse"),
            ),
        )
        monkeypatch.setattr(
            proxy_mcp, "build_stdio_argv", lambda entry, home_dir, backend=None: ["node"]
        )
        return self


def mcp_export(tmp_path, name="devops-cli", transport="http", **kwargs):
    config = MCPConfig(
        name=name,
        transport=transport,
        command="https://devops.internal.example/mcp" if transport != "stdio" else "node",
        **kwargs,
    )
    return proxy_mcp.McpExport(name=name, config=config, directory=tmp_path)


def test_http_headers_carry_only_the_declared_credentials(tmp_path, process_env, monkeypatch):
    """A remote endpoint is not a subprocess: it gets credentials, never the env."""
    recorded = _RecordingTransports().install(monkeypatch)
    entry = mcp_export(
        tmp_path,
        transport="http",
        secrets=["DEVOPS_PASSWORD"],
        variables=["CORALOGIX_DOMAIN"],
        env={"LITERAL_HEADER": "literal-value"},
    )
    monkeypatch.setenv("TRELLIS_USER_ID", "user-1")
    monkeypatch.setenv("TRELLIS_USER_EMAIL", "user-1@corp.example")
    monkeypatch.setenv("CORALOGIX_DOMAIN", "corp.example")
    env = proxy_mcp._server_env(
        entry, tmp_path, {"user": "user-1", "user_email": "user-1@corp.example"},
        passthrough=False, token_env=None,
    )

    proxy_mcp._transport(entry, tmp_path, env)

    assert recorded.calls["http"]["headers"] == {
        "DEVOPS_PASSWORD": "hunter2",
        "CORALOGIX_DOMAIN": "corp.example",
        "LITERAL_HEADER": "literal-value",
    }
    # The scoped env is still a subprocess env: identity, HOME, PATH are all there.
    assert env["TRELLIS_USER_EMAIL"] == "user-1@corp.example"
    assert env["TRELLIS_USER_ID"] == "user-1"
    assert "HOME" in env and "PATH" in env
    assert "TRELLIS_EDGE_TOKEN" not in env


def test_sse_headers_never_include_the_scoped_environment(tmp_path, process_env, monkeypatch):
    recorded = _RecordingTransports().install(monkeypatch)
    entry = mcp_export(tmp_path, transport="sse", secrets=["DEVOPS_PASSWORD"])
    env = proxy_mcp._server_env(entry, tmp_path, {}, passthrough=False, token_env=None)

    proxy_mcp._transport(entry, tmp_path, env)

    headers = recorded.calls["sse"]["headers"]
    assert headers == {"DEVOPS_PASSWORD": "hunter2"}
    for leaked in (
        "HOME",
        "PATH",
        "TMPDIR",
        "TRELLIS_EDGE_TOKEN",
        "TRELLIS_EDGE_SITE",
        "SUSPICIOUS",
    ):
        assert leaked not in headers


def test_passthrough_does_not_widen_http_headers(tmp_path, process_env, monkeypatch):
    """env_passthrough is a subprocess policy; it must not ship the operator env."""
    recorded = _RecordingTransports().install(monkeypatch)
    entry = mcp_export(tmp_path, transport="http", secrets=["DEVOPS_PASSWORD"])
    env = proxy_mcp._server_env(entry, tmp_path, {}, passthrough=True, token_env=None)

    proxy_mcp._transport(entry, tmp_path, env)

    assert recorded.calls["http"]["headers"] == {"DEVOPS_PASSWORD": "hunter2"}
    # ... while the stdio env does get the passthrough treatment.
    assert env["SUSPICIOUS"] == "1"


def test_stdio_still_receives_the_full_scoped_environment(tmp_path, process_env, monkeypatch):
    recorded = _RecordingTransports().install(monkeypatch)
    entry = mcp_export(tmp_path, transport="stdio", secrets=["DEVOPS_PASSWORD"])
    env = proxy_mcp._server_env(
        entry, tmp_path, {"user_email": "user-1@corp.example"}, passthrough=False, token_env=None
    )

    proxy_mcp._transport(entry, tmp_path, env)

    assert recorded.calls["stdio"]["env"] is env


def test_a_renamed_token_is_not_sent_as_a_header(tmp_path, process_env, monkeypatch):
    """A host that renames the enrollment token must not ship it to an endpoint."""
    recorded = _RecordingTransports().install(monkeypatch)
    monkeypatch.setenv("CUSTOM_EDGE_TOKEN", TOKEN)
    entry = mcp_export(tmp_path, transport="http", secrets=["CUSTOM_EDGE_TOKEN"])
    env = proxy_mcp._server_env(
        entry, tmp_path, {}, passthrough=False, token_env="CUSTOM_EDGE_TOKEN"
    )

    proxy_mcp._transport(entry, tmp_path, env, "CUSTOM_EDGE_TOKEN")

    assert recorded.calls["http"]["headers"] == {}
    assert "CUSTOM_EDGE_TOKEN" not in env


# --- proxy.yaml surface -------------------------------------------------------------


def write_config(tmp_path, **overrides):
    data = {
        "site": "plant-floor",
        "server_url": "wss://relay.example.com/edge/v1/connect",
        "tools_dir": str(tmp_path / "tools"),
        "exports": [],
    }
    data.update(overrides)
    path = tmp_path / "proxy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_env_passthrough_defaults_off(tmp_path):
    assert proxy.load_config(write_config(tmp_path)).env_passthrough is False


@pytest.mark.parametrize("value,expected", [(True, True), ("true", True), (False, False)])
def test_env_passthrough_is_read_from_yaml(tmp_path, value, expected):
    assert proxy.load_config(write_config(tmp_path, env_passthrough=value)).env_passthrough is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", True),
        ("true", True),
        ("YES", True),
        ("on", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("off", False),
    ],
)
def test_the_env_override_mirrors_env_passthrough(monkeypatch, tmp_path, value, expected):
    monkeypatch.setenv("TRELLIS_EDGE_ENV_PASSTHROUGH", value)

    config = proxy.load_config(write_config(tmp_path, env_passthrough=not expected))

    assert config.env_passthrough is expected


def test_an_unparseable_env_override_keeps_the_file_value(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("TRELLIS_EDGE_ENV_PASSTHROUGH", "maybe")

    with caplog.at_level(logging.WARNING):
        config = proxy.load_config(write_config(tmp_path, env_passthrough=True))

    assert config.env_passthrough is True
    assert "TRELLIS_EDGE_ENV_PASSTHROUGH" in caplog.text


def test_sighup_reports_a_changed_env_policy_as_needing_a_restart(tmp_path, caplog):
    path = write_config(tmp_path)
    session = proxy._Session(proxy.load_config(path), path)

    write_config(tmp_path, env_passthrough=True)
    with caplog.at_level(logging.WARNING):
        session.reload()

    assert "env_passthrough changes need a restart" in caplog.text
    assert session.config.env_passthrough is False
