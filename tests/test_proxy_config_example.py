# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""``deploy/proxy/proxy.yaml.example`` is the config surface operators get.

It is documentation *and* a fixture: this suite loads the shipped file through
``core.proxy.load_config`` so a key that is renamed, dropped, or newly validated
fails here instead of shipping an example that no longer starts an edge. It also
pins the credential-mode mapping forms and the container paths the sample compose
must mount.

No sandbox, no etcd, no tunnel: the example is parsed as an operator would parse it.
"""

import dataclasses
import re
from pathlib import Path

import pytest
import yaml

from core import edge_user_secrets, proxy, proxy_mcp

REPO_ROOT = Path(__file__).parent.parent
EXAMPLE = REPO_ROOT / "deploy/proxy" / "proxy.yaml.example"
COMPOSE = REPO_ROOT / "deploy/proxy" / "docker-compose.yml"

# Absolute paths the sample compose mounts. A config path outside these works on the
# author's workstation and fails (or silently writes somewhere else) in the container.
MOUNTED_ROOTS = ("/app/workspace", "/etc/trellis", "/run/secrets")

# The container working directory (Dockerfile ``WORKDIR /app``): a relative setting is
# resolved against it, which is how ``./workspace/tools`` reaches the mounted tree.
CONTAINER_WORKDIR = Path("/app")

# Derived from the ``exports`` mappings by ``_parse_exports``; not a YAML key.
DERIVED_FIELDS = {"export_modes"}

# The keys the example sets, so adding or deleting one is a deliberate edit here.
EXPECTED_KEYS = {
    "site",
    "server_url",
    "token_file",
    "tools_dir",
    "exports",
    "mcps_dir",
    "export_mcps",
    "secrets_dir",
    "env_passthrough",
    "sandbox",
    "runner_socket",
}


@pytest.fixture(autouse=True)
def _clean_edge_env(monkeypatch):
    """No TRELLIS_EDGE_* leaking in from the developer's shell, and a token.

    The token is what an operator would have in the environment (or in
    ``token_file``); setting it keeps the test independent of both.
    """
    for name in (
        "TRELLIS_EDGE_CONFIG",
        "TRELLIS_EDGE_SITE",
        "TRELLIS_SERVER_URL",
        "TRELLIS_EDGE_TOOLS_DIR",
        "TRELLIS_EDGE_MCPS_DIR",
        "TRELLIS_EDGE_SECRETS_DIR",
        "TRELLIS_EDGE_USER_SECRETS_DIR",
        "TRELLIS_EDGE_TOKEN_FILE",
        "TRELLIS_EDGE_ENV_PASSTHROUGH",
        "TRELLIS_EDGE_TLS_CA",
        "TRELLIS_EDGE_TLS_CERT",
        "TRELLIS_EDGE_TLS_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TRELLIS_EDGE_TOKEN", "edge_dc1_test-only")


def _example_text() -> str:
    assert EXAMPLE.is_file(), f"missing shipped example: {EXAMPLE}"
    return EXAMPLE.read_text(encoding="utf-8")


def _load_variant(tmp_path, *replacements) -> proxy.ProxyConfig:
    """Parse a copy of the example with exact textual edits applied.

    ``replacements`` are ``(old, new)`` pairs applied once each; a missing ``old``
    means the example drifted and the test has to be updated, so it fails loudly.
    """
    text = _example_text()
    for old, new in replacements:
        assert old in text, f"example no longer contains {old!r}"
        text = text.replace(old, new, 1)
    path = tmp_path / "proxy.yaml"
    path.write_text(text, encoding="utf-8")
    return proxy.load_config(path)


# ---------------------------------------------------------------- the shipped file


def test_example_is_a_mapping_and_loads():
    assert isinstance(yaml.safe_load(_example_text()), dict)
    config = proxy.load_config(EXAMPLE)
    assert isinstance(config, proxy.ProxyConfig)


def test_example_sets_exactly_the_documented_keys():
    raw = yaml.safe_load(_example_text())
    assert set(raw) == EXPECTED_KEYS


def test_every_proxy_config_field_is_documented():
    """The example and ``load_config`` cannot drift apart silently.

    A field is documented whether it is active (``site:``) or shown commented out
    (``# token_env:`` / the TLS block) -- commented forms are how the optional keys
    are explained without breaking a copy-and-run install.
    """
    text = _example_text()
    fields = {field.name for field in dataclasses.fields(proxy.ProxyConfig)}
    for name in sorted(fields - DERIVED_FIELDS):
        assert re.search(rf"(?m)^\s*#?\s*{name}\s*:", text), f"{name} is not documented"
    # `token_env` and the TLS trio are the documented-but-commented keys; if one
    # becomes active the assertion above still holds, this just keeps the intent clear.
    for name in ("token_env", "tls_ca_file", "tls_cert_file", "tls_key_file"):
        assert f"# {name}:" in text


def test_example_values_parse_as_declared():
    config = proxy.load_config(EXAMPLE)

    assert config.site == "dc1"
    assert config.server_url.startswith("wss://")
    # The preferred form: a mounted file, not an env var a tool could read.
    assert config.token_file == "/run/secrets/edge_token"
    assert config.token_env == proxy.DEFAULT_TOKEN_ENV

    # Manifest trees live in the mounted workspace.
    assert config.tools_dir == Path("workspace/tools")
    assert config.mcps_dir == Path("workspace/mcps")

    # The shared credential store lives outside the tool-writable workspace. Per-user
    # credentials are sealed in central, so there is no per-user directory.
    assert config.secrets_dir == Path("/etc/trellis/edge-secrets")
    assert not hasattr(config, "user_secrets_dir")

    assert config.sandbox == "container"
    assert config.runner_socket == "/run/trellis/runner.sock"
    assert config.env_passthrough is False
    assert config.tls_ca_file is None


def test_exports_mapping_form_sets_credential_modes():
    config = proxy.load_config(EXAMPLE)

    # Both forms, in one allowlist: a bare name (shared) and per-user mappings.
    assert config.exports == ["boiler_status", "node_ssh", "node_file_transfer"]
    assert config.export_modes == {
        "boiler_status": "shared",
        "node_ssh": "per_user",
        "node_file_transfer": "per_user",
    }
    assert set(config.export_modes.values()) <= edge_user_secrets.CREDENTIAL_MODES


def test_export_mcps_entries_survive_and_reach_the_loaded_export(tmp_path):
    """The allowlist is not just parsed: its policy reaches ``McpExport``."""
    config = proxy.load_config(EXAMPLE)

    # ``load_config`` keeps the operator's entries verbatim (names or mappings).
    assert config.export_mcps[0]["name"] == "devops-cli"
    assert config.export_mcps[0]["credential_mode"] == "per_user_required"
    assert config.export_mcps[0]["session_ttl_minutes"] == 30
    assert config.export_mcps[0]["max_sessions"] == 8
    assert "coralogix" in config.export_mcps

    # ... and they survive the manifest load, which is what the proxy publishes.
    mcps_dir = _write_mcp_manifests(tmp_path / "mcps")
    exports = proxy_mcp.load_mcps(mcps_dir, config.export_mcps)
    assert set(exports) == {"devops-cli", "coralogix"}

    devops = exports["devops-cli"]
    assert devops.credential_mode == "per_user_required"
    assert devops.session_ttl_minutes == 30
    assert devops.max_sessions == 8
    assert devops.include_tools == (
        "tenant_account_tools",
        "tenant_network_tools",
        "node_power_tools",
        "list_actions",
    )
    assert devops.exclude_tools == ("tenant_admin_tools",)
    # The explicit tools: catalog is published as written, schemas included.
    assert devops.config.tools[0].inputSchema["oneOf"]

    # The bare form carries the defaults.
    coralogix = exports["coralogix"]
    assert coralogix.credential_mode == "shared"
    assert coralogix.include_tools == ()
    assert coralogix.session_ttl_minutes == proxy_mcp.DEFAULT_SESSION_TTL_MINUTES
    assert coralogix.max_sessions == proxy_mcp.MAX_SESSIONS_PER_MCP


# ---------------------------------------------------------------- documented options


def test_token_env_form_parses(tmp_path):
    """The env-var fallback is documented commented; it is a real config key."""
    config = _load_variant(
        tmp_path,
        ("# token_env: TRELLIS_EDGE_TOKEN", "token_env: TRELLIS_EDGE_TOKEN_DC1"),
    )
    assert config.token_env == "TRELLIS_EDGE_TOKEN_DC1"


def test_mutual_tls_block_parses_when_enabled(tmp_path):
    ca, cert, key = (tmp_path / name for name in ("ca.pem", "edge.pem", "edge-key.pem"))
    for path in (ca, cert, key):
        path.write_text("placeholder\n", encoding="utf-8")

    config = _load_variant(
        tmp_path,
        ("# tls_ca_file: /etc/trellis/tls/ca.pem", f"tls_ca_file: {ca}"),
        ("# tls_cert_file: /etc/trellis/tls/edge.pem", f"tls_cert_file: {cert}"),
        ("# tls_key_file: /etc/trellis/tls/edge-key.pem", f"tls_key_file: {key}"),
    )
    assert config.tls_ca_file == str(ca)
    assert config.tls_cert_file == str(cert)
    assert config.tls_key_file == str(key)


def test_env_passthrough_opt_out_parses(tmp_path, monkeypatch):
    enabled = _load_variant(tmp_path, ("env_passthrough: false", "env_passthrough: true"))
    assert enabled.env_passthrough is True

    # The documented env mirror wins over the file, for env-only deploys.
    monkeypatch.setenv("TRELLIS_EDGE_ENV_PASSTHROUGH", "1")
    assert proxy.load_config(EXAMPLE).env_passthrough is True


# ---------------------------------------------------------------- validated surface


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        # `per-user` is the natural typo for `per_user`: a startup error, not a tool
        # that silently reads the wrong store.
        (
            "  - name: node_ssh\n    credential_mode: per_user",
            "  - name: node_ssh\n    credential_mode: per-user",
            "credential_mode",
        ),
        ("  - boiler_status", "  - 42", "must be a name or a mapping"),
        (
            "credential_mode: per_user_required",
            "credential_mode: per_user_only",
            "credential_mode",
        ),
        ("  - coralogix", "  - [coralogix]", "export_mcps entries"),
    ],
    ids=["exports-mode", "exports-entry-type", "export_mcps-mode", "export_mcps-entry-type"],
)
def test_broken_copy_is_rejected_at_load(tmp_path, old, new, match):
    """The example exercises the validated surface, not just the happy path."""
    with pytest.raises(ValueError, match=match):
        _load_variant(tmp_path, (old, new))


# ---------------------------------------------------------------- container paths


def test_paths_are_inside_the_container_mounts():
    config = proxy.load_config(EXAMPLE)

    named = {name: Path(getattr(config, name)) for name in ("tools_dir", "mcps_dir", "secrets_dir")}
    # The key path is env-only (EDGE_PRIVATE_KEY_PATH), not a ProxyConfig field.
    named["edge_key"] = Path("/etc/trellis/keys/edge-key")
    for name, path in named.items():
        assert ".." not in path.parts, f"{name} escapes its mount: {path}"
        absolute = path if path.is_absolute() else CONTAINER_WORKDIR / path
        assert str(absolute).startswith(MOUNTED_ROOTS), f"{name} is not a mounted path: {path}"


def test_credential_stores_are_outside_the_tool_writable_workspace():
    """Tool code can read the workspace; a credential store inside it would leak."""
    config = proxy.load_config(EXAMPLE)
    workspace = CONTAINER_WORKDIR / "workspace"

    for path in (Path(config.secrets_dir), Path("/etc/trellis/keys/edge-key")):
        assert not str(path).startswith(str(workspace))


def test_compose_mounts_what_proxy_yaml_points_at():
    """The sample compose and the sample config must agree, or the install is dead."""
    config = proxy.load_config(EXAMPLE)
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    proxy_service = compose["services"]["trellis-proxy"]
    volumes = proxy_service["volumes"]

    targets = []
    for entry in volumes:
        source, _, rest = str(entry).partition(":")
        target = rest.split(":", 1)[0] if rest else source
        targets.append(Path(target))

    for name in ("tools_dir", "mcps_dir", "secrets_dir"):
        path = Path(getattr(config, name))
        absolute = path if path.is_absolute() else CONTAINER_WORKDIR / path
        assert any(
            absolute == target or str(absolute).startswith(f"{target}/") for target in targets
        ), f"{name} ({absolute}) is not mounted by {COMPOSE.name}"

    # The seal key is a read-only DIRECTORY mount into the proxy ONLY: the rotation
    # overlap needs edge-key.old beside edge-key, and a single-file bind pins one
    # inode, so the old key would be invisible and every blob would fail closed.
    assert Path("/etc/trellis/keys") in targets
    key_path = proxy_service["environment"]["EDGE_PRIVATE_KEY_PATH"]
    assert "/etc/trellis/keys/edge-key" in key_path
    runner_targets = {
        str(entry).partition(":")[2].split(":", 1)[0]
        for entry in compose["services"]["runner"]["volumes"]
        if ":" in str(entry)
    }
    assert "/etc/trellis/keys" not in runner_targets
    # No plaintext per-user store is mounted anywhere any more.
    assert not any("edge-user-secrets" in str(entry) for entry in volumes)


# ---------------------------------------------------------------- helpers


def _write_mcp_manifests(root: Path) -> Path:
    """Minimal ``mcp.yaml`` trees for the two exported servers in the example."""
    (root / "devops-cli").mkdir(parents=True, exist_ok=True)
    (root / "coralogix").mkdir(parents=True, exist_ok=True)

    shared_schema = {
        "type": "object",
        "oneOf": [
            {"type": "object", "properties": {"action": {"const": "get_account"}},
             "required": ["action"]},
            {"type": "object", "properties": {"action": {"const": "list_accounts"}},
             "required": ["action"]},
        ],
    }
    (root / "devops-cli" / "mcp.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "devops-cli",
                "transport": "stdio",
                "command": "node",
                "args": ["/opt/devops-cli-mcp/dist/index.js"],
                "secrets": ["DEVOPS_URL", "DEVOPS_USERNAME", "DEVOPS_PASSWORD"],
                "tools": [
                    {
                        "name": "tenant_account_tools",
                        "description": "Tenant accounts.",
                        "inputSchema": shared_schema,
                    },
                    {"name": "list_actions", "description": "List actions.",
                     "inputSchema": {"type": "object"}},
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / "coralogix" / "mcp.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "coralogix",
                "transport": "stdio",
                "command": "node",
                "args": ["/opt/coralogix-mcp/index.js"],
                "tools": [
                    {"name": "query_logs", "description": "Query logs.",
                     "inputSchema": {"type": "object"}}
                ],
            }
        ),
        encoding="utf-8",
    )
    return root
