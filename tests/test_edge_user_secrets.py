# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge credential rules: the shared store, sealed per-user sets, and no mixing.

Per-user credentials are no longer files on the edge: central stores a browser-sealed
envelope and the edge opens it with the key in ``core.edge_keypair``. These tests pin
the resolution rules around that (R8): a sealed set is all-or-nothing for secrets,
``variables`` never come from it, and ``per_user_required`` fails closed when the caller
has none. The MCP tests use an in-memory stand-in for the runner session transport.
"""

import asyncio
import contextlib
import json
import logging
import sys
from pathlib import Path

import pytest
import yaml

from core import edge_user_secrets as secrets
from core import proxy, proxy_mcp
from core.models import MCPConfig, ToolConfig
from services.edge_relay import protocol

FIXTURE = Path(__file__).parent / "fixtures" / "mcp_stateful_server.py"
DEADLINE_MS = 60_000

SECRET_VALUE = "s3cr3t-from-the-file"
PROCESS_VALUE = "from-the-process-env"

SERVER_TOOLS = [
    {"name": "set_value", "description": "store a value", "inputSchema": {"type": "object"}},
    {"name": "get_value", "description": "read a value", "inputSchema": {"type": "object"}},
    {"name": "get_home", "description": "the session HOME", "inputSchema": {"type": "object"}},
    {"name": "env_dump", "description": "the env this process received", "inputSchema": {"type": "object"}},
]

ENV_VARS = (
    "TRELLIS_USER_ID",
    "TRELLIS_USER_EMAIL",
    "TRELLIS_EDGE_TOKEN",
    "TRELLIS_EDGE_CONFIG",
    "TRELLIS_EDGE_SECRETS_DIR",
    "TRELLIS_EDGE_USER_SECRETS_DIR",
    "TRELLIS_EDGE_MCPS_DIR",
    "EDGE_PRIVATE_KEY_PATH",
    "WORKSPACE_ROOT",
    "DEVOPS_PASSWORD",
    "CORALOGIX_DOMAIN",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """No ambient identity, token, secret, or "warned once" state between tests."""
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    secrets._WARNED_PERMISSIVE.clear()
    yield
    secrets._WARNED_PERMISSIVE.clear()


# ---------------------------------------------------------------- helpers


def make_store(tmp_path):
    return secrets.CredentialStore(secrets_dir=tmp_path / "edge-secrets")


def write_shared(store, name="devops", **values):
    path = store.shared_file(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    path.chmod(0o600)
    return path


def tool_config(name="devops", **kw):
    return ToolConfig(
        name=name, description=f"{name} tool", runtime="python", entrypoint="main.py", **kw
    )


def mcp_config(name="stateful", **kw):
    payload = {
        "name": name,
        "transport": "stdio",
        "command": sys.executable,
        "args": [str(FIXTURE)],
        "secrets": ["DEVOPS_PASSWORD"],
    }
    payload.update(kw)
    return MCPConfig(**payload)


def edge_config(tmp_path, **kw):
    payload = {
        "site": "plant-floor",
        "server_url": "ws://relay.local/edge/v1/connect",
        "secrets_dir": tmp_path / "edge-secrets",
    }
    payload.update(kw)
    return proxy.ProxyConfig(**payload)


def write_config_file(tmp_path, **overrides):
    data = {
        "site": "plant-floor",
        "server_url": "ws://relay.local/edge/v1/connect",
        "secrets_dir": str(tmp_path / "edge-secrets"),
    }
    data.update(overrides)
    path = tmp_path / "proxy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------- normalize_email


@pytest.mark.parametrize(
    "variant",
    ["ops@example.com", "OPS@Example.COM", "  Ops@Example.Com  ", "oPs@ExAmPlE.cOm"],
)
def test_case_variants_of_one_address_normalize_to_one_stem(variant):
    assert secrets.normalize_email(variant) == secrets.normalize_email("ops@example.com")


def test_unicode_addresses_are_deterministic_and_ascii_only():
    first = secrets.normalize_email("Ünïcode@Exämple.COM")
    second = secrets.normalize_email("ünïcode@exämple.com")

    assert first == second
    assert first.isascii()
    assert first[-9] == "_" and len(first.rsplit("_", 1)[1]) == 8


def test_two_addresses_that_slugify_alike_stay_distinct():
    assert secrets.normalize_email("a.b@x.example") != secrets.normalize_email("a-b@x.example")


def test_a_very_long_address_is_capped_and_still_unique():
    long_email = f"{'a' * 200}@example.com"
    stem = secrets.normalize_email(long_email)

    assert len(stem) <= secrets.MAX_SANITIZED_EMAIL + 9
    assert stem != secrets.normalize_email(f"{'a' * 201}@example.com")


def test_a_trailing_hyphen_after_capping_is_trimmed():
    stem = secrets.normalize_email(f"{'a' * 47}-b@example.com")
    slug = stem.rsplit("_", 1)[0]

    assert not slug.endswith("-")
    assert len(slug) <= secrets.MAX_SANITIZED_EMAIL


# ---------------------------------------------------------------- file format


def test_parse_env_text_is_defensive_and_never_interpolates():
    values = secrets.parse_env_text(
        "\n".join(
            [
                "# a comment",
                "",
                "DEVOPS_PASSWORD=hunter2",
                "  SPACED = padded  ",
                "EMPTY=",
                'QUOTED="a b c"',
                "SINGLE='x=y'",
                "not a key value line",
                "1BAD=nope",
                "DEVOPS_PASSWORD=last-wins",
                "TEMPLATE=$DEVOPS_PASSWORD",
            ]
        )
    )

    assert values["DEVOPS_PASSWORD"] == "last-wins"
    assert values["SPACED"] == "padded"
    assert values["EMPTY"] == ""
    assert values["QUOTED"] == "a b c"
    assert values["SINGLE"] == "x=y"
    assert values["TEMPLATE"] == "$DEVOPS_PASSWORD"  # no interpolation, ever
    assert "1BAD" not in values
    assert "not a key value line" not in values


def test_parse_env_file_tolerates_a_missing_or_broken_file(tmp_path):
    assert secrets.parse_env_file(tmp_path / "nope.env") == {}

    broken = tmp_path / "broken.env"
    broken.write_bytes(b"\xff\xfeKEY=value")
    assert secrets.parse_env_file(broken) == {}


def test_parse_env_text_accepts_an_export_prefix():
    """``export KEY=VALUE`` is the common dotenv form; dropping it silently loses a key."""
    values = secrets.parse_env_text(
        "export DEVOPS_PASSWORD=hunter2\nexport\tDEVOPS_URL=https://x\nexported=1\nexport\n"
    )

    assert values == {
        "DEVOPS_PASSWORD": "hunter2",
        "DEVOPS_URL": "https://x",
        "exported": "1",
    }


# ---------------------------------------------------------------- shared mode


def test_shared_mode_prefers_the_file_over_the_process_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)

    resolved = store.resolve(tool_config(secrets=["DEVOPS_PASSWORD"]), name="devops",
                             email="ops@example.com", site="dc1")

    assert resolved == {"DEVOPS_PASSWORD": SECRET_VALUE}


def test_a_declared_secret_never_comes_from_the_process_env(tmp_path, monkeypatch):
    """v0.7.1: the shared file is the only non-sealed secret source."""
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    store = make_store(tmp_path)
    write_shared(store, CORALOGIX_DOMAIN="corp.example")

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"], variables=["CORALOGIX_DOMAIN"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
    )

    # The secret is absent (not the process value); the variable still resolves.
    assert resolved == {"CORALOGIX_DOMAIN": "corp.example"}


def test_a_declared_variable_still_comes_from_the_process_env(tmp_path, monkeypatch):
    """Endpoints are edge configuration, not per-user material: the env layer stays."""
    monkeypatch.setenv("CORALOGIX_DOMAIN", "from-the-container")
    store = make_store(tmp_path)

    resolved = store.resolve(
        tool_config(variables=["CORALOGIX_DOMAIN"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
    )

    assert resolved == {"CORALOGIX_DOMAIN": "from-the-container"}


def test_shared_mode_with_no_file_and_no_env_returns_nothing(tmp_path):
    store = make_store(tmp_path)

    assert store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"]), name="devops", email=None, site="dc1"
    ) == {}


def test_an_empty_shared_file_value_leaves_the_secret_unset(tmp_path, monkeypatch):
    """A blank file value is "unset" -- and there is no process-env layer behind it."""
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    store = make_store(tmp_path)
    shared = store.shared_file("devops")
    shared.parent.mkdir(parents=True, exist_ok=True)
    shared.write_text("DEVOPS_PASSWORD=   \n", encoding="utf-8")

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
    )

    assert resolved == {}


def test_an_empty_shared_file_value_does_not_mask_a_variables_process_env(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("CORALOGIX_DOMAIN", "from-the-container")
    store = make_store(tmp_path)
    shared = store.shared_file("devops")
    shared.parent.mkdir(parents=True, exist_ok=True)
    shared.write_text("CORALOGIX_DOMAIN=   \n", encoding="utf-8")

    resolved = store.resolve(
        tool_config(variables=["CORALOGIX_DOMAIN"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
    )

    assert resolved == {"CORALOGIX_DOMAIN": "from-the-container"}


# ---------------------------------------------------------------- sealed sets


def test_a_sealed_set_wins_over_the_shared_file(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE, DEVOPS_URL="https://shared.internal")

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"], variables=["DEVOPS_URL"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
        sealed={"DEVOPS_PASSWORD": "from-the-browser"},
    )

    # The secret comes from the blob; the variable stays the edge's configuration.
    assert resolved == {
        "DEVOPS_PASSWORD": "from-the-browser",
        "DEVOPS_URL": "https://shared.internal",
    }


def test_a_partial_sealed_set_never_falls_back_to_the_shared_file(tmp_path):
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE, DEVOPS_KEY="shared-key")

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD", "DEVOPS_KEY"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
        sealed={"DEVOPS_PASSWORD": "only-one"},
    )

    assert resolved == {"DEVOPS_PASSWORD": "only-one"}
    assert "DEVOPS_KEY" not in resolved


def test_a_variable_in_a_sealed_set_is_ignored(tmp_path, monkeypatch):
    """Write-time rejects it; if one slips through, the edge still cannot move an endpoint."""
    monkeypatch.setenv("DEVOPS_URL", "https://corp.example")
    store = make_store(tmp_path)

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"], variables=["DEVOPS_URL"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
        sealed={"DEVOPS_URL": "https://attacker.invalid", "DEVOPS_PASSWORD": "pw"},
    )

    assert resolved["DEVOPS_URL"] == "https://corp.example"
    assert resolved["DEVOPS_PASSWORD"] == "pw"


def test_an_undeclared_name_in_a_sealed_set_is_ignored(tmp_path):
    store = make_store(tmp_path)

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
        sealed={"DEVOPS_PASSWORD": "pw", "EXTRA_KEY": "nope"},
    )

    assert resolved == {"DEVOPS_PASSWORD": "pw"}


def test_a_blank_sealed_value_counts_as_unset(tmp_path):
    """A blank field must not satisfy per_user_required (or reach a tool as "")."""
    store = make_store(tmp_path)

    with pytest.raises(secrets.MissingCredentials):
        store.resolve(
            tool_config(secrets=["DEVOPS_PASSWORD"]),
            name="devops",
            email="ops@example.com",
            site="dc1",
            mode="per_user_required",
            sealed={"DEVOPS_PASSWORD": ""},
        )


def test_an_unknown_mode_is_a_value_error(tmp_path):
    with pytest.raises(ValueError, match="credential_mode"):
        make_store(tmp_path).resolve(
            tool_config(), name="devops", email="a@b", site="dc1", mode="everyone"
        )


# ---------------------------------------------------------------- fail closed


def test_per_user_required_without_a_sealed_set_fails_closed(tmp_path):
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)

    with pytest.raises(secrets.MissingCredentials) as caught:
        store.resolve(
            tool_config(secrets=["DEVOPS_PASSWORD"]),
            name="devops",
            email="ops@example.com",
            site="dc1",
            mode="per_user_required",
        )

    assert caught.value.code == secrets.MISSING_CREDENTIALS == "missing_credentials"
    assert caught.value.message == "no credentials for ops@example.com on edge dc1"


def test_per_user_required_with_a_sealed_set_runs(tmp_path):
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
        mode="per_user_required",
        sealed={"DEVOPS_PASSWORD": "mine"},
    )

    assert resolved == {"DEVOPS_PASSWORD": "mine"}


def test_per_user_required_refuses_a_sealed_set_without_a_declared_name(tmp_path):
    store = make_store(tmp_path)

    with pytest.raises(secrets.MissingCredentials):
        store.resolve(
            tool_config(secrets=["DEVOPS_PASSWORD"]),
            name="devops",
            email="ops@example.com",
            site="dc1",
            mode="per_user_required",
            sealed={"SOMETHING_ELSE": "x"},
        )


def test_per_user_required_refuses_a_missing_identity_but_never_names_a_value(tmp_path):
    store = make_store(tmp_path)

    with pytest.raises(secrets.MissingCredentials) as caught:
        store.resolve(
            tool_config(secrets=["DEVOPS_PASSWORD"]),
            name="devops",
            email=None,
            site="dc1",
            mode="per_user_required",
        )

    assert caught.value.message == "no credentials for anonymous on edge dc1"


# ---------------------------------------------------------------- hygiene


def test_resolve_never_creates_a_directory(tmp_path):
    store = make_store(tmp_path)
    config = tool_config(secrets=["DEVOPS_PASSWORD"])

    store.resolve(config, name="devops", email="a@b", site="dc1")
    with pytest.raises(secrets.MissingCredentials):
        store.resolve(config, name="devops", email="a@b", site="dc1", mode="per_user_required")

    assert not store.secrets_dir.exists()


def test_a_permissive_shared_file_warns_once_and_never_leaks_the_value(tmp_path, caplog):
    store = make_store(tmp_path)
    path = write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)
    path.chmod(0o644)
    config = tool_config(secrets=["DEVOPS_PASSWORD"])

    with caplog.at_level(logging.WARNING, logger="core.edge_user_secrets"):
        store.resolve(config, name="devops", email="a@b", site="dc1")
        store.resolve(config, name="devops", email="a@b", site="dc1")

    warnings = [record for record in caplog.records if "group/other" in record.getMessage()]
    assert len(warnings) == 1
    assert "0600" in caplog.text
    assert SECRET_VALUE not in caplog.text


def test_an_unsafe_manifest_name_cannot_escape_the_secrets_dir(tmp_path, caplog):
    store = make_store(tmp_path)

    with caplog.at_level(logging.WARNING, logger="core.edge_user_secrets"):
        resolved = store.resolve(
            tool_config(secrets=["DEVOPS_PASSWORD"]), name="../etc/passwd", email="a@b", site="dc1"
        )

    assert resolved == {}
    assert "invalid credential file name" in caplog.text


def test_the_v05_per_user_store_is_gone():
    """Sealed credentials replaced it: no helper, no env var, no directory constant."""
    assert not hasattr(secrets, "warn_about_legacy_user_secrets")
    assert not hasattr(secrets, "LEGACY_USER_SECRETS_DIR")
    assert not hasattr(secrets, "LEGACY_USER_SECRETS_ENV")


def test_a_dropped_credential_key_is_logged(tmp_path, caplog):
    """A silently ignored `my-key=` looks like a missing credential at call time."""
    store = make_store(tmp_path)
    shared = store.shared_file("devops")
    shared.parent.mkdir(parents=True, exist_ok=True)
    shared.write_text(
        "DEVOPS_PASSWORD=kept\nmy-key=dropped\n1NVALID=also-dropped\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="core.edge_user_secrets"):
        resolved = store.resolve(
            tool_config(secrets=["DEVOPS_PASSWORD"]), name="devops", site="dc1"
        )

    assert resolved == {"DEVOPS_PASSWORD": "kept"}
    drops = [r.getMessage() for r in caplog.records if "dropping credential key" in r.getMessage()]
    assert len(drops) == 2
    assert "my-key" in " ".join(drops)
    assert str(shared) in " ".join(drops)
    # Never the value.
    assert "also-dropped" not in " ".join(drops)


# ---------------------------------------------------------------- build_env


def test_build_env_reads_the_shared_file_and_hides_extra_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE, EXTRA_KEY="should-not-leak")
    config = tool_config(secrets=["DEVOPS_PASSWORD"])

    env = proxy.build_env(tmp_path, config, credentials=store, site="dc1", email="ops@example.com")

    assert env["DEVOPS_PASSWORD"] == SECRET_VALUE
    assert "EXTRA_KEY" not in env


def test_build_env_keeps_the_token_out_even_when_a_file_carries_it(tmp_path):
    store = make_store(tmp_path)
    store.secrets_dir.mkdir(parents=True)
    (store.secrets_dir / "devops.env").write_text("TRELLIS_EDGE_TOKEN=from-a-file\n", encoding="utf-8")

    env = proxy.build_env(tmp_path, tool_config(), credentials=store, site="dc1")

    assert "TRELLIS_EDGE_TOKEN" not in env


def test_build_env_raises_missing_credentials_without_a_sealed_set(tmp_path):
    store = make_store(tmp_path)

    with pytest.raises(secrets.MissingCredentials) as caught:
        proxy.build_env(
            tmp_path,
            tool_config(secrets=["DEVOPS_PASSWORD"]),
            {"user_email": "ops@example.com"},
            credentials=store,
            credential_mode="per_user_required",
            site="dc1",
        )

    assert caught.value.message == "no credentials for ops@example.com on edge dc1"


def test_build_env_with_a_partial_sealed_set_never_uses_the_process_env_gap(
    tmp_path, monkeypatch
):
    """The blocking property: passthrough must not complete a partial sealed set."""
    monkeypatch.setenv("DEVOPS_PASSWORD", "leaked-from-the-container")
    monkeypatch.setenv("CORALOGIX_DOMAIN", "corp.example")
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_URL="https://shared.internal")
    config = tool_config(secrets=["DEVOPS_PASSWORD", "DEVOPS_URL"], variables=["CORALOGIX_DOMAIN"])

    env = proxy.build_env(
        tmp_path,
        config,
        {"user_email": "ops@example.com"},
        passthrough=True,
        credentials=store,
        credential_mode="per_user_required",
        site="dc1",
        sealed={"DEVOPS_URL": "https://ops.internal"},
    )

    assert env["DEVOPS_URL"] == "https://ops.internal"
    assert "DEVOPS_PASSWORD" not in env
    # Variables are edge configuration and still resolve.
    assert env["CORALOGIX_DOMAIN"] == "corp.example"


def test_two_users_get_their_own_sealed_values_and_nothing_else(tmp_path):
    store = make_store(tmp_path)
    config = tool_config(secrets=["DEVOPS_PASSWORD"])

    def env_for(email, value):
        return proxy.build_env(
            tmp_path,
            config,
            {"user_email": email},
            credentials=store,
            credential_mode="per_user_required",
            site="dc1",
            sealed={"DEVOPS_PASSWORD": value},
        )

    first, second = env_for("a@example.com", "alpha"), env_for("b@example.com", "beta")

    assert first["DEVOPS_PASSWORD"] == "alpha"
    assert second["DEVOPS_PASSWORD"] == "beta"
    assert "alpha" not in second.values() and "beta" not in first.values()
    assert first["TRELLIS_USER_EMAIL"] == "a@example.com"


# ---------------------------------------------------------------- tool calls


def _never_called(*args, **kwargs):
    raise AssertionError("execute_tool must not run when credentials are missing")


def test_handle_call_refuses_per_user_required_without_a_sealed_set(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", _never_called)
    store_config = edge_config(tmp_path)
    frame = {
        "t": "call",
        "id": "c1",
        "tool": "devops",
        "args": {},
        "deadline_ms": DEADLINE_MS,
        "user_email": "ops@example.com",
    }

    result = asyncio.run(
        proxy.handle_call(
            {"devops": (tool_config(secrets=["DEVOPS_PASSWORD"]), tmp_path)},
            frame,
            proxy_config=store_config,
            credential_modes={"devops": "per_user_required"},
        )
    )

    assert result["ok"] is False
    assert result["error"] == {
        "code": "missing_credentials",
        "message": "no credentials for ops@example.com on edge plant-floor",
    }


def test_the_credential_mode_travels_through_the_deadline_wrapper(tmp_path, monkeypatch):
    store_config = edge_config(tmp_path)
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", _never_called)
    frame = {
        "t": "call",
        "id": "c3",
        "tool": "devops",
        "args": {},
        "deadline_ms": DEADLINE_MS,
        "user_email": "ops@example.com",
    }

    result = asyncio.run(
        proxy._call_with_deadline(
            {"devops": (tool_config(secrets=["DEVOPS_PASSWORD"]), tmp_path)},
            frame,
            proxy_config=store_config,
            credential_modes={"devops": "per_user_required"},
        )
    )

    assert result["error"]["code"] == "missing_credentials"


def test_handle_call_without_a_mode_mapping_uses_the_config(tmp_path, monkeypatch):
    """A direct caller must not be able to downgrade ``per_user_required`` silently."""
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", _never_called)
    store_config = edge_config(tmp_path, export_modes={"devops": "per_user_required"})
    frame = {
        "t": "call",
        "id": "c4",
        "tool": "devops",
        "args": {},
        "deadline_ms": DEADLINE_MS,
        "user_email": "ops@example.com",
    }

    result = asyncio.run(
        proxy.handle_call(
            {"devops": (tool_config(secrets=["DEVOPS_PASSWORD"]), tmp_path)},
            frame,
            proxy_config=store_config,
        )
    )

    assert result["error"]["code"] == "missing_credentials"


# ---------------------------------------------------------------- no leaks


class RecordingWebSocket:
    """Just enough of the relay socket to run ``_serve`` and capture every frame."""

    def __init__(self, frames, grace=0.2):
        self._frames = [protocol.encode(frame) for frame in frames]
        self.sent = []
        self._grace = grace
        self._drained = False

    async def send(self, data):
        self.sent.append(json.loads(data))

    async def recv(self):
        return self._frames.pop(0)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._frames:
            return self._frames.pop(0)
        if not self._drained:
            self._drained = True
            await asyncio.sleep(self._grace)
        raise StopAsyncIteration

    async def close(self, code=1000, reason=""):
        return None


def test_no_secret_value_reaches_a_frame_or_a_log_line(tmp_path, monkeypatch, caplog):
    """The edge's whole output surface, over one refused call."""
    store_config = edge_config(tmp_path)
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", _never_called)
    config_map = {"devops": (tool_config(secrets=["DEVOPS_PASSWORD"]), tmp_path)}

    session = proxy._Session(store_config, config_path=None)
    session.tools = config_map
    session.credential_modes = {"devops": "per_user_required"}
    ws = RecordingWebSocket(
        [
            {"t": "welcome", "site": "plant-floor"},
            {
                "t": "call",
                "id": "c9",
                "tool": "devops",
                "args": {},
                "deadline_ms": DEADLINE_MS,
                "user_email": "ops@example.com",
            },
        ]
    )

    with caplog.at_level(logging.DEBUG):
        asyncio.run(proxy._serve(session, ws))

    sent = json.dumps(ws.sent)
    assert "missing_credentials" in sent
    assert SECRET_VALUE not in sent
    assert SECRET_VALUE not in caplog.text
    # The hello frame describes the catalog, never a credential.
    hello = proxy.hello_frame(config_map, {})
    assert SECRET_VALUE not in protocol.encode(hello)


# ---------------------------------------------------------------- MCP sessions


@pytest.fixture
def fake_sessions(tmp_path, monkeypatch):
    """In-memory runner-session transport: a real FastMCP server, no process/dirs."""
    pytest.importorskip("fastmcp", reason="the in-memory MCP server needs fastmcp")
    from fastmcp import FastMCP
    from fastmcp.client.transports.base import ClientTransport
    from fastmcp.client.transports.memory import FastMCPTransport

    writable = tmp_path / "rw"
    monkeypatch.setenv("WORKSPACE_ROOT", str(writable))
    created = []

    class FakeRunnerTransport(ClientTransport):
        def __init__(self, entry, env, **kwargs):
            self.env = dict(env)
            self.kwargs = kwargs
            state = {"data": {}, "home": f"session-{len(created)}"}
            self.state = state
            server = FastMCP("stateful")

            @server.tool
            def set_value(key: str, value: object) -> str:
                state["data"][key] = value
                return "ok"

            @server.tool
            def get_value(key: str) -> object:
                return state["data"].get(key)

            @server.tool
            def get_home() -> str:
                return state["home"]

            @server.tool
            def env_dump() -> dict:
                return dict(self.env)

            self._inner = FastMCPTransport(server)

        @contextlib.asynccontextmanager
        async def connect_session(self, *, transport_options=None, **session_kwargs):
            async with self._inner.connect_session(
                transport_options=transport_options, **session_kwargs
            ) as session:
                yield session

    def factory(entry, env, **kwargs):
        transport = FakeRunnerTransport(entry, env, **kwargs)
        created.append(transport)
        return transport

    monkeypatch.setattr(proxy_mcp, "_runner_transport", factory)
    return created


def write_mcp(root, name="stateful", **overrides):
    directory = Path(root) / name
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "name": name,
        "transport": "stdio",
        "command": "stateful-mcp",
        "args": ["--serve"],
        "tools": SERVER_TOOLS,
        "secrets": ["DEVOPS_PASSWORD"],
    }
    payload.update(overrides)
    (directory / "mcp.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")
    return directory


def mcp_entries(root, **export):
    entry = {"name": "stateful"}
    entry.update(export)
    return proxy_mcp.load_mcps(root, [entry])


def text(result):
    return " ".join(block.get("text", "") for block in result["content"])


def structured(result):
    payload = result.get("structuredContent")
    if payload is None:
        payload = json.loads(text(result))
    # FastMCP wraps a scalar/dict tool return under a single "result" key.
    if isinstance(payload, dict) and set(payload) == {"result"}:
        payload = payload["result"]
    return payload


def test_an_mcp_session_sees_only_the_callers_sealed_credentials(
    tmp_path, fake_sessions, monkeypatch
):
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    root = tmp_path / "mcps"
    write_mcp(root, secrets=["DEVOPS_PASSWORD"])
    entries = mcp_entries(root, credential_mode="per_user_required")
    manager = proxy_mcp.McpSessionManager(credentials=make_store(tmp_path), site="plant-floor")

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries, tmp_path))
            return {
                email: structured(
                    await manager.call(
                        "stateful",
                        "env_dump",
                        {},
                        {"user_email": email},
                        DEADLINE_MS,
                        sealed={"DEVOPS_PASSWORD": value, "EXTRA_KEY": "nope"},
                    )
                )
                for email, value in (("a@example.com", "alpha"), ("b@example.com", "beta"))
            }
        finally:
            await manager.kill_all()

    envs = asyncio.run(scenario())

    assert envs["a@example.com"]["DEVOPS_PASSWORD"] == "alpha"
    assert envs["b@example.com"]["DEVOPS_PASSWORD"] == "beta"
    assert "EXTRA_KEY" not in envs["a@example.com"]
    assert "beta" not in envs["a@example.com"].values()
    for env in envs.values():
        assert "TRELLIS_EDGE_TOKEN" not in env


def test_per_user_required_mcp_spawns_nothing_without_a_sealed_set(tmp_path, fake_sessions):
    root = tmp_path / "mcps"
    write_mcp(root, secrets=["DEVOPS_PASSWORD"])
    entries = mcp_entries(root, credential_mode="per_user_required")
    manager = proxy_mcp.McpSessionManager(credentials=make_store(tmp_path), site="plant-floor")

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries, tmp_path))
            with pytest.raises(proxy_mcp.McpCallError) as caught:
                await manager.call(
                    "stateful", "env_dump", {}, {"user_email": "ops@example.com"}, DEADLINE_MS
                )
            return caught.value
        finally:
            await manager.kill_all()

    error = asyncio.run(scenario())

    assert error.code == "missing_credentials"
    assert error.message == "no credentials for ops@example.com on edge plant-floor"
    # Fail closed means no container: no transport, no session, no host directory.
    assert fake_sessions == []
    assert not (tmp_path / "rw" / "mcp-sessions").exists()
    assert manager._sessions == {}


def test_a_new_sealed_set_reaches_a_reopened_session(tmp_path, fake_sessions):
    """A live session keeps its env; a new container gets the new sealed set."""
    root = tmp_path / "mcps"
    write_mcp(root, secrets=["DEVOPS_PASSWORD"])
    entries = mcp_entries(root, credential_mode="per_user_required")
    manager = proxy_mcp.McpSessionManager(credentials=make_store(tmp_path), site="plant-floor")

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries, tmp_path))
            identity = {"user_email": "ops@example.com"}
            live = structured(
                await manager.call(
                    "stateful", "env_dump", {}, identity, DEADLINE_MS,
                    sealed={"DEVOPS_PASSWORD": "before"},
                )
            )
            home = text(
                await manager.call(
                    "stateful", "get_home", {}, identity, DEADLINE_MS,
                    sealed={"DEVOPS_PASSWORD": "before"},
                )
            )
            still_live = structured(
                await manager.call(
                    "stateful", "env_dump", {}, identity, DEADLINE_MS,
                    sealed={"DEVOPS_PASSWORD": "after"},
                )
            )
            same_home = text(
                await manager.call(
                    "stateful", "get_home", {}, identity, DEADLINE_MS,
                    sealed={"DEVOPS_PASSWORD": "after"},
                )
            )
            await manager.kill_all()
            fresh = structured(
                await manager.call(
                    "stateful", "env_dump", {}, identity, DEADLINE_MS,
                    sealed={"DEVOPS_PASSWORD": "after"},
                )
            )
            fresh_home = text(
                await manager.call(
                    "stateful", "get_home", {}, identity, DEADLINE_MS,
                    sealed={"DEVOPS_PASSWORD": "after"},
                )
            )
            return live, home, still_live, same_home, fresh, fresh_home
        finally:
            await manager.kill_all()

    live, home, still_live, same_home, fresh, fresh_home = asyncio.run(scenario())

    assert live["DEVOPS_PASSWORD"] == "before"
    # A changed sealed set reopens the session: "store credentials" takes effect
    # on the next call instead of waiting for the TTL.
    assert still_live["DEVOPS_PASSWORD"] == "after"
    assert same_home != home
    assert fresh["DEVOPS_PASSWORD"] == "after"
    # A new session is a new container, so its tmpfs HOME is fresh (no persisted state).
    assert fresh_home != home


def test_a_shared_file_is_used_for_an_mcp_session(tmp_path, fake_sessions, monkeypatch):
    """``shared`` mode is the service-account path: file first, process env last."""
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    root = tmp_path / "mcps"
    write_mcp(root, secrets=["DEVOPS_PASSWORD"])
    entries = mcp_entries(root)
    store = make_store(tmp_path)
    write_shared(store, name="stateful", DEVOPS_PASSWORD=SECRET_VALUE)
    manager = proxy_mcp.McpSessionManager(credentials=store, site="plant-floor")

    async def scenario():
        try:
            manager.set_entries(entries, await catalogs_for(entries, tmp_path))
            return structured(
                await manager.call(
                    "stateful", "env_dump", {}, {"user_email": "anyone@example.com"}, DEADLINE_MS
                )
            )
        finally:
            await manager.kill_all()

    env = asyncio.run(scenario())

    assert env["DEVOPS_PASSWORD"] == SECRET_VALUE


def test_discovery_of_a_per_user_required_server_says_to_declare_a_catalog(
    tmp_path, fake_sessions
):
    """No caller exists during discovery, so a live catalog cannot be resolved."""
    root = tmp_path / "mcps"
    write_mcp(root, tools=[], secrets=["DEVOPS_PASSWORD"])
    entries = mcp_entries(root, credential_mode="per_user_required")
    store = make_store(tmp_path)

    async def scenario():
        return await proxy_mcp.build_catalog(entries["stateful"], credentials=store, site="plant-floor")

    with pytest.raises(proxy_mcp.McpCallError) as caught:
        asyncio.run(scenario())

    assert caught.value.code == "mcp_unavailable"
    assert "static 'tools:' catalog" in caught.value.message


def test_http_headers_come_from_the_sealed_set(tmp_path, monkeypatch):
    """A declared credential from a sealed set must reach the endpoint, not the env."""
    recorded = {}

    class FakeClient:
        def __init__(self, transport):
            self.transport = transport

    def transport_class(kind):
        def build(**kwargs):
            recorded[kind] = kwargs
            return kwargs

        return build

    monkeypatch.setattr(
        proxy_mcp,
        "_fastmcp",
        lambda: (FakeClient, transport_class("http"), transport_class("sse")),
    )
    entry = proxy_mcp.McpExport(
        name="stateful",
        config=MCPConfig(
            name="stateful",
            transport="http",
            command="https://internal.example/mcp",
            secrets=["DEVOPS_PASSWORD"],
        ),
        directory=tmp_path,
        credential_mode="per_user",
    )
    identity = {"user_email": "ops@example.com", "user": "u1"}

    env = proxy_mcp._server_env(
        entry, identity, passthrough=False, token_env=None,
        credentials=make_store(tmp_path), site="plant-floor",
        sealed={"DEVOPS_PASSWORD": "sealed-value"},
    )
    proxy_mcp._transport(entry, env)

    assert recorded["http"]["headers"] == {"DEVOPS_PASSWORD": "sealed-value"}
    assert env["TRELLIS_USER_EMAIL"] == "ops@example.com"


async def catalogs_for(entries, tmp_path):
    return {
        name: await proxy_mcp.build_catalog(entry, credentials=make_store(tmp_path), site="plant-floor")
        for name, entry in entries.items()
    }


# ---------------------------------------------------------------- CLI


def test_user_secrets_is_an_unknown_command():
    """The v0.5 plaintext CLI must be gone, not silently accepted."""
    with pytest.raises(SystemExit) as caught:
        proxy.main(["user-secrets", "list"])

    assert caught.value.code == 2


def test_edge_keygen_delegates_to_the_keypair_module(tmp_path, monkeypatch, capsys):
    from core import edge_keypair

    path = tmp_path / "etc-trellis" / "edge-key"
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
    key = edge_keypair.generate(path)

    with pytest.raises(SystemExit) as caught:
        proxy.main(["edge-keygen", "--show", "--path", str(path)])

    assert caught.value.code == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed == key.public_json()


def test_edge_keygen_rotate_and_drop_old(tmp_path, monkeypatch):
    from core import edge_keypair

    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
    path = tmp_path / "etc-trellis" / "edge-key"
    edge_keypair.generate(path)
    old_fp = edge_keypair.load(path).fingerprint

    with pytest.raises(SystemExit) as caught:
        proxy.main(["edge-keygen", "--rotate", "--path", str(path)])
    assert caught.value.code == 0
    assert edge_keypair.load(path).fingerprint != old_fp
    assert edge_keypair.load_old(path) is not None

    with pytest.raises(SystemExit) as caught:
        proxy.main(["edge-keygen", "--drop-old-key", "--path", str(path)])
    assert caught.value.code == 0
    assert edge_keypair.load_old(path) is None


# ---------------------------------------------------------------- proxy.yaml surface


def test_load_config_reads_the_shared_credential_dir(tmp_path):
    path = write_config_file(tmp_path, secrets_dir=str(tmp_path / "svc"))

    config = proxy.load_config(path)

    assert config.secrets_dir == tmp_path / "svc"
    assert not hasattr(config, "user_secrets_dir")


def test_load_config_defaults_the_shared_credential_dir(tmp_path):
    path = tmp_path / "proxy.yaml"
    path.write_text(
        "site: plant-floor\nserver_url: ws://relay.local/edge/v1/connect\n", encoding="utf-8"
    )

    config = proxy.load_config(path)

    assert config.secrets_dir == Path("edge-secrets")


def test_the_shared_credential_dir_can_be_overridden_from_the_environment(tmp_path, monkeypatch):
    path = write_config_file(tmp_path)
    monkeypatch.setenv("TRELLIS_EDGE_SECRETS_DIR", str(tmp_path / "env-svc"))

    config = proxy.load_config(path)

    assert config.secrets_dir == tmp_path / "env-svc"


def test_a_legacy_user_secrets_dir_key_is_ignored(tmp_path):
    path = write_config_file(tmp_path, user_secrets_dir=str(tmp_path / "users"))

    config = proxy.load_config(path)

    assert not hasattr(config, "user_secrets_dir")


def test_exports_accept_the_mapping_form(tmp_path):
    path = write_config_file(
        tmp_path,
        exports=["plain", {"name": "guarded", "credential_mode": "per_user_required"}],
    )

    config = proxy.load_config(path)

    assert config.exports == ["plain", "guarded"]
    assert config.export_modes == {"plain": "shared", "guarded": "per_user_required"}


@pytest.mark.parametrize(
    "entry",
    [
        {"name": "guarded", "credential_mode": "sometimes"},
        {"name": "guarded", "mode": "per_user"},
        {"credential_mode": "per_user"},
        ["nested"],
        5,
    ],
)
def test_a_malformed_exports_entry_is_a_startup_error(tmp_path, entry):
    path = write_config_file(tmp_path, exports=[entry])

    with pytest.raises(ValueError, match="exports"):
        proxy.load_config(path)


def test_sighup_reports_a_moved_credential_dir_as_needing_a_restart(tmp_path, caplog):
    path = write_config_file(tmp_path)
    session = proxy._Session(proxy.load_config(path), path)
    session.reload()

    write_config_file(tmp_path, secrets_dir=str(tmp_path / "moved"))
    with caplog.at_level(logging.WARNING):
        session.reload()

    assert "secrets_dir changes need a restart" in caplog.text
    assert session.config.secrets_dir == tmp_path / "edge-secrets"


def test_sighup_applies_a_changed_credential_mode(tmp_path):
    tools = tmp_path / "tools"
    directory = tools / "devops"
    directory.mkdir(parents=True)
    (directory / "tool.yaml").write_text(
        "name: devops\ndescription: d\nruntime: python\nentrypoint: main.py\n", encoding="utf-8"
    )
    config_path = write_config_file(tmp_path, tools_dir=str(tools), exports=["devops"])

    session = proxy._Session(proxy.load_config(config_path), config_path)
    session.reload()
    assert session.credential_modes == {"devops": "shared"}

    write_config_file(
        tmp_path,
        tools_dir=str(tools),
        exports=[{"name": "devops", "credential_mode": "per_user_required"}],
    )
    session.reload()

    assert session.credential_modes == {"devops": "per_user_required"}
    # The session's MCP manager keeps the same store (restart-required fields).
    assert session.mcp.site == "plant-floor"
