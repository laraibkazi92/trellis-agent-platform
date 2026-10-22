# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Edge-local credential tests: normalization, the three modes, CLI, and no leaks.

Credentials never leave the edge VM: they arrive in ``edge-secrets`` /
``edge-user-secrets`` files and are handed to a child process only through the names
its manifest declares. These tests pin the resolution chain per mode, the fail-closed
refusal, and the two properties an operator is trusting: a user only ever sees their
own file, and no value appears in a frame, a log line, or a config payload.

The MCP session tests spawn ``tests/fixtures/mcp_stateful_server.py`` (the sandbox seam
is monkeypatched) so an edited file can be shown not to touch a live session.
"""

import asyncio
import io
import json
import logging
import stat
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
OTHER_VALUE = "other-users-secret"
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
    "SANDBOX_BACKEND",
    "SANDBOX_RW_PATH",
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
    return secrets.CredentialStore(
        secrets_dir=tmp_path / "edge-secrets",
        user_secrets_dir=tmp_path / "edge-user-secrets",
    )


def write_shared(store, name="devops", **values):
    path = store.shared_file(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    path.chmod(0o600)
    return path


def write_user(store, email, **values):
    path = store.user_file(email)
    secrets.write_env_file(path, {key: str(value) for key, value in values.items()})
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
        "user_secrets_dir": tmp_path / "edge-user-secrets",
    }
    payload.update(kw)
    return proxy.ProxyConfig(**payload)


def write_config_file(tmp_path, **overrides):
    data = {
        "site": "plant-floor",
        "server_url": "ws://relay.local/edge/v1/connect",
        "secrets_dir": str(tmp_path / "edge-secrets"),
        "user_secrets_dir": str(tmp_path / "edge-user-secrets"),
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
def test_case_variants_of_one_address_normalize_to_one_file(variant):
    assert secrets.normalize_email(variant) == secrets.normalize_email("ops@example.com")


def test_unicode_addresses_are_deterministic_and_ascii_only():
    first = secrets.normalize_email("Ünïcode@Exämple.COM")
    second = secrets.normalize_email("ünïcode@exämple.com")

    assert first == second
    assert first.isascii()
    assert first.endswith("_") or "_" in first


def test_two_addresses_that_slugify_alike_stay_distinct():
    """The hash suffix is what keeps `a.b@x` and `a-b@x` from sharing a file."""
    assert secrets.normalize_email("a.b@x.example") != secrets.normalize_email("a-b@x.example")


def test_a_very_long_address_is_capped_and_still_unique():
    long_email = f"{'a' * 200}@example.com"

    stem = secrets.normalize_email(long_email)

    slug, _, digest = stem.rpartition("_")
    assert len(slug) <= secrets.MAX_SANITIZED_EMAIL
    assert len(digest) == 8 and all(ch in "0123456789abcdef" for ch in digest)
    assert len(stem) <= secrets.MAX_SANITIZED_EMAIL + 9


def test_a_trailing_hyphen_after_capping_is_trimmed():
    # 47 a's, then "-b": capping at 48 would end on the separator.
    stem = secrets.normalize_email(f"{'a' * 47}-b@example.com")

    slug = stem.rpartition("_")[0]
    assert not slug.endswith("-")
    assert len(slug) <= secrets.MAX_SANITIZED_EMAIL


@pytest.mark.parametrize(
    "hostile",
    [
        "../../etc/passwd",
        "/etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "a/b",
        "..\\..\\windows",
        "....//....//x",
        "a@b/../../../root",
    ],
)
def test_no_email_can_escape_the_user_secrets_dir(tmp_path, hostile):
    store = make_store(tmp_path)

    path = store.user_file(hostile)

    assert path.parent == store.user_secrets_dir
    assert "/" not in path.name and "\\" not in path.name
    assert ".." not in path.name
    # And it really lands inside the store when written.
    secrets.write_env_file(path, {"DEVOPS_PASSWORD": "x"})
    assert path.resolve().parent == store.user_secrets_dir.resolve()


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


def test_write_env_file_keeps_the_mode_of_a_directory_it_did_not_create(tmp_path):
    """A 0750 volume the operator mounted is theirs; only a directory we create is 0700."""
    directory = tmp_path / "mounted"
    directory.mkdir()
    directory.chmod(0o750)

    secrets.write_env_file(directory / "ops.env", {"K": "v"})

    assert stat.S_IMODE(directory.stat().st_mode) == 0o750
    assert stat.S_IMODE((directory / "ops.env").stat().st_mode) == 0o600


def test_write_env_file_is_0600_atomic_and_round_trips(tmp_path):
    path = tmp_path / "store" / "ops.env"

    secrets.write_env_file(path, {"A": "1", "B": "two words"})

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert secrets.parse_env_file(path) == {"A": "1", "B": "two words"}
    # Atomic: no temp file was left behind, and the directory is private.
    assert [entry.name for entry in path.parent.iterdir()] == [path.name]
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_write_env_file_rejects_a_value_a_dotenv_cannot_represent(tmp_path):
    with pytest.raises(ValueError, match="newline"):
        secrets.write_env_file(tmp_path / "x.env", {"KEY": "one\ntwo"})

    with pytest.raises(ValueError, match="invalid credential key"):
        secrets.write_env_file(tmp_path / "x.env", {"BAD KEY": "x"})


# ---------------------------------------------------------------- shared mode


def test_shared_mode_prefers_the_file_over_the_process_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)

    resolved = store.resolve(tool_config(secrets=["DEVOPS_PASSWORD"]), name="devops",
                             email="ops@example.com", site="dc1")

    assert resolved == {"DEVOPS_PASSWORD": SECRET_VALUE}


def test_shared_mode_falls_back_to_the_process_env_per_key(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    store = make_store(tmp_path)
    write_shared(store, CORALOGIX_DOMAIN="corp.example")

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"], variables=["CORALOGIX_DOMAIN"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
    )

    assert resolved == {"DEVOPS_PASSWORD": PROCESS_VALUE, "CORALOGIX_DOMAIN": "corp.example"}


def test_shared_mode_never_consults_a_per_user_file(tmp_path):
    """A service account must not be shadowed by one user's file."""
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)
    write_user(store, "ops@example.com", DEVOPS_PASSWORD=OTHER_VALUE)

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
    )

    assert resolved["DEVOPS_PASSWORD"] == SECRET_VALUE


def test_shared_mode_with_no_file_and_no_env_returns_nothing(tmp_path):
    store = make_store(tmp_path)

    assert store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"]), name="devops", email=None, site="dc1"
    ) == {}


# ---------------------------------------------------------------- per_user mode


def test_per_user_mode_prefers_the_user_file(tmp_path, monkeypatch):
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)
    write_user(store, "ops@example.com", DEVOPS_PASSWORD=OTHER_VALUE)

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
        mode="per_user",
    )

    assert resolved["DEVOPS_PASSWORD"] == OTHER_VALUE


def test_per_user_mode_falls_back_to_shared_then_the_process_env(tmp_path, monkeypatch):
    monkeypatch.setenv("CORALOGIX_DOMAIN", PROCESS_VALUE)
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)
    write_user(store, "ops@example.com", DEVOPS_PASSWORD=OTHER_VALUE)

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"], variables=["CORALOGIX_DOMAIN"]),
        name="devops",
        email="mallory@example.com",
        site="dc1",
        mode="per_user",
    )

    assert resolved == {"DEVOPS_PASSWORD": SECRET_VALUE, "CORALOGIX_DOMAIN": PROCESS_VALUE}


def test_an_empty_user_value_does_not_mask_the_shared_file(tmp_path):
    """Empty is unset: a blank value in the top layer must not shadow a real one."""
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)
    path = store.user_file("ops@example.com")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("DEVOPS_PASSWORD=\n", encoding="utf-8")

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
        mode="per_user",
    )

    assert resolved == {"DEVOPS_PASSWORD": SECRET_VALUE}


def test_an_empty_file_value_does_not_mask_the_process_env(tmp_path, monkeypatch):
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

    assert resolved == {"DEVOPS_PASSWORD": PROCESS_VALUE}


# ---------------------------------------------------------------- fail closed


def test_per_user_required_resolves_the_users_own_file(tmp_path):
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE)
    write_user(store, "ops@example.com", DEVOPS_PASSWORD=OTHER_VALUE)

    resolved = store.resolve(
        tool_config(secrets=["DEVOPS_PASSWORD"]),
        name="devops",
        email="ops@example.com",
        site="dc1",
        mode="per_user_required",
    )

    assert resolved == {"DEVOPS_PASSWORD": OTHER_VALUE}


@pytest.mark.parametrize(
    "arrange",
    [
        pytest.param(lambda store: None, id="no-file"),
        pytest.param(
            lambda store: write_user(store, "mallory@example.com", DEVOPS_PASSWORD=OTHER_VALUE),
            id="someone-else-file-only",
        ),
        pytest.param(
            lambda store: write_user(store, "ops@example.com", UNRELATED="x"),
            id="file-without-any-declared-key",
        ),
        pytest.param(lambda store: write_shared(store, DEVOPS_PASSWORD=SECRET_VALUE), id="shared-only"),
    ],
)
def test_per_user_required_fails_closed_with_the_exact_message(tmp_path, arrange):
    store = make_store(tmp_path)
    arrange(store)

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


def test_per_user_required_with_nothing_declared_also_fails_closed(tmp_path):
    """A manifest that declares no key cannot satisfy a per-user requirement."""
    store = make_store(tmp_path)
    write_user(store, "ops@example.com", DEVOPS_PASSWORD=OTHER_VALUE)

    with pytest.raises(secrets.MissingCredentials):
        store.resolve(
            tool_config(),
            name="devops",
            email="ops@example.com",
            site="dc1",
            mode="per_user_required",
        )


def test_an_empty_value_does_not_satisfy_per_user_required(tmp_path):
    """Nothing to send is not a credential: ``KEY=`` must fail closed, not run."""
    store = make_store(tmp_path)
    path = store.user_file("ops@example.com")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("DEVOPS_PASSWORD=\nDEVOPS_URL=   \n", encoding="utf-8")

    with pytest.raises(secrets.MissingCredentials) as caught:
        store.resolve(
            tool_config(secrets=["DEVOPS_PASSWORD", "DEVOPS_URL"]),
            name="devops",
            email="ops@example.com",
            site="dc1",
            mode="per_user_required",
        )

    assert caught.value.message == "no credentials for ops@example.com on edge dc1"


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


def test_an_unknown_mode_is_a_value_error(tmp_path):
    with pytest.raises(ValueError, match="credential_mode"):
        make_store(tmp_path).resolve(
            tool_config(), name="devops", email="a@b", site="dc1", mode="everyone"
        )


# ---------------------------------------------------------------- hygiene


def test_resolve_never_creates_a_directory(tmp_path):
    store = make_store(tmp_path)
    config = tool_config(secrets=["DEVOPS_PASSWORD"])

    store.resolve(config, name="devops", email="a@b", site="dc1")
    with pytest.raises(secrets.MissingCredentials):
        store.resolve(config, name="devops", email="a@b", site="dc1", mode="per_user_required")

    assert not store.secrets_dir.exists()
    assert not store.user_secrets_dir.exists()


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


def test_a_permissive_user_file_warns_but_is_still_read(tmp_path, caplog):
    store = make_store(tmp_path)
    path = write_user(store, "ops@example.com", DEVOPS_PASSWORD=OTHER_VALUE)
    path.chmod(0o644)

    with caplog.at_level(logging.WARNING, logger="core.edge_user_secrets"):
        resolved = store.resolve(
            tool_config(secrets=["DEVOPS_PASSWORD"]),
            name="devops",
            email="ops@example.com",
            site="dc1",
            mode="per_user",
        )

    assert resolved["DEVOPS_PASSWORD"] == OTHER_VALUE
    assert "group/other" in caplog.text
    assert OTHER_VALUE not in caplog.text


def test_an_unsafe_manifest_name_cannot_escape_the_secrets_dir(tmp_path, caplog):
    store = make_store(tmp_path)

    with caplog.at_level(logging.WARNING, logger="core.edge_user_secrets"):
        resolved = store.resolve(
            tool_config(secrets=["DEVOPS_PASSWORD"]), name="../etc/passwd", email="a@b", site="dc1"
        )

    assert resolved == {}
    assert "invalid credential file name" in caplog.text


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
    secrets_dir = store.secrets_dir
    secrets_dir.mkdir(parents=True)
    (secrets_dir / "devops.env").write_text("TRELLIS_EDGE_TOKEN=from-a-file\n", encoding="utf-8")
    config = tool_config()

    env = proxy.build_env(tmp_path, config, credentials=store, site="dc1")

    assert "TRELLIS_EDGE_TOKEN" not in env


def test_build_env_raises_missing_credentials_for_an_unmapped_user(tmp_path):
    store = make_store(tmp_path)
    write_user(store, "someone@example.com", DEVOPS_PASSWORD=OTHER_VALUE)

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


def test_two_users_get_their_own_values_and_nothing_else(tmp_path):
    """The whole L3 property, at the env level."""
    store = make_store(tmp_path)
    write_shared(store, DEVOPS_PASSWORD="shared-service-account")
    write_user(store, "a@example.com", DEVOPS_PASSWORD="alpha")
    write_user(store, "b@example.com", DEVOPS_PASSWORD="beta")
    config = tool_config(secrets=["DEVOPS_PASSWORD"])

    def env_for(email):
        return proxy.build_env(
            tmp_path,
            config,
            {"user_email": email},
            credentials=store,
            credential_mode="per_user",
            site="dc1",
        )

    first, second = env_for("a@example.com"), env_for("b@example.com")

    assert first["DEVOPS_PASSWORD"] == "alpha"
    assert second["DEVOPS_PASSWORD"] == "beta"
    assert "alpha" not in second.values() and "beta" not in first.values()
    assert first["TRELLIS_USER_EMAIL"] == "a@example.com"


def test_per_user_required_with_passthrough_ignores_the_process_env(tmp_path, monkeypatch):
    """The blocking property: ``passthrough`` must not turn the mode into user -> env.

    ``passthrough`` copies the sanitized container env *before* the credential overlay,
    so a declared key the caller's file omits would otherwise arrive from the container
    and a fail-closed mode would quietly execute with the wrong credentials.
    """
    monkeypatch.setenv("DEVOPS_PASSWORD", "leaked-from-the-container")
    monkeypatch.setenv("CORALOGIX_DOMAIN", "corp.example")
    store = make_store(tmp_path)
    write_user(store, "ops@example.com", DEVOPS_URL="https://ops.internal")
    config = tool_config(secrets=["DEVOPS_PASSWORD", "DEVOPS_URL"])

    env = proxy.build_env(
        tmp_path,
        config,
        {"user_email": "ops@example.com"},
        passthrough=True,
        credentials=store,
        credential_mode="per_user_required",
        site="dc1",
    )

    assert env["DEVOPS_URL"] == "https://ops.internal"
    assert "DEVOPS_PASSWORD" not in env
    # Everything the manifest does not declare still comes through passthrough.
    assert env["CORALOGIX_DOMAIN"] == "corp.example"


# ---------------------------------------------------------------- tool calls


def _never_called(*args, **kwargs):
    raise AssertionError("execute_tool must not run when credentials are missing")


def test_handle_call_refuses_per_user_required_without_running_the_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", _never_called)
    store_config = edge_config(tmp_path)
    write_user(make_store(tmp_path), "someone@example.com", DEVOPS_PASSWORD=OTHER_VALUE)
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


def test_handle_call_runs_the_tool_with_the_users_own_value(tmp_path, monkeypatch):
    store_config = edge_config(tmp_path)
    write_user(make_store(tmp_path), "ops@example.com", DEVOPS_PASSWORD=OTHER_VALUE)
    seen = {}

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None):
        seen.update(env)
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    frame = {
        "t": "call",
        "id": "c2",
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
            credential_modes={"devops": "per_user"},
        )
    )

    assert result["ok"] is True
    assert seen["DEVOPS_PASSWORD"] == OTHER_VALUE
    assert seen["TRELLIS_USER_EMAIL"] == "ops@example.com"


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
    write_user(store, "someone@example.com", DEVOPS_PASSWORD=OTHER_VALUE)
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
    for value in (SECRET_VALUE, OTHER_VALUE):
        assert value not in sent
        assert value not in caplog.text
        # ... and not in the config payloads either.
        assert value not in json.dumps(store_config.secrets_dir.as_posix())
        assert value not in repr(store_config)
    # The hello frame describes the catalog, never a credential.
    hello = proxy.hello_frame(config_map, {})
    assert SECRET_VALUE not in protocol.encode(hello)


# ---------------------------------------------------------------- MCP sessions


@pytest.fixture
def fixture_server(tmp_path, monkeypatch):
    """The stateful server, unsandboxed, with a private writable root."""
    pytest.importorskip("fastmcp", reason="the stateful fixture server needs fastmcp")
    writable = tmp_path / "rw"
    monkeypatch.setenv("SANDBOX_RW_PATH", str(writable))
    monkeypatch.setattr(
        proxy_mcp,
        "build_stdio_argv",
        lambda entry, home_dir, backend=None: [sys.executable, str(FIXTURE)],
    )
    return writable


def write_mcp(root, name="stateful", **overrides):
    directory = Path(root) / name
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "name": name,
        "transport": "stdio",
        "command": sys.executable,
        "args": [str(FIXTURE)],
        "tools": SERVER_TOOLS,
        "secrets": ["DEVOPS_PASSWORD"],
    }
    payload.update(overrides)
    (directory / "mcp.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")
    return directory


def mcp_entries(root, **export):
    entry = {"name": "stateful"}
    entry.update(export)
    entries = proxy_mcp.load_mcps(root, [entry])
    assert set(entries) == {"stateful"}, entries
    return entries


def text(result):
    return " ".join(block.get("text", "") for block in result["content"])


def structured(result):
    if result.get("structuredContent") is not None:
        return result["structuredContent"]
    return json.loads(text(result))


def test_an_mcp_session_sees_only_the_callers_own_credentials(
    tmp_path, fixture_server, monkeypatch
):
    monkeypatch.setenv("DEVOPS_PASSWORD", PROCESS_VALUE)
    root = tmp_path / "mcps"
    write_mcp(root, secrets=["DEVOPS_PASSWORD"])
    entries = mcp_entries(root, credential_mode="per_user")
    store = make_store(tmp_path)
    # A key the manifest does not declare must never reach the server process.
    write_user(store, "a@example.com", DEVOPS_PASSWORD="alpha", EXTRA_KEY="nope")
    write_user(store, "b@example.com", DEVOPS_PASSWORD="beta")
    manager = proxy_mcp.McpSessionManager(credentials=store, site="plant-floor")

    async def scenario():
        try:
            manager.set_entries(
                entries,
                {name: await proxy_mcp.build_catalog(entry, credentials=store, site="plant-floor")
                 for name, entry in entries.items()},
            )
            return {
                email: structured(
                    await manager.call("stateful", "env_dump", {}, {"user_email": email}, DEADLINE_MS)
                )
                for email in ("a@example.com", "b@example.com")
            }
        finally:
            await manager.kill_all()

    envs = asyncio.run(scenario())

    assert envs["a@example.com"]["DEVOPS_PASSWORD"] == "alpha"
    assert envs["b@example.com"]["DEVOPS_PASSWORD"] == "beta"
    assert "EXTRA_KEY" not in envs["a@example.com"]
    assert "beta" not in envs["a@example.com"].values()
    # The declaration policy still applies: the tunnel token is never there.
    for env in envs.values():
        assert "TRELLIS_EDGE_TOKEN" not in env


def test_per_user_required_mcp_spawns_nothing_for_an_unmapped_user(tmp_path, fixture_server):
    root = tmp_path / "mcps"
    write_mcp(root, secrets=["DEVOPS_PASSWORD"])
    entries = mcp_entries(root, credential_mode="per_user_required")
    store = make_store(tmp_path)
    write_user(store, "someone@example.com", DEVOPS_PASSWORD=OTHER_VALUE)
    manager = proxy_mcp.McpSessionManager(credentials=store, site="plant-floor")

    async def scenario():
        try:
            manager.set_entries(
                entries,
                {name: await proxy_mcp.build_catalog(entry, credentials=store, site="plant-floor")
                 for name, entry in entries.items()},
            )
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
    # Fail closed means no process: no session dir, no pid file, no tracked session.
    assert not (fixture_server / "mcp-sessions" / "stateful").exists()
    assert manager._sessions == {}


def test_a_credential_change_does_not_touch_a_live_mcp_session(tmp_path, fixture_server):
    root = tmp_path / "mcps"
    write_mcp(root, secrets=["DEVOPS_PASSWORD"])
    entries = mcp_entries(root, credential_mode="per_user_required")
    store = make_store(tmp_path)
    write_user(store, "ops@example.com", DEVOPS_PASSWORD="before")
    manager = proxy_mcp.McpSessionManager(credentials=store, site="plant-floor")

    async def scenario():
        try:
            manager.set_entries(
                entries,
                {name: await proxy_mcp.build_catalog(entry, credentials=store, site="plant-floor")
                 for name, entry in entries.items()},
            )
            identity = {"user_email": "ops@example.com"}
            live = structured(await manager.call("stateful", "env_dump", {}, identity, DEADLINE_MS))
            home = text(await manager.call("stateful", "get_home", {}, identity, DEADLINE_MS))
            # Rotate the password while the session is up.
            write_user(store, "ops@example.com", DEVOPS_PASSWORD="after")
            still_live = structured(
                await manager.call("stateful", "env_dump", {}, identity, DEADLINE_MS)
            )
            same_home = text(await manager.call("stateful", "get_home", {}, identity, DEADLINE_MS))
            # A new session (what a TTL expiry/restart produces) re-reads the file.
            await manager.kill_all()
            fresh = structured(await manager.call("stateful", "env_dump", {}, identity, DEADLINE_MS))
            fresh_home = text(await manager.call("stateful", "get_home", {}, identity, DEADLINE_MS))
            return live, home, still_live, same_home, fresh, fresh_home
        finally:
            await manager.kill_all()

    live, home, still_live, same_home, fresh, fresh_home = asyncio.run(scenario())

    assert live["DEVOPS_PASSWORD"] == "before"
    assert still_live["DEVOPS_PASSWORD"] == "before"
    assert same_home == home
    assert fresh["DEVOPS_PASSWORD"] == "after"
    assert fresh_home == home  # same per-(mcp, user) state dir, new process


def test_a_shared_file_is_used_for_an_mcp_session(tmp_path, fixture_server, monkeypatch):
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
            manager.set_entries(
                entries,
                {name: await proxy_mcp.build_catalog(entry, credentials=store, site="plant-floor")
                 for name, entry in entries.items()},
            )
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
    tmp_path, fixture_server, monkeypatch
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


def test_http_headers_come_from_the_resolved_chain(tmp_path, monkeypatch):

    """A declared credential from a per-user file must reach the endpoint, not the env."""
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
        lambda: (FakeClient, transport_class("stdio"), transport_class("http"), transport_class("sse")),
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
    store = make_store(tmp_path)
    write_user(store, "ops@example.com", DEVOPS_PASSWORD=OTHER_VALUE)
    identity = {"user_email": "ops@example.com", "user": "u1"}

    env = proxy_mcp._server_env(
        entry, tmp_path, identity, passthrough=False, token_env=None,
        credentials=store, site="plant-floor",
    )
    proxy_mcp._transport(entry, tmp_path, env)

    assert recorded["http"]["headers"] == {"DEVOPS_PASSWORD": OTHER_VALUE}
    assert env["TRELLIS_USER_EMAIL"] == "ops@example.com"


# ---------------------------------------------------------------- CLI


@pytest.fixture
def cli(tmp_path, monkeypatch):
    """Run ``trellis-proxy user-secrets`` with stdin and a temp proxy.yaml."""

    def run(argv, stdin=""):
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        return proxy.main(["user-secrets", *argv])

    config_path = write_config_file(tmp_path)
    return run, config_path, make_store(tmp_path)


def test_cli_set_writes_0600_and_merges(cli):
    run, config_path, store = cli

    assert run(["set", "Ops@Example.com", "--config", str(config_path)],
               stdin="DEVOPS_PASSWORD=hunter2\nCORALOGIX_DOMAIN=corp.example\n") is None
    assert run(["set", "ops@example.com", "--config", str(config_path)],
               stdin="DEVOPS_PASSWORD=rotated\n") is None

    path = store.user_file("ops@example.com")
    assert secrets.parse_env_file(path) == {
        "DEVOPS_PASSWORD": "rotated",
        "CORALOGIX_DOMAIN": "corp.example",
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_cli_set_is_idempotent_for_case_variants(cli):
    run, config_path, store = cli

    run(["set", "Ops@Example.com", "--config=" + str(config_path)], stdin="K=v1\n")
    run(["set", "ops@example.com", "--config", str(config_path)], stdin="J=v2\n")

    files = sorted(store.user_secrets_dir.glob("*.env"))
    assert len(files) == 1
    assert secrets.parse_env_file(files[0]) == {"K": "v1", "J": "v2"}


def test_cli_list_prints_key_names_never_values(cli, capsys):
    run, config_path, store = cli
    write_user(store, "ops@example.com", DEVOPS_PASSWORD=SECRET_VALUE, CORALOGIX_DOMAIN="corp")

    run(["list", "--config", str(config_path)])

    printed = capsys.readouterr().out
    # A legacy file has no ``# email:`` header, so the hashed stem is the fallback.
    assert secrets.normalize_email("ops@example.com") in printed
    assert "DEVOPS_PASSWORD" in printed
    assert "CORALOGIX_DOMAIN" in printed
    assert SECRET_VALUE not in printed
    assert "corp" not in printed


def test_cli_set_then_list_shows_the_email_not_the_filename(cli, capsys):
    run, config_path, store = cli

    assert run(
        ["set", "Ops@Example.com", "--config", str(config_path)],
        stdin="DEVOPS_PASSWORD=hunter2\n",
    ) is None
    header = store.user_file("ops@example.com").read_text(encoding="utf-8").splitlines()[0]
    assert header == "# email: Ops@Example.com"

    capsys.readouterr()  # drop the ``set`` receipt, which names the file path
    run(["list", "--config", str(config_path)])

    printed = capsys.readouterr().out
    assert "Ops@Example.com:" in printed
    # Not the normalization stem an operator cannot map back to a person.
    assert secrets.normalize_email("ops@example.com") not in printed
    assert "DEVOPS_PASSWORD" in printed
    assert "hunter2" not in printed


def test_cli_set_refuses_to_overwrite_an_unreadable_file(cli, capsys):
    """An unreadable file is not an empty one: merging from ``{}`` would drop its keys."""
    run, config_path, store = cli
    path = store.user_file("ops@example.com")
    path.parent.mkdir(parents=True, exist_ok=True)
    original = b"\xff\xfeDEVOPS_PASSWORD=unreadable"
    path.write_bytes(original)

    with pytest.raises(SystemExit) as caught:
        run(["set", "ops@example.com", "--config", str(config_path)], stdin="NEW_KEY=v\n")

    assert caught.value.code == 1
    err = capsys.readouterr().err
    assert "cannot read" in err
    assert "refusing to overwrite" in err
    assert str(path) in err
    # Untouched: no rewrite from {}.
    assert path.read_bytes() == original


def test_cli_list_on_a_missing_directory_is_quiet(cli, capsys):
    run, config_path, _store = cli

    assert run(["list", "--config", str(config_path)]) is None
    assert capsys.readouterr().out == ""


def test_cli_delete_removes_the_file_and_reports_an_unknown_email(cli, capsys):
    run, config_path, store = cli
    path = write_user(store, "ops@example.com", DEVOPS_PASSWORD=SECRET_VALUE)

    assert run(["delete", "ops@example.com", "--config", str(config_path)]) is None
    assert not path.exists()

    with pytest.raises(SystemExit) as caught:
        run(["delete", "ops@example.com", "--config", str(config_path)])

    assert caught.value.code == 1
    err = capsys.readouterr().err
    assert "no stored credentials for ops@example.com" in err
    assert SECRET_VALUE not in err


def test_cli_rejects_a_non_email_without_a_traceback(cli, capsys):
    run, config_path, _store = cli

    with pytest.raises(SystemExit) as caught:
        run(["set", "not-an-email", "--config", str(config_path)], stdin="K=v\n")

    assert caught.value.code == 2
    assert "not an email address" in capsys.readouterr().err


def test_cli_rejects_empty_stdin(cli, capsys):
    run, config_path, store = cli

    with pytest.raises(SystemExit) as caught:
        run(["set", "ops@example.com", "--config", str(config_path)], stdin="# nothing useful\n")

    assert caught.value.code == 2
    assert "no KEY=VALUE lines on stdin" in capsys.readouterr().err
    assert not store.user_secrets_dir.exists()


def test_cli_reports_a_missing_config_file(cli, tmp_path, capsys):
    run, _config_path, _store = cli

    with pytest.raises(SystemExit) as caught:
        run(["list", "--config", str(tmp_path / "absent.yaml")])

    assert caught.value.code == 2
    assert "file not found" in capsys.readouterr().err


def test_cli_defaults_match_the_edge_defaults(tmp_path, monkeypatch, capsys):
    """With no --config, the CLI uses the same env override the proxy reads."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TRELLIS_EDGE_USER_SECRETS_DIR", str(tmp_path / "mounted"))
    monkeypatch.setattr(sys, "stdin", io.StringIO("K=v\n"))

    assert proxy.main(["user-secrets", "set", "ops@example.com"]) is None
    assert (tmp_path / "mounted" / f"{secrets.normalize_email('ops@example.com')}.env").is_file()


# ---------------------------------------------------------------- proxy.yaml surface


def test_load_config_reads_the_credential_dirs(tmp_path):
    path = write_config_file(
        tmp_path,
        secrets_dir=str(tmp_path / "svc"),
        user_secrets_dir=str(tmp_path / "users"),
    )

    config = proxy.load_config(path)

    assert config.secrets_dir == tmp_path / "svc"
    assert config.user_secrets_dir == tmp_path / "users"


def test_load_config_defaults_the_credential_dirs(tmp_path):
    path = tmp_path / "proxy.yaml"
    path.write_text(
        "site: plant-floor\nserver_url: ws://relay.local/edge/v1/connect\n", encoding="utf-8"
    )

    config = proxy.load_config(path)

    assert config.secrets_dir == Path("edge-secrets")
    assert config.user_secrets_dir == Path("edge-user-secrets")


def test_the_credential_dirs_can_be_overridden_from_the_environment(tmp_path, monkeypatch):
    path = write_config_file(tmp_path)
    monkeypatch.setenv("TRELLIS_EDGE_SECRETS_DIR", str(tmp_path / "env-svc"))
    monkeypatch.setenv("TRELLIS_EDGE_USER_SECRETS_DIR", str(tmp_path / "env-users"))

    config = proxy.load_config(path)

    assert config.secrets_dir == tmp_path / "env-svc"
    assert config.user_secrets_dir == tmp_path / "env-users"


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

    write_config_file(tmp_path, user_secrets_dir=str(tmp_path / "moved"))
    with caplog.at_level(logging.WARNING):
        session.reload()

    assert "user_secrets_dir changes need a restart" in caplog.text
    assert session.config.user_secrets_dir == tmp_path / "edge-user-secrets"


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
