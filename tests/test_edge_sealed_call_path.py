# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The Phase 4 call path, end to end at the unit boundary.

A browser-sealed envelope travels central -> relay -> edge, is opened with the edge key,
and reaches the container env. The properties pinned here are the ones a regression would
silently break: byte-identical values, all-or-nothing secrets, no per-user variables, no
cross-target replay, and an audit record that knows a blob was present but not what it is.
"""

import asyncio
import base64
import json
import logging

import pytest
from fastapi.testclient import TestClient

from core import edge_crypto, edge_keypair, proxy
from core.models import ToolConfig
from services.edge_relay import app as relay_app
from services.edge_relay import protocol
from services.edge_relay.app import EdgeConn
from services.edge_relay.registry import publish_edge_credentials

SITE = "dc1"
ALICE = "alice@example.com"
TOOL = "node_ssh"
DECLARED = ("NODE_SSH_USER", "NODE_SSH_PASSWORD", "NODE_SSH_KEY")
BROWSER_VALUES = {
    "NODE_SSH_USER": "operator-01",
    "NODE_SSH_PASSWORD": "correct horse ⚡ battery",
    "NODE_SSH_KEY": "",
}
SHARED_SERVICE_ACCOUNT = {
    "NODE_SSH_USER": "svc-shared",
    "NODE_SSH_PASSWORD": "shared-password",
    "NODE_SSH_KEY": "shared-key",
}
DEADLINE_MS = 60_000


# ---------------------------------------------------------------- fixtures / helpers


@pytest.fixture
def edge_key(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
    path = tmp_path / "etc-trellis" / "edge-key"
    key = edge_keypair.generate(path)
    monkeypatch.setenv("EDGE_PRIVATE_KEY_PATH", str(path))
    return key, path


def tool_config(name=TOOL, **kw):
    return ToolConfig(
        name=name, description=name, runtime="python", entrypoint="main.py", **kw
    )


def seal(key, values, *, site=SITE, kind="tool", name=TOOL, identity=ALICE):
    public = key.public_json()
    return edge_crypto.seal(
        public["spki"], values, site=site, kind=kind, name=name,
        identity=identity, key_id=public["key_id"],
    )


def call_frame(*, tool=TOOL, user="u-alice", email=ALICE, sealed=None):
    frame = {
        "t": "call",
        "id": "c1",
        "tool": tool,
        "args": {},
        "deadline_ms": DEADLINE_MS,
        "user": user,
        "user_email": email,
    }
    if sealed is not None:
        frame["sealed"] = sealed
    return frame


def edge_proxy_config(tmp_path, *, site=SITE):
    return proxy.ProxyConfig(
        site=site,
        server_url="ws://relay.local/edge/v1/connect",
        secrets_dir=tmp_path / "edge-secrets",
    )


def capture_env(monkeypatch):
    seen = {}

    async def fake_execute(config, tool_dir, arguments, *, env, on_health=None, **kwargs):
        seen.update(env)
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    return seen


def never_runs(monkeypatch):
    def _fail(*args, **kwargs):
        raise AssertionError("the tool must not run when the credential is refused")

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", _fail)


# ---------------------------------------------------------------- tool round trip


def test_handle_call_round_trip_is_byte_identical_in_the_container_env(
    edge_key, tmp_path, monkeypatch
):
    key, _path = edge_key
    seen = capture_env(monkeypatch)
    config = tool_config(secrets=list(DECLARED))

    result = asyncio.run(
        proxy.handle_call(
            {TOOL: (config, tmp_path)},
            call_frame(sealed=seal(key, BROWSER_VALUES)),
            proxy_config=edge_proxy_config(tmp_path),
            edge_key=key,
        )
    )

    assert result["ok"] is True
    # A blank field is unset (consistent with files/env); non-blank values are
    # byte-identical, and a blank key never falls back to the shared value.
    assert {name: seen[name] for name in DECLARED if BROWSER_VALUES[name]} == {
        name: value for name, value in BROWSER_VALUES.items() if value
    }
    assert "NODE_SSH_KEY" not in seen
    assert seen["NODE_SSH_PASSWORD"] == "correct horse ⚡ battery"
    assert seen["TRELLIS_USER_EMAIL"] == ALICE


def test_a_sealed_credential_reaches_the_tool_through_the_stdin_preamble(
    edge_key, tmp_path, monkeypatch
):
    """`docker inspect` never shows a sealed value; the process still receives it.

    The edge hands the opened mapping to ``execute_tool`` as the call's environment
    (above); what reaches the container is then derived by the shared spec builder.
    Pinned here: the credential set is absent from the create payload and present,
    byte-identical, in the one stdin preamble line -- the same path a central tool
    takes, because both call the same builder.
    """
    from core.execution import docker_backend, env as env_module, spec as spec_module

    key, _path = edge_key
    seen = capture_env(monkeypatch)
    config = tool_config(secrets=list(DECLARED))
    suite = tmp_path / "workspace" / "tools" / TOOL
    suite.mkdir(parents=True)
    (suite / "main.py").write_text("print('{}')\n", encoding="utf-8")
    monkeypatch.setenv("TRELLIS_UID", "1000")
    monkeypatch.setenv("TRELLIS_GID", "1000")
    monkeypatch.setenv("RUNNER_IMAGE", "trellis-agent-platform:test")

    asyncio.run(
        proxy.handle_call(
            {TOOL: (config, suite)},
            call_frame(sealed=seal(key, BROWSER_VALUES)),
            proxy_config=edge_proxy_config(tmp_path),
            edge_key=key,
        )
    )

    container_spec = spec_module.build_spec(
        config,
        kind="tool",
        suite_rel=f"tools/{TOOL}",
        target=TOOL,
        # What actually crosses the socket: declared keys only (core.tool_runtime).
        env={k: v for k, v in seen.items() if k in spec_module.declared_env_keys(config)},
        host_workspace=str(tmp_path / "workspace"),
    )
    payload = docker_backend._create_payload(container_spec)
    body = json.dumps(payload)

    for name in DECLARED:
        value = BROWSER_VALUES[name]
        assert name not in container_spec.env
        if not value:
            continue
        assert value not in body, name
        assert container_spec.preamble_env[name] == value
    # ... and the preamble is exactly ONE line, so tool/MCP framing survives it.
    preamble = env_module.preamble_line(container_spec.preamble_env)
    assert preamble.count(b"\n") == 1 and preamble.endswith(b"\n")
    assert json.loads(preamble)["env"]["NODE_SSH_PASSWORD"] == (
        BROWSER_VALUES["NODE_SSH_PASSWORD"]
    )
    # Identity is a documented contract variable, not a secret: it may stay in Env.
    assert "TRELLIS_USER_EMAIL" in body


@pytest.mark.parametrize(
    ("overrides", "sealed_for"),
    [
        ({"tool": "node_file_transfer"}, {"name": TOOL}),
        ({"email": "bob@example.com"}, {}),
        ({}, {"site": "dc2"}),
        ({}, {"kind": "mcp"}),
    ],
    ids=["another-target", "another-user", "another-site", "another-kind"],
)
def test_a_blob_replayed_for_another_target_user_or_site_is_rejected(
    edge_key, tmp_path, monkeypatch, overrides, sealed_for
):
    key, _path = edge_key
    never_runs(monkeypatch)
    blob = seal(key, BROWSER_VALUES, **sealed_for)
    config_map = {
        TOOL: (tool_config(secrets=list(DECLARED)), tmp_path),
        "node_file_transfer": (
            tool_config("node_file_transfer", secrets=list(DECLARED)),
            tmp_path,
        ),
    }

    result = asyncio.run(
        proxy.handle_call(
            config_map,
            call_frame(sealed=blob, **overrides),
            proxy_config=edge_proxy_config(tmp_path, site=overrides.get("site", SITE)),
            edge_key=key,
        )
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "credential_rejected"
    # The message names the binding, never a value.
    for value in BROWSER_VALUES.values():
        if value:
            assert value not in result["error"]["message"]


def test_a_partial_sealed_set_is_all_or_nothing(edge_key, tmp_path, monkeypatch):
    key, _path = edge_key
    seen = capture_env(monkeypatch)
    shared = tmp_path / "edge-secrets"
    shared.mkdir()
    (shared / f"{TOOL}.env").write_text(
        "".join(f"{name}={value}\n" for name, value in SHARED_SERVICE_ACCOUNT.items()),
        encoding="utf-8",
    )
    partial = {"NODE_SSH_USER": "operator-01", "NODE_SSH_PASSWORD": "only-two"}

    result = asyncio.run(
        proxy.handle_call(
            {TOOL: (tool_config(secrets=list(DECLARED)), tmp_path)},
            call_frame(sealed=seal(key, partial)),
            proxy_config=edge_proxy_config(tmp_path),
            edge_key=key,
        )
    )

    assert result["ok"] is True
    assert seen["NODE_SSH_USER"] == "operator-01"
    assert seen["NODE_SSH_PASSWORD"] == "only-two"
    # The gap is not filled from the shared account.
    assert "NODE_SSH_KEY" not in seen
    assert not set(SHARED_SERVICE_ACCOUNT.values()) & set(seen.values())


def test_a_sealed_variable_is_ignored_at_the_edge(edge_key, tmp_path, monkeypatch):
    key, _path = edge_key
    monkeypatch.setenv("DEVOPS_URL", "https://edge-configured.internal")
    seen = capture_env(monkeypatch)
    config = tool_config(secrets=["DEVOPS_PASSWORD"], variables=["DEVOPS_URL"])
    blob = seal(key, {"DEVOPS_URL": "https://attacker.invalid", "DEVOPS_PASSWORD": "pw"})

    result = asyncio.run(
        proxy.handle_call(
            {TOOL: (config, tmp_path)},
            call_frame(sealed=blob),
            proxy_config=edge_proxy_config(tmp_path),
            edge_key=key,
        )
    )

    assert result["ok"] is True
    assert seen["DEVOPS_URL"] == "https://edge-configured.internal"
    assert seen["DEVOPS_PASSWORD"] == "pw"


def test_rotation_overlap_opens_the_old_key_and_drop_old_ends_it(
    edge_key, tmp_path, monkeypatch
):
    key, path = edge_key
    seen = capture_env(monkeypatch)
    blob = seal(key, BROWSER_VALUES)
    current = edge_keypair.rotate(path)
    previous = edge_keypair.load_old(path)
    config_map = {TOOL: (tool_config(secrets=list(DECLARED)), tmp_path)}

    during = asyncio.run(
        proxy.handle_call(
            config_map,
            call_frame(sealed=blob),
            proxy_config=edge_proxy_config(tmp_path),
            edge_key=current,
            prev_edge_key=previous,
        )
    )
    assert during["ok"] is True
    assert seen["NODE_SSH_USER"] == BROWSER_VALUES["NODE_SSH_USER"]

    assert edge_keypair.drop_old(path) is True
    after = asyncio.run(
        proxy.handle_call(
            config_map,
            call_frame(sealed=blob),
            proxy_config=edge_proxy_config(tmp_path),
            edge_key=current,
            prev_edge_key=None,
        )
    )
    assert after["ok"] is False
    assert after["error"]["code"] == "credential_rejected"


def test_handle_mcp_call_hands_the_opened_mapping_to_the_manager(edge_key):
    key, _path = edge_key
    seen = {}

    class Manager:
        site = SITE

        async def call(
            self, mcp, tool, args, identity, deadline_ms, *, sealed=None
        ):
            seen["sealed"] = sealed
            return {"content": [], "isError": False}

    blob = seal(key, {"DEVOPS_PASSWORD": "pw"}, kind="mcp", name="devops-cli")
    frame = {
        "t": "call",
        "id": "m1",
        "kind": "mcp",
        "mcp": "devops-cli",
        "tool": "list_actions",
        "args": {},
        "user_email": ALICE,
        "sealed": blob,
    }

    result = asyncio.run(proxy.handle_mcp_call(Manager(), frame, edge_key=key))

    assert result["ok"] is True
    assert seen["sealed"] == {"DEVOPS_PASSWORD": "pw"}


# ---------------------------------------------------------------- relay forwarding


def _fake_blob(ciphertext="AAAA"):
    return {
        "v": 1,
        "alg": edge_crypto.SEAL_ALG,
        "key_fp": "SHA256:" + base64.b64encode(b"x" * 32).decode("ascii"),
        "key_id": "abcdefghijklmnop",
        "aad": "v1|dc1|tool|node_ssh|alice@example.com|abcdefghijklmnop",
        "wrapped_key": "AAAA",
        "iv": "AAAA",
        "ciphertext": ciphertext,
        "keys": ["NODE_SSH_USER"],
    }


class _Ws:
    def __init__(self):
        self.sent = []

    async def send_text(self, data):
        self.sent.append(protocol.decode(data, protocol.RELAY_FRAMES))

    async def close(self, code=1000, reason=None):
        self.sent.append({"closed": code})


def _install_conn():
    ws = _Ws()
    conn = EdgeConn(
        ws,
        SITE,
        {"node_ssh": protocol.EdgeTool(name="node_ssh", inputs={})},
        caps=["tools"],
    )
    relay_app.relay.sites[SITE] = conn
    return conn, ws


@pytest.fixture(autouse=True)
def _clean_relay():
    relay_app.relay.sites.clear()
    yield
    relay_app.relay.sites.clear()


@pytest.fixture(autouse=True)
def _relay_rollout_mode(monkeypatch):
    """These cases are about the sealed blob, not who may call.

    The token rollout window (``log``) keeps the relay's authorization gate out of the
    way -- it is covered in tests/test_edge_relay.py and test_enforcement_matrix.py --
    and an empty policy keeps the evaluator off etcd.
    """
    from core import tool_access

    class _NoPolicy:
        def put(self, key, value):
            raise AssertionError(f"no write expected: {key}")

        def get(self, key, **_kwargs):
            return None, None

    monkeypatch.setenv("ENFORCE_AGENT_TOKENS", "log")
    monkeypatch.setattr(tool_access, "_client", lambda: _NoPolicy())
    tool_access.reset_snapshot()


def test_relay_forwards_sealed_verbatim_and_audits_only_presence(monkeypatch):
    conn, ws = _install_conn()
    blob = _fake_blob()
    seen = {}

    async def fake_request(tool, args, deadline_ms, user=None, user_email=None, **kwargs):
        seen["sealed"] = kwargs.get("sealed")
        return {"id": "x", "ok": True, "result": {"ok": True}}

    conn.request = fake_request
    audited = []
    monkeypatch.setattr(relay_app.audit, "record", lambda *a, **kw: audited.append(kw))
    client = TestClient(relay_app.app)

    response = client.post(
        f"/v1/sites/{SITE}/call",
        json={"tool": "node_ssh", "args": {}, "sealed": blob},
    )

    assert response.status_code == 200
    assert seen["sealed"] == blob
    assert audited and audited[-1]["has_sealed"] is True
    assert "sealed" not in audited[-1]
    assert blob["ciphertext"] not in json.dumps(audited)


def test_relay_rejects_a_malformed_or_oversized_sealed_blob(monkeypatch):
    conn, ws = _install_conn()
    client = TestClient(relay_app.app)

    for blob in ({"v": 1}, _fake_blob(ciphertext="A" * (edge_crypto.MAX_SEALED_BYTES + 64))):
        response = client.post(
            f"/v1/sites/{SITE}/call", json={"tool": "node_ssh", "args": {}, "sealed": blob}
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_arguments"

    assert ws.sent == []


def test_the_relay_never_logs_the_sealed_blob(monkeypatch, caplog):
    conn, _ws = _install_conn()
    blob = _fake_blob()

    async def fake_request(tool, args, deadline_ms, user=None, user_email=None, **kwargs):
        return {"id": "x", "ok": True, "result": {"ok": True}}

    conn.request = fake_request
    client = TestClient(relay_app.app)

    with caplog.at_level(logging.DEBUG):
        response = client.post(
            f"/v1/sites/{SITE}/call",
            json={"tool": "node_ssh", "args": {}, "sealed": blob},
        )

    assert response.status_code == 200
    assert blob["ciphertext"] not in caplog.text
    assert blob["wrapped_key"] not in caplog.text
    assert blob["aad"] not in caplog.text


def test_the_aad_identity_is_identical_when_it_comes_from_the_claims(
    edge_key, tmp_path, monkeypatch
):
    """Phase 2's blocking property: claims-derived identity must open the same blob.

    The browser seals to the identity central computes for the *user*; the relay now
    builds the frame identity from the token's ``u``/``e`` claims instead of a request
    body. The AAD input has to stay byte-identical (normalization included) or every
    existing sealed set would stop opening.
    """
    from types import SimpleNamespace

    from core.edge_secrets_central import sealed_identity

    key, _path = edge_key
    seen = capture_env(monkeypatch)
    config = tool_config(secrets=list(DECLARED))

    # A claims object as `core.agent_token.verify` surfaces it -- the email spelled
    # with capitals, exactly what an OIDC claim can carry.
    claims = SimpleNamespace(user_id="u-alice", user_email="Alice@Example.COM")
    user, email = relay_app._claims_identity(claims)
    assert (user, email) == ("u-alice", "Alice@Example.COM")

    # Central sealed it under the normalized address; the edge must derive the same.
    assert sealed_identity(user, email) == ALICE

    blob = seal(key, BROWSER_VALUES)  # identity=ALICE, i.e. sealed_identity(...)
    result = asyncio.run(
        proxy.handle_call(
            {TOOL: (config, tmp_path)},
            call_frame(sealed=blob, user=user, email=email),
            proxy_config=edge_proxy_config(tmp_path),
            edge_key=key,
        )
    )

    assert result["ok"] is True
    assert seen["NODE_SSH_PASSWORD"] == BROWSER_VALUES["NODE_SSH_PASSWORD"]
    # The tool sees the frame identity unchanged (not the normalized AAD form).
    assert seen["TRELLIS_USER_EMAIL"] == "Alice@Example.COM"
    assert seen["TRELLIS_USER_ID"] == "u-alice"


def test_claims_without_an_email_never_open_a_sealed_set(edge_key, tmp_path, monkeypatch):
    """No ``e`` claim: ``identity_incomplete`` at central, and no AAD match here."""
    from types import SimpleNamespace

    key, _path = edge_key
    never_runs(monkeypatch)
    config = tool_config(secrets=list(DECLARED))
    user, email = relay_app._claims_identity(SimpleNamespace(user_id="u-alice", user_email=None))

    assert (user, email) == ("u-alice", None)
    result = asyncio.run(
        proxy.handle_call(
            {TOOL: (config, tmp_path)},
            call_frame(sealed=seal(key, BROWSER_VALUES), user=user, email=email),
            proxy_config=edge_proxy_config(tmp_path),
            edge_key=key,
        )
    )

    assert result["ok"] is False
    assert result["error"]["code"] == edge_crypto.CREDENTIAL_REJECTED


# ---------------------------------------------------------------- hello / site record


def _mcp_catalog(name="devops-cli"):
    return protocol.validate_mcps(
        [
            {
                "name": name,
                "transport": "stdio",
                "tools": [{"name": "list_actions", "inputSchema": {"type": "object"}}],
            }
        ]
    )[0]


def test_hello_publishes_the_key_and_declared_credential_names(edge_key, tmp_path):
    key, _path = edge_key
    tool = tool_config(
        secrets=["DEVOPS_PASSWORD"],
        optional_secrets=["DEVOPS_TOKEN"],
        variables=["DEVOPS_URL"],
        secret_groups=[
            {"options": [{"fields": [{"key": "PROD_SSH"}]}]},
        ],
    )

    class Entry:
        config = type("Cfg", (), {
            "secrets": ["MCP_PASSWORD"],
            "optional_secrets": [],
            "variables": ["MCP_URL"],
            "secret_groups": [],
        })()

    frame = proxy.hello_frame(
        {TOOL: (tool, tmp_path)},
        {"devops-cli": _mcp_catalog()},
        mcp_entries={"devops-cli": Entry()},
        edge_key=key,
    )

    assert frame["edge_pubkey"] == key.spki_b64
    assert frame["edge_key_fp"] == key.fingerprint
    assert frame["prev_edge_key_fp"] is None
    assert frame["credential_keys"][TOOL] == {
        "secret_keys": ["DEVOPS_PASSWORD", "DEVOPS_TOKEN", "PROD_SSH"],
        "variable_keys": ["DEVOPS_URL"],
    }
    assert frame["credential_keys"]["devops-cli"] == {
        "secret_keys": ["MCP_PASSWORD"],
        "variable_keys": ["MCP_URL"],
    }

    validated = protocol.validate_hello(frame)
    assert validated.credentials.edge_pubkey == key.spki_b64
    assert validated.credentials.edge_key_fp == key.fingerprint
    assert validated.credentials.credential_keys == frame["credential_keys"]
    assert validated.credentials.key_id == key.key_id


def test_a_mismatched_hello_fingerprint_is_refused(edge_key):
    key, _path = edge_key
    frame = proxy.hello_frame({}, edge_key=key)
    frame["edge_key_fp"] = "SHA256:" + base64.b64encode(b"y" * 32).decode("ascii")

    with pytest.raises(protocol.ProtocolError, match="does not match"):
        protocol.validate_hello(frame)


class _Registry:
    def __init__(self, record=None):
        self.record = record
        self.saved = None

    def get_edge_config(self, site):
        return dict(self.record) if self.record is not None else None

    def save_edge_config(self, site, config):
        self.saved = dict(config)


def test_the_relay_writes_the_key_and_credential_names_to_the_site_record(edge_key, tmp_path):
    key, path = edge_key
    tool = tool_config(secrets=["DEVOPS_PASSWORD"], variables=["DEVOPS_URL"])
    frame = proxy.hello_frame({TOOL: (tool, tmp_path)}, edge_key=key)
    credentials = protocol.validate_hello(frame).credentials
    registry = _Registry({"name": SITE, "enabled": True, "exports": [], "admin_note": "keep"})

    assert publish_edge_credentials(registry, SITE, credentials) is True
    record = registry.saved
    assert record["edge_pubkey"] == key.spki_b64
    assert record["edge_key_fp"] == key.fingerprint
    assert record["edge_key_id"] == key.key_id
    assert record.get("prev_edge_key_fp") is None
    assert record["edge_key_fps"] == []
    assert record["credential_keys"][TOOL] == {
        "secret_keys": ["DEVOPS_PASSWORD"],
        "variable_keys": ["DEVOPS_URL"],
    }
    # The admin-editable part of the record survives the merge.
    assert record["admin_note"] == "keep"

    # An unchanged hello is a no-op (no etcd write on every reconnect).
    again = _Registry(record)
    assert publish_edge_credentials(again, SITE, credentials) is False

    # A rotation publishes the new key plus the overlap fingerprint.
    rotated = edge_keypair.rotate(path)
    previous = edge_keypair.load_old(path)
    rotated_frame = proxy.hello_frame(
        {TOOL: (tool, tmp_path)}, edge_key=rotated, prev_edge_key=previous
    )
    rotated_credentials = protocol.validate_hello(rotated_frame).credentials
    rotation = _Registry(record)
    assert publish_edge_credentials(rotation, SITE, rotated_credentials) is True
    assert rotation.saved["edge_key_fp"] == rotated.fingerprint
    assert rotation.saved["prev_edge_key_fp"] == key.fingerprint
    assert rotation.saved["edge_key_fps"] == [key.fingerprint]

    # Dropped old key: the overlap clears, so central stops accepting blobs for it.
    dropped_frame = proxy.hello_frame({TOOL: (tool, tmp_path)}, edge_key=rotated)
    dropped_credentials = protocol.validate_hello(dropped_frame).credentials
    dropped = _Registry(rotation.saved)
    assert publish_edge_credentials(dropped, SITE, dropped_credentials) is True
    assert dropped.saved["edge_key_fps"] == []
    assert "prev_edge_key_fp" not in dropped.saved
    # History keeps the retired key for display.
    assert key.fingerprint in {entry["fp"] for entry in dropped.saved["edge_key_history"]}
