# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""CONNECT allowlist proxy behaviour (hermetic: loopback only)."""

import dataclasses
import json
import socket
import socketserver
import threading
import time

import pytest

from scripts.egress_proxy import (
    EgressProxyServer,
    ProxyConfig,
    _blocked_address,
    config_from_env,
    host_allowed,
    load_allowlist,
)


class _Echo:
    """Minimal byte-echo upstream on 127.0.0.1."""

    def __init__(self):
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen()
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                connection, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._echo, args=(connection,), daemon=True).start()

    @staticmethod
    def _echo(connection):
        with connection:
            try:
                while True:
                    data = connection.recv(4096)
                    if not data:
                        return
                    connection.sendall(data)
            except OSError:
                return

    def close(self):
        self._listener.close()


@pytest.fixture
def echo():
    server = _Echo()
    yield server
    server.close()


def _start(**overrides):
    config = ProxyConfig(
        allowlist=frozenset({"allowed.test"}),
        ports=frozenset({443}),
        resolver=lambda host, port: ["127.0.0.1"],
        allow_private_destinations=True,
        idle_timeout=5.0,
        max_tunnel_seconds=30.0,
        connect_timeout=2.0,
        log=lambda message: None,
    )
    config = dataclasses.replace(config, **overrides)
    server = EgressProxyServer(("127.0.0.1", 0), config)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    return server, server.server_address[1]


def _open(port, request):
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.sendall(request)
    return client


def _status(client):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = client.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.split(b"\r\n", 1)[0].decode("latin-1")


def _connect(proxy_port, host, port):
    request = (
        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    ).encode()
    return _open(proxy_port, request)


@pytest.fixture
def proxy(echo):
    servers = []

    def start(**overrides):
        overrides.setdefault("ports", frozenset({echo.port}))
        server, port = _start(**overrides)
        servers.append(server)
        return port

    yield start

    for server in servers:
        server.shutdown()
        server.server_close()


def test_allowed_connect_returns_200_and_tunnels_bytes(proxy, echo):
    port = proxy()
    client = _connect(port, "allowed.test", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 200 Connection Established"
        client.sendall(b"hello tunnel")
        assert client.recv(1024) == b"hello tunnel"
    finally:
        client.close()


def test_subdomain_and_trailing_dot_and_case_are_normalized(proxy, echo):
    port = proxy(allowlist=frozenset({"example.com"}))
    for host in ("api.example.com", "API.EXAMPLE.COM.", "example.com"):
        client = _connect(port, host, echo.port)
        try:
            assert _status(client) == "HTTP/1.1 200 Connection Established", host
        finally:
            client.close()


def test_lookalike_suffix_is_not_allowed(proxy, echo):
    port = proxy(allowlist=frozenset({"example.com"}))
    client = _connect(port, "notexample.com", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 403 Forbidden"
    finally:
        client.close()


def test_unknown_host_is_denied(proxy, echo):
    port = proxy()
    client = _connect(port, "denied.test", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 403 Forbidden"
    finally:
        client.close()


def test_empty_allowlist_denies_everything(proxy, echo):
    port = proxy(allowlist=frozenset())
    client = _connect(port, "allowed.test", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 403 Forbidden"
    finally:
        client.close()


def test_ip_literal_is_rejected_before_resolution(proxy, echo):
    calls = []

    def resolver(host, port):
        calls.append(host)
        return ["127.0.0.1"]

    port = proxy(resolver=resolver, allowlist=frozenset({"127.0.0.1"}))
    client = _connect(port, "127.0.0.1", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 403 Forbidden"
    finally:
        client.close()
    assert calls == []


def test_ipv6_literal_is_rejected(proxy, echo):
    port = proxy(allowlist=frozenset({"::1"}))
    client = _connect(port, "[::1]", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 403 Forbidden"
    finally:
        client.close()


def test_non_connect_method_is_405(proxy, echo):
    port = proxy()
    client = _open(
        port, b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n"
    )
    try:
        assert _status(client) == "HTTP/1.1 405 Method Not Allowed"
    finally:
        client.close()


def test_port_outside_egress_ports_is_403(proxy, echo):
    port = proxy(ports=frozenset({443}))
    client = _connect(port, "allowed.test", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 403 Forbidden"
    finally:
        client.close()


def test_private_destination_is_denied_by_default(proxy, echo):
    port = proxy(allow_private_destinations=False)
    client = _connect(port, "allowed.test", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 403 Forbidden"
    finally:
        client.close()


def test_private_destination_allowed_when_opted_in(proxy, echo):
    port = proxy(allow_private_destinations=True)
    client = _connect(port, "allowed.test", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 200 Connection Established"
    finally:
        client.close()


def test_any_private_address_in_the_answer_denies(proxy, echo):
    port = proxy(
        allow_private_destinations=False,
        resolver=lambda host, port: ["93.184.216.34", "10.0.0.5"],
    )
    client = _connect(port, "allowed.test", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 403 Forbidden"
    finally:
        client.close()


def test_resolution_failure_is_denied(proxy, echo):
    def resolver(host, port):
        raise socket.gaierror(socket.EAI_NONAME, "name not known")

    port = proxy(resolver=resolver)
    client = _connect(port, "allowed.test", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 403 Forbidden"
    finally:
        client.close()


def test_upstream_connect_failure_is_502(proxy, echo):
    # Port 1 is closed on the loopback, so the resolved connect fails.
    port = proxy(ports=frozenset({1}))
    client = _connect(port, "allowed.test", 1)
    try:
        assert _status(client) == "HTTP/1.1 502 Bad Gateway"
    finally:
        client.close()


def test_malformed_request_is_400(proxy):
    port = proxy()
    client = _open(port, b"CONNECT allowed.test\r\n\r\n")
    try:
        assert _status(client) == "HTTP/1.1 400 Bad Request"
    finally:
        client.close()


def test_oversized_request_head_is_413(proxy):
    port = proxy()
    client = _open(port, b"CONNECT " + b"a" * 9000)
    try:
        assert _status(client) == "HTTP/1.1 413 Payload Too Large"
    finally:
        client.close()


def test_connection_cap_replies_503(proxy, echo):
    port = proxy(max_connections=1)
    first = _connect(port, "allowed.test", echo.port)
    try:
        assert _status(first) == "HTTP/1.1 200 Connection Established"
        second = _connect(port, "allowed.test", echo.port)
        try:
            assert _status(second) == "HTTP/1.1 503 Service Unavailable"
        finally:
            second.close()
    finally:
        first.close()


def test_host_allowed_matches_suffixes_not_substrings():
    allowlist = frozenset({"example.com"})
    assert host_allowed("example.com", allowlist)
    assert host_allowed("a.b.example.com", allowlist)
    assert not host_allowed("notexample.com", allowlist)
    assert not host_allowed("example.com.evil.test", allowlist)


# -- destination guard -------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "100.64.0.1",      # RFC 6598 CGNAT: is_private is False on Python 3.12
        "100.127.255.254",  # top of 100.64.0.0/10
        "10.0.0.5",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.168.1.1",
        "0.0.0.0",
        "240.0.0.1",
        "192.0.2.1",       # TEST-NET-1
        "::1",
        "fd00::1",
        "fe80::1",
        "2001:db8::1",
        "not-an-address",
    ],
)
def test_blocked_address_refuses_anything_not_globally_routable(address):
    assert _blocked_address(address) is True


@pytest.mark.parametrize(
    "address", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"]
)
def test_blocked_address_allows_public_unicast(address):
    assert _blocked_address(address) is False


def test_cgnat_resolution_is_denied_by_default(proxy, echo):
    """RFC 6598 sits outside is_private, so it needs its own regression test."""
    port = proxy(
        allow_private_destinations=False, resolver=lambda host, port: ["100.64.0.1"]
    )
    client = _connect(port, "allowed.test", echo.port)
    try:
        assert _status(client) == "HTTP/1.1 403 Forbidden"
    finally:
        client.close()


# -- allowlist parsing -------------------------------------------------


def test_load_allowlist_skips_invalid_entries_and_logs_each(tmp_path, capsys):
    path = tmp_path / "allowlist"
    path.write_text(
        "\n".join(
            [
                "com",                 # bare TLD: would allow every .com
                "*.com",               # same after wildcard stripping
                ".example.com",        # leading dot: never matches a host
                "Example.COM",         # valid, case-insensitive
                "*.ok.test",           # valid wildcard form
                "https://bad.test",    # scheme
                "10.0.0.1",            # IP literal
                "localhost",           # single label
                "-dash.test",          # illegal label
                "  # comment only  ",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert load_allowlist(path) == frozenset({"example.com", "ok.test"})

    out = capsys.readouterr().out
    assert out.count("event=allowlist-invalid-entry") == 7
    assert "entry=com" in out
    assert "entry=localhost" in out


def test_config_from_env_with_only_invalid_entries_is_empty_not_an_error(
    tmp_path, capsys
):
    path = tmp_path / "allowlist"
    path.write_text("com\n.example.com\n", encoding="utf-8")

    config = config_from_env(
        {
            "EGRESS_ALLOWLIST_FILE": str(path),
            "EGRESS_PORTS": "443",
            "EGRESS_MAX_CONNECTIONS": "8",
        }
    )

    assert config.allowlist == frozenset()
    assert "event=allowlist-invalid-entry" in capsys.readouterr().out


# -- connection admission ----------------------------------------------


def test_rejected_connection_gets_503_without_spawning_a_thread(monkeypatch):
    logs = []
    server = EgressProxyServer(
        ("127.0.0.1", 0), ProxyConfig(max_connections=1, log=logs.append)
    )
    created = []
    real_thread = threading.Thread

    class CountingThread(real_thread):
        def __init__(self, *args, **kwargs):
            created.append(args)
            super().__init__(*args, **kwargs)

    try:
        # Simulate one in-flight tunnel holding the only slot.
        assert server.acquire_slot()
        monkeypatch.setattr(socketserver.threading, "Thread", CountingThread)

        peer, request = socket.socketpair()
        try:
            server.process_request(request, ("127.0.0.1", 4242))
            assert created == []
            assert peer.recv(4096).startswith(b"HTTP/1.1 503 Service Unavailable")
        finally:
            peer.close()

        # The reject path never took a slot, so it must not have released one:
        # the in-flight tunnel's slot is still the only one that exists.
        assert server._slots.acquire(blocking=False) is False
        server.release_slot()
        assert server._slots.acquire(blocking=False) is True
        server.release_slot()
    finally:
        server.server_close()

    assert logs and "reason=too-many-connections" in logs[-1]


def test_slot_is_released_after_a_rejected_connection(proxy, echo):
    port = proxy(max_connections=1)
    first = _connect(port, "allowed.test", echo.port)
    try:
        assert _status(first) == "HTTP/1.1 200 Connection Established"
        for _ in range(3):
            rejected = _connect(port, "allowed.test", echo.port)
            try:
                assert _status(rejected) == "HTTP/1.1 503 Service Unavailable"
            finally:
                rejected.close()
    finally:
        first.close()

    # The cap is the only thing refusing traffic: once the tunnel closes, the
    # slot is free again and a new request is admitted.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        client = _connect(port, "allowed.test", echo.port)
        try:
            if _status(client) == "HTTP/1.1 200 Connection Established":
                return
        finally:
            client.close()
        time.sleep(0.02)
    pytest.fail("the slot was never released after the tunnel closed")


# -- request-head deadline ---------------------------------------------


def test_silent_client_gets_408_at_the_head_deadline(proxy):
    port = proxy(idle_timeout=0.3)
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        started = time.monotonic()
        assert _status(client) == "HTTP/1.1 408 Request Timeout"
        assert time.monotonic() - started < 3
    finally:
        client.close()


def test_dribbling_client_cannot_pin_a_slot(proxy):
    """The deadline is absolute; per-recv timeouts alone would never fire."""
    port = proxy(idle_timeout=0.3)
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.settimeout(0.05)
    buffer = b""
    try:
        client.sendall(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test\r\n")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and b"\r\n\r\n" not in buffer:
            try:
                # One byte per idle-timeout window: a per-recv timer resets
                # forever, an absolute deadline does not.
                client.sendall(b"X")
            except OSError:
                pass  # the proxy already answered 408 and closed
            try:
                buffer += client.recv(1024)
            except TimeoutError:
                pass
            time.sleep(0.1)
    finally:
        client.close()
    assert buffer.split(b"\r\n", 1)[0] == b"HTTP/1.1 408 Request Timeout"


# -- sandbox_smoke helpers (imported lazily: they pull in core.sandbox) --


def _smoke():
    from scripts import sandbox_smoke

    return sandbox_smoke


def _sandbox_result(returncode=0, stdout="", stderr="", argv=None):
    return {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "argv": argv or [],
    }


def _egress_info(**overrides):
    info = {
        "proxy_env": "HTTP_PROXY",
        "proxy": "http://egress-proxy:3128",
        "direct": "unresolved:gaierror",
        "allowed": "HTTP/1.1 200 Connection Established",
        "denied": "HTTP/1.1 403 Forbidden",
        "literal_target": "172.18.0.9",
        "literal_source": "env",
        "literal": "HTTP/1.1 403 Forbidden",
        "no_proxy": "etcd,redis,host,hub,localhost",
    }
    info.update(overrides)
    return info


def _run_check_egress(monkeypatch, info):
    smoke = _smoke()
    networks = []

    def fake(cmd, backend, timeout, network=None):
        networks.append(network)
        return _sandbox_result(stdout=json.dumps(info))

    monkeypatch.setattr(smoke, "run_in_sandbox", fake)
    monkeypatch.setenv("HTTP_PROXY", "http://egress-proxy:3128")
    report, errors = smoke.check_egress(smoke.sandbox.Backend.BWRAP, 30)
    return report, errors, networks


def test_check_egress_probes_with_network_allow(monkeypatch):
    """SANDBOX_NET_DEFAULT=none must not turn the egress probe into a DNS error."""
    report, errors, networks = _run_check_egress(monkeypatch, _egress_info())
    assert errors == []
    assert networks == ["allow"]
    assert report["direct"] == "unresolved:gaierror"
    assert report["literal_source"] == "env"


def test_check_egress_reports_a_direct_route_as_such(monkeypatch):
    _, errors, _ = _run_check_egress(monkeypatch, _egress_info(direct="connected"))
    assert len(errors) == 1
    assert "route outside toolnet" in errors[0]


def test_check_egress_reports_an_unclassified_direct_verdict(monkeypatch):
    _, errors, _ = _run_check_egress(monkeypatch, _egress_info(direct="timeout"))
    assert errors
    assert "could not resolve or connect" in errors[0]
    assert "'timeout'" in errors[0]


def test_check_egress_still_requires_the_literal_to_be_refused(monkeypatch):
    _, errors, _ = _run_check_egress(
        monkeypatch, _egress_info(literal="HTTP/1.1 200 Connection Established")
    )
    assert any("IP literal" in error for error in errors)


def _run_check_net(monkeypatch, backend_name, *, udp_refused_under_none):
    smoke = _smoke()
    backend = smoke.sandbox.Backend(backend_name)
    flag = smoke._net_flag(backend)
    seen = []

    def fake(cmd, backend, timeout, network=None):
        udp = "SOCK_DGRAM" in " ".join(cmd)
        seen.append(("udp" if udp else "tcp", network))
        if udp:
            if network == "none" and udp_refused_under_none:
                return _sandbox_result(7, "denied:PermissionError")
            return _sandbox_result(0, "allowed")
        if network == "none":
            return _sandbox_result(1, "", "Connection refused", argv=[flag])
        return _sandbox_result(0)

    monkeypatch.setattr(smoke, "run_in_sandbox", fake)
    report, errors = smoke.check_net(backend, 30)
    return report, errors, seen


def test_check_net_udp_leg_is_denied_on_landlock(monkeypatch):
    report, errors, seen = _run_check_net(
        monkeypatch, "landlock", udp_refused_under_none=True
    )
    assert errors == []
    assert report["udp"]["expected_none"] == "denied"
    assert ("udp", "none") in seen and ("udp", "allow") in seen


def test_check_net_udp_leg_is_allowed_but_routeless_on_bwrap(monkeypatch):
    report, errors, _ = _run_check_net(
        monkeypatch, "bwrap", udp_refused_under_none=False
    )
    assert errors == []
    assert report["udp"]["expected_none"] == "allowed-no-route"


def test_check_net_fails_when_landlock_still_creates_udp_sockets(monkeypatch):
    _, errors, _ = _run_check_net(
        monkeypatch, "landlock", udp_refused_under_none=False
    )
    assert any("seccomp UDP rule is gone" in error for error in errors)


def test_check_net_fails_when_bwrap_unexpectedly_refuses_udp(monkeypatch):
    _, errors, _ = _run_check_net(
        monkeypatch, "bwrap", udp_refused_under_none=True
    )
    assert any("does not install the UDP seccomp rule" in error for error in errors)


class _FakeConnection:
    def __init__(self, reply=b"HTTP/1.1 403 Forbidden\r\n\r\n"):
        self.reply = reply

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def sendall(self, data):
        pass

    def recv(self, size):
        reply, self.reply = self.reply, b""
        return reply


def _run_egress_snippet(monkeypatch, capsys, *, env_ip=None, resolves=None):
    """Execute the real probe snippet in-process with stubbed DNS/sockets."""
    smoke = _smoke()
    monkeypatch.setenv("HTTP_PROXY", "http://egress-proxy:3128")
    if env_ip is None:
        monkeypatch.delenv("EGRESS_TEST_IP", raising=False)
    else:
        monkeypatch.setenv("EGRESS_TEST_IP", env_ip)

    def fake_gethostbyname(host):
        if resolves is None:
            raise socket.gaierror(socket.EAI_NONAME, "name not known")
        return resolves

    def fake_getaddrinfo(host, port, **kwargs):
        if resolves is None:
            raise socket.gaierror(socket.EAI_NONAME, "name not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolves, port))]

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        socket, "create_connection", lambda address, timeout=None: _FakeConnection()
    )

    source = smoke.EGRESS_SNIPPET.replace("__LIVE_HOST__", '""')
    exec(compile(source, "<egress-probe>", "exec"), {"__name__": "egress_probe"})
    stdout = capsys.readouterr().out.strip().splitlines()
    return json.loads(stdout[-1])


def test_egress_snippet_reports_the_env_literal_branch(monkeypatch, capsys):
    info = _run_egress_snippet(
        monkeypatch, capsys, env_ip="172.18.0.9", resolves="172.18.0.9"
    )
    assert info["literal_target"] == "172.18.0.9"
    assert info["literal_source"] == "env"
    assert info["literal"].startswith("HTTP/1.1 403")


def test_egress_snippet_reports_the_resolved_branch(monkeypatch, capsys):
    info = _run_egress_snippet(monkeypatch, capsys, resolves="172.18.0.9")
    assert info["literal_target"] == "172.18.0.9"
    assert info["literal_source"] == "resolved:api.egress-allowed.test"


def test_egress_snippet_reports_the_public_fallback_branch(monkeypatch, capsys):
    info = _run_egress_snippet(monkeypatch, capsys)
    assert info["literal_target"] == "1.1.1.1"
    assert info["literal_source"] == "fallback:1.1.1.1"
    assert info["literal"].startswith("HTTP/1.1 403")
    assert info["direct"].startswith("unresolved:")
