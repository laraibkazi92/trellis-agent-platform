# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""CONNECT allowlist proxy behaviour (hermetic: loopback only)."""

import dataclasses
import socket
import threading

import pytest

from scripts.egress_proxy import EgressProxyServer, ProxyConfig, host_allowed


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
