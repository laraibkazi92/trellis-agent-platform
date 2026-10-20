#!/usr/bin/env python3
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""CONNECT-only allowlist proxy for opt-in tool egress (v1).

Runs in the ``egress-proxy`` container, which is the only service with a route
off the internal ``toolnet``. Tools (and the hub they run under) reach it
through ``HTTP_PROXY``/``HTTPS_PROXY``; the proxy opens a raw TCP tunnel to an
allowlisted host and nothing else.

Allowlist form
--------------
One DNS suffix per line, lowercase, no scheme, no port, no path::

    api.example.com
    example.com

``example.com`` matches ``example.com`` and every ``*.example.com`` subdomain.
That plain-suffix form is what ``scripts/generate_egress_acl.py`` writes. A
leading ``*.`` is accepted on load and normalized away so a hand-written file
behaves the same. Blank lines and ``#`` comments are ignored. A missing or empty
file denies everything (fail closed, never allow-all).

A hand-edited line that is not a valid DNS suffix -- a bare top-level domain
(``com``, which would match every ``.com``), a leading dot (``.example.com``,
which never matches), a scheme/path/port, an IP literal, or an illegal label --
is skipped and logged as ``event=allowlist-invalid-entry``. Skipping is the fail
-closed direction: the entry grants nothing and the proxy still starts.

Decision matrix (one log line per request)
------------------------------------------
=========================  ======  ==========================================
Request                    Status  Reason
=========================  ======  ==========================================
``CONNECT host:443``       200     allowlisted + resolves to public addresses
method is not CONNECT      405     ``method``
malformed / bad host       400     ``malformed``
request head > 8 KiB       413     ``request-too-large``
head not finished in time  408     ``head-timeout``
port not in EGRESS_PORTS   403     ``port-not-allowed``
host not in the allowlist  403     ``not-allowlisted``
IP-literal target          403     ``ip-literal``
DNS failure                403     ``resolve-error``
non-public address         403     ``private-destination``
all upstream connects fail 502     ``connect-failed``
EGRESS_MAX_CONNECTIONS hit 503     ``too-many-connections``
=========================  ======  ==========================================

IP literals are always rejected, before resolution: that is the SSRF guard and
mirrors Squid's ``dstdomain`` semantics. Any resolved address that is not
globally routable -- private, loopback, link-local, reserved, unspecified,
multicast, or carrier-grade NAT (RFC 6598 ``100.64.0.0/10``, which Python's
``is_private`` does *not* report) -- is also rejected unless
``EGRESS_ALLOW_PRIVATE_DESTINATIONS=true`` (CI mock and on-prem APIs).

Not implemented on purpose: TLS termination, MITM, caching, forwarding CONNECT
to another proxy, per-tool authentication (v2).

Environment
-----------
``EGRESS_LISTEN_PORT``               listen port (default 3128)
``EGRESS_ALLOWLIST_FILE``            allowlist path (missing/empty = deny all)
``EGRESS_PORTS``                     comma-separated CONNECT ports (default 443)
``EGRESS_ALLOW_PRIVATE_DESTINATIONS`` ``true`` allows RFC1918/loopback targets
``EGRESS_CONNECT_TIMEOUT``           upstream connect timeout, seconds (10)
``EGRESS_IDLE_TIMEOUT``              tunnel idle timeout, seconds (60)
``EGRESS_MAX_TUNNEL_S``              tunnel lifetime cap, seconds (600)
``EGRESS_MAX_CONNECTIONS``           concurrent tunnel cap (64)

Send ``SIGHUP`` to reload the allowlist from disk without dropping tunnels.
"""

from __future__ import annotations

import ipaddress
import os
import re
import select
import signal
import socket
import socketserver
import sys
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable, Sequence

MAX_REQUEST_HEAD = 8192
CHUNK = 65536
DEFAULT_LISTEN_PORT = 3128
# Absolute budget for a client to finish its request head. Per-recv timeouts
# alone let a client that dribbles one byte per idle_timeout pin a slot (and a
# thread) forever; this is measured with time.monotonic() from the first byte.
HEAD_DEADLINE_SECONDS = 10.0
MAX_ALLOWLIST_ENTRY = 253
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# CONNECT is the only accepted method. The host may not contain a colon (that
# would be a port or an IPv6 literal); IPv6 literals are matched separately so
# they get the same 403 as any other IP literal instead of a 400.
_REQUEST_RE = re.compile(
    r"^CONNECT (?P<host>[A-Za-z0-9_.-]{1,253})"
    r":(?P<port>[0-9]{1,5}) HTTP/1\.[01]$"
)
_IPV6_LITERAL_RE = re.compile(
    r"^CONNECT \[(?P<host>[0-9A-Fa-f:.]+)\]:(?P<port>[0-9]{1,5}) HTTP/1\.[01]$"
)

_BLOCKED_ATTRIBUTES = (
    "is_private",
    "is_loopback",
    "is_link_local",
    "is_reserved",
    "is_unspecified",
    "is_multicast",
)

Resolver = Callable[[str, int], Sequence[str]]


def log_line(message: str) -> None:
    """One audit line on stdout; never writes tunnel bytes or credentials."""
    print(f"egress {message}", flush=True)


def normalize_host(host: str) -> str:
    """Lowercase and strip a trailing dot (``example.com.`` -> ``example.com``)."""
    return host.strip().lower().rstrip(".")


def host_allowed(host: str, allowlist: Iterable[str]) -> bool:
    """Suffix match: ``example.com`` allows itself and ``*.example.com``."""
    host = normalize_host(host)
    for suffix in allowlist:
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def load_allowlist(path: str | os.PathLike) -> frozenset[str]:
    """Read the allowlist file; a missing or unreadable file is an empty list.

    Invalid lines are skipped (fail closed) and logged individually, so a typo
    in a hand-edited file denies a host instead of silently allowing a whole
    top-level domain or blocking the proxy from starting.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        log_line(f"event=allowlist-missing path={path} decision=deny-all")
        return frozenset()
    except OSError as exc:
        log_line(
            f"event=allowlist-unreadable path={path} error={type(exc).__name__} "
            "decision=deny-all"
        )
        return frozenset()

    entries: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        entry = parse_allowlist_entry(line)
        if entry is None:
            log_line(
                f"event=allowlist-invalid-entry path={path} line={number} "
                f"entry={_log_value(line)} decision=skip"
            )
            continue
        entries.add(entry)
    return frozenset(entries)


def parse_allowlist_entry(raw: str) -> str | None:
    """Return the canonical suffix for one allowlist line, or None if invalid.

    Canonical form is a plain lowercase suffix with at least two labels: a bare
    top-level domain (``com``) is rejected because it would match every host
    under it, and a leading dot (``.example.com``) is rejected because it can
    never match a normalized host.
    """
    value = raw.split("#", 1)[0].strip().lower()
    if not value:
        return None
    if value.startswith("*."):
        value = value[2:]
    if value.startswith(".") or "*" in value:
        return None
    value = normalize_host(value)
    if (
        not value
        or value.startswith(".")
        or len(value) > MAX_ALLOWLIST_ENTRY
        or "://" in value
        or any(character in value for character in "/:")
        or any(character.isspace() for character in value)
    ):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return None
    labels = value.split(".")
    if len(labels) < 2:
        return None
    if not all(_LABEL_RE.match(label) for label in labels):
        return None
    return value


def _log_value(value: str, limit: int = 80) -> str:
    """Sanitize a file line for the audit log (no control chars/newlines)."""
    return re.sub(r"[^A-Za-z0-9._*:/-]", "?", value)[:limit] or "-"


def _blocked_address(address: str) -> bool:
    """True unless ``address`` is globally routable unicast.

    ``not is_global`` is the load-bearing check: on Python 3.12 ``is_private``
    is False for ``100.64.0.0/10`` (RFC 6598 carrier-grade NAT, which Tailscale
    and some clouds hand out), so the named attributes alone would let a CGNAT
    destination through. The explicit attributes stay because they state the
    intent and cover the ranges where Python versions disagree; anything they
    miss is still caught by ``is_global``.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    if any(getattr(ip, attribute) for attribute in _BLOCKED_ATTRIBUTES):
        return True
    return not ip.is_global


def system_resolve(host: str, port: int) -> list[str]:
    """Resolve ``host`` once; the tunnel connects to these addresses verbatim."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


@dataclass(frozen=True)
class ProxyConfig:
    """Everything the handler needs, injectable for tests."""

    allowlist: frozenset[str] = frozenset()
    ports: frozenset[int] = frozenset({443})
    resolver: Resolver = system_resolve
    allow_private_destinations: bool = False
    connect_timeout: float = 10.0
    idle_timeout: float = 60.0
    max_tunnel_seconds: float = 600.0
    max_connections: int = 64
    log: Callable[[str], None] = log_line


def _env_bool(environ: dict, name: str, default: bool = False) -> bool:
    value = environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_float(environ: dict, name: str, default: float) -> float:
    value = (environ.get(name) or "").strip()
    if not value:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"{name}={value!r} is not a number") from exc
    if parsed <= 0:
        raise ValueError(f"{name}={value!r} must be positive")
    return parsed


def _env_int(environ: dict, name: str, default: int) -> int:
    value = (environ.get(name) or "").strip()
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name}={value!r} is not an integer") from exc
    if parsed <= 0:
        raise ValueError(f"{name}={value!r} must be positive")
    return parsed


def _env_ports(environ: dict) -> frozenset[int]:
    raw = (environ.get("EGRESS_PORTS") or "443").strip()
    ports: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError as exc:
            raise ValueError(f"EGRESS_PORTS entry {token!r} is not an integer") from exc
        if not 0 < port < 65536:
            raise ValueError(f"EGRESS_PORTS entry {port} is out of range")
        ports.add(port)
    return frozenset(ports)


def config_from_env(environ: dict | None = None) -> ProxyConfig:
    env = os.environ if environ is None else environ
    path = (env.get("EGRESS_ALLOWLIST_FILE") or "").strip()
    allowlist = load_allowlist(path) if path else frozenset()
    if not path:
        log_line("event=allowlist-unset decision=deny-all")
    return ProxyConfig(
        allowlist=allowlist,
        ports=_env_ports(env),
        allow_private_destinations=_env_bool(
            env, "EGRESS_ALLOW_PRIVATE_DESTINATIONS"
        ),
        connect_timeout=_env_float(env, "EGRESS_CONNECT_TIMEOUT", 10.0),
        idle_timeout=_env_float(env, "EGRESS_IDLE_TIMEOUT", 60.0),
        max_tunnel_seconds=_env_float(env, "EGRESS_MAX_TUNNEL_S", 600.0),
        max_connections=_env_int(env, "EGRESS_MAX_CONNECTIONS", 64),
    )


class EgressProxyServer(socketserver.ThreadingTCPServer):
    """Thread-per-connection CONNECT proxy.

    ``config`` is swapped atomically on SIGHUP; each request reads it once. The
    connection cap is a bounded semaphore taken in ``process_request`` -- in the
    accept loop, *before* a thread is spawned -- so a flood of idle sockets
    cannot create unbounded threads. Over-cap connections get a ``503`` on the
    accepted socket and are closed without a thread.
    """

    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address: tuple[str, int], config: ProxyConfig):
        self.config = config
        self._slots = threading.BoundedSemaphore(max(1, int(config.max_connections)))
        super().__init__(address, _Handler)

    def acquire_slot(self) -> bool:
        return self._slots.acquire(blocking=False)

    def release_slot(self) -> None:
        try:
            self._slots.release()
        except ValueError:
            pass

    # -- connection admission --------------------------------------------

    def process_request(self, request, client_address) -> None:
        """Admit the connection before handing it to a thread.

        The cap must bound *threads*, not just parsed requests: acquiring the
        slot inside the handler thread would still spawn one thread per idle
        socket. A rejected connection never acquires a slot, so it must not
        release one either -- ``handle`` owns the release for admitted ones.
        """
        if not self.acquire_slot():
            _reject_connection(self, request, client_address, "too-many-connections")
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            # Thread creation failed: the handler will never run its finally.
            self.release_slot()
            raise

    def reload(self, allowlist: frozenset[str]) -> None:
        self.config = replace(self.config, allowlist=allowlist)


def _reject_connection(server, request, client_address, reason: str) -> None:
    """Answer ``503`` on an accepted socket and close it, without a thread."""
    client = f"{client_address[0]}:{client_address[1]}"
    body = b"503 Service Unavailable\n"
    try:
        # The response is tiny (fits in the socket buffer), but a timeout keeps
        # the accept loop from ever parking on a peer that stopped reading.
        request.settimeout(1.0)
        request.sendall(
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
    except OSError:
        pass
    finally:
        # shutdown_request flushes the FIN, then closes -- the same teardown a
        # handled connection gets.
        server.shutdown_request(request)
    server.config.log(
        f"client={client} method=- host=- port=- decision=deny reason={reason}"
    )


class _Handler(socketserver.BaseRequestHandler):
    """One CONNECT request per connection; the socket becomes the tunnel.

    The connection slot was already taken by ``EgressProxyServer.
    process_request`` before this thread existed, so ``handle`` only has to
    release it -- on every exit path, including a mid-tunnel error.
    """

    def handle(self) -> None:
        server = self.server
        client = _client(self)
        try:
            assert isinstance(server, EgressProxyServer), server
            self._handle_connect(client)
        except (ConnectionError, OSError):
            # Client or upstream disappeared mid-tunnel, or a recv timed out.
            pass
        finally:
            if isinstance(server, EgressProxyServer):
                server.release_slot()

    # -- request handling -------------------------------------------------

    def _handle_connect(self, client: str) -> None:
        config = self.server.config
        head, extra = self._read_head()
        if head is None:
            return

        text = head.decode("latin-1", "replace")
        request_line = text.split("\r\n", 1)[0]
        # Log only an alphabetic token: the raw line is client-controlled and
        # could otherwise inject newlines into the audit log.
        method = re.sub(r"[^A-Za-z]", "", request_line.split(" ", 1)[0])[:16] or "-"

        if not request_line.startswith("CONNECT "):
            self._respond(405, "Method Not Allowed", client, method, "-", "-", "method")
            return

        match = _REQUEST_RE.match(request_line)
        if match is None:
            if _IPV6_LITERAL_RE.match(request_line):
                self._respond(403, "Forbidden", client, method, "-", "-", "ip-literal")
            else:
                self._respond(400, "Bad Request", client, method, "-", "-", "malformed")
            return

        host = normalize_host(match.group("host"))
        port_text = match.group("port")
        port = int(port_text)

        if not host or host.startswith(".") or ".." in host:
            self._respond(400, "Bad Request", client, method, host or "-", port_text, "malformed")
            return

        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            self._respond(403, "Forbidden", client, method, host, port_text, "ip-literal")
            return

        if port not in config.ports:
            self._respond(403, "Forbidden", client, method, host, port_text,
                          "port-not-allowed")
            return

        if not host_allowed(host, config.allowlist):
            self._respond(403, "Forbidden", client, method, host, port_text,
                          "not-allowlisted")
            return

        try:
            addresses = list(config.resolver(host, port))
        except Exception:  # noqa: BLE001 - any resolver failure is a deny, not a crash
            addresses = []
        if not addresses:
            self._respond(403, "Forbidden", client, method, host, port_text,
                          "resolve-error")
            return

        if not config.allow_private_destinations:
            for address in addresses:
                if _blocked_address(address):
                    self._respond(403, "Forbidden", client, method, host, port_text,
                                  "private-destination")
                    return

        upstream = self._connect(addresses, port, config.connect_timeout)
        if upstream is None:
            self._respond(502, "Bad Gateway", client, method, host, port_text,
                          "connect-failed")
            return

        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            config.log(
                f"client={client} method={method} host={host} port={port} "
                "decision=allow reason=allowlisted"
            )
            if extra:
                upstream.sendall(extra)
            self._tunnel(self.request, upstream, config)
        finally:
            _close(upstream)

    def _read_head(self) -> tuple[bytes | None, bytes]:
        """Read the request head (through the blank line), bounded to 8 KiB.

        Returns ``(head, leftover)``. Headers are discarded -- only the request
        line is used -- and any bytes that arrived after the blank line are
        forwarded to the upstream once the tunnel is established.

        The read is bounded by an absolute ``min(idle_timeout, 10s)`` deadline
        from the first byte, not by a per-recv timeout: otherwise a client that
        dribbles one byte per idle_timeout keeps a slot (and a thread) forever.
        A head that misses the deadline gets ``408`` and the socket is closed.
        """
        config = self.server.config
        deadline = time.monotonic() + min(config.idle_timeout, HEAD_DEADLINE_SECONDS)
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            if len(buffer) > MAX_REQUEST_HEAD:
                self._respond(413, "Payload Too Large", _client(self), "-", "-", "-",
                              "request-too-large")
                return None, b""
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._respond(408, "Request Timeout", _client(self), "-", "-", "-",
                              "head-timeout")
                return None, b""
            try:
                self.request.settimeout(remaining)
                chunk = self.request.recv(1024)
            except TimeoutError:
                # Per-recv timeout: the remaining deadline elapsed mid-read.
                self._respond(408, "Request Timeout", _client(self), "-", "-", "-",
                              "head-timeout")
                return None, b""
            except OSError:
                return None, b""
            if not chunk:
                return None, b""
            buffer += chunk
        head, _, extra = buffer.partition(b"\r\n\r\n")
        if len(head) > MAX_REQUEST_HEAD:
            self._respond(413, "Payload Too Large", _client(self), "-", "-", "-",
                          "request-too-large")
            return None, b""
        return head, extra

    def _connect(
        self, addresses: Sequence[str], port: int, timeout: float
    ) -> socket.socket | None:
        """Connect to the already-resolved addresses; no second DNS lookup."""
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((address, port))
            except OSError:
                _close(sock)
                continue
            return sock
        return None

    def _tunnel(
        self, client: socket.socket, upstream: socket.socket, config: ProxyConfig
    ) -> None:
        """Pump bytes both ways until EOF, idle timeout, or lifetime cap."""
        for sock in (client, upstream):
            sock.settimeout(config.idle_timeout)
        peers = {client: upstream, upstream: client}
        started = time.monotonic()
        while True:
            remaining = config.max_tunnel_seconds - (time.monotonic() - started)
            if remaining <= 0:
                return
            readable, _, errored = select.select(
                list(peers), [], list(peers), min(config.idle_timeout, remaining)
            )
            if errored or not readable:
                return
            for sock in readable:
                data = sock.recv(CHUNK)
                if not data:
                    return
                peers[sock].sendall(data)

    def _respond(
        self,
        status: int,
        reason: str,
        client: str,
        method: str,
        host: str,
        port: str,
        decision_reason: str,
    ) -> None:
        body = f"{status} {reason}\n".encode()
        try:
            self.request.sendall(
                f"HTTP/1.1 {status} {reason}\r\n"
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n".encode()
                + body
            )
        except OSError:
            pass
        self.server.config.log(
            f"client={client} method={method} host={host or '-'} "
            f"port={port or '-'} decision=deny reason={decision_reason}"
        )


def _client(handler: _Handler) -> str:
    return f"{handler.client_address[0]}:{handler.client_address[1]}"


def _close(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    try:
        config = config_from_env()
        listen_port = _env_int(os.environ, "EGRESS_LISTEN_PORT", DEFAULT_LISTEN_PORT)
    except ValueError as exc:
        log_line(f"event=config-error error={exc}")
        return 2

    server = EgressProxyServer(("0.0.0.0", listen_port), config)

    path = (os.environ.get("EGRESS_ALLOWLIST_FILE") or "").strip()

    def _reload(_signum, _frame):
        entries = load_allowlist(path) if path else frozenset()
        server.reload(entries)
        log_line(f"event=reload allowlist={len(entries)}")

    signal.signal(signal.SIGHUP, _reload)

    log_line(
        f"event=start listen=0.0.0.0:{listen_port} "
        f"ports={','.join(str(p) for p in sorted(config.ports))} "
        f"allowlist={len(config.allowlist)} "
        f"allow_private={str(config.allow_private_destinations).lower()}"
    )
    if not config.allowlist:
        log_line("event=allowlist-empty decision=deny-all")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
