"""Deterministic fixture harness: named loopback origins, a programmable resolver and
receiver logs observed outside the library under test.

Ordinary fixture traffic is enabled only through explicit ``TrustedOrigin`` allowances.
Public-policy tests use the same servers without those allowances and assert that the
receiver log stays empty.
"""

from __future__ import annotations

import http.server
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from fetchward import TrustedOrigin

Handler = Callable[["Request"], "Reply"]


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    headers: dict[str, str]
    client: str
    client_port: int = 0
    body: bytes = b""
    at: float = 0.0


@dataclass
class Reply:
    status: int = 200
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    # Send this many body bytes then close the connection without completing.
    truncate_at: int | None = None


class ReceiverLog:
    """Every request a fixture origin actually received, recorded by the server itself."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: list[Request] = []

    def add(self, request: Request) -> None:
        with self._lock:
            self.requests.append(request)

    def paths(self) -> list[str]:
        with self._lock:
            return [r.path for r in self.requests]

    def __len__(self) -> int:
        with self._lock:
            return len(self.requests)

    def clear(self) -> None:
        with self._lock:
            self.requests.clear()


class FixtureOrigin:
    """One HTTP or HTTPS origin on 127.0.0.1 with routable handlers."""

    def __init__(self, name: str, *, tls: ssl.SSLContext | None = None) -> None:
        self.name = name
        self.log = ReceiverLog()
        self.routes: dict[str, Handler] = {}
        origin = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self) -> None:
                length_text = self.headers.get("Content-Length", "0")
                try:
                    length = max(0, int(length_text))
                except ValueError:
                    length = 0
                request_body = self.rfile.read(length) if length else b""
                request = Request(
                    self.command, self.path, {k.lower(): v for k, v in self.headers.items()},
                    self.client_address[0], self.client_address[1], request_body, time.monotonic(),
                )
                origin.log.add(request)
                handler = origin.routes.get(self.path.split("?", 1)[0])
                reply = handler(request) if handler else Reply(404, [("Content-Type", "text/plain")], b"not found")
                body = reply.body
                self.send_response(reply.status)
                names = {k.lower() for k, _ in reply.headers}
                for key, value in reply.headers:
                    self.send_header(key, value)
                if "content-length" not in names:
                    self.send_header("Content-Length", str(len(body)))
                if reply.truncate_at is not None:
                    self.send_header("Connection", "close")
                self.end_headers()
                if self.command == "HEAD":
                    return
                if reply.truncate_at is not None:
                    self.wfile.write(body[: reply.truncate_at])
                    self.wfile.flush()
                    self.close_connection = True
                    return
                self.wfile.write(body)

            do_GET = _handle  # noqa: N815
            do_HEAD = _handle  # noqa: N815
            do_POST = _handle  # noqa: N815
            do_PUT = _handle  # noqa: N815
            do_PATCH = _handle  # noqa: N815
            do_DELETE = _handle  # noqa: N815
            do_OPTIONS = _handle  # noqa: N815

            def log_message(self, *args: object) -> None:
                pass

        class _Server(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request: object, client_address: object) -> None:
                # Client aborts (failed TLS handshakes, byte-cap resets) are expected
                # fixture events; keep them observable instead of printing tracebacks.
                import sys

                origin.server_errors.append(repr(sys.exc_info()[1]))

        self.server_errors: list[str] = []
        self._server = _Server(("127.0.0.1", 0), _Handler)
        if tls is not None:
            self._server.socket = tls.wrap_socket(self._server.socket, server_side=True)
        self.scheme = "https" if tls is not None else "http"
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, name=f"fixture-{name}", daemon=True)
        self._thread.start()

    def route(self, path: str, handler: Handler | Reply) -> None:
        self.routes[path] = handler if callable(handler) else (lambda _r, reply=handler: reply)

    def url(self, path: str = "/") -> str:
        return f"{self.scheme}://{self.name}:{self.port}{path}"

    def ip_url(self, path: str = "/") -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}{path}"

    def trusted(self) -> TrustedOrigin:
        return TrustedOrigin(self.scheme, self.name, self.port, ("127.0.0.1",))

    def reset(self) -> None:
        self.routes.clear()
        self.log.clear()
        self.server_errors.clear()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


class StaticResolver:
    """Programmable in-process resolver honouring the Resolver contract.

    ``delay`` simulates a slow lookup; the wait is bounded by the caller's timeout and no
    work remains after the call returns, as the contract requires.
    """

    def __init__(self, answers: dict[str, tuple[str, ...]] | None = None, *, delay: float = 0.0) -> None:
        self.answers = dict(answers or {})
        self.delay = delay
        self.calls: list[str] = []

    def resolve(self, host: str, port: int, timeout: float, cancel=None) -> tuple[str, ...]:
        import time

        from fetchward._safety import DNSCancelled, DNSFailure, DNSTimeout

        self.calls.append(host)
        if self.delay:
            if cancel is not None:
                if cancel.wait(min(self.delay, timeout)):
                    raise DNSCancelled()
            else:
                time.sleep(min(self.delay, timeout))
            if self.delay > timeout:
                raise DNSTimeout()
        if host not in self.answers:
            raise DNSFailure("NXDOMAIN (fixture)")
        return self.answers[host]


class DNSFixtureServer:
    """UDP DNS server on 127.0.0.1 that answers A/AAAA queries or silently drops them.

    Every received packet is logged with a monotonic timestamp, so tests can observe
    resolver traffic from outside the library, including traffic after a deadline.
    """

    def __init__(
        self,
        records: dict[str, tuple[str, ...]] | None = None,
        *,
        blackhole: bool = False,
        answer_qtypes: frozenset[int] | None = None,
        responder: Callable[[str, int], tuple[str, ...] | None] | None = None,
    ) -> None:
        """``answer_qtypes`` (e.g. ``{28}`` for AAAA only) silently drops other query types.

        ``responder(qname, qtype)`` overrides ``records``: it returns the addresses to answer
        for that query (filtered to the query's family), or ``None`` for NXDOMAIN. It lets a
        test change answers between lookups, e.g. to model DNS rebinding.
        """
        import socket
        import time

        self.records = dict(records or {})
        self.blackhole = blackhole
        self.answer_qtypes = answer_qtypes
        self.responder = responder
        self.packets: list[tuple[float, str]] = []
        self.packet_event = threading.Event()
        self._lock = threading.Lock()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._clock = time.monotonic
        self._thread = threading.Thread(target=self._serve, name="fixture-dns", daemon=True)
        self._thread.start()

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    def packets_after(self, moment: float) -> int:
        with self._lock:
            return sum(1 for t, _ in self.packets if t > moment)

    def wait_for_packet(self, timeout: float) -> bool:
        return self.packet_event.wait(timeout)

    def _serve(self) -> None:
        while True:
            try:
                data, peer = self._sock.recvfrom(4096)
            except OSError:
                return
            try:
                qname, qtype, question_end = self._parse(data)
            except (IndexError, ValueError):
                continue
            with self._lock:
                self.packets.append((self._clock(), qname))
                self.packet_event.set()
            if self.blackhole or (self.answer_qtypes is not None and qtype not in self.answer_qtypes):
                continue
            self._sock.sendto(self._answer(data, qname, qtype, question_end), peer)

    @staticmethod
    def _parse(data: bytes) -> tuple[str, int, int]:
        labels, i = [], 12
        while data[i]:
            length = data[i]
            labels.append(data[i + 1 : i + 1 + length].decode("ascii"))
            i += 1 + length
        qtype = int.from_bytes(data[i + 1 : i + 3], "big")
        return ".".join(labels).lower(), qtype, i + 5

    def _answer(self, query: bytes, qname: str, qtype: int, question_end: int) -> bytes:
        import ipaddress

        if self.responder is not None:
            answer = self.responder(qname, qtype)
            known, addresses = answer is not None, [ipaddress.ip_address(a) for a in answer or ()]
        else:
            known = qname in self.records
            addresses = [ipaddress.ip_address(a) for a in self.records.get(qname, ())]
        wanted = [a for a in addresses if (a.version == 4) == (qtype == 1)] if qtype in (1, 28) else []
        flags = 0x8180 if known else 0x8183  # NOERROR or NXDOMAIN, recursion available
        header = query[:2] + flags.to_bytes(2, "big") + (1).to_bytes(2, "big") + len(wanted).to_bytes(2, "big") + bytes(4)
        body = query[12:question_end]
        for address in wanted:
            rtype = 1 if address.version == 4 else 28
            rdata = address.packed
            body += b"\xc0\x0c" + rtype.to_bytes(2, "big") + (1).to_bytes(2, "big") + (60).to_bytes(4, "big")
            body += len(rdata).to_bytes(2, "big") + rdata
        return header + body

    def close(self) -> None:
        self._sock.close()
        self._thread.join(timeout=2)


class ConnectionObserver:
    """Raw TCP listener that records every accepted connection, then closes it.

    It sits on a destination that must never be reached. Any accepted connection counts
    as a contact, even one that never sends an HTTP request or TLS handshake.
    """

    def __init__(self, host: str, port: int = 0) -> None:
        import socket
        import time

        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._sock = socket.socket(family, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(16)
        self.host, self.port = host, self._sock.getsockname()[1]
        self.accepts: list[tuple[float, str]] = []
        self.lines: list[str] = []
        self._lock = threading.Lock()
        self._clock = time.monotonic
        self._thread = threading.Thread(target=self._serve, name=f"observer-{host}", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, peer = self._sock.accept()
            except OSError:
                return
            with self._lock:
                self.accepts.append((self._clock(), str(peer[0])))
            threading.Thread(target=self._read_first_line, args=(conn,), daemon=True).start()

    def _read_first_line(self, conn) -> None:
        """Best effort: record the request line (e.g. ``GET /img.png HTTP/1.1``) for attribution.

        A connection that sends nothing (a preconnect) is recorded as ``""``.
        """
        data = b""
        try:
            conn.settimeout(0.5)
            while b"\r\n" not in data and len(data) < 2048:
                chunk = conn.recv(2048)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        finally:
            conn.close()
        with self._lock:
            self.lines.append(data.split(b"\r\n", 1)[0].decode("latin-1", "replace"))

    def __len__(self) -> int:
        with self._lock:
            return len(self.accepts)

    def close(self) -> None:
        self._sock.close()
        self._thread.join(timeout=2)


class DatagramObserver:
    """UDP listener recording every datagram (e.g. WebRTC STUN) sent to a forbidden address."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        import socket
        import time

        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._sock = socket.socket(family, socket.SOCK_DGRAM)
        self._sock.bind((host, 0))
        self.port = self._sock.getsockname()[1]
        self.datagrams: list[float] = []
        self._lock = threading.Lock()
        self._clock = time.monotonic
        self._thread = threading.Thread(target=self._serve, name="observer-udp", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                self._sock.recvfrom(4096)
            except OSError:
                return
            with self._lock:
                self.datagrams.append(self._clock())

    def __len__(self) -> int:
        with self._lock:
            return len(self.datagrams)

    def close(self) -> None:
        self._sock.close()
        self._thread.join(timeout=2)


def audit_gateway(admissions, events) -> dict:
    """Cross-check interception admissions against gateway traffic, preserving multiplicity.

    ``admissions``: ``(monotonic time, origin, target)`` per request the interception layer
    admitted. Each plain-HTTP gateway forward must consume a *distinct* earlier admission for
    the same origin and target. Tunnels carry encrypted requests the gateway cannot see, so
    they get only an origin-membership check, reported separately: that is never proof that
    every request inside a tunnel was counted.
    """
    pool = sorted(admissions, key=lambda a: a[0])
    used = [False] * len(pool)
    unaccounted_forwards = []
    for event in sorted((e for e in events if e.kind == "forward"), key=lambda e: e.at):
        for i, (at, origin, target) in enumerate(pool):
            if not used[i] and origin == event.origin and target == event.path and at <= event.at:
                used[i] = True
                break
        else:
            unaccounted_forwards.append((event.origin, event.path))
    tunnels_without_admitted_origin = [
        e.origin for e in events
        if e.kind == "tunnel" and not any(origin == e.origin and at <= e.at for at, origin, _ in pool)
    ]
    return {
        "unaccounted_forwards": unaccounted_forwards,
        "tunnels_without_admitted_origin": tunnels_without_admitted_origin,
        "tunnels": sum(1 for e in events if e.kind == "tunnel"),
        "tunnel_requests_proven": False,  # per-request accounting inside tunnels is not observable here
        "internal_errors": [e.path for e in events if e.reason == "gateway.internal_error"],
    }


def spki_sha256(cert_pem: bytes) -> str:
    """Chromium ``--ignore-certificate-errors-spki-list`` value for one fixture certificate."""
    import base64
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def audit_origin_requests(admissions, origin_requests, origin: tuple) -> dict:
    """Match each request the *origin* decoded to a distinct, earlier admission.

    ``admissions``: ``(time, origin, target)``; ``origin_requests``: objects with ``at`` and
    ``path``. An origin request without its own earlier admission is ``unmatched``: traffic
    that the interception layer never admitted or counted.
    """
    pool = [[at, target, False] for at, o, target in sorted(admissions, key=lambda a: a[0]) if o == origin]
    unmatched = []
    for request in sorted(origin_requests, key=lambda r: r.at):
        for slot in pool:
            if not slot[2] and slot[1] == request.path and slot[0] <= request.at:
                slot[2] = True
                break
        else:
            unmatched.append(request.path)
    return {"unmatched": unmatched, "origin_requests": len(origin_requests), "admissions": len(pool)}
