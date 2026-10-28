"""Authenticated, non-decrypting controlled-egress proxy for Chromium.

A loopback-only HTTP proxy that a browser is launched behind. It is the *connection*
layer of browser confinement: every tunnel (``CONNECT``) and every plain-HTTP request is
validated by the destination guard at connect time and dialed only to the validated
address. It never terminates TLS. Per-request admission and accounting is a separate
layer (browser request interception); this gateway does not replace it, and is not a
trusted-local exemption that pages can use: clients must present a per-session
credential, and the listener binds to loopback only.

Lifetime rules: no work starts once the acquisition deadline has passed or the gateway is
stopping — every dial, read and write re-checks both, with no fresh allowance for expired
work. :meth:`EgressGateway.stop` cancels in-flight DNS, wakes and closes every tunnel, and
waits (bounded) for handler threads to finish.

"""

from __future__ import annotations

import base64
import hmac
import secrets
import selectors
import socket
import socketserver
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ._cancel import Cancellation
from ._redact import safe_url
from ._safety import CanonicalURL, Destination, DNSCancelled, DNSFailure, DNSTimeout, SafetyRejection, canonicalize

_MAX_HEAD = 64 * 1024
_BUFFER_LIMIT = 256 * 1024  # per direction; reading pauses while the peer's buffer is full
_TICK = 0.1  # longest wait between deadline/stop checks
_HOP_HEADERS = frozenset({"proxy-authorization", "proxy-connection", "connection", "keep-alive", "te", "upgrade"})


class _Expired(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GatewayEvent:
    at: float
    kind: str  # tunnel | forward | denied | auth_required
    target: str  # redacted summary
    origin: tuple[str, str, int] | None = None
    path: str | None = None  # plain-HTTP origin-form target (caller data; tests only)
    address: str | None = None
    reason: str | None = None


@dataclass
class _State:
    events: list[GatewayEvent] = field(default_factory=list)
    sockets: set[socket.socket] = field(default_factory=set)
    handlers: set[threading.Thread] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)
    stopped: bool = False


class EgressGateway:
    """Start with :meth:`start`; pass :attr:`proxy` to the browser; always :meth:`stop`."""

    def __init__(
        self,
        check: Callable[..., Destination],
        *,
        remaining: Callable[[], float],
        connect_timeout: float = 5.0,
        cleanup_timeout: float = 1.0,
    ) -> None:
        self._check = check  # DestinationGuard.check(url, timeout, cancel=...) or a test wrapper
        self._remaining = remaining  # the acquisition's remaining time
        self._connect_timeout = connect_timeout
        self._cleanup_timeout = cleanup_timeout
        self._state = _State()
        self._cancel = Cancellation()
        self.username = "fetchward"
        self.password = secrets.token_urlsafe(24)
        self._expected = "Basic " + base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self.unfinished_handlers_at_stop: int | None = None

    # -- lifecycle ----------------------------------------------------------------------
    def start(self) -> int:
        gateway = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                gateway._handle(self.request)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True
            block_on_close = False  # stop() joins handlers itself, with a bound

            def handle_error(self, request: object, client_address: object) -> None:
                pass  # client/upstream resets end that connection only

        self._server = Server(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="fetchward-gateway", daemon=True)
        self._thread.start()
        return self._server.server_address[1]

    @property
    def proxy(self) -> dict[str, str]:
        assert self._server is not None
        return {
            "server": f"http://127.0.0.1:{self._server.server_address[1]}",
            "bypass": "<-loopback>",  # loopback destinations are proxied (and guarded) too
            "username": self.username,
            "password": self.password,
        }

    @property
    def active_handlers(self) -> int:
        with self._state.lock:
            return sum(1 for t in self._state.handlers if t.is_alive())

    def stop(self) -> None:
        """Refuse new work, cancel in-flight DNS, close every socket, join handlers (bounded)."""
        with self._state.lock:
            self._state.stopped = True
            live = list(self._state.sockets)
            handlers = list(self._state.handlers)
        self._cancel.cancel()  # wakes resolver and splice waits
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        for sock in live:
            _close(sock)
        deadline = time.monotonic() + self._cleanup_timeout
        for thread in handlers:
            thread.join(max(0.0, deadline - time.monotonic()))
        self.unfinished_handlers_at_stop = sum(1 for t in handlers if t.is_alive())
        if self.unfinished_handlers_at_stop == 0:
            self._cancel.close()

    @property
    def events(self) -> tuple[GatewayEvent, ...]:
        with self._state.lock:
            return tuple(self._state.events)

    # -- time and stop checks -------------------------------------------------------------
    def _allowance(self) -> float:
        """Remaining time for the next step; raises instead of granting a fresh allowance."""
        if self._state.stopped or self._cancel.cancelled:
            raise _Expired("gateway.stopped")
        remaining = self._remaining()
        if remaining <= 0:
            raise _Expired("budget.deadline")
        return remaining

    # -- bookkeeping ------------------------------------------------------------------------
    def _record(self, event: GatewayEvent) -> None:
        with self._state.lock:
            self._state.events.append(event)

    def _track(self, sock: socket.socket) -> bool:
        with self._state.lock:
            if self._state.stopped:
                return False
            self._state.sockets.add(sock)
            return True

    def _untrack(self, sock: socket.socket) -> None:
        with self._state.lock:
            self._state.sockets.discard(sock)
        _close(sock)

    def _deny(self, client: socket.socket, status: str, kind: str, target: str, reason: str, **extra: object) -> None:
        self._record(GatewayEvent(time.monotonic(), kind, target, reason=reason, **extra))  # type: ignore[arg-type]
        headers = "Proxy-Authenticate: Basic realm=\"fetchward\"\r\n" if status.startswith("407") else ""
        try:
            client.settimeout(_TICK)
            client.sendall(f"HTTP/1.1 {status}\r\n{headers}Content-Length: 0\r\nConnection: close\r\n\r\n".encode())
        except OSError:
            pass

    # -- request handling ---------------------------------------------------------------------
    def _handle(self, client: socket.socket) -> None:
        me = threading.current_thread()
        with self._state.lock:
            self._state.handlers.add(me)
        try:
            if not self._track(client):
                return
            try:
                parsed = self._read_head(client)
                if parsed is None:
                    return
                head, rest = parsed
                lines = head.decode("latin-1").split("\r\n")
                method, _, remainder = lines[0].partition(" ")
                target, _, _version = remainder.partition(" ")
                headers = [tuple(part.strip() for part in line.split(":", 1)) for line in lines[1:] if ":" in line]
                auth = next((v for k, v in headers if k.lower() == "proxy-authorization"), "")
                if not hmac.compare_digest(auth.encode(), self._expected.encode()):
                    self._deny(client, "407 Proxy Authentication Required", "auth_required", "[proxy]", "gateway.auth")
                    return
                if method.upper() == "CONNECT":
                    self._tunnel(client, target, rest)
                else:
                    self._forward(client, method, target, headers, rest)
            except _Expired as expired:
                self._record(GatewayEvent(time.monotonic(), "denied", "[in-flight]", reason=expired.code))
            except OSError:
                pass
            except Exception as exc:  # fail closed, but visibly: the connection is dropped
                self._record(GatewayEvent(time.monotonic(), "denied", "[internal]", reason="gateway.internal_error",
                                          path=type(exc).__name__))
            finally:
                self._untrack(client)
        finally:
            with self._state.lock:
                self._state.handlers.discard(me)

    def _read_head(self, client: socket.socket) -> tuple[bytes, bytes] | None:
        data = b""
        while b"\r\n\r\n" not in data:
            client.settimeout(min(_TICK, self._allowance()))
            try:
                chunk = client.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                return None
            data += chunk
            if len(data) > _MAX_HEAD:
                return None
        head, _, rest = data.partition(b"\r\n\r\n")
        return head, rest

    def _authorize(self, client: socket.socket, url_text: str, *, tunnel: bool = False) -> Destination | None:
        extra: dict[str, object] = {}
        try:
            url = canonicalize(url_text)
            extra = {"origin": url.origin, "path": None if tunnel else url.target}
            return self._check(url, self._allowance(), cancel=self._cancel)
        except _Expired as expired:
            self._deny(client, "504 Gateway Timeout", "denied", safe_url(url_text), expired.code, **extra)
        except SafetyRejection as rejection:
            self._deny(client, "403 Forbidden", "denied", safe_url(url_text), rejection.code, **extra)
        except DNSCancelled:
            self._deny(client, "503 Service Unavailable", "denied", safe_url(url_text), "gateway.stopped", **extra)
        except DNSTimeout:
            self._deny(client, "504 Gateway Timeout", "denied", safe_url(url_text), "budget.deadline", **extra)
        except DNSFailure:
            self._deny(client, "502 Bad Gateway", "denied", safe_url(url_text), "network.dns", **extra)
        return None

    def _dial(self, destination: Destination) -> socket.socket:
        """Connect to the validated address. On any failure the socket is closed and untracked:
        ownership passes to the caller only on success."""
        family = socket.AF_INET6 if ":" in destination.address else socket.AF_INET
        upstream = socket.socket(family, socket.SOCK_STREAM)
        if not self._track(upstream):
            upstream.close()
            raise _Expired("gateway.stopped")
        try:
            # Re-check immediately before connecting: validation may have consumed the deadline.
            upstream.settimeout(min(self._connect_timeout, self._allowance()))
            upstream.connect((destination.address, destination.url.port))  # pinned: no DNS here
        except BaseException:
            self._untrack(upstream)
            raise
        return upstream

    @property
    def tracked_sockets(self) -> int:
        with self._state.lock:
            return len(self._state.sockets)

    def _connect(self, client: socket.socket, destination: Destination, url_text: str) -> socket.socket | None:
        try:
            return self._dial(destination)
        except _Expired as expired:
            self._deny(client, "504 Gateway Timeout", "denied", safe_url(url_text), expired.code, path=destination.url.target)
        except OSError:
            self._deny(client, "502 Bad Gateway", "denied", safe_url(url_text), "network.connect", path=destination.url.target)
        return None

    def _tunnel(self, client: socket.socket, authority: str, rest: bytes) -> None:
        url_text = f"https://{authority}/"
        destination = self._authorize(client, url_text, tunnel=True)  # the path is inside the tunnel
        if destination is None:
            return
        upstream = self._connect(client, destination, url_text)
        if upstream is None:
            return
        self._record(GatewayEvent(time.monotonic(), "tunnel", safe_url(url_text), destination.url.origin, None, destination.address))
        try:
            self._splice(client, upstream, to_client=b"HTTP/1.1 200 Connection Established\r\n\r\n", to_upstream=rest)
        finally:
            self._untrack(upstream)

    def _forward(self, client: socket.socket, method: str, target: str, headers: list, rest: bytes) -> None:
        if not target.lower().startswith("http://"):
            self._deny(client, "400 Bad Request", "denied", "[non-http]", "safety.url_rejected")
            return
        destination = self._authorize(client, target)
        if destination is None:
            return
        url = destination.url
        upstream = self._connect(client, destination, target)
        if upstream is None:
            return
        self._record(GatewayEvent(time.monotonic(), "forward", safe_url(target), url.origin, url.target, destination.address))
        try:
            kept = [(k, v) for k, v in headers if k.lower() not in _HOP_HEADERS]
            head = f"{method} {url.target} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in kept)
            self._splice(client, upstream, to_upstream=(head + "Connection: close\r\n\r\n").encode("latin-1") + rest)
        finally:
            self._untrack(upstream)

    def _splice(self, client: socket.socket, upstream: socket.socket, *, to_client: bytes = b"", to_upstream: bytes = b"") -> None:
        """Transparent TCP relay of both directions; every step re-checks deadline and stop.

        Writes never block: each direction has a bounded buffer, and reading from one side
        pauses while the buffer towards its peer is full, so a non-reading peer cannot make
        the gateway buffer or block without limit. Half-close is relayed: when one side sends
        EOF, the bytes already read from it are delivered, the peer's write half is shut
        down, and the other direction keeps flowing until its own EOF, the deadline or stop.
        """
        pending = {client: bytearray(to_client), upstream: bytearray(to_upstream)}  # bytes owed TO each socket
        peer = {client: upstream, upstream: client}
        reading = {client: True, upstream: True}  # False once that side sent EOF
        write_shut = {client: False, upstream: False}
        selector = selectors.DefaultSelector()
        try:
            for sock in (client, upstream):
                sock.setblocking(False)
            selector.register(self._cancel.fileno(), selectors.EVENT_READ, data=None)
            registered: dict[socket.socket, int] = {}
            while True:
                allowance = self._allowance()
                # Propagate a half-close once everything read before the EOF has been delivered.
                for source in (client, upstream):
                    sink = peer[source]
                    if not reading[source] and not pending[sink] and not write_shut[sink]:
                        try:
                            sink.shutdown(socket.SHUT_WR)
                        except OSError:
                            return
                        write_shut[sink] = True
                if all(write_shut.values()):
                    return  # both directions finished
                for sock in (client, upstream):
                    events = 0
                    if reading[sock] and len(pending[peer[sock]]) < _BUFFER_LIMIT:
                        events |= selectors.EVENT_READ
                    if pending[sock]:
                        events |= selectors.EVENT_WRITE
                    if events != registered.get(sock, 0):
                        if sock in registered and events:
                            selector.modify(sock, events, data=sock)
                        elif events:
                            selector.register(sock, events, data=sock)
                        else:
                            selector.unregister(sock)
                        if events:
                            registered[sock] = events
                        else:
                            registered.pop(sock, None)
                for key, events in selector.select(min(_TICK, allowance)):
                    sock = key.data
                    if sock is None:  # cancellation woke us
                        raise _Expired("gateway.stopped")
                    self._allowance()  # the wait may have overrun: no I/O on expired work
                    if events & selectors.EVENT_WRITE and pending[sock]:
                        try:
                            sent = sock.send(pending[sock])
                        except (BlockingIOError, InterruptedError):
                            sent = 0
                        del pending[sock][:sent]
                    if events & selectors.EVENT_READ and reading[sock]:
                        try:
                            data = sock.recv(65536)
                        except (BlockingIOError, InterruptedError):
                            continue
                        if data:
                            pending[peer[sock]].extend(data)
                        else:
                            reading[sock] = False  # EOF: relayed above once its buffer drains
        except _Expired as expired:
            self._record(GatewayEvent(time.monotonic(), "denied", "[tunnel]", reason=expired.code))
        except (OSError, ValueError):  # peer reset, or a socket closed by stop()
            return
        finally:
            selector.close()

def _close(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
