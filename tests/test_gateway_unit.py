"""Experimental egress gateway: properties that do not need a browser (gateway experiment)."""

from __future__ import annotations

import base64
import socket
import time

import pytest

from harness import ConnectionObserver, Reply
from fetchward import DestinationPolicy
from fetchward._egress import EgressGateway
from fetchward._safety import DestinationGuard


@pytest.fixture
def gateway(origins, resolver):
    trusted = (origins["a"].trusted(), origins["tls"].trusted())  # CONNECT is always treated as https
    guard = DestinationGuard(DestinationPolicy(trusted_local=trusted), resolver)
    deadline = time.monotonic() + 10
    gw = EgressGateway(guard.check, remaining=lambda: deadline - time.monotonic())
    port = gw.start()
    yield gw, port
    gw.stop()


def _exchange(port: int, request: bytes, *, read_until_close: bool = True) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.sendall(request)
        data = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if not read_until_close and b"\r\n\r\n" in data:
                break
        return data


def _auth(gw: EgressGateway) -> str:
    return "Basic " + base64.b64encode(f"{gw.username}:{gw.password}".encode()).decode()


def test_unauthenticated_client_cannot_use_gateway(gateway, origins) -> None:
    gw, port = gateway
    origins["a"].route("/", Reply(200, [], b"secret"))
    for credential in (None, "Basic " + base64.b64encode(b"fetchward:wrong").decode()):
        header = f"Proxy-Authorization: {credential}\r\n" if credential else ""
        reply = _exchange(port, f"GET {origins['a'].url('/')} HTTP/1.1\r\nHost: x\r\n{header}\r\n".encode())
        assert reply.startswith(b"HTTP/1.1 407")
        reply = _exchange(port, f"CONNECT origin-a.test:{origins['a'].port} HTTP/1.1\r\n{header}\r\n".encode())
        assert reply.startswith(b"HTTP/1.1 407")
    assert len(origins["a"].log) == 0  # nothing was dialed for unauthenticated clients
    assert {e.kind for e in gw.events} == {"auth_required"}


def test_authenticated_forward_is_pinned_and_rewritten(gateway, origins) -> None:
    gw, port = gateway
    origins["a"].route("/p", Reply(200, [("Content-Type", "text/plain")], b"hello"))
    reply = _exchange(port, f"GET {origins['a'].url('/p?q=1')} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n".encode())
    assert reply.startswith(b"HTTP/1.1 200") and reply.endswith(b"hello")
    (request,) = origins["a"].log.requests
    assert request.path == "/p?q=1" and "proxy-authorization" not in request.headers
    (event,) = [e for e in gw.events if e.kind == "forward"]
    assert event.address == "127.0.0.1"


def test_authenticated_client_still_cannot_reach_forbidden(gateway, origins) -> None:
    gw, port = gateway
    observer = ConnectionObserver("::1")
    try:
        for request in (
            f"GET http://[::1]:{observer.port}/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n",
            f"CONNECT [::1]:{observer.port} HTTP/1.1\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n",
            f"GET {origins['b'].url('/')} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n",  # untrusted local
            f"GET file:///etc/hosts HTTP/1.1\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n",
        ):
            assert _exchange(port, request.encode()).startswith((b"HTTP/1.1 403", b"HTTP/1.1 400"))
        time.sleep(0.2)
        assert len(observer) == 0 and len(origins["b"].log) == 0
    finally:
        observer.close()


def test_connect_to_http_only_trusted_origin_is_refused(gateway, origins) -> None:
    gw, port = gateway
    reply = _exchange(port, f"CONNECT origin-a.test:{origins['a'].port} HTTP/1.1\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n".encode())
    assert reply.startswith(b"HTTP/1.1 403")  # the allowance is for http://, not a raw tunnel


def test_stop_closes_live_tunnels(gateway, origins) -> None:
    gw, port = gateway
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        sock.sendall(f"CONNECT origin-a.test:{origins['tls'].port} HTTP/1.1\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n".encode())
        assert sock.recv(1024).startswith(b"HTTP/1.1 200")
        gw.stop()
        sock.settimeout(2)
        assert sock.recv(1024) == b""  # the gateway closed the tunnel
    finally:
        sock.close()


# -- lifetime boundaries ------------------------------------------------------------
import threading  # noqa: E402

from harness import DNSFixtureServer, StaticResolver, audit_gateway  # noqa: E402
from fetchward import TrustedOrigin  # noqa: E402
from fetchward._dns import CaresResolver  # noqa: E402


def _make_gateway(trusted, resolver, seconds, *, after_check=None):
    guard = DestinationGuard(DestinationPolicy(trusted_local=tuple(trusted)), resolver)
    deadline = time.monotonic() + seconds

    def check(url, timeout, cancel=None):
        destination = guard.check(url, timeout, cancel=cancel)
        if after_check:
            after_check()
        return destination

    gw = EgressGateway(check, remaining=lambda: deadline - time.monotonic())
    return gw, gw.start(), deadline


@pytest.mark.parametrize("kind", ["forward", "tunnel"])
def test_no_dial_after_deadline_following_slow_validation(origins, resolver, kind) -> None:
    """Validation finishes, then scheduling delay passes the deadline: nothing may be dialed."""
    origins["a"].route("/", Reply(200, [], b"late"))
    gw, port, deadline = _make_gateway([origins["a"].trusted(), origins["tls"].trusted()], resolver, 0.15,
                                       after_check=lambda: time.sleep(0.25))
    try:
        auth = _auth(gw)
        request = (
            f"GET {origins['a'].url('/')} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {auth}\r\n\r\n"
            if kind == "forward"
            else f"CONNECT origin-a.test:{origins['tls'].port} HTTP/1.1\r\nProxy-Authorization: {auth}\r\n\r\n"
        )
        reply = _exchange(port, request.encode())
        assert reply.startswith(b"HTTP/1.1 504"), reply[:40]
        assert len(origins["a"].log) == 0 and len(origins["tls"].log) == 0
        assert [e.reason for e in gw.events if e.kind == "denied"] == ["budget.deadline"]
        assert not any(e.kind in ("forward", "tunnel") for e in gw.events)
    finally:
        gw.stop()


def test_request_arriving_after_deadline_is_refused_unread(origins, resolver) -> None:
    gw, port, deadline = _make_gateway([origins["a"].trusted()], resolver, 0.05)
    try:
        time.sleep(0.1)
        try:
            _exchange(port, f"GET {origins['a'].url('/')} HTTP/1.1\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n".encode())
        except ConnectionResetError:
            pass  # closed without reading: no work started on expired acquisition
        assert len(origins["a"].log) == 0
        assert [e.reason for e in gw.events] == ["budget.deadline"]
    finally:
        gw.stop()


def test_stop_cancels_in_flight_dns(origins) -> None:
    dns = DNSFixtureServer(blackhole=True)
    resolver = CaresResolver([dns.address], attempt_timeout=0.05, tries=50)
    gw, port, _ = _make_gateway([], resolver, 5)
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        client.sendall(f"GET http://slow.test:8080/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n".encode())
        waited = time.monotonic() + 2
        while len(dns.packets) < 2 and time.monotonic() < waited:
            time.sleep(0.01)
        assert len(dns.packets) >= 2  # the lookup really is in flight and retrying
        started = time.monotonic()
        gw.stop()
        stopped = time.monotonic()
        assert stopped - started < 1.5
        time.sleep(0.5)
        assert dns.packets_after(stopped) == 0  # no DNS work after stop() returned
        assert gw.unfinished_handlers_at_stop == 0 and gw.active_handlers == 0
        assert any(e.reason == "gateway.stopped" for e in gw.events)
    finally:
        client.close()
        dns.close()


class _Flood:
    """Upstream that writes as fast as it can; records when its connection is torn down."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.closed_at: list[float] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        chunk = b"x" * 65536
        try:
            while True:
                conn.sendall(chunk)
        except OSError:
            self.closed_at.append(time.monotonic())
        finally:
            conn.close()

    def close(self) -> None:
        self.sock.close()


def _stalled_tunnel(gw, port, flood):
    client = socket.socket()
    # Must be set before connect(): a small window makes the gateway face real backpressure.
    # (Set after connect, it had no effect and the pre-fix stall did not reproduce.)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    client.settimeout(3)
    client.connect(("127.0.0.1", port))
    client.sendall(f"CONNECT flood.test:{flood.port} HTTP/1.1\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n".encode())
    assert client.recv(64).startswith(b"HTTP/1.1 200")
    return client  # never read again: the gateway faces full backpressure


def test_tunnel_backpressure_cannot_outlive_deadline() -> None:
    flood = _Flood()
    resolver = StaticResolver({"flood.test": ("127.0.0.1",)})
    gw, port, deadline = _make_gateway([TrustedOrigin("https", "flood.test", flood.port, ("127.0.0.1",))], resolver, 0.5)
    client = _stalled_tunnel(gw, port, flood)
    try:
        limit = deadline + 0.5
        while gw.active_handlers and time.monotonic() < limit:
            time.sleep(0.02)
        assert gw.active_handlers == 0, "tunnel worker still running after the deadline"
        assert any(e.kind == "denied" and e.reason == "budget.deadline" for e in gw.events)
    finally:
        client.close()
        gw.stop()
        flood.close()


def test_stop_ends_backpressured_tunnel_promptly() -> None:
    flood = _Flood()
    resolver = StaticResolver({"flood.test": ("127.0.0.1",)})
    gw, port, _ = _make_gateway([TrustedOrigin("https", "flood.test", flood.port, ("127.0.0.1",))], resolver, 30)
    client = _stalled_tunnel(gw, port, flood)
    try:
        time.sleep(0.3)  # let buffers fill
        started = time.monotonic()
        gw.stop()
        assert time.monotonic() - started < 1.5
        assert gw.unfinished_handlers_at_stop == 0
        time.sleep(0.3)
        assert flood.closed_at  # the upstream connection was torn down
    finally:
        client.close()
        flood.close()


# -- accounting audit preserves multiplicity -------------------------------------------
ORIGIN = ("http", "a.test", 80)


def _event(kind, at, origin=ORIGIN, path="/x"):
    from harness.gateway import GatewayEvent

    return GatewayEvent(at, kind, "[t]", origin, path if kind == "forward" else None)


def test_audit_requires_one_admission_per_forward() -> None:
    assert audit_gateway([(1.0, ORIGIN, "/x")], [_event("forward", 2.0), _event("forward", 3.0)])["unaccounted_forwards"] == [(ORIGIN, "/x")]
    assert audit_gateway([(1.0, ORIGIN, "/x"), (1.5, ORIGIN, "/x")], [_event("forward", 2.0), _event("forward", 3.0)])["unaccounted_forwards"] == []
    assert audit_gateway([(5.0, ORIGIN, "/x")], [_event("forward", 2.0)])["unaccounted_forwards"] == [(ORIGIN, "/x")]  # admitted too late
    assert audit_gateway([(1.0, ORIGIN, "/y")], [_event("forward", 2.0)])["unaccounted_forwards"] == [(ORIGIN, "/x")]
    tunnel = audit_gateway([(1.0, ORIGIN, "/x")], [_event("tunnel", 2.0, origin=("https", "b.test", 443))])
    assert tunnel["tunnels_without_admitted_origin"] == [("https", "b.test", 443)] and tunnel["tunnel_requests_proven"] is False


def test_audit_calibration_through_real_gateway(gateway, origins) -> None:
    """The reviewer's calibration: one modeled admission, two real forwards → one unaccounted."""
    gw, port = gateway
    origins["a"].route("/c", Reply(200, [], b"c"))
    admitted = [(time.monotonic(), ("http", "origin-a.test", origins["a"].port), "/c")]
    for _ in range(2):
        assert _exchange(port, f"GET {origins['a'].url('/c')} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n".encode()).startswith(b"HTTP/1.1 200")
    assert len(origins["a"].log) == 2
    assert audit_gateway(admitted, gw.events)["unaccounted_forwards"] == [(("http", "origin-a.test", origins["a"].port), "/c")]


# -- re-review ------------------------------------------------------------------------------
def _delay_after_channel_setup(monkeypatch, action) -> None:
    """Run ``action`` right after the real c-ares channel is constructed (models slow setup)."""
    import pycares

    real = pycares.Channel

    class SlowSetup(real):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            action()

    monkeypatch.setattr("fetchward._dns.pycares.Channel", SlowSetup)


def test_no_initial_dns_query_after_cancellation_during_setup(monkeypatch) -> None:
    from harness.cancel import Cancellation
    from fetchward._safety import DNSCancelled

    dns = DNSFixtureServer(blackhole=True)
    token = Cancellation()
    try:
        _delay_after_channel_setup(monkeypatch, token.cancel)
        with pytest.raises(DNSCancelled):
            CaresResolver([dns.address], attempt_timeout=0.05, tries=5).resolve("x.test", 80, 5, cancel=token)
        time.sleep(0.3)
        assert dns.packets == []  # the initial A/AAAA queries were never sent
    finally:
        token.close()
        dns.close()


def test_no_initial_dns_query_after_deadline_during_setup(monkeypatch) -> None:
    from fetchward._safety import DNSTimeout

    dns = DNSFixtureServer(blackhole=True)
    try:
        _delay_after_channel_setup(monkeypatch, lambda: time.sleep(0.25))
        with pytest.raises(DNSTimeout):
            CaresResolver([dns.address], attempt_timeout=0.05, tries=5).resolve("x.test", 80, 0.15)
        time.sleep(0.3)
        assert dns.packets == []
    finally:
        dns.close()


class _HalfCloseUpstream:
    """``mode="respond_after_eof"``: read to EOF, then answer. ``mode="greet_then_eof"``:
    send a greeting, shut its write half, then read whatever arrives until EOF."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.received = b""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.done = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        conn, _ = self.sock.accept()
        conn.settimeout(3)
        try:
            if self.mode == "greet_then_eof":
                conn.sendall(b"greeting")
                conn.shutdown(socket.SHUT_WR)
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                self.received += chunk
            if self.mode == "respond_after_eof":
                conn.sendall(b"upstream-response-after-request-eof")
        finally:
            conn.close()
            self.done.set()

    def close(self) -> None:
        self.sock.close()


def _tunnel_to(gw, port, upstream):
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(f"CONNECT up.test:{upstream.port} HTTP/1.1\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += client.recv(1)
    assert head.startswith(b"HTTP/1.1 200")
    return client


def _read_to_eof(sock) -> bytes:
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk


@pytest.mark.parametrize("mode", ["respond_after_eof", "greet_then_eof"])
def test_tunnel_relays_half_close_in_both_directions(mode) -> None:
    upstream = _HalfCloseUpstream(mode)
    resolver = StaticResolver({"up.test": ("127.0.0.1",)})
    gw, port, _ = _make_gateway([TrustedOrigin("https", "up.test", upstream.port, ("127.0.0.1",))], resolver, 5)
    try:
        client = _tunnel_to(gw, port, upstream)
        if mode == "respond_after_eof":
            client.sendall(b"request-payload")
            client.shutdown(socket.SHUT_WR)  # keep the read half open for the response
            assert _read_to_eof(client) == b"upstream-response-after-request-eof"
            assert upstream.received == b"request-payload"
        else:
            assert _read_to_eof(client) == b"greeting"  # upstream's FIN was relayed
            client.sendall(b"late-client-data")  # the other direction is still open
            client.shutdown(socket.SHUT_WR)
            assert upstream.done.wait(3)
            assert upstream.received == b"late-client-data"
        client.close()
        limit = time.monotonic() + 2
        while gw.active_handlers and time.monotonic() < limit:
            time.sleep(0.01)
        assert gw.active_handlers == 0  # relay ended once both directions finished
    finally:
        gw.stop()
        upstream.close()


def test_failed_dials_do_not_accumulate_sockets(origins) -> None:
    import os

    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    dead_port = closed.getsockname()[1]
    closed.close()  # nothing listens here: connects are refused
    resolver = StaticResolver({"dead.test": ("127.0.0.1",)})
    gw, port, _ = _make_gateway([TrustedOrigin("http", "dead.test", dead_port, ("127.0.0.1",))], resolver, 10)
    try:
        assert _exchange(port, f"GET http://dead.test:{dead_port}/ HTTP/1.1\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n".encode()).startswith(b"HTTP/1.1 502")
        baseline = len(os.listdir("/dev/fd"))
        for _ in range(5):
            reply = _exchange(port, f"GET http://dead.test:{dead_port}/ HTTP/1.1\r\nProxy-Authorization: {_auth(gw)}\r\n\r\n".encode())
            assert reply.startswith(b"HTTP/1.1 502")
        limit = time.monotonic() + 2
        while gw.active_handlers and time.monotonic() < limit:
            time.sleep(0.01)
        assert gw.active_handlers == 0
        assert gw.tracked_sockets == 0  # every failed upstream was closed and untracked
        assert len(os.listdir("/dev/fd")) <= baseline  # no descriptor growth while running
    finally:
        gw.stop()


def test_dial_refused_after_stop_leaves_no_socket(origins, resolver) -> None:
    gw, port, _ = _make_gateway([origins["a"].trusted()], resolver, 10, after_check=lambda: None)
    destination = DestinationGuard(DestinationPolicy(trusted_local=(origins["a"].trusted(),)), resolver).check(
        __import__("fetchward._safety", fromlist=["canonicalize"]).canonicalize(origins["a"].url("/")), 2)
    gw.stop()
    from fetchward._egress import _Expired

    with pytest.raises(_Expired):
        gw._dial(destination)
    assert gw.tracked_sockets == 0 and len(origins["a"].log) == 0
