"""HTTP/2 TLS fixture origin that independently records every decoded request and stream.

It sees decrypted requests because it *is* the TLS endpoint: no interception is involved.
A per-request ``decide(path, nth)`` hook can respond normally, refuse the stream
(``RST_STREAM(REFUSED_STREAM)``), or send ``GOAWAY`` with ``last_stream_id`` below the
request's stream, both of which tell the client the request was not processed, so it may
retry it.
"""

from __future__ import annotations

import itertools
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions


@dataclass(frozen=True)
class H2Request:
    at: float
    connection: int
    stream: int
    method: str
    path: str
    action: str  # respond | refuse | goaway


class H2Origin:
    def __init__(self, name: str, context: ssl.SSLContext, *, decide: Callable[[str, int], str] | None = None) -> None:
        context.set_alpn_protocols(["h2"])
        self.name = name
        self._context = context
        self.decide = decide or (lambda path, nth: "respond")
        self.routes: dict[str, tuple[int, list[tuple[str, str]], bytes]] = {}
        self.requests: list[H2Request] = []
        self.connections: list[tuple[float, str]] = []  # (accepted at, negotiated ALPN)
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self._per_path: dict[str, int] = {}
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(32)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._accept, name="h2-origin", daemon=True).start()

    def url(self, path: str = "/") -> str:
        return f"https://{self.name}:{self.port}{path}"

    def route(self, path: str, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.routes[path] = (status, headers, body)

    def reset(self) -> None:
        with self._lock:
            self.requests.clear()
            self.connections.clear()
            self._per_path.clear()

    def snapshot(self) -> list[H2Request]:
        with self._lock:
            return list(self.requests)

    # -- server ---------------------------------------------------------------------------------
    def _accept(self) -> None:
        while True:
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw, next(self._ids)), daemon=True).start()

    def _serve(self, raw: socket.socket, conn_id: int) -> None:
        try:
            tls = self._context.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        with self._lock:
            self.connections.append((time.monotonic(), tls.selected_alpn_protocol() or ""))
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
        conn.initiate_connection()
        tls.sendall(conn.data_to_send())
        tls.settimeout(10)
        highest_processed = 0
        try:
            while True:
                data = tls.recv(65536)
                if not data:
                    return
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        headers = dict(event.headers)
                        path = headers.get(":path", "")
                        base = path.split("?", 1)[0]
                        with self._lock:
                            nth = self._per_path.get(path, 0) + 1
                            self._per_path[path] = nth
                        action = self.decide(base, nth)
                        with self._lock:
                            self.requests.append(H2Request(time.monotonic(), conn_id, event.stream_id,
                                                           headers.get(":method", ""), path, action))
                        if action == "refuse":
                            conn.reset_stream(event.stream_id, error_code=h2.errors.ErrorCodes.REFUSED_STREAM)
                        elif action == "goaway":
                            conn.close_connection(error_code=h2.errors.ErrorCodes.NO_ERROR, last_stream_id=highest_processed)
                            tls.sendall(conn.data_to_send())
                            return
                        else:
                            highest_processed = max(highest_processed, event.stream_id)
                            status, extra, body = self.routes.get(base, (404, [("content-type", "text/plain")], b"not found"))
                            conn.send_headers(event.stream_id, [(":status", str(status)), ("content-length", str(len(body))),
                                                                ("cache-control", "no-store"), *extra])
                            conn.send_data(event.stream_id, body, end_stream=True)
                tls.sendall(conn.data_to_send())
        except (OSError, ssl.SSLError, h2.exceptions.ProtocolError):
            return
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def close(self) -> None:
        self._sock.close()
