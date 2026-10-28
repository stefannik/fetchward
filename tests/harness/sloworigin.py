"""Raw HTTP(S) fixture that drips a response body in fixed intervals.

Used only to test absolute deadline/cancellation behavior: a per-recv socket timeout can be
satisfied repeatedly by a slow-drip peer while the total transfer exceeds the deadline.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time


class SlowOrigin:
    def __init__(
        self,
        context: ssl.SSLContext | None = None,
        *,
        chunk: bytes = b"12345678",
        chunks: int = 10,
        delay: float = 0.07,
        name: str = "slow.test",
    ) -> None:
        self.name = name
        self.chunk = chunk
        self.chunks = chunks
        self.delay = delay
        self.accepts = 0
        self.started = threading.Event()
        self.closed = threading.Event()
        self._context = context
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept, name="slow-origin", daemon=True)
        self._thread.start()

    def url(self, path: str = "/slow") -> str:
        return f"{'https' if self._context else 'http'}://{self.name}:{self.port}{path}"

    def _accept(self) -> None:
        try:
            raw, _ = self._sock.accept()
        except OSError:
            return
        self.accepts += 1
        view: socket.socket = raw
        try:
            if self._context is not None:
                view = self._context.wrap_socket(raw, server_side=True)
            view.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = view.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.started.set()
            view.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(self.chunk) * self.chunks}\r\n"
                "Content-Type: text/plain\r\n\r\n".encode()
            )
            for _ in range(self.chunks):
                view.sendall(self.chunk)
                time.sleep(self.delay)
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.closed.set()
            try:
                view.close()
            except OSError:
                pass

    def close(self) -> None:
        self._sock.close()
        self._thread.join(timeout=2)
