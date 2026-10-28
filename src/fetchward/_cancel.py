"""Cooperative cancellation token for the acquisition path.

The token is set once. Waiters observe :attr:`cancelled`, and anything blocked on a selector
(DNS, the browser gateway) can watch :meth:`fileno`, which becomes readable when the token is
set. It cancels *work*, not threads: the worker finishes through its normal deadline paths.

The self-pipe is created lazily, so a token that is never cancelled and never registered with
a selector costs nothing.
"""

from __future__ import annotations

import socket
import threading


class CancellationToken:
    """Set once; waiters see :attr:`cancelled` and a readable :meth:`fileno`."""

    def __init__(self) -> None:
        self._event: threading.Event = threading.Event()
        self._reader: socket.socket | None = None
        self._writer: socket.socket | None = None
        self._lock: threading.Lock = threading.Lock()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        """Set the token; a registered selector wakes on the next wait."""
        with self._lock:
            already = self._event.is_set()
            self._event.set()
            if already or self._writer is None:
                return
            try:
                _ = self._writer.send(b"x")
            except OSError:  # closed by an owner that no longer waits
                pass

    def fileno(self) -> int:
        """A readable-when-cancelled descriptor, for ``selectors``-based waits."""
        with self._lock:
            if self._reader is None:
                reader, writer = socket.socketpair()
                reader.setblocking(False)
                writer.setblocking(False)
                self._reader, self._writer = reader, writer
                if self._event.is_set():
                    try:
                        _ = writer.send(b"x")
                    except OSError:
                        pass
            return self._reader.fileno()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def close(self) -> None:
        """Release the self-pipe. Only safe once no waiter has it registered."""
        with self._lock:
            reader, writer = self._reader, self._writer
            self._reader = self._writer = None
            for sock in (reader, writer):
                if sock is not None:
                    sock.close()


# The egress proxy (T2) uses the older name.
Cancellation = CancellationToken

__all__ = ["Cancellation", "CancellationToken"]
