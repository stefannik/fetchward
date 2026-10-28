"""Cancellable DNS resolution on c-ares.

A blocking ``getaddrinfo`` cannot be stopped, so a lookup abandoned at the deadline could
keep retrying. Instead each lookup gets its own c-ares channel, driven synchronously on
the caller's thread through its sockets. When the lookup finishes, the deadline passes or
anything (including ``KeyboardInterrupt``) interrupts the wait, the channel is cancelled
and closed before this function returns: no query is outstanding and no resolver socket
remains open. The channel reads the system resolver configuration (``/etc/hosts``, and
resolv.conf or the macOS system configuration) unless fixture ``servers`` are given.
"""

from __future__ import annotations

import selectors
import time
from collections.abc import Sequence

import pycares

from ._safety import DNSCancelled, DNSFailure, DNSTimeout

_NO_SOCKET = pycares.ARES_SOCKET_BAD


class CaresResolver:
    def __init__(self, servers: Sequence[str] | None = None, *, attempt_timeout: float = 2.0, tries: int = 2) -> None:
        self._servers = list(servers) if servers else None
        self._attempt_timeout = attempt_timeout
        self._tries = tries

    def resolve(self, host: str, port: int, timeout: float, cancel=None) -> tuple[str, ...]:
        if cancel is not None and cancel.cancelled:
            raise DNSCancelled()
        if timeout <= 0:
            raise DNSTimeout()
        deadline = time.monotonic() + timeout
        # selectors (kqueue/epoll/poll) rather than select(): no FD_SETSIZE limit on descriptors.
        selector = selectors.DefaultSelector()
        closed = False

        def on_socket_state(fd: int, readable: bool, writable: bool) -> None:
            if closed:  # pycares may destroy the channel later on its own thread
                return
            events = (selectors.EVENT_READ if readable else 0) | (selectors.EVENT_WRITE if writable else 0)
            registered = fd in selector.get_map()
            if events and registered:
                selector.modify(fd, events)
            elif events:
                selector.register(fd, events)
            elif registered:
                selector.unregister(fd)

        options: dict[str, object] = {
            "sock_state_cb": on_socket_state,  # manual drive: no c-ares event thread
            "timeout": min(self._attempt_timeout, timeout),
            "tries": self._tries,
        }
        if self._servers:
            options["servers"] = self._servers
        outcome: list[tuple[object, int | None]] = []
        channel = None
        if cancel is not None:
            selector.register(cancel.fileno(), selectors.EVENT_READ, data="cancel")  # wakes the wait
        try:
            channel = pycares.Channel(**options)
            # getaddrinfo() sends the initial queries: channel setup may have been slow, so
            # re-check cancellation and the absolute deadline immediately before dispatch.
            if cancel is not None and cancel.cancelled:
                raise DNSCancelled()
            if time.monotonic() >= deadline:
                raise DNSTimeout()
            channel.getaddrinfo(host, port, type=1, callback=lambda result, error: outcome.append((result, error)))
            while not outcome:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DNSTimeout()
                next_timer = channel.timeout()
                wait = min(remaining, next_timer) if next_timer else remaining
                ready = selector.select(max(0.0, wait)) if selector.get_map() else _sleep(wait)
                drives = [
                    (
                        key.fd if events & selectors.EVENT_READ else _NO_SOCKET,
                        key.fd if events & selectors.EVENT_WRITE else _NO_SOCKET,
                    )
                    for key, events in ready
                    if key.data != "cancel"
                ] or [(_NO_SOCKET, _NO_SOCKET)]  # nothing ready: run due timers (retries)
                for read_fd, write_fd in drives:
                    if outcome:
                        break
                    # A wait or an earlier drive can overrun the deadline or be cancelled, and any
                    # drive may fire retry timers and send queries: re-check before every drive.
                    if cancel is not None and cancel.cancelled:
                        raise DNSCancelled()
                    if time.monotonic() >= deadline:
                        raise DNSTimeout()
                    channel.process_fd(read_fd, write_fd)
        finally:
            if channel is not None:
                channel.cancel()  # synchronously ends outstanding queries and closes their sockets
                channel.close()
            closed = True
            selector.close()
        result, error = outcome[0]
        if error:
            raise DNSFailure(pycares.errno.errorcode.get(error, str(error)))
        seen: dict[str, None] = {}
        for node in result.nodes:  # type: ignore[attr-defined]
            address = node.addr[0]
            text = address.decode("ascii") if isinstance(address, bytes) else str(address)
            seen.setdefault(text.split("%")[0], None)
        return tuple(seen)


def _sleep(seconds: float) -> list[tuple[selectors.SelectorKey, int]]:
    time.sleep(max(0.0, seconds))
    return []
