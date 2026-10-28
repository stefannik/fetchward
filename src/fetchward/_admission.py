"""Per-acquisition admission authority: one deadline and one set of counters.

Every outbound request, redirect follow and resource attempt is reserved here before it
can leave. Reservation is atomic; a denial is recorded but is not outbound traffic.
Process-wide host pacing, cooldown and robots admission attach to this object in V01-B.

An optional cancellation token collapses the remaining time and allowance to zero. Every
existing deadline check then refuses new work, so cancellation needs no second code path.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Protocol

from ._cancel import CancellationToken
from ._redact import safe_url
from ._types import BudgetUsage, RequestEvent
from .policy import Budgets


class Clock(Protocol):
    def monotonic(self) -> float: ...
    def wall(self) -> float: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def wall(self) -> float:
        return time.time()


@dataclass(frozen=True)
class Ticket:
    seq: int
    purpose: str
    target: str


class Denied(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Admission:
    def __init__(
        self,
        budgets: Budgets,
        timeout: float,
        clock: Clock,
        cancel: CancellationToken | None = None,
    ) -> None:
        self._budgets = budgets
        self._clock = clock
        self._cancel = cancel
        self._lock = threading.Lock()
        self.started = clock.monotonic()
        self.deadline = self.started + timeout
        self._requests = 0
        self._browser_requests = 0
        self._redirects = 0
        self._attempts = 0
        self._retries_used = 0
        self._retained_bytes = 0
        self._seq = 0
        self._exhausted: list[str] = []
        self._events: list[RequestEvent] = []

    # -- time -------------------------------------------------------------------------
    @property
    def cancel(self) -> CancellationToken | None:
        """The caller's cancellation token, if any; DNS and browser waits watch it."""
        return self._cancel

    def remaining(self) -> float:
        # A cancelled acquisition has no time left: every existing deadline check refuses.
        if self._cancel is not None and self._cancel.cancelled:
            return 0.0
        return max(0.0, self.deadline - self._clock.monotonic())

    def work_allowance(self) -> float:
        """Time a request may use, keeping the stop reserve for capture/teardown when possible."""
        remaining = self.remaining()
        reserve = self._budgets.stop_reserve
        return remaining - reserve if remaining > 2 * reserve else remaining

    # -- retained representation bytes (source and DOM, across all attempts) ------------
    def byte_allowance(self) -> int:
        with self._lock:
            return self._budgets.max_total_bytes - self._retained_bytes

    def retain_bytes(self, count: int) -> None:
        """Charge retained representation bytes; callers cap captures by :meth:`byte_allowance`."""
        with self._lock:
            self._retained_bytes += count

    def note_exhausted(self, code: str) -> None:
        with self._lock:
            self._exhaust(code)

    # -- reservations -----------------------------------------------------------------
    def _exhaust(self, code: str) -> Denied:
        if code not in self._exhausted:
            self._exhausted.append(code)
        return Denied(code)

    def reserve_attempt(self) -> None:
        with self._lock:
            if self._attempts >= self._budgets.max_attempts:
                raise self._exhaust("budget.attempts")
            if self.remaining() <= 0:
                raise self._exhaust("budget.deadline")
            self._attempts += 1

    def reserve_redirect(self) -> None:
        with self._lock:
            if self._redirects >= self._budgets.max_redirects:
                raise self._exhaust("budget.redirects")
            self._redirects += 1

    def reserve_retry(self) -> bool:
        """Consume the shared retry token, or return false when none/time remains."""
        with self._lock:
            if self._retries_used >= self._budgets.retries or self.remaining() <= 0:
                return False
            self._retries_used += 1
            return True

    def reserve_retry_and_attempt(self) -> bool:
        """Atomically consume one retry token and one resource-attempt slot."""
        with self._lock:
            if (
                self._retries_used >= self._budgets.retries
                or self._attempts >= self._budgets.max_attempts
                or self.remaining() <= 0
            ):
                return False
            self._retries_used += 1
            self._attempts += 1
            return True

    def reserve_browser_request(self) -> bool:
        """Count routed requests, including those aborted past the browser cap."""
        with self._lock:
            self._browser_requests += 1
            if self._browser_requests > self._budgets.max_browser_requests:
                self._exhaust("budget.browser_requests")
                return False
            return True

    def reserve_request(self, purpose: str, url: str) -> Ticket:
        """Reserve one outbound request; raises :class:`Denied` and records a denied event."""
        with self._lock:
            self._seq += 1
            target = safe_url(url)
            code = None
            if self.remaining() <= 0:
                code = "budget.deadline"
            elif self._requests >= self._budgets.max_requests:
                code = "budget.requests"
            if code is not None:
                self._events.append(RequestEvent(self._seq, purpose, target, admitted=False, reason=code))
                raise self._exhaust(code)
            self._requests += 1
            return Ticket(self._seq, purpose, target)

    def record_denied(self, purpose: str, url: str, code: str) -> None:
        """Record local work denied before admission (e.g. a forbidden destination)."""
        with self._lock:
            self._seq += 1
            self._events.append(RequestEvent(self._seq, purpose, safe_url(url), admitted=False, reason=code))

    def complete(
        self,
        ticket: Ticket,
        *,
        status_code: int | None,
        pinned_address: str | None,
        connected_address: str | None,
        elapsed: float,
        reason: str | None = None,
    ) -> RequestEvent:
        event = RequestEvent(
            ticket.seq,
            ticket.purpose,
            ticket.target,
            admitted=True,
            reason=reason,
            status_code=status_code,
            pinned_address=pinned_address,
            connected_address=connected_address,
            elapsed=elapsed,
        )
        with self._lock:
            self._events.append(event)
        return event

    def events_since(self, seq: int) -> tuple[RequestEvent, ...]:
        with self._lock:
            return tuple(sorted((e for e in self._events if e.seq > seq), key=lambda e: e.seq))

    @property
    def seq(self) -> int:
        return self._seq

    def usage(self) -> BudgetUsage:
        with self._lock:
            return BudgetUsage(
                deadline=self.deadline - self.started,
                elapsed=self._clock.monotonic() - self.started,
                requests=self._requests,
                browser_requests=self._browser_requests,
                max_requests=self._budgets.max_requests,
                redirects=self._redirects,
                max_redirects=self._budgets.max_redirects,
                attempts=self._attempts,
                max_attempts=self._budgets.max_attempts,
                retries_used=self._retries_used,
                retained_bytes=self._retained_bytes,
                max_total_bytes=self._budgets.max_total_bytes,
                exhausted=tuple(self._exhausted),
            )
