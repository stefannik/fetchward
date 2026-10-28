"""Process-shared host and acquisition safety authority.

The authority is deliberately process-local and bounded. It owns the active-acquisition
limit, per-host in-flight/start pacing, 429/503 cooldowns, and the failure circuit. All
outbound HTTP work admitted by the direct adapter uses one host lease per request; robots
lookups use the same path. There is no background refresh and no cross-process promise.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Protocol

from ._fork import register_child_reset
from ._retry_after import parse_retry_after
from .policy import SchedulingPolicy

_TRANSIENT = frozenset({"network.connect", "network.timeout", "network.interrupted"})
_CIRCUIT_STATUSES = frozenset({502, 503, 504})


class _Clock(Protocol):
    def monotonic(self) -> float: ...
    def wall(self) -> float: ...


class _SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def wall(self) -> float:
        return time.time()


class HostDenied(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class _HostState:
    inflight: int = 0
    next_start: float = 0.0
    cooldown_until: float = 0.0
    circuit_open: bool = False
    circuit_until: float = 0.0
    circuit_duration: float = 30.0
    probe_active: bool = False
    failures: list[float] = field(default_factory=list)
    failure_window: float = 0.0
    idle_grace: float = 0.0
    last_used: float = 0.0


class AcquisitionLease:
    def __init__(self, runtime: "SafetyRuntime") -> None:
        self._runtime = runtime
        self._released = False

    def __enter__(self) -> "AcquisitionLease":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._runtime._release_acquisition()


class HostLease:
    """One admitted host request. Exactly one observation should precede release."""

    def __init__(
        self, runtime: "SafetyRuntime", host: str, probe: bool, scheduling: SchedulingPolicy
    ) -> None:
        self._runtime = runtime
        self._host = host
        self._probe = probe
        self._scheduling = scheduling
        self._observed = False
        self._released = False

    def observe_response(self, status: int, headers, received_at: float, received_wall: float) -> None:
        if self._observed:
            return
        self._observed = True
        self._runtime._observe_response(
            self._host, status, headers, received_at, received_wall, self._probe, self._scheduling
        )

    def observe_failure(self, code: str, at: float | None = None) -> None:
        if self._observed:
            return
        self._observed = True
        self._runtime._observe_failure(self._host, code, at, self._probe, self._scheduling)

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        if not self._observed and self._probe:
            # A probe cannot remain indefinitely active if the caller tears down.
            self._runtime._observe_failure(
                self._host, "network.error", None, True, self._scheduling
            )
        self._runtime._release_host(self._host)


class SafetyRuntime:
    def __init__(self, scheduling: SchedulingPolicy | None = None, *, clock: _Clock | None = None) -> None:
        self._scheduling = scheduling or SchedulingPolicy()
        self._clock = clock or _SystemClock()
        self._condition = threading.Condition()
        self._active = 0
        self._hosts: dict[str, _HostState] = {}

    def acquire_acquisition(self, remaining: float, active_limit: int | None = None) -> AcquisitionLease:
        limit = active_limit if active_limit is not None else self._scheduling.active_acquisitions
        if limit <= 0:
            raise HostDenied("budget.deadline")
        deadline = self._clock.monotonic() + max(0.0, remaining)
        with self._condition:
            while self._active >= limit:
                left = deadline - self._clock.monotonic()
                if left <= 0:
                    raise HostDenied("budget.deadline")
                self._condition.wait(left)
            self._active += 1
        return AcquisitionLease(self)

    def _release_acquisition(self) -> None:
        with self._condition:
            if self._active > 0:
                self._active -= 1
            self._condition.notify_all()

    def host_slot(
        self, host: str, remaining: float, scheduling: SchedulingPolicy | None = None
    ) -> "_HostSlot":
        return _HostSlot(self, host, remaining, scheduling or self._scheduling)

    def _acquire_host(self, host: str, remaining: float, scheduling: SchedulingPolicy) -> HostLease:
        deadline = self._clock.monotonic() + max(0.0, remaining)
        with self._condition:
            while True:
                now = self._clock.monotonic()
                state = self._state_locked(
                    host,
                    now,
                    scheduling.state_capacity,
                    scheduling.circuit_window,
                    scheduling.circuit_cooldown_max,
                )
                if state.cooldown_until > now:
                    raise HostDenied("host.cooldown")
                if state.circuit_open and now < state.circuit_until:
                    raise HostDenied("host.circuit_open")
                probe = False
                if state.circuit_open and now >= state.circuit_until:
                    if state.probe_active:
                        raise HostDenied("host.circuit_open")
                    probe = True
                if state.inflight >= scheduling.max_in_flight_per_host:
                    left = deadline - now
                    if left <= 0:
                        raise HostDenied("budget.deadline")
                    self._condition.wait(left)
                    continue
                if now < state.next_start:
                    left = deadline - now
                    wait = min(state.next_start - now, left)
                    if wait <= 0:
                        raise HostDenied("budget.deadline")
                    self._condition.wait(wait)
                    continue
                if probe:
                    state.probe_active = True
                state.inflight += 1
                state.next_start = now + max(0.0, scheduling.min_host_interval)
                state.last_used = now
                return HostLease(self, host, probe, scheduling)

    def _release_host(self, host: str) -> None:
        with self._condition:
            state = self._hosts.get(host)
            if state is not None and state.inflight > 0:
                state.inflight -= 1
                state.last_used = self._clock.monotonic()
            self._condition.notify_all()

    def _state_locked(
        self,
        host: str,
        now: float,
        capacity: int,
        window_hint: float = 0.0,
        grace_hint: float = 0.0,
    ) -> _HostState:
        state = self._hosts.get(host)
        if state is not None:
            return state
        if len(self._hosts) >= capacity:
            self._prune_locked(now, window_hint, grace_hint)
        if len(self._hosts) >= capacity:
            raise HostDenied("host.capacity")
        state = _HostState(last_used=now)
        self._hosts[host] = state
        return state

    def _expire_failures_locked(
        self, state: _HostState, now: float, window_hint: float
    ) -> None:
        if not state.failures:
            state.failure_window = 0.0
            return
        state.failure_window = max(state.failure_window, window_hint)
        cutoff = now - state.failure_window
        state.failures = [stamp for stamp in state.failures if stamp >= cutoff]
        if not state.failures:
            state.failure_window = 0.0

    def _prune_locked(
        self, now: float, window_hint: float = 0.0, grace_hint: float = 0.0
    ) -> None:
        # Capacity pressure may discard only fully inactive records. Pacing windows,
        # live cooldowns, active probes and retained **live** failure history are protection
        # state. Failure timestamps are expired first. An open circuit is retained through
        # its cooldown plus a finite idle grace so the single half-open probe is preserved;
        # only a never-revisited circuit older than both may be discarded. A later request
        # after that stale expiry is treated as a fresh host (the documented tradeoff).
        for state in self._hosts.values():
            self._expire_failures_locked(state, now, window_hint)
            if state.circuit_open:
                state.idle_grace = max(state.idle_grace, grace_hint)
        removable = [
            (host, state.last_used)
            for host, state in self._hosts.items()
            if state.inflight == 0
            and not state.probe_active
            and (
                not state.circuit_open
                or now >= state.circuit_until + state.idle_grace
            )
            and state.cooldown_until <= now
            and state.next_start <= now
            and not state.failures
        ]
        for host, _ in sorted(removable, key=lambda item: item[1]):
            self._hosts.pop(host, None)

    def _observe_response(
        self,
        host: str,
        status: int,
        headers,
        received_at: float,
        received_wall: float,
        probe: bool,
        scheduling: SchedulingPolicy,
    ) -> None:
        with self._condition:
            state = self._hosts.get(host)
            if state is None:
                return
            delay, present = parse_retry_after(headers, now_wall=received_wall)
            if status == 429:
                fallback = scheduling.default_cooldown
                state.cooldown_until = max(
                    state.cooldown_until,
                    received_at + (delay if present and delay is not None else fallback),
                )
            elif status == 503 and present and delay is not None:
                state.cooldown_until = max(state.cooldown_until, received_at + delay)
            if status in _CIRCUIT_STATUSES:
                self._failure_locked(state, received_at, probe, scheduling)
            else:
                self._success_locked(state, scheduling)
            state.last_used = received_at
            self._condition.notify_all()

    def _observe_failure(
        self, host: str, code: str, at: float | None, probe: bool, scheduling: SchedulingPolicy
    ) -> None:
        with self._condition:
            state = self._hosts.get(host)
            if state is None:
                return
            now = self._clock.monotonic() if at is None else at
            if probe or code in _TRANSIENT:
                self._failure_locked(state, now, probe, scheduling)
            else:
                self._success_locked(state, scheduling)
            state.last_used = now
            self._condition.notify_all()

    def _failure_locked(
        self, state: _HostState, now: float, probe: bool, scheduling: SchedulingPolicy
    ) -> None:
        if state.circuit_open and (probe or state.probe_active):
            state.probe_active = False
            state.circuit_duration = min(
                scheduling.circuit_cooldown_max,
                max(scheduling.circuit_cooldown, state.circuit_duration * 2),
            )
            state.circuit_until = now + state.circuit_duration
            state.failures.clear()
            state.failure_window = 0.0
            state.idle_grace = max(state.idle_grace, scheduling.circuit_cooldown_max)
            return
        if state.circuit_open:
            return
        # Retain the longest window observed for this host, but count only failures inside
        # the current caller's window for the threshold decision. A smaller-window fetch
        # cannot erase history needed by a larger observed window; a later larger window
        # still benefits from stamps retained under the previous maximum.
        state.failure_window = max(state.failure_window, scheduling.circuit_window)
        cutoff = now - state.failure_window
        state.failures = [stamp for stamp in state.failures if stamp >= cutoff]
        state.failures.append(now)
        recent_cutoff = now - scheduling.circuit_window
        recent = [stamp for stamp in state.failures if stamp >= recent_cutoff]
        if len(recent) >= scheduling.circuit_threshold:
            state.circuit_open = True
            state.circuit_until = now + scheduling.circuit_cooldown
            state.circuit_duration = scheduling.circuit_cooldown
            state.probe_active = False
            state.failures.clear()
            state.failure_window = 0.0
            state.idle_grace = scheduling.circuit_cooldown_max

    def _success_locked(self, state: _HostState, scheduling: SchedulingPolicy) -> None:
        state.circuit_open = False
        state.circuit_until = 0.0
        state.circuit_duration = scheduling.circuit_cooldown
        state.probe_active = False
        state.failures.clear()
        state.failure_window = 0.0
        state.idle_grace = 0.0

    def cooldown_remaining(self, host: str) -> float:
        with self._condition:
            state = self._hosts.get(host)
            if state is None:
                return 0.0
            return max(0.0, state.cooldown_until - self._clock.monotonic())

    def active_acquisitions(self) -> int:
        with self._condition:
            return self._active

    def snapshot(self) -> dict[str, dict[str, float | int | bool]]:
        with self._condition:
            return {
                host: {
                    "inflight": state.inflight,
                    "cooldown_until": state.cooldown_until,
                    "circuit_open": state.circuit_open,
                    "circuit_until": state.circuit_until,
                    "probe_active": state.probe_active,
                }
                for host, state in self._hosts.items()
            }

    def reset_for_tests(self) -> None:
        with self._condition:
            self._hosts.clear()
            self._active = 0
            self._condition.notify_all()


class _HostSlot:
    def __init__(
        self, runtime: SafetyRuntime, host: str, remaining: float, scheduling: SchedulingPolicy
    ) -> None:
        self._runtime = runtime
        self._host = host
        self._remaining = remaining
        self._scheduling = scheduling
        self._lease: HostLease | None = None

    def __enter__(self) -> HostLease:
        self._lease = self._runtime._acquire_host(self._host, self._remaining, self._scheduling)
        return self._lease

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._lease is not None:
            self._lease.release()

    def __call__(self) -> "_HostSlot":
        return self


_PROCESS_SAFETY = SafetyRuntime()
_PROCESS_LOCK = threading.Lock()


def _reset_after_fork() -> None:
    global _PROCESS_SAFETY, _PROCESS_LOCK
    # New objects only; parent state and inherited locks are untouched.
    _PROCESS_SAFETY = SafetyRuntime()
    _PROCESS_LOCK = threading.Lock()


register_child_reset(_reset_after_fork)


def process_safety() -> SafetyRuntime:
    return _PROCESS_SAFETY


def reset_process_safety_for_tests() -> None:
    """Test-only isolation hook; production callers must not use this to clear protection."""
    _PROCESS_SAFETY.reset_for_tests()
