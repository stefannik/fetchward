"""Capacity pressure must expire dead failure history without evicting live protection."""

from __future__ import annotations

import time

import pytest

from harness import Reply
from fetchward import (
    AccessPolicy,
    AcquisitionPolicy,
    Budgets,
    DestinationPolicy,
    Fetcher,
    Outcome,
    SchedulingPolicy,
    TransportPolicy,
)
from fetchward._safety_runtime import HostDenied, SafetyRuntime


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def wall(self) -> float:
        return 1_700_000_000.0 + self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _scheduling(
    *,
    window: float,
    threshold: int = 3,
    cooldown: float = 30.0,
    max_cooldown: float = 300.0,
    capacity: int = 1,
) -> SchedulingPolicy:
    return SchedulingPolicy(
        min_host_interval=0.0,
        retry_backoff=0.0,
        retry_jitter=0.0,
        circuit_window=window,
        circuit_threshold=threshold,
        circuit_cooldown=cooldown,
        circuit_cooldown_max=max_cooldown,
        state_capacity=capacity,
    )


def _record_failure(
    runtime: SafetyRuntime, host: str, scheduling: SchedulingPolicy, at: float
) -> None:
    with runtime.host_slot(host, 1.0, scheduling) as lease:
        lease.observe_failure("network.connect", at=at)


def test_expired_failure_history_is_pruned_at_capacity_pressure() -> None:
    clock = FakeClock()
    scheduling = _scheduling(window=0.05)
    runtime = SafetyRuntime(scheduling, clock=clock)
    _record_failure(runtime, "a.test", scheduling, clock.monotonic())

    clock.advance(0.04)
    with pytest.raises(HostDenied) as denied:
        with runtime.host_slot("b.test", 1.0, scheduling):
            pass
    assert denied.value.code == "host.capacity"

    clock.advance(0.02)  # total 0.06, past the 0.05 window
    with runtime.host_slot("b.test", 1.0, scheduling):
        pass
    assert "a.test" not in runtime.snapshot()
    assert "b.test" in runtime.snapshot()


def test_smaller_window_cannot_erase_history_needed_by_larger_window() -> None:
    clock = FakeClock()
    large = _scheduling(window=1.0)
    small = _scheduling(window=0.05)
    runtime = SafetyRuntime(large, clock=clock)
    _record_failure(runtime, "a.test", large, clock.monotonic())

    clock.advance(0.10)
    with pytest.raises(HostDenied) as denied:
        with runtime.host_slot("b.test", 1.0, small):
            pass
    assert denied.value.code == "host.capacity"

    clock.advance(1.01)  # total 1.11, past the retained larger window
    with runtime.host_slot("b.test", 1.0, small):
        pass
    assert "a.test" not in runtime.snapshot()


def test_larger_window_uses_history_recorded_under_smaller_window() -> None:
    clock = FakeClock()
    small = _scheduling(window=0.05)
    large = _scheduling(window=1.0)
    runtime = SafetyRuntime(small, clock=clock)
    _record_failure(runtime, "a.test", small, clock.monotonic())

    clock.advance(0.10)
    with pytest.raises(HostDenied) as denied:
        with runtime.host_slot("b.test", 1.0, large):
            pass
    assert denied.value.code == "host.capacity"

    clock.advance(1.01)
    with runtime.host_slot("b.test", 1.0, large):
        pass
    assert "a.test" not in runtime.snapshot()


def test_open_circuit_capacity_is_protected_through_cooldown_and_grace() -> None:
    clock = FakeClock()
    scheduling = _scheduling(window=0.05, threshold=1, cooldown=0.05, max_cooldown=0.10)
    runtime = SafetyRuntime(scheduling, clock=clock)
    _record_failure(runtime, "a.test", scheduling, clock.monotonic())
    assert runtime.snapshot()["a.test"]["circuit_open"] is True

    clock.advance(0.04)  # live cooldown
    with pytest.raises(HostDenied) as denied:
        with runtime.host_slot("b.test", 1.0, scheduling):
            pass
    assert denied.value.code == "host.capacity"

    clock.advance(0.07)  # total 0.11: cooldown elapsed, grace retained
    with pytest.raises(HostDenied) as denied:
        with runtime.host_slot("b.test", 1.0, scheduling):
            pass
    assert denied.value.code == "host.capacity"
    assert "a.test" in runtime.snapshot()


def test_active_half_open_probe_cannot_be_evicted_and_is_single() -> None:
    clock = FakeClock()
    scheduling = _scheduling(window=0.05, threshold=1, cooldown=0.05, max_cooldown=0.10)
    runtime = SafetyRuntime(scheduling, clock=clock)
    _record_failure(runtime, "a.test", scheduling, clock.monotonic())
    clock.advance(0.06)  # cooldown elapsed, within grace

    with runtime.host_slot("a.test", 1.0, scheduling) as probe:
        with pytest.raises(HostDenied) as second:
            with runtime.host_slot("a.test", 1.0, scheduling):
                pass
        assert second.value.code == "host.circuit_open"

        clock.advance(0.20)  # already beyond the idle grace while the probe is active
        with pytest.raises(HostDenied) as denied:
            with runtime.host_slot("b.test", 1.0, scheduling):
                pass
        assert denied.value.code == "host.capacity"
        assert "a.test" in runtime.snapshot()
        probe.release()


def test_truly_stale_never_revisited_circuit_eventually_frees_capacity() -> None:
    clock = FakeClock()
    scheduling = _scheduling(window=0.05, threshold=1, cooldown=0.05, max_cooldown=0.10)
    runtime = SafetyRuntime(scheduling, clock=clock)
    _record_failure(runtime, "a.test", scheduling, clock.monotonic())
    clock.advance(0.16)  # cooldown 0.05 + grace 0.10 elapsed

    with runtime.host_slot("b.test", 1.0, scheduling):
        pass
    assert "a.test" not in runtime.snapshot()
    assert "b.test" in runtime.snapshot()


def test_consumer_capacity_recovers_after_failure_expiry(
    origins, resolver, ca_bundle
) -> None:
    a, b = origins["a"], origins["b"]
    a.route("/fail", Reply(503, [("Content-Type", "text/plain")], b"unavailable"))
    b.route("/b", Reply(200, [("Content-Type", "text/html")], b"<html>b</html>"))
    scheduling = _scheduling(window=0.05, threshold=3)
    policy = AcquisitionPolicy(
        budgets=Budgets(retries=0),
        access=AccessPolicy(mode="user_initiated"),
        destinations=DestinationPolicy(trusted_local=(a.trusted(), b.trusted())),
        transport=TransportPolicy(ca_bundle=ca_bundle),
        scheduling=scheduling,
    )
    runtime = SafetyRuntime(scheduling)
    fetcher = Fetcher(policy, _resolver=resolver, _safety=runtime)

    assert fetcher.fetch(a.url("/fail"), mode="http", timeout=0.5).outcome is Outcome.ERROR
    blocked = fetcher.fetch(b.url("/b"), mode="http", timeout=0.5)
    assert blocked.outcome is Outcome.ERROR
    assert blocked.diagnostics.stop_reason == "host.capacity"
    assert a.log.paths() == ["/fail"]
    assert b.log.paths() == []

    time.sleep(0.12)
    recovered = fetcher.fetch(b.url("/b"), mode="http", timeout=0.5)
    assert recovered.ok
    assert recovered.response_body == b"<html>b</html>"
    assert a.log.paths() == ["/fail"]
    assert b.log.paths() == ["/b"]
    assert "a.test" not in runtime.snapshot()
    fetcher.close()
