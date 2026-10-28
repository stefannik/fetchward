"""Consumer-visible and observer-backed tests for shared safety and bounded retry."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

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
from fetchward._retry_after import parse_retry_after
from fetchward._safety_runtime import SafetyRuntime

HTML = [("Content-Type", "text/html")]


def _build(
    origins,
    resolver,
    ca_bundle,
    *,
    runtime: SafetyRuntime | None = None,
    budgets: Budgets | None = None,
    scheduling: SchedulingPolicy | None = None,
    sleeps: list[float] | None = None,
) -> Fetcher:
    schedule = scheduling or SchedulingPolicy(min_host_interval=0.0, retry_backoff=0.0, retry_jitter=0.0)
    policy = AcquisitionPolicy(
        budgets=budgets or Budgets(retries=0),
        access=AccessPolicy(mode="user_initiated"),
        destinations=DestinationPolicy(trusted_local=(origins["a"].trusted(),)),
        transport=TransportPolicy(ca_bundle=ca_bundle),
        scheduling=schedule,
    )
    return Fetcher(
        policy,
        _resolver=resolver,
        _safety=runtime,
        _sleep=(sleeps.append if sleeps is not None else None),
        _random=lambda: 0.0,
    )


def test_host_minimum_start_interval_is_observed(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/p", Reply(200, HTML, b"<html>ok</html>"))
    scheduling = SchedulingPolicy(min_host_interval=0.08)
    runtime = SafetyRuntime(scheduling)
    fetcher = _build(origins, resolver, ca_bundle, runtime=runtime, scheduling=scheduling)
    assert fetcher.fetch(origins["a"].url("/p"), mode="http").ok
    assert fetcher.fetch(origins["a"].url("/p"), mode="http").ok
    requests = origins["a"].log.requests
    assert len(requests) == 2
    assert requests[1].at - requests[0].at >= 0.06


def test_host_in_flight_limit_is_enforced(origins, resolver, ca_bundle) -> None:
    active = 0
    maximum = 0
    release = threading.Event()
    lock = threading.Lock()

    def page(request):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
        assert release.wait(5)
        with lock:
            active -= 1
        return Reply(200, HTML, b"<html>concurrent</html>")

    origins["a"].route("/p", page)
    scheduling = SchedulingPolicy(min_host_interval=0.0, max_in_flight_per_host=2)
    runtime = SafetyRuntime(scheduling)
    fetcher = _build(origins, resolver, ca_bundle, runtime=runtime, scheduling=scheduling)
    results: list = []

    def worker() -> None:
        results.append(fetcher.fetch(origins["a"].url("/p"), mode="http"))

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 3
    while maximum < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert maximum == 2
    release.set()
    for thread in threads:
        thread.join(5)
    assert len(results) == 3 and all(result.ok for result in results)
    assert maximum == 2
    assert len(origins["a"].log) == 3


def test_429_cooldown_is_shared_across_fetchers_and_blocks_target(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/limited", Reply(429, [("Retry-After", "1")], b"limited"))
    origins["a"].route("/after", Reply(200, HTML, b"<html>after</html>"))
    runtime = SafetyRuntime(SchedulingPolicy(min_host_interval=0.0))
    first_fetcher = _build(origins, resolver, ca_bundle, runtime=runtime)
    second_fetcher = _build(origins, resolver, ca_bundle, runtime=runtime)
    first = first_fetcher.fetch(origins["a"].url("/limited"), mode="http")
    assert first.outcome is Outcome.RATE_LIMITED
    assert origins["a"].log.paths() == ["/limited"]
    second = second_fetcher.fetch(origins["a"].url("/after"), mode="http")
    assert second.outcome is Outcome.RATE_LIMITED
    assert second.diagnostics.stop_reason == "host.cooldown"
    assert origins["a"].log.paths() == ["/limited"]
    assert any(e.code == "host.cooldown" for e in second.diagnostics.evidence)


def test_401_and_403_do_not_create_a_host_cooldown(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/forbidden", Reply(403, [], b"forbidden"))
    origins["a"].route("/after", Reply(200, HTML, b"<html>after</html>"))
    runtime = SafetyRuntime(SchedulingPolicy(min_host_interval=0.0))
    fetcher = _build(origins, resolver, ca_bundle, runtime=runtime)
    first = fetcher.fetch(origins["a"].url("/forbidden"), mode="http")
    assert first.outcome is Outcome.BLOCKED
    second = fetcher.fetch(origins["a"].url("/after"), mode="http")
    assert second.ok
    assert origins["a"].log.paths() == ["/forbidden", "/after"]


def test_circuit_opens_after_three_failures_and_half_open_recovers(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/fail", Reply(503, [], b"unavailable"))
    origins["a"].route("/ok", Reply(200, HTML, b"<html>ok</html>"))
    scheduling = SchedulingPolicy(
        min_host_interval=0.0,
        circuit_threshold=3,
        circuit_cooldown=0.2,
        circuit_window=60.0,
    )
    runtime = SafetyRuntime(scheduling)
    fetcher = _build(origins, resolver, ca_bundle, runtime=runtime, scheduling=scheduling)
    for _ in range(3):
        assert fetcher.fetch(origins["a"].url("/fail"), mode="http").outcome is Outcome.ERROR
    assert runtime.snapshot()[origins["a"].name]["circuit_open"] is True
    blocked = fetcher.fetch(origins["a"].url("/ok"), mode="http")
    assert blocked.outcome is Outcome.ERROR
    assert blocked.diagnostics.stop_reason == "host.circuit_open"
    assert origins["a"].log.paths() == ["/fail", "/fail", "/fail"]
    time.sleep(0.25)
    probe = fetcher.fetch(origins["a"].url("/ok"), mode="http")
    assert probe.ok
    assert origins["a"].log.paths() == ["/fail", "/fail", "/fail", "/ok"]
    assert runtime.snapshot()[origins["a"].name]["circuit_open"] is False


@pytest.mark.parametrize("status", [502, 503, 504])
def test_transient_retry_is_bounded_and_successful(origins, resolver, ca_bundle, status) -> None:
    count = 0

    def flaky(request):
        nonlocal count
        count += 1
        if count == 1:
            return Reply(status, [], b"first")
        return Reply(200, HTML, b"<html>recovered</html>")

    origins["a"].route("/flaky", flaky)
    sleeps: list[float] = []
    fetcher = _build(
        origins, resolver, ca_bundle,
        budgets=Budgets(retries=1),
        scheduling=SchedulingPolicy(min_host_interval=0.0, retry_backoff=0.01, retry_jitter=0.0),
        sleeps=sleeps,
    )
    result = fetcher.fetch(origins["a"].url("/flaky"), mode="http")
    assert result.ok and result.html == "<html>recovered</html>"
    assert len(result.attempts) == 2
    assert result.diagnostics.budget.retries_used == 1
    assert result.diagnostics.budget.requests == 2
    assert origins["a"].log.paths() == ["/flaky", "/flaky"]
    assert sleeps == [0.01]


def test_retry_does_not_run_for_429(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/limited", Reply(429, [("Retry-After", "60")], b"limited"))
    fetcher = _build(origins, resolver, ca_bundle, budgets=Budgets(retries=1))
    result = fetcher.fetch(origins["a"].url("/limited"), mode="http")
    assert result.outcome is Outcome.RATE_LIMITED
    assert len(result.attempts) == 1
    assert origins["a"].log.paths() == ["/limited"]


def test_retry_does_not_run_for_403(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/forbidden", Reply(403, [], b"forbidden"))
    fetcher = _build(origins, resolver, ca_bundle, budgets=Budgets(retries=1))
    result = fetcher.fetch(origins["a"].url("/forbidden"), mode="http")
    assert result.outcome is Outcome.BLOCKED
    assert len(result.attempts) == 1
    assert origins["a"].log.paths() == ["/forbidden"]


def test_retry_respects_request_cap(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/fail", Reply(503, [], b"unavailable"))
    sleeps: list[float] = []
    fetcher = _build(
        origins, resolver, ca_bundle,
        budgets=Budgets(retries=1, max_requests=1),
        sleeps=sleeps,
    )
    result = fetcher.fetch(origins["a"].url("/fail"), mode="http")
    assert result.outcome is Outcome.ERROR
    assert len(result.attempts) == 1
    assert result.diagnostics.budget.requests == 1
    assert origins["a"].log.paths() == ["/fail"]
    assert sleeps == []


def test_policy_circuit_threshold_applies_to_process_runtime(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/fail", Reply(503, [], b"unavailable"))
    origins["a"].route("/ok", Reply(200, HTML, b"<html>ok</html>"))
    scheduling = SchedulingPolicy(
        min_host_interval=0.0,
        circuit_threshold=1,
        circuit_cooldown=1.0,
        circuit_window=60.0,
    )
    fetcher = _build(origins, resolver, ca_bundle, scheduling=scheduling)
    assert fetcher.fetch(origins["a"].url("/fail"), mode="http").outcome is Outcome.ERROR
    denied = fetcher.fetch(origins["a"].url("/ok"), mode="http")
    assert denied.outcome is Outcome.ERROR
    assert denied.diagnostics.stop_reason == "host.circuit_open"
    assert origins["a"].log.paths() == ["/fail"]


def test_retry_after_parser_supports_date_and_fallback() -> None:
    now = 1_700_000_000.0
    past = datetime.fromtimestamp(now, timezone.utc) - timedelta(seconds=5)
    future = datetime.fromtimestamp(now, timezone.utc) + timedelta(seconds=20)
    assert parse_retry_after([("Retry-After", "7")], now_wall=now) == (7.0, True)
    assert parse_retry_after([("Retry-After", format_datetime(future, usegmt=True))], now_wall=now)[0] == 20.0
    assert parse_retry_after([("Retry-After", format_datetime(past, usegmt=True))], now_wall=now) == (0.0, True)
    assert parse_retry_after([("Retry-After", "invalid")], now_wall=now) == (60.0, True)
    assert parse_retry_after([], now_wall=now) == (None, False)


def test_active_acquisition_limit_waits_for_release() -> None:
    runtime = SafetyRuntime(SchedulingPolicy(active_acquisitions=1))
    lease = runtime.acquire_acquisition(1.0)
    acquired = threading.Event()

    def worker() -> None:
        with runtime.acquire_acquisition(1.0):
            acquired.set()

    thread = threading.Thread(target=worker)
    thread.start()
    assert not acquired.wait(0.05)
    lease.release()
    assert acquired.wait(1.0)
    thread.join(2)


def test_host_state_capacity_does_not_evict_active_records() -> None:
    from fetchward._safety_runtime import HostDenied

    runtime = SafetyRuntime(
        SchedulingPolicy(min_host_interval=0.0, state_capacity=2)
    )
    with runtime.host_slot("a.test", 1.0), runtime.host_slot("b.test", 1.0):
        with pytest.raises(HostDenied) as denied:
            with runtime.host_slot("c.test", 1.0):
                pass
        assert denied.value.code == "host.capacity"
    with runtime.host_slot("c.test", 1.0):
        pass


def test_capacity_pressure_cannot_evict_a_pacing_window(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/a", Reply(200, HTML, b"<html>a</html>"))
    origins["b"].route("/b", Reply(200, HTML, b"<html>b</html>"))
    scheduling = SchedulingPolicy(
        min_host_interval=60.0,
        state_capacity=1,
        retry_backoff=0.0,
        retry_jitter=0.0,
    )
    policy = AcquisitionPolicy(
        budgets=Budgets(retries=0),
        access=AccessPolicy(mode="user_initiated"),
        destinations=DestinationPolicy(
            trusted_local=(origins["a"].trusted(), origins["b"].trusted())
        ),
        transport=TransportPolicy(ca_bundle=ca_bundle),
        scheduling=scheduling,
    )
    runtime = SafetyRuntime(scheduling)
    fetcher = Fetcher(policy, _resolver=resolver, _safety=runtime)

    assert fetcher.fetch(origins["a"].url("/a"), mode="http", timeout=0.2).ok
    denied = fetcher.fetch(origins["b"].url("/b"), mode="http", timeout=0.2)
    assert denied.outcome is Outcome.ERROR
    assert denied.diagnostics.stop_reason == "host.capacity"
    assert origins["a"].log.paths() == ["/a"]
    assert origins["b"].log.paths() == []

    second_a = fetcher.fetch(origins["a"].url("/a"), mode="http", timeout=0.2)
    assert second_a.outcome is Outcome.ERROR
    assert second_a.diagnostics.stop_reason == "budget.deadline"
    assert origins["a"].log.paths() == ["/a"]
    assert origins["b"].log.paths() == []


def test_public_fetch_smoke_rejects_unsupported_scheme_without_network() -> None:
    from fetchward import fetch as public_fetch

    result = public_fetch("file:///etc/hosts", mode="http", timeout=0.2)
    assert result.outcome is Outcome.ERROR
    assert result.diagnostics.stop_reason == "safety.url_rejected"
    assert result.attempts == ()


def test_public_fetcher_context_and_closed_state(origins, resolver, ca_bundle) -> None:
    fetcher = _build(origins, resolver, ca_bundle)
    with fetcher:
        pass
    from fetchward import FetcherClosedError

    with pytest.raises(FetcherClosedError):
        fetcher.fetch(origins["a"].url("/"), mode="http")


def test_429_cooldown_starts_at_response_receipt(origins, resolver, ca_bundle) -> None:
    def delayed(request):
        time.sleep(0.2)
        return Reply(429, [("Retry-After", "1")], b"limited")

    origins["a"].route("/limited", delayed)
    runtime = SafetyRuntime(SchedulingPolicy(min_host_interval=0.0))
    fetcher = _build(origins, resolver, ca_bundle, runtime=runtime)
    result = fetcher.fetch(origins["a"].url("/limited"), mode="http")
    assert result.outcome is Outcome.RATE_LIMITED
    remaining = runtime.cooldown_remaining(origins["a"].name)
    assert remaining > 0.9


def test_503_retry_after_creates_cooldown_but_keeps_error_outcome(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/limited", Reply(503, [("Retry-After", "1")], b"unavailable"))
    origins["a"].route("/after", Reply(200, HTML, b"<html>after</html>"))
    runtime = SafetyRuntime(SchedulingPolicy(min_host_interval=0.0))
    fetcher = _build(origins, resolver, ca_bundle, runtime=runtime)
    first = fetcher.fetch(origins["a"].url("/limited"), mode="http")
    assert first.outcome is Outcome.ERROR
    second = fetcher.fetch(origins["a"].url("/after"), mode="http")
    assert second.outcome is Outcome.RATE_LIMITED
    assert second.diagnostics.stop_reason == "host.cooldown"
    assert origins["a"].log.paths() == ["/limited"]


def test_429_http_date_cooldown_blocks_target(origins, resolver, ca_bundle) -> None:
    future = format_datetime(
        datetime.now(timezone.utc) + timedelta(seconds=3), usegmt=True
    )
    origins["a"].route("/limited", Reply(429, [("Retry-After", future)], b"limited"))
    origins["a"].route("/after", Reply(200, HTML, b"<html>after</html>"))
    runtime = SafetyRuntime(SchedulingPolicy(min_host_interval=0.0))
    fetcher = _build(origins, resolver, ca_bundle, runtime=runtime)
    first = fetcher.fetch(origins["a"].url("/limited"), mode="http")
    assert first.outcome is Outcome.RATE_LIMITED
    remaining = runtime.cooldown_remaining(origins["a"].name)
    assert 0.5 < remaining < 3.5
    second = fetcher.fetch(origins["a"].url("/after"), mode="http")
    assert second.outcome is Outcome.RATE_LIMITED
    assert origins["a"].log.paths() == ["/limited"]
