"""Async API: same engine, same contract, bounded executor, cooperative cancellation."""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time

import pytest

from harness import Reply, StaticResolver
from harness.sloworigin import SlowOrigin
from fetchward import (
    AccessPolicy,
    AcquisitionPolicy,
    AsyncFetcher,
    DestinationPolicy,
    Fetcher,
    FetcherClosedError,
    Outcome,
    ResourceKind,
    SchedulingPolicy,
    TransportPolicy,
    TrustedOrigin,
    async_fetch,
    fetch,
)


def _policy(ca_bundle: str, *trusted: TrustedOrigin, scheduling: SchedulingPolicy | None = None) -> AcquisitionPolicy:
    return AcquisitionPolicy(
        access=AccessPolicy(mode="user_initiated"),
        destinations=DestinationPolicy(trusted_local=tuple(trusted)),
        transport=TransportPolicy(ca_bundle=ca_bundle),
        scheduling=scheduling or SchedulingPolicy(),
    )


def _slow_policy(origin: SlowOrigin) -> AcquisitionPolicy:
    return AcquisitionPolicy(
        access=AccessPolicy(mode="user_initiated"),
        destinations=DestinationPolicy(
            trusted_local=(TrustedOrigin("http", origin.name, origin.port, ("127.0.0.1",)),)
        ),
        scheduling=SchedulingPolicy(min_host_interval=0.0),
    )


async def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


class _ProbeResolver(StaticResolver):
    """Records which threads resolve and how many lookups overlap."""

    def __init__(self, answers: dict[str, tuple[str, ...]], *, delay: float = 0.0) -> None:
        super().__init__(answers, delay=delay)
        self._lock = threading.Lock()
        self.threads: set[str] = set()
        self.active = 0
        self.peak = 0

    def resolve(self, host: str, port: int, timeout: float, cancel=None) -> tuple[str, ...]:
        with self._lock:
            self.threads.add(threading.current_thread().name)
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            return super().resolve(host, port, timeout, cancel)
        finally:
            with self._lock:
                self.active -= 1


@pytest.mark.parametrize(
    ("path", "content_type", "body", "kind"),
    [
        ("/page", "text/html; charset=utf-8", b"<html><body>async</body></html>", ResourceKind.HTML),
        ("/data", "application/json", b'{"ok": true}', ResourceKind.JSON),
    ],
)
def test_async_fetcher_matches_sync(origins, resolver, ca_bundle, path, content_type, body, kind) -> None:
    origins["a"].route(path, Reply(200, [("Content-Type", content_type)], body))
    url = origins["a"].url(path)
    policy = _policy(ca_bundle, origins["a"].trusted())

    with Fetcher(policy, _resolver=resolver) as fetcher:
        sync = fetcher.fetch(url, mode="http", timeout=10)

    async def go():
        async with AsyncFetcher(policy, _resolver=resolver) as fetcher:
            return await fetcher.fetch(url, mode="http", timeout=10)

    result = asyncio.run(go())
    assert result.outcome is Outcome.SUCCESS
    assert (result.outcome, result.status_code, result.kind, result.response_body) == (
        sync.outcome,
        sync.status_code,
        sync.kind,
        sync.response_body,
    )
    assert result.kind is kind


def test_async_fetch_matches_fetch_under_default_policy(origins) -> None:
    # The default policy rejects loopback before any request; both APIs must report that
    # identically and leave the fixture receiver untouched.
    url = origins["a"].ip_url("/")

    sync = fetch(url, mode="http", timeout=5)
    result = asyncio.run(async_fetch(url, mode="http", timeout=5))

    assert result.outcome is sync.outcome
    assert result.diagnostics.stop_reason == sync.diagnostics.stop_reason
    assert sync.diagnostics.stop_reason == "safety.destination_rejected"
    assert len(origins["a"].log) == 0


def test_concurrent_fetches_stay_within_active_acquisitions(origins, ca_bundle) -> None:
    for index in range(10):
        origins["a"].route(
            f"/p{index}", Reply(200, [("Content-Type", "text/plain")], f"page {index}".encode())
        )
    probe = _ProbeResolver({"origin-a.test": ("127.0.0.1",)}, delay=0.02)
    policy = _policy(
        ca_bundle,
        origins["a"].trusted(),
        scheduling=SchedulingPolicy(
            active_acquisitions=3, max_in_flight_per_host=3, min_host_interval=0.0
        ),
    )

    async def go():
        async with AsyncFetcher(policy, _resolver=probe) as fetcher:
            return await asyncio.gather(
                *(fetcher.fetch(origins["a"].url(f"/p{index}"), mode="http", timeout=10) for index in range(10))
            )

    results = asyncio.run(go())
    assert [result.outcome for result in results] == [Outcome.SUCCESS] * 10
    assert probe.peak <= 3
    assert len(probe.threads) <= 3


def test_cancellation_during_slow_body_reraises_promptly_without_new_request() -> None:
    # A ~1.5 s dripped body: cancellation must not wait for it, and the worker must not
    # start a second request (a retry) once the token is set.
    origin = SlowOrigin(chunk=b"01234567", chunks=30, delay=0.05, name="slow.test")
    try:
        resolver = StaticResolver({"slow.test": ("127.0.0.1",)})

        async def go() -> float:
            async with AsyncFetcher(_slow_policy(origin), _resolver=resolver) as fetcher:
                task = asyncio.create_task(fetcher.fetch(origin.url("/slow"), mode="http", timeout=10))
                assert await _wait_for(origin.started.is_set)
                started = time.monotonic()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                return time.monotonic() - started

        elapsed = asyncio.run(go())
        assert elapsed < 0.5
        assert origin.closed.wait(5)
        assert origin.accepts == 1
    finally:
        origin.close()


def test_event_loop_is_not_blocked_during_slow_fetch() -> None:
    origin = SlowOrigin(chunk=b"01234567", chunks=12, delay=0.05, name="slow.test")
    try:
        resolver = StaticResolver({"slow.test": ("127.0.0.1",)})

        async def go():
            ticks = 0

            async def ticker() -> None:
                nonlocal ticks
                while True:
                    await asyncio.sleep(0.01)
                    ticks += 1

            tick = asyncio.create_task(ticker())
            try:
                async with AsyncFetcher(_slow_policy(origin), _resolver=resolver) as fetcher:
                    result = await fetcher.fetch(origin.url("/slow"), mode="http", timeout=10)
            finally:
                tick.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await tick
            return result, ticks

        result, ticks = asyncio.run(go())
        assert result.ok
        assert ticks >= 10
    finally:
        origin.close()


def test_cancellation_wakes_in_flight_dns_lookup() -> None:
    policy = AcquisitionPolicy(
        access=AccessPolicy(mode="user_initiated"),
        destinations=DestinationPolicy(
            trusted_local=(TrustedOrigin("http", "slow.test", 8080, ("127.0.0.1",)),)
        ),
    )
    finished = threading.Event()

    class _Watched(StaticResolver):
        def resolve(self, host, port, timeout, cancel=None):
            try:
                return super().resolve(host, port, timeout, cancel)
            finally:
                finished.set()

    watched = _Watched({"slow.test": ("127.0.0.1",)}, delay=3.0)

    async def go():
        async with AsyncFetcher(policy, _resolver=watched) as fetcher:
            task = asyncio.create_task(fetcher.fetch("http://slow.test:8080/", mode="http", timeout=10))
            assert await _wait_for(lambda: bool(watched.calls))
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            # The lookup ends on the token, not on its three-second delay.
            assert await _wait_for(finished.is_set, timeout=1.0)

    asyncio.run(go())
    assert watched.calls == ["slow.test"]


def test_cancellation_stops_a_retry_from_being_sent(origins, ca_bundle) -> None:
    # The first response is retryable (503) and arrives after the cancellation: the retry
    # must not start, so the receiver sees exactly one request.
    def busy(_request):
        time.sleep(0.4)
        return Reply(503, [("Content-Type", "text/plain")], b"busy")

    origins["a"].route("/busy", busy)
    resolver = StaticResolver({"origin-a.test": ("127.0.0.1",)})
    policy = _policy(
        ca_bundle,
        origins["a"].trusted(),
        scheduling=SchedulingPolicy(min_host_interval=0.0, retry_backoff=0.01, retry_jitter=0.0),
    )

    async def go():
        async with AsyncFetcher(policy, _resolver=resolver) as fetcher:
            task = asyncio.create_task(fetcher.fetch(origins["a"].url("/busy"), mode="http", timeout=10))
            assert await _wait_for(lambda: len(origins["a"].log) == 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(go())
    time.sleep(0.9)  # past the point where a retry would have been sent
    assert origins["a"].log.paths() == ["/busy"]


def test_async_fetcher_close_is_terminal(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/", Reply(200, [("Content-Type", "text/html")], b"<html>one</html>"))
    url = origins["a"].url("/")

    async def go():
        fetcher = AsyncFetcher(_policy(ca_bundle, origins["a"].trusted()), _resolver=resolver)
        result = await fetcher.fetch(url, mode="http", timeout=10)
        await fetcher.aclose()
        with pytest.raises(FetcherClosedError):
            await fetcher.fetch(url, mode="http", timeout=10)
        return result

    assert asyncio.run(go()).ok
    assert len(origins["a"].log) == 1
