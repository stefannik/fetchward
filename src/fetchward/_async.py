"""Async API: the synchronous engine on a bounded executor with cooperative cancellation.

There is one acquisition engine. ``AsyncFetcher`` and :func:`async_fetch` submit
``Fetcher._fetch`` to a thread pool sized by ``SchedulingPolicy.active_acquisitions``, so the
result contract, outcomes, budgets and process-shared safety state are exactly the sync ones.
The event loop only ever awaits a future.

Cancellation is cooperative, not preemptive: cancelling the awaiting task sets a token, the
in-flight acquisition winds down through the normal deadline paths (no new outbound request
starts), and the worker thread finishes on its own. Nothing in the async path can kill a
thread; the caller only loses the result.
"""

from __future__ import annotations

import asyncio
import functools
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from ._admission import Clock
from ._cache import ResponseCache
from ._cancel import CancellationToken
from ._fetcher import Fetcher
from ._fork import generation, register_child_reset
from ._profile import BrowserProfile
from ._safety import Resolver
from ._safety_runtime import SafetyRuntime
from ._session import Session
from ._types import FetchResult
from .policy import AcquisitionPolicy


class _BoundedExecutor:
    """One thread pool, recreated after ``fork()`` where inherited threads do not exist."""

    def __init__(self, max_workers: int, name: str) -> None:
        self._max_workers: int = max_workers
        self._name: str = name
        self._lock: threading.Lock = threading.Lock()
        self._executor: ThreadPoolExecutor | None = None
        self._generation: int = generation()

    def _current(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._executor is None or self._generation != generation():
                self._executor = ThreadPoolExecutor(
                    max_workers=self._max_workers, thread_name_prefix=self._name
                )
                self._generation = generation()
            return self._executor

    async def run(self, call: Callable[[], FetchResult]) -> FetchResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._current(), call)

    def shutdown(self) -> None:
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            # Pending work must not start after close; running workers wind down on their own.
            executor.shutdown(wait=False, cancel_futures=True)


async def _run(
    executor: _BoundedExecutor,
    fetcher: Fetcher,
    url: str,
    *,
    mode: str,
    timeout: float,
) -> FetchResult:
    # Fail closed before the pool: a closed fetcher or one inherited across fork() must not
    # enqueue work.
    fetcher._assert_usable()
    cancel = CancellationToken()
    call = functools.partial(fetcher._fetch, url, mode=mode, timeout=timeout, cancel=cancel)
    try:
        return await executor.run(call)
    except asyncio.CancelledError:
        # The worker finishes on its own; from here on no new outbound request may start.
        cancel.cancel()
        raise


class AsyncFetcher:
    """Async view of :class:`~fetchward.Fetcher`: same policy, session, cache, profile and results.

    ``_resolver``, ``_clock``, ``_safety``, ``_sleep`` and ``_random`` are the same test seams
    ``Fetcher`` takes, not public API. Use ``async with`` or :meth:`aclose` to release the
    thread pool; the caller-supplied ``Session`` stays caller-owned.
    """

    def __init__(
        self,
        policy: AcquisitionPolicy | None = None,
        *,
        session: Session | None = None,
        cache: ResponseCache | None = None,
        profile: BrowserProfile | None = None,
        _resolver: Resolver | None = None,
        _clock: Clock | None = None,
        _safety: SafetyRuntime | None = None,
        _sleep: Callable[[float], None] | None = None,
        _random: Callable[[], float] | None = None,
    ) -> None:
        self._fetcher: Fetcher = Fetcher(
            policy,
            session=session,
            cache=cache,
            profile=profile,
            _resolver=_resolver,
            _clock=_clock,
            _safety=_safety,
            _sleep=_sleep,
            _random=_random,
        )
        self._executor: _BoundedExecutor = _BoundedExecutor(
            self._fetcher.policy.scheduling.active_acquisitions, "fetchward-async"
        )

    @property
    def policy(self) -> AcquisitionPolicy:
        return self._fetcher.policy

    async def fetch(self, url: str, *, mode: str = "auto", timeout: float = 20) -> FetchResult:
        """Acquire one resource. Cancelling the awaiting task cancels the acquisition."""
        return await _run(self._executor, self._fetcher, url, mode=mode, timeout=timeout)

    async def aclose(self) -> None:
        """Close the fetcher and stop accepting work; running workers finish on their own."""
        self._fetcher.close()
        self._executor.shutdown()

    async def __aenter__(self) -> AsyncFetcher:
        self._fetcher._assert_current_process()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


_module_executor: _BoundedExecutor | None = None
_module_lock: threading.Lock = threading.Lock()


def _reset_after_fork() -> None:
    # An inherited pool's threads do not exist in the child, and an inherited lock may be
    # held forever. New objects only; the parent's state is never touched.
    global _module_executor, _module_lock
    _module_executor = None
    _module_lock = threading.Lock()


register_child_reset(_reset_after_fork)


def _shared_executor() -> _BoundedExecutor:
    global _module_executor
    with _module_lock:
        if _module_executor is None:
            _module_executor = _BoundedExecutor(
                AcquisitionPolicy().scheduling.active_acquisitions, "fetchward-async"
            )
        return _module_executor


async def async_fetch(url: str, *, mode: str = "auto", timeout: float = 20) -> FetchResult:
    """Acquire one resource with the default policy. Leaves no open session behind."""
    with Fetcher() as fetcher:
        return await _run(_shared_executor(), fetcher, url, mode=mode, timeout=timeout)


__all__ = ["AsyncFetcher", "async_fetch"]
