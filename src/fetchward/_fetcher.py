"""Public ``fetch``/``Fetcher`` orchestration.

The synchronous path runs the guarded HTTP vertical slice and the optional isolated browser
backend: canonical destination validation, RFC 9309 robots evaluation, process-shared host
scheduling/cooldown/circuit, bounded transient retry, pinned transport, typed capture, and a
bounded browser fallback selected only by explicit rendering/selector readiness or a
conservative structural JS-shell signal. Browser traffic uses an authenticated,
non-decrypting loopback egress proxy. Missing browser dependencies are an explicit
``backend.unavailable`` result, never a fabricated HTTP success.
"""

from __future__ import annotations

import itertools
import random
import threading
import time
from collections.abc import Callable

from ._admission import Admission, Clock, Denied, SystemClock
from ._cache import CacheEntry, ResponseCache, cache_attempt, policy_fingerprint, store_response
from ._cancel import CancellationToken
from ._challenge import detect_challenge
from ._browser import (
    _BrowserPool,
    _BrowserOperationalError,
    _BrowserUnavailable,
    browser_status,
    run_browser,
)
from ._dns import CaresResolver
from ._fork import assert_generation, generation
from ._http_curl import CurlHTTPAdapter, RedirectHook, backend_status
from ._interactive import InteractionResult, run_session, validate_session
from ._js_shell import detect_js_shell
from ._memory import AcquisitionMemory
from ._profile import BrowserProfile
from ._retry_after import parse_retry_after
from ._robots import RobotsAuthority, RobotsDecision, robots_authority
from ._safety import CanonicalURL, DestinationGuard, Resolver, SafetyRejection, canonicalize
from ._safety_runtime import HostDenied, SafetyRuntime, process_safety
from ._selection import Requirements, Selection, select
from ._session import Session
from ._types import (
    AttemptRecord,
    Diagnostics,
    Evidence,
    EvidenceCategory,
    FetchResult,
    Mode,
    Outcome,
    RESTRICTION_OUTCOMES,
    ResourceKind,
)
from .errors import ConfigurationError, FetcherClosedError
from .policy import POLICY_VERSION, AcquisitionPolicy

_attempt_ids = itertools.count(1)
_RETRY_REASONS = frozenset({"network.connect", "network.timeout", "network.interrupted"})
_RETRY_STATUSES = frozenset({502, 503, 504})


def _next_attempt_id() -> str:
    return f"a{next(_attempt_ids)}"


class Fetcher:
    """Reusable acquisition entry point holding one policy snapshot.

    ``_resolver``, ``_clock``, ``_safety``, ``_sleep`` and ``_random`` are test seams, not
    public API. Safety state is process-shared by default; policy scheduling values shape
    each host lease while cooldown/circuit/cache state belongs to the one runtime. The
    optional ``cache`` answers anonymous HTTP GETs under HTTP caching rules and never stores
    or serves a rendered DOM. The optional ``memory`` supplies advisory per-host routing and
    remembered cooldowns; without it behavior is unchanged. The optional ``profile`` is the
    caller-owned directory browser attempts persist state in; it is never combined with
    ``Session`` cookies, is not used by HTTP requests, and disables the cache.
    """

    def __init__(
        self,
        policy: AcquisitionPolicy | None = None,
        *,
        session: Session | None = None,
        cache: ResponseCache | None = None,
        memory: AcquisitionMemory | None = None,
        profile: BrowserProfile | None = None,
        _resolver: Resolver | None = None,
        _clock: Clock | None = None,
        _safety: SafetyRuntime | None = None,
        _sleep: Callable[[float], None] | None = None,
        _random: Callable[[], float] | None = None,
    ) -> None:
        if session is not None and not isinstance(session, Session):
            raise TypeError("session must be a Session or None")
        if cache is not None and not isinstance(cache, ResponseCache):
            raise TypeError("cache must be a ResponseCache or None")
        if memory is not None and not isinstance(memory, AcquisitionMemory):
            raise TypeError("memory must be an AcquisitionMemory or None")
        if profile is not None and not isinstance(profile, BrowserProfile):
            raise TypeError("profile must be a BrowserProfile or None")
        self._policy = policy if policy is not None else AcquisitionPolicy()
        self._session = session
        self._cache = cache
        self._memory = memory
        self._profile = profile
        self._resolver = _resolver or CaresResolver()
        self._clock = _clock or SystemClock()
        self._safety = _safety or process_safety()
        self._robots: RobotsAuthority = robots_authority()
        self._sleep = _sleep or time.sleep
        self._random = _random or random.random
        self._closed = False
        self._browser_pool = _BrowserPool(self._policy.scheduling.active_acquisitions)
        self._lock = threading.Lock()
        self._fork_generation = generation()

    @property
    def policy(self) -> AcquisitionPolicy:
        return self._policy

    def _assert_current_process(self) -> None:
        assert_generation(self._fork_generation, "Fetcher")

    def _assert_usable(self) -> None:
        """Reject an inherited-across-fork or closed object before any work starts."""
        self._assert_current_process()
        if self._closed:
            raise FetcherClosedError("fetcher is closed")

    def close(self) -> None:
        # Check before acquiring the instance lock: an inherited lock may be held forever.
        self._assert_current_process()
        with self._lock:
            self._closed = True
        self._browser_pool.close()

    def __enter__(self) -> Fetcher:
        self._assert_current_process()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _retry_eligible(self, record: AttemptRecord) -> bool:
        source = record.source
        if source is None:
            return any(reason in _RETRY_REASONS for reason in record.reasons)
        return source.status_code in _RETRY_STATUSES

    def _final_host(self, record: AttemptRecord) -> str | None:
        if record.source is None:
            return None
        try:
            return canonicalize(record.source.url).host
        except SafetyRejection:
            return None

    def _remember(
        self,
        host: str | None,
        *,
        mode: Mode,
        attempts: tuple[AttemptRecord, ...],
        selection: Selection,
        outcome: Outcome,
        fallback_reason: str | None,
    ) -> None:
        """Store advisory per-host facts after selection. Never affects the outcome."""
        memory = self._memory
        if memory is None or host is None:
            return
        now_wall = self._clock.wall()
        chosen = next((a for a in attempts if a.id == selection.attempt_id), None)
        needs_browser_at: float | None = None
        http_sufficient_at: float | None = None
        if mode is Mode.AUTO and chosen is not None:
            if fallback_reason is not None:
                if chosen.mode is Mode.BROWSER and chosen.outcome is Outcome.SUCCESS:
                    needs_browser_at = now_wall
            elif chosen.mode is Mode.HTTP and chosen.outcome is Outcome.SUCCESS:
                http_sufficient_at = now_wall
        memory._record(
            host,
            now_wall=now_wall,
            needs_browser_at=needs_browser_at,
            http_sufficient_at=http_sufficient_at,
            outcome=outcome,
        )
        for attempt in attempts:
            delay = self._retry_delay(attempt, now_wall)
            if delay is None:
                continue
            cooldown_host = self._final_host(attempt)
            if cooldown_host is None:
                continue
            memory._record(
                cooldown_host,
                now_wall=now_wall,
                cooldown_delay=delay,
                now_monotonic=self._clock.monotonic(),
            )

    def _retry_delay(self, attempt: AttemptRecord, now_wall: float) -> float | None:
        """Seconds a 429/503 response asked this host to wait, or None."""
        source = attempt.source
        if source is None or attempt.mode is not Mode.HTTP:
            return None
        if source.status_code == 429:
            delay, present = parse_retry_after(source.headers, now_wall=now_wall)
            if present and delay is not None:
                return delay if delay > 0 else None
            return self._policy.scheduling.default_cooldown
        if source.status_code == 503:
            delay, present = parse_retry_after(source.headers, now_wall=now_wall)
            if present and delay is not None and delay > 0:
                return delay
        return None

    def _run_with_retry(
        self,
        adapter: CurlHTTPAdapter,
        admission: Admission,
        start,
        *,
        attempt_id: str,
        purpose: str,
        redirect_purpose: str,
        max_redirects: int,
        source_cap: int,
        redirect_hook: RedirectHook | None,
        consume_attempt: bool,
        use_credentials: bool = False,
        request_headers: tuple[tuple[str, str], ...] = (),
    ) -> list[AttemptRecord]:
        records: list[AttemptRecord] = []
        record = adapter.run(
            attempt_id,
            start,
            admission,
            self._clock.wall(),
            purpose=purpose,
            redirect_purpose=redirect_purpose,
            max_redirects=max_redirects,
            source_cap=source_cap,
            redirect_hook=redirect_hook,
            use_credentials=use_credentials,
            request_headers=request_headers,
        )
        records.append(record)
        scheduling = self._policy.scheduling
        while self._retry_eligible(record) and len(records) <= self._policy.budgets.retries:
            delay = scheduling.retry_backoff + self._random() * scheduling.retry_jitter
            usage = admission.usage()
            if usage.retries_used >= self._policy.budgets.retries:
                break
            if usage.requests >= self._policy.budgets.max_requests:
                break
            if consume_attempt and usage.attempts >= self._policy.budgets.max_attempts:
                break
            if admission.remaining() <= delay + 0.05:
                break
            host = self._final_host(record)
            if host is not None and self._safety.cooldown_remaining(host) > admission.remaining() - delay:
                break
            if consume_attempt:
                if not admission.reserve_retry_and_attempt():
                    break
            elif not admission.reserve_retry():
                break
            if delay > 0:
                self._sleep(delay)
            if admission.remaining() <= 0:
                break
            record = adapter.run(
                _next_attempt_id(),
                start,
                admission,
                self._clock.wall(),
                purpose=purpose,
                redirect_purpose=redirect_purpose,
                max_redirects=max_redirects,
                source_cap=source_cap,
                redirect_hook=redirect_hook,
                use_credentials=use_credentials,
                request_headers=request_headers,
            )
            records.append(record)
        return records

    def fetch(self, url: str, *, mode: str = "auto", timeout: float = 20) -> FetchResult:
        """Acquire one resource. ``_fetch`` is the same call with an internal cancel token."""
        return self._fetch(url, mode=mode, timeout=timeout)

    def _fetch(
        self,
        url: str,
        *,
        mode: str = "auto",
        timeout: float = 20,
        cancel: CancellationToken | None = None,
    ) -> FetchResult:
        # No lock/network work may occur on an object inherited across fork().
        self._assert_usable()
        if not isinstance(url, str):
            raise TypeError("url must be a str")
        credentials = self._session.snapshot() if self._session is not None else None
        if self._profile is not None and credentials is not None and credentials.has_cookies():
            # A profile is a browser identity of its own; Session cookies are a separate one.
            raise ConfigurationError("profile cannot be combined with Session cookies")
        policy = self._policy
        resolved_mode = policy.validate_call(mode, timeout)
        admission = Admission(policy.budgets, float(timeout), self._clock, cancel)
        evidence: list[Evidence] = []
        if self._profile is not None and resolved_mode is Mode.HTTP:
            # A profile applies to browser attempts only.
            evidence.append(Evidence("profile.not_applied_http", EvidenceCategory.OBSERVATION, True))
        attempts: list[AttemptRecord] = []
        redirect_evidence: list[Evidence] = []
        memory_host: str | None = None
        fallback_reason: str | None = None
        browser_attempted = False

        def result(
            stop_reason: str | None,
            prefer_rendered: bool = False,
            outcome_override: Outcome | None = None,
        ) -> FetchResult:
            selection = select(
                tuple(attempts),
                Requirements(
                    require_rendering=policy.readiness.requires_browser,
                    prefer_rendered=prefer_rendered,
                ),
            )
            final_outcome = selection.outcome
            if outcome_override is not None and not attempts:
                final_outcome = outcome_override
            if stop_reason is None and selection.attempt_id is not None:
                chosen = next(a for a in attempts if a.id == selection.attempt_id)
                stop_reason = chosen.reasons[-1] if chosen.reasons else None
            self._remember(
                memory_host,
                mode=resolved_mode,
                attempts=tuple(attempts),
                selection=selection,
                outcome=final_outcome,
                fallback_reason=fallback_reason,
            )
            if self._memory is not None:
                evidence.extend(self._memory._drain_notices())
            all_evidence = tuple(evidence) + tuple(redirect_evidence) + tuple(
                e for a in attempts for e in a.evidence
            )
            diagnostics = Diagnostics(
                policy_version=POLICY_VERSION,
                access=policy.access.mode,
                budget=admission.usage(),
                selection_reason=selection.reason,
                stop_reason=stop_reason,
                evidence=all_evidence,
            )
            return FetchResult(
                requested_url=url,
                outcome=final_outcome,
                attempts=tuple(attempts),
                diagnostics=diagnostics,
                selected_attempt_id=selection.attempt_id,
            )

        try:
            canonical = canonicalize(url)
        except SafetyRejection as rejection:
            evidence.append(
                Evidence(
                    rejection.code, EvidenceCategory.OBSERVATION, True,
                    facts=(("detail", rejection.detail),),
                )
            )
            return result(rejection.code)

        try:
            lease = self._safety.acquire_acquisition(
                admission.remaining(), policy.scheduling.active_acquisitions
            )
        except HostDenied as denied:
            evidence.append(Evidence(denied.code, EvidenceCategory.OBSERVATION, True))
            return result(denied.code)

        memory_host = canonical.host
        browser_failure: str | None = None

        def try_browser() -> AttemptRecord | None:
            nonlocal browser_failure, browser_attempted
            browser_attempted = True
            bstatus = browser_status()
            if not bstatus.available:
                browser_failure = bstatus.code or "backend.unavailable"
                evidence.append(
                    Evidence(
                        browser_failure,
                        EvidenceCategory.OBSERVATION,
                        True,
                        facts=(("detail", bstatus.detail),) + bstatus.facts,
                    )
                )
                return None
            if policy.budgets.browser_navigations <= 0:
                browser_failure = "budget.browser_navigations"
                evidence.append(
                    Evidence("budget.browser_navigations", EvidenceCategory.OBSERVATION, True)
                )
                return None
            if admission.remaining() <= 0:
                browser_failure = "budget.deadline"
                evidence.append(Evidence("budget.deadline", EvidenceCategory.OBSERVATION, True))
                return None
            try:
                admission.reserve_attempt()
            except Denied as denied:
                browser_failure = denied.code
                evidence.append(Evidence(denied.code, EvidenceCategory.OBSERVATION, True))
                return None
            try:
                return run_browser(
                    policy,
                    admission,
                    guard,
                    self._safety,
                    self._robots,
                    start=canonical,
                    attempt_id=_next_attempt_id(),
                    started_wall=self._clock.wall(),
                    credentials=credentials,
                    pool=self._browser_pool,
                    profile=self._profile,
                )
            except _BrowserUnavailable as unavailable:
                browser_failure = unavailable.status.code or "backend.unavailable"
                evidence.append(
                    Evidence(
                        browser_failure,
                        EvidenceCategory.OBSERVATION,
                        True,
                        facts=(("detail", unavailable.status.detail),) + unavailable.status.facts,
                    )
                )
            except _BrowserOperationalError as exc:
                browser_failure = exc.code or "backend.unavailable"
                evidence.append(
                    Evidence(
                        browser_failure,
                        EvidenceCategory.OBSERVATION,
                        True,
                        facts=(("detail", exc.detail),),
                    )
                )
            return None

        try:
            guard = DestinationGuard(policy.destinations, self._resolver)

            now_wall = self._clock.wall()
            if self._memory is not None:
                remembered = self._memory._cooldown_remaining(
                    canonical.host, now_wall, self._clock.monotonic()
                )
                if remembered > 0:
                    evidence.append(
                        Evidence(
                            "memory.cooldown",
                            EvidenceCategory.OBSERVATION,
                            True,
                            facts=(("remaining", f"{remembered:.3f}"),),
                        )
                    )
                    return result("host.cooldown", outcome_override=Outcome.RATE_LIMITED)

            if resolved_mode is Mode.BROWSER:
                if self._safety.cooldown_remaining(canonical.host) > 0:
                    evidence.append(
                        Evidence("host.cooldown", EvidenceCategory.OBSERVATION, True)
                    )
                    return result("host.cooldown", outcome_override=Outcome.RATE_LIMITED)
                if policy.access.mode == "automated":
                    http_status = backend_status()
                    if not http_status.available:
                        code = http_status.code or "backend.unavailable"
                        evidence.append(
                            Evidence(
                                code,
                                EvidenceCategory.OBSERVATION,
                                True,
                                facts=(("detail", "robots transport unavailable for browser"),
                                       ("backend_detail", http_status.detail)) + http_status.facts,
                            )
                        )
                        return result(code)
                if policy.access.mode == "user_initiated":
                    evidence.append(Evidence("access.user_initiated", EvidenceCategory.OBSERVATION, True))
                record = try_browser()
                if record is None:
                    return result(browser_failure or "backend.unavailable")
                attempts.append(record)
                return result(None, prefer_rendered=True)

            if resolved_mode is Mode.AUTO and self._memory is not None:
                age = self._memory._browser_first_age(canonical.host, now_wall)
                if age is not None:
                    # Advisory only: this host needed the browser before. One browser
                    # attempt, then at most the ordinary HTTP attempt if it fails.
                    evidence.append(
                        Evidence(
                            "memory.browser_first",
                            EvidenceCategory.OBSERVATION,
                            True,
                            facts=(("age", f"{age:.3f}"),),
                        )
                    )
                    first = try_browser()
                    if first is not None:
                        attempts.append(first)
                        if first.outcome is not Outcome.ERROR:
                            return result(None, prefer_rendered=True)

            status = backend_status()
            if not status.available:
                code = status.code or "backend.unavailable"
                evidence.append(
                    Evidence(
                        code, EvidenceCategory.OBSERVATION, True,
                        facts=(("detail", status.detail),) + status.facts,
                    )
                )
                return result(code)

            adapter = CurlHTTPAdapter(
                policy, guard, safety=self._safety, credentials=credentials
            )

            def decide(target: CanonicalURL) -> RobotsDecision:
                return self._robots.decide(
                    target,
                    policy,
                    admission,
                    lambda: self._robots_fetch_for(target, adapter, admission),
                    now_wall=self._clock.wall,
                )

            if policy.access.mode == "user_initiated":
                evidence.append(Evidence("access.user_initiated", EvidenceCategory.OBSERVATION, True))
            else:
                decision = decide(canonical)
                evidence.extend(decision.evidence)
                if not decision.allowed:
                    return result(decision.reason or "access.robots_unreachable", outcome_override=decision.outcome)

            def redirect_hook(target: CanonicalURL) -> tuple[str | None, Outcome | None]:
                if policy.access.mode != "automated":
                    return None, None
                decision = self._robots.decide(
                    target,
                    policy,
                    admission,
                    lambda: self._robots_fetch_for(target, adapter, admission),
                    now_wall=self._clock.wall,
                )
                redirect_evidence.extend(decision.evidence)
                if not decision.allowed:
                    return decision.reason, decision.outcome
                return None, None

            # The cache answers only the HTTP attempt, only for anonymous requests, and never
            # when this call must be rendered: a fresh copy costs nothing, a stale copy with a
            # validator is revalidated through the normal guarded path (so pacing, cooldown and
            # budgets apply to it).
            # Credentialed requests neither read nor write the shared anonymous cache.
            # A profile is a credentialed identity too: neither read nor write for it.
            active_cache = (
                self._cache
                if credentials is None and self._profile is None and not policy.readiness.requires_browser
                else None
            )
            fingerprint = ""
            sent_headers: dict[str, str] = {}
            cached: CacheEntry | None = None
            conditional: tuple[tuple[str, str], ...] = ()
            served_from_cache = False
            if active_cache is not None:
                fingerprint = policy_fingerprint(
                    policy.access.mode, policy.transport.user_agent, policy.transport.ca_bundle
                )
                sent_headers = dict(adapter.request_headers)
                cached = active_cache._lookup(canonical.url, fingerprint, sent_headers)
                if cached is not None and cached.fresh(self._clock.wall()):
                    attempts.append(
                        cache_attempt(
                            cached,
                            attempt_id=_next_attempt_id(),
                            requested_url=url,
                            now_wall=self._clock.wall(),
                        )
                    )
                    cached = None
                    served_from_cache = True
                elif cached is not None and cached.can_revalidate():
                    conditional = cached.conditional_headers()
                elif cached is not None:
                    # Fresh again can never come from a copy without a validator.
                    active_cache._discard(cached)
                    cached = None

            if not served_from_cache:
                try:
                    admission.reserve_attempt()
                except Denied as denied:
                    return result(denied.code)
                records = self._run_with_retry(
                    adapter,
                    admission,
                    canonical,
                    attempt_id=_next_attempt_id(),
                    purpose="resource",
                    redirect_purpose="redirect",
                    max_redirects=policy.budgets.max_redirects,
                    source_cap=policy.budgets.max_source_bytes,
                    redirect_hook=redirect_hook,
                    consume_attempt=True,
                    use_credentials=credentials is not None,
                    request_headers=conditional,
                )
                only = records[0] if len(records) == 1 else None
                if (
                    conditional
                    and active_cache is not None
                    and cached is not None
                    and only is not None
                    and only.source is not None
                    and only.source.status_code == 304
                ):
                    refreshed = active_cache._refresh(
                        cached,
                        only.source.headers,
                        now_wall=self._clock.wall(),
                        sent_headers=sent_headers,
                    )
                    attempts.append(
                        cache_attempt(
                            refreshed,
                            attempt_id=only.id,
                            requested_url=url,
                            now_wall=self._clock.wall(),
                            started_at=only.started_at,
                            duration=only.duration,
                            requests=only.requests,
                            revalidated_status=304,
                        )
                    )
                else:
                    attempts.extend(records)
                    if active_cache is not None and credentials is None and records:
                        last = records[-1]
                        if last.outcome is Outcome.SUCCESS and last.source is not None:
                            store_response(
                                active_cache,
                                last.source,
                                fingerprint=fingerprint,
                                sent_headers=sent_headers,
                                now_wall=self._clock.wall(),
                                max_bytes=policy.budgets.max_source_bytes,
                            )

            if resolved_mode is Mode.AUTO:
                if (
                    attempts
                    and not browser_attempted
                    and not any(a.outcome in RESTRICTION_OUTCOMES for a in attempts)
                ):
                    pre = select(tuple(attempts), Requirements())
                    chosen = next((a for a in attempts if a.id == pre.attempt_id), None)
                    if (
                        chosen is not None
                        and (chosen.outcome is Outcome.SUCCESS or "http.accepted_incomplete" in chosen.reasons)
                        and not any(
                            reason.startswith(("safety.", "access.", "budget."))
                            for reason in chosen.reasons
                        )
                    ):
                        if "http.accepted_incomplete" in chosen.reasons:
                            fallback_reason = "http.accepted_incomplete"
                        elif policy.readiness.requires_browser:
                            fallback_reason = "explicit_rendering"
                        elif chosen.source is not None and chosen.source.kind is ResourceKind.HTML:
                            shell = detect_js_shell(chosen.source.decoded_text)
                            evidence.append(
                                Evidence(
                                    "evidence.js_shell",
                                    EvidenceCategory.OBSERVATION,
                                    shell.detected,
                                    chosen.id,
                                    facts=(
                                        ("visible_text", str(shell.visible_text)),
                                        ("scripts", str(shell.scripts)),
                                        ("root_markers", str(shell.root_markers)),
                                    ),
                                )
                            )
                            if shell.detected:
                                fallback_reason = "js_shell"
                if fallback_reason is not None:
                    evidence.append(
                        Evidence(
                            "browser.fallback",
                            EvidenceCategory.OBSERVATION,
                            True,
                            facts=(("reason", fallback_reason),),
                        )
                    )
                    record = try_browser()
                    if record is not None:
                        attempts.append(record)
                        # Selection keeps an earlier policy-satisfying HTTP success when the
                        # optional heuristic fallback is restricted, including a challenge or
                        # login restriction observed only in the browser. With explicit
                        # rendering requirements the HTTP attempt cannot satisfy selection, so
                        # the browser restriction is still surfaced.
                        return result(None, prefer_rendered=True)
            return result(None)
        finally:
            lease.release()

    def interactive(
        self,
        url: str,
        *,
        until_url: str | None = None,
        until_selector: str | None = None,
        timeout: float = 300.0,
        _headless_for_tests: bool = False,
        _page_hook: Callable[..., None] | None = None,
    ) -> InteractionResult:
        """Let a person use a visible browser on this fetcher's profile, then return.

        Requires ``Fetcher(profile=BrowserProfile(...))``; anything else raises
        :class:`~fetchward.ConfigurationError` before I/O. The session ends at the first of: the
        user closes the window or page (``closed``), the main frame URL starts with
        ``until_url`` or ``until_selector`` becomes attached (``condition``), or ``timeout``
        elapses (``timeout``). Cookies survive in the profile for later browser fetches.

        The library never clicks, types or fills a form: no automation runs inside the session.
        Every connection still goes through the guarded egress proxy, popups are allowed but
        stay inside it, resource blocking is off and downloads are refused. robots.txt does not
        apply, because a person initiated the session. ``_headless_for_tests`` and
        ``_page_hook`` are test seams, not public API.
        """
        self._assert_usable()
        if self._profile is None:
            raise ConfigurationError("interactive() requires Fetcher(profile=BrowserProfile(...))")
        snapshot = self._session.snapshot() if self._session is not None else None
        if snapshot is not None and snapshot.has_cookies():
            # Session cookies would silently not be applied: a hidden identity is worse than an
            # error. The profile itself is the browser identity here.
            raise ConfigurationError("interactive() cannot be combined with Session cookies")
        target = validate_session(url, until_url, until_selector, timeout)
        extra: tuple[Evidence, ...] = ()
        if snapshot is not None and snapshot.has_browser_headers(target):
            extra = (Evidence("session.headers_not_applied", EvidenceCategory.OBSERVATION, True),)
        return run_session(
            profile=self._profile,
            policy=self._policy,
            resolver=self._resolver,
            target=target,
            until_url=until_url,
            until_selector=until_selector,
            timeout=timeout,
            headless=_headless_for_tests,
            page_hook=_page_hook,
            extra_evidence=extra,
        )

    def _robots_fetch_for(
        self, target: CanonicalURL, adapter: CurlHTTPAdapter, admission: Admission
    ) -> AttemptRecord:
        robots_url = canonicalize(
            f"{target.scheme}://"
            + (f"[{target.host}]" if ":" in target.host else target.host)
            + f":{target.port}/robots.txt"
        )
        records = self._run_with_retry(
            adapter,
            admission,
            robots_url,
            attempt_id=_next_attempt_id(),
            purpose="robots",
            redirect_purpose="robots",
            max_redirects=min(
                self._policy.scheduling.robots_max_redirects,
                self._policy.budgets.max_robots_redirects,
            ),
            source_cap=self._policy.scheduling.robots_max_bytes,
            redirect_hook=None,
            consume_attempt=False,
            use_credentials=False,
        )
        return records[-1]


def fetch(url: str, *, mode: str = "auto", timeout: float = 20) -> FetchResult:
    """Acquire one resource with the default policy. Leaves no open session behind."""
    with Fetcher() as fetcher:
        return fetcher.fetch(url, mode=mode, timeout=timeout)


__all__ = ["Fetcher", "fetch"]
