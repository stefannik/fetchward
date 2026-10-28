"""Response cache through the public API, with each fixture receiver log as the oracle."""

from __future__ import annotations

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
    Readiness,
    ResponseCache,
    SchedulingPolicy,
    Session,
    TransportPolicy,
)

HTML = [("Content-Type", "text/html; charset=utf-8")]
CACHED = b"<html>cached</html>"
SVG = [("Content-Type", "image/svg+xml")]


class Clock:
    """Wall clock the cache judges freshness by; monotonic time stays fixed on purpose."""

    def __init__(self) -> None:
        self.wall_now = 1_700_000_000.0
        self.mono = 0.0

    def wall(self) -> float:
        return self.wall_now

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall_now += seconds


def build(
    origins,
    resolver,
    ca_bundle,
    *,
    cache: ResponseCache | None = None,
    clock: Clock | None = None,
    readiness: Readiness | None = None,
    user_agent: str | None = None,
    session: Session | None = None,
    browser_navigations: int = 1,
) -> Fetcher:
    return Fetcher(
        AcquisitionPolicy(
            access=AccessPolicy(mode="user_initiated"),
            destinations=DestinationPolicy(trusted_local=(origins["a"].trusted(),)),
            transport=TransportPolicy(ca_bundle=ca_bundle, user_agent=user_agent),
            readiness=readiness or Readiness(),
            scheduling=SchedulingPolicy(min_host_interval=0.0),
            budgets=Budgets(browser_navigations=browser_navigations),
        ),
        session=session,
        cache=cache,
        _resolver=resolver,
        _clock=clock,
    )


def test_fresh_hit_is_served_without_a_contact(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/page", Reply(200, HTML + [("Cache-Control", "max-age=60")], CACHED))
    cache, clock = ResponseCache(), Clock()
    assert (cache.max_entries, cache.max_bytes) == (256, 64 * 1024 * 1024)
    fetcher = build(origins, resolver, ca_bundle, cache=cache, clock=clock)

    first = fetcher.fetch(origins["a"].url("/page"), mode="http")
    clock.advance(10)
    second = fetcher.fetch(origins["a"].url("/page"), mode="http")

    assert first.ok and second.ok
    assert origins["a"].log.paths() == ["/page"]
    assert second.response_body == CACHED
    assert second.diagnostics.budget.requests == 0
    attempt = second.selected
    assert attempt is not None
    assert attempt.backend == "cache" and attempt.requests_dispatched == 0
    assert attempt.final_url == origins["a"].url("/page")
    assert attempt.source is not None and attempt.source.status_code == 200
    hit = [e.value for e in attempt.evidence if e.code == "cache.hit"]
    assert hit == [True]
    facts = dict(attempt.evidence[-1].facts)
    assert facts["age"] == "10.000"
    assert facts["stored_at"].startswith("2023-11-14T")
    assert len(cache) == 1

    cache.clear()
    assert len(cache) == 0
    assert fetcher.fetch(origins["a"].url("/page"), mode="http").diagnostics.budget.requests == 1
    assert origins["a"].log.paths() == ["/page", "/page"]


@pytest.mark.parametrize(
    "headers",
    [
        [("Cache-Control", "no-store")],
        [("Cache-Control", "private, max-age=60")],
        [("Cache-Control", "max-age=60"), ("Vary", "*")],
    ],
    ids=["no-store", "private", "vary-star"],
)
def test_unstorable_responses_are_not_kept(origins, resolver, ca_bundle, headers) -> None:
    origins["a"].route("/p", Reply(200, HTML + headers, CACHED))
    cache, clock = ResponseCache(), Clock()
    fetcher = build(origins, resolver, ca_bundle, cache=cache, clock=clock)

    fetcher.fetch(origins["a"].url("/p"), mode="http")
    fetcher.fetch(origins["a"].url("/p"), mode="http")

    assert len(origins["a"].log) == 2
    assert len(cache) == 0


def test_credentialed_response_is_not_stored(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/p", Reply(200, HTML + [("Cache-Control", "max-age=60")], CACHED))
    cache, clock = ResponseCache(), Clock()
    session = Session()
    session.add_credentials(origins["a"].url(), {"Authorization": "Bearer fixture"})
    try:
        fetcher = build(origins, resolver, ca_bundle, cache=cache, clock=clock, session=session)
        fetcher.fetch(origins["a"].url("/p"), mode="http")
        fetcher.fetch(origins["a"].url("/p"), mode="http")
    finally:
        session.close()

    assert origins["a"].log.paths() == ["/p", "/p"]
    assert origins["a"].log.requests[0].headers["authorization"] == "Bearer fixture"
    assert len(cache) == 0


def test_credentialed_request_never_reads_an_anonymous_copy(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/p", Reply(200, HTML + [("Cache-Control", "max-age=60")], CACHED))
    cache, clock = ResponseCache(), Clock()
    build(origins, resolver, ca_bundle, cache=cache, clock=clock).fetch(origins["a"].url("/p"), mode="http")
    assert len(cache) == 1
    session = Session()
    session.add_credentials(origins["a"].url(), {"Authorization": "Bearer fixture"})
    try:
        fetcher = build(origins, resolver, ca_bundle, cache=cache, clock=clock, session=session)
        result = fetcher.fetch(origins["a"].url("/p"), mode="http")
    finally:
        session.close()

    assert result.selected is not None and result.selected.backend != "cache"
    assert origins["a"].log.paths() == ["/p", "/p"]
    assert origins["a"].log.requests[1].headers["authorization"] == "Bearer fixture"


def test_stale_entry_revalidates_with_one_conditional_request(origins, resolver, ca_bundle) -> None:
    def handler(request) -> Reply:
        if request.headers.get("if-none-match") == '"v1"':
            return Reply(304, [("ETag", '"v1"'), ("Cache-Control", "max-age=60")])
        return Reply(200, HTML + [("ETag", '"v1"'), ("Cache-Control", "max-age=0")], CACHED)

    origins["a"].route("/p", handler)
    cache, clock = ResponseCache(), Clock()
    fetcher = build(origins, resolver, ca_bundle, cache=cache, clock=clock)

    assert fetcher.fetch(origins["a"].url("/p"), mode="http").ok
    clock.advance(5)
    second = fetcher.fetch(origins["a"].url("/p"), mode="http")

    assert [r.headers.get("if-none-match") for r in origins["a"].log.requests] == [None, '"v1"']
    assert second.ok and second.response_body == CACHED and second.status_code == 200
    assert second.diagnostics.budget.requests == 1
    revalidated = second.selected
    assert revalidated is not None
    codes = [e.code for e in revalidated.evidence]
    assert codes == ["cache.revalidated"]
    # The 304's max-age=60 refreshed the copy: the next fetch needs no network at all.
    third = fetcher.fetch(origins["a"].url("/p"), mode="http")
    assert third.ok and third.diagnostics.budget.requests == 0
    assert len(origins["a"].log) == 2


def test_stale_entry_is_replaced_by_a_200(origins, resolver, ca_bundle) -> None:
    def handler(request) -> Reply:
        if request.headers.get("if-none-match") == '"v1"':
            return Reply(200, HTML + [("ETag", '"v2"'), ("Cache-Control", "max-age=60")], b"<html>v2</html>")
        return Reply(200, HTML + [("ETag", '"v1"'), ("Cache-Control", "max-age=0")], b"<html>v1</html>")

    origins["a"].route("/p", handler)
    cache, clock = ResponseCache(), Clock()
    fetcher = build(origins, resolver, ca_bundle, cache=cache, clock=clock)

    fetcher.fetch(origins["a"].url("/p"), mode="http")
    replaced = fetcher.fetch(origins["a"].url("/p"), mode="http")
    assert replaced.response_body == b"<html>v2</html>"

    third = fetcher.fetch(origins["a"].url("/p"), mode="http")
    assert third.response_body == b"<html>v2</html>"
    assert third.diagnostics.budget.requests == 0
    assert len(origins["a"].log) == 2


def test_failed_revalidation_never_serves_the_stale_copy(origins, resolver, ca_bundle) -> None:
    def handler(request) -> Reply:
        if request.headers.get("if-none-match") == '"v1"':
            return Reply(500, HTML, b"<html>boom</html>")
        return Reply(200, HTML + [("ETag", '"v1"'), ("Cache-Control", "max-age=0")], CACHED)

    origins["a"].route("/p", handler)
    cache, clock = ResponseCache(), Clock()
    fetcher = build(origins, resolver, ca_bundle, cache=cache, clock=clock)

    fetcher.fetch(origins["a"].url("/p"), mode="http")
    failed = fetcher.fetch(origins["a"].url("/p"), mode="http")

    assert not failed.ok and failed.outcome is Outcome.ERROR
    assert failed.response_body == b"<html>boom</html>"
    assert not any(e.code in ("cache.hit", "cache.revalidated") for e in failed.diagnostics.evidence)
    assert len(origins["a"].log) == 2


def test_vary_keys_the_copy_by_the_request_headers_sent(origins, resolver, ca_bundle) -> None:
    origins["a"].route(
        "/p", Reply(200, HTML + [("Cache-Control", "max-age=60"), ("Vary", "User-Agent")], CACHED)
    )
    cache, clock = ResponseCache(), Clock()
    first = build(origins, resolver, ca_bundle, cache=cache, clock=clock, user_agent="Agent/1")
    second = build(origins, resolver, ca_bundle, cache=cache, clock=clock, user_agent="Agent/2")

    first.fetch(origins["a"].url("/p"), mode="http")
    second.fetch(origins["a"].url("/p"), mode="http")
    first.fetch(origins["a"].url("/p"), mode="http")

    assert len(origins["a"].log) == 2
    assert len(cache) == 2


@pytest.mark.parametrize(
    "readiness",
    [Readiness(require_rendering=True), Readiness(selector="#app")],
    ids=["require_rendering", "selector"],
)
def test_rendering_requirements_are_not_satisfied_by_the_cache(
    origins, resolver, ca_bundle, readiness
) -> None:
    origins["a"].route("/p", Reply(200, HTML + [("Cache-Control", "max-age=60")], CACHED))
    cache, clock = ResponseCache(), Clock()
    build(origins, resolver, ca_bundle, cache=cache, clock=clock).fetch(
        origins["a"].url("/p"), mode="http"
    )
    assert len(cache) == 1

    # No browser is launched: the navigation budget is zero, so only the HTTP attempt runs.
    rendering = build(
        origins, resolver, ca_bundle, cache=cache, clock=clock, readiness=readiness,
        browser_navigations=0,
    )
    result = rendering.fetch(origins["a"].url("/p"))

    assert len(origins["a"].log) == 2
    assert result.attempts[0].backend == "direct-curl_cffi"
    assert not any(e.code == "cache.hit" for e in result.diagnostics.evidence)


def test_browser_mode_never_reads_the_cache(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/p", Reply(200, HTML + [("Cache-Control", "max-age=60")], CACHED))
    cache, clock = ResponseCache(), Clock()
    build(origins, resolver, ca_bundle, cache=cache, clock=clock).fetch(
        origins["a"].url("/p"), mode="http"
    )
    assert len(cache) == 1

    result = build(
        origins, resolver, ca_bundle, cache=cache, clock=clock, browser_navigations=0
    ).fetch(origins["a"].url("/p"), mode="browser")

    assert not result.ok and result.diagnostics.stop_reason == "budget.browser_navigations"
    assert not any(e.code == "cache.hit" for e in result.diagnostics.evidence)
    assert len(origins["a"].log) == 1


@pytest.mark.parametrize(
    "cache",
    [ResponseCache(max_entries=1), ResponseCache(max_bytes=150)],
    ids=["entries", "bytes"],
)
def test_lru_evicts_the_least_recently_used_copy(origins, resolver, ca_bundle, cache) -> None:
    body = b"<html>" + b"x" * 94  # 100 bytes per stored copy
    for path in ("/a", "/b"):
        origins["a"].route(path, Reply(200, SVG + [("Cache-Control", "max-age=60")], body))
    clock = Clock()
    fetcher = build(origins, resolver, ca_bundle, cache=cache, clock=clock)

    fetcher.fetch(origins["a"].url("/a"), mode="http")
    fetcher.fetch(origins["a"].url("/b"), mode="http")
    fetcher.fetch(origins["a"].url("/a"), mode="http")

    assert origins["a"].log.paths() == ["/a", "/b", "/a"]
    assert len(cache) == 1


def test_expires_minus_date_and_the_age_header_set_the_lifetime(
    origins, resolver, ca_bundle
) -> None:
    def handler(_request) -> Reply:
        expires = datetime.now(timezone.utc) + timedelta(seconds=120)
        return Reply(
            200,
            HTML + [("Expires", format_datetime(expires, usegmt=True)), ("Age", "60")],
            CACHED,
        )

    origins["a"].route("/p", handler)
    cache, clock = ResponseCache(), Clock()
    fetcher = build(origins, resolver, ca_bundle, cache=cache, clock=clock)
    fetcher.fetch(origins["a"].url("/p"), mode="http")

    clock.advance(30)  # age 90 of ~120: still fresh
    assert fetcher.fetch(origins["a"].url("/p"), mode="http").diagnostics.budget.requests == 0
    clock.advance(40)  # age 130: stale, and without a validator the copy is dropped
    assert fetcher.fetch(origins["a"].url("/p"), mode="http").diagnostics.budget.requests == 1
    assert len(origins["a"].log) == 2


def test_cooldown_serves_fresh_hits_but_blocks_revalidation(origins, resolver, ca_bundle) -> None:
    origins["a"].route("/fresh", Reply(200, HTML + [("Cache-Control", "max-age=60")], CACHED))
    origins["a"].route(
        "/stale", Reply(200, HTML + [("Cache-Control", "max-age=0"), ("ETag", '"s"')], CACHED)
    )
    origins["a"].route("/limited", Reply(429, HTML + [("Retry-After", "5")], b"limited"))
    cache, clock = ResponseCache(), Clock()
    fetcher = build(origins, resolver, ca_bundle, cache=cache, clock=clock)

    assert fetcher.fetch(origins["a"].url("/fresh"), mode="http").ok
    assert fetcher.fetch(origins["a"].url("/stale"), mode="http").ok
    limited = fetcher.fetch(origins["a"].url("/limited"), mode="http")
    assert limited.outcome is Outcome.RATE_LIMITED
    contacts = len(origins["a"].log)

    clock.advance(1)
    hit = fetcher.fetch(origins["a"].url("/fresh"), mode="http")
    assert hit.ok and hit.diagnostics.budget.requests == 0
    assert len(origins["a"].log) == contacts

    blocked = fetcher.fetch(origins["a"].url("/stale"), mode="http")
    assert blocked.outcome is Outcome.RATE_LIMITED
    assert blocked.diagnostics.stop_reason == "host.cooldown"
    assert len(origins["a"].log) == contacts
