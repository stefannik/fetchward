"""RFC 9309 parser and guarded-robots integration tests."""

from __future__ import annotations

import threading
import time

import pytest

from harness import Reply
from fetchward import AccessPolicy, AcquisitionPolicy, Budgets, SchedulingPolicy, Outcome
from fetchward._admission import Admission, SystemClock
from fetchward._robots import RobotsAuthority, RobotsCache, parse_robots
from fetchward._safety import canonicalize

HTML = [("Content-Type", "text/html")]


def _policy(**kwargs) -> AcquisitionPolicy:
    scheduling = SchedulingPolicy(min_host_interval=0.0, retry_backoff=0.0, retry_jitter=0.0)
    return AcquisitionPolicy(scheduling=scheduling, **kwargs)


def _automated(make_fetcher, **overrides):
    return make_fetcher(
        policy=_policy(budgets=overrides.pop("budgets", Budgets())),
        access=AccessPolicy(mode="automated"),
        **overrides,
    )


def test_parser_merges_specific_groups_and_ignores_star() -> None:
    rules = parse_robots(
        b"""# comment
User-agent: *
Disallow: /star

User-agent: fetchward
Disallow: /private
Allow: /private/public

User-agent: FETCHWARD/1.0
Disallow: /versioned

User-agent: other
Disallow: /other
"""
    )
    assert rules.allows("/star")
    assert not rules.allows("/private")
    assert rules.allows("/private/public")
    assert not rules.allows("/versioned")
    assert rules.allows("/other")


def test_parser_wildcards_end_anchor_and_longest_allow_tie() -> None:
    rules = parse_robots(
        b"""User-agent: *
Disallow: /*.pdf$
Allow: /docs/
Disallow: /docs/private
Allow: /tie
Disallow: /tie
"""
    )
    assert not rules.allows("/doc.pdf")
    assert rules.allows("/doc.pdf?download=1")
    assert rules.allows("/docs/public")
    assert not rules.allows("/docs/private")
    assert rules.allows("/tie")  # equal length: Allow wins


def test_parser_percent_encoding_and_malformed_lines() -> None:
    rules = parse_robots(
        b"""User-agent: fetchward
Disallow: /caf%C3%A9
Disallow: /a%2Fb
Disallow: /tilde%7E
not-a-rule
Crawl-delay: 9
Sitemap: https://example.test/s.xml
"""
    )
    assert not rules.allows("/caf%C3%A9")
    assert not rules.allows("/caf%c3%a9")
    assert not rules.allows("/a%2Fb")
    assert not rules.allows("/a%2fb")
    assert not rules.allows("/tilde~")
    assert rules.malformed == 1
    # Crawl-delay and unknown extension lines are ignored, not errors.
    assert rules.malformed == 1


def test_parser_truncates_and_does_not_treat_later_rules_as_visible() -> None:
    prefix = b"User-agent: *\n"
    body = prefix + b"#" * (512 * 1024) + b"\nDisallow: /late\n"
    rules = parse_robots(body)
    assert rules.truncated
    assert rules.allows("/late")  # no rule in retained prefix


def test_parser_within_cap_applies_rules() -> None:
    rules = parse_robots(b"User-agent: *\nDisallow: /private\n")
    assert not rules.truncated
    assert not rules.allows("/private")


def test_parser_compares_utf8_rule_against_percent_encoded_target() -> None:
    raw = "User-agent: *\nDisallow: /café\n".encode()
    percent = b"User-agent: *\nDisallow: /caf%C3%A9\n"
    for rules in (parse_robots(raw), parse_robots(percent)):
        assert not rules.allows("/caf%C3%A9")
        assert not rules.allows("/caf%c3%a9")
        assert not rules.allows("/café")
        assert rules.allows("/cafe")


def test_parser_non_ascii_octets_count_as_utf8_for_specificity() -> None:
    rules = parse_robots(
        "User-agent: *\nDisallow: /é\nAllow: /é/ok\n".encode()
    )
    assert not rules.allows("/%C3%A9")
    assert rules.allows("/%C3%A9/ok")


def test_empty_rule_line_terminates_the_user_agent_group() -> None:
    rules = parse_robots(
        b"User-agent: fetchward\nDisallow:\nUser-agent: *\nDisallow: /\n"
    )
    assert rules.allows("/article")


def test_end_anchor_is_part_of_specificity_and_allow_ties() -> None:
    anchored = parse_robots(
        b"User-agent: *\nDisallow: /foo$\nAllow: /foo\n"
    )
    assert not anchored.allows("/foo")
    assert anchored.allows("/foobar")
    tie = parse_robots(b"User-agent: *\nAllow: /same\nDisallow: /same\n")
    assert tie.allows("/same")


def test_adversarial_wildcards_are_linear_not_regex_backtracking() -> None:
    pattern = "/" + "a*" * 300 + "b"
    rules = parse_robots(b"User-agent: *\nDisallow: " + pattern.encode() + b"\n")
    target = "/" + "a" * 5000 + "b"
    started = time.monotonic()
    assert not rules.allows(target)
    assert time.monotonic() - started < 1.0


def test_long_literal_after_wildcard_is_bounded() -> None:
    pattern = "*" + "a" * 12_000 + "b"
    rules = parse_robots(b"User-agent: *\nDisallow: " + pattern.encode() + b"\n")
    target = "a" * 24_000
    started = time.monotonic()
    assert rules.allows(target)
    assert time.monotonic() - started < 0.5


def test_robots_matching_overrun_prevents_target_dispatch(monkeypatch, origins, make_fetcher) -> None:
    from fetchward import _robots

    real = _robots._glob_matches

    def slow_match(pattern, text, end_anchor):
        time.sleep(0.2)
        return real(pattern, text, end_anchor)

    monkeypatch.setattr(_robots, "_glob_matches", slow_match)
    origins["a"].route("/robots.txt", Reply(200, [], b"User-agent: *\nAllow: /\n"))
    origins["a"].route("/article", Reply(200, HTML, b"must not be served"))
    result = _automated(make_fetcher).fetch(
        origins["a"].url("/article"), mode="http", timeout=0.1
    )
    assert result.outcome is Outcome.ERROR
    assert result.diagnostics.stop_reason == "budget.deadline"
    assert origins["a"].log.paths() == ["/robots.txt"]


def test_unexpected_robots_fetch_exception_propagates() -> None:
    policy = AcquisitionPolicy(access=AccessPolicy(mode="automated"))
    admission = Admission(Budgets(), 1.0, SystemClock())
    authority = RobotsAuthority(RobotsCache())

    def programming_error():
        raise RuntimeError("programming error")

    with pytest.raises(RuntimeError, match="programming error"):
        authority.decide(
            canonicalize("http://origin-a.test/article"),
            policy,
            admission,
            programming_error,
        )


def test_automated_disallow_never_requests_target(origins, make_fetcher) -> None:
    origins["a"].route(
        "/robots.txt", Reply(200, [], b"User-agent: *\nDisallow: /private\n")
    )
    origins["a"].route("/private", Reply(200, HTML, b"must not be served"))
    result = _automated(make_fetcher).fetch(origins["a"].url("/private"), mode="http")
    assert result.outcome is Outcome.BLOCKED
    assert result.diagnostics.stop_reason == "access.robots_denied"
    assert result.response_body is None
    assert origins["a"].log.paths() == ["/robots.txt"]
    assert any(e.code == "access.robots_denied" for e in result.diagnostics.evidence)


def test_automated_utf8_disallow_never_requests_percent_encoded_target(origins, make_fetcher) -> None:
    origins["a"].route(
        "/robots.txt",
        Reply(200, [], "User-agent: *\nDisallow: /café\n".encode()),
    )
    origins["a"].route("/caf%C3%A9", Reply(200, HTML, b"must not be served"))
    result = _automated(make_fetcher).fetch(
        origins["a"].url("/caf%C3%A9"), mode="http"
    )
    assert result.outcome is Outcome.BLOCKED
    assert result.diagnostics.stop_reason == "access.robots_denied"
    assert origins["a"].log.paths() == ["/robots.txt"]


def test_empty_specific_rule_line_ends_group_and_allows_target(origins, make_fetcher) -> None:
    origins["a"].route(
        "/robots.txt",
        Reply(
            200,
            [],
            b"User-agent: fetchward\nDisallow:\nUser-agent: *\nDisallow: /\n",
        ),
    )
    origins["a"].route("/article", Reply(200, HTML, b"<html>article</html>"))
    result = _automated(make_fetcher).fetch(origins["a"].url("/article"), mode="http")
    assert result.ok and result.html == "<html>article</html>"
    assert origins["a"].log.paths() == ["/robots.txt", "/article"]


def test_automated_robots_requests_have_no_credentials(origins, make_fetcher) -> None:
    seen: list[dict[str, str]] = []

    def robots(request):
        seen.append(dict(request.headers))
        return Reply(200, [], b"User-agent: *\nAllow: /\n")

    origins["a"].route("/robots.txt", robots)
    origins["a"].route("/page", Reply(200, HTML, b"<html>ok</html>"))
    result = _automated(make_fetcher).fetch(origins["a"].url("/page"), mode="http")
    assert result.ok
    assert seen and "authorization" not in seen[0] and "cookie" not in seen[0]
    user_agent = seen[0].get("user-agent", "")
    assert "fetchward" in user_agent.lower()


@pytest.mark.parametrize(
    ("status", "outcome", "reason"),
    [
        (401, Outcome.AUTH_REQUIRED, "access.robots_unreachable"),
        (403, Outcome.BLOCKED, "access.robots_unreachable"),
        (429, Outcome.RATE_LIMITED, "host.cooldown"),
        (500, Outcome.ERROR, "access.robots_unreachable"),
        (418, Outcome.BLOCKED, "access.robots_denied"),
    ],
)
def test_robots_failure_modes_do_not_request_target(origins, make_fetcher, status, outcome, reason) -> None:
    origins["a"].route(
        "/robots.txt", Reply(status, [("Retry-After", "30")], b"robots failure")
    )
    origins["a"].route("/page", Reply(200, HTML, b"must not be served"))
    result = _automated(make_fetcher).fetch(origins["a"].url("/page"), mode="http")
    assert result.outcome is outcome
    assert result.diagnostics.stop_reason == reason
    assert origins["a"].log.paths() == ["/robots.txt"]


def test_robots_429_cooldown_blocks_later_calls_and_target(origins, make_fetcher) -> None:
    origins["a"].route("/robots.txt", Reply(429, [("Retry-After", "60")], b"later"))
    fetcher = _automated(make_fetcher)
    first = fetcher.fetch(origins["a"].url("/"), mode="http")
    assert first.outcome is Outcome.RATE_LIMITED
    assert origins["a"].log.paths() == ["/robots.txt"]
    second = fetcher.fetch(origins["a"].url("/"), mode="http")
    assert second.outcome is Outcome.RATE_LIMITED
    assert origins["a"].log.paths() == ["/robots.txt"]
    assert any(e.code == "host.cooldown" for e in second.diagnostics.evidence)


def test_target_redirect_checks_destination_origin_robots(origins, make_fetcher) -> None:
    a, b = origins["a"], origins["b"]
    a.route("/robots.txt", Reply(200, [], b"User-agent: *\nAllow: /\n"))
    b.route("/robots.txt", Reply(200, [], b"User-agent: *\nDisallow: /page\n"))
    a.route("/go", Reply(302, [("Location", b.url("/page"))]))
    b.route("/page", Reply(200, HTML, b"must not be served"))
    result = _automated(make_fetcher).fetch(a.url("/go"), mode="http")
    assert result.outcome is Outcome.BLOCKED
    assert result.diagnostics.stop_reason == "access.robots_denied"
    assert a.log.paths() == ["/robots.txt", "/go"]
    assert b.log.paths() == ["/robots.txt"]


def test_target_redirect_allowed_by_new_origin_robots(origins, make_fetcher) -> None:
    a, b = origins["a"], origins["b"]
    a.route("/robots.txt", Reply(200, [], b"User-agent: *\nAllow: /\n"))
    b.route("/robots.txt", Reply(200, [], b"User-agent: *\nAllow: /page\n"))
    a.route("/go", Reply(302, [("Location", b.url("/page"))]))
    b.route("/page", Reply(200, HTML, b"<html>redirected</html>"))
    result = _automated(make_fetcher).fetch(a.url("/go"), mode="http")
    assert result.ok and result.html == "<html>redirected</html>"
    assert a.log.paths() == ["/robots.txt", "/go"]
    assert b.log.paths() == ["/robots.txt", "/page"]


def test_robots_redirect_rules_apply_to_initial_origin(origins, make_fetcher) -> None:
    a, b = origins["a"], origins["b"]
    a.route("/robots.txt", Reply(302, [("Location", b.url("/rules"))]))
    b.route("/rules", Reply(200, [], b"User-agent: *\nDisallow: /secret\n"))
    a.route("/secret", Reply(200, HTML, b"must not be served"))
    result = _automated(make_fetcher).fetch(a.url("/secret"), mode="http")
    assert result.outcome is Outcome.BLOCKED
    assert result.diagnostics.stop_reason == "access.robots_denied"
    assert a.log.paths() == ["/robots.txt"]
    assert b.log.paths() == ["/rules"]


def test_oversized_robots_is_conservative_and_never_requests_target(origins, make_fetcher) -> None:
    body = b"User-agent: *\n" + b"#" * (512 * 1024) + b"\nDisallow: /secret\n"
    origins["a"].route("/robots.txt", Reply(200, [], body))
    origins["a"].route("/ok", Reply(200, HTML, b"must not be served"))
    result = _automated(make_fetcher).fetch(origins["a"].url("/ok"), mode="http")
    assert result.outcome is Outcome.ERROR
    assert result.diagnostics.stop_reason == "access.robots_unreachable"
    assert origins["a"].log.paths() == ["/robots.txt"]
    assert any(e.code == "access.robots_truncated" for e in result.diagnostics.evidence)


def test_robots_no_store_is_not_reused(origins, make_fetcher) -> None:
    count = 0

    def robots(request):
        nonlocal count
        count += 1
        return Reply(200, [("Cache-Control", "no-store")], b"User-agent: *\nAllow: /\n")

    origins["a"].route("/robots.txt", robots)
    origins["a"].route("/page", Reply(200, HTML, b"<html>ok</html>"))
    fetcher = _automated(make_fetcher)
    assert fetcher.fetch(origins["a"].url("/page"), mode="http").ok
    assert fetcher.fetch(origins["a"].url("/page"), mode="http").ok
    assert count == 2
    assert origins["a"].log.paths().count("/robots.txt") == 2


def test_concurrent_robots_lookups_are_deduplicated(origins, resolver, ca_bundle, make_fetcher) -> None:
    started = threading.Event()
    release = threading.Event()
    count = 0

    def robots(request):
        nonlocal count
        count += 1
        started.set()
        assert release.wait(5)
        return Reply(200, [], b"User-agent: *\nAllow: /\n")

    origins["a"].route("/robots.txt", robots)
    origins["a"].route("/page", Reply(200, HTML, b"<html>ok</html>"))
    fetchers = [_automated(make_fetcher), _automated(make_fetcher)]
    results = []

    def run(fetcher):
        results.append(fetcher.fetch(origins["a"].url("/page"), mode="http"))

    threads = [threading.Thread(target=run, args=(fetcher,)) for fetcher in fetchers]
    for thread in threads:
        thread.start()
    assert started.wait(5)
    time.sleep(0.1)
    release.set()
    for thread in threads:
        thread.join(10)
    assert len(results) == 2 and all(result.ok for result in results)
    assert count == 1
    assert origins["a"].log.paths().count("/robots.txt") == 1


def test_user_initiated_skips_robots_but_records_policy(origins, make_fetcher) -> None:
    origins["a"].route("/page", Reply(200, HTML, b"<html>ok</html>"))
    result = make_fetcher().fetch(origins["a"].url("/page"), mode="http")
    assert result.ok
    assert result.diagnostics.access == "user_initiated"
    assert any(e.code == "access.user_initiated" for e in result.diagnostics.evidence)
    assert origins["a"].log.paths() == ["/page"]


def test_robots_lookup_consumes_the_shared_request_cap(origins, make_fetcher) -> None:
    origins["a"].route("/robots.txt", Reply(200, [], b"User-agent: *\nAllow: /\n"))
    origins["a"].route("/page", Reply(200, HTML, b"must not be served"))
    fetcher = _automated(make_fetcher, budgets=Budgets(max_requests=1, retries=0))
    result = fetcher.fetch(origins["a"].url("/page"), mode="http")
    assert result.outcome is Outcome.ERROR
    assert result.diagnostics.stop_reason == "budget.requests"
    assert origins["a"].log.paths() == ["/robots.txt"]


def test_robots_redirect_to_forbidden_destination_fails_closed(origins, make_fetcher) -> None:
    a, b = origins["a"], origins["b"]
    a.route("/robots.txt", Reply(302, [("Location", b.url("/rules"))]))
    b.route("/rules", Reply(200, [], b"User-agent: *\nAllow: /\n"))
    a.route("/page", Reply(200, HTML, b"must not be served"))
    fetcher = make_fetcher(
        trust=("a",),
        policy=_policy(),
        access=AccessPolicy(mode="automated"),
    )
    result = fetcher.fetch(a.url("/page"), mode="http")
    assert result.outcome is Outcome.ERROR
    assert result.diagnostics.stop_reason == "safety.destination_rejected"
    assert a.log.paths() == ["/robots.txt"]
    assert b.log.paths() == []


def test_robots_deadline_prevents_target_request(origins, make_fetcher) -> None:
    def slow_robots(request):
        time.sleep(0.3)
        return Reply(200, [], b"User-agent: *\nAllow: /\n")

    origins["a"].route("/robots.txt", slow_robots)
    origins["a"].route("/page", Reply(200, HTML, b"must not be served"))
    fetcher = _automated(make_fetcher)
    result = fetcher.fetch(origins["a"].url("/page"), mode="http", timeout=0.1)
    assert result.outcome is Outcome.ERROR
    assert result.diagnostics.stop_reason == "budget.deadline"
    assert origins["a"].log.paths() == ["/robots.txt"]


def test_stale_deny_continues_to_deny_after_failed_refresh(origins, make_fetcher) -> None:
    count = 0

    def robots(request):
        nonlocal count
        count += 1
        if count == 1:
            return Reply(200, [("Cache-Control", "max-age=0")], b"User-agent: *\nDisallow: /secret\n")
        return Reply(500, [], b"refresh failed")

    origins["a"].route("/robots.txt", robots)
    origins["a"].route("/secret", Reply(200, HTML, b"must not be served"))
    fetcher = _automated(make_fetcher)
    first = fetcher.fetch(origins["a"].url("/secret"), mode="http")
    assert first.outcome is Outcome.BLOCKED
    second = fetcher.fetch(origins["a"].url("/secret"), mode="http")
    assert second.outcome is Outcome.BLOCKED
    assert second.diagnostics.stop_reason == "access.robots_denied"
    assert any(e.code == "access.robots_stale_deny" for e in second.diagnostics.evidence)
    assert origins["a"].log.paths() == ["/robots.txt", "/robots.txt"]


LOGIN_FORM = (
    b"<!doctype html><html><body><main>"
    b"<h1>Sign in to continue</h1>"
    b"<form action='/login' method='post'>"
    b"<label>Email <input name='email' type='email'></label>"
    b"<label>Password <input name='password' type='password'></label>"
    b"<button type='submit'>Sign in</button></form>"
    b"</main></body></html>"
)


@pytest.mark.parametrize(
    ("second", "outcome", "reason", "code"),
    [
        (
            Reply(200, [("Content-Type", "text/html")], LOGIN_FORM),
            Outcome.AUTH_REQUIRED,
            "http.login_required",
            "http.login_required",
        ),
        (
            Reply(429, [("Retry-After", "30")], b"rate limited"),
            Outcome.RATE_LIMITED,
            "host.cooldown",
            "host.cooldown",
        ),
        (
            Reply(401, [], b"auth required"),
            Outcome.AUTH_REQUIRED,
            "access.robots_unreachable",
            "http.auth_required",
        ),
    ],
)
def test_stale_disallow_does_not_override_newer_restriction(
    origins, make_fetcher, second, outcome, reason, code
) -> None:
    count = 0

    def robots(request):
        nonlocal count
        count += 1
        if count == 1:
            return Reply(
                200,
                [("Cache-Control", "max-age=0")],
                b"User-agent: *\nDisallow: /secret\n",
            )
        return second

    origins["a"].route("/robots.txt", robots)
    origins["a"].route("/secret", Reply(200, HTML, b"must not be served"))
    fetcher = _automated(make_fetcher)
    first = fetcher.fetch(origins["a"].url("/secret"), mode="http")
    assert first.outcome is Outcome.BLOCKED
    second_result = fetcher.fetch(origins["a"].url("/secret"), mode="http")
    assert second_result.outcome is outcome
    assert second_result.diagnostics.stop_reason == reason
    assert any(e.code == code for e in second_result.diagnostics.evidence)
    assert not any(
        e.code == "access.robots_stale_deny"
        for e in second_result.diagnostics.evidence
    )
    assert origins["a"].log.paths() == ["/robots.txt", "/robots.txt"]


def test_stale_allow_is_not_used_after_failed_refresh(origins, make_fetcher) -> None:
    count = 0

    def robots(request):
        nonlocal count
        count += 1
        if count == 1:
            return Reply(200, [("Cache-Control", "max-age=0")], b"User-agent: *\nAllow: /\n")
        return Reply(500, [], b"refresh failed")

    origins["a"].route("/robots.txt", robots)
    origins["a"].route("/page", Reply(200, HTML, b"<html>ok</html>"))
    fetcher = _automated(make_fetcher)
    assert fetcher.fetch(origins["a"].url("/page"), mode="http").ok
    second = fetcher.fetch(origins["a"].url("/page"), mode="http")
    assert second.outcome is Outcome.ERROR
    assert second.diagnostics.stop_reason == "access.robots_unreachable"
    assert origins["a"].log.paths() == ["/robots.txt", "/page", "/robots.txt"]


def test_robots_for_robots_is_nfetchwarded_recursively(origins, make_fetcher) -> None:
    origins["a"].route("/robots.txt", Reply(200, [], b"User-agent: *\nDisallow: /\n"))
    result = _automated(make_fetcher).fetch(origins["a"].url("/robots.txt"), mode="http")
    assert result.ok
    assert origins["a"].log.paths() == ["/robots.txt"]


def test_robots_410_is_known_unavailable_and_cached(origins, make_fetcher) -> None:
    count = 0

    def robots(request):
        nonlocal count
        count += 1
        return Reply(410, [], b"")

    origins["a"].route("/robots.txt", robots)
    origins["a"].route("/page", Reply(200, HTML, b"<html>ok</html>"))
    fetcher = _automated(make_fetcher)
    assert fetcher.fetch(origins["a"].url("/page"), mode="http").ok
    assert fetcher.fetch(origins["a"].url("/page"), mode="http").ok
    assert count == 1


def test_robots_max_age_is_honored_as_freshness(origins, make_fetcher) -> None:
    count = 0

    def robots(request):
        nonlocal count
        count += 1
        return Reply(200, [("Cache-Control", "max-age=60")], b"User-agent: *\nAllow: /\n")

    origins["a"].route("/robots.txt", robots)
    origins["a"].route("/page", Reply(200, HTML, b"<html>ok</html>"))
    fetcher = _automated(make_fetcher)
    assert fetcher.fetch(origins["a"].url("/page"), mode="http").ok
    assert fetcher.fetch(origins["a"].url("/page"), mode="http").ok
    assert count == 1


def test_robots_transient_retry_uses_shared_retry_token(origins, make_fetcher) -> None:
    count = 0

    def robots(request):
        nonlocal count
        count += 1
        if count == 1:
            return Reply(503, [], b"try again")
        return Reply(200, [], b"User-agent: *\nAllow: /\n")

    origins["a"].route("/robots.txt", robots)
    origins["a"].route("/page", Reply(200, HTML, b"<html>ok</html>"))
    fetcher = _automated(make_fetcher)
    result = fetcher.fetch(origins["a"].url("/page"), mode="http")
    assert result.ok
    assert count == 2
    assert result.diagnostics.budget.retries_used == 1
    assert origins["a"].log.paths() == ["/robots.txt", "/robots.txt", "/page"]


def test_robots_incomplete_body_is_conservative_and_not_cached(origins, make_fetcher) -> None:
    origins["a"].route(
        "/robots.txt",
        Reply(200, [], b"User-agent: *\nAllow: /\n", truncate_at=5),
    )
    origins["a"].route("/page", Reply(200, HTML, b"must not be served"))
    fetcher = _automated(make_fetcher)
    first = fetcher.fetch(origins["a"].url("/page"), mode="http")
    assert first.outcome is Outcome.ERROR
    assert first.diagnostics.stop_reason == "access.robots_unreachable"
    assert origins["a"].log.paths() == ["/robots.txt"]
    second = fetcher.fetch(origins["a"].url("/page"), mode="http")
    assert second.diagnostics.stop_reason == "access.robots_unreachable"
    assert origins["a"].log.paths() == ["/robots.txt", "/robots.txt"]


def test_https_robots_use_the_same_pinned_tls_path(origins, make_fetcher) -> None:
    origins["tls"].route("/robots.txt", Reply(200, [], b"User-agent: *\nAllow: /\n"))
    origins["tls"].route("/page", Reply(200, HTML, b"<html>tls robots</html>"))
    result = _automated(make_fetcher).fetch(origins["tls"].url("/page"), mode="http")
    assert result.ok and result.html == "<html>tls robots</html>"
    assert origins["tls"].log.paths() == ["/robots.txt", "/page"]


@pytest.mark.parametrize(
    "target",
    [
        "/public/../private",
        "/public/%2e%2e/private",
        "/public/.%2e/private",
        "/public/%2E./private",
    ],
)
def test_normalized_dot_path_cannot_bypass_robots(origins, make_fetcher, target) -> None:
    a = origins["a"]
    a.route("/robots.txt", Reply(200, [], b"User-agent: *\nDisallow: /private\n"))
    a.route("/private", Reply(200, HTML, b"<html>private</html>"))
    result = _automated(make_fetcher).fetch(a.url(target), mode="http")
    assert result.outcome is Outcome.BLOCKED
    assert result.diagnostics.stop_reason == "access.robots_denied"
    assert a.log.paths() == ["/robots.txt"]


@pytest.mark.parametrize(
    "robots_body",
    [
        b"<html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>",
        b"<html><body><h1>Sign in to continue</h1><form action='/login'>"
        b"<input name='password' type='password'></form></body></html>",
    ],
)
def test_robots_2xx_restriction_is_not_parsed_as_allow(origins, make_fetcher, robots_body) -> None:
    a = origins["a"]
    a.route("/robots.txt", Reply(200, HTML, robots_body))
    a.route("/private", Reply(200, HTML, b"<html>must not be requested</html>"))
    fetcher = _automated(make_fetcher)
    first = fetcher.fetch(a.url("/private"), mode="http")
    second = fetcher.fetch(a.url("/private"), mode="http")
    assert first.outcome in (Outcome.BLOCKED, Outcome.AUTH_REQUIRED)
    assert second.outcome in (Outcome.BLOCKED, Outcome.AUTH_REQUIRED)
    assert first.diagnostics.stop_reason in ("http.challenge", "http.login_required")
    assert second.diagnostics.stop_reason in ("http.challenge", "http.login_required")
    assert a.log.paths() == ["/robots.txt", "/robots.txt"]


def test_robots_bytes_do_not_charge_retained_resource_budget(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route(
        "/robots.txt",
        Reply(
            200,
            [("Content-Type", "text/plain")],
            b"User-agent: *\nAllow: /\n" + b"# padding\n" * 80,
        ),
    )
    a.route("/page", Reply(200, HTML, b"<html><body>ok</body></html>"))
    result = _automated(
        make_fetcher, budgets=Budgets(max_total_bytes=100, retries=0)
    ).fetch(a.url("/page"), mode="http")
    assert result.ok
    assert result.response_body == b"<html><body>ok</body></html>"
    assert a.log.paths() == ["/robots.txt", "/page"]
