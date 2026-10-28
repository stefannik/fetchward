"""Integration through the real public API, real curl transport and fixture receivers.

These tests cover the initial connection, redirect, status and safety scenarios; later
coverage extends them.
"""

from __future__ import annotations

import gzip
import json

import pytest

from harness import Reply
from fetchward import AccessPolicy, AcquisitionPolicy, Budgets, Fetcher, Outcome, ResourceKind

HTML = [("Content-Type", "text/html; charset=utf-8")]


def _assert_pinned(result) -> None:
    """Every dispatched request connected to exactly the address that was validated."""
    admitted = [e for a in result.attempts for e in a.requests if e.admitted]
    assert admitted
    for event in admitted:
        assert event.pinned_address == "127.0.0.1"
        assert event.connected_address == event.pinned_address


# -- C01: ordinary HTML, short, empty; ok is success-only ----------------------------------
@pytest.mark.parametrize(
    "body",
    [b"<!doctype html><html><body><article>" + b"long " * 500 + b"</article></body></html>", b"<html><img src=x></html>", b""],
    ids=["static", "short-image", "empty"],
)
def test_c01_html_success_regardless_of_length(make_fetcher, origins, body) -> None:
    origins["a"].route("/page", Reply(200, HTML, body))
    result = make_fetcher().fetch(origins["a"].url("/page"), mode="http")
    assert result.outcome is Outcome.SUCCESS and result.ok
    assert result.kind is ResourceKind.HTML
    assert result.response_body == body
    assert result.html == body.decode()
    assert result.rendered_html is None
    assert result.status_code == 200 and result.content_type == "text/html"
    assert result.final_url == origins["a"].url("/page")
    assert len(result.attempts) == 1 and result.attempts[0].backend == "direct-curl_cffi"
    assert result.diagnostics.access == "user_initiated"
    # The check runs; False means "no matching evidence", not proof that no challenge exists.
    assert result.diagnostics.summary()["challenge_detected"] is False
    assert origins["a"].log.paths() == ["/page"]
    _assert_pinned(result)


def test_c01_https_with_fixture_ca(make_fetcher, origins) -> None:
    origins["tls"].route("/secure", Reply(200, HTML, b"<html>tls</html>"))
    result = make_fetcher().fetch(origins["tls"].url("/secure"), mode="http")
    assert result.ok and result.html == "<html>tls</html>"
    _assert_pinned(result)


def test_auto_mode_runs_http_without_browser(make_fetcher, origins) -> None:
    origins["a"].route("/p", Reply(200, HTML, b"<html>x</html>"))
    result = make_fetcher().fetch(origins["a"].url("/p"))
    assert result.ok and len(result.attempts) == 1


# -- C02: compression and charsets (slice) --------------------------------------------------
def test_c02_gzip_and_charset(make_fetcher, origins) -> None:
    raw = '<html><meta charset="windows-1251">привет</html>'.encode("cp1251")
    origins["a"].route("/gz", Reply(200, [("Content-Type", "text/html"), ("Content-Encoding", "gzip")], gzip.compress(raw)))
    result = make_fetcher().fetch(origins["a"].url("/gz"), mode="http")
    assert result.ok
    assert result.response_body == raw  # after content decoding, before character decoding
    assert result.encoding.content_encoding == ("gzip",) and result.encoding.content_decoded
    assert result.encoding.source == "meta" and "привет" in result.html


def test_c02_missing_type_sniffed_html(make_fetcher, origins) -> None:
    origins["a"].route("/notype", Reply(200, [], b"<!DOCTYPE html><html>hi</html>"))
    result = make_fetcher().fetch(origins["a"].url("/notype"), mode="http")
    assert result.kind is ResourceKind.HTML and result.content_type is None
    assert result.attempts[0].source.inferred_media_type == "text/html"


# -- C03: non-HTML bytes --------------------------------------------------------------------
def test_c03_json_and_binary(make_fetcher, origins) -> None:
    payload = json.dumps({"k": [1, 2]}).encode()
    pdf = b"%PDF-1.7\n" + bytes(range(256)) * 10
    origins["a"].route("/data.json", Reply(200, [("Content-Type", "application/json")], payload))
    origins["a"].route("/doc.pdf", Reply(200, [("Content-Type", "application/pdf")], pdf))
    fetcher = make_fetcher()
    data = fetcher.fetch(origins["a"].url("/data.json"), mode="http")
    assert data.ok and data.kind is ResourceKind.JSON and data.response_body == payload and data.html is None
    doc = fetcher.fetch(origins["a"].url("/doc.pdf"), mode="http")
    assert doc.ok and doc.kind is ResourceKind.FILE and doc.response_body == pdf and doc.html is None
    assert doc.content_type == "application/pdf"


def test_c03_html_like_bytes_declared_binary_stay_binary(make_fetcher, origins) -> None:
    origins["a"].route("/bin", Reply(200, [("Content-Type", "application/octet-stream")], b"<html>trick</html>"))
    result = make_fetcher().fetch(origins["a"].url("/bin"), mode="http")
    assert result.kind is ResourceKind.FILE and result.html is None
    assert any(e.code == "evidence.media_type_disagreement" for e in result.diagnostics.evidence)


# -- C05: redirects --------------------------------------------------------------------------
def test_c05_same_and_cross_origin_chain(make_fetcher, origins) -> None:
    a, b = origins["a"], origins["b"]
    a.route("/start", Reply(301, [("Location", "/hop")]))
    a.route("/hop", Reply(302, [("Location", b.url("/final"))]))
    b.route("/final", Reply(200, HTML, b"<html>done</html>"))
    result = make_fetcher().fetch(a.url("/start"), mode="http")
    assert result.ok and result.final_url == b.url("/final")
    hops = result.attempts[0].redirects
    assert [(h.from_url, h.to_url, h.status_code) for h in hops] == [
        (a.url("/start"), a.url("/hop"), 301),
        (a.url("/hop"), b.url("/final"), 302),
    ]
    assert result.diagnostics.budget.requests == 3 and result.diagnostics.budget.redirects == 2
    assert a.log.paths() == ["/start", "/hop"] and b.log.paths() == ["/final"]
    _assert_pinned(result)


def test_c05_loop_stops(make_fetcher, origins) -> None:
    a = origins["a"]
    a.route("/x", Reply(302, [("Location", "/y")]))
    a.route("/y", Reply(302, [("Location", "/x")]))
    result = make_fetcher().fetch(a.url("/x"), mode="http")
    assert result.outcome is Outcome.ERROR and "http.redirect_loop" in result.attempts[0].reasons
    assert a.log.paths() == ["/x", "/y"]


def test_c05_cap_exhaustion_sends_no_excess_request(make_fetcher, origins) -> None:
    a = origins["a"]
    for i in range(10):
        a.route(f"/r{i}", Reply(302, [("Location", f"/r{i + 1}")]))
    fetcher = make_fetcher(policy=AcquisitionPolicy(budgets=Budgets(max_redirects=3)))
    result = fetcher.fetch(a.url("/r0"), mode="http")
    assert result.outcome is Outcome.ERROR
    assert result.diagnostics.stop_reason == "budget.redirects"
    assert a.log.paths() == ["/r0", "/r1", "/r2", "/r3"]  # 3 follows, the 4th never sent


def test_request_cap_counts_redirects(make_fetcher, origins) -> None:
    a = origins["a"]
    for i in range(5):
        a.route(f"/r{i}", Reply(302, [("Location", f"/r{i + 1}")]))
    result = make_fetcher(policy=AcquisitionPolicy(budgets=Budgets(max_requests=2))).fetch(a.url("/r0"), mode="http")
    assert result.diagnostics.stop_reason == "budget.requests" and len(a.log) == 2


# -- C06: status outcomes keep their bodies -----------------------------------------------------
def test_202_is_partial_and_retains_body(make_fetcher, origins) -> None:
    body = b"<html>processing</html>"
    origins["a"].route("/accepted", Reply(202, HTML, body))
    result = make_fetcher().fetch(origins["a"].url("/accepted"), mode="http")
    assert result.outcome is Outcome.PARTIAL and not result.ok
    assert result.response_body == body
    assert "http.accepted_incomplete" in result.selected.reasons
    assert any(e.code == "http.accepted_incomplete" for e in result.diagnostics.evidence)


@pytest.mark.parametrize(
    "status,outcome",
    [(401, Outcome.AUTH_REQUIRED), (403, Outcome.BLOCKED), (429, Outcome.RATE_LIMITED), (404, Outcome.ERROR), (500, Outcome.ERROR)],
)
def test_c06_status_outcomes(make_fetcher, origins, status, outcome) -> None:
    origins["a"].route("/s", Reply(status, HTML + [("Retry-After", "30")], b"<html>denied</html>"))
    result = make_fetcher().fetch(origins["a"].url("/s"), mode="http")
    assert result.outcome is outcome and not result.ok
    assert result.status_code == status and result.response_body == b"<html>denied</html>"
    assert result.response_headers.get("retry-after") == "30"


# -- C07: truncation, budget and connection failures are results ----------------------------------
def test_c07_truncated_body_is_partial(make_fetcher, origins) -> None:
    origins["a"].route("/t", Reply(200, HTML, b"<html>" + b"x" * 5000, truncate_at=100))
    result = make_fetcher().fetch(origins["a"].url("/t"), mode="http")
    assert result.outcome is Outcome.PARTIAL
    source = result.attempts[0].source
    assert not source.complete and source.interruption == "network.interrupted"
    assert result.response_body == (b"<html>" + b"x" * 5000)[:100]


def test_c07_byte_cap_is_partial(make_fetcher, origins) -> None:
    origins["a"].route("/big", Reply(200, HTML, b"y" * 200_000))
    policy = AcquisitionPolicy(budgets=Budgets(max_source_bytes=1000))
    result = make_fetcher(policy=policy).fetch(origins["a"].url("/big"), mode="http")
    assert result.outcome is Outcome.PARTIAL and len(result.response_body) == 1000
    assert result.attempts[0].source.interruption == "budget.bytes"


def test_c07_connect_failure_is_error_result(make_fetcher) -> None:
    from harness import FixtureOrigin

    dead = FixtureOrigin("origin-b.test")
    url = dead.url("/gone")
    dead.close()
    result = make_fetcher(extra_trust=(dead.trusted(),)).fetch(url, mode="http")
    assert result.outcome is Outcome.ERROR and result.response_body is None
    assert "network.connect" in result.attempts[0].reasons


def test_c07_dns_failure_is_error_result(make_fetcher, origins, resolver) -> None:
    del resolver.answers["origin-b.test"]
    result = make_fetcher().fetch(origins["b"].url("/"), mode="http")
    assert result.outcome is Outcome.ERROR and "network.dns" in result.attempts[0].reasons


def test_c07_tls_failure_without_fixture_ca(origins, resolver) -> None:
    from fetchward import DestinationPolicy

    origins["tls"].route("/", Reply(200, HTML, b"x"))
    policy = AcquisitionPolicy(
        access=AccessPolicy(mode="user_initiated"),
        destinations=DestinationPolicy(trusted_local=(origins["tls"].trusted(),)),
    )
    result = Fetcher(policy, _resolver=resolver).fetch(origins["tls"].url("/"), mode="http")
    assert result.outcome is Outcome.ERROR and "network.tls" in result.attempts[0].reasons


def test_browser_mode_is_explicitly_unavailable_when_backend_missing(monkeypatch, make_fetcher, origins) -> None:
    from fetchward._browser import BrowserStatus

    monkeypatch.setattr(
        "fetchward._fetcher.browser_status",
        lambda: BrowserStatus(False, "backend.unavailable", "fixture browser unavailable"),
    )
    result = make_fetcher().fetch(origins["a"].url("/"), mode="browser")
    assert result.outcome is Outcome.ERROR and result.diagnostics.stop_reason == "backend.unavailable"
    assert len(origins["a"].log) == 0


def test_automated_robots_404_allows_target_and_is_cached(origins, resolver, make_fetcher) -> None:
    origins["a"].route("/", Reply(200, HTML, b"<html>robots missing</html>"))
    fetcher = make_fetcher(access=AccessPolicy(mode="automated"))
    first = fetcher.fetch(origins["a"].url("/"), mode="http")
    assert first.ok and first.html == "<html>robots missing</html>"
    assert origins["a"].log.paths() == ["/robots.txt", "/"]
    second = fetcher.fetch(origins["a"].url("/"), mode="http")
    assert second.ok
    assert origins["a"].log.paths() == ["/robots.txt", "/", "/"]


# -- S01/S02: forbidden destinations are never contacted -------------------------------------------
def test_s01_public_policy_rejects_loopback_fixture(make_fetcher, origins) -> None:
    forbidden = origins["forbidden"]
    forbidden.route("/", Reply(200, HTML, b"should never be served"))
    fetcher = make_fetcher(trust=())  # public policy: no trusted-local allowances
    for url in (forbidden.url("/"), forbidden.ip_url("/"), f"http://[::ffff:127.0.0.1]:{forbidden.port}/"):
        result = fetcher.fetch(url, mode="http")
        assert result.outcome is Outcome.ERROR and result.response_body is None
        assert result.attempts[0].reasons == ("safety.destination_rejected",)
        assert result.diagnostics.budget.requests == 0
    for url in (f"http://2130706433:{forbidden.port}/", f"http://user:pw@127.0.0.1:{forbidden.port}/", "file:///etc/hosts"):
        result = fetcher.fetch(url, mode="http")
        assert result.outcome is Outcome.ERROR and result.diagnostics.stop_reason == "safety.url_rejected"
        assert result.attempts == ()
    assert len(forbidden.log) == 0


@pytest.mark.parametrize(
    "location_kind", ["named", "ip", "mapped", "metadata", "decimal", "scheme"],
)
def test_s02_redirect_to_forbidden_destination(make_fetcher, origins, location_kind) -> None:
    a, forbidden = origins["a"], origins["forbidden"]
    forbidden.route("/secret", Reply(200, HTML, b"internal"))
    location = {
        "named": forbidden.url("/secret"),
        "ip": forbidden.ip_url("/secret"),
        "mapped": f"http://[::ffff:127.0.0.1]:{forbidden.port}/secret",
        "metadata": "http://169.254.169.254/latest/meta-data/",
        "decimal": f"http://2130706433:{forbidden.port}/secret",
        "scheme": "file:///etc/passwd",
    }[location_kind]
    a.route("/go", Reply(302, [("Location", location)]))
    result = make_fetcher().fetch(a.url("/go"), mode="http")
    assert result.outcome is Outcome.ERROR and result.response_body is None
    reasons = result.attempts[0].reasons
    assert reasons[-1] in ("safety.destination_rejected", "safety.url_rejected")
    assert len(forbidden.log) == 0
    assert a.log.paths() == ["/go"]


def test_trusted_origin_cannot_redirect_to_untrusted_local(make_fetcher, origins) -> None:
    a, b = origins["a"], origins["b"]
    a.route("/go", Reply(302, [("Location", b.url("/x"))]))
    result = make_fetcher(trust=("a",)).fetch(a.url("/go"), mode="http")
    assert result.attempts[0].reasons == ("safety.destination_rejected",)
    assert len(b.log) == 0


# -- C13: safe diagnostics and reprs -----------------------------------------------------------------
def test_c13_repr_and_diagnostics_hide_caller_data(make_fetcher, origins) -> None:
    a = origins["a"]
    a.route("/canary-path", Reply(200, HTML + [("Set-Cookie", "sid=canary-cookie")], b"<html>canary-body</html>"))
    result = make_fetcher().fetch(a.url("/canary-path?token=canary-query"), mode="http")
    assert result.ok
    rendered = repr(result) + repr(result.attempts) + repr(result.diagnostics.summary())
    rendered += repr([e.target for e in result.attempts[0].requests])
    for canary in ("canary-path", "canary-query", "canary-cookie", "canary-body"):
        assert canary not in rendered
    assert "set-cookie" not in {k.lower() for k in result.response_headers}
    assert result.final_url.endswith("/canary-path?token=canary-query")  # caller data is still available


def test_closed_fetcher_rejects_use(make_fetcher) -> None:
    from fetchward import FetcherClosedError

    fetcher = make_fetcher()
    with fetcher:
        pass
    with pytest.raises(FetcherClosedError):
        fetcher.fetch("http://origin-a.test/", mode="http")
