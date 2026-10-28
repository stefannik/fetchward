"""Browser readiness, deadline and bounded-DOM behavior through the public Fetcher."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("playwright.sync_api")

from harness import Reply
from fetchward import AcquisitionPolicy, Budgets, Outcome

pytestmark = pytest.mark.browser

HTML = [("Content-Type", "text/html")]


def test_navigation_timeout_with_source_is_partial(origins, make_fetcher) -> None:
    a = origins["a"]

    def stall(request):
        time.sleep(3.0)
        return Reply(200, [("Content-Type", "application/javascript")], b"void 0;")

    body = (
        b"<!doctype html><html><body><div id='app'>STATIC</div>"
        b"<script src='/stall.js'></script></body></html>"
    )
    a.route("/page", Reply(200, HTML, body))
    a.route("/stall.js", stall)
    result = make_fetcher().fetch(a.url("/page"), mode="browser", timeout=2.0)
    assert result.outcome is Outcome.PARTIAL
    assert result.response_body is not None and b"STATIC" in result.response_body
    assert result.diagnostics.stop_reason == "browser.timeout"
    assert result.selected is not None and result.selected.source is not None
    assert "/page" in a.log.paths() and "/stall.js" in a.log.paths()


def test_navigation_timeout_without_source_stays_error(origins, make_fetcher) -> None:
    a = origins["a"]

    def hang(request):
        time.sleep(2.0)
        return Reply(200, HTML, b"<html><body>too late</body></html>")

    a.route("/hang", hang)
    result = make_fetcher().fetch(a.url("/hang"), mode="browser", timeout=0.7)
    assert result.outcome is Outcome.ERROR
    assert result.response_body is None
    assert result.rendered_html is None
    assert result.selected is not None
    assert result.selected.source is None


def test_large_dom_capture_is_bounded_and_reported_partial(origins, make_fetcher) -> None:
    a = origins["a"]
    body = b"<html><body>" + b"<div class='row'>item</div>" * 100_000 + b"</body></html>"
    a.route("/large", Reply(200, HTML, body))
    policy = AcquisitionPolicy(
        budgets=Budgets(
            max_source_bytes=4 * 1024 * 1024,
            max_dom_bytes=1024,
            max_total_bytes=8 * 1024 * 1024,
            retries=0,
        )
    )
    result = make_fetcher(policy=policy).fetch(a.url("/large"), mode="browser", timeout=15)
    assert result.outcome is Outcome.PARTIAL
    attempt = result.selected
    assert attempt is not None and attempt.source is not None
    assert attempt.rendered is None
    assert result.rendered_html is None
    assert attempt.readiness is not None and "dom_limit" in attempt.readiness.limits
    assert any(e.code == "evidence.dom_limit" for e in result.diagnostics.evidence)
    assert result.diagnostics.budget.retained_bytes <= 8 * 1024 * 1024
    assert len(result.response_body or b"") == len(body)
