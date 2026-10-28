"""Browser source content-encoding handling with real Chromium and origin observation."""

from __future__ import annotations

import gzip

import pytest

pytest.importorskip("playwright.sync_api")

from harness import Reply
from fetchward import AcquisitionPolicy, Budgets, Outcome

pytestmark = pytest.mark.browser

HTML = [("Content-Type", "text/html")]


def test_browser_gzip_source_is_decoded_separately_from_browser_bytes(origins, make_fetcher) -> None:
    origin = origins["a"]
    plain = b"<!doctype html><html><body><p>plain-source</p></body></html>"
    origin.route(
        "/gzip",
        Reply(200, HTML + [("Content-Encoding", "gzip")], gzip.compress(plain)),
    )
    result = make_fetcher().fetch(origin.url("/gzip"), mode="browser", timeout=15)
    assert result.ok
    attempt = result.selected
    assert attempt is not None and attempt.source is not None
    assert attempt.source.body == plain
    assert attempt.source.encoding.content_encoding == ("gzip",)
    assert attempt.source.encoding.content_decoded is True
    assert attempt.source.complete is True and attempt.source.interruption is None
    assert attempt.source.decoded_text is not None and "plain-source" in attempt.source.decoded_text
    assert result.response_body == plain
    assert result.rendered_html is not None and "plain-source" in result.rendered_html
    assert origin.log.paths() == ["/gzip"]


def test_browser_oversized_decompression_is_bounded_and_partial(origins, make_fetcher) -> None:
    origin = origins["a"]
    plain = b"<html><body>" + b"A" * 2_000_000 + b"</body></html>"
    compressed = gzip.compress(plain)
    assert 0 < len(compressed) < 4096
    origin.route(
        "/bomb",
        Reply(200, HTML + [("Content-Encoding", "gzip")], compressed),
    )
    policy = AcquisitionPolicy(
        budgets=Budgets(
            max_source_bytes=4096,
            max_dom_bytes=1024,
            max_total_bytes=8192,
            retries=0,
        )
    )
    result = make_fetcher(policy=policy).fetch(origin.url("/bomb"), mode="browser", timeout=15)
    assert result.outcome is Outcome.PARTIAL
    attempt = result.selected
    assert attempt is not None and attempt.source is not None
    assert not attempt.source.complete
    assert len(attempt.source.body) <= 4096
    assert result.rendered_html is None
    assert origin.log.paths() == ["/bomb"]


def test_browser_corrupt_gzip_is_not_marked_decoded(origins, make_fetcher) -> None:
    origin = origins["a"]
    origin.route(
        "/corrupt",
        Reply(200, HTML + [("Content-Encoding", "gzip")], b"not-a-gzip-stream"),
    )
    result = make_fetcher().fetch(origin.url("/corrupt"), mode="browser", timeout=15)
    assert result.outcome is not Outcome.SUCCESS
    assert result.rendered_html is None
    assert origin.log.paths() == ["/corrupt"]
