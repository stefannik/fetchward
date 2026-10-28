"""Generic prose must not be relabelled as a challenge; known challenge structure remains."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")

from harness import Reply
from fetchward import Outcome

HTML = [("Content-Type", "text/html")]
PROSE = (
    b"<!doctype html><html><head><title>A travel story</title></head><body>"
    b"<article><h1>TRAVEL-STORY</h1>"
    b"<p>Just a moment, she said, before describing the trip. "
    b"Checking your browser was never part of the itinerary.</p></article>"
    b"</body></html>"
)
CHALLENGE = (
    b"<!doctype html><html><head><title>Just a moment...</title></head><body>"
    b"<p>Checking your browser before accessing.</p></body></html>"
)


@pytest.mark.parametrize("mode", ["http", pytest.param("browser", marks=pytest.mark.browser), "auto"])
def test_prose_with_generic_challenge_words_is_not_challenge(origins, make_fetcher, mode) -> None:
    a = origins["a"]
    a.route("/prose", Reply(200, HTML, PROSE))
    result = make_fetcher().fetch(a.url("/prose"), mode=mode, timeout=15)
    assert result.outcome is Outcome.SUCCESS
    assert result.selected is not None and result.selected.source is not None
    assert b"TRAVEL-STORY" in result.selected.source.body
    assert not any(
        e.code == "evidence.challenge" and e.value is True
        for e in result.diagnostics.evidence
    )
    assert a.log.paths() == ["/prose"]


@pytest.mark.parametrize("mode", ["http", pytest.param("browser", marks=pytest.mark.browser), "auto"])
def test_ordinary_title_with_generic_words_is_not_challenge(origins, make_fetcher, mode) -> None:
    a = origins["a"]
    body = (
        b"<!doctype html><html><head><title>Just a moment in Paris</title></head><body>"
        b"<article><h1>PARIS-ESSAY</h1><p>A public travel essay.</p></article>"
        b"</body></html>"
    )
    a.route("/essay", Reply(200, HTML, body))
    result = make_fetcher().fetch(a.url("/essay"), mode=mode, timeout=15)
    assert result.outcome is Outcome.SUCCESS
    assert result.selected is not None and result.selected.source is not None
    assert b"PARIS-ESSAY" in result.selected.source.body
    assert not any(
        e.code == "evidence.challenge" and e.value is True
        for e in result.diagnostics.evidence
    )
    assert a.log.paths() == ["/essay"]


@pytest.mark.parametrize("mode", ["http", pytest.param("browser", marks=pytest.mark.browser), "auto"])
def test_known_challenge_structure_still_blocks(origins, make_fetcher, mode) -> None:
    a = origins["a"]
    a.route("/challenge", Reply(200, HTML, CHALLENGE))
    result = make_fetcher().fetch(a.url("/challenge"), mode=mode, timeout=15)
    assert result.outcome is Outcome.BLOCKED
    assert a.log.paths() == ["/challenge"]
    assert any(
        e.code == "evidence.challenge" and e.value is True
        for e in result.diagnostics.evidence
    )
