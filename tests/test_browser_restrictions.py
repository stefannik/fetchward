"""Browser restriction, popup and navigation controls through the public Fetcher."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")

from harness import Reply
from fetchward import AcquisitionPolicy, Outcome, Readiness, Session

pytestmark = pytest.mark.browser

HTML = [("Content-Type", "text/html")]
SHELL = b"<!doctype html><html><body><div id='app'>STATIC</div><script>document.getElementById('app').textContent='JS_OK'</script></body></html>"


def _origin(origin) -> str:
    return f"{origin.scheme}://{origin.name}:{origin.port}"


def test_optional_401_does_not_restrict_main(origins, make_fetcher) -> None:
    a = origins["a"]
    body = (
        b"<!doctype html><html><body><div id='app'>STATIC</div>"
        b"<script>"
        b"document.getElementById('app').textContent='JS_OK';"
        b"fetch('/auth').catch(() => {}).finally(() => {"
        b"const d = document.createElement('div'); d.id = 'done';"
        b"document.body.appendChild(d); });"
        b"</script></body></html>"
    )
    a.route("/page", Reply(200, HTML, body))
    a.route(
        "/auth",
        Reply(401, [("Content-Type", "text/html"), ("WWW-Authenticate", 'Basic realm="x"')], b"no"),
    )
    session = Session()
    session.add_credentials(_origin(a), {"Authorization": "Bearer OPTIONAL-CANARY"})
    policy = AcquisitionPolicy(readiness=Readiness(selector="#done"))
    result = make_fetcher(session=session, policy=policy).fetch(
        a.url("/page"), mode="browser", timeout=15
    )
    assert result.ok
    assert "/auth" in a.log.paths()
    assert "/page" in a.log.paths()
    assert "OPTIONAL-CANARY" not in repr(result.diagnostics)


def test_main_401_stops_follow_on_requests(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route(
        "/auth",
        Reply(
            401,
            [("Content-Type", "text/html"), ("WWW-Authenticate", 'Basic realm="x"')],
            b"<html><body><img src='/optional'></body></html>",
        ),
    )
    a.route("/optional", Reply(200, HTML, b"must not be served"))
    result = make_fetcher().fetch(a.url("/auth"), mode="browser", timeout=15)
    assert result.outcome is Outcome.AUTH_REQUIRED
    assert a.log.paths() == ["/auth"]


def test_main_403_stops_follow_on_requests(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route(
        "/forbidden",
        Reply(403, HTML, b"<html><body><img src='/optional'></body></html>"),
    )
    a.route("/optional", Reply(200, HTML, b"must not be served"))
    result = make_fetcher().fetch(a.url("/forbidden"), mode="browser", timeout=15)
    assert result.outcome is Outcome.BLOCKED
    assert a.log.paths() == ["/forbidden"]


def test_main_challenge_stops_optional_requests(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route(
        "/challenge",
        Reply(
            200,
            HTML,
            b"<html><head><title>Just a moment...</title></head>"
            b"<body>Checking your browser<img src='/optional'></body></html>",
        ),
    )
    a.route("/optional", Reply(200, HTML, b"must not be served"))
    result = make_fetcher().fetch(a.url("/challenge"), mode="browser", timeout=15)
    assert result.outcome is Outcome.BLOCKED
    assert result.diagnostics.stop_reason == "browser.challenge"
    assert result.response_body is not None and b"Checking your browser" in result.response_body
    assert a.log.paths() == ["/challenge"]


def test_main_429_uses_shared_cooldown_across_acquisitions(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/rate", Reply(429, [], b"limited"))
    first = make_fetcher().fetch(a.url("/rate"), mode="browser", timeout=15)
    assert first.outcome is Outcome.RATE_LIMITED
    assert a.log.paths() == ["/rate"]
    second_fetcher = make_fetcher()
    second = second_fetcher.fetch(a.url("/rate"), mode="browser", timeout=15)
    assert any(e.code == "host.cooldown" for e in second.diagnostics.evidence), [
        e.code for e in second.diagnostics.evidence
    ]
    assert second.outcome is Outcome.RATE_LIMITED
    assert a.log.paths() == ["/rate"]


def test_popup_is_denied_before_origin_dispatch(origins, make_fetcher) -> None:
    a = origins["a"]
    body = (
        b"<!doctype html><html><body><div id='app'>STATIC</div>"
        b"<script>document.getElementById('app').textContent='JS_OK';"
        b"window.open('/popup');</script></body></html>"
    )
    a.route("/page", Reply(200, HTML, body))
    a.route("/popup", Reply(200, HTML, b"must not be served"))
    result = make_fetcher().fetch(a.url("/page"), mode="browser", timeout=15)
    assert result.ok
    assert a.log.paths() == ["/page"]
    assert any(e.code == "navigation.popup_denied" for e in result.diagnostics.evidence)
    assert result.response_body is not None and b"window.open" in result.response_body


def test_scripted_second_navigation_is_denied_before_origin_dispatch(origins, make_fetcher) -> None:
    a = origins["a"]
    body = (
        b"<!doctype html><html><body><div id='app'>STATIC</div>"
        b"<script>document.getElementById('app').textContent='JS_OK';"
        b"const d=document.createElement('div'); d.id='ready'; document.body.appendChild(d);"
        b"window.location.href='/second';</script></body></html>"
    )
    a.route("/page", Reply(200, HTML, body))
    a.route("/second", Reply(200, HTML, b"must not be served"))
    result = make_fetcher().fetch(a.url("/page"), mode="browser", timeout=15)
    assert "/second" not in a.log.paths()
    assert a.log.paths() == ["/page"]
    if result.response_body is not None:
        assert b"STATIC" in result.response_body
