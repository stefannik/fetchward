"""Terminal dot normalization must match the exact dispatched receiver path."""

from __future__ import annotations

import pytest

from harness import Reply
from fetchward import AccessPolicy, Outcome, Session

pytest.importorskip("playwright.sync_api")

HTML = [("Content-Type", "text/html")]


def _origin(origin) -> str:
    return f"{origin.scheme}://{origin.name}:{origin.port}"


@pytest.mark.parametrize("target", ["/foo/.", "/foo/%2e"])
def test_terminal_dot_uses_exact_normalized_receiver_path(origins, make_fetcher, target) -> None:
    a = origins["a"]
    a.route("/foo", Reply(200, HTML, b"<html>slashless</html>"))
    a.route("/foo/", Reply(200, HTML, b"<html>slash</html>"))
    result = make_fetcher().fetch(a.url(target), mode="http")
    assert result.ok
    assert result.response_body == b"<html>slash</html>"
    assert a.log.paths()[-1] == "/foo/"


@pytest.mark.parametrize(
    "target", ["/foo/..", "/foo/%2e%2e", "/foo/.%2e", "/foo/%2e."]
)
def test_terminal_dotdot_uses_root_normalized_path(origins, make_fetcher, target) -> None:
    a = origins["a"]
    a.route("/", Reply(200, HTML, b"<html>root</html>"))
    a.route("/foo", Reply(200, HTML, b"<html>slashless</html>"))
    result = make_fetcher().fetch(a.url(target), mode="http")
    assert result.ok
    assert result.response_body == b"<html>root</html>"
    assert a.log.paths()[-1] == "/"


def test_robots_disallow_uses_terminal_dot_normalized_path(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/robots.txt", Reply(200, [], b"User-agent: *\nDisallow: /foo/\n"))
    a.route("/foo", Reply(200, HTML, b"<html>slashless</html>"))
    a.route("/foo/", Reply(200, HTML, b"<html>slash</html>"))
    result = make_fetcher(access=AccessPolicy(mode="automated")).fetch(
        a.url("/foo/."), mode="http"
    )
    assert result.outcome is Outcome.BLOCKED
    assert result.diagnostics.stop_reason == "access.robots_denied"
    assert a.log.paths() == ["/robots.txt"]


def test_session_cookie_uses_terminal_dot_normalized_path(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/foo", Reply(200, HTML, b"<html>slashless</html>"))
    a.route("/foo/", Reply(200, HTML, b"<html>slash</html>"))
    session = Session()
    session.add_cookie(_origin(a), "sid", "SLASH", path="/foo/")
    result = make_fetcher(session=session).fetch(a.url("/foo/."), mode="http")
    assert result.ok
    request = a.log.requests[-1]
    assert request.path == "/foo/"
    assert "sid=SLASH" in request.headers.get("cookie", "")


@pytest.mark.browser
def test_browser_terminal_dot_uses_exact_normalized_path(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/foo", Reply(200, HTML, b"<html>slashless</html>"))
    a.route("/foo/", Reply(200, HTML, b"<html>slash</html>"))
    result = make_fetcher().fetch(a.url("/foo/."), mode="browser", timeout=15)
    assert result.ok
    assert result.response_body == b"<html>slash</html>"
    assert a.log.paths()[-1] == "/foo/"
