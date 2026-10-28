"""Scoped in-memory Session credentials/cookies through the public Fetcher."""

from __future__ import annotations

import pytest

from harness import Reply
from fetchward import (
    AccessPolicy,
    AcquisitionPolicy,
    Budgets,
    FetcherClosedError,
    Outcome,
    Session,
    SessionClosedError,
)
from fetchward.errors import ConfigurationError

HTML = [("Content-Type", "text/html")]


def _origin(origin) -> str:
    return f"{origin.scheme}://{origin.name}:{origin.port}"


def test_http_session_credentials_cookies_and_robots_are_scoped(origins, make_fetcher) -> None:
    a, b = origins["a"], origins["b"]
    a.route("/robots.txt", Reply(200, [], b"User-agent: *\nAllow: /\n"))
    a.route("/page", Reply(200, HTML, b"<html>a</html>"))
    b.route("/page", Reply(200, HTML, b"<html>b</html>"))
    session = Session()
    session.add_credentials(_origin(a), {"Authorization": "Bearer A-SECRET"})
    session.add_cookie(_origin(a), "sid", "A-COOKIE")
    session.add_credentials(_origin(b), {"Authorization": "Bearer B-SECRET"})
    result = make_fetcher(
        session=session, access=AccessPolicy(mode="automated")
    ).fetch(a.url("/page"), mode="http")
    assert result.ok
    requests = {request.path: request for request in a.log.requests}
    robots = requests["/robots.txt"]
    page = requests["/page"]
    assert "authorization" not in robots.headers and "cookie" not in robots.headers
    assert page.headers["authorization"] == "Bearer A-SECRET"
    assert "sid=A-COOKIE" in page.headers["cookie"]
    assert b.log.paths() == []
    assert "A-SECRET" not in repr(result)
    assert "A-SECRET" not in repr(result.diagnostics)
    assert "A-COOKIE" not in repr(result.diagnostics)


def test_http_cross_origin_redirect_does_not_forward_credentials(origins, make_fetcher) -> None:
    a, b = origins["a"], origins["b"]
    a.route("/go", Reply(302, [("Location", b.url("/target"))]))
    b.route("/target", Reply(200, HTML, b"<html>b</html>"))
    session = Session()
    session.add_credentials(_origin(a), {"Authorization": "Bearer REDIRECT-SECRET"})
    session.add_cookie(_origin(a), "sid", "REDIRECT-COOKIE")
    result = make_fetcher(session=session).fetch(a.url("/go"), mode="http")
    assert result.ok
    assert a.log.requests[0].headers["authorization"] == "Bearer REDIRECT-SECRET"
    target = b.log.requests[0]
    assert "authorization" not in target.headers and "cookie" not in target.headers
    assert "REDIRECT-SECRET" not in repr(result.diagnostics)


def test_http_session_cookie_path_and_clear(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/public", Reply(200, HTML, b"<html>public</html>"))
    a.route("/private/page", Reply(200, HTML, b"<html>private</html>"))
    session = Session()
    session.add_cookie(_origin(a), "sid", "PATH-COOKIE", path="/private")
    session.add_cookie(_origin(a), "secure", "SECURE-COOKIE", secure=True)
    fetcher = make_fetcher(session=session)
    assert fetcher.fetch(a.url("/public"), mode="http").ok
    assert "cookie" not in a.log.requests[-1].headers
    assert fetcher.fetch(a.url("/private/page"), mode="http").ok
    assert "sid=PATH-COOKIE" in a.log.requests[-1].headers["cookie"]
    assert "SECURE-COOKIE" not in a.log.requests[-1].headers["cookie"]
    session.clear()
    assert fetcher.fetch(a.url("/public"), mode="http").ok
    assert "cookie" not in a.log.requests[-1].headers


def test_session_port_scope_and_unrelated_fetchers(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/page", Reply(200, HTML, b"<html>a</html>"))
    session = Session()
    session.add_credentials(_origin(a), {"Authorization": "Bearer ONLY-A"})
    session.add_cookie(_origin(a), "sid", "ONLY-A")
    with_session = make_fetcher(session=session)
    anonymous = make_fetcher()
    assert with_session.fetch(a.url("/page"), mode="http").ok
    assert a.log.requests[-1].headers["authorization"] == "Bearer ONLY-A"
    assert "sid=ONLY-A" in a.log.requests[-1].headers["cookie"]
    assert anonymous.fetch(a.url("/page"), mode="http").ok
    assert "authorization" not in a.log.requests[-1].headers
    assert "cookie" not in a.log.requests[-1].headers


def test_session_clear_and_close_lifecycle(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/page", Reply(200, HTML, b"<html>a</html>"))
    session = Session()
    session.add_credentials(_origin(a), {"Authorization": "Bearer CLEAR-ME"})
    fetcher = make_fetcher(session=session)
    assert fetcher.fetch(a.url("/page"), mode="http").ok
    session.clear()
    assert fetcher.fetch(a.url("/page"), mode="http").ok
    assert "authorization" not in a.log.requests[-1].headers
    session.close()
    session.close()
    session.clear()
    before = len(a.log)
    with pytest.raises(SessionClosedError):
        fetcher.fetch(a.url("/page"), mode="http")
    assert len(a.log) == before
    assert "CLEAR-ME" not in repr(session)


def test_session_rejects_bad_origin_and_headers_before_io(origins) -> None:
    a = origins["a"]
    session = Session()
    with pytest.raises(ConfigurationError):
        session.add_credentials(f"http://user:pass@{a.name}:{a.port}", {"Authorization": "x"})
    with pytest.raises(ConfigurationError):
        session.add_credentials(f"http://{a.name}:{a.port}/path", {"Authorization": "x"})
    with pytest.raises(ConfigurationError):
        session.add_credentials(f"http://{a.name}:{a.port}?query=1", {"Authorization": "x"})
    with pytest.raises(ConfigurationError):
        session.add_credentials(_origin(a), {"Host": "elsewhere"})
    with pytest.raises(ConfigurationError):
        session.add_cookie(_origin(a), "bad name", "value")
    assert a.log.paths() == []


def test_session_request_cap_is_shared_with_credentials(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/page", Reply(200, HTML, b"<html>a</html>"))
    session = Session()
    session.add_credentials(_origin(a), {"Authorization": "Bearer CAP-SECRET"})
    policy = AcquisitionPolicy(budgets=Budgets(max_requests=1, retries=0))
    result = make_fetcher(policy=policy, session=session).fetch(a.url("/page"), mode="http")
    assert result.ok
    assert result.diagnostics.budget.requests == 1
    assert a.log.paths() == ["/page"]
    assert a.log.requests[0].headers["authorization"] == "Bearer CAP-SECRET"


def test_session_401_does_not_trigger_native_auth_retry(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/auth", Reply(401, [("WWW-Authenticate", 'Basic realm="x"')], b"no"))
    session = Session()
    session.add_credentials(_origin(a), {"Authorization": "Bearer HTTP-AUTH-CANARY"})
    result = make_fetcher(session=session).fetch(a.url("/auth"), mode="http")
    assert result.outcome is Outcome.AUTH_REQUIRED
    assert a.log.paths() == ["/auth"]
    assert a.log.requests[0].headers["authorization"] == "Bearer HTTP-AUTH-CANARY"


def test_session_port_scope_http(origins, make_fetcher) -> None:
    from harness import FixtureOrigin

    a = origins["a"]
    other = FixtureOrigin("origin-a.test")
    try:
        a.route("/page", Reply(200, HTML, b"<html>a</html>"))
        other.route("/secret", Reply(200, HTML, b"<html>other</html>"))
        session = Session()
        session.add_credentials(_origin(a), {"Authorization": "Bearer PORT-SCOPE"})
        fetcher = make_fetcher(
            trust=("a",), extra_trust=(other.trusted(),), session=session
        )
        assert fetcher.fetch(a.url("/page"), mode="http").ok
        assert a.log.requests[-1].headers["authorization"] == "Bearer PORT-SCOPE"
        assert fetcher.fetch(other.url("/secret"), mode="http").ok
        assert "authorization" not in other.log.requests[-1].headers
        assert "cookie" not in other.log.requests[-1].headers
    finally:
        other.close()


def test_fetcher_close_does_not_close_caller_session(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/page", Reply(200, HTML, b"<html>a</html>"))
    session = Session()
    session.add_credentials(_origin(a), {"Authorization": "Bearer CALLER-OWNED"})
    fetcher = make_fetcher(session=session)
    assert fetcher.fetch(a.url("/page"), mode="http").ok
    fetcher.close()
    with pytest.raises(FetcherClosedError):
        fetcher.fetch(a.url("/page"), mode="http")
    assert session.closed is False
    assert make_fetcher(session=session).fetch(a.url("/page"), mode="http").ok
    assert a.log.requests[-1].headers["authorization"] == "Bearer CALLER-OWNED"


@pytest.mark.parametrize(
    "target",
    [
        "/public/../private",
        "/public/%2e%2e/private",
        "/public/.%2e/private",
        "/public/%2E./private",
    ],
)
def test_path_scoped_cookie_is_not_leaked_across_dot_normalization(
    origins, make_fetcher, target
) -> None:
    a = origins["a"]
    a.route("/private", Reply(200, HTML, b"<html>private</html>"))
    session = Session()
    session.add_cookie(_origin(a), "sid", "PUBLIC-ONLY", path="/public")
    result = make_fetcher(session=session).fetch(a.url(target), mode="http")
    assert result.ok
    request = a.log.requests[-1]
    assert request.path == "/private"
    assert "cookie" not in request.headers
