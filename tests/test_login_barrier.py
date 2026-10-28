"""Confirmed 200 login barriers become auth_required without credential escalation."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")

from harness import Reply
from fetchward import Mode, Outcome

HTML = [("Content-Type", "text/html")]
LOGIN_FORM = (
    b"<!doctype html><html><body><main>"
    b"<h1>Sign in to continue</h1>"
    b"<form action='/login' method='post'>"
    b"<label>Email <input name='email' type='email'></label>"
    b"<label>Password <input name='password' type='password'></label>"
    b"<button type='submit'>Sign in</button></form>"
    b"</main></body></html>"
)
OPTIONAL_FORM = (
    b"<!doctype html><html><body><article><h1>OPTIONAL-CONTENT</h1>"
    b"<p>Public article body.</p></article>"
    b"<form action='/login'><input name='password' type='password'></form>"
    b"<a href='/login'>Sign in</a></body></html>"
)
OPTIONAL_LINK = (
    b"<!doctype html><html><body><article><h1>OPTIONAL-LINK</h1>"
    b"<p>Public article body.</p></article><a href='/login'>Sign in</a></body></html>"
)


@pytest.mark.parametrize("mode", ["http", pytest.param("browser", marks=pytest.mark.browser), "auto"])
def test_explicit_login_barrier_is_auth_required_in_all_modes(origins, make_fetcher, mode) -> None:
    a = origins["a"]
    a.route("/barrier", Reply(200, HTML, LOGIN_FORM))
    result = make_fetcher().fetch(a.url("/barrier"), mode=mode, timeout=15)
    assert result.outcome is Outcome.AUTH_REQUIRED
    assert result.diagnostics.stop_reason == "http.login_required"
    assert result.selected is not None
    assert result.selected.source is not None
    assert result.selected.source.status_code == 200
    assert b"Sign in to continue" in result.selected.source.body
    assert any(
        e.code == "evidence.login_barrier" and e.value is True
        for e in result.diagnostics.evidence
    )
    assert len(a.log.paths()) == 1
    assert "/login" not in a.log.paths()


def test_auto_login_barrier_does_not_launch_browser(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/barrier", Reply(200, HTML, LOGIN_FORM))
    result = make_fetcher().fetch(a.url("/barrier"), mode="auto", timeout=15)
    assert result.outcome is Outcome.AUTH_REQUIRED
    assert len(result.attempts) == 1
    assert result.attempts[0].mode is Mode.HTTP
    assert a.log.paths() == ["/barrier"]


@pytest.mark.parametrize("mode", ["http", pytest.param("browser", marks=pytest.mark.browser), "auto"])
def test_attributable_redirect_to_login_form_is_auth_required(
    origins, make_fetcher, mode
) -> None:
    a = origins["a"]
    a.route("/private", Reply(302, [("Location", "/login")], b""))
    a.route("/login", Reply(200, HTML, LOGIN_FORM))
    result = make_fetcher().fetch(a.url("/private"), mode=mode, timeout=15)
    assert result.outcome is Outcome.AUTH_REQUIRED
    assert result.selected is not None and result.selected.source is not None
    assert result.selected.source.url.endswith("/login")
    assert result.selected.redirects
    assert result.selected.redirects[-1].to_url.endswith("/login")
    assert a.log.paths() == ["/private", "/login"]


def test_redirected_login_form_without_required_words_is_attributable(
    origins, make_fetcher
) -> None:
    a = origins["a"]
    body = (
        b"<!doctype html><html><body><form action='/login' method='post'>"
        b"<input name='password' type='password'></form></body></html>"
    )
    a.route("/private-wordless", Reply(302, [("Location", "/login")], b""))
    a.route("/login", Reply(200, HTML, body))
    result = make_fetcher().fetch(a.url("/private-wordless"), mode="http", timeout=15)
    assert result.outcome is Outcome.AUTH_REQUIRED
    assert any(
        e.code == "evidence.login_barrier" and e.value is True
        for e in result.diagnostics.evidence
    )


@pytest.mark.parametrize("mode", ["http", pytest.param("browser", marks=pytest.mark.browser), "auto"])
def test_optional_login_form_and_link_are_not_barriers(origins, make_fetcher, mode) -> None:
    a = origins["a"]
    a.route("/optional-form", Reply(200, HTML, OPTIONAL_FORM))
    form_result = make_fetcher().fetch(a.url("/optional-form"), mode=mode, timeout=15)
    assert form_result.outcome is Outcome.SUCCESS
    assert form_result.selected is not None and form_result.selected.source is not None
    assert b"OPTIONAL-CONTENT" in form_result.selected.source.body

    b = origins["b"]
    b.route("/optional-link", Reply(200, HTML, OPTIONAL_LINK))
    link_result = make_fetcher().fetch(b.url("/optional-link"), mode=mode, timeout=15)
    assert link_result.outcome is Outcome.SUCCESS
    assert link_result.selected is not None and link_result.selected.source is not None
    assert b"OPTIONAL-LINK" in link_result.selected.source.body


def test_login_path_with_form_but_no_redirect_or_required_language_is_not_barrier(
    origins, make_fetcher
) -> None:
    a = origins["a"]
    body = (
        b"<!doctype html><html><body><form action='/login'>"
        b"<input name='password' type='password'></form></body></html>"
    )
    a.route("/login", Reply(200, HTML, body))
    result = make_fetcher().fetch(a.url("/login"), mode="http", timeout=15)
    assert result.outcome is Outcome.SUCCESS


def test_required_language_without_password_form_is_not_barrier(origins, make_fetcher) -> None:
    a = origins["a"]
    body = b"<!doctype html><html><body><p>Sign in to continue</p></body></html>"
    a.route("/copy", Reply(200, HTML, body))
    result = make_fetcher().fetch(a.url("/copy"), mode="http", timeout=15)
    assert result.outcome is Outcome.SUCCESS


@pytest.mark.parametrize("mode", ["http", pytest.param("browser", marks=pytest.mark.browser), "auto"])
def test_public_article_with_sign_in_to_comment_widget_is_not_barrier(
    origins, make_fetcher, mode
) -> None:
    a = origins["a"]
    body = (
        b"<!doctype html><html><head><title>A travel story</title></head><body>"
        b"<article><h1>PUBLIC-ARTICLE</h1><p>Completely public article.</p></article>"
        b"<aside><p>Please sign in to comment.</p>"
        b"<form action='/login'><input name='password' type='password'></form></aside>"
        b"</body></html>"
    )
    a.route("/story", Reply(200, HTML, body))
    result = make_fetcher().fetch(a.url("/story"), mode=mode, timeout=15)
    assert result.outcome is Outcome.SUCCESS
    assert result.selected is not None and result.selected.source is not None
    assert b"PUBLIC-ARTICLE" in result.selected.source.body
    assert not any(
        e.code == "evidence.login_barrier" and e.value is True
        for e in result.diagnostics.evidence
    )


@pytest.mark.parametrize("mode", ["http", pytest.param("browser", marks=pytest.mark.browser), "auto"])
def test_public_content_with_comment_class_sign_in_widget_is_not_barrier(
    origins, make_fetcher, mode
) -> None:
    a = origins["a"]
    body = (
        b"<!doctype html><html><head><title>A travel story</title></head><body>"
        b"<div class='article'>Completely public article.</div>"
        b"<div class='comments'><p>Please sign in to comment.</p>"
        b"<form action='/login'><input name='password' type='password'></form></div>"
        b"</body></html>"
    )
    a.route("/story-classes", Reply(200, HTML, body))
    result = make_fetcher().fetch(a.url("/story-classes"), mode=mode, timeout=15)
    assert result.outcome is Outcome.SUCCESS
    assert result.selected is not None and result.selected.source is not None
    assert b"Completely public article." in result.selected.source.body
    assert not any(
        e.code == "evidence.login_barrier" and e.value is True
        for e in result.diagnostics.evidence
    )
