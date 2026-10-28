"""Known 2xx challenges must be blocked in every HTTP mode."""

from __future__ import annotations

from harness import Reply
from fetchward import Outcome

HTML = [("Content-Type", "text/html")]
CHALLENGE = b"<html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>"


def test_http_mode_blocks_known_challenge_and_keeps_body(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/challenge", Reply(200, HTML, CHALLENGE))
    result = make_fetcher().fetch(a.url("/challenge"), mode="http")
    assert result.outcome is Outcome.BLOCKED
    assert result.diagnostics.stop_reason == "http.challenge"
    assert result.response_body == CHALLENGE
    assert result.status_code == 200
    assert any(e.code == "evidence.challenge" for e in result.diagnostics.evidence)
    assert a.log.paths() == ["/challenge"]


def test_http_mode_blocks_challenge_header(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/challenge", Reply(200, HTML + [("X-Challenge", "fixture")], b"<html>x</html>"))
    result = make_fetcher().fetch(a.url("/challenge"), mode="http")
    assert result.outcome is Outcome.BLOCKED
    assert result.diagnostics.stop_reason == "http.challenge"
    assert result.response_body == b"<html>x</html>"


def test_202_challenge_remains_blocked(origins, make_fetcher) -> None:
    a = origins["a"]
    a.route("/challenge", Reply(202, HTML, CHALLENGE))
    result = make_fetcher().fetch(a.url("/challenge"), mode="http")
    assert result.outcome is Outcome.BLOCKED and not result.ok
    assert "http.challenge" in result.selected.reasons
    assert any(e.code == "evidence.challenge" for e in result.diagnostics.evidence)


def test_auto_challenge_does_not_launch_browser(monkeypatch, origins, make_fetcher) -> None:
    a = origins["a"]
    a.route(
        "/challenge",
        Reply(
            200,
            HTML,
            b"<html><head><title>Just a moment...</title></head><body>"
            b"<div id='app'>STATIC</div><script>1</script>"
            b"<p>Checking your browser</p></body></html>",
        ),
    )
    called = False

    def browser_must_not_run(*args, **kwargs):
        nonlocal called
        called = True
        raise RuntimeError("browser must not run for a known challenge")

    monkeypatch.setattr("fetchward._fetcher.run_browser", browser_must_not_run)
    result = make_fetcher().fetch(a.url("/challenge"), mode="auto")
    assert called is False
    assert len(result.attempts) == 1
    assert result.outcome is Outcome.BLOCKED
    assert result.diagnostics.stop_reason == "http.challenge"
    assert a.log.paths() == ["/challenge"]


AWS_WAF = (
    b"<html><head><script src='https://abc.def.eu-west-1.token.awswaf.com/abc/def/ghi/challenge.js'>"
    b"</script></head><body><div id='challenge-container'></div><script>"
    b"AwsWafIntegration.saveReferrer();</script></body></html>"
)


def test_aws_waf_challenge_is_blocked_for_200_and_202(origins, make_fetcher) -> None:
    a = origins["a"]
    for status in (200, 202):
        a.route(f"/waf{status}", Reply(status, HTML, AWS_WAF))
        result = make_fetcher().fetch(a.url(f"/waf{status}"), mode="http")
        assert result.outcome is Outcome.BLOCKED, status
        assert "http.challenge" in result.selected.reasons


def test_page_merely_loading_aws_waf_sdk_is_not_a_challenge(origins, make_fetcher) -> None:
    a = origins["a"]
    page = b"<html><head><script src='https://x.y.token.awswaf.com/a/b/challenge.js'></script></head><body><article>Real content</article></body></html>"
    a.route("/page", Reply(200, HTML, page))
    result = make_fetcher().fetch(a.url("/page"), mode="http")
    assert result.ok
    assert any(e.code == "evidence.challenge" and e.value is False for e in result.diagnostics.evidence)
