"""User-mediated visible sessions: endings, profile persistence and unchanged safety."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")

from harness import Reply
from fetchward import BrowserProfile, ConfigurationError, InteractionResult

pytestmark = pytest.mark.browser

# No display is needed and the endings are deterministic; the headful path is exercised by
# bench/manual_interactive.py.
_HEADLESS = {"_headless_for_tests": True}


def _page(body: bytes = b"<html><body>page</body></html>") -> Reply:
    return Reply(200, [("Content-Type", "text/html")], body)


def test_condition_ending_and_cookie_persistence(origins, make_fetcher, tmp_path):
    origin = origins["a"]
    origin.route("/start", Reply(
        200,
        [("Content-Type", "text/html"),
         ("Set-Cookie", "sid=interactive-secret; Path=/; Max-Age=3600")],
        b"<html><body>login</body>"
        b"<script>setTimeout(() => location.replace('/done'), 1000)</script></html>",
    ))
    origin.route("/done", _page())
    origin.route("/after", _page())
    profile = BrowserProfile(tmp_path / "profile")
    with make_fetcher(profile=profile) as fetcher:
        result = fetcher.interactive(origin.url("/start"), until_url=origin.url("/done"),
                                     timeout=60, **_HEADLESS)
        assert isinstance(result, InteractionResult)
        assert result.ended_by == "condition"
        assert result.elapsed < 60
        assert result.requests >= 1
        # Redacted like diagnostics: no path, query or fragment.
        assert result.final_url.startswith(f"http://{origin.name}:{origin.port}/")
        assert "/start" not in result.final_url and "/done" not in result.final_url
        assert not any("interactive-secret" in repr(e) for e in result.evidence)
        after = fetcher.fetch(origin.url("/after"), mode="browser", timeout=30)
    assert after.ok
    assert "sid=interactive-secret" in origin.log.requests[-1].headers.get("cookie", "")


def test_timeout_ending(origins, make_fetcher, tmp_path):
    origin = origins["a"]
    origin.route("/wait", _page())
    with make_fetcher(profile=BrowserProfile(tmp_path / "profile")) as fetcher:
        result = fetcher.interactive(origin.url("/wait"), timeout=2.0, **_HEADLESS)
    assert result.ended_by == "timeout"
    assert 1.0 <= result.elapsed < 30
    assert result.requests >= 1
    assert origin.log.paths().count("/wait") == 1


def test_closed_ending(origins, make_fetcher, tmp_path):
    origin = origins["a"]
    origin.route("/close", _page())
    with make_fetcher(profile=BrowserProfile(tmp_path / "profile")) as fetcher:
        result = fetcher.interactive(origin.url("/close"), timeout=60,
                                     _page_hook=lambda page: page.close(), **_HEADLESS)
    assert result.ended_by == "closed"
    assert result.elapsed < 60


def test_requires_a_profile_and_valid_conditions(origins, make_fetcher, tmp_path):
    origin = origins["a"]
    origin.route("/", _page())
    with make_fetcher() as fetcher:
        with pytest.raises(ConfigurationError):
            fetcher.interactive(origin.url("/"))
    with make_fetcher(profile=BrowserProfile(tmp_path / "profile")) as fetcher:
        for kwargs in ({"until_selector": "div["}, {"until_url": ""}, {"timeout": 0},
                       {"timeout": 3601.0}, {"timeout": float("nan")}):
            with pytest.raises(ConfigurationError):
                fetcher.interactive(origin.url("/"), **kwargs)
    assert origin.log.paths() == []


def test_forbidden_subresource_is_never_contacted(origins, make_fetcher, tmp_path):
    origin, forbidden = origins["a"], origins["forbidden"]
    origin.route("/page", _page(
        f"<html><body>page</body><script src='{forbidden.url('/secret')}'></script>"
        f"<script>setTimeout(() => location.replace('/done'), 1000)</script></html>".encode(),
    ))
    origin.route("/done", _page())
    with make_fetcher(profile=BrowserProfile(tmp_path / "profile")) as fetcher:
        result = fetcher.interactive(origin.url("/page"), until_url=origin.url("/done"),
                                     timeout=60, **_HEADLESS)
    assert result.ended_by == "condition"
    assert forbidden.log.paths() == []
    assert any(e.code == "safety.destination_rejected" for e in result.evidence)
