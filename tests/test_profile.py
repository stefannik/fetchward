"""Dedicated persistent browser profiles: creation, locking, and per-acquisition use."""

from __future__ import annotations

import json
import stat
import time

import pytest

from harness import Reply
from fetchward import BrowserProfile, ConfigurationError, FetchwardError, Outcome, ResponseCache, Session
from fetchward._profile import PROFILE_MARKER


@pytest.fixture
def _browser():
    pytest.importorskip("playwright.sync_api")


def test_profile_creates_private_directory_with_marker(tmp_path):
    path = tmp_path / "profile"
    profile = BrowserProfile(path)
    assert profile.exists
    assert profile.path == path
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    marker = json.loads((path / PROFILE_MARKER).read_text("utf-8"))
    assert marker["schema"] == 2
    assert stat.S_IMODE((path / PROFILE_MARKER).stat().st_mode) == 0o600
    # Both current and old markers are accepted on reopening.
    assert BrowserProfile(path).exists
    (path / PROFILE_MARKER).write_text(json.dumps({"schema": 1, "created_by": "fetchward"}))
    assert BrowserProfile(path).exists


def test_profile_refuses_foreign_and_browser_directories(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert BrowserProfile(empty).exists

    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "notes.txt").write_text("caller data", "utf-8")
    with pytest.raises(ConfigurationError):
        BrowserProfile(foreign)
    assert not (foreign / PROFILE_MARKER).exists()

    everyday = tmp_path / "everyday"
    everyday.mkdir()
    (everyday / "Local State").write_text("{}", "utf-8")
    with pytest.raises(ConfigurationError):
        BrowserProfile(everyday)
    assert not (everyday / PROFILE_MARKER).exists()


def test_delete_refuses_while_locked_and_removes_after(tmp_path):
    profile = BrowserProfile(tmp_path / "profile")
    lock = profile._acquire(time.monotonic())
    try:
        with pytest.raises(FetchwardError):
            profile.delete()
        assert profile.exists
    finally:
        lock.release()
    profile.delete()
    assert not profile.exists


def test_delete_refuses_a_directory_without_our_marker(tmp_path):
    profile = BrowserProfile(tmp_path / "profile")
    (profile.path / "fetchward-profile.json").unlink()
    (profile.path / "keep.txt").write_text("not ours")
    with pytest.raises(FetchwardError):
        profile.delete()
    assert (profile.path / "keep.txt").exists()


def test_profile_with_session_cookies_is_rejected_before_io(origins, make_fetcher, tmp_path):
    origin = origins["a"]
    session = Session()
    session.add_cookie(f"{origin.scheme}://{origin.name}:{origin.port}", "sid", "secret")
    with make_fetcher(profile=BrowserProfile(tmp_path / "profile"), session=session) as fetcher:
        with pytest.raises(ConfigurationError):
            fetcher.fetch(origin.url("/one"), mode="browser", timeout=5)
    assert origin.log.paths() == []


def test_http_mode_records_profile_not_applied(origins, make_fetcher, tmp_path):
    origin = origins["a"]
    origin.route("/resource", Reply(200, [("Content-Type", "text/html")], b"<html>ok</html>"))
    with make_fetcher(profile=BrowserProfile(tmp_path / "profile")) as fetcher:
        result = fetcher.fetch(origin.url("/resource"), mode="http", timeout=10)
    assert result.ok
    codes = {e.code for e in result.diagnostics.evidence}
    assert "profile.not_applied_http" in codes
    assert "profile.used" not in codes


def test_cache_is_not_used_with_a_profile(origins, make_fetcher, tmp_path):
    origin = origins["a"]
    cache = ResponseCache()
    origin.route("/resource", Reply(
        200, [("Content-Type", "text/html"), ("Cache-Control", "max-age=600")], b"<html>ok</html>"
    ))
    with make_fetcher(profile=BrowserProfile(tmp_path / "profile"), cache=cache) as fetcher:
        assert fetcher.fetch(origin.url("/resource"), mode="http", timeout=10).ok
        assert fetcher.fetch(origin.url("/resource"), mode="http", timeout=10).ok
    assert len(cache) == 0
    assert origin.log.paths().count("/resource") == 2


@pytest.mark.browser
def test_cookie_persists_between_fetches_only_with_profile(_browser, origins, make_fetcher, tmp_path):
    origin = origins["a"]
    origin.route("/one", Reply(
        200, [("Content-Type", "text/html"), ("Set-Cookie", "sid=profile-secret; Path=/; Max-Age=3600")],
        b"<html>one</html>",
    ))
    origin.route("/two", Reply(200, [("Content-Type", "text/html")], b"<html>two</html>"))
    profile = BrowserProfile(tmp_path / "profile")
    with make_fetcher(profile=profile) as fetcher:
        assert fetcher.fetch(origin.url("/one"), mode="browser", timeout=20).ok
        second = fetcher.fetch(origin.url("/two"), mode="browser", timeout=20)
    assert second.ok
    assert "sid=profile-secret" in origin.log.requests[-1].headers.get("cookie", "")
    used = [e for e in second.diagnostics.evidence if e.code == "profile.used"]
    assert used and dict(used[0].facts) == {"profile": profile.path.name}
    assert str(profile.path) not in repr(second.diagnostics.evidence)

    with make_fetcher() as fetcher:
        assert fetcher.fetch(origin.url("/two"), mode="browser", timeout=20).ok
    assert "sid=profile-secret" not in origin.log.requests[-1].headers.get("cookie", "")


@pytest.mark.browser
def test_forbidden_subresource_still_denied_with_profile(_browser, origins, make_fetcher, tmp_path):
    origin, forbidden = origins["a"], origins["forbidden"]
    origin.route("/page", Reply(
        200, [("Content-Type", "text/html")],
        f"<html><script src='{forbidden.url('/secret')}'></script></html>".encode(),
    ))
    with make_fetcher(profile=BrowserProfile(tmp_path / "profile")) as fetcher:
        result = fetcher.fetch(origin.url("/page"), mode="browser", timeout=20)
    assert result.ok
    assert len(forbidden.log) == 0


@pytest.mark.browser
def test_locked_profile_fails_with_reason_without_receiver_contact(_browser, origins, make_fetcher, tmp_path):
    origin = origins["a"]
    origin.route("/one", Reply(200, [("Content-Type", "text/html")], b"<html>one</html>"))
    profile = BrowserProfile(tmp_path / "profile")
    lock = profile._acquire(time.monotonic())
    try:
        started = time.monotonic()
        with make_fetcher(profile=profile) as fetcher:
            result = fetcher.fetch(origin.url("/one"), mode="browser", timeout=1.5)
        elapsed = time.monotonic() - started
    finally:
        lock.release()
    assert result.outcome is Outcome.ERROR
    assert result.diagnostics.stop_reason == "profile.locked"
    assert any(e.code == "profile.locked" for e in result.diagnostics.evidence)
    assert elapsed < 5
    assert origin.log.paths() == []
