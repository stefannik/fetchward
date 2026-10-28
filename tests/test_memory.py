"""Per-host acquisition memory through the public API and the SQLite file it keeps."""

from __future__ import annotations

import sqlite3
import stat

import pytest

from harness import Reply
from fetchward import (
    AccessPolicy,
    AcquisitionMemory,
    AcquisitionPolicy,
    DestinationPolicy,
    Fetcher,
    Mode,
    Outcome,
    Readiness,
    SchedulingPolicy,
    TransportPolicy,
)
from fetchward._safety_runtime import SafetyRuntime
from fetchward.errors import ConfigurationError

HTML = [("Content-Type", "text/html; charset=utf-8")]
ARTICLE = b"<html><body>" + b"Real article text. " * 40 + b"</body></html>"
SHELL = (
    b"<!doctype html><html><body><div id='app'>STATIC</div><script>"
    b"document.getElementById('app').textContent='JS_OK';</script></body></html>"
)
HOST = "origin-a.test"


class Clock:
    """Fake wall/monotonic pair so TTL and cooldown math is deterministic."""

    def __init__(self) -> None:
        self.wall_now = 1_700_000_000.0
        self.mono = 0.0

    def wall(self) -> float:
        return self.wall_now

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall_now += seconds
        self.mono += seconds


def build(
    origins,
    resolver,
    ca_bundle,
    *,
    memory: AcquisitionMemory | None = None,
    clock: Clock | None = None,
    readiness: Readiness | None = None,
) -> Fetcher:
    return Fetcher(
        AcquisitionPolicy(
            access=AccessPolicy(mode="user_initiated"),
            destinations=DestinationPolicy(trusted_local=(origins["a"].trusted(),)),
            transport=TransportPolicy(ca_bundle=ca_bundle),
            readiness=readiness or Readiness(),
            scheduling=SchedulingPolicy(min_host_interval=0.0),
        ),
        memory=memory,
        _resolver=resolver,
        _clock=clock or Clock(),
        _safety=SafetyRuntime(),
    )


def _codes(result) -> list[str]:
    return [evidence.code for evidence in result.diagnostics.evidence]


def test_remembered_429_blocks_a_new_fetcher_without_contact(
    origins, resolver, ca_bundle, tmp_path
) -> None:
    origins["a"].route("/limited", Reply(429, [("Retry-After", "120")], b"slow down"))
    path = str(tmp_path / "memory.db")
    clock = Clock()

    first = build(origins, resolver, ca_bundle, memory=AcquisitionMemory(path), clock=clock)
    assert first.fetch(origins["a"].url("/limited"), mode="http").outcome is Outcome.RATE_LIMITED

    second = build(origins, resolver, ca_bundle, memory=AcquisitionMemory(path), clock=clock)
    blocked = second.fetch(origins["a"].url("/limited"), mode="http")

    assert blocked.outcome is Outcome.RATE_LIMITED
    assert blocked.diagnostics.stop_reason == "host.cooldown"
    evidence = next(e for e in blocked.diagnostics.evidence if e.code == "memory.cooldown")
    assert 0.0 < float(dict(evidence.facts)["remaining"]) <= 120.0
    assert origins["a"].log.paths() == ["/limited"]


def test_remembered_entry_expires_after_ttl(origins, resolver, ca_bundle, tmp_path) -> None:
    origins["a"].route("/limited", Reply(429, [("Retry-After", "120")], b"slow down"))
    clock = Clock()
    memory = AcquisitionMemory(str(tmp_path / "memory.db"), ttl_days=1 / 86400)

    build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(
        origins["a"].url("/limited"), mode="http"
    )
    clock.advance(2)

    after = build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(
        origins["a"].url("/limited"), mode="http"
    )

    assert "memory.cooldown" not in _codes(after)
    assert origins["a"].log.paths() == ["/limited", "/limited"]


def test_corrupt_database_is_reported_once_and_recreated(
    origins, resolver, ca_bundle, tmp_path
) -> None:
    origins["a"].route("/page", Reply(200, HTML, ARTICLE))
    path = tmp_path / "memory.db"
    path.write_bytes(b"this is not a sqlite database\n" * 32)
    memory = AcquisitionMemory(str(path))
    fetcher = build(origins, resolver, ca_bundle, memory=memory)

    first = fetcher.fetch(origins["a"].url("/page"), mode="auto")
    notices = [e for e in first.diagnostics.evidence if e.code == "memory.corrupt"]
    assert len(notices) == 1 and notices[0].value is True
    assert dict(notices[0].facts)["reason"] == "not a database"

    second = fetcher.fetch(origins["a"].url("/page"), mode="auto")
    assert first.ok and second.ok
    assert "memory.corrupt" not in _codes(second)
    rows = sqlite3.connect(str(path)).execute("SELECT host FROM host_state").fetchall()
    assert ("origin-a.test",) in rows


def test_database_is_private_and_stores_only_the_host(
    origins, resolver, ca_bundle, tmp_path
) -> None:
    origins["a"].route("/secret/page", Reply(200, HTML, ARTICLE))
    path = tmp_path / "memory.db"
    fetcher = build(origins, resolver, ca_bundle, memory=AcquisitionMemory(str(path)))

    result = fetcher.fetch(
        origins["a"].url("/secret/page?token=canary-value"), mode="http"
    )

    assert result.ok
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    blob = path.read_bytes()
    assert HOST.encode() in blob
    for canary in (b"canary-value", b"token=", b"secret/page", b"?"):
        assert canary not in blob
    rows = sqlite3.connect(str(path)).execute("SELECT host FROM host_state").fetchall()
    assert rows == [(HOST,)]


def test_explicit_http_mode_ignores_needs_browser(
    monkeypatch, origins, resolver, ca_bundle
) -> None:
    from fetchward._browser import BrowserStatus

    monkeypatch.setattr(
        "fetchward._fetcher.browser_status",
        lambda: BrowserStatus(False, "backend.unavailable", "fixture browser unavailable"),
    )
    origins["a"].route("/page", Reply(200, HTML, ARTICLE))
    clock = Clock()
    memory = AcquisitionMemory()
    memory._record(HOST, now_wall=clock.wall(), needs_browser_at=clock.wall())

    result = build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(
        origins["a"].url("/page"), mode="http"
    )

    assert result.ok
    assert [attempt.mode for attempt in result.attempts] == [Mode.HTTP]
    assert "memory.browser_first" not in _codes(result)
    assert origins["a"].log.paths() == ["/page"]


def test_browser_first_falls_back_to_http_when_the_browser_is_unavailable(
    monkeypatch, origins, resolver, ca_bundle
) -> None:
    from fetchward._browser import BrowserStatus

    monkeypatch.setattr(
        "fetchward._fetcher.browser_status",
        lambda: BrowserStatus(False, "backend.unavailable", "fixture browser unavailable"),
    )
    origins["a"].route("/page", Reply(200, HTML, ARTICLE))
    clock = Clock()
    memory = AcquisitionMemory()
    memory._record(HOST, now_wall=clock.wall(), needs_browser_at=clock.wall())

    result = build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(
        origins["a"].url("/page"), mode="auto"
    )

    assert result.ok
    assert [attempt.mode for attempt in result.attempts] == [Mode.HTTP]
    codes = _codes(result)
    assert "memory.browser_first" in codes and "backend.unavailable" in codes
    assert origins["a"].log.paths() == ["/page"]


def test_browser_first_never_retries_the_browser_after_a_failure(
    monkeypatch, origins, resolver, ca_bundle
) -> None:
    from fetchward._browser import _BrowserOperationalError

    origins["a"].route("/page", Reply(200, HTML, SHELL))
    clock = Clock()
    memory = AcquisitionMemory()
    memory._record(HOST, now_wall=clock.wall(), needs_browser_at=clock.wall())

    def failing_browser(*args, **kwargs):
        raise _BrowserOperationalError("backend.unavailable", "fixture browser failure")

    monkeypatch.setattr("fetchward._fetcher.run_browser", failing_browser)
    result = build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(
        origins["a"].url("/page"), mode="auto"
    )

    assert result.ok
    assert [attempt.mode for attempt in result.attempts] == [Mode.HTTP]
    codes = _codes(result)
    assert "memory.browser_first" in codes and "browser.fallback" not in codes
    assert origins["a"].log.paths() == ["/page"]


def test_a_newer_http_success_suppresses_browser_first(
    monkeypatch, origins, resolver, ca_bundle
) -> None:
    from fetchward._browser import BrowserStatus

    origins["a"].route("/page", Reply(200, HTML, ARTICLE))
    clock = Clock()
    memory = AcquisitionMemory()

    http_only = build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(
        origins["a"].url("/page"), mode="auto"
    )
    assert http_only.ok and [a.mode for a in http_only.attempts] == [Mode.HTTP]
    # An older browser observation cannot outvote the newer HTTP success.
    memory._record(HOST, now_wall=clock.wall() - 100, needs_browser_at=clock.wall() - 100)

    monkeypatch.setattr(
        "fetchward._fetcher.browser_status",
        lambda: BrowserStatus(False, "backend.unavailable", "fixture browser unavailable"),
    )
    later = build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(
        origins["a"].url("/page"), mode="auto"
    )

    assert later.ok
    assert "memory.browser_first" not in _codes(later)
    assert origins["a"].log.paths() == ["/page", "/page"]


@pytest.mark.browser
def test_auto_js_shell_fallback_makes_the_next_auto_call_browser_first(
    origins, resolver, ca_bundle, tmp_path
) -> None:
    pytest.importorskip("playwright.sync_api")
    origins["a"].route("/page", Reply(200, HTML, SHELL))
    clock = Clock()
    fetcher = build(
        origins, resolver, ca_bundle, memory=AcquisitionMemory(str(tmp_path / "memory.db")), clock=clock
    )
    first = fetcher.fetch(origins["a"].url("/page"), mode="auto", timeout=15)
    assert first.ok
    assert [attempt.mode for attempt in first.attempts] == [Mode.HTTP, Mode.BROWSER]
    assert first.rendered_html is not None and "JS_OK" in first.rendered_html

    requests_before = len(origins["a"].log)
    second = fetcher.fetch(origins["a"].url("/page"), mode="auto", timeout=15)

    assert second.ok
    assert [attempt.mode for attempt in second.attempts] == [Mode.BROWSER]
    assert any(e.code == "memory.browser_first" for e in second.diagnostics.evidence)
    # Exactly the one browser navigation: no HTTP attempt was made first.
    assert len(origins["a"].log) == requests_before + 1
    assert second.rendered_html is not None and "JS_OK" in second.rendered_html


def test_a_wall_clock_jump_cannot_shorten_a_remembered_cooldown(
    origins, resolver, ca_bundle
) -> None:
    origins["a"].route("/limited", Reply(429, [("Retry-After", "120")], b"slow down"))
    clock = Clock()
    memory = AcquisitionMemory()
    url = origins["a"].url("/limited")

    build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(url, mode="http")
    clock.wall_now += 3600  # a clock change; monotonic time keeps running normally

    blocked = build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(
        url, mode="http"
    )

    assert blocked.outcome is Outcome.RATE_LIMITED
    assert "memory.cooldown" in _codes(blocked)
    assert origins["a"].log.paths() == ["/limited"]


def test_forget_and_clear_drop_a_remembered_cooldown(
    origins, resolver, ca_bundle
) -> None:
    origins["a"].route("/limited", Reply(429, [("Retry-After", "120")], b"slow down"))
    clock = Clock()
    memory = AcquisitionMemory()
    url = origins["a"].url("/limited")

    build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(url, mode="http")
    assert "memory.cooldown" in _codes(
        build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(url, mode="http")
    )
    assert origins["a"].log.paths() == ["/limited"]

    memory.forget(HOST)
    assert "memory.cooldown" not in _codes(
        build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(url, mode="http")
    )
    memory.clear()
    assert "memory.cooldown" not in _codes(
        build(origins, resolver, ca_bundle, memory=memory, clock=clock).fetch(url, mode="http")
    )
    assert origins["a"].log.paths() == ["/limited"] * 3


def test_in_process_memory_is_not_shared_between_instances(
    origins, resolver, ca_bundle
) -> None:
    origins["a"].route("/limited", Reply(429, [("Retry-After", "120")], b"slow down"))
    clock = Clock()
    url = origins["a"].url("/limited")

    build(origins, resolver, ca_bundle, memory=AcquisitionMemory(), clock=clock).fetch(
        url, mode="http"
    )
    other = build(origins, resolver, ca_bundle, memory=AcquisitionMemory(), clock=clock).fetch(
        url, mode="http"
    )

    assert "memory.cooldown" not in _codes(other)
    assert origins["a"].log.paths() == ["/limited", "/limited"]


def test_invalid_memory_configuration_fails_before_io() -> None:
    with pytest.raises(ConfigurationError):
        AcquisitionMemory(ttl_days=0)
    with pytest.raises(TypeError):
        AcquisitionMemory(3)
    with pytest.raises(TypeError):
        Fetcher(memory="not a memory")
