"""Opt-in installed Chrome through the same destination guard."""
from __future__ import annotations

import os
import subprocess
import threading
import time

import pytest

pytest.importorskip("playwright.sync_api")
from harness import Reply
from fetchward import AcquisitionPolicy, BrowserProfile, ConfigurationError, Fetcher, StealthPolicy, TrustedOrigin

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
pytestmark = [pytest.mark.browser, pytest.mark.skipif(not os.path.isfile(CHROME), reason="Chrome not installed")]


def html(body):
    return Reply(200, [("Content-Type", "text/html")], body.encode())


def test_fetch_renders_without_webdriver_and_guards_subresources(origins, make_fetcher, tmp_path):
    origin, forbidden = origins["a"], origins["forbidden"]
    origin.route("/", html(f"<html><body>rendered<script>fetch('/report?webdriver='+navigator.webdriver)</script><script src='{forbidden.url('/secret')}'></script></body></html>"))
    origin.route("/report", Reply(200, [], b"ok"))
    with make_fetcher(profile=BrowserProfile(tmp_path / "p"), stealth=StealthPolicy(mode="real-chrome")) as fetcher:
        result = fetcher.fetch(origin.url(), mode="browser", timeout=30)
    assert result.ok
    assert "rendered" in result.html
    assert "/report?webdriver=false" in origin.log.paths()
    assert forbidden.log.paths() == []
    assert {"stealth.real_chrome", "stealth.proxy_unauthenticated"} <= {e.code for e in result.diagnostics.evidence}
    chrome = next(e for e in result.diagnostics.evidence if e.code == "stealth.real_chrome")
    assert dict(chrome.facts)["ownership"] in {"browser_pid", "endpoint_and_liveness"}


def test_owned_child_stops_on_completion_and_deadline(origins, make_fetcher, tmp_path, monkeypatch):
    origin = origins["a"]
    origin.route("/", html("<html><body>ok</body></html>"))
    started = threading.Event()
    def slow(request):
        started.set()
        time.sleep(5)
        return html("<html>late</html>")
    origin.route("/slow", slow)
    processes = []
    real_popen = subprocess.Popen
    def capture(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        if args and isinstance(args[0], list) and args[0][0] == CHROME:
            processes.append(process)
        return process
    monkeypatch.setattr(subprocess, "Popen", capture)
    with make_fetcher(profile=BrowserProfile(tmp_path / "p"), stealth=StealthPolicy(mode="real-chrome")) as fetcher:
        assert fetcher.fetch(origin.url(), mode="browser", timeout=30).ok
        assert processes and processes[-1].poll() is not None
        fetcher.fetch(origin.url("/slow"), mode="browser", timeout=2)
        assert len(processes) == 2 and processes[-1].poll() is not None
        started.clear()
        errors = []
        def acquire():
            try:
                fetcher.fetch(origin.url("/slow"), mode="browser", timeout=20)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=acquire)
        thread.start()
        assert started.wait(15)
        fetcher.close()
        thread.join(5)
        assert not thread.is_alive()
        assert len(processes) == 3 and processes[-1].poll() is not None
        assert not errors


def test_requires_profile(origins, make_fetcher, tmp_path, monkeypatch):
    with pytest.raises(ConfigurationError, match="profile"):
        Fetcher(AcquisitionPolicy(stealth=StealthPolicy(mode="real-chrome")))
    origin = origins["a"]
    with make_fetcher(profile=BrowserProfile(tmp_path / "p"),
                      stealth=StealthPolicy(mode="real-chrome", chrome_path=str(tmp_path / "missing"))) as fetcher:
        result = fetcher.fetch(origin.url(), mode="browser", timeout=10)
    assert result.diagnostics.stop_reason == "backend.unavailable"
    assert not origin.log.paths()
    assert any(e.code == "backend.unavailable" and "Google Chrome" in repr(e.facts)
               for e in result.diagnostics.evidence)
    origin.route("/", html("<html><body>retry succeeded</body></html>"))
    real_popen = subprocess.Popen
    launches = []
    def first_child_exits(*args, **kwargs):
        if args and isinstance(args[0], list) and args[0][0] == CHROME:
            launches.append(args[0])
            if len(launches) == 1:
                return real_popen(["/usr/bin/false"], **kwargs)
        return real_popen(*args, **kwargs)
    monkeypatch.setattr(subprocess, "Popen", first_child_exits)
    with make_fetcher(profile=BrowserProfile(tmp_path / "retry"),
                      stealth=StealthPolicy(mode="real-chrome")) as fetcher:
        result = fetcher.fetch(origin.url(), mode="browser", timeout=30)
    assert result.ok
    assert len(launches) == 2
    assert launches[0][2] != launches[1][2]


def test_profile_engine_mismatch(origins, make_fetcher, tmp_path):
    origin = origins["a"]
    origin.route("/", html("<html><body>ok</body></html>"))
    profile = BrowserProfile(tmp_path / "p")
    with make_fetcher(profile=profile, stealth=StealthPolicy(mode="real-chrome")) as fetcher:
        assert fetcher.fetch(origin.url(), mode="browser", timeout=30).ok
    with make_fetcher(profile=profile) as fetcher:
        with pytest.raises(ConfigurationError, match="engine mismatch"):
            fetcher.fetch(origin.url(), mode="browser", timeout=30)


def test_interactive_condition_and_popup(origins, make_fetcher, tmp_path):
    origin = origins["a"]
    origin.route("/", html("<html><body><div id='done'>ok</div></body></html>"))
    origin.route("/popup", html("<html><body>popup</body></html>"))
    def popup(page):
        with page.expect_popup() as event:
            page.evaluate("url => window.open(url)", origin.url("/popup"))
        assert event.value.locator("body").inner_text(timeout=10000) == "popup"
    with make_fetcher(profile=BrowserProfile(tmp_path / "p"), stealth=StealthPolicy(mode="real-chrome")) as fetcher:
        result = fetcher.interactive(origin.url(), until_selector="#done", timeout=30,
                                     _headless_for_tests=True, _page_hook=popup)
    assert result.ended_by == "condition"
    assert {"stealth.real_chrome", "stealth.proxy_unauthenticated", "stealth.service_workers_allowed"} <= {e.code for e in result.evidence}


def test_fetch_bypasses_existing_service_worker(origins, make_fetcher, tmp_path):
    origin = origins["a"]
    origin.route("/", html("<html><body>register</body></html>"))
    origin.route("/target", html("<html><body>origin content</body></html>"))
    origin.route("/sw.js", Reply(200, [("Content-Type", "application/javascript")],
                                b"self.addEventListener('fetch', e => { if (e.request.url.endsWith('/target')) "
                                b"e.respondWith(new Response('<html>worker content</html>', "
                                b"{headers:{'Content-Type':'text/html'}})); });"))
    trusted = TrustedOrigin("http", "127.0.0.1", origin.port, ("127.0.0.1",))
    def register(page):
        page.evaluate("async () => { await navigator.serviceWorker.register('/sw.js'); await navigator.serviceWorker.ready; }")
    with make_fetcher(profile=BrowserProfile(tmp_path / "p"), stealth=StealthPolicy(mode="real-chrome"),
                      extra_trust=(trusted,)) as fetcher:
        fetcher.interactive(origin.ip_url(), until_selector="body", timeout=30,
                            _headless_for_tests=True, _page_hook=register)
        result = fetcher.fetch(origin.ip_url("/target"), mode="browser", timeout=30)
    assert result.ok
    assert "origin content" in result.html
    assert "/target" in origin.log.paths()
