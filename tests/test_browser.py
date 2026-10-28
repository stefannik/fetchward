"""Browser credential scoping across an origin-changing redirect."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")

from harness import FixtureOrigin, Reply, StaticResolver
from fetchward import AcquisitionPolicy, DestinationPolicy, Fetcher, Outcome, Session, TransportPolicy

pytestmark = pytest.mark.browser


@pytest.mark.parametrize("content_type,body,kind", [
    ("application/json", b'{"ok": true}', "json"),
    ("image/png", b"\x89PNG\r\n\x1a\nexample", "file"),
])
def test_non_html_browser_source(origins, make_fetcher, content_type, body, kind):
    origin = origins["a"]
    origin.route("/resource", Reply(200, [("Content-Type", content_type)], body))
    with make_fetcher() as fetcher:
        result = fetcher.fetch(origin.url("/resource"), mode="browser", timeout=15)
        assert result.ok
        assert result.response_body == body
        assert result.selected.source.kind.value == kind
        assert result.selected.rendered is None
        if kind == "file":
            origin.route("/untyped", Reply(200, [], body))
            result = fetcher.fetch(origin.url("/untyped"), mode="browser", timeout=15)
            assert result.ok and result.response_body == body
            assert result.selected.source.kind.value == "file"
            assert result.selected.rendered is None


def test_non_html_browser_selector_keeps_source(origins, make_fetcher):
    from fetchward import Readiness

    origin = origins["a"]
    body = b'{"ok": true}'
    origin.route("/resource", Reply(200, [("Content-Type", "application/json")], body))
    with make_fetcher(readiness=Readiness(selector="#ready")) as fetcher:
        result = fetcher.fetch(origin.url("/resource"), mode="browser", timeout=15)
    assert result.outcome.value == "partial"
    assert result.diagnostics.stop_reason == "readiness.unsupported"
    assert result.response_body == body
    assert result.selected.rendered is None


def test_browser_reuses_launch_but_not_cookies_and_closes(origins, make_fetcher, monkeypatch):
    from playwright.sync_api import BrowserType

    launches = []
    launch = BrowserType.launch

    def counted_launch(self, *args, **kwargs):
        launches.append(1)
        return launch(self, *args, **kwargs)

    monkeypatch.setattr(BrowserType, "launch", counted_launch)
    origin = origins["a"]
    origin.route("/one", Reply(200, [("Content-Type", "text/html"), ("Set-Cookie", "sid=secret; Path=/")], b"<html>one</html>"))
    origin.route("/two", Reply(200, [("Content-Type", "text/html")], b"<html>two</html>"))
    fetcher = make_fetcher()
    try:
        assert fetcher.fetch(origin.url("/one"), mode="browser", timeout=15).ok
        assert fetcher.fetch(origin.url("/two"), mode="browser", timeout=15).ok
        assert len(launches) == 1
        assert "sid=secret" not in origin.log.requests[-1].headers.get("cookie", "")
        threads = [host.thread for hosts in fetcher._browser_pool.hosts.values() for host in hosts]
    finally:
        fetcher.close()
    assert threads and all(not thread.is_alive() for thread in threads)


def test_second_browser_context_denies_forbidden_subresource(origins, make_fetcher):
    origin, forbidden = origins["a"], origins["forbidden"]
    origin.route("/one", Reply(200, [("Content-Type", "text/html")], b"<html>one</html>"))
    origin.route("/two", Reply(200, [("Content-Type", "text/html")],
        f"<html><script src='{forbidden.url('/secret')}'></script></html>".encode()))
    forbidden.route("/secret", Reply(200, [("Content-Type", "application/javascript")], b"void 0"))
    with make_fetcher() as fetcher:
        assert fetcher.fetch(origin.url("/one"), mode="browser", timeout=15).ok
        result = fetcher.fetch(origin.url("/two"), mode="browser", timeout=15)
    assert any(e.code == "safety.destination_rejected" for e in result.diagnostics.evidence)
    assert not forbidden.log.requests


def test_browser_hosts_allow_concurrent_acquisitions(origins, make_fetcher):
    from concurrent.futures import ThreadPoolExecutor
    import threading

    entered, release = threading.Event(), threading.Event()
    origin = origins["a"]

    def slow(_request):
        entered.set()
        release.wait(10)
        return Reply(200, [("Content-Type", "text/html")], b"<html>slow</html>")

    origin.route("/slow", slow)
    origin.route("/fast", Reply(200, [("Content-Type", "text/html")], b"<html>fast</html>"))
    with make_fetcher() as fetcher, ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(fetcher.fetch, origin.url("/slow"), mode="browser", timeout=15)
        try:
            assert entered.wait(10)
            second = executor.submit(fetcher.fetch, origin.url("/fast"), mode="browser", timeout=15)
            assert second.result(timeout=10).ok
        finally:
            release.set()
        assert first.result(timeout=10).ok


def test_browser_overrun_retires_host(origins, make_fetcher, monkeypatch):
    import threading
    import fetchward._browser as browser_module
    from playwright.sync_api import BrowserType

    launches = []
    launch = BrowserType.launch

    def counted_launch(self, *args, **kwargs):
        launches.append(1)
        return launch(self, *args, **kwargs)

    monkeypatch.setattr(BrowserType, "launch", counted_launch)
    entered, release = threading.Event(), threading.Event()
    worker = browser_module._browser_worker

    def stall_once(*args):
        if not entered.is_set():
            entered.set()
            release.wait(10)
        worker(*args)

    monkeypatch.setattr(browser_module, "_browser_worker", stall_once)
    origin = origins["a"]
    origin.route("/", Reply(200, [("Content-Type", "text/html")], b"<html>ok</html>"))
    fetcher = make_fetcher()
    try:
        first = fetcher.fetch(origin.url(), mode="browser", timeout=1.0)
        assert entered.is_set()
        assert any(e.code == "cleanup.overrun" for e in first.diagnostics.evidence)
        release.set()
        assert fetcher.fetch(origin.url(), mode="browser", timeout=15).ok
        assert len(launches) == 2
    finally:
        release.set()
        fetcher.close()


def test_redirect_does_not_send_session_headers_to_other_port():
    source = FixtureOrigin("same.test")
    target = FixtureOrigin("same.test")
    try:
        source.route("/start", Reply(302, [("Location", target.url("/target"))]))
        target.route("/target", Reply(200, [("Content-Type", "text/html")], b"<html>target</html>"))
        session = Session()
        session.add_credentials(source.url(), {"Authorization": "Bearer scoped-secret"})
        policy = AcquisitionPolicy(destinations=DestinationPolicy(trusted_local=(source.trusted(), target.trusted())))
        with Fetcher(policy, session=session, _resolver=StaticResolver({"same.test": ("127.0.0.1",)})) as fetcher:
            result = fetcher.fetch(source.url("/start"), mode="browser", timeout=15)
        assert source.log.requests and "authorization" not in source.log.requests[0].headers
        assert target.log.requests and "authorization" not in target.log.requests[0].headers
        assert any(e.code == "session.headers_not_applied" for e in result.diagnostics.evidence)
    finally:
        source.close()
        target.close()


def test_session_cookie_scope_includes_same_host_other_port():
    source, target = FixtureOrigin("same.test"), FixtureOrigin("same.test")
    try:
        source.route("/", Reply(200, [("Content-Type", "text/html")],
            f"<html><script src='{target.url('/script')}'></script></html>".encode()))
        target.route("/script", Reply(200, [("Content-Type", "application/javascript")], b"void 0"))
        session = Session()
        session.add_cookie(source.url(), "sid", "cookie-value")
        policy = AcquisitionPolicy(destinations=DestinationPolicy(trusted_local=(source.trusted(), target.trusted())))
        with Fetcher(policy, session=session, _resolver=StaticResolver({"same.test": ("127.0.0.1",)})) as fetcher:
            result = fetcher.fetch(source.url(), mode="browser", timeout=15)
        assert result.ok
        assert "sid=cookie-value" in source.log.requests[0].headers.get("cookie", "")
        assert "sid=cookie-value" in target.log.requests[0].headers.get("cookie", "")
    finally:
        source.close()
        target.close()


def test_auto_falls_back_from_202_to_browser_200(origins, make_fetcher):
    a = origins["a"]
    calls = 0

    def accepted_then_page(_request):
        nonlocal calls
        calls += 1
        status = 202 if calls == 1 else 200
        body = b"<html>processing</html>" if status == 202 else b"<html><body>rendered page</body></html>"
        return Reply(status, [("Content-Type", "text/html")], body)

    a.route("/accepted", accepted_then_page)
    result = make_fetcher().fetch(a.url("/accepted"), mode="auto", timeout=15)
    assert result.ok
    assert result.selected.mode.value == "browser"
    assert result.rendered_html and "rendered page" in result.rendered_html
    assert any(
        e.code == "browser.fallback" and dict(e.facts).get("reason") == "http.accepted_incomplete"
        for e in result.diagnostics.evidence
    )


def test_javascript_source_and_rendered_are_distinct(origins, make_fetcher):
    a = origins["a"]
    a.route("/", Reply(200, [("Content-Type", "text/html")],
                       b"<html><body>source<script>document.body.append('DOM'+'-ONLY')</script></body></html>"))
    result = make_fetcher().fetch(a.url(), mode="browser", timeout=15)
    assert result.ok
    assert b"DOM-ONLY" not in result.response_body
    assert "DOM-ONLY" in result.rendered_html
    assert a.log.paths() == ["/"]


def test_redirect_to_login_preserves_provenance(origins, make_fetcher):
    a = origins["a"]
    a.route("/private", Reply(302, [("Location", "/login")]))
    a.route("/login", Reply(200, [("Content-Type", "text/html")],
                            b"<html><h1>Sign in required</h1><form><input type=password></form></html>"))
    result = make_fetcher().fetch(a.url("/private"), mode="browser", timeout=15)
    assert result.outcome.value == "auth_required"
    assert len(result.selected.redirects) == 1
    assert result.selected.redirects[0].to_url.endswith("/login")
    assert a.log.paths() == ["/private", "/login"]


def test_redirect_robots_check_is_posthoc(origins, make_fetcher):
    from fetchward import AccessPolicy
    a, b = origins["a"], origins["b"]
    a.route("/robots.txt", Reply(200, [], b"User-agent: *\nAllow: /\n"))
    b.route("/robots.txt", Reply(200, [], b"User-agent: *\nDisallow: /private\n"))
    a.route("/start", Reply(302, [("Location", b.url("/private"))]))
    b.route("/private", Reply(200, [("Content-Type", "text/html")], b"<html>not retained</html>"))
    result = make_fetcher(access=AccessPolicy(mode="automated")).fetch(a.url("/start"), mode="browser", timeout=15)
    assert result.outcome.value == "blocked"
    assert result.diagnostics.stop_reason == "access.robots_denied"
    assert result.response_body is None
    assert any(e.code == "access.robots_posthoc" for e in result.diagnostics.evidence)
    assert "/private" in b.log.paths()


@pytest.mark.parametrize("status,outcome", [(403, "blocked"), (429, "rate_limited")])
def test_http_restriction_and_cooldown(origins, make_fetcher, status, outcome):
    a = origins["a"]
    a.route("/", Reply(status, [("Content-Type", "text/html"), ("Retry-After", "60")], b"<html>restricted</html>"))
    first = make_fetcher().fetch(a.url(), mode="browser", timeout=15)
    assert first.outcome.value == outcome
    if status == 429:
        second = make_fetcher().fetch(a.url(), mode="browser", timeout=15)
        assert second.outcome.value == "rate_limited"
        assert len(a.log) == 1


@pytest.mark.parametrize("selector,outcome", [("#ready", "success"), ("#missing", "partial")])
def test_selector_readiness_retains_dom(origins, make_fetcher, selector, outcome):
    from fetchward import Readiness
    a = origins["a"]
    a.route("/", Reply(200, [("Content-Type", "text/html")], b"<html><body><p id=ready>ready</p></body></html>"))
    policy = AcquisitionPolicy(readiness=Readiness(selector=selector, selector_timeout=0.2))
    result = make_fetcher(policy=policy).fetch(a.url(), mode="browser", timeout=15)
    assert result.outcome.value == outcome
    assert "ready" in result.rendered_html


def test_multiple_selector_match_policy(origins, make_fetcher):
    from fetchward import Readiness
    a = origins["a"]
    a.route("/", Reply(200, [("Content-Type", "text/html")], b"<html><body><p id=one>one</p></body></html>"))
    any_result = make_fetcher(policy=AcquisitionPolicy(
        readiness=Readiness(selectors=("#one", "#two"), match="any", selector_timeout=0.2)
    )).fetch(a.url(), mode="browser", timeout=15)
    all_result = make_fetcher(policy=AcquisitionPolicy(
        readiness=Readiness(selectors=("#one", "#two"), match="all", selector_timeout=0.2)
    )).fetch(a.url(), mode="browser", timeout=15)
    assert any_result.outcome.value == "success"
    assert all_result.outcome.value == "partial"
    assert any_result.attempts[0].readiness.conditions[0].condition == "selector"


def test_selector_visibility_and_text_readiness(origins, make_fetcher):
    from fetchward import Readiness
    a = origins["a"]
    a.route("/", Reply(200, [("Content-Type", "text/html")],
                       b'<html><body><p id=hidden style="display:none">needle text</p></body></html>'))
    attached = make_fetcher(policy=AcquisitionPolicy(
        readiness=Readiness(selector="#hidden", selector_timeout=0.2)
    )).fetch(a.url(), mode="browser", timeout=15)
    visible = make_fetcher(policy=AcquisitionPolicy(
        readiness=Readiness(selector="#hidden", visible=True, selector_timeout=0.2)
    )).fetch(a.url(), mode="browser", timeout=15)
    text_met = make_fetcher(policy=AcquisitionPolicy(
        readiness=Readiness(selector="#hidden", text_contains="needle", selector_timeout=0.2)
    )).fetch(a.url(), mode="browser", timeout=15)
    text_unmet = make_fetcher(policy=AcquisitionPolicy(
        readiness=Readiness(selector="#hidden", text_contains="absent", selector_timeout=0.2)
    )).fetch(a.url(), mode="browser", timeout=15)
    assert attached.outcome.value == "success"
    assert visible.outcome.value == "partial"
    assert text_met.outcome.value == "success"
    assert text_unmet.outcome.value == "partial"
    assert {item.condition for item in text_unmet.attempts[0].readiness.conditions} == {"selector", "text_contains"}


def test_dom_stability_waits_then_times_out_with_partial_dom(origins, make_fetcher):
    from fetchward import Readiness
    a = origins["a"]
    a.route("/stops", Reply(200, [("Content-Type", "text/html")],
        b"<html><body><script>let n=0;const timer=setInterval(()=>{const e=document.createElement('i');e.textContent='x';document.body.append(e);if(++n===10)clearInterval(timer)},50)</script></body></html>"))
    a.route("/never", Reply(200, [("Content-Type", "text/html")],
        b"<html><body><script>setInterval(()=>{const e=document.createElement('i');e.textContent='x';document.body.append(e)},50)</script></body></html>"))
    stable = make_fetcher(policy=AcquisitionPolicy(
        readiness=Readiness(dom_stable_ms=100, selector_timeout=2.0)
    )).fetch(a.url("/stops"), mode="browser", timeout=15)
    unstable = make_fetcher(policy=AcquisitionPolicy(
        readiness=Readiness(dom_stable_ms=100, selector_timeout=0.35)
    )).fetch(a.url("/never"), mode="browser", timeout=15)
    assert stable.outcome.value == "success"
    assert stable.attempts[0].readiness.conditions[0].status == "satisfied"
    assert unstable.outcome.value == "partial"
    assert unstable.rendered_html
    assert unstable.attempts[0].readiness.conditions[0].status == "timeout"


def test_invalid_readiness_rejected_before_receiver_contact(origins):
    from fetchward import Readiness
    from fetchward.errors import ConfigurationError
    a = origins["a"]
    a.route("/", Reply(200, [("Content-Type", "text/html")], b"<html>must not be requested</html>"))
    with pytest.raises(ConfigurationError):
        AcquisitionPolicy(readiness=Readiness(selectors=("div{",)))
    assert a.log.paths() == []


def test_forbidden_start_redirect_and_subresource(origins, make_fetcher):
    a, forbidden = origins["a"], origins["forbidden"]
    first = make_fetcher().fetch(forbidden.url("/start"), mode="browser", timeout=15)
    assert first.diagnostics.stop_reason == "safety.destination_rejected"
    a.route("/redirect", Reply(302, [("Location", forbidden.url("/target"))]))
    second = make_fetcher().fetch(a.url("/redirect"), mode="browser", timeout=15)
    assert second.diagnostics.stop_reason == "safety.destination_rejected"
    a.route("/page", Reply(200, [("Content-Type", "text/html")],
                            f"<html><script src='{forbidden.url('/script')}'></script></html>".encode()))
    third = make_fetcher().fetch(a.url("/page"), mode="browser", timeout=15)
    assert any(e.code == "safety.destination_rejected" for e in third.diagnostics.evidence)
    assert forbidden.log.paths() == []


def test_resource_block_and_request_cap(origins, make_fetcher):
    from fetchward import Budgets
    a = origins["a"]
    a.route("/", Reply(200, [("Content-Type", "text/html")],
                       b"<html><img src='/image'><script src='/one'></script><script src='/two'></script></html>"))
    for path in ("/image", "/one", "/two"):
        a.route(path, Reply(200, [("Content-Type", "application/javascript")], b"void 0"))
    result = make_fetcher(policy=AcquisitionPolicy(budgets=Budgets(max_browser_requests=3))).fetch(a.url(), mode="browser", timeout=15)
    assert "/image" not in a.log.paths()
    assert any(e.code == "budget.browser_requests" for e in result.diagnostics.evidence)
    assert result.diagnostics.budget.browser_requests > 3
    # The cap alone does not downgrade a captured document with met readiness.
    assert result.outcome is Outcome.SUCCESS


def test_proxy_rechecks_rebinding_before_each_dial():
    from fetchward import Readiness, TrustedOrigin
    page, receiver = FixtureOrigin("page.test"), FixtureOrigin("rebind.test")
    class RebindingResolver(StaticResolver):
        def resolve(self, host, port, timeout, cancel=None):
            if host == "rebind.test":
                self.calls.append(host)
                return ("127.0.0.2",) if self.calls.count(host) == 1 else ("127.0.0.1",)
            return super().resolve(host, port, timeout, cancel)
    try:
        target = receiver.url("/secret")
        page.route("/", Reply(200, [("Content-Type", "text/html")],
            f"<html><script>fetch('{target}').catch(()=>{{}}).finally(()=>{{let x=document.createElement('p');x.id='done';document.body.append(x)}})</script></html>".encode()))
        resolver = RebindingResolver({"page.test": ("127.0.0.1",)})
        policy = AcquisitionPolicy(
            destinations=DestinationPolicy(trusted_local=(page.trusted(), TrustedOrigin("http", "rebind.test", receiver.port, ("127.0.0.2",)))),
            readiness=Readiness(selector="#done"))
        from fetchward._safety import DestinationGuard, canonicalize
        assert DestinationGuard(policy.destinations, resolver).check(canonicalize(target), 1).address == "127.0.0.2"
        with Fetcher(policy, _resolver=resolver) as fetcher:
            result = fetcher.fetch(page.url(), mode="browser", timeout=15)
        assert resolver.calls.count("rebind.test") >= 2
        assert receiver.log.paths() == []
        assert any(e.code == "safety.destination_rejected" for e in result.diagnostics.evidence)
    finally:
        page.close()
        receiver.close()


def test_download_is_reported_unsupported(origins, make_fetcher):
    a = origins["a"]
    a.route("/file", Reply(200, [("Content-Type", "application/octet-stream"),
                                ("Content-Disposition", "attachment; filename=file.bin")], b"file"))
    result = make_fetcher().fetch(a.url("/file"), mode="browser", timeout=15)
    assert not result.ok
    assert result.diagnostics.stop_reason == "backend.unsupported"
    assert a.log.paths() == ["/file"]


def test_deadline_retains_source(origins, make_fetcher):
    import time
    a = origins["a"]
    a.route("/", Reply(200, [("Content-Type", "text/html")],
                       b"<html><body>source retained<script src='/stall'></script></body></html>"))
    def stall(_):
        time.sleep(4)
        return Reply(200, [("Content-Type", "application/javascript")], b"void 0")
    a.route("/stall", stall)
    started = time.monotonic()
    result = make_fetcher().fetch(a.url(), mode="browser", timeout=2)
    assert time.monotonic() - started < 4.5
    assert result.outcome.value in ("partial", "error")
    assert result.response_body and b"source retained" in result.response_body


@pytest.mark.parametrize("engine", ["chromium", "chrome"])
def test_browser_engine_uses_selected_channel_with_guarded_proxy(origins, make_fetcher, engine):
    from playwright.sync_api import Error, sync_playwright

    if engine == "chrome":
        try:
            with sync_playwright() as playwright:
                probe = playwright.chromium.launch(channel="chrome", headless=True)
                probe.close()
        except Error:
            pytest.skip("Google Chrome is not installed")
    origin, forbidden = origins["a"], origins["forbidden"]
    origin.route("/", Reply(200, [("Content-Type", "text/html")],
        f"<html><body><script src='{forbidden.url('/blocked')}'></script><script>document.body.dataset.ready='yes'</script></body></html>".encode()))
    forbidden.route("/blocked", Reply(200, [("Content-Type", "application/javascript")], b"void 0"))
    fetcher = make_fetcher(transport=TransportPolicy(browser_engine=engine))
    try:
        result = fetcher.fetch(origin.url(), mode="browser", timeout=20)
    finally:
        fetcher.close()
    assert result.ok
    assert 'data-ready="yes"' in result.html
    assert forbidden.log.paths() == []
    assert result.attempts[-1].backend_version.startswith(engine + "/")


def test_invalid_browser_engine_is_rejected_before_io():
    from fetchward import ConfigurationError

    with pytest.raises(ConfigurationError, match="browser_engine"):
        TransportPolicy(browser_engine="invalid")


def test_browser_pool_keeps_hosts_separate_by_engine(monkeypatch):
    import queue
    from fetchward._browser import _BrowserPool

    class Host:
        def __init__(self, engine):
            self.engine, self.jobs = engine, queue.Queue()
            self.busy, self.healthy = False, True
        def stop(self):
            pass

    class Admission:
        def remaining(self):
            return 1.0

    monkeypatch.setattr("fetchward._browser._BrowserHost", Host)
    pool = _BrowserPool(1)
    chromium, _ = pool.submit((), Admission(), "chromium")
    chrome, _ = pool.submit((), Admission(), "chrome")
    assert chromium is not chrome
    assert set(pool.hosts) == {"chromium", "chrome"}
    pool.close(wait=False)


def test_pdf_viewer_page_is_never_reported_as_the_pdf(origins, make_fetcher):
    a = origins["a"]
    pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
    a.route("/doc.pdf", Reply(200, [("Content-Type", "application/pdf")], pdf))
    result = make_fetcher().fetch(a.url("/doc.pdf"), mode="browser", timeout=15)
    body = result.response_body or b""
    # Either the real bytes, or an honest non-success; never Chromium's viewer HTML as the PDF.
    assert body == pdf or (not result.ok and not body.lstrip().lower().startswith((b"<!doctype", b"<html")))
