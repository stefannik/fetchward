"""Chromium acquisition through a guarded, non-decrypting loopback proxy."""
from __future__ import annotations

import importlib.metadata
import queue
import random
import threading
import time
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from ._admission import Admission, Denied
from ._challenge import detect_challenge
from ._content_encoding import decode_content
from ._egress import EgressGateway
from ._fork import generation, is_forked_child
from ._http_curl import CurlHTTPAdapter
from ._js_shell import detect_js_shell
from ._login import detect_login_barrier
from ._profile import _ProfileLocked, _ProfileMissing
from ._representation import classify, decode_html, parse_content_length, parse_media_type, safe_headers
from ._robots import RobotsAuthority
from ._safety import CanonicalURL, DestinationGuard, SafetyRejection, canonicalize
from ._safety_runtime import HostDenied, SafetyRuntime
from ._session import SessionSnapshot
from ._types import (AttemptRecord, ConditionResult, EncodingRecord, Evidence, EvidenceCategory,
                     Headers, Mode, Outcome, ReadinessResult, RedirectHop, RenderedRepresentation,
                     ResourceKind, SourceRepresentation)
from .policy import AcquisitionPolicy, build_user_agent

BROWSER_BACKEND = "playwright-chromium"
_HARDENING = (
    "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-background-networking",
    "--disable-component-update", "--disable-domain-reliability", "--dns-prefetch-disable",
    "--disable-default-apps", "--disable-extensions", "--disable-file-system", "--disable-sync",
    "--no-pings", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
)


def _browser_channel(engine: str) -> dict[str, str]:
    """Return the Playwright launch channel for the selected browser engine."""
    return {} if engine == "headless-shell" else {"channel": engine}


@dataclass(frozen=True)
class BrowserStatus:
    available: bool
    code: str | None
    detail: str
    facts: tuple[tuple[str, str], ...] = ()

def browser_status(policy=None) -> BrowserStatus:
    if is_forked_child():
        return BrowserStatus(False, "backend.fork_unsafe", "browser runtime is not supported in a forked child")
    if policy is not None and policy.stealth.mode == "real-chrome":
        import os
        from ._real_chrome import DEFAULT_CHROME
        executable = policy.stealth.chrome_path or DEFAULT_CHROME
        if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
            return BrowserStatus(False, "backend.unavailable", f"Google Chrome executable unavailable: {executable}")
        try:
            importlib.metadata.version("playwright")
        except importlib.metadata.PackageNotFoundError:
            return BrowserStatus(False, "backend.unavailable", "install fetchward[browser] for CDP attachment")
        return BrowserStatus(True, None, "installed Chrome with guarded proxy")
    return _browser_status_cached()

@lru_cache(maxsize=1)
def _browser_status_cached() -> BrowserStatus:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as driver:
            executable = Path(driver.chromium.executable_path)
        if not executable.exists():
            raise FileNotFoundError
        version = importlib.metadata.version("playwright")
        return BrowserStatus(True, None, "Playwright Chromium with guarded proxy", (("playwright", version),))
    except Exception:
        return BrowserStatus(False, "backend.unavailable", "install fetchward[browser] and Playwright Chromium")

def _source_from_capture(
    document: tuple[str, int, tuple[tuple[str, str], ...], bytes, str | None] | None,
    attempt_id: str,
    decode_limit: int,
) -> tuple[SourceRepresentation | None, list[Evidence]]:
    if document is None:
        return None, []
    url, status, raw_headers, raw_body, body_error = document
    headers = Headers(raw_headers)
    declared = headers.get("content-type")
    media = parse_media_type(declared)
    content_encoding = tuple(
        token.strip().lower()
        for value in headers.get_all("content-encoding")
        for token in value.split(",")
        if token.strip()
    )
    # Playwright response.body() is already content-decoded by Chromium.
    body, content_decoded, encoding_error = raw_body[:decode_limit], bool(content_encoding), None
    if encoding_error is not None:
        body = raw_body
    kind, inferred, evidence = classify(declared, body, attempt_id)
    text = None
    if kind is ResourceKind.HTML and encoding_error is None:
        text, encoding = decode_html(body, media.charset, content_encoding, content_decoded)
    else:
        encoding = EncodingRecord(
            content_encoding=content_encoding,
            content_decoded=False,
            transport_charset=media.charset,
            conflicts=(encoding_error,) if encoding_error else (),
        )
    if encoding_error is not None:
        evidence.append(
            Evidence(
                "content.encoding_error",
                EvidenceCategory.OBSERVATION,
                True,
                attempt_id,
                facts=(
                    ("code", encoding_error),
                    ("encoding", ",".join(content_encoding)),
                ),
            )
        )
    length_header = headers.get("content-length")
    declared_length, malformed_length = parse_content_length(length_header)
    if malformed_length and body_error is None:
        body_error = "network.interrupted"
    if body_error is not None:
        evidence.append(
            Evidence(
                "content.body_incomplete",
                EvidenceCategory.OBSERVATION,
                True,
                attempt_id,
                facts=(("code", body_error),),
            )
        )
    interruption = body_error or encoding_error
    source = SourceRepresentation(
        body=body,
        attempt_id=attempt_id,
        url=url,
        status_code=status,
        headers=safe_headers(headers),
        kind=kind,
        declared_media_type=media.essence,
        inferred_media_type=inferred,
        encoding=encoding,
        complete=encoding_error is None and body_error is None,
        interruption=interruption,
        declared_content_length=declared_length,
        decoded_text=text,
    )
    return source, evidence


def _challenge_detected(
    status: int,
    headers: tuple[tuple[str, str], ...],
    dom: str,
    source_text: str | None = None,
    *,
    html: bool = False,
) -> bool:
    # Explicit challenge headers apply to every media type. Textual markers are checked
    # independently in source and rendered DOM: a JS-only interstitial may exist only in the
    # DOM, while a source interstitial may be replaced during rendering.
    parsed = Headers(headers)
    if detect_challenge(status, parsed, None):
        return True
    if not html:
        return False
    if source_text and detect_challenge(status, parsed, source_text):
        return True
    return bool(dom) and detect_challenge(status, parsed, dom)


def _login_barrier(
    status: int,
    headers: tuple[tuple[str, str], ...],
    dom: str,
    source_text: str | None,
    *,
    url: str | None,
    redirected: bool,
):
    if not (200 <= status < 300):
        return None
    for text in (source_text, dom):
        if text:
            barrier = detect_login_barrier(text, url=url, redirected=redirected)
            if barrier.detected:
                return barrier
    return None


def _playwright_redirects(navigation) -> list[RedirectHop]:
    from playwright.sync_api import Error as PlaywrightError

    redirects: list[RedirectHop] = []
    try:
        chain = []
        current_request = navigation.request if navigation is not None else None
        while current_request is not None:
            chain.append(current_request)
            current_request = current_request.redirected_from
        chain.reverse()
        for previous, following in zip(chain, chain[1:]):
            previous_response = previous.response()
            redirects.append(
                RedirectHop(
                    previous.url,
                    following.url,
                    previous_response.status if previous_response is not None else 301,
                )
            )
    except PlaywrightError:
        return []
    return redirects



class _BrowserOperationalError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail  # read by _fetcher when it records the failure
        super().__init__(detail)


class _BrowserUnavailable(Exception):
    def __init__(self, status: BrowserStatus) -> None:
        self.status = status
        super().__init__(status.detail)


@dataclass
class _Capture:
    document: tuple[str, int, tuple[tuple[str, str], ...], bytes, str | None] | None = None
    status: int | None = None
    headers: tuple[tuple[str, str], ...] = ()
    final_url: str = ""
    redirects: tuple[RedirectHop, ...] = ()
    dom: str = ""
    dom_truncated: bool = False
    condition: ConditionResult = field(default_factory=lambda: ConditionResult("selector", "not_evaluated"))
    conditions: list[ConditionResult] = field(default_factory=list)
    error: str | None = None
    denial: str | None = None
    denial_outcome: Outcome | None = None
    evidence: list[Evidence] = field(default_factory=list)
    current: CanonicalURL | None = None
    error_exception: BaseException | None = None
    completed: bool = False
    backend_version: str = "unknown"
    error_detail: str | None = None


def _capture_dom(page, limit: int, timeout_seconds: float) -> tuple[str, bool]:
    if limit <= 0 or timeout_seconds <= 0:
        return "", True
    text = page.content()
    return (text, False) if len(text.encode("utf-8")) <= limit else ("", True)


def _wait_for_readiness(page, readiness, admission, timeout_error):
    """Evaluate declared conditions under one shared selector/deadline budget."""
    started = time.monotonic()
    deadline = started + min(readiness.selector_timeout, max(0.0, admission.work_allowance()))
    selectors = ((readiness.selector,) if readiness.selector is not None else ()) + readiness.selectors
    results: list[ConditionResult] = []

    def remaining() -> float:
        return max(0.0, min(deadline - time.monotonic(), admission.work_allowance()))

    def wait_for_selectors(state: str) -> bool:
        if not selectors:
            return True
        if readiness.match == "any":
            allowance = remaining()
            if allowance <= 0:
                return False
            page.locator(", ".join(selectors)).first.wait_for(state=state, timeout=allowance * 1000)
            return remaining() > 0
        for selector in selectors:
            allowance = remaining()
            if allowance <= 0:
                return False
            page.locator(selector).first.wait_for(state=state, timeout=allowance * 1000)
            if remaining() <= 0:
                return False
        return True

    def wait_for_text() -> bool:
        locator = page.locator(", ".join(selectors)) if selectors else page.locator("body")
        if readiness.visible:
            locator = locator.filter(visible=True)
        while remaining() > 0:
            matched = any(readiness.text_contains in text for text in locator.all_inner_texts())
            if remaining() <= 0:
                return False
            if matched:
                return True
            delay = min(0.1, remaining())
            if delay > 0:
                time.sleep(delay)
        return False

    def wait_for_stable_dom(duration_ms: int) -> bool:
        duration = duration_ms / 1000
        previous_length: int | None = None
        stable_since = 0.0
        while remaining() > 0:
            length = len(page.content())
            now = time.monotonic()
            if remaining() <= 0:
                return False
            if previous_length is None or length != previous_length:
                previous_length = length
                stable_since = now
            elif now - stable_since >= duration:
                return True
            delay = min(0.1, remaining(), max(0.0, duration - (time.monotonic() - stable_since)))
            if delay > 0:
                time.sleep(delay)
            elif duration == 0:
                return True
        return False

    if selectors:
        condition_started = time.monotonic()
        state = "visible" if readiness.visible else "attached"
        try:
            met = wait_for_selectors(state)
        except timeout_error:
            met = False
        elapsed = time.monotonic() - condition_started
        results.append(ConditionResult("selector", "satisfied" if met else "timeout", elapsed))
        if readiness.visible:
            results.append(ConditionResult("visible", "satisfied" if met else "timeout", elapsed))
    elif readiness.visible:
        results.append(ConditionResult("visible", "satisfied", 0.0))

    if readiness.text_contains is not None:
        condition_started = time.monotonic()
        try:
            met = wait_for_text()
        except timeout_error:
            met = False
        results.append(ConditionResult("text_contains", "satisfied" if met else "timeout",
                                       time.monotonic() - condition_started))

    other_conditions_met = all(result.status == "satisfied" for result in results)
    if readiness.dom_stable_ms is not None:
        condition_started = time.monotonic()
        if other_conditions_met:
            try:
                met = wait_for_stable_dom(readiness.dom_stable_ms)
            except timeout_error:
                met = False
            status = "satisfied" if met else "timeout"
        else:
            status = "not_evaluated"
        results.append(ConditionResult("dom_stable", status, time.monotonic() - condition_started))

    if results:
        satisfied = all(result.status == "satisfied" for result in results)
        summary = ConditionResult("readiness", "satisfied" if satisfied else "timeout",
                                  time.monotonic() - started)
    else:
        summary = ConditionResult("readiness", "not_evaluated")
    return results, summary


def _robots_check(target, policy, admission, guard, safety, robots):
    http = CurlHTTPAdapter(policy, guard, safety=safety)
    host = f"[{target.host}]" if ":" in target.host else target.host
    robots_url = canonicalize(f"{target.scheme}://{host}:{target.port}/robots.txt")

    def fetch():
        return http.run(
            "browser-robots", robots_url, admission, time.time(), purpose="robots",
            redirect_purpose="robots",
            max_redirects=min(policy.scheduling.robots_max_redirects, policy.budgets.max_robots_redirects),
            source_cap=policy.scheduling.robots_max_bytes, redirect_hook=None,
        )
    return robots.decide(target, policy, admission, fetch, now_wall=time.time)


def _effective_ua(policy, native_ua):
    """The UA this acquisition sends: configured or native, plus the token in automated mode."""
    ua = policy.transport.user_agent or native_ua
    if policy.access.mode == "automated":
        ua = build_user_agent(ua, policy.access.product_token, fallback=native_ua)
    return ua


def _browser_worker(browser, native_ua, policy, admission, guard, safety, robots, gateway, state, start, credentials, attempt_id, context=None):
    from playwright.sync_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeout

    # ``context`` is either the caller's persistent context or one this worker creates and closes.
    host_lease = ticket = page = None
    ticket_started = 0.0
    first_document = True

    def timeout_ms():
        return max(1, int(admission.work_allowance() * 1000))

    def note(code):
        if not any(item.code == code for item in state.evidence):
            state.evidence.append(Evidence(code, EvidenceCategory.OBSERVATION, True, attempt_id))

    def on_request(request):
        try:
            target = canonicalize(request.url)
        except SafetyRejection:
            return
        if credentials and credentials.has_browser_headers(target):
            note("session.headers_not_applied")
        try:
            if request.is_navigation_request() and request.frame == page.main_frame:
                state.current = target
                state.final_url = target.url
        except PlaywrightError:
            pass

    def route_request(route):
        nonlocal first_document, ticket, ticket_started, host_lease
        request = route.request
        if not admission.reserve_browser_request():
            note("budget.browser_requests")
            route.abort()
            return
        scheme = urlsplit(request.url).scheme.lower()
        if scheme not in ("http", "https", "data", "blob"):
            route.abort()
            return
        try:
            frame = request.frame
            is_main = request.is_navigation_request() and frame == page.main_frame
            is_popup = frame.page != page
        except PlaywrightError:
            is_main, is_popup = False, True
        if is_popup:
            note("navigation.popup_denied")
            route.abort()
            return
        if request.resource_type in policy.transport.browser_block_resource_types:
            route.abort()
            return
        if is_main:
            if not first_document:
                note("navigation.unexpected_document")
                route.abort()
                return
            first_document = False
            try:
                slot = safety.host_slot(start.host, admission.work_allowance(), policy.scheduling)
                host_lease = slot.__enter__()
                ticket = admission.reserve_request("resource", request.url)
                ticket_started = time.monotonic()
            except (Denied, HostDenied) as exc:
                state.denial = exc.code
                route.abort()
                return
        # Never inject Session headers; Playwright forwards overrides across redirects.
        route.continue_()

    def on_response(response):
        nonlocal host_lease, ticket
        try:
            request = response.request
            if not request.is_navigation_request() or request.frame != page.main_frame:
                return
            headers = tuple((entry["name"], entry["value"]) for entry in response.headers_array())
            state.status = response.status
            state.headers = headers
            state.final_url = response.url
            state.redirects = tuple(_playwright_redirects(response))
            if host_lease is None and response.status in (429, 503):
                try:
                    target = canonicalize(response.url)
                    host_lease = safety.host_slot(target.host, admission.work_allowance(), policy.scheduling).__enter__()
                except (HostDenied, SafetyRejection):
                    pass
            if host_lease is not None:
                host_lease.observe_response(response.status, Headers(headers), time.monotonic(), time.time())
                host_lease.release()
                host_lease = None
            if ticket is not None:
                admission.complete(ticket, status_code=response.status, pinned_address=None,
                                   connected_address=None, elapsed=time.monotonic() - ticket_started)
                ticket = None
        except PlaywrightError:
            pass

    try:
        if credentials and credentials.has_browser_headers(start):
            note("session.headers_not_applied")
        if policy.access.mode == "automated":
            decision = _robots_check(start, policy, admission, guard, safety, robots)
            state.evidence.extend(decision.evidence)
            if not decision.allowed:
                state.denial, state.denial_outcome = decision.reason, decision.outcome
                return
        if context is None:
            context = browser.new_context(user_agent=_effective_ua(policy, native_ua),
                                          service_workers="block", accept_downloads=False,
                                          proxy=gateway.proxy)
        if credentials:
            cookies = credentials.browser_cookies()
            if cookies:
                context.add_cookies(cookies)
        page = context.new_page()
        def deny_popup(popup):
            if popup != page:
                note("navigation.popup_denied")
                popup.close()
        context.on("page", deny_popup)
        context.on("request", on_request)
        context.route("**/*", route_request)
        context.on("response", on_response)
        if policy.stealth.mode == "real-chrome":
            cdp = context.new_cdp_session(page)
            cdp.send("Network.enable")
            cdp.send("Network.setBypassServiceWorker", {"bypass": True})
            native = page.evaluate("navigator.userAgent").replace("HeadlessChrome", "Chrome")
            ua = _effective_ua(policy, native)
            if ua:
                cdp.send("Network.setUserAgentOverride", {"userAgent": ua})
        try:
            navigation = page.goto(start.url, wait_until="commit", timeout=timeout_ms())
            if navigation is not None:
                state.status = navigation.status
                state.headers = tuple((h["name"], h["value"]) for h in navigation.headers_array())
                state.redirects = tuple(_playwright_redirects(navigation))
                state.final_url = navigation.url
                for hop in state.redirects:
                    try:
                        admission.reserve_redirect()
                        redirect_ticket = admission.reserve_request("redirect", hop.to_url)
                        admission.complete(redirect_ticket, status_code=None, pinned_address=None,
                                           connected_address=None, elapsed=0)
                    except Denied as exc:
                        state.error = exc.code
                        break
                if policy.access.mode == "automated":
                    for hop in state.redirects:
                        decision = _robots_check(canonicalize(hop.to_url), policy, admission, guard, safety, robots)
                        state.evidence.extend(decision.evidence)
                        if not decision.allowed:
                            state.denial = decision.reason or "access.robots_denied"
                            state.denial_outcome = decision.outcome or Outcome.BLOCKED
                            note("access.robots_posthoc")
                            return
                length, malformed = parse_content_length(Headers(state.headers).get("content-length"))
                cap = min(policy.budgets.max_source_bytes, max(0, admission.byte_allowance()))
                if length is not None and length > cap:
                    body, error = b"", "budget.bytes"
                else:
                    try:
                        body = navigation.body()
                        error = None
                        if len(body) > cap:
                            body, error = body[:cap], "budget.bytes"
                        if malformed:
                            error = "network.interrupted"
                    except PlaywrightError:
                        body, error = b"", "network.interrupted"
                if error == "budget.bytes":
                    admission.note_exhausted(error)
                declared = (Headers(state.headers).get("content-type") or "").split(";")[0].strip().lower()
                if declared and "html" not in declared and not declared.startswith("text/") \
                        and body.lstrip()[:15].lower().startswith((b"<!doctype", b"<html")):
                    # Chromium substituted a viewer page (e.g. its PDF viewer) for the resource:
                    # these bytes are not the document the server sent, so don't claim them.
                    state.error = "backend.unsupported"
                    note("browser.viewer_substituted")
                    return
                state.document = (navigation.url, navigation.status, state.headers, body, error)
                kind, _, _ = classify(Headers(state.headers).get("content-type"), body, attempt_id)
                if kind is ResourceKind.HTML and state.status not in (401, 403, 429):
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=timeout_ms())
                        state.conditions, state.condition = _wait_for_readiness(
                            page, policy.readiness, admission, PlaywrightTimeout)
                        dom_cap = min(policy.budgets.max_dom_bytes, max(0, admission.byte_allowance() - len(body)))
                        state.dom, state.dom_truncated = _capture_dom(page, dom_cap, admission.work_allowance())
                    except PlaywrightTimeout:
                        state.error = "browser.timeout"
                        try:
                            state.dom, state.dom_truncated = _capture_dom(page, policy.budgets.max_dom_bytes, admission.work_allowance())
                        except PlaywrightError:
                            pass
        except PlaywrightTimeout:
            state.error = "browser.timeout"
        except PlaywrightError as exc:
            state.error = "backend.unsupported" if "Download is starting" in str(exc) else "network.connect"
    except PlaywrightError:
        state.error = "budget.deadline" if admission.remaining() <= 0 else "backend.unavailable"
    except BaseException as exc:
        state.error_exception = exc
    finally:
        if ticket is not None:
            admission.complete(ticket, status_code=None, pinned_address=None, connected_address=None,
                               elapsed=time.monotonic() - ticket_started, reason=state.denial or state.error)
        if host_lease is not None:
            host_lease.release()
        if context is not None and policy.stealth.mode != "real-chrome":
            try:
                context.close()
            except Exception:
                pass
        elif context is not None:
            # The attached default context outlives this worker: detach handlers before the
            # connection drops so in-flight routes are not cancelled noisily.
            try:
                context.unroute_all(behavior="ignoreErrors")
                if page is not None:
                    page.close()
            except Exception:
                pass
        state.completed = True


def _launch_persistent(manager, profile_path, proxy, user_agent, timeout_ms, engine="chromium", *, headless=True):
    """One Chromium on the caller's user-data directory behind this acquisition's proxy."""
    options = {
        **_browser_channel(engine),
        "headless": headless,
        "proxy": proxy,
        "args": list(_HARDENING),
        "timeout": timeout_ms,
        "service_workers": "block",
        "accept_downloads": False,
    }
    if user_agent is not None:
        options["user_agent"] = user_agent
    return manager.chromium.launch_persistent_context(str(profile_path), **options)


def _native_user_agent(context) -> str:
    page = context.new_page()
    try:
        return page.evaluate("navigator.userAgent").replace("HeadlessChrome", "Chrome")
    finally:
        page.close()


# One probe per process and engine binary: the string is a property of the engine, not of the
# profile, so later launches skip the extra Chromium start.
_NATIVE_UA: dict[str, str] = {}
_NATIVE_UA_LOCK = threading.Lock()


def _native_user_agent_for(manager, profile_path, proxy, timeout_ms, engine="chromium") -> str:
    """The engine's own UA, probing only on the first launch for this engine."""
    key = (engine, str(manager.chromium.executable_path))
    with _NATIVE_UA_LOCK:
        cached = _NATIVE_UA.get(key)
    if cached is not None:
        return cached
    # A persistent context fixes its UA at launch and the default UA derives from the
    # engine's own string, so probe it once, then relaunch with the UA we would send.
    probe = _launch_persistent(manager, profile_path, proxy, None, timeout_ms, engine)
    try:
        value = _native_user_agent(probe)
    finally:
        probe.close()
    with _NATIVE_UA_LOCK:
        _NATIVE_UA.setdefault(key, value)
    return value


def _profile_acquisition(manager, profile, policy, admission, guard, safety, robots, gateway, state, start, credentials, attempt_id):
    """Run one acquisition on a profile. The worker closes the context it is given."""
    timeout_ms = max(1, int(admission.work_allowance() * 1000))
    native_ua = None
    if policy.transport.user_agent is None:
        native_ua = _native_user_agent_for(manager, profile.path, gateway.proxy, timeout_ms,
                                           policy.transport.browser_engine)
    context = _launch_persistent(manager, profile.path, gateway.proxy,
                                 _effective_ua(policy, native_ua), timeout_ms,
                                 policy.transport.browser_engine)
    _browser_worker(None, native_ua, policy, admission, guard, safety, robots, gateway, state,
                    start, credentials, attempt_id, context=context)


def _profile_thread(profile, lock, policy, admission, guard, safety, robots, gateway, state, start, credentials, attempt_id, done, chrome=None):
    from playwright.sync_api import Error as PlaywrightError, sync_playwright

    manager = None
    try:
        try:
            manager = sync_playwright().start()
            if chrome is None:
                _profile_acquisition(manager, profile, policy, admission, guard, safety, robots,
                                     gateway, state, start, credentials, attempt_id)
            else:
                browser, context = chrome.start(manager)
                try:
                    state.backend_version = browser.version
                    state.evidence.append(Evidence("stealth.real_chrome", EvidenceCategory.OBSERVATION, True,
                                                   attempt_id, facts=(("version", browser.version),
                                                                      ("ownership", chrome.ownership))))
                    _browser_worker(None, None, policy, admission, guard, safety, robots, gateway, state,
                                    start, credentials, attempt_id, context=context)
                finally:
                    browser.close()
        except (FileNotFoundError, OSError) as exc:
            state.error = "backend.unavailable"
            state.error_detail = str(exc)
        except (TimeoutError, RuntimeError) as exc:
            state.error = "backend.unavailable" if chrome is not None else (
                "budget.deadline" if admission.remaining() <= 0 else "backend.unavailable")
            state.error_detail = str(exc)
        except PlaywrightError:
            state.error = "budget.deadline" if admission.remaining() <= 0 else "backend.unavailable"
        except BaseException as exc:
            state.error_exception = exc
    finally:
        if manager is not None:
            try:
                manager.stop()
            except Exception:
                pass
        if chrome is not None:
            chrome.stop()
        state.completed = True
        lock.release()
        done.set()


def _build_record(policy, admission, gateway, state, start, attempt_id, started_wall, first_seq, overrun):
    evidence = list(state.evidence)
    if state.error_detail:
        evidence.append(Evidence("backend.unavailable", EvidenceCategory.OBSERVATION, True, attempt_id,
                                 facts=(("detail", state.error_detail),)))
    source, source_evidence = _source_from_capture(state.document, attempt_id, min(policy.budgets.max_source_bytes, admission.byte_allowance()))
    evidence.extend(source_evidence)
    denied = [e for e in gateway.events if e.kind == "denied" and e.reason not in ("gateway.stopped", "budget.deadline")]
    for event in denied:
        evidence.append(Evidence(event.reason or "network.connect", EvidenceCategory.OBSERVATION, True, attempt_id))
    current = state.current or start
    denial = state.denial
    if denial is None:
        matching = [e for e in denied if e.origin == current.origin and (e.path is None or e.path == current.target)]
        reached = any(e.kind in ("forward", "tunnel") and e.origin == current.origin and
                      (e.path is None or e.path == current.target) for e in gateway.events)
        if matching and not reached:
            denial = matching[-1].reason
            source = None
    if denial == "safety.url_rejected":
        denial = "safety.destination_rejected"
    status = state.status
    reason = state.error
    outcome = Outcome.ERROR
    if denial:
        reason = denial
        outcome = state.denial_outcome or (Outcome.BLOCKED if denial == "access.robots_denied" else Outcome.ERROR)
        source = None
    elif status == 401:
        outcome, reason = Outcome.AUTH_REQUIRED, "http.auth_required"
    elif status == 403:
        outcome, reason = Outcome.BLOCKED, "http.forbidden"
    elif status == 429:
        outcome, reason = Outcome.RATE_LIMITED, "http.rate_limited"
    elif status is not None and not 200 <= status < 300:
        reason = "http.error_status"
    elif source is not None and _challenge_detected(status, state.headers, state.dom, source.decoded_text, html=source.kind is ResourceKind.HTML):
        outcome, reason = Outcome.BLOCKED, "browser.challenge"
        evidence.append(Evidence("evidence.challenge", EvidenceCategory.OBSERVATION, True, attempt_id))
    elif status == 202:
        outcome, reason = Outcome.PARTIAL, "http.accepted_incomplete"
        evidence.append(Evidence("http.accepted_incomplete", EvidenceCategory.OBSERVATION, True, attempt_id))
    elif source is not None and source.kind is ResourceKind.HTML and (barrier := _login_barrier(status, state.headers, state.dom, source.decoded_text, url=state.final_url, redirected=bool(state.redirects))) is not None:
        outcome, reason = Outcome.AUTH_REQUIRED, "http.login_required"
        evidence.append(Evidence("evidence.login_barrier", EvidenceCategory.OBSERVATION, True, attempt_id, facts=barrier.facts()))
    elif source is not None and source.interruption:
        outcome, reason = (Outcome.PARTIAL if source.body else Outcome.ERROR), source.interruption
        if not source.body:
            source = None
    elif state.error:
        outcome = Outcome.PARTIAL if source is not None and source.body else Outcome.ERROR
    elif source is not None and source.kind is not ResourceKind.HTML:
        if policy.readiness.requires_browser:
            outcome, reason = Outcome.PARTIAL, "readiness.unsupported"
        else:
            outcome, reason = Outcome.SUCCESS, None
    elif state.condition.status in ("timeout", "unsupported"):
        outcome, reason = Outcome.PARTIAL, "readiness.selector_unmet"
    elif state.dom_truncated:
        outcome, reason = Outcome.PARTIAL, "readiness.dom_limit"
    elif state.dom and source:
        outcome, reason = Outcome.SUCCESS, None
    elif source:
        outcome, reason = Outcome.PARTIAL, "browser.no_dom"
    # Hitting the page-request cap aborts extra subresources; it is reported as evidence and in
    # budget.exhausted, but the document is not partial unless a readiness requirement failed.
    if overrun:
        evidence.append(Evidence("cleanup.overrun", EvidenceCategory.OBSERVATION, True, attempt_id))
    if source and source.decoded_text:
        shell = detect_js_shell(source.decoded_text)
        evidence.append(Evidence("evidence.js_shell", EvidenceCategory.INFERENCE, shell.detected, attempt_id))
    limits = ["no_frame_flattening", "no_shadow_serialization", "no_interaction"]
    if state.dom_truncated:
        limits.append("dom_limit")
        evidence.append(Evidence("evidence.dom_limit", EvidenceCategory.OBSERVATION, True, attempt_id))
    readiness = ReadinessResult(lifecycle="domcontentloaded", conditions=tuple(state.conditions),
                                elapsed=max(0.0, time.time() - started_wall), limits=tuple(limits))
    rendered = None
    if state.dom and source and source.kind is ResourceKind.HTML:
        dom_bytes = len(state.dom.encode("utf-8"))
        if dom_bytes + len(source.body) <= admission.byte_allowance():
            admission.retain_bytes(dom_bytes)
            rendered = RenderedRepresentation(state.dom, attempt_id, state.final_url or start.url, time.time(), readiness)
    if source:
        admission.retain_bytes(len(source.body))
    backend = "real-chrome" if policy.stealth.mode == "real-chrome" else BROWSER_BACKEND
    return AttemptRecord(id=attempt_id, mode=Mode.BROWSER, backend=backend, backend_version=state.backend_version,
                         started_at=started_wall, duration=max(0.0, time.time() - started_wall), requested_url=start.url,
                         final_url=state.final_url or start.url, outcome=outcome, reasons=(reason,) if reason else (),
                         redirects=state.redirects, requests=admission.events_since(first_seq), evidence=tuple(evidence),
                         readiness=readiness, source=source, rendered=rendered)


class _BrowserHost:
    """A single Chromium and all its Playwright objects, confined to one thread."""

    def __init__(self, engine):
        self.engine = engine
        self.jobs = queue.Queue()
        self.healthy = True
        self.busy = False
        self.thread = threading.Thread(target=self._run, daemon=True, name="browser-host")
        self.thread.start()

    def _run(self):
        from playwright.sync_api import Error as PlaywrightError, sync_playwright

        manager = browser = None
        native_ua = None
        try:
            while True:
                job = self.jobs.get()
                if job is None:
                    break
                args, done = job
                admission, state = args[1], args[6]
                try:
                    if browser is None:
                        manager = sync_playwright().start()
                        browser = manager.chromium.launch(
                            **_browser_channel(self.engine), headless=True,
                            proxy={"server": "http://127.0.0.1:9"}, args=list(_HARDENING),
                            timeout=max(1, int(admission.work_allowance() * 1000)))
                        state.backend_version = f"{self.engine}/{browser.version}"
                        probe = browser.new_context()
                        try:
                            native_ua = probe.new_page().evaluate("navigator.userAgent").replace("HeadlessChrome", "Chrome")
                        finally:
                            probe.close()
                    _browser_worker(browser, native_ua, *args)
                    self.healthy = browser.is_connected()
                except PlaywrightError:
                    state.error = "budget.deadline" if admission.remaining() <= 0 else "backend.unavailable"
                    if state.error == "backend.unavailable" and self.engine == "chrome":
                        state.error_detail = "Google Chrome is unavailable for Playwright channel 'chrome'; install Google Chrome"
                    state.completed = True
                    self.healthy = False
                except BaseException as exc:
                    state.error_exception = exc
                    state.completed = True
                    self.healthy = False
                finally:
                    args = job = state = None
                    done.set()
                if not self.healthy:
                    break
        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
            if manager is not None:
                try:
                    manager.stop()
                except Exception:
                    pass

    def stop(self):
        self.jobs.put(None)


class _BrowserPool:
    """Lazily allocate one serial host per concurrent browser acquisition."""

    def __init__(self, capacity):
        self.capacity = capacity
        self.fork_generation = generation()
        self.condition = threading.Condition()
        self.hosts: dict[str, set[_BrowserHost]] = {}
        self.chromes = set()
        self.closed = False

    def register_chrome(self, chrome):
        with self.condition:
            if self.closed:
                raise _BrowserOperationalError("backend.unavailable", "browser pool is closed")
            self.chromes.add(chrome)

    def unregister_chrome(self, chrome):
        with self.condition:
            self.chromes.discard(chrome)

    def submit(self, args, admission, engine):
        with self.condition:
            while True:
                if self.closed:
                    raise _BrowserOperationalError("backend.unavailable", "browser pool is closed")
                engine_hosts = self.hosts.setdefault(engine, set())
                host = next((h for h in engine_hosts if not h.busy), None)
                if host is None and len(engine_hosts) < self.capacity:
                    host = _BrowserHost(engine)
                    engine_hosts.add(host)
                if host is not None:
                    host.busy = True
                    done = threading.Event()
                    host.jobs.put((args, done))
                    return host, done
                remaining = admission.remaining()
                if remaining <= 0:
                    raise _BrowserOperationalError("budget.deadline", "browser host wait timed out")
                self.condition.wait(remaining)

    def release(self, host, retire=False):
        with self.condition:
            if retire or not host.healthy:
                engine_hosts = self.hosts.get(host.engine)
                if engine_hosts is not None:
                    engine_hosts.discard(host)
                    if not engine_hosts:
                        self.hosts.pop(host.engine, None)
                host.stop()
            else:
                host.busy = False
            self.condition.notify_all()

    def close(self, wait=True):
        with self.condition:
            self.closed = True
            hosts = tuple(host for engine_hosts in self.hosts.values() for host in engine_hosts)
            chromes = tuple(self.chromes)
            self.hosts.clear()
            for host in hosts:
                host.stop()
            self.condition.notify_all()
        for chrome in chromes:
            chrome.stop()
        if wait:
            deadline = time.monotonic() + 1.5
            for host in hosts:
                host.thread.join(max(0, deadline - time.monotonic()))

    def __del__(self):
        if getattr(self, "fork_generation", None) == generation():
            self.close(wait=False)


def run_browser(policy, admission, guard, safety, robots, *, start, attempt_id, started_wall, credentials=None, pool, profile=None):
    status = browser_status(policy) if policy.stealth.mode == "real-chrome" else browser_status()
    if not status.available:
        raise _BrowserUnavailable(status)
    lock = None
    if profile is not None:
        try:
            lock = profile._acquire(time.monotonic() + max(0.0, admission.remaining()))
        except _ProfileLocked as exc:
            raise _BrowserOperationalError("profile.locked", "profile is in use by another acquisition") from exc
        except _ProfileMissing as exc:
            raise _BrowserOperationalError("profile.unavailable", "profile directory is missing") from exc
    handed_off = False
    chrome = None
    try:
        real_chrome = policy.stealth.mode == "real-chrome"
        if profile is not None:
            profile._use_engine("real-chrome" if real_chrome else "playwright-chromium")
        gateway = EgressGateway(guard.check, remaining=admission.remaining, cleanup_timeout=0.5,
                                require_auth=not real_chrome)
        try:
            gateway.start()
        except OSError as exc:
            raise _BrowserOperationalError("backend.unavailable", "browser proxy could not start") from exc
        state = _Capture(final_url=start.url)
        first_seq = admission.seq
        if profile is not None:
            if real_chrome:
                from ._real_chrome import RealChrome
                chrome = RealChrome(pool, policy.stealth.chrome_path, profile.path, gateway.proxy["server"],
                                    time.monotonic() + admission.remaining(), headless=True)
            # Directory name only: the full path is the caller's business.
            state.evidence.append(Evidence("profile.used", EvidenceCategory.OBSERVATION, True, attempt_id,
                                           facts=(("profile", profile.path.name),)))
            done = threading.Event()
            threading.Thread(
                target=_profile_thread,
                args=(profile, lock, policy, admission, guard, safety, robots, gateway, state, start,
                      credentials, attempt_id, done, chrome),
                daemon=True, name="browser-profile",
            ).start()
            # The profile thread releases the lock when its own cleanup ends, so an overrun
            # cannot free the profile while Chromium is still using it.
            handed_off = True
        else:
            try:
                host, done = pool.submit((policy, admission, guard, safety, robots, gateway, state, start, credentials, attempt_id), admission, policy.transport.browser_engine)
            except BaseException:
                gateway.stop()
                raise
        try:
            done.wait(admission.remaining())
        except BaseException:
            if chrome is not None:
                chrome.stop()
            gateway.stop()
            finished = done.wait(1.5)
            if profile is None:
                pool.release(host, retire=not finished)
            raise
        if chrome is not None and not done.is_set():
            chrome.stop()
        gateway.stop()
        finished = done.wait(1.5) if not done.is_set() else True
        if profile is None:
            pool.release(host, retire=not finished)
    finally:
        if lock is not None and not handed_off:
            lock.release()
    if state.error_exception is not None:
        raise state.error_exception
    if not finished or not state.completed:
        state.error = state.error or "budget.deadline"
    return _build_record(policy, admission, gateway, state, start, attempt_id, started_wall, first_seq,
                         not finished or bool(gateway.unfinished_handlers_at_stop))


__all__ = ["BrowserStatus", "browser_status", "run_browser"]
