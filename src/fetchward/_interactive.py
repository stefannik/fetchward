"""Explicit user-mediated browser session on a dedicated profile.

Some resources need a person: a login on a site the caller subscribes to, a consent wall, a
challenge. This module opens one visible Chromium on the caller's profile, lets the user act,
and closes it again. The library never clicks, types or fills a form in this session; it only
waits for one of three endings: the user closes the window, an ``until_*`` condition is
observed, or the timeout elapses. Cookies the user's actions produce stay in the profile for
later headless browser acquisitions.

Confinement is the browser confinement described above: every connection goes
through the authenticated, non-decrypting loopback egress proxy with destination checks at
connect time. Popups are allowed (logins use them) but a popup is still an ordinary page in
the same context, so it is proxied and guarded too. Resource blocking is off because the user
needs a normal page; downloads, service workers, QUIC and WebRTC UDP stay off. robots.txt is
not consulted: the session is user-initiated by definition.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from ._browser import _launch_persistent, browser_status
from ._egress import EgressGateway
from ._profile import BrowserProfile, _ProfileLocked, _ProfileMissing
from ._redact import safe_url
from ._safety import CanonicalURL, DestinationGuard, Resolver, SafetyRejection, canonicalize
from ._selectors import validate_selector
from ._types import Evidence, EvidenceCategory
from .errors import ConfigurationError, FetchwardError
from .policy import AcquisitionPolicy

SESSION_REQUEST_CAP = 5_000
MAX_TIMEOUT = 3600.0
_POLL_SECONDS = 0.2
_ENDINGS = frozenset({"closed", "condition", "timeout"})


@dataclass(frozen=True)
class InteractionResult:
    """Outcome of one user-mediated session. Holds no cookies and no page content.

    ``ended_by`` is ``"closed"`` (the user closed the window or the page), ``"condition"``
    (``until_url`` matched the main frame or ``until_selector`` became attached) or
    ``"timeout"``. ``final_url`` is redacted like every diagnostic: origin plus an opaque
    per-run id, never a path, query or fragment. ``requests`` counts the requests interception
    observed, including the ones aborted past the session cap.
    """

    ended_by: str
    final_url: str
    elapsed: float
    requests: int
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if self.ended_by not in _ENDINGS:
            raise ValueError(f"ended_by must be one of {sorted(_ENDINGS)}")


def validate_session(
    url: str,
    until_url: str | None,
    until_selector: str | None,
    timeout: float,
) -> CanonicalURL:
    """Reject bad interactive configuration before any I/O."""
    if not isinstance(url, str):
        raise ConfigurationError("url must be a str")
    if until_url is not None and (not isinstance(until_url, str) or not until_url.strip()):
        raise ConfigurationError("until_url must be a non-empty string or None")
    if until_selector is not None:
        if not isinstance(until_selector, str):
            raise ConfigurationError("until_selector must be a string or None")
        validate_selector(until_selector)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ConfigurationError("timeout must be a number")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ConfigurationError("timeout must be finite and positive")
    if timeout > MAX_TIMEOUT:
        raise ConfigurationError("timeout must be at most 3600 seconds")
    try:
        return canonicalize(url)
    except SafetyRejection as exc:
        raise ConfigurationError("url is not usable for an interactive session") from exc


def run_session(
    *,
    profile: BrowserProfile,
    policy: AcquisitionPolicy,
    resolver: Resolver,
    target: CanonicalURL,
    until_url: str | None,
    until_selector: str | None,
    timeout: float,
    headless: bool = False,
    page_hook: Callable[..., None] | None = None,
    extra_evidence: tuple[Evidence, ...] = (),
) -> InteractionResult:
    """Open one visible session, wait for an ending, then close it; ``page_hook`` is a test seam."""
    from playwright.sync_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeout, sync_playwright

    status = browser_status()
    if not status.available:
        raise FetchwardError(f"browser backend unavailable: {status.code or 'backend.unavailable'}")

    started = time.monotonic()
    deadline = started + timeout
    try:
        lock = profile._acquire(deadline)
    except _ProfileLocked as exc:
        raise FetchwardError("profile is in use by another acquisition") from exc
    except _ProfileMissing as exc:
        raise FetchwardError("profile directory is missing") from exc

    evidence: list[Evidence] = [
        Evidence("profile.used", EvidenceCategory.OBSERVATION, True,
                 facts=(("profile", profile.path.name),)),
        Evidence("access.user_initiated", EvidenceCategory.OBSERVATION, True),
        *extra_evidence,
    ]
    seen = {item.code for item in evidence}
    requests = 0
    capped = False
    closed = threading.Event()
    final_url = target.url
    ended_by = "timeout"
    gateway: EgressGateway | None = None
    manager = None
    context = page = None

    def note(code: str, *, value: object = True) -> None:
        if code not in seen:
            seen.add(code)
            evidence.append(Evidence(code, EvidenceCategory.OBSERVATION, value))

    try:
        guard = DestinationGuard(policy.destinations, resolver)
        # Check the start URL before opening a window: a denied destination should be a clear
        # error, not a browser page showing a proxy failure.
        try:
            guard.check(target, max(0.1, min(10.0, deadline - time.monotonic())))
        except SafetyRejection as exc:
            raise FetchwardError(
                f"interactive destination not allowed ({exc.code}); private or local addresses "
                "need an explicit DestinationPolicy(trusted_local=...)"
            ) from exc
        gateway = EgressGateway(
            guard.check, remaining=lambda: max(0.0, deadline - time.monotonic()), cleanup_timeout=0.5
        )
        try:
            gateway.start()
        except OSError as exc:
            raise FetchwardError("browser proxy could not start") from exc

        manager = sync_playwright().start()
        try:
            context = _launch_persistent(
                manager, profile.path, gateway.proxy, None,
                max(1, int(max(0.0, deadline - time.monotonic()) * 1000)),
                policy.transport.browser_engine, headless=headless,
            )
        except PlaywrightError as exc:
            raise FetchwardError("browser could not be started for an interactive session") from exc

        def route_request(route) -> None:
            # No resource blocking: the user needs a normal page. Nothing is clicked or typed
            # here either; interception only counts and caps what the page asks for.
            nonlocal requests, capped
            requests += 1
            if requests > SESSION_REQUEST_CAP:
                capped = True
                note("budget.browser_requests", value=requests)
                route.abort()
                return
            if urlsplit(route.request.url).scheme.lower() not in ("http", "https", "data", "blob"):
                route.abort()
                return
            route.continue_()

        context.route("**/*", route_request)
        context.on("close", lambda *_: closed.set())
        page = context.pages[0] if context.pages else context.new_page()
        page.on("close", lambda *_: closed.set())

        def finish(ending: str, url: str) -> InteractionResult:
            for event in gateway.events:
                if event.kind == "denied" and event.reason not in ("gateway.stopped", "budget.deadline"):
                    note(event.reason or "network.connect")
            if capped:
                note("budget.browser_requests", value=requests)
            return InteractionResult(
                ended_by=ending,
                final_url=safe_url(url),
                elapsed=time.monotonic() - started,
                requests=requests,
                evidence=tuple(evidence),
            )

        try:
            page.goto(target.url, wait_until="commit",
                      timeout=max(1, int(max(0.0, deadline - time.monotonic()) * 1000)))
        except PlaywrightTimeout:
            pass  # a page that never commits still leaves a window the user can act in
        except PlaywrightError as exc:
            if closed.is_set() or page.is_closed():
                return finish("closed", final_url)
            raise FetchwardError("interactive navigation failed") from exc
        final_url = page.url
        if page_hook is not None:
            page_hook(page)

        while True:
            if closed.is_set():
                ended_by = "closed"
                break
            try:
                final_url = page.url
                met = (until_url is not None and final_url.startswith(until_url)) or (
                    until_selector is not None and page.locator(until_selector).count() > 0
                )
            except PlaywrightError:
                ended_by = "closed" if closed.is_set() or page.is_closed() else "timeout"
                break
            if met:
                ended_by = "condition"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                ended_by = "timeout"
                break
            try:
                page.wait_for_timeout(min(_POLL_SECONDS * 1000, max(1.0, remaining * 1000)))
            except PlaywrightError:
                if closed.is_set() or page.is_closed():
                    ended_by = "closed"
                else:
                    raise
                break

        return finish(ended_by, final_url)
    finally:
        # Cookies the user produced are flushed by a clean context close; the profile lock is
        # held until Chromium has actually let go of the directory.
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if manager is not None:
            try:
                manager.stop()
            except Exception:
                pass
        if gateway is not None:
            gateway.stop()
        lock.release()


__all__ = ["InteractionResult", "MAX_TIMEOUT", "SESSION_REQUEST_CAP", "run_session", "validate_session"]
