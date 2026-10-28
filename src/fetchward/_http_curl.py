"""Direct HTTP adapter on low-level ``curl_cffi`` with Chrome impersonation.

One curl handle per request, Chrome TLS and HTTP fingerprints (HTTP/2 when negotiated),
no proxies, HTTP(S) only, no automatic redirects. libcurl may transparently resend a
request (e.g. after an HTTP/2 ``REFUSED_STREAM``); these internal resends are not included
in the library's request count. The connection is pinned to the address the destination guard validated
and the observed peer address is checked afterwards. Redirects are followed here, hop by
hop, each through the destination guard and the admission authority.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from collections.abc import Callable

from ._admission import Admission, Denied
from ._challenge import detect_challenge
from ._login import detect_login_barrier
from ._redact import safe_url
from ._representation import classify, decode_html, parse_content_length, parse_media_type, safe_headers
from ._safety import (
    CanonicalURL,
    DestinationGuard,
    DNSCancelled,
    DNSFailure,
    DNSTimeout,
    SafetyRejection,
    resolve_redirect,
)
from ._safety_runtime import HostDenied, SafetyRuntime
from ._selection import http_status_outcome
from ._types import (
    AttemptRecord,
    EncodingRecord,
    Evidence,
    EvidenceCategory,
    Headers,
    Mode,
    Outcome,
    RedirectHop,
    ResourceKind,
    SourceRepresentation,
)
from .policy import AcquisitionPolicy, build_user_agent

RedirectHook = Callable[[CanonicalURL], tuple[str | None, Outcome | None]]

BACKEND_NAME = "direct-curl_cffi"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# The newest Chrome target curl_cffi 0.17 impersonates. It is recorded in every attempt's
# ``backend_version`` so a capture can be tied to the fingerprint that produced it.
IMPERSONATE_TARGET = "chrome152"
# The User-Agent curl_cffi attaches as a default header for IMPERSONATE_TARGET. It is only
# the base when the RFC 9309 product token must be appended (automated mode); otherwise
# impersonation supplies the header untouched.
IMPERSONATE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
)

_TLS_CODES = frozenset({35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91, 98})
_INTERRUPTED_CODES = frozenset({8, 16, 18, 52, 55, 56, 92})


@dataclass(frozen=True)
class BackendStatus:
    """Whether the direct backend can run in this installation.

    ``available`` is false and ``code`` is ``backend.unavailable`` when the curl_cffi
    package or its low-level API is missing. The facts contain only reported version
    strings and a safe detail line, never exception text.
    """

    available: bool
    code: str | None
    detail: str
    facts: tuple[tuple[str, str], ...] = ()


def backend_status() -> BackendStatus:
    """Probe the installed curl_cffi package and its low-level API without raising.

    A missing package or a missing low-level API is ``backend.unavailable``. The public
    API turns this into an error result before any admission or dispatch.
    """
    backend = (("backend", BACKEND_NAME),)
    try:
        import curl_cffi
    except Exception:
        return BackendStatus(
            False,
            "backend.unavailable",
            "curl_cffi is not installed; reinstall fetchward",
            backend + (("component", "curl_cffi"), ("required_package", "curl_cffi>=0.17,<0.18")),
        )

    try:
        wrapper = str(curl_cffi.__version__)
    except Exception:
        wrapper = "unknown"

    try:
        from curl_cffi import Curl  # noqa: F401
    except Exception:
        return BackendStatus(
            False,
            "backend.unavailable",
            f"curl_cffi {wrapper} does not expose its low-level API",
            backend + (("observed_curl_cffi", wrapper),),
        )

    return BackendStatus(
        True,
        None,
        "direct HTTP backend",
        backend + (("observed_curl_cffi", wrapper), ("impersonate", IMPERSONATE_TARGET)),
    )


def backend_version() -> str:
    import curl_cffi

    return f"curl_cffi/{curl_cffi.__version__} {IMPERSONATE_TARGET}"


@dataclass
class _Response:
    status: int = 0
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytearray = field(default_factory=bytearray)
    error_code: int | None = None
    cap_hit: bool = False
    connected_address: str | None = None
    received_at: float | None = None
    received_wall: float | None = None


def _same_address(a: str | None, b: str) -> bool:
    if not a:
        return False
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


class CurlHTTPAdapter:
    name = BACKEND_NAME

    def __init__(
        self,
        policy: AcquisitionPolicy,
        guard: DestinationGuard,
        safety: SafetyRuntime | None = None,
        credentials: SessionSnapshot | None = None,
    ) -> None:
        self._policy = policy
        self._guard = guard
        self._safety = safety
        self._credentials = credentials
        base = policy.transport.user_agent or IMPERSONATE_USER_AGENT
        # The default identity is impersonation's Chrome UA, untouched. In automated mode the
        # RFC 9309 product token is appended so robots matching stays truthful; an explicitly
        # configured UA is sent as given otherwise.
        self._user_agent = (
            build_user_agent(
                base,
                policy.access.product_token,
                fallback=base,
                annotate=policy.access.mode == "automated",
            )
            if policy.transport.user_agent or policy.access.mode == "automated"
            else None
        )

    @property
    def request_headers(self) -> tuple[tuple[str, str], ...]:
        """Request headers this adapter sets explicitly, as ``(lower-name, value)``.

        curl_cffi impersonation supplies the rest as a constant default set. The response
        cache uses this to match a stored copy's ``Vary`` names against what was sent.
        """
        return () if self._user_agent is None else (("user-agent", self._user_agent),)

    # -- one request -------------------------------------------------------------------
    def _perform(
        self,
        url: CanonicalURL,
        address: str,
        admission: Admission,
        byte_cap: int,
        request_headers: tuple[tuple[str, str], ...] = (),
    ) -> _Response:
        from curl_cffi import Curl, CurlError, CurlInfo, CurlOpt

        response = _Response()

        def on_header(line: bytes) -> int:
            text = line.decode("latin-1").rstrip("\r\n")
            if text.startswith("HTTP/"):
                response.headers.clear()  # a new (possibly final, after 1xx) response begins
                response.received_at = time.monotonic()
                response.received_wall = time.time()
            elif ":" in text:
                name, _, value = text.partition(":")
                response.headers.append((name.strip(), value.strip()))
            return len(line)

        def on_body(chunk: bytes) -> int:
            room = byte_cap - len(response.body)
            if len(chunk) > room:
                response.body.extend(chunk[: max(room, 0)])
                response.cap_hit = True
                return 0xFFFFFFFF  # CURL_WRITEFUNC_ERROR: abort the transfer
            response.body.extend(chunk)
            return len(chunk)

        allowance_ms = max(1, int(admission.work_allowance() * 1000))
        curl = Curl()
        try:
            # Chrome's TLS and HTTP/2 fingerprint, plus its default request headers. libcurl
            # may transparently resend a request (e.g. after an HTTP/2 REFUSED_STREAM); these
            # internal resends are not included in the library's request count.
            curl.impersonate(IMPERSONATE_TARGET, default_headers=True)
            curl.setopt(CurlOpt.URL, url.url.encode("ascii"))
            if url.ip is None:
                pinned = f"[{address}]" if ":" in address else address
                curl.setopt(CurlOpt.RESOLVE, [f"{url.host}:{url.port}:{pinned}".encode("ascii")])
            curl.setopt(CurlOpt.PROXY, b"")
            curl.setopt(CurlOpt.NOPROXY, b"*")
            curl.setopt(CurlOpt.PROTOCOLS_STR, b"http,https")
            curl.setopt(CurlOpt.REDIR_PROTOCOLS_STR, b"http,https")
            curl.setopt(CurlOpt.FOLLOWLOCATION, 0)
            curl.setopt(CurlOpt.TIMEOUT_MS, allowance_ms)
            curl.setopt(CurlOpt.CONNECTTIMEOUT_MS, allowance_ms)
            # Decode transfer encodings in libcurl and keep the original headers, which the
            # representation layer reports as ``content_encoding`` plus ``content_decoded``.
            curl.setopt(CurlOpt.ACCEPT_ENCODING, b"")
            if self._user_agent is not None:
                curl.setopt(CurlOpt.USERAGENT, self._user_agent.encode("ascii", "replace"))
            # Only caller-supplied headers: impersonation's defaults (Accept, sec-ch-ua,
            # Accept-Language, ...) must reach the wire untouched.
            headers = [
                f"{name}: {value}".encode("latin-1") for name, value in request_headers
            ]
            curl.setopt(CurlOpt.HTTPHEADER, headers)
            curl.setopt(CurlOpt.SSL_VERIFYPEER, 1)
            curl.setopt(CurlOpt.SSL_VERIFYHOST, 2)
            if self._policy.transport.ca_bundle:
                curl.setopt(CurlOpt.CAINFO, self._policy.transport.ca_bundle.encode())
            curl.setopt(CurlOpt.HEADERFUNCTION, on_header)
            curl.setopt(CurlOpt.WRITEFUNCTION, on_body)
            try:
                curl.perform()
            except CurlError as exc:
                response.error_code = int(getattr(exc, "code", 0) or 0)
            response.status = int(curl.getinfo(CurlInfo.RESPONSE_CODE) or 0)
            primary = curl.getinfo(CurlInfo.PRIMARY_IP)
            response.connected_address = primary.decode() if isinstance(primary, bytes) else (primary or None)
        finally:
            curl.close()
        return response

    @staticmethod
    def _error_code(response: _Response, admission: Admission) -> str:
        code = response.error_code or 0
        if response.cap_hit:
            return "budget.bytes"
        if code == 28:
            return "budget.deadline" if admission.work_allowance() <= 0.05 else "network.timeout"
        if code == 7:
            return "network.connect"
        if code == 6:
            return "network.dns"
        if code in _TLS_CODES:
            return "network.tls"
        if code == 61:
            return "network.content_decoding"
        if code in _INTERRUPTED_CODES:
            return "network.interrupted"
        return "network.error"

    # -- one attempt -------------------------------------------------------------------
    def run(
        self,
        attempt_id: str,
        start: CanonicalURL,
        admission: Admission,
        started_wall: float,
        *,
        purpose: str = "resource",
        redirect_purpose: str = "redirect",
        max_redirects: int | None = None,
        source_cap: int | None = None,
        redirect_hook: RedirectHook | None = None,
        use_credentials: bool = False,
        request_headers: tuple[tuple[str, str], ...] = (),
    ) -> AttemptRecord:
        t0 = admission.remaining()
        first_seq = admission.seq
        hops: list[RedirectHop] = []
        evidence: list[Evidence] = []
        visited = {start.url}
        current = start
        current_purpose = purpose
        outcome = Outcome.ERROR
        reasons: list[str] = []
        source: SourceRepresentation | None = None
        final_url: str | None = None
        effective_redirects = (
            self._policy.budgets.max_redirects
            if max_redirects is None
            else min(self._policy.budgets.max_redirects, max_redirects)
        )
        effective_source_cap = (
            self._policy.budgets.max_source_bytes
            if source_cap is None
            else min(self._policy.budgets.max_source_bytes, source_cap)
        )

        def finish() -> AttemptRecord:
            final_outcome = (
                Outcome.RATE_LIMITED
                if outcome is Outcome.ERROR and reasons and reasons[-1] == "host.cooldown"
                else outcome
            )
            return AttemptRecord(
                id=attempt_id,
                mode=Mode.HTTP,
                backend=BACKEND_NAME,
                backend_version=backend_version(),
                started_at=started_wall,
                duration=max(0.0, t0 - admission.remaining()),
                requested_url=start.url,
                final_url=final_url,
                outcome=final_outcome,
                reasons=tuple(reasons),
                redirects=tuple(hops),
                requests=admission.events_since(first_seq),
                evidence=tuple(evidence),
                source=source,
            )

        while True:
            try:
                destination = self._guard.check(
                    current, admission.work_allowance(), cancel=admission.cancel
                )
            except (DNSTimeout, DNSCancelled):
                admission.record_denied(current_purpose, current.url, "budget.deadline")
                reasons.append("budget.deadline")
                return finish()
            except SafetyRejection as rejection:
                admission.record_denied(current_purpose, current.url, rejection.code)
                reasons.append(rejection.code)
                evidence.append(
                    Evidence(rejection.code, EvidenceCategory.OBSERVATION, True, attempt_id,
                             facts=(("target", safe_url(current.url)), ("detail", rejection.detail)))
                )
                return finish()
            except DNSFailure:
                admission.record_denied(current_purpose, current.url, "network.dns")
                reasons.append("network.dns")
                return finish()
            byte_cap = (
                effective_source_cap
                if purpose == "robots"
                else min(effective_source_cap, admission.byte_allowance())
            )
            if byte_cap <= 0:
                admission.record_denied(current_purpose, current.url, "budget.bytes")
                reasons.append("budget.bytes")
                return finish()

            response: _Response | None = None
            ticket = None
            error: str | None = None
            try:
                if self._safety is not None:
                    lease_context = self._safety.host_slot(
                        current.host, admission.remaining(), self._policy.scheduling
                    )
                    with lease_context as lease:
                        try:
                            ticket = admission.reserve_request(current_purpose, current.url)
                        except Denied as denied:
                            reasons.append(denied.code)
                            return finish()
                        response = self._perform(
                            current,
                            destination.address,
                            admission,
                            byte_cap,
                            (
                                self._credentials.headers_for(current)
                                if use_credentials and self._credentials is not None
                                else ()
                            )
                            # Conditional headers revalidate one exact stored representation,
                            # so they never follow a redirect to a different target.
                            + (request_headers if not hops else ()),
                        )
                        error = (
                            self._error_code(response, admission)
                            if response.error_code is not None or response.cap_hit
                            else None
                        )
                        observed_at = response.received_at if response.received_at is not None else time.monotonic()
                        observed_wall = response.received_wall if response.received_wall is not None else time.time()
                        if (
                            (response.error_code is not None or response.cap_hit)
                            and response.status not in (429, 503)
                        ) or response.status == 0:
                            lease.observe_failure(error or "network.error", observed_at)
                        else:
                            lease.observe_response(
                                response.status, response.headers, observed_at, observed_wall
                            )
                else:
                    ticket = admission.reserve_request(current_purpose, current.url)
                    response = self._perform(
                        current,
                        destination.address,
                        admission,
                        byte_cap,
                        (
                            self._credentials.headers_for(current)
                            if use_credentials and self._credentials is not None
                            else ()
                        )
                        + (request_headers if not hops else ()),
                    )
                    error = (
                        self._error_code(response, admission)
                        if response.error_code is not None or response.cap_hit
                        else None
                    )
            except HostDenied as denied:
                admission.record_denied(current_purpose, current.url, denied.code)
                reasons.append(denied.code)
                evidence.append(Evidence(denied.code, EvidenceCategory.OBSERVATION, True, attempt_id))
                return finish()
            except Denied as denied:
                reasons.append(denied.code)
                return finish()
            assert response is not None and ticket is not None
            elapsed = max(0.0, t0 - admission.remaining())
            # A response (or an observed connection) must come from the validated address.
            # No observable peer is not evidence of safety: fail closed rather than accept.
            if (response.status or response.connected_address) and not _same_address(
                response.connected_address, destination.address
            ):
                code = "safety.connection_mismatch" if response.connected_address else "safety.connection_unverified"
                admission.complete(ticket, status_code=None, pinned_address=destination.address,
                                   connected_address=response.connected_address, elapsed=elapsed,
                                   reason="safety.destination_rejected")
                reasons.append("safety.destination_rejected")
                evidence.append(Evidence(code, EvidenceCategory.OBSERVATION, True, attempt_id))
                return finish()
            error = self._error_code(response, admission) if response.error_code is not None or response.cap_hit else None
            admission.complete(ticket, status_code=response.status or None, pinned_address=destination.address,
                               connected_address=response.connected_address, elapsed=elapsed, reason=error)
            raw_headers = Headers(response.headers)

            if response.status == 0:
                reasons.append(error or "network.error")
                return finish()

            final_url = current.url
            location = raw_headers.get("location")
            if response.status in REDIRECT_STATUSES and location and error is None:
                try:
                    target = resolve_redirect(current, location)
                except SafetyRejection as rejection:
                    admission.record_denied("redirect", location, rejection.code)
                    reasons.append(rejection.code)
                    return finish()
                hops.append(RedirectHop(current.url, target.url, response.status))
                if target.url in visited:
                    reasons.append("http.redirect_loop")
                    return finish()
                if len(hops) > effective_redirects:
                    reasons.append("budget.redirects")
                    return finish()
                try:
                    admission.reserve_redirect()
                except Denied as denied:
                    reasons.append(denied.code)
                    return finish()
                if redirect_hook is not None:
                    code, hook_outcome = redirect_hook(target)
                    if code is not None:
                        reasons.append(code)
                        outcome = hook_outcome or Outcome.ERROR
                        return finish()
                visited.add(target.url)
                current = target
                current_purpose = redirect_purpose
                continue

            source, outcome, attempt_reasons, source_evidence = self._build_source(
                attempt_id, current, response, raw_headers, error, redirected=bool(hops)
            )
            if purpose != "robots":
                admission.retain_bytes(len(source.body))
                if source.interruption == "budget.bytes":
                    admission.note_exhausted("budget.bytes")
            reasons.extend(attempt_reasons)
            evidence.extend(source_evidence)
            return finish()

    def _build_source(
        self, attempt_id: str, url: CanonicalURL, response: _Response, raw: Headers, error: str | None,
        *, redirected: bool = False,
    ) -> tuple[SourceRepresentation, Outcome, list[str], list[Evidence]]:
        body = bytes(response.body)
        declared = raw.get("content-type")
        media = parse_media_type(declared)
        content_encoding = tuple(
            token.strip().lower() for value in raw.get_all("content-encoding") for token in value.split(",") if token.strip()
        )
        decoded = bool(content_encoding) and all(t in ("gzip", "x-gzip", "deflate", "br", "zstd", "identity") for t in content_encoding)
        kind, inferred, evidence = classify(declared, body, attempt_id)
        text = None
        if kind is ResourceKind.HTML:
            text, encoding = decode_html(body, media.charset, content_encoding, decoded)
        else:
            encoding = EncodingRecord(content_encoding=content_encoding, content_decoded=decoded,
                                      transport_charset=media.charset)
        length_header = raw.get("content-length")
        declared_length, malformed_length = parse_content_length(length_header)
        if malformed_length and error is None:
            error = "network.interrupted"
        complete = error is None
        status_outcome, status_reason = http_status_outcome(response.status)
        reasons = [status_reason] if status_reason else []
        outcome = status_outcome
        if detect_challenge(response.status, raw, text):
            outcome = Outcome.BLOCKED
            reasons.append("http.challenge")
            evidence.append(
                Evidence("evidence.challenge", EvidenceCategory.OBSERVATION, True, attempt_id)
            )
        elif response.status == 202:
            evidence.append(
                Evidence("http.accepted_incomplete", EvidenceCategory.OBSERVATION, True, attempt_id)
            )
        elif 200 <= response.status < 300 and kind is ResourceKind.HTML:
            barrier = detect_login_barrier(
                text, url=url.url, redirected=redirected
            )
            if barrier.detected:
                outcome = Outcome.AUTH_REQUIRED
                reasons.append("http.login_required")
                evidence.append(
                    Evidence(
                        "evidence.login_barrier",
                        EvidenceCategory.OBSERVATION,
                        True,
                        attempt_id,
                        facts=barrier.facts(),
                    )
                )
        if not complete:
            reasons.append(error or "network.interrupted")
            if outcome is Outcome.SUCCESS:
                outcome = Outcome.PARTIAL if body else Outcome.ERROR
        retry_after = raw.get("retry-after")
        if retry_after is not None:
            evidence.append(Evidence("http.retry_after", EvidenceCategory.OBSERVATION, retry_after, attempt_id))
        evidence.append(Evidence("evidence.content_present", EvidenceCategory.OBSERVATION, bool(body), attempt_id))
        if not any(item.code == "evidence.challenge" for item in evidence):
            # The check ran (above) and found nothing; that is "no evidence", not proof.
            evidence.append(Evidence("evidence.challenge", EvidenceCategory.OBSERVATION, False, attempt_id))
        evidence.append(Evidence("evidence.js_shell", EvidenceCategory.UNKNOWN, None, attempt_id,
                                 facts=(("check", "not_performed_in_p0a"),)))
        source = SourceRepresentation(
            body=body,
            attempt_id=attempt_id,
            url=url.url,
            status_code=response.status,
            headers=safe_headers(raw),
            kind=kind,
            declared_media_type=media.essence,
            inferred_media_type=inferred,
            encoding=encoding,
            complete=complete,
            interruption=error,
            declared_content_length=declared_length,
            decoded_text=text,
        )
        return source, outcome, reasons, evidence
