"""Pure-logic units: policy validation, admission, representation, selection, redaction."""

from __future__ import annotations

import math

import pytest

from fetchward import (
    AcquisitionPolicy,
    AttemptRecord,
    Budgets,
    ConfigurationError,
    Fetcher,
    Headers,
    Mode,
    Outcome,
    Readiness,
    RenderedRepresentation,
    ReadinessResult,
    ResourceKind,
    TrustedOrigin,
)
from fetchward._admission import Admission, Denied
from fetchward._redact import safe_url
from fetchward._representation import classify, decode_html, safe_headers
from fetchward._selection import Requirements, http_status_outcome, select


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def wall(self) -> float:
        return self.now


# -- policy (C08 configuration slice) -----------------------------------------------------
def _contained(policy: AcquisitionPolicy | None = None) -> Fetcher:
    """A fetcher whose resolver refuses every name: a regression cannot reach real DNS or hosts."""
    from harness import StaticResolver

    return Fetcher(policy, _resolver=StaticResolver())


@pytest.mark.parametrize("timeout", [0, -1, math.inf, math.nan])
def test_bad_timeouts_raise_before_io(timeout: float) -> None:
    with pytest.raises(ConfigurationError):
        _contained().fetch("http://example.com/", timeout=timeout)


def test_bad_mode_and_contradictions_raise() -> None:
    with pytest.raises(ConfigurationError):
        _contained().fetch("http://example.com/", mode="stealth")
    policy = AcquisitionPolicy(readiness=Readiness(selector="#app"))
    with pytest.raises(ConfigurationError):
        _contained(policy).fetch("http://example.com/", mode="http")
    with pytest.raises(ConfigurationError):
        Budgets(max_requests=0)
    with pytest.raises(ConfigurationError):
        Budgets(stop_reserve=math.inf)
    with pytest.raises(ConfigurationError):
        TrustedOrigin("http", "x.test", 80, ("not-an-ip",))
    with pytest.raises(ConfigurationError):
        Readiness(selector="  ")


def test_non_string_url_is_api_misuse() -> None:
    with pytest.raises(TypeError):
        _contained().fetch(b"http://example.com/")  # type: ignore[arg-type]


# -- admission --------------------------------------------------------------------------
def test_request_cap_is_atomic_and_denials_recorded() -> None:
    clock = FakeClock()
    admission = Admission(Budgets(max_requests=2), 20, clock)
    admission.reserve_request("resource", "http://a.test/x?secret=1")
    admission.reserve_request("redirect", "http://a.test/y")
    with pytest.raises(Denied) as info:
        admission.reserve_request("redirect", "http://a.test/z")
    assert info.value.code == "budget.requests"
    usage = admission.usage()
    assert usage.requests == 2 and usage.exhausted == ("budget.requests",)
    denied = [e for e in admission.events_since(0) if not e.admitted]
    assert len(denied) == 1 and "secret" not in denied[0].target


def test_deadline_is_total_and_monotonic() -> None:
    clock = FakeClock()
    admission = Admission(Budgets(), 2.0, clock)
    clock.now += 1.5
    assert admission.remaining() == pytest.approx(0.5)
    clock.now += 1.0
    with pytest.raises(Denied) as info:
        admission.reserve_request("resource", "http://a.test/")
    assert info.value.code == "budget.deadline"


def test_redirect_and_attempt_caps() -> None:
    admission = Admission(Budgets(max_redirects=1, max_attempts=1), 20, FakeClock())
    admission.reserve_redirect()
    with pytest.raises(Denied):
        admission.reserve_redirect()
    admission.reserve_attempt()
    with pytest.raises(Denied):
        admission.reserve_attempt()


# -- representation (C02/C03 slice) ---------------------------------------------------------
def test_classification_prefers_declared_type_and_records_disagreement() -> None:
    kind, inferred, evidence = classify("application/octet-stream", b"<!DOCTYPE html><html></html>", "a1")
    assert kind is ResourceKind.FILE and inferred == "text/html"
    assert evidence and evidence[0].code == "evidence.media_type_disagreement"
    assert classify(None, b"%PDF-1.7 ...", "a1")[0] is ResourceKind.FILE
    assert classify(None, b"<html><body>x", "a1")[0] is ResourceKind.HTML
    assert classify(None, b'{"a": 1}', "a1")[0] is ResourceKind.UNKNOWN  # never guess JSON
    assert classify("application/problem+json", b"{}", "a1")[0] is ResourceKind.JSON
    assert classify("text/html; charset=utf-8", b"", "a1")[0] is ResourceKind.HTML


def test_html_decoding_procedure() -> None:
    text, record = decode_html("café".encode("utf-8"), None, (), False)
    assert text == "café" and record.source == "fallback" and not record.replacement_used
    body = b'<meta charset="windows-1251">' + "привет".encode("cp1251")
    text, record = decode_html(body, None, (), False)
    assert "привет" in text and record.source == "meta" and record.effective == "cp1251"
    text, record = decode_html(body, "utf-8", (), False)
    assert record.source == "transport" and record.replacement_used and "transport_vs_meta" in record.conflicts
    text, record = decode_html(b"\xef\xbb\xbfhi", "iso-8859-1", (), False)
    assert text == "hi" and record.source == "bom" and "bom_vs_transport" in record.conflicts
    _, record = decode_html(b"\xe9", "iso-8859-1", (), False)
    assert record.effective == "cp1252"  # WHATWG label mapping


def test_safe_headers_allowlist() -> None:
    raw = Headers([("Content-Type", "text/html"), ("Set-Cookie", "s=1"), ("X-Secret", "t"), ("ETag", "x")])
    safe = safe_headers(raw)
    assert set(k.lower() for k in safe) == {"content-type", "etag"}
    assert Headers([("A", "1"), ("a", "2")]).get_all("A") == ("1", "2")


# -- outcome and selection (C06/C12 slice) -------------------------------------------------
def test_status_mapping() -> None:
    assert http_status_outcome(200) == (Outcome.SUCCESS, None)
    assert http_status_outcome(202) == (Outcome.PARTIAL, "http.accepted_incomplete")
    assert http_status_outcome(401)[0] is Outcome.AUTH_REQUIRED
    assert http_status_outcome(403)[0] is Outcome.BLOCKED
    assert http_status_outcome(429)[0] is Outcome.RATE_LIMITED
    assert http_status_outcome(404) == (Outcome.ERROR, "http.error_status")
    assert http_status_outcome(503) == (Outcome.ERROR, "http.error_status")


def _attempt(id: str, outcome: Outcome, *, rendered: bool = False, source: bool = True) -> AttemptRecord:
    from fetchward import EncodingRecord, SourceRepresentation

    src = (
        SourceRepresentation(b"x", id, "http://a/", 200, Headers(), ResourceKind.HTML, "text/html", None, EncodingRecord())
        if source
        else None
    )
    dom = RenderedRepresentation("<html/>", id, "http://a/", 0.0, ReadinessResult("domcontentloaded")) if rendered else None
    return AttemptRecord(id, Mode.HTTP if not rendered else Mode.BROWSER, "t", "0", 0.0, 0.0, "http://a/", "http://a/",
                         outcome, (), source=src, rendered=dom)


def test_worse_browser_result_does_not_erase_http_success() -> None:
    s = select((_attempt("a1", Outcome.SUCCESS), _attempt("a2", Outcome.ERROR, rendered=False, source=False)), Requirements())
    assert (s.outcome, s.attempt_id, s.reason) == (Outcome.SUCCESS, "a1", "selection.retained_prior")


def test_required_rendering_makes_http_only_success_partial() -> None:
    s = select((_attempt("a1", Outcome.SUCCESS),), Requirements(require_rendering=True))
    assert (s.outcome, s.reason) == (Outcome.PARTIAL, "selection.best_partial")
    s = select((_attempt("a1", Outcome.SUCCESS), _attempt("a2", Outcome.SUCCESS, rendered=True)), Requirements(require_rendering=True))
    assert (s.outcome, s.attempt_id) == (Outcome.SUCCESS, "a2")


def test_restriction_precedence_over_partial() -> None:
    s = select((_attempt("a1", Outcome.PARTIAL), _attempt("a2", Outcome.BLOCKED)), Requirements())
    assert (s.outcome, s.attempt_id) == (Outcome.BLOCKED, "a2")


def test_prefer_intended_render_among_satisfying() -> None:
    s = select((_attempt("a1", Outcome.SUCCESS), _attempt("a2", Outcome.SUCCESS, rendered=True)), Requirements(prefer_rendered=True))
    assert s.attempt_id == "a2"


def test_no_resource_selects_terminal_error() -> None:
    s = select((_attempt("a1", Outcome.ERROR, source=False),), Requirements())
    assert (s.outcome, s.attempt_id, s.reason) == (Outcome.ERROR, "a1", "selection.no_resource")


# -- redaction (C13 slice) -------------------------------------------------------------------
def test_safe_url_drops_path_query_userinfo() -> None:
    summary = safe_url("https://u:canary-pass@host.test:8443/private/canary-path?token=canary-q#frag")
    assert summary.startswith("https://host.test:8443/[r:")
    for canary in ("canary", "token", "frag", "private", "u:"):
        assert canary not in summary
