"""Engine-neutral result, representation and evidence types."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ._redact import safe_url


class Mode(StrEnum):
    HTTP = "http"
    BROWSER = "browser"
    AUTO = "auto"


class Outcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    AUTH_REQUIRED = "auth_required"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class ResourceKind(StrEnum):
    HTML = "html"
    JSON = "json"
    FILE = "file"
    UNKNOWN = "unknown"


class EvidenceCategory(StrEnum):
    OBSERVATION = "observation"
    INFERENCE = "inference"
    UNKNOWN = "unknown"


RESTRICTION_OUTCOMES = frozenset({Outcome.BLOCKED, Outcome.AUTH_REQUIRED, Outcome.RATE_LIMITED})


class Headers(Mapping[str, str]):
    """Immutable, case-insensitive header multimap preserving order and duplicates.

    Mapping access returns the first value; use :meth:`get_all` for every value.
    """

    __slots__ = ("_items",)

    def __init__(self, items: Iterable[tuple[str, str]] = ()) -> None:
        self._items: tuple[tuple[str, str], ...] = tuple((str(k), str(v)) for k, v in items)

    def __getitem__(self, name: str) -> str:
        lowered = name.lower()
        for key, value in self._items:
            if key.lower() == lowered:
                return value
        raise KeyError(name)

    def __iter__(self) -> Iterator[str]:
        seen: set[str] = set()
        for key, _ in self._items:
            if key.lower() not in seen:
                seen.add(key.lower())
                yield key

    def __len__(self) -> int:
        return len({key.lower() for key, _ in self._items})

    def get_all(self, name: str) -> tuple[str, ...]:
        lowered = name.lower()
        return tuple(value for key, value in self._items if key.lower() == lowered)

    def raw_items(self) -> tuple[tuple[str, str], ...]:
        return self._items

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Headers):
            return self._items == other._items
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._items)

    def __repr__(self) -> str:
        return f"Headers({list(self._items)!r})"


@dataclass(frozen=True)
class Evidence:
    """One observation, inference or explicit unknown, keyed by a stable reason code."""

    code: str
    category: EvidenceCategory
    value: Any = None
    attempt_id: str | None = None
    version: str = "p0"
    facts: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class EncodingRecord:
    """How the source body was decoded: content decoding first, then (HTML only) characters."""

    content_encoding: tuple[str, ...] = ()
    content_decoded: bool = False
    transport_charset: str | None = None
    bom: str | None = None
    declared_meta_charset: str | None = None
    effective: str | None = None
    source: str = "not_applicable"  # bom | transport | meta | fallback | not_applicable
    replacement_used: bool = False
    conflicts: tuple[str, ...] = ()


@dataclass(frozen=True)
class SourceRepresentation:
    """Retained HTTP response body of one attempt; never a DOM serialization."""

    body: bytes = field(repr=False)
    attempt_id: str
    url: str = field(repr=False)
    status_code: int
    headers: Headers = field(repr=False)
    kind: ResourceKind
    declared_media_type: str | None
    inferred_media_type: str | None
    encoding: EncodingRecord
    complete: bool = True
    interruption: str | None = None
    declared_content_length: int | None = None
    decoded_text: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ConditionResult:
    condition: str
    status: str  # satisfied | timeout | unsupported | not_evaluated
    elapsed: float | None = None


@dataclass(frozen=True)
class ReadinessResult:
    lifecycle: str | None = None
    conditions: tuple[ConditionResult, ...] = ()
    elapsed: float | None = None
    limits: tuple[str, ...] = ()


@dataclass(frozen=True)
class RenderedRepresentation:
    """Browser DOM snapshot of a top-level document after a declared readiness point."""

    dom: str = field(repr=False)
    attempt_id: str
    url: str = field(repr=False)
    captured_at: float
    readiness: ReadinessResult
    limits: tuple[str, ...] = ("no_frame_flattening", "no_shadow_serialization", "no_interaction")


@dataclass(frozen=True)
class RedirectHop:
    """One followed redirect. URLs are caller data, not safe diagnostics."""

    from_url: str = field(repr=False)
    to_url: str = field(repr=False)
    status_code: int


@dataclass(frozen=True)
class RequestEvent:
    """One admission decision. Denied events never left the process."""

    seq: int
    purpose: str  # resource | redirect | robots
    target: str  # redacted summary
    admitted: bool
    reason: str | None = None
    status_code: int | None = None
    pinned_address: str | None = None
    connected_address: str | None = None
    elapsed: float | None = None


@dataclass(frozen=True)
class AttemptRecord:
    id: str
    mode: Mode
    backend: str
    backend_version: str
    started_at: float
    duration: float
    requested_url: str = field(repr=False)
    final_url: str | None = field(repr=False)
    outcome: Outcome
    reasons: tuple[str, ...]
    redirects: tuple[RedirectHop, ...] = field(default=(), repr=False)
    requests: tuple[RequestEvent, ...] = field(default=(), repr=False)
    evidence: tuple[Evidence, ...] = field(default=(), repr=False)
    readiness: ReadinessResult | None = None
    source: SourceRepresentation | None = None
    rendered: RenderedRepresentation | None = None

    @property
    def has_resource(self) -> bool:
        return self.source is not None or self.rendered is not None

    @property
    def requests_dispatched(self) -> int:
        return sum(1 for event in self.requests if event.admitted)


@dataclass(frozen=True)
class BudgetUsage:
    deadline: float
    elapsed: float
    requests: int
    max_requests: int
    redirects: int
    max_redirects: int
    attempts: int
    max_attempts: int
    retries_used: int
    retained_bytes: int = 0
    max_total_bytes: int = 0
    exhausted: tuple[str, ...] = ()
    browser_requests: int = 0


@dataclass(frozen=True)
class Diagnostics:
    """Safe acquisition summary. Contains no bodies, credentials or raw URLs."""

    policy_version: str
    access: str
    budget: BudgetUsage
    selection_reason: str
    stop_reason: str | None
    evidence: tuple[Evidence, ...] = ()

    def summary(self) -> dict[str, Any]:
        """Scope §4 style summary: ``None`` means unknown/unperformed, never ``False``."""

        def lookup(code: str) -> Any:
            for item in self.evidence:
                if item.code == code and item.category is not EvidenceCategory.UNKNOWN:
                    return item.value
            return None

        return {
            "challenge_detected": lookup("evidence.challenge"),
            "js_rendering_suspected": lookup("evidence.js_shell"),
            "content_present": lookup("evidence.content_present"),
            "completeness": "unknown",
            "selection_reason": self.selection_reason,
            "stop_reason": self.stop_reason,
        }


@dataclass(frozen=True)
class FetchResult:
    requested_url: str = field(repr=False)
    outcome: Outcome
    attempts: tuple[AttemptRecord, ...]
    diagnostics: Diagnostics = field(repr=False)
    selected_attempt_id: str | None = None

    @property
    def ok(self) -> bool:
        return self.outcome is Outcome.SUCCESS

    @property
    def selected(self) -> AttemptRecord | None:
        for attempt in self.attempts:
            if attempt.id == self.selected_attempt_id:
                return attempt
        return None

    @property
    def _source(self) -> SourceRepresentation | None:
        attempt = self.selected
        return attempt.source if attempt else None

    @property
    def response_body(self) -> bytes | None:
        source = self._source
        return source.body if source else None

    @property
    def rendered_html(self) -> str | None:
        attempt = self.selected
        return attempt.rendered.dom if attempt and attempt.rendered else None

    @property
    def html(self) -> str | None:
        rendered = self.rendered_html
        if rendered is not None:
            return rendered
        source = self._source
        if source is not None and source.kind is ResourceKind.HTML:
            return source.decoded_text
        return None

    @property
    def final_url(self) -> str | None:
        attempt = self.selected
        return attempt.final_url if attempt else None

    @property
    def content_type(self) -> str | None:
        source = self._source
        return source.declared_media_type if source else None

    @property
    def encoding(self) -> EncodingRecord | None:
        source = self._source
        return source.encoding if source else None

    @property
    def response_headers(self) -> Headers | None:
        source = self._source
        return source.headers if source else None

    @property
    def status_code(self) -> int | None:
        source = self._source
        return source.status_code if source else None

    @property
    def kind(self) -> ResourceKind:
        attempt = self.selected
        if attempt and attempt.rendered is not None:
            return ResourceKind.HTML
        source = self._source
        return source.kind if source else ResourceKind.UNKNOWN

    def __repr__(self) -> str:
        final = safe_url(self.final_url) if self.final_url else None
        return (
            f"FetchResult(outcome={self.outcome.value!r}, kind={self.kind.value!r}, "
            f"status_code={self.status_code!r}, final_url={final!r}, attempts={len(self.attempts)})"
        )
