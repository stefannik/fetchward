"""Bounded in-memory HTTP response cache for anonymous HTTP acquisitions (v0.2 U2).

The cache answers a request only when HTTP caching rules say the stored copy is still fresh,
or when a conditional request proves it unchanged. It stores nothing rendered, nothing
credentialed and nothing the server marked private, and a failed revalidation never turns a
stale copy into a success. There is no disk persistence and no heuristic freshness.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from ._types import (
    AttemptRecord,
    Evidence,
    EvidenceCategory,
    Headers,
    Mode,
    Outcome,
    RequestEvent,
    SourceRepresentation,
)

MiB = 1024 * 1024
CACHE_BACKEND = "cache"
CACHE_VERSION = "1"

# Request headers the adapter does not set explicitly come from curl_cffi impersonation's
# default set. That set is constant within one process, so one stable marker identifies it
# when a stored response's ``Vary`` names are matched against the request we sent.
_DEFAULT_REQUEST_MARKER = "impersonation-default"

# Response headers a 304 refresh carries forward onto the stored copy (RFC 9111 §3.2).
_REFRESHED_HEADERS = frozenset(
    {"date", "age", "cache-control", "expires", "etag", "last-modified", "vary"}
)


@dataclass(frozen=True)
class CacheEntry:
    """One stored representation together with everything needed to judge its freshness."""

    url: str
    fingerprint: str
    vary: tuple[tuple[str, str], ...]
    source: SourceRepresentation
    stored_at: float
    age_at_store: float
    lifetime: float

    @property
    def size(self) -> int:
        return len(self.source.body)

    @property
    def etag(self) -> str | None:
        return self.source.headers.get("etag")

    @property
    def last_modified(self) -> str | None:
        return self.source.headers.get("last-modified")

    def age(self, now_wall: float) -> float:
        """Current age: the response's own ``Age`` plus time spent in this cache."""
        return self.age_at_store + max(0.0, now_wall - self.stored_at)

    def fresh(self, now_wall: float) -> bool:
        return self.lifetime - self.age(now_wall) > 0

    def can_revalidate(self) -> bool:
        return self.etag is not None or self.last_modified is not None

    def conditional_headers(self) -> tuple[tuple[str, str], ...]:
        headers: list[tuple[str, str]] = []
        if self.etag is not None:
            headers.append(("If-None-Match", self.etag))
        if self.last_modified is not None:
            headers.append(("If-Modified-Since", self.last_modified))
        return tuple(headers)


class ResponseCache:
    """Thread-safe bounded LRU of anonymous, complete ``200`` HTTP responses.

    ``max_entries`` bounds stored representations (each ``Vary`` variant counts) and
    ``max_bytes`` bounds the stored body bytes. The least recently used URL group is evicted
    first. There is no disk persistence.
    """

    def __init__(self, *, max_entries: int = 256, max_bytes: int = 64 * MiB) -> None:
        if type(max_entries) is not int or max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError("max_bytes must be a positive integer")
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._lock = threading.Lock()
        self._groups: OrderedDict[tuple[str, str], list[CacheEntry]] = OrderedDict()
        self._entries = 0
        self._bytes = 0

    @property
    def max_entries(self) -> int:
        return self._max_entries

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    def __len__(self) -> int:
        with self._lock:
            return self._entries

    def clear(self) -> None:
        with self._lock:
            self._groups.clear()
            self._entries = 0
            self._bytes = 0

    # -- internals ---------------------------------------------------------------------
    def _lookup(
        self, url: str, fingerprint: str, sent_headers: Mapping[str, str]
    ) -> CacheEntry | None:
        key = (url, fingerprint)
        with self._lock:
            group = self._groups.get(key)
            if not group:
                return None
            self._groups.move_to_end(key)
            for entry in group:
                if all(value == _sent_value(name, sent_headers) for name, value in entry.vary):
                    return entry
            return None

    def _discard(self, entry: CacheEntry) -> None:
        with self._lock:
            self._remove_locked(entry)

    def _store(self, entry: CacheEntry) -> None:
        if entry.size > self._max_bytes:
            return
        with self._lock:
            self._insert_locked(entry)
            self._evict_locked()

    def _refresh(
        self,
        entry: CacheEntry,
        headers: Headers,
        *,
        now_wall: float,
        sent_headers: Mapping[str, str],
    ) -> CacheEntry:
        """Update a stored copy after a ``304 Not Modified`` and return what to serve."""
        refreshed = _refreshed_entry(
            entry, headers, now_wall=now_wall, sent_headers=sent_headers
        )
        with self._lock:
            self._remove_locked(entry)
            if refreshed is not None:
                self._insert_locked(refreshed)
                self._evict_locked()
        return refreshed if refreshed is not None else entry

    def _insert_locked(self, entry: CacheEntry) -> None:
        key = (entry.url, entry.fingerprint)
        group = self._groups.get(key)
        if group is None:
            group = []
            self._groups[key] = group
        for index, existing in enumerate(group):
            if existing.vary == entry.vary:
                self._bytes -= existing.size
                self._entries -= 1
                group[index] = entry
                break
        else:
            group.append(entry)
        self._entries += 1
        self._bytes += entry.size
        self._groups.move_to_end(key)

    def _remove_locked(self, entry: CacheEntry) -> None:
        key = (entry.url, entry.fingerprint)
        group = self._groups.get(key)
        if group is None:
            return
        for index, existing in enumerate(group):
            if existing is entry:
                self._bytes -= existing.size
                self._entries -= 1
                del group[index]
                break
        if not group:
            del self._groups[key]

    def _evict_locked(self) -> None:
        # Evicting a whole URL group keeps the entry cap simple; a group is at least one entry.
        while self._groups and (
            self._entries > self._max_entries or self._bytes > self._max_bytes
        ):
            _, group = self._groups.popitem(last=False)
            self._entries -= len(group)
            self._bytes -= sum(entry.size for entry in group)


# -- policy fingerprint ------------------------------------------------------------------
def policy_fingerprint(
    access_mode: str, user_agent: str | None, ca_bundle: str | None
) -> str:
    """Short stable key for the request-shaping policy parts that change a representation."""
    material = f"access={access_mode}\x00ua={user_agent or ''}\x00ca={ca_bundle or ''}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


# -- response metadata -------------------------------------------------------------------
def _cache_control(headers: Headers) -> dict[str, str | None]:
    directives: dict[str, str | None] = {}
    for value in headers.get_all("cache-control"):
        for part in value.split(","):
            name, separator, argument = part.partition("=")
            name = name.strip().lower()
            if not name:
                continue
            directives[name] = argument.strip().strip('"') if separator else None
    return directives


def _vary_names(headers: Headers) -> tuple[str, ...]:
    names: list[str] = []
    for value in headers.get_all("vary"):
        for name in value.split(","):
            lowered = name.strip().lower()
            if lowered and lowered not in names:
                names.append(lowered)
    return tuple(names)


def _http_date(value: str | None) -> float | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        return parsed.timestamp()
    except (OverflowError, OSError, ValueError):
        return None


def _age_seconds(headers: Headers) -> float:
    value = headers.get("age")
    if value is None:
        return 0.0
    text = value.strip()
    return float(text) if text.isdigit() else 0.0


def _freshness_lifetime(headers: Headers, stored_at: float) -> float:
    """Private-cache freshness in seconds; no heuristic freshness is ever inferred."""
    directives = _cache_control(headers)
    if "no-cache" in directives:
        return 0.0
    if "max-age" in directives:
        value = directives["max-age"]
        if value is None or not value.isdigit():
            return 0.0
        return float(int(value))
    expires = _http_date(headers.get("expires"))
    if expires is None:
        return 0.0
    date = _http_date(headers.get("date"))
    return max(0.0, expires - (stored_at if date is None else date))


def _storable_headers(headers: Headers) -> bool:
    directives = _cache_control(headers)
    if "no-store" in directives or "private" in directives:
        return False
    return "*" not in _vary_names(headers)


def _sent_value(name: str, sent_headers: Mapping[str, str]) -> str:
    return sent_headers.get(name, _DEFAULT_REQUEST_MARKER)


def _vary_key(
    headers: Headers, sent_headers: Mapping[str, str]
) -> tuple[tuple[str, str], ...]:
    return tuple((name, _sent_value(name, sent_headers)) for name in _vary_names(headers))


# -- building entries and attempt records ---------------------------------------------------
def store_response(
    cache: ResponseCache,
    source: SourceRepresentation,
    *,
    fingerprint: str,
    sent_headers: Mapping[str, str],
    now_wall: float,
    max_bytes: int,
) -> CacheEntry | None:
    """Store a response if HTTP caching rules allow it; return the stored entry or ``None``.

    Only a complete ``200`` whose directives permit caching is kept. An authenticated or
    partial response must be rejected by the caller, which knows about credentials.
    """
    if source.status_code != 200 or not source.complete:
        return None
    if len(source.body) > max_bytes or not _storable_headers(source.headers):
        return None
    entry = CacheEntry(
        url=source.url,
        fingerprint=fingerprint,
        vary=_vary_key(source.headers, sent_headers),
        source=source,
        stored_at=now_wall,
        age_at_store=_age_seconds(source.headers),
        lifetime=_freshness_lifetime(source.headers, now_wall),
    )
    cache._store(entry)
    return entry


def cache_attempt(
    entry: CacheEntry,
    *,
    attempt_id: str,
    requested_url: str,
    now_wall: float,
    started_at: float | None = None,
    duration: float = 0.0,
    requests: tuple[RequestEvent, ...] = (),
    revalidated_status: int | None = None,
) -> AttemptRecord:
    """Attempt record for a representation served from the cache, with its provenance."""
    age = entry.age(now_wall)
    facts = (
        ("stored_at", _wall_text(entry.stored_at)),
        ("age", f"{age:.3f}"),
    )
    if revalidated_status is None:
        evidence = Evidence(
            "cache.hit", EvidenceCategory.OBSERVATION, True, attempt_id, facts=facts
        )
    else:
        evidence = Evidence(
            "cache.revalidated",
            EvidenceCategory.OBSERVATION,
            True,
            attempt_id,
            facts=(("status", str(revalidated_status)),) + facts,
        )
    return AttemptRecord(
        id=attempt_id,
        mode=Mode.HTTP,
        backend=CACHE_BACKEND,
        backend_version=f"{CACHE_BACKEND}/{CACHE_VERSION}",
        started_at=now_wall if started_at is None else started_at,
        duration=duration,
        requested_url=requested_url,
        final_url=entry.url,
        outcome=Outcome.SUCCESS,
        reasons=(),
        requests=requests,
        evidence=(evidence,),
        source=replace(entry.source, attempt_id=attempt_id),
    )


def _wall_text(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def _refreshed_entry(
    entry: CacheEntry,
    headers: Headers,
    *,
    now_wall: float,
    sent_headers: Mapping[str, str],
) -> CacheEntry | None:
    """Apply a 304's cache metadata to a stored entry; ``None`` when it is no longer storable."""
    updated = {
        name.lower(): value
        for name, value in headers.raw_items()
        if name.lower() in _REFRESHED_HEADERS
    }
    if not updated:
        merged = entry.source.headers
    else:
        kept = [
            (name, value)
            for name, value in entry.source.headers.raw_items()
            if name.lower() not in updated
        ]
        merged = Headers(kept + list(updated.items()))
    if not _storable_headers(merged):
        return None
    return replace(
        entry,
        vary=_vary_key(merged, sent_headers),
        source=replace(entry.source, headers=merged),
        stored_at=now_wall,
        age_at_store=_age_seconds(merged),
        lifetime=_freshness_lifetime(merged, now_wall),
    )


__all__ = [
    "CacheEntry",
    "ResponseCache",
    "cache_attempt",
    "policy_fingerprint",
    "store_response",
]
