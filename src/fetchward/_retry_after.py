"""Retry-After interpretation shared by HTTP controls and host safety state.

The returned delay is relative to the response receipt instant supplied by the caller.
Seconds and HTTP-date forms are supported. A malformed value is conservatively treated as
60 seconds; an absent header is distinguished so callers can decide whether it applies.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from ._types import Headers

DEFAULT_RETRY_AFTER = 60.0


def _items(headers: Headers | Iterable[tuple[str, str]]) -> Iterable[tuple[str, str]]:
    if isinstance(headers, Headers):
        return headers.raw_items()
    return headers


def parse_retry_after(
    headers: Headers | Iterable[tuple[str, str]], *, now_wall: float | None = None
) -> tuple[float | None, bool]:
    """Return ``(delay_seconds, present)`` for the first Retry-After header.

    ``present`` is true for a malformed header too; its delay is the 60-second fallback.
    A past HTTP-date yields ``0.0``. An absent header yields ``(None, False)``.
    """
    text = None
    for name, value in _items(headers):
        if str(name).lower() == "retry-after":
            text = str(value).strip()
            break
    if text is None:
        return None, False
    if text.isdigit():
        return float(text), True
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        return DEFAULT_RETRY_AFTER, True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc).timestamp() if now_wall is None else now_wall
    return max(0.0, parsed.timestamp() - now), True
