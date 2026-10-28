"""Conservative challenge-page detection shared by the HTTP and browser paths.

A 2xx challenge interstitial is not success. Detection is intentionally narrow: response
headers that explicitly mark a challenge, or a small set of well-known interstitial markers.
It is a safety signal, never an attempt to solve or bypass a challenge.
"""

from __future__ import annotations

import re

from ._types import Headers

# A title or a combined structural signal is required. A generic phrase in prose is not
# challenge evidence; the same words can occur in an ordinary article.
_EXACT_TITLES = frozenset(
    {
        "just a moment",
        "attention required cloudflare",
        "checking your browser",
        "verify you are human",
    }
)
_BODY_MARKERS = (
    "just a moment",
    "attention required",
    "verify you are human",
    "checking your browser",
    "checking if the site connection is secure",
    "enable javascript and cookies to continue",
)
_STRUCTURE = re.compile(
    r"(?:cdn-cgi/challenge-platform|__cf_chl|cf_chl_opt|challenge-platform|"
    r"challenge-form|challenge-running|cf-chl|cf-turnstile)",
    re.IGNORECASE,
)
# AWS WAF's JavaScript challenge interstitial: its challenge script plus the integration call.
# Both are required; neither appears in an ordinary page that merely uses AWS WAF.
_AWS_WAF_SCRIPT = re.compile(r"\.token\.awswaf\.com/[^\"']*/challenge\.js", re.IGNORECASE)
_AWS_WAF_CALL = re.compile(r"awswafintegration\.", re.IGNORECASE)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAGS = re.compile(r"<[^>]+>", re.DOTALL)


def detect_challenge(status: int, headers: Headers, text: str | None) -> bool:
    if not (200 <= status < 300):
        return False
    lowered = {
        name.lower(): value.lower()
        for name in headers
        for value in headers.get_all(name)
    }
    if "cf-mitigated" in lowered and "challenge" in lowered["cf-mitigated"]:
        return True
    if "x-challenge" in lowered:
        return True
    if not text:
        return False
    raw = text[:200_000]
    folded = raw.casefold()
    if _AWS_WAF_SCRIPT.search(raw) and _AWS_WAF_CALL.search(folded):
        return True
    structure = _STRUCTURE.search(folded) is not None
    body_signal = any(marker in folded for marker in _BODY_MARKERS)
    title_match = _TITLE.search(raw)
    if title_match is not None:
        title = _TAGS.sub(" ", title_match.group(1)).casefold()
        normalized = re.sub(r"[^a-z0-9]+", " ", title).strip()
        if normalized in _EXACT_TITLES and (body_signal or structure):
            return True
    return structure and body_signal


__all__ = ["detect_challenge"]
