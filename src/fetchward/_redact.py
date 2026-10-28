"""Redaction for diagnostics, reprs and logs.

Query strings, fragments, userinfo and paths are never emitted. A path is replaced by a
per-process keyed identifier so one run can correlate events without a globally
correlatable hash of caller data.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

_RUN_KEY = secrets.token_bytes(32)


def resource_id(url: str) -> str:
    return hmac.new(_RUN_KEY, url.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:10]


def safe_url(url: str) -> str:
    """Origin plus an opaque per-run resource id; never path, query, fragment or userinfo."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return f"[unparseable:r{resource_id(url)}]"
    if ":" in host:
        host = f"[{host}]"
    origin = f"{parts.scheme}://{host}" + (f":{port}" if port else "") if parts.scheme else "[relative]"
    return f"{origin}/[r:{resource_id(url)}]"
