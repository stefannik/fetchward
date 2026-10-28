"""Explicit, origin-scoped, in-memory HTTP credentials and cookies.

A ``Session`` is opt-in. It stores only caller-supplied values in process memory; it never
imports a browser profile, netrc file, environment credential or server cookie automatically.
Scopes are exact ``(scheme, host, port)`` triples. A snapshot is taken for each acquisition so
clearing or closing a session never changes an already-started request's scope.

HTTP cookies are exact-origin scoped and path and secure checked. Browser Session cookies use
Chromium's host, path and Secure scope, which does not isolate ports; browser Session headers
are not applied. HTTP and browser cookie state is not synchronized.
"""

from __future__ import annotations

import base64
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from ._fork import assert_generation, generation
from ._safety import CanonicalURL, SafetyRejection, canonicalize
from .errors import ConfigurationError, FetchwardError

_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_FORBIDDEN_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
        "expect",
        "accept-encoding",
    }
)


class SessionClosedError(FetchwardError, RuntimeError):
    """A closed session or a fetch using it cannot start new work."""


@dataclass(frozen=True, repr=False)
class _Cookie:
    name: str
    value: str
    path: str = "/"
    secure: bool = False

    def __repr__(self) -> str:
        return f"_Cookie(name={self.name!r}, path={self.path!r}, secure={self.secure!r})"


@dataclass(frozen=True, repr=False)
class _Scope:
    headers: tuple[tuple[str, str], ...] = ()
    cookies: tuple[_Cookie, ...] = ()

    def __repr__(self) -> str:
        return f"_Scope(headers={len(self.headers)}, cookies={len(self.cookies)})"


class SessionSnapshot:
    """Immutable acquisition-local view of a session's explicit scopes."""

    __slots__ = ("_entries",)

    def __init__(self, entries: tuple[tuple[tuple[str, str, int], _Scope], ...]) -> None:
        self._entries = dict(entries)

    def __repr__(self) -> str:
        return f"SessionSnapshot(scopes={len(self._entries)})"

    @staticmethod
    def _path_matches(target: str, cookie_path: str) -> bool:
        if target == cookie_path:
            return True
        if not target.startswith(cookie_path):
            return False
        if cookie_path.endswith("/"):
            return True
        return target[len(cookie_path) :].startswith("/")

    def has_browser_headers(self, url: CanonicalURL) -> bool:
        scope = self._entries.get(url.origin)
        return bool(scope and scope.headers)

    def has_cookies(self) -> bool:
        return any(scope.cookies for scope in self._entries.values())

    def browser_cookies(self) -> list[dict[str, object]]:
        return [
            {"name": cookie.name, "value": cookie.value, "domain": host,
             "path": cookie.path, "secure": cookie.secure}
            for (_, host, _), scope in self._entries.items() for cookie in scope.cookies
        ]

    def headers_for(self, url: CanonicalURL) -> tuple[tuple[str, str], ...]:
        scope = self._entries.get((url.scheme, url.host, url.port))
        if scope is None:
            return ()
        result: list[tuple[str, str]] = []
        cookie_values: list[str] = []
        for name, value in scope.headers:
            if name.lower() == "cookie":
                cookie_values.append(value)
            else:
                result.append((name, value))
        target_path = url.target.split("?", 1)[0]
        selected = [
            cookie
            for cookie in scope.cookies
            if (not cookie.secure or url.scheme == "https")
            and self._path_matches(target_path, cookie.path)
        ]
        selected.sort(key=lambda cookie: (-len(cookie.path),))
        if selected:
            cookie_values.append("; ".join(f"{cookie.name}={cookie.value}" for cookie in selected))
        if cookie_values:
            result.append(("Cookie", "; ".join(cookie_values)))
        return tuple(result)


class Session:
    """Explicit in-memory scoped credentials and cookies for one or more fetchers.

    Anonymous acquisition remains the default. A session does not become global state and is
    not shared through convenience calls. ``close()`` clears secrets and makes the session
    unusable for new acquisitions; ``clear()`` removes secrets while leaving it reusable.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scopes: dict[tuple[str, str, int], _Scope] = {}
        self._closed = False
        self._fork_generation = generation()

    def _assert_current_process(self) -> None:
        assert_generation(self._fork_generation, "Session")

    def __repr__(self) -> str:
        self._assert_current_process()
        with self._lock:
            return f"Session(scopes={len(self._scopes)}, closed={self._closed})"

    @property
    def closed(self) -> bool:
        self._assert_current_process()
        with self._lock:
            return self._closed

    def __enter__(self) -> "Session":
        self._assert_current_process()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @staticmethod
    def _origin(origin: str) -> tuple[str, str, int]:
        if not isinstance(origin, str) or not origin:
            raise ConfigurationError("session origin must be a non-empty string")
        if any(char in origin for char in "?#"):
            raise ConfigurationError("session origin must not contain query or fragment")
        try:
            parsed = urlsplit(origin)
        except ValueError as exc:
            raise ConfigurationError("session origin is not a valid URL") from exc
        if parsed.scheme.lower() not in ("http", "https") or parsed.path not in ("", "/"):
            raise ConfigurationError("session origin must be an http(s) scheme/host/port only")
        try:
            canonical = canonicalize(origin)
        except SafetyRejection as exc:
            raise ConfigurationError("session origin is invalid") from exc
        return canonical.origin

    @staticmethod
    def _header(name: str, value: str) -> tuple[str, str]:
        if not isinstance(name, str) or not _HEADER_NAME.match(name):
            raise ConfigurationError("credential header name is invalid")
        if name.lower() in _FORBIDDEN_HEADERS:
            raise ConfigurationError("credential header is not allowed")
        if not isinstance(value, str) or any(char in value for char in "\r\n\x00"):
            raise ConfigurationError("credential header value is invalid")
        try:
            value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ConfigurationError("credential header value must be latin-1") from exc
        return name, value

    def add_credentials(self, origin: str, headers: Mapping[str, str]) -> None:
        """Attach safe request headers to exactly one scheme/host/port origin."""
        self._assert_current_process()
        scope = self._origin(origin)
        if not isinstance(headers, Mapping) or not headers:
            raise ConfigurationError("credentials must be a non-empty mapping")
        if any(not isinstance(name, str) or not isinstance(value, str) for name, value in headers.items()):
            raise ConfigurationError("credential header names and values must be strings")
        incoming = tuple(self._header(name, value) for name, value in headers.items())
        with self._lock:
            if self._closed:
                raise SessionClosedError("session is closed")
            current = self._scopes.get(scope, _Scope())
            replaced = {name.lower() for name, _ in incoming}
            merged = tuple(
                (name, value)
                for name, value in current.headers
                if name.lower() not in replaced
            ) + incoming
            self._scopes[scope] = _Scope(merged, current.cookies)

    def add_cookie(
        self,
        origin: str,
        name: str,
        value: str,
        *,
        path: str = "/",
        secure: bool | None = None,
    ) -> None:
        """Attach a cookie; HTTP uses exact origin, browser uses host/path/Secure scope."""
        self._assert_current_process()
        scope = self._origin(origin)
        if not isinstance(name, str) or not _COOKIE_NAME.match(name):
            raise ConfigurationError("cookie name is invalid")
        if not isinstance(value, str) or not value or any(
            char in value for char in "\r\n\x00;, \t"
        ):
            raise ConfigurationError("cookie value is invalid")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or any(char in path for char in "\r\n\x00;?")
        ):
            raise ConfigurationError("cookie path is invalid")
        if secure is not None and not isinstance(secure, bool):
            raise ConfigurationError("cookie secure flag must be a boolean")
        secure_flag = (scope[0] == "https") if secure is None else secure
        with self._lock:
            if self._closed:
                raise SessionClosedError("session is closed")
            current = self._scopes.get(scope, _Scope())
            cookies = tuple(
                existing
                for existing in current.cookies
                if not (existing.name == name and existing.path == path)
            ) + (_Cookie(name, value, path, secure_flag),)
            self._scopes[scope] = _Scope(current.headers, cookies)

    def add_basic_auth(self, origin: str, username: str, password: str) -> None:
        """Convenience for an explicit Basic ``Authorization`` header."""
        self._assert_current_process()
        if not isinstance(username, str) or not isinstance(password, str):
            raise ConfigurationError("basic auth username/password must be strings")
        if any(char in username + password for char in "\r\n\x00"):
            raise ConfigurationError("basic auth value is invalid")
        encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        self.add_credentials(origin, {"Authorization": f"Basic {encoded}"})

    def clear(self) -> None:
        """Remove every credential/cookie while leaving the session reusable."""
        self._assert_current_process()
        with self._lock:
            self._scopes.clear()

    def close(self) -> None:
        """Clear secrets and permanently prevent new credentials or acquisitions."""
        self._assert_current_process()
        with self._lock:
            self._scopes.clear()
            self._closed = True

    def snapshot(self) -> SessionSnapshot:
        self._assert_current_process()
        with self._lock:
            if self._closed:
                raise SessionClosedError("session is closed")
            return SessionSnapshot(tuple(self._scopes.items()))


__all__ = ["Session", "SessionClosedError", "SessionSnapshot"]
