"""Conservative detection of a rendered/declared login barrier.

This is not a generic login-form detector and it never submits credentials. A page is a
barrier only when it presents a password field inside a form and either:

- explicit required-authentication language ("sign in to continue", "login required", ...),
  or
- the acquisition followed a redirect to a login-like final URL with that form.

An ordinary content page with an optional sign-in link or an optional header form is not a
barrier. Previews remain previews unless they carry the required form/language evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

_REQUIRED_LANGUAGE = re.compile(
    r"(?:"
    r"\b(?:sign|log)[ -]?in (?:is )?(?:required|needed)\b"
    r"|\b(?:sign|log)[ -]?in to (?:continue|proceed|view|access|see|use|read)\b"
    r"|\b(?:authentication|auth) required\b"
    r"|\byou (?:must|need to) (?:sign|log)[ -]?in\b"
    r"|\ba login is required\b"
    r")",
    re.IGNORECASE,
)
_LOGIN_PATH = re.compile(r"/(?:login|signin|sign-in|authenticate|auth)(?:/|$)", re.IGNORECASE)


@dataclass(frozen=True)
class LoginBarrier:
    detected: bool
    password_form: bool
    required_language: bool
    redirected: bool
    login_path: bool
    form_action: str | None = None
    primary_password_form: bool = False
    public_article: bool = False

    def facts(self) -> tuple[tuple[str, str], ...]:
        return (
            ("password_form", str(self.password_form).lower()),
            ("primary_password_form", str(self.primary_password_form).lower()),
            ("required_language", str(self.required_language).lower()),
            ("public_article", str(self.public_article).lower()),
            ("redirected", str(self.redirected).lower()),
            ("login_path", str(self.login_path).lower()),
        )


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.form_depth = 0
        self.password_form = False
        self.primary_password_form = False
        self.form_action: str | None = None
        self.script_depth = 0
        self.style_depth = 0
        self.text: list[str] = []
        self.heading_text: list[str] = []
        self.heading_depth = 0
        self.excluded_depth = 0
        self.article_depth = 0
        self.public_article = False

    @staticmethod
    def _excluded(tag: str) -> bool:
        return tag in {"article", "aside", "nav", "footer", "header"}

    def handle_starttag(self, tag: str, attrs) -> None:
        lowered = tag.lower()
        attributes = {name.lower(): value for name, value in attrs}
        if lowered == "form":
            self.form_depth += 1
            action = (attributes.get("action") or "").strip()
            if action:
                self.form_action = action
        elif lowered == "input":
            if (attributes.get("type") or "").lower() == "password" and self.form_depth > 0:
                self.password_form = True
                if self.excluded_depth == 0 and self.article_depth == 0:
                    self.primary_password_form = True
        elif lowered == "script":
            self.script_depth += 1
        elif lowered == "style":
            self.style_depth += 1
        if lowered in {"h1", "h2", "h3", "title"}:
            self.heading_depth += 1
        if self._excluded(lowered):
            if lowered == "article":
                self.article_depth += 1
            self.excluded_depth += 1

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered == "form" and self.form_depth:
            self.form_depth -= 1
        elif lowered == "script" and self.script_depth:
            self.script_depth -= 1
        elif lowered == "style" and self.style_depth:
            self.style_depth -= 1
        if lowered in {"h1", "h2", "h3", "title"} and self.heading_depth:
            self.heading_depth -= 1
        if self._excluded(lowered):
            if self.excluded_depth:
                self.excluded_depth -= 1
            if lowered == "article" and self.article_depth:
                self.article_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.script_depth or self.style_depth:
            return
        if self.article_depth > 0 and data.strip():
            self.public_article = True
        if self.heading_depth > 0:
            self.heading_text.append(data)
        if self.excluded_depth == 0:
            self.text.append(data)


def _login_path(url: str | None) -> bool:
    if not url:
        return False
    try:
        path = urlsplit(url).path
    except ValueError:
        return False
    return _LOGIN_PATH.search(path) is not None


def detect_login_barrier(
    html: str | None,
    *,
    url: str | None = None,
    redirected: bool = False,
) -> LoginBarrier:
    if not html:
        return LoginBarrier(False, False, False, redirected, _login_path(url))
    parser = _Parser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return LoginBarrier(False, False, False, redirected, _login_path(url))
    required = _REQUIRED_LANGUAGE.search(" ".join(parser.heading_text)) is not None
    login_path = _login_path(url)
    direct_barrier = (
        parser.primary_password_form
        and required
        and not parser.public_article
    )
    redirected_barrier = redirected and login_path and parser.password_form
    detected = direct_barrier or redirected_barrier
    return LoginBarrier(
        detected,
        parser.password_form,
        required,
        redirected,
        login_path,
        parser.form_action,
        parser.primary_password_form,
        parser.public_article,
    )


__all__ = ["LoginBarrier", "detect_login_barrier"]
