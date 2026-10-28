"""Conservative structural JS-shell detection (never length alone)."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser

_ROOT_MARKERS = frozenset({"app", "root", "main", "__next", "__nuxt", "react-root"})


@dataclass(frozen=True)
class JsShell:
    detected: bool
    visible_text: int
    scripts: int
    root_markers: int


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.script_depth = 0
        self.style_depth = 0
        self.visible = 0
        self.scripts = 0
        self.markers = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        lowered = tag.lower()
        if lowered == "script":
            self.scripts += 1
            self.script_depth += 1
        elif lowered == "style":
            self.style_depth += 1
        for name, value in attrs:
            if name.lower() in ("id", "class") and value:
                tokens = {token.lower() for token in value.split()}
                if tokens & _ROOT_MARKERS:
                    self.markers += 1

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() in ("script", "style"):
            # Self-closing script/style is unusual; keep balance.
            if tag.lower() == "script" and self.script_depth:
                self.script_depth -= 1
            if tag.lower() == "style" and self.style_depth:
                self.style_depth -= 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self.script_depth:
            self.script_depth -= 1
        elif tag.lower() == "style" and self.style_depth:
            self.style_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self.script_depth and not self.style_depth:
            self.visible += len(data.strip())


def detect_js_shell(html: str | None) -> JsShell:
    if not html:
        return JsShell(False, 0, 0, 0)
    parser = _Parser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return JsShell(False, 0, 0, 0)
    detected = parser.scripts > 0 and parser.markers > 0 and parser.visible <= 32
    return JsShell(detected, parser.visible, parser.scripts, parser.markers)


__all__ = ["JsShell", "detect_js_shell"]
