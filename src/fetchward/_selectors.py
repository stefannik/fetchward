"""Pre-I/O selector validation for the one optional readiness condition.

The readiness contract is a CSS selector, not an arbitrary Playwright selector expression.
This module performs a conservative CSS selector syntax gate so obvious configuration errors
are rejected before DNS, robots or browser navigation. Playwright remains the authority for
the final attached check; a selector that passes this gate but is rejected by the engine is
reported as an unsupported readiness condition, not silently ignored.
"""

from __future__ import annotations

import re

from .errors import ConfigurationError

_ATTRIBUTE = re.compile(
    r"""^\s*
    (?P<name>(?:\\.|[^\s~|^$*!=\]\[\\])+)
    (?:
        \s*(?P<operator>[~|^$*]?=)\s*
        (?P<value>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|(?:\\.|[^\s\]=])+)
        \s*(?P<flag>[iIsS])?
    )?
    \s*$""",
    re.VERBOSE,
)

_FORBIDDEN_OUTSIDE = frozenset("{};@?<>!")
def _identifier_start(char: str) -> bool:
    return char.isalpha() or char == "_" or char == "-" or char == "\\" or ord(char) >= 128


def _invalid() -> ConfigurationError:
    return ConfigurationError("selector must be a valid CSS selector")


def validate_selector(selector: str) -> None:
    """Reject clearly malformed CSS selectors without interpreting the document.

    Quoted strings, attribute selectors, pseudo-function arguments and CSS escapes are
    scanned structurally: commas/combinators inside them are not mistaken for top-level
    selector separators. The engine remains the final authority for accepted syntax.
    """
    if not isinstance(selector, str) or not selector.strip():
        raise ConfigurationError("selector must be a non-empty string")

    quote: str | None = None
    escaped = False
    bracket = False
    bracket_has_content = False
    attribute: list[str] = []
    parens = 0
    paren_content: list[bool] = []
    top: list[str] = []
    index = 0
    length = len(selector)
    while index < length:
        char = selector[index]
        if escaped:
            escaped = False
            if bracket:
                bracket_has_content = True
                attribute.append("\\")
                attribute.append(char)
            elif parens:
                paren_content[-1] = True
            index += 1
            continue
        if char == "\\":
            if index + 1 >= length:
                raise _invalid()
            escaped = True
            if bracket == 0 and parens == 0:
                top.append("X")
            index += 1
            continue
        if quote is not None:
            if char == quote:
                quote = None
            elif char in "\r\n\x00":
                raise _invalid()
            if bracket:
                attribute.append(char)
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            if bracket:
                attribute.append(char)
            elif parens:
                paren_content[-1] = True
            index += 1
            continue
        if ord(char) < 0x20 or ord(char) == 0x7F:
            raise _invalid()
        if char == "[":
            if bracket:
                raise _invalid()
            if parens:
                paren_content[-1] = True
            bracket = True
            bracket_has_content = False
            attribute = []
            if parens == 0:
                top.append("X")
            index += 1
            continue
        if char == "]":
            if not bracket or not bracket_has_content:
                raise _invalid()
            if _ATTRIBUTE.match("".join(attribute)) is None:
                raise _invalid()
            bracket = False
            index += 1
            continue
        if char == "(":
            if parens:
                paren_content[-1] = True
            parens += 1
            paren_content.append(False)
            if bracket:
                index += 1
                continue
            if parens == 1:
                top.append("X")
            index += 1
            continue
        if char == ")":
            if parens == 0 or not paren_content[-1]:
                raise _invalid()
            parens -= 1
            paren_content.pop()
            index += 1
            continue
        if bracket:
            # Attribute-selector contents may include strings, operators and values.
            # Structural bracket/quote balance was handled above.
            if char in "?{};@<>":
                raise _invalid()
            if not char.isspace():
                bracket_has_content = True
            attribute.append(char)
            index += 1
            continue
        if parens:
            # Pseudo-function arguments are CSS selector/string content. Only balance and
            # control-character checks apply here; nested attributes are handled above.
            if not char.isspace():
                paren_content[-1] = True
            index += 1
            continue
        if char in "?{};@<!":
            raise _invalid()
        if char == "=":
            raise _invalid()
        if char in "#.:" and index + 1 < length:
            following = selector[index + 1]
            if char in "#." and not _identifier_start(following):
                raise _invalid()
            if char == ":":
                if following == ":":
                    if index + 2 >= length or not _identifier_start(selector[index + 2]):
                        raise _invalid()
                elif not _identifier_start(following):
                    raise _invalid()
        top.append(char)
        index += 1

    if quote is not None or bracket or parens:
        raise _invalid()

    text = "".join(top)
    if not text.strip() or text[-1] in "#.:":
        raise _invalid()

    def check_segment(segment: str) -> None:
        fragment = "".join(segment.split())
        if not fragment:
            raise _invalid()
        if fragment[0] in ">+~" or fragment[-1] in ">+~":
            raise _invalid()
        previous = ""
        for char in fragment:
            if char in ">+~":
                if previous == "" or previous in ">+~":
                    raise _invalid()
            previous = char

    for segment in text.split(","):
        check_segment(segment)


__all__ = ["validate_selector"]
