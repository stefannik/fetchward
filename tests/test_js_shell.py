"""Structural JS-shell detector tests (never length alone)."""

from __future__ import annotations

from fetchward._js_shell import detect_js_shell


def test_structural_shell_requires_script_and_root_marker() -> None:
    shell = detect_js_shell(
        "<html><body><div id='app'></div><script src='/app.js'></script></body></html>"
    )
    assert shell.detected and shell.scripts == 1 and shell.root_markers >= 1


def test_short_content_alone_is_not_a_shell() -> None:
    assert not detect_js_shell("<html><body>short</body></html>").detected


def test_script_without_root_marker_is_not_a_shell() -> None:
    assert not detect_js_shell("<html><body><script>1</script></body></html>").detected


def test_visible_text_makes_shell_non_trivial() -> None:
    html = (
        "<html><body><div id='app'>"
        + "Real article text. " * 8
        + "</div><script>1</script></body></html>"
    )
    assert not detect_js_shell(html).detected
