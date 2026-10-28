"""S01 unit layer: URL canonicalization and address classification (no network)."""

from __future__ import annotations

import ipaddress
import time

import pytest

from harness import StaticResolver
from fetchward import AcquisitionPolicy, DestinationPolicy, Fetcher, Outcome, TrustedOrigin
from fetchward._safety import DestinationGuard, SafetyRejection, canonicalize, forbidden_reason


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/",
        "javascript:alert(1)",
        "data:text/html,hi",
        "chrome://settings",
        "gopher://example.com/",
        "http://user:pass@example.com/",
        "http://user@example.com/",
        "http://2130706433/",  # decimal 127.0.0.1
        "http://0x7f000001/",  # hex
        "http://0177.0.0.1/",  # octal octet
        "http://127.1/",  # short form
        "http://0x7f.0.0.1/",
        "http://127.0.0.01/",
        "http://256.1.1.1/",
        "http://１２７.0.0.1/",  # fullwidth digits normalize to an IPv4 literal...
        "http://[::1%25eth0]/",
        "http://exa mple.com/",
        "http://example.com\\@evil/",
        "http://example.com:0/",
        "http://example.com:99999/",
        "http://example.com:/",
        "http:///nohost",
        "http://-bad-.example/",
        "http://%31%32%37.0.0.1/",
        "relative/path",
    ],
)
def test_rejected_urls(url: str) -> None:
    if url == "http://１２７.0.0.1/":
        # ...which is then a strict dotted-decimal literal: accepted syntactically, and
        # destination classification (below) is what rejects loopback.
        assert canonicalize(url).ip == ipaddress.IPv4Address("127.0.0.1")
        return
    with pytest.raises(SafetyRejection) as info:
        canonicalize(url)
    assert info.value.code == "safety.url_rejected"


def test_canonical_form() -> None:
    c = canonicalize("HTTP://Example.COM.:80/caf\u00e9?q=1#frag")
    assert c.url == "http://example.com/caf%C3%A9?q=1"
    assert c.origin == ("http", "example.com", 80)
    assert canonicalize("https://bücher.example/").host == "xn--bcher-kva.example"
    assert canonicalize("http://[::FFFF:7f00:1]/").ip == ipaddress.IPv6Address("::ffff:127.0.0.1")


@pytest.mark.parametrize(
    "address,reason",
    [
        ("127.0.0.1", "loopback"),
        ("10.1.2.3", "private"),
        ("172.16.0.1", "private"),
        ("192.168.1.1", "private"),
        ("169.254.169.254", "metadata"),
        ("169.254.1.1", "link_local"),
        ("100.100.100.200", "metadata"),
        ("100.64.0.1", "non_global"),
        ("0.0.0.0", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
        ("::1", "loopback"),
        ("fe80::1", "link_local"),
        ("fc00::1", "private"),
        ("fd00:ec2::254", "metadata"),
        ("::ffff:127.0.0.1", "embedded_loopback"),
        ("::ffff:169.254.169.254", "embedded_metadata"),
        ("64:ff9b::a00:1", "embedded_private"),
        ("2002:7f00:1::", "embedded_loopback"),
    ],
)
def test_forbidden_addresses(address: str, reason: str) -> None:
    assert forbidden_reason(ipaddress.ip_address(address)) == reason


@pytest.mark.parametrize("address", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses(address: str) -> None:
    assert forbidden_reason(ipaddress.ip_address(address)) is None


def test_mixed_answer_set_rejected_entirely() -> None:
    guard = DestinationGuard(DestinationPolicy(), StaticResolver({"mixed.example": ("1.1.1.1", "10.0.0.1")}))
    with pytest.raises(SafetyRejection) as info:
        guard.check(canonicalize("http://mixed.example/"), 5)
    assert info.value.code == "safety.destination_rejected"


def test_public_answer_is_pinned() -> None:
    guard = DestinationGuard(DestinationPolicy(), StaticResolver({"pub.example": ("1.1.1.1", "1.0.0.1")}))
    destination = guard.check(canonicalize("http://pub.example/"), 5)
    assert destination.address == "1.1.1.1" and not destination.trusted


def test_trusted_origin_is_narrow() -> None:
    trusted = TrustedOrigin("http", "local.test", 8080, ("127.0.0.1",))
    resolver = StaticResolver({"local.test": ("127.0.0.1",), "other.test": ("127.0.0.1",)})
    guard = DestinationGuard(DestinationPolicy(trusted_local=(trusted,)), resolver)
    assert guard.check(canonicalize("http://local.test:8080/"), 5).trusted
    for url in ("http://local.test:8081/", "https://local.test:8080/", "http://other.test:8080/", "http://127.0.0.1:8080/"):
        with pytest.raises(SafetyRejection):
            guard.check(canonicalize(url), 5)
    resolver.answers["local.test"] = ("127.0.0.1", "127.0.0.2")
    with pytest.raises(SafetyRejection):
        guard.check(canonicalize("http://local.test:8080/"), 5)


@pytest.mark.parametrize(
    ("url", "target"),
    [
        ("http://example.com/public/../private", "/private"),
        ("http://example.com/public/%2e%2e/private", "/private"),
        ("http://example.com/public/.%2E/private", "/private"),
        ("http://example.com/public/%2E./private", "/private"),
        ("http://example.com/a/./b", "/a/b"),
        ("http://example.com/a//b", "/a//b"),
        ("http://example.com/a/../", "/"),
        ("http://example.com/foo/.", "/foo/"),
        ("http://example.com/foo/..", "/"),
        ("http://example.com/foo/bar/..", "/foo/"),
        ("http://example.com/foo/bar/.", "/foo/bar/"),
        ("http://example.com/foo//.", "/foo//"),
        ("http://example.com/foo//..", "/foo/"),
        ("http://example.com/foo/%2e", "/foo/"),
        ("http://example.com/foo/%2e%2e", "/"),
        ("http://example.com/foo/.%2e", "/"),
        ("http://example.com/foo/%2e.", "/"),
        ("http://example.com/a/b/c/./../../g", "/a/g"),
        ("http://example.com/foo/.?q=1", "/foo/?q=1"),
    ],
)
def test_dot_segments_are_normalized_before_transport(url: str, target: str) -> None:
    assert canonicalize(url).target == target


@pytest.mark.parametrize("path", ["a/" * 400_000, "a" * 2_000_000])
def test_huge_untrusted_path_is_rejected_within_the_deadline(path: str) -> None:
    """Canonicalization and the destination check must stay bounded before any network."""
    fetcher = Fetcher(AcquisitionPolicy())
    started = time.monotonic()
    try:
        result = fetcher.fetch("http://127.0.0.1/" + path, mode="http", timeout=0.5)
    finally:
        fetcher.close()
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, elapsed
    assert result.outcome is Outcome.ERROR
    assert result.diagnostics.stop_reason == "safety.destination_rejected"
    assert result.diagnostics.budget.requests == 0
