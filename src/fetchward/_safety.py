"""URL canonicalization and destination enforcement (scope §6).

One parser interprets every URL. Hosts that any common parser could read as an IPv4
number in a non-dotted-decimal form are rejected rather than reinterpreted. Every
resolved address is classified; one forbidden answer rejects the whole set. The
validated address is returned for pinning so the transport cannot reach a different one.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote, urljoin, urlsplit

from .policy import DestinationPolicy, TrustedOrigin

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_DEFAULT_PORTS = {"http": 80, "https": 443}
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_DECIMAL_OCTET = re.compile(r"^(0|[1-9][0-9]{0,2})$")
_NUMERIC_LIKE = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x20\x7f\\]")

# Explicitly named so the reason is useful; `is_global` already excludes most of these.
_METADATA = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("169.254.170.2/32"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class SafetyRejection(Exception):
    """A destination or URL is not permitted. ``code`` is a stable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class DNSFailure(Exception):
    pass


class DNSTimeout(Exception):
    """Resolution did not finish within the acquisition's remaining time."""


class DNSCancelled(Exception):
    """Resolution was cancelled by its owner (e.g. a gateway stopping); no work remains."""


@dataclass(frozen=True)
class CanonicalURL:
    scheme: str
    host: str  # lowercase ASCII (IDNA) host, IPv6 without brackets
    port: int
    target: str  # path + query, percent-encoded, never empty
    ip: IPAddress | None

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = "" if _DEFAULT_PORTS[self.scheme] == self.port else f":{self.port}"
        return f"{self.scheme}://{host}{port}{self.target}"


def _reject(detail: str) -> SafetyRejection:
    return SafetyRejection("safety.url_rejected", detail)


def _canonical_host(raw: str) -> tuple[str, IPAddress | None]:
    if raw.startswith("["):
        if not raw.endswith("]") or "%" in raw:
            raise _reject("malformed or zoned IPv6 literal")
        try:
            address = ipaddress.IPv6Address(raw[1:-1])
        except ValueError as exc:
            raise _reject("malformed IPv6 literal") from exc
        return str(address), address
    if not raw:
        raise _reject("empty host")
    try:
        host = raw.encode("idna").decode("ascii").lower() if not raw.isascii() else raw.lower()
    except UnicodeError as exc:
        raise _reject("host is not valid IDNA") from exc
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253:
        raise _reject("invalid host length")
    labels = host.split(".")
    # WHATWG treats a host whose last label is numeric as IPv4; demand strict dotted-decimal.
    if _NUMERIC_LIKE.match(labels[-1]):
        if len(labels) != 4 or not all(_DECIMAL_OCTET.match(label) and int(label) <= 255 for label in labels):
            raise _reject("ambiguous numeric host")
        address = ipaddress.IPv4Address(host)
        return str(address), address
    for label in labels:
        if not _LABEL.match(label):
            raise _reject("invalid host label")
    return host, None


def _dot_segment(segment: str) -> str | None:
    """Return '.', '..', or None after normalizing percent-encoded dot octets.

    Only %2e is decoded for this structural decision; other percent escapes stay untouched.
    """
    lowered = segment.lower().replace("%2e", ".")
    if lowered == ".":
        return "."
    if lowered == "..":
        return ".."
    return None


def _normalize_path(path: str) -> str:
    """Apply RFC 3986 dot-segment removal in linear time, including ``%2e`` dots.

    The exact path is what robots and Session path matching see and what the transport
    dispatches; repeated slashes and a terminal slash are significant and preserved.
    Segments are materialized once and joined once, so a long untrusted path does not cause
    repeated slicing or quadratic copying.
    """
    if not path:
        return "/"
    absolute = path.startswith("/")
    segments = path.split("/")
    if absolute:
        segments = segments[1:]
    output: list[str] = []
    last = len(segments) - 1
    for index, segment in enumerate(segments):
        kind = _dot_segment(segment)
        if kind == "..":
            if output:
                output.pop()
            if index == last:
                # A terminal dot segment denotes a directory path and keeps its slash.
                output.append("")
        elif kind == ".":
            if index == last:
                output.append("")
        else:
            output.append(segment)
    return ("/" if absolute else "") + "/".join(output)


def canonicalize(url: str) -> CanonicalURL:
    """Parse an absolute HTTP(S) URL strictly. Fragments are dropped; they are never sent."""
    if not isinstance(url, str):
        raise TypeError("url must be a str")
    if _FORBIDDEN_CHARS.search(url):
        raise _reject("control, space or backslash character in URL")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise _reject("unparseable URL") from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise _reject("unsupported scheme")
    netloc = parts.netloc
    if "@" in netloc:
        raise _reject("embedded credentials")
    if not netloc:
        raise _reject("missing host")
    if netloc.startswith("["):
        end = netloc.find("]")
        if end < 0:
            raise _reject("malformed IPv6 literal")
        raw_host, rest = netloc[: end + 1], netloc[end + 1 :]
    else:
        raw_host, _, port_text = netloc.partition(":")
        rest = f":{port_text}" if ":" in netloc else ""
    if rest:
        if not rest.startswith(":") or not rest[1:].isdigit() or not rest[1:].isascii():
            raise _reject("malformed port")
        port = int(rest[1:])
        if not 0 < port < 65536:
            raise _reject("port out of range")
    else:
        port = _DEFAULT_PORTS[scheme]
    host, ip = _canonical_host(raw_host)
    path = quote(_normalize_path(parts.path or "/"), safe="/%:@!$&'()*+,;=-._~")
    target = path + (f"?{quote(parts.query, safe='/?%:@!$&()*+,;=-._~')}" if parts.query else "")
    return CanonicalURL(scheme=scheme, host=host, port=port, target=target, ip=ip)


def resolve_redirect(current: CanonicalURL, location: str) -> CanonicalURL:
    return canonicalize(urljoin(current.url, location.strip()))


def forbidden_reason(address: IPAddress) -> str | None:
    """Why an address is not a public destination, or ``None`` if it is public."""
    if isinstance(address, ipaddress.IPv6Address):
        embedded = address.ipv4_mapped or address.sixtofour
        if embedded is None and address in _NAT64:
            embedded = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        if embedded is None and address.teredo:
            embedded = address.teredo[1]
        if embedded is not None:
            inner = forbidden_reason(embedded)
            if inner:
                return f"embedded_{inner}"
    if any(address in network for network in _METADATA):
        return "metadata"
    if address.is_unspecified:
        return "unspecified"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "reserved"
    if address.is_private:
        return "private"
    if not address.is_global:
        return "non_global"
    return None


class Resolver(Protocol):
    """Resolve ``host`` within ``timeout`` seconds.

    Contract: raise :class:`DNSTimeout` at the timeout, :class:`DNSCancelled` promptly once
    ``cancel`` (a cancellation token with ``cancelled``/``fileno``) is set, and :class:`DNSFailure` on
    failure; leave no lookup work running once the call returns or raises. The production
    implementation is :class:`fetchward._dns.CaresResolver`.
    """

    def resolve(self, host: str, port: int, timeout: float, cancel=None) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class Destination:
    url: CanonicalURL
    address: str  # validated address the connection must use
    trusted: bool


class DestinationGuard:
    """Validates a canonical URL's destination and returns the address to pin."""

    def __init__(self, policy: DestinationPolicy, resolver: Resolver) -> None:
        self._trusted: dict[tuple[str, str, int], TrustedOrigin] = {
            (o.scheme, o.host, o.port): o for o in policy.trusted_local
        }
        self._resolver = resolver

    def check(self, url: CanonicalURL, timeout: float, cancel=None) -> Destination:
        """Validate ``url``'s destination. Resolution is bounded by ``timeout`` and ``cancel``."""
        trusted = self._trusted.get(url.origin)
        if url.ip is not None:
            answers: tuple[str, ...] = (str(url.ip),)
        else:
            if timeout <= 0:
                raise DNSTimeout()
            answers = self._resolver.resolve(url.host, url.port, timeout, cancel=cancel)
            if not answers:
                raise DNSFailure("no addresses")
        addresses: list[IPAddress] = []
        for answer in answers:
            try:
                addresses.append(ipaddress.ip_address(answer))
            except ValueError as exc:
                raise SafetyRejection("safety.destination_rejected", "resolver returned a non-IP answer") from exc
        if trusted is not None:
            for address in addresses:
                if str(address) not in trusted.addresses:
                    raise SafetyRejection(
                        "safety.destination_rejected", "trusted origin resolved outside its allowance"
                    )
            return Destination(url=url, address=str(addresses[0]), trusted=True)
        for address in addresses:
            reason = forbidden_reason(address)
            if reason is not None:
                raise SafetyRejection("safety.destination_rejected", f"non-public destination: {reason}")
        return Destination(url=url, address=str(addresses[0]), trusted=False)
