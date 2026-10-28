"""Immutable acquisition policy. The defaults below are the v0.1 baseline."""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from typing import Literal

from ._selectors import validate_selector
from ._types import Mode
from .errors import ConfigurationError

POLICY_VERSION = "p0a-1"

MiB = 1024 * 1024


def _finite_positive(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{name} must be a number")
    if not math.isfinite(value) or value <= 0:
        raise ConfigurationError(f"{name} must be finite and positive")


def _non_negative_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigurationError(f"{name} must be a non-negative integer")


def _finite_nonnegative(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{name} must be a number")
    if not math.isfinite(value) or value < 0:
        raise ConfigurationError(f"{name} must be finite and non-negative")


@dataclass(frozen=True)
class SchedulingPolicy:
    """Process-shared operational limits. State lives in ``SafetyRuntime``."""

    max_in_flight_per_host: int = 4
    min_host_interval: float = 0.25
    active_acquisitions: int = 8
    retry_backoff: float = 0.5
    retry_jitter: float = 0.25
    default_cooldown: float = 60.0
    circuit_window: float = 60.0
    circuit_threshold: int = 3
    circuit_cooldown: float = 30.0
    circuit_cooldown_max: float = 300.0
    state_capacity: int = 1024
    robots_cache_ttl: float = 3600.0
    robots_cache_max_ttl: float = 86400.0
    robots_max_bytes: int = 512 * 1024
    robots_max_redirects: int = 5

    def __post_init__(self) -> None:
        for name in ("max_in_flight_per_host", "active_acquisitions", "circuit_threshold", "state_capacity", "robots_max_bytes"):
            _non_negative_int(name, getattr(self, name))
            if getattr(self, name) == 0:
                raise ConfigurationError(f"{name} must be positive")
        for name in (
            "min_host_interval", "retry_backoff", "retry_jitter", "default_cooldown",
            "circuit_window", "circuit_cooldown", "circuit_cooldown_max",
            "robots_cache_ttl", "robots_cache_max_ttl",
        ):
            _finite_nonnegative(name, getattr(self, name))
        for name in ("default_cooldown", "circuit_window", "circuit_cooldown", "circuit_cooldown_max", "robots_cache_ttl", "robots_cache_max_ttl"):
            if getattr(self, name) <= 0:
                raise ConfigurationError(f"{name} must be positive")
        if self.circuit_cooldown_max < self.circuit_cooldown:
            raise ConfigurationError("circuit_cooldown_max must be >= circuit_cooldown")
        if self.robots_cache_max_ttl < self.robots_cache_ttl:
            raise ConfigurationError("robots_cache_max_ttl must be >= robots_cache_ttl")
        _non_negative_int("robots_max_redirects", self.robots_max_redirects)


@dataclass(frozen=True)
class Budgets:
    max_requests: int = 64
    max_attempts: int = 3
    retries: int = 1
    max_redirects: int = 10
    max_robots_redirects: int = 5
    browser_navigations: int = 1
    max_browser_requests: int = 250
    max_source_bytes: int = 32 * MiB
    max_dom_bytes: int = 32 * MiB
    max_total_bytes: int = 64 * MiB
    stop_reserve: float = 0.5

    def __post_init__(self) -> None:
        for name in ("max_requests", "max_attempts", "max_browser_requests", "max_source_bytes", "max_dom_bytes", "max_total_bytes"):
            _non_negative_int(name, getattr(self, name))
            if getattr(self, name) == 0:
                raise ConfigurationError(f"{name} must be positive")
        for name in ("retries", "max_redirects", "max_robots_redirects", "browser_navigations"):
            _non_negative_int(name, getattr(self, name))
        # Robots redirects also consume the total cap, so the effective robots limit is the minimum.
        _finite_positive("stop_reserve", self.stop_reserve)


@dataclass(frozen=True)
class Readiness:
    """Declarative browser readiness conditions after ``domcontentloaded``."""

    require_rendering: bool = False
    selector: str | None = None
    selector_timeout: float = 5.0
    lifecycle: Literal["domcontentloaded"] = "domcontentloaded"
    selectors: tuple[str, ...] = ()
    match: Literal["all", "any"] = "all"
    visible: bool = False
    text_contains: str | None = None
    dom_stable_ms: int | None = None

    def __post_init__(self) -> None:
        _finite_positive("selector_timeout", self.selector_timeout)
        if self.lifecycle != "domcontentloaded":
            raise ConfigurationError("only the 'domcontentloaded' lifecycle is supported")
        if self.selector is not None:
            if not isinstance(self.selector, str) or not self.selector.strip():
                raise ConfigurationError("selector must be a non-empty string")
            validate_selector(self.selector)
        if not isinstance(self.selectors, tuple):
            raise ConfigurationError("selectors must be a tuple of CSS selectors")
        for selector in self.selectors:
            if not isinstance(selector, str) or not selector.strip():
                raise ConfigurationError("selectors must contain non-empty strings")
            validate_selector(selector)
        if self.match not in ("all", "any"):
            raise ConfigurationError("match must be 'all' or 'any'")
        if not isinstance(self.visible, bool):
            raise ConfigurationError("visible must be a boolean")
        if self.text_contains is not None and not isinstance(self.text_contains, str):
            raise ConfigurationError("text_contains must be a string or None")
        if self.dom_stable_ms is not None:
            _non_negative_int("dom_stable_ms", self.dom_stable_ms)

    @property
    def requires_browser(self) -> bool:
        return (
            self.require_rendering
            or self.selector is not None
            or bool(self.selectors)
            or self.match != "all"
            or self.visible
            or self.text_contains is not None
            or self.dom_stable_ms is not None
        )


_PRODUCT_TOKEN = re.compile(r"^[A-Za-z_-]+$")


def _contains_product_token(value: str, token: str) -> bool:
    return re.search(
        rf"(?<![A-Za-z_-]){re.escape(token)}(?![A-Za-z_-])",
        value,
        re.IGNORECASE,
    ) is not None


def build_user_agent(
    user_agent: str | None, product_token: str, *, fallback: str, annotate: bool = True
) -> str:
    """Return a header-safe UA, optionally advertising the configured RFC 9309 token.

    ``annotate`` defaults to true, which keeps the browser caller's behavior unchanged: the
    token is appended unless the UA already contains it.
    """
    value = (user_agent or "").strip() or fallback
    if annotate and not _contains_product_token(value, product_token):
        value = f"{value} (+{product_token})"
    return value


def _validate_header_value(name: str, value: str) -> None:
    if not isinstance(value, str):
        raise ConfigurationError(f"{name} must be a string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ConfigurationError(f"{name} must not contain control characters")
    try:
        value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ConfigurationError(f"{name} must be latin-1 transportable") from exc


@dataclass(frozen=True)
class AccessPolicy:
    """``user_initiated`` (default) skips robots.txt and is recorded; ``automated`` opts in to it.

    robots.txt is opt-in. Politeness controls
    (pacing, 429/Retry-After, cooldown, circuit breaker, budgets) apply in both modes.
    """

    mode: Literal["automated", "user_initiated"] = "user_initiated"
    product_token: str = "fetchward"

    def __post_init__(self) -> None:
        if self.mode not in ("automated", "user_initiated"):
            raise ConfigurationError("access mode must be 'automated' or 'user_initiated'")
        if not isinstance(self.product_token, str) or not _PRODUCT_TOKEN.fullmatch(
            self.product_token
        ):
            raise ConfigurationError(
                "product_token must contain only ASCII letters, underscores and hyphens"
            )


@dataclass(frozen=True)
class TrustedOrigin:
    """A narrow trusted-local allowance: one origin, reachable only at the listed addresses."""

    scheme: Literal["http", "https"]
    host: str
    port: int
    addresses: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.scheme not in ("http", "https"):
            raise ConfigurationError("trusted origin scheme must be http or https")
        if not isinstance(self.port, int) or not 0 < self.port < 65536:
            raise ConfigurationError("trusted origin port must be 1-65535")
        if not self.addresses:
            raise ConfigurationError("trusted origin needs at least one explicit address")
        normalized = []
        for address in self.addresses:
            try:
                normalized.append(str(ipaddress.ip_address(address)))
            except ValueError as exc:
                raise ConfigurationError("trusted origin addresses must be IP literals") from exc
        object.__setattr__(self, "host", self.host.lower().rstrip("."))
        object.__setattr__(self, "addresses", tuple(normalized))


@dataclass(frozen=True)
class DestinationPolicy:
    trusted_local: tuple[TrustedOrigin, ...] = ()


@dataclass(frozen=True)
class TransportPolicy:
    """Transport settings. ``ca_bundle`` replaces HTTP trust roots; Chromium uses native trust."""

    ca_bundle: str | None = None
    user_agent: str | None = None
    browser_block_resource_types: tuple[str, ...] = ("image", "media", "font")
    browser_engine: Literal["headless-shell", "chromium", "chrome"] = "chromium"

    def __post_init__(self) -> None:
        if self.browser_engine not in ("headless-shell", "chromium", "chrome"):
            raise ConfigurationError("browser_engine must be 'headless-shell', 'chromium' or 'chrome'")
        resource_types = {"document", "stylesheet", "image", "media", "font", "script", "texttrack", "xhr", "fetch", "eventsource", "websocket", "manifest", "other"}
        if not isinstance(self.browser_block_resource_types, tuple) or any(
            not isinstance(value, str) or value not in resource_types
            for value in self.browser_block_resource_types
        ):
            raise ConfigurationError("browser_block_resource_types must be a tuple of Playwright resource types")
        if self.user_agent is not None:
            if not isinstance(self.user_agent, str):
                raise ConfigurationError("user_agent must be a string or None")
            _validate_header_value("user_agent", self.user_agent)


@dataclass(frozen=True)
class AcquisitionPolicy:
    budgets: Budgets = field(default_factory=Budgets)
    readiness: Readiness = field(default_factory=Readiness)
    access: AccessPolicy = field(default_factory=AccessPolicy)
    destinations: DestinationPolicy = field(default_factory=DestinationPolicy)
    transport: TransportPolicy = field(default_factory=TransportPolicy)
    scheduling: SchedulingPolicy = field(default_factory=SchedulingPolicy)

    def validate_call(self, mode: str, timeout: float) -> Mode:
        """Reject unsupported or contradictory call configuration before any I/O."""
        try:
            resolved = Mode(mode)
        except ValueError as exc:
            raise ConfigurationError(f"unsupported mode {mode!r}") from exc
        _finite_positive("timeout", timeout)
        if resolved is Mode.HTTP and self.readiness.requires_browser:
            raise ConfigurationError("mode='http' contradicts a browser-only readiness requirement")
        return resolved
