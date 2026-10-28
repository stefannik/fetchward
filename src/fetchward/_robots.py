"""RFC 9309 robots parsing, decisions, cache and concurrent lookup deduplication.

Parsing is bounded by the caller-supplied byte cap; a truncated file cannot authorize a
target whose matching rules were outside the retained prefix. Cache entries are partitioned
by origin, product token and the destination/transport policy. Robots fetches use the same
direct adapter (and therefore the same safety/budget/pinning path) as resources; this module
never performs network work itself.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ._admission import Admission
from ._fork import register_child_reset
from ._safety import CanonicalURL
from ._types import AttemptRecord, Evidence, EvidenceCategory, Headers, Outcome
from .policy import AcquisitionPolicy

DEFAULT_ROBOTS_MAX_BYTES = 512 * 1024
DEFAULT_ROBOTS_CACHE_TTL = 3600.0
MAX_ROBOTS_CACHE_TTL = 86400.0
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_HEX = frozenset("0123456789abcdefABCDEF")
_PATH_SAFE = _UNRESERVED | frozenset("/%:@!$&'()*+,;=-._~?")


@dataclass(frozen=True)
class RobotsRule:
    allow: bool
    pattern: str
    length: int
    end_anchor: bool

    def matches(self, target: str) -> bool:
        return _glob_matches(self.pattern, target, self.end_anchor)


def _glob_matches(pattern: str, text: str, end_anchor: bool) -> bool:
    """Match RFC 9309 `*`/optional `$` with bounded literal-section searches.

    Literal sections between wildcards are searched with ``str.find`` (C-level substring
    search) instead of a per-character backtracking loop. This avoids the quadratic
    pathological case of a long literal after a wildcard and cannot spawn regex
    backtracking. A non-anchored pattern matches a prefix; an anchored pattern must end
    with the final literal.
    """
    if "*" not in pattern:
        return text == pattern if end_anchor else text.startswith(pattern)

    parts = pattern.split("*")
    pos = 0
    first = parts[0]
    if first:
        if not text.startswith(first):
            return False
        pos = len(first)
    for part in parts[1:-1]:
        if not part:
            continue
        found = text.find(part, pos)
        if found < 0:
            return False
        pos = found + len(part)
    last = parts[-1]
    if not end_anchor:
        if not last:
            return True
        return text.find(last, pos) >= 0
    if not last:
        return True
    start = len(text) - len(last)
    return start >= pos and text.endswith(last)


@dataclass(frozen=True)
class RobotsRules:
    rules: tuple[RobotsRule, ...] = ()
    truncated: bool = False
    malformed: int = 0

    def match(self, target: str) -> RobotsRule | None:
        normalized = _normalize_octets(target)
        matching = [rule for rule in self.rules if rule.matches(normalized)]
        if not matching:
            return None
        return max(matching, key=lambda rule: (rule.length, rule.allow))

    def allows(self, target: str) -> bool:
        match = self.match(target)
        return match is None or match.allow


@dataclass(frozen=True)
class RobotsDecision:
    allowed: bool
    reason: str | None
    outcome: Outcome | None
    evidence: tuple[Evidence, ...] = ()
    status: int | None = None
    cached: bool = False
    stale: bool = False


@dataclass(frozen=True)
class _CacheEntry:
    rules: RobotsRules
    stored_wall: float
    expires_wall: float
    status: int
    no_cache: bool


@dataclass
class _FetchResult:
    rules: RobotsRules | None
    reason: str | None
    outcome: Outcome | None
    evidence: tuple[Evidence, ...]
    status: int | None
    ttl: float | None = None
    no_store: bool = False
    no_cache: bool = False


@dataclass
class _Flight:
    result: _FetchResult | None = None


class RobotsCache:
    def __init__(self, capacity: int = 1024) -> None:
        self._capacity = capacity
        self._entries: OrderedDict[tuple, _CacheEntry] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: tuple, now_wall: float) -> tuple[_CacheEntry | None, bool]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None, False
            fresh = not entry.no_cache and now_wall < entry.expires_wall
            return entry, fresh

    def put(self, key: tuple, entry: _CacheEntry) -> None:
        with self._lock:
            self._entries.pop(key, None)
            self._entries[key] = entry
            while len(self._entries) > self._capacity:
                self._entries.popitem(last=False)

    def remove(self, key: tuple) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class RobotsAuthority:
    """Process-shared cache and one in-flight fetch per origin/policy partition."""

    def __init__(self, cache: RobotsCache | None = None) -> None:
        self._cache = cache or RobotsCache()
        self._condition = threading.Condition()
        self._flights: dict[tuple, _Flight] = {}

    def reset_for_tests(self) -> None:
        self._cache.clear()
        with self._condition:
            self._flights.clear()
            self._condition.notify_all()

    def decide(
        self,
        url: CanonicalURL,
        policy: AcquisitionPolicy,
        admission: Admission,
        fetch: Callable[[], AttemptRecord],
        *,
        now_wall: Callable[[], float] = time.time,
    ) -> RobotsDecision:
        """Return an allow/deny decision for ``url``; never fetch recursively for robots."""
        if policy.access.mode == "user_initiated":
            return RobotsDecision(
                True,
                None,
                None,
                (Evidence("access.user_initiated", EvidenceCategory.OBSERVATION, True),),
            )
        if url.target.split("?", 1)[0] == "/robots.txt":
            return RobotsDecision(
                True,
                None,
                None,
                (Evidence("access.robots_allowed", EvidenceCategory.OBSERVATION, True),),
            )

        key = _cache_key(url, policy)
        while True:
            entry, fresh = self._cache.get(key, now_wall())
            if fresh and entry is not None:
                return self._evaluate(entry, url.target, cached=True, stale=False)
            with self._condition:
                flight = self._flights.get(key)
                if flight is None:
                    flight = _Flight()
                    self._flights[key] = flight
                    owner = True
                else:
                    owner = False
                    remaining = admission.remaining()
                    if remaining <= 0:
                        return self._failure("budget.deadline", Outcome.ERROR, None)
                    self._condition.wait(remaining)
                    result = flight.result
                    if result is None:
                        continue
                    if result.reason == "budget.deadline" and admission.remaining() > 0.05:
                        # The owner's deadline is not this waiter's deadline; re-admit.
                        continue
                    return self._resolve_result(result, entry, url.target)
            if not owner:
                continue
            try:
                result = self._fetch(policy, admission, fetch, now_wall)
            except BaseException:
                with self._condition:
                    self._flights.pop(key, None)
                    self._condition.notify_all()
                raise
            if result.no_store:
                self._cache.remove(key)
            elif result.rules is not None and result.ttl is not None:
                self._cache.put(
                    key,
                    _CacheEntry(
                        rules=result.rules,
                        stored_wall=now_wall(),
                        expires_wall=now_wall() + (0.0 if result.no_cache else result.ttl),
                        status=result.status or 0,
                        no_cache=result.no_cache,
                    ),
                )
            with self._condition:
                flight.result = result
                self._flights.pop(key, None)
                self._condition.notify_all()
            return self._resolve_result(result, entry, url.target)

    def _failure(self, code: str, outcome: Outcome, status: int | None) -> RobotsDecision:
        return RobotsDecision(
            False,
            code,
            outcome,
            (Evidence(code, EvidenceCategory.OBSERVATION, True, facts=(("status", status or "none"),)),),
            status,
        )

    def _resolve_result(
        self, result: _FetchResult, stale_entry: _CacheEntry | None, target: str
    ) -> RobotsDecision:
        if result.rules is not None:
            entry = _CacheEntry(result.rules, 0.0, 0.0, result.status or 0, result.no_cache)
            return self._evaluate(entry, target, cached=False, stale=False, extra=result.evidence)
        # A freshly observed auth/rate restriction is newer than a stale policy deny. Do not
        # let the old disallow replace the real outcome; no target request is made either way.
        if result.outcome in (Outcome.AUTH_REQUIRED, Outcome.RATE_LIMITED):
            return RobotsDecision(
                False,
                result.reason or "access.robots_unreachable",
                result.outcome,
                result.evidence,
                result.status,
            )
        if stale_entry is not None and not stale_entry.rules.truncated:
            match = stale_entry.rules.match(target)
            if match is not None and not match.allow:
                evidence = (
                    Evidence(
                        "access.robots_stale_deny",
                        EvidenceCategory.OBSERVATION,
                        True,
                        facts=(("status", str(result.status or "none")),),
                    ),
                )
                return RobotsDecision(
                    False,
                    "access.robots_denied",
                    Outcome.BLOCKED,
                    result.evidence + evidence,
                    result.status,
                    cached=True,
                    stale=True,
                )
        return RobotsDecision(
            False,
            result.reason or "access.robots_unreachable",
            result.outcome or Outcome.ERROR,
            result.evidence,
            result.status,
        )

    def _evaluate(
        self,
        entry: _CacheEntry,
        target: str,
        *,
        cached: bool,
        stale: bool,
        extra: Iterable[Evidence] = (),
    ) -> RobotsDecision:
        rules = entry.rules
        match = rules.match(target)
        facts = (
            ("status", str(entry.status)),
            ("cached", "true" if cached else "false"),
            ("stale", "true" if stale else "false"),
        )
        evidence = tuple(extra) + (
            Evidence(
                "access.robots_malformed",
                EvidenceCategory.OBSERVATION,
                rules.malformed,
                facts=(("lines", str(rules.malformed)),),
            ),
        )
        if rules.truncated:
            if match is not None and not match.allow:
                return RobotsDecision(
                    False,
                    "access.robots_denied",
                    Outcome.BLOCKED,
                    evidence
                    + (Evidence("access.robots_truncated", EvidenceCategory.OBSERVATION, True, facts=facts),),
                    entry.status,
                    cached=cached,
                    stale=stale,
                )
            return RobotsDecision(
                False,
                "access.robots_unreachable",
                Outcome.ERROR,
                evidence
                + (Evidence("access.robots_truncated", EvidenceCategory.OBSERVATION, True, facts=facts),),
                entry.status,
                cached=cached,
                stale=stale,
            )
        if match is None or match.allow:
            return RobotsDecision(
                True,
                None,
                None,
                evidence
                + (Evidence("access.robots_allowed", EvidenceCategory.OBSERVATION, True, facts=facts),),
                entry.status,
                cached=cached,
                stale=stale,
            )
        return RobotsDecision(
            False,
            "access.robots_denied",
            Outcome.BLOCKED,
            evidence + (Evidence("access.robots_denied", EvidenceCategory.OBSERVATION, True, facts=facts),),
            entry.status,
            cached=cached,
            stale=stale,
        )

    def _fetch(
        self,
        policy: AcquisitionPolicy,
        admission: Admission,
        fetch: Callable[[], AttemptRecord],
        now_wall: Callable[[], float],
    ) -> _FetchResult:
        # Expected transport/status failures are converted to an AttemptRecord by the
        # adapter. Do not catch arbitrary exceptions here: programming errors and
        # cancellation must propagate rather than become a robots verdict.
        record = fetch()
        source = record.source
        if source is None:
            code = _failure_code(record.reasons)
            outcome = Outcome.RATE_LIMITED if code in ("host.cooldown", "http.rate_limited") else Outcome.ERROR
            return _FetchResult(
                None,
                code,
                outcome,
                (Evidence(code, EvidenceCategory.OBSERVATION, True, facts=(("status", "none"),)),),
                None,
            )
        status = source.status_code
        facts = (("status", str(status)),)
        if 200 <= status < 300 and record.outcome in (
            Outcome.BLOCKED,
            Outcome.AUTH_REQUIRED,
        ):
            code = next(
                (reason for reason in record.reasons if reason.startswith("http.")),
                "access.robots_unreachable",
            )
            return _FetchResult(
                None,
                code,
                record.outcome,
                (
                    Evidence(code, EvidenceCategory.OBSERVATION, True, facts=facts),
                    Evidence(
                        "access.robots_unreachable",
                        EvidenceCategory.OBSERVATION,
                        True,
                        facts=facts,
                    ),
                ),
                status,
            )
        if 200 <= status < 300:
            max_bytes = policy.scheduling.robots_max_bytes
            rules = parse_robots(source.body, max_bytes=max_bytes, product=policy.access.product_token)
            truncated = rules.truncated or not source.complete
            if truncated:
                rules = RobotsRules(rules.rules, True, rules.malformed)
            ttl, no_store, no_cache = _cache_control(source.headers, policy)
            if truncated:
                return _FetchResult(
                    rules,
                    None,
                    None,
                    (
                        Evidence(
                            "access.robots_truncated",
                            EvidenceCategory.OBSERVATION,
                            True,
                            facts=facts + (
                                ("truncated", "true"),
                                ("parsed_rules", str(len(rules.rules))),
                                ("malformed", str(rules.malformed)),
                            ),
                        ),
                    ),
                    status,
                )
            return _FetchResult(
                rules,
                None,
                None,
                (Evidence("access.robots_parsed", EvidenceCategory.OBSERVATION, True, facts=facts),),
                status,
                ttl=ttl,
                no_store=no_store,
                no_cache=no_cache,
            )
        if status in (404, 410):
            ttl, no_store, no_cache = _cache_control(source.headers, policy)
            return _FetchResult(
                RobotsRules(),
                None,
                None,
                (Evidence("access.robots_unavailable", EvidenceCategory.OBSERVATION, True, facts=facts),),
                status,
                ttl=ttl,
                no_store=no_store,
                no_cache=no_cache,
            )
        if status in (401, 403):
            outcome = Outcome.AUTH_REQUIRED if status == 401 else Outcome.BLOCKED
            detail = "http.auth_required" if status == 401 else "http.forbidden"
            return _FetchResult(
                None,
                "access.robots_unreachable",
                outcome,
                (
                    Evidence(detail, EvidenceCategory.OBSERVATION, True, facts=facts),
                    Evidence("access.robots_unreachable", EvidenceCategory.OBSERVATION, True, facts=facts),
                ),
                status,
            )
        if status == 429:
            return _FetchResult(
                None,
                "host.cooldown",
                Outcome.RATE_LIMITED,
                (
                    Evidence("http.rate_limited", EvidenceCategory.OBSERVATION, True, facts=facts),
                    Evidence("host.cooldown", EvidenceCategory.OBSERVATION, True, facts=facts),
                ),
                status,
            )
        if 500 <= status < 600:
            return _FetchResult(
                None,
                "access.robots_unreachable",
                Outcome.ERROR,
                (Evidence("access.robots_unreachable", EvidenceCategory.OBSERVATION, True, facts=facts),),
                status,
            )
        if 300 <= status < 400:
            return _FetchResult(
                None,
                "access.robots_unreachable",
                Outcome.ERROR,
                (Evidence("access.robots_unreachable", EvidenceCategory.OBSERVATION, True, facts=facts),),
                status,
            )
        # Other ordinary 4xx: conservative denial; RFC permits access on an unavailable
        # response but does not require it.
        return _FetchResult(
            None,
            "access.robots_denied",
            Outcome.BLOCKED,
            (Evidence("access.robots_denied", EvidenceCategory.OBSERVATION, True, facts=facts),),
            status,
        )


def _failure_code(reasons: Iterable[str]) -> str:
    values = tuple(reasons)
    for code in ("host.cooldown", "host.circuit_open", "budget.deadline", "budget.requests", "budget.redirects"):
        if code in values:
            return code
    for code in values:
        if code.startswith("safety."):
            return code
    return "access.robots_unreachable"


def parse_robots(
    body: bytes, *, max_bytes: int = DEFAULT_ROBOTS_MAX_BYTES, product: str = "fetchward"
) -> RobotsRules:
    truncated = len(body) > max_bytes
    payload = body[:max_bytes]
    text = payload.decode("utf-8", "replace").lstrip("\ufeff")
    groups: list[tuple[list[str], list[RobotsRule]]] = []
    agents: list[str] = []
    rules: list[RobotsRule] = []
    saw_rule = False
    malformed = 0

    def finish() -> None:
        nonlocal agents, rules, saw_rule
        if agents:
            groups.append((agents, rules))
        agents, rules, saw_rule = [], [], False

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        field, sep, value = line.partition(":")
        if not sep:
            malformed += 1
            continue
        name = field.strip().lower()
        value = value.strip()
        if name == "user-agent":
            if agents and saw_rule:
                finish()
            if not value:
                malformed += 1
                continue
            agents.append(value.casefold())
        elif name in ("allow", "disallow"):
            if not agents:
                malformed += 1
                continue
            saw_rule = True
            if not value:
                continue
            pattern = _normalize_octets(value)
            if not pattern.startswith("/"):
                malformed += 1
                continue
            end_anchor = pattern.endswith("$")
            rule_pattern = pattern[:-1] if end_anchor else pattern
            rules.append(
                RobotsRule(
                    allow=name == "allow",
                    pattern=rule_pattern,
                    length=len(pattern.encode("utf-8")),
                    end_anchor=end_anchor,
                )
            )
        elif name == "crawl-delay":
            # Not an RFC 9309 standard rule; library pacing is separate.
            continue
        else:
            # Unknown extension records are ignored, not errors.
            continue
    finish()

    specific = [
        group for group in groups if any(_agent_matches(agent, product) and agent != "*" for agent in group[0])
    ]
    star = [group for group in groups if any(agent == "*" for agent in group[0])]
    selected = specific or star
    merged: list[RobotsRule] = []
    for _group_agents, group_rules in selected:
        merged.extend(group_rules)
    return RobotsRules(tuple(merged), truncated, malformed)


def _agent_matches(agent: str, product: str) -> bool:
    agent = agent.strip().casefold()
    product = product.casefold()
    return agent == "*" or agent == product or agent.startswith(product + "/")


def _normalize_octets(value: str) -> str:
    """Canonical octet representation for robots paths and patterns.

    Percent escapes for unreserved ASCII are decoded; reserved escapes stay encoded.
    Raw non-ASCII and ASCII characters outside the URL path/query safe set are encoded
    as uppercase UTF-8 octets, so a UTF-8 rule and a percent-encoded target compare equal.
    """
    output: list[str] = []
    index = 0
    while index < len(value):
        if (
            value[index] == "%"
            and index + 2 < len(value)
            and value[index + 1] in _HEX
            and value[index + 2] in _HEX
        ):
            byte = int(value[index + 1 : index + 3], 16)
            if byte < 128 and chr(byte) in _UNRESERVED:
                output.append(chr(byte))
            else:
                output.append(f"%{byte:02X}")
            index += 3
            continue
        char = value[index]
        if ord(char) < 128 and char in _PATH_SAFE:
            output.append(char)
        else:
            output.extend(f"%{byte:02X}" for byte in char.encode("utf-8", "surrogatepass"))
        index += 1
    return "".join(output)


def _cache_control(headers: Headers, policy: AcquisitionPolicy) -> tuple[float, bool, bool]:
    directives = {}
    for value in headers.get_all("cache-control"):
        for directive in value.split(","):
            name, _, argument = directive.strip().partition("=")
            directives[name.strip().lower()] = argument.strip().strip("\"'")
    no_store = "no-store" in directives
    no_cache = "no-cache" in directives
    ttl = policy.scheduling.robots_cache_ttl
    if "max-age" in directives:
        try:
            ttl = max(0.0, float(directives["max-age"]))
        except ValueError:
            ttl = 0.0
    ttl = min(ttl, policy.scheduling.robots_cache_max_ttl)
    return ttl, no_store, no_cache


def _cache_key(url: CanonicalURL, policy: AcquisitionPolicy) -> tuple:
    trusted = tuple(
        (origin.scheme, origin.host, origin.port, origin.addresses)
        for origin in policy.destinations.trusted_local
    )
    return (
        url.scheme,
        url.host,
        url.port,
        policy.access.product_token.casefold(),
        trusted,
        policy.transport.ca_bundle or "",
        policy.scheduling.robots_max_bytes,
        policy.scheduling.robots_cache_ttl,
        policy.scheduling.robots_cache_max_ttl,
    )


_GLOBAL_AUTHORITY = RobotsAuthority()


def _reset_after_fork() -> None:
    global _GLOBAL_AUTHORITY
    # New cache/authority; the parent's cache and inherited lock objects are untouched.
    _GLOBAL_AUTHORITY = RobotsAuthority()


register_child_reset(_reset_after_fork)


def robots_authority() -> RobotsAuthority:
    return _GLOBAL_AUTHORITY


def reset_robots_for_tests() -> None:
    _GLOBAL_AUTHORITY.reset_for_tests()
