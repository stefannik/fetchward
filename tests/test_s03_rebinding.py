"""S03: connection-level destination binding for the direct HTTP adapter (scenario).

Permitted destination: 127.0.0.1:P via an explicit trusted-local allowance. Forbidden
destination: [::1]:P (same port), watched by a raw TCP ConnectionObserver. DNS comes from a
loopback fixture server through the production c-ares resolver. Every scenario has a
control that removes the protection under test and must show the observer being reached;
otherwise "zero contacts" would not prove anything. The rebinding scenario uses a stable control endpoint.
"""

from __future__ import annotations

import ssl

import pytest

from harness import ConnectionObserver, DNSFixtureServer, FixtureOrigin, Reply
from fetchward import AccessPolicy, AcquisitionPolicy, DestinationPolicy, Fetcher, Outcome, TransportPolicy
from fetchward._dns import CaresResolver

HTML = [("Content-Type", "text/html")]


def rebinding(first: str = "127.0.0.1", then: str = "::1"):
    """First lookup answers ``first``; every later lookup answers ``then`` (per query type)."""
    seen: dict[int, int] = {}

    def respond(qname: str, qtype: int) -> tuple[str, ...]:
        seen[qtype] = seen.get(qtype, 0) + 1
        return (first,) if seen[qtype] == 1 else (then,)

    return respond


@pytest.fixture
def target():
    """A permitted HTTP origin on 127.0.0.1:P and a forbidden observer on [::1]:P."""
    for _ in range(20):
        origin = FixtureOrigin("rebind.test")
        try:
            observer = ConnectionObserver("::1", origin.port)
            break
        except OSError:
            origin.close()
    else:  # pragma: no cover
        pytest.skip("could not pair 127.0.0.1 and ::1 on one port")
    yield origin, observer
    observer.close()
    origin.close()


@pytest.fixture
def dns():
    servers: list[DNSFixtureServer] = []

    def make(**kwargs) -> DNSFixtureServer:
        server = DNSFixtureServer(**kwargs)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def fetcher_for(origin: FixtureOrigin, dns_server: DNSFixtureServer, *, ca_bundle: str | None = None, trusted=None) -> Fetcher:
    policy = AcquisitionPolicy(
        access=AccessPolicy(mode="user_initiated"),
        destinations=DestinationPolicy(trusted_local=trusted if trusted is not None else (origin.trusted(),)),
        transport=TransportPolicy(ca_bundle=ca_bundle),
    )
    return Fetcher(policy, _resolver=CaresResolver([dns_server.address], attempt_timeout=0.5, tries=2))


def unpinned_curl(monkeypatch, dns_server: DNSFixtureServer) -> None:
    """Control: drop the RESOLVE pin and let curl's own resolver query the fixture DNS."""
    import curl_cffi
    from curl_cffi import CurlOpt

    real = curl_cffi.Curl

    class Unpinned(real):
        def setopt(self, option, value):
            if option == CurlOpt.RESOLVE:
                return super().setopt(CurlOpt.DNS_SERVERS, dns_server.address.encode())
            return super().setopt(option, value)

    monkeypatch.setattr(curl_cffi, "Curl", Unpinned)


# -- S03-a: answers flip between validation and connection ---------------------------------------
def test_s03a_rebind_after_validation_never_reaches_forbidden_address(target, dns) -> None:
    origin, forbidden = target
    server = dns(responder=rebinding())
    origin.route("/", Reply(200, HTML, b"<html>pinned</html>"))
    result = fetcher_for(origin, server).fetch(origin.url("/"), mode="http")
    assert result.ok and result.html == "<html>pinned</html>"
    assert len(forbidden) == 0
    assert origin.log.paths() == ["/"]
    (event,) = [e for e in result.attempts[0].requests if e.admitted]
    assert event.pinned_address == event.connected_address == "127.0.0.1"
    assert len(server.packets) == 2  # one A + one AAAA: the validator's lookup only; curl never resolved


def test_s03a_control_unpinned_connection_reaches_forbidden_address(target, dns, monkeypatch) -> None:
    origin, forbidden = target
    server = dns(responder=rebinding())
    origin.route("/", Reply(200, HTML, b"<html>pinned</html>"))
    unpinned_curl(monkeypatch, server)
    result = fetcher_for(origin, server).fetch(origin.url("/"), mode="http")
    assert len(forbidden) >= 1  # the harness detects a rebinding connection when pinning is absent
    # The after-the-fact peer check still refuses the response, but only after the contact.
    assert result.outcome is Outcome.ERROR and result.response_body is None
    assert any(e.code == "safety.connection_mismatch" for e in result.diagnostics.evidence)


# -- S03-b: every redirect hop is re-resolved and revalidated ---------------------------------------
def test_s03b_rebind_between_redirect_hops_is_rejected(target, dns) -> None:
    origin, forbidden = target
    server = dns(responder=rebinding())
    origin.route("/start", Reply(302, [("Location", "/next")]))
    origin.route("/next", Reply(200, HTML, b"<html>should not be fetched</html>"))
    result = fetcher_for(origin, server).fetch(origin.url("/start"), mode="http")
    assert result.outcome is Outcome.ERROR
    assert result.attempts[0].reasons[-1] == "safety.destination_rejected"
    assert origin.log.paths() == ["/start"] and len(forbidden) == 0
    assert len(server.packets) == 4  # two lookups (A + AAAA each): the second hop was re-resolved


# -- S03-c: a mixed answer set is rejected as a whole ---------------------------------------------
def test_s03c_mixed_trusted_and_forbidden_answers_rejected(target, dns) -> None:
    origin, forbidden = target
    server = dns(responder=lambda qname, qtype: ("127.0.0.1", "::1"))
    origin.route("/", Reply(200, HTML, b"x"))
    result = fetcher_for(origin, server).fetch(origin.url("/"), mode="http")
    assert result.attempts[0].reasons == ("safety.destination_rejected",)
    assert len(origin.log) == 0 and len(forbidden) == 0
    assert result.diagnostics.budget.requests == 0


def test_s03c_mixed_public_and_loopback_answers_rejected_at_guard(dns) -> None:
    """Public-policy case checked at the real-DNS/guard boundary only.

    A public address must never reach an HTTP connection path in tests: if a regression
    filtered answers instead of rejecting the set, the fetcher would dial the public IP.
    """
    from fetchward._safety import DestinationGuard, SafetyRejection, canonicalize

    server = dns(responder=lambda qname, qtype: ("93.184.215.14", "::1"))
    guard = DestinationGuard(DestinationPolicy(), CaresResolver([server.address], attempt_timeout=0.5, tries=2))
    with pytest.raises(SafetyRejection) as info:
        guard.check(canonicalize("http://mixed.test/"), 2)
    assert info.value.code == "safety.destination_rejected"
    assert {name for _, name in server.packets} == {"mixed.test"}  # answers came from real DNS


# -- S03-d: no connection reuse; each request is a validated new connection ---------------------------
def test_s03d_each_request_uses_a_new_connection_after_its_own_lookup(target, dns) -> None:
    origin, forbidden = target
    server = dns(responder=lambda qname, qtype: ("127.0.0.1",))
    origin.route("/a", Reply(302, [("Location", "/b")]))
    origin.route("/b", Reply(200, HTML, b"<html>b</html>"))
    result = fetcher_for(origin, server).fetch(origin.url("/a"), mode="http")
    assert result.ok
    ports = [r.client_port for r in origin.log.requests]
    assert len(ports) == 2 and len(set(ports)) == 2  # distinct TCP connections
    assert len(server.packets) == 4  # a fresh lookup preceded each connection
    assert len(forbidden) == 0


# -- S03-e: proxy environment variables cannot redirect egress -------------------------------------------
PROXY_VARS = ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")


def _set_proxy_env(monkeypatch, proxy: ConnectionObserver) -> None:
    for name in PROXY_VARS:
        monkeypatch.setenv(name, f"http://127.0.0.1:{proxy.port}")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)


@pytest.mark.parametrize("which", ["a", "tls"])
def test_s03e_proxy_environment_is_ignored(make_fetcher, origins, monkeypatch, which) -> None:
    proxy = ConnectionObserver("127.0.0.1")
    try:
        _set_proxy_env(monkeypatch, proxy)
        origins[which].route("/", Reply(200, HTML, b"<html>direct</html>"))
        result = make_fetcher().fetch(origins[which].url("/"), mode="http")
        assert result.ok and result.html == "<html>direct</html>"
        assert len(proxy) == 0 and len(origins[which].log) == 1
    finally:
        proxy.close()


def test_s03e_control_without_proxy_override_uses_environment_proxy(make_fetcher, origins, monkeypatch) -> None:
    import curl_cffi
    from curl_cffi import CurlOpt

    proxy = ConnectionObserver("127.0.0.1")
    real = curl_cffi.Curl

    class HonoursEnv(real):
        def setopt(self, option, value):
            if option in (CurlOpt.PROXY, CurlOpt.NOPROXY):
                return 0  # control: leave libcurl's environment-proxy behaviour in place
            return super().setopt(option, value)

    try:
        _set_proxy_env(monkeypatch, proxy)
        monkeypatch.setattr(curl_cffi, "Curl", HonoursEnv)
        origins["a"].route("/", Reply(200, HTML, b"x"))
        make_fetcher().fetch(origins["a"].url("/"), mode="http")
        assert len(proxy) >= 1  # libcurl does read proxy env vars; the override is what blocks it
        assert len(origins["a"].log) == 0
    finally:
        proxy.close()


# -- S03-f: pinning keeps hostname TLS verification -------------------------------------------------------
@pytest.fixture
def wrong_name_origin(ca):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ca.issue_cert("other.test").configure_cert(context)  # valid chain, wrong name
    origin = FixtureOrigin("pinned-tls.test", tls=context)
    origin.route("/", Reply(200, HTML, b"<html>wrong name</html>"))
    yield origin
    origin.close()


def test_s03f_pinned_https_still_verifies_hostname(wrong_name_origin, dns, ca_bundle) -> None:
    server = dns(responder=lambda qname, qtype: ("127.0.0.1",))
    result = fetcher_for(wrong_name_origin, server, ca_bundle=ca_bundle).fetch(wrong_name_origin.url("/"), mode="http")
    assert result.outcome is Outcome.ERROR and result.response_body is None
    assert "network.tls" in result.attempts[0].reasons
    assert len(wrong_name_origin.log) == 0


def test_s03f_control_hostname_check_disabled_accepts_wrong_name(wrong_name_origin, dns, ca_bundle, monkeypatch) -> None:
    import curl_cffi
    from curl_cffi import CurlOpt

    real = curl_cffi.Curl

    class NoHostCheck(real):
        def setopt(self, option, value):
            if option == CurlOpt.SSL_VERIFYHOST:
                value = 0
            return super().setopt(option, value)

    monkeypatch.setattr(curl_cffi, "Curl", NoHostCheck)
    server = dns(responder=lambda qname, qtype: ("127.0.0.1",))
    result = fetcher_for(wrong_name_origin, server, ca_bundle=ca_bundle).fetch(wrong_name_origin.url("/"), mode="http")
    assert result.ok  # the fixture really presents a wrong-name certificate on a trusted chain
