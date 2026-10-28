"""Public behavior of the native HTTP engine: Chrome impersonation, HTTP/2 and the UA policy."""

from __future__ import annotations

import gzip
import sys
import ssl

import pytest

pytest.importorskip("h2")

from harness import Reply, StaticResolver  # noqa: E402
from harness.h2origin import H2Origin  # noqa: E402
from fetchward import (  # noqa: E402
    AccessPolicy,
    AcquisitionPolicy,
    DestinationPolicy,
    Fetcher,
    Outcome,
    TransportPolicy,
    TrustedOrigin,
)

HTML = "text/html"


@pytest.fixture(scope="module")
def h2origin(ca):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ca.issue_cert("h2.test").configure_cert(context)
    origin = H2Origin("h2.test", context)
    origin.route("/", 200, [("content-type", HTML)], b"<html><body>h2</body></html>")
    origin.route(
        "/gz",
        200,
        [("content-type", HTML), ("content-encoding", "gzip")],
        gzip.compress(b"<html>compressed over h2</html>"),
    )
    yield origin
    origin.close()


def _h2_fetcher(origin: H2Origin, ca_bundle: str) -> Fetcher:
    policy = AcquisitionPolicy(
        destinations=DestinationPolicy(
            trusted_local=(TrustedOrigin("https", origin.name, origin.port, ("127.0.0.1",)),)
        ),
        transport=TransportPolicy(ca_bundle=ca_bundle),
    )
    return Fetcher(policy, _resolver=StaticResolver({origin.name: ("127.0.0.1",)}))


def test_http2_tls_fetch_succeeds_and_records_impersonation(h2origin, ca_bundle) -> None:
    h2origin.reset()
    result = _h2_fetcher(h2origin, ca_bundle).fetch(h2origin.url("/"), mode="http", timeout=10)
    assert result.ok and result.status_code == 200
    assert result.html == "<html><body>h2</body></html>"
    assert [alpn for _, alpn in h2origin.connections] == ["h2"]
    assert [request.path for request in h2origin.snapshot()] == ["/"]
    backend_version = result.attempts[0].backend_version
    assert backend_version.startswith("curl_cffi/") and backend_version.endswith("chrome152")


def test_http2_encoded_body_is_decoded_and_reported(h2origin, ca_bundle) -> None:
    h2origin.reset()
    result = _h2_fetcher(h2origin, ca_bundle).fetch(h2origin.url("/gz"), mode="http", timeout=10)
    assert result.ok
    assert result.response_body == b"<html>compressed over h2</html>"
    assert result.encoding is not None
    assert result.encoding.content_encoding == ("gzip",) and result.encoding.content_decoded


def test_default_user_agent_is_chrome_without_product_token(make_fetcher, origins) -> None:
    origins["tls"].route("/page", Reply(200, [("Content-Type", HTML)], b"<html>ua</html>"))
    result = make_fetcher().fetch(origins["tls"].url("/page"), mode="http")
    assert result.ok
    user_agent = origins["tls"].log.requests[0].headers["user-agent"]
    assert "Chrome/" in user_agent and "Safari/537.36" in user_agent
    assert "fetchward" not in user_agent
    # Impersonation's own default headers must reach the receiver untouched.
    headers = origins["tls"].log.requests[0].headers
    assert headers["accept"].startswith("text/html")
    assert "sec-ch-ua" in headers and "accept-language" in headers


def test_automated_mode_appends_the_product_token(make_fetcher, origins) -> None:
    origin = origins["tls"]
    origin.route("/robots.txt", Reply(200, [("Content-Type", "text/plain")], b"User-agent: *\nAllow: /\n"))
    origin.route("/page", Reply(200, [("Content-Type", HTML)], b"<html>ua</html>"))
    result = make_fetcher(access=AccessPolicy(mode="automated")).fetch(
        origin.url("/page"), mode="http"
    )
    assert result.ok
    seen = {request.path: request.headers["user-agent"] for request in origin.log.requests}
    for path in ("/robots.txt", "/page"):
        assert "Chrome/" in seen[path] and "fetchward" in seen[path]


def test_configured_user_agent_is_sent_as_given(make_fetcher, origins, ca_bundle) -> None:
    origins["tls"].route("/page", Reply(200, [("Content-Type", HTML)], b"<html>ua</html>"))
    fetcher = make_fetcher(
        transport=TransportPolicy(ca_bundle=ca_bundle, user_agent="CustomAgent/1.0")
    )
    result = fetcher.fetch(origins["tls"].url("/page"), mode="http")
    assert result.ok
    assert origins["tls"].log.requests[0].headers["user-agent"] == "CustomAgent/1.0"


def test_missing_curl_cffi_is_backend_unavailable_without_contact(
    make_fetcher, origins, monkeypatch
) -> None:
    monkeypatch.setitem(sys.modules, "curl_cffi", None)
    result = make_fetcher().fetch(origins["a"].url("/"), mode="http")
    assert result.outcome is Outcome.ERROR
    assert result.diagnostics.stop_reason == "backend.unavailable"
    assert origins["a"].log.paths() == []
