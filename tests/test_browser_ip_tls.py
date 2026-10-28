"""HTTPS IP-literal origins: absent SNI for IPs, strict upstream certificate checks."""

from __future__ import annotations

import ssl

import pytest

pytest.importorskip("playwright.sync_api")

from harness import FixtureOrigin, Reply, StaticResolver
from fetchward import (
    AccessPolicy,
    AcquisitionPolicy,
    DestinationPolicy,
    Fetcher,
    Outcome,
    TransportPolicy,
    TrustedOrigin,
)

pytestmark = pytest.mark.browser

HTML = [("Content-Type", "text/html")]


def _policy(origin: FixtureOrigin, ca_bundle: str) -> AcquisitionPolicy:
    return AcquisitionPolicy(
        access=AccessPolicy(mode="user_initiated"),
        destinations=DestinationPolicy(
            trusted_local=(
                TrustedOrigin("https", origin.name, origin.port, ("127.0.0.1",)),
            )
        ),
        transport=TransportPolicy(ca_bundle=ca_bundle),
    )


def test_https_ip_literal_wrong_certificate_is_not_success(ca, ca_bundle) -> None:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ca.issue_cert("127.0.0.2").configure_cert(context)
    origin = FixtureOrigin("127.0.0.1", tls=context)
    try:
        origin.route("/page", Reply(200, HTML, b"<html>wrong</html>"))
        fetcher = Fetcher(
            _policy(origin, ca_bundle),
            _resolver=StaticResolver({"127.0.0.1": ("127.0.0.1",)}),
        )
        result = fetcher.fetch(
            f"https://127.0.0.1:{origin.port}/page", mode="browser", timeout=15
        )
        assert result.outcome is not Outcome.SUCCESS
        assert origin.log.paths() == []
    finally:
        origin.close()
