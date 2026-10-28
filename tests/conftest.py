from __future__ import annotations

import ssl
from collections.abc import Iterator

import pytest
import trustme

from harness import FixtureOrigin, StaticResolver
from fetchward import AccessPolicy, AcquisitionPolicy, DestinationPolicy, Fetcher, TransportPolicy

FIXTURE_NAMES = ("origin-a.test", "origin-b.test", "forbidden.test")


@pytest.fixture(autouse=True)
def _isolated_process_safety():
    from fetchward._robots import reset_robots_for_tests
    from fetchward._safety_runtime import reset_process_safety_for_tests

    reset_process_safety_for_tests()
    reset_robots_for_tests()
    yield
    reset_process_safety_for_tests()
    reset_robots_for_tests()


@pytest.fixture(scope="session")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(scope="session")
def ca_bundle(ca: trustme.CA, tmp_path_factory: pytest.TempPathFactory) -> str:
    path = tmp_path_factory.mktemp("ca") / "fixture-ca.pem"
    ca.cert_pem.write_to_path(str(path))
    return str(path)


@pytest.fixture(scope="session")
def tls_context(ca: trustme.CA) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ca.issue_cert(*FIXTURE_NAMES, "127.0.0.1").configure_cert(context)
    return context


@pytest.fixture(scope="session")
def _servers(tls_context: ssl.SSLContext) -> Iterator[dict[str, FixtureOrigin]]:
    created = {
        "a": FixtureOrigin("origin-a.test"),
        "b": FixtureOrigin("origin-b.test"),
        "tls": FixtureOrigin("origin-a.test", tls=tls_context),
        "forbidden": FixtureOrigin("forbidden.test"),
    }
    yield created
    for origin in created.values():
        origin.close()


@pytest.fixture
def origins(_servers: dict[str, FixtureOrigin]) -> dict[str, FixtureOrigin]:
    """Long-lived servers with routes and receiver logs reset for every test."""
    for origin in _servers.values():
        origin.reset()
    return _servers


@pytest.fixture
def resolver() -> StaticResolver:
    return StaticResolver({name: ("127.0.0.1",) for name in FIXTURE_NAMES})


@pytest.fixture
def make_fetcher(origins: dict[str, FixtureOrigin], resolver: StaticResolver, ca_bundle: str):
    """A fetcher trusting the named fixture origins (never ``forbidden``) unless told otherwise."""

    def build(*, trust: tuple[str, ...] = ("a", "b", "tls"), extra_trust=(), policy: AcquisitionPolicy | None = None, session=None, cache=None, profile=None, **overrides) -> Fetcher:
        base = policy or AcquisitionPolicy()
        trusted = tuple(origins[key].trusted() for key in trust) + tuple(extra_trust)
        fields = {
            "access": AccessPolicy(mode="user_initiated"),
            "destinations": DestinationPolicy(trusted_local=trusted),
            "transport": TransportPolicy(ca_bundle=ca_bundle),
            "budgets": base.budgets,
            "readiness": base.readiness,
            "scheduling": base.scheduling,
        }
        fields.update(overrides)
        return Fetcher(AcquisitionPolicy(**fields), session=session, cache=cache, profile=profile, _resolver=resolver)

    return build
