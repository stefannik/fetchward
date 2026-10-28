"""Regression tests for review findings."""

from __future__ import annotations

import threading
import time

import pytest

from harness import Reply
from fetchward import AcquisitionPolicy, Budgets, Outcome
from fetchward._admission import Admission, SystemClock

HTML = [("Content-Type", "text/html")]


# -- Finding 1: DNS resolution is bounded by the acquisition deadline ------------------------
def test_slow_dns_returns_within_deadline(make_fetcher, origins, resolver) -> None:
    origins["a"].route("/", Reply(200, HTML, b"<html>x</html>"))
    resolver.delay = 0.3
    fetcher = make_fetcher()
    started = time.monotonic()
    result = fetcher.fetch(origins["a"].url("/"), mode="http", timeout=0.05)
    elapsed = time.monotonic() - started
    assert elapsed < 0.2, elapsed
    assert result.outcome is Outcome.ERROR
    assert result.attempts[0].reasons == ("budget.deadline",)
    assert result.diagnostics.budget.requests == 0
    assert len(origins["a"].log) == 0


def test_dns_within_deadline_still_works(make_fetcher, origins, resolver) -> None:
    origins["a"].route("/", Reply(200, HTML, b"<html>x</html>"))
    resolver.delay = 0.05
    assert make_fetcher().fetch(origins["a"].url("/"), mode="http", timeout=5).ok


# -- Finding 2: total retained-byte ceiling ----------------------------------------------------
def _policy(**budgets) -> AcquisitionPolicy:
    return AcquisitionPolicy(budgets=Budgets(**budgets))


def test_total_byte_ceiling_truncates_to_partial(make_fetcher, origins) -> None:
    origins["a"].route("/big", Reply(200, HTML, b"z" * 100))
    result = make_fetcher(policy=_policy(max_total_bytes=8)).fetch(origins["a"].url("/big"), mode="http")
    assert result.outcome is Outcome.PARTIAL
    assert result.response_body == b"z" * 8
    assert result.attempts[0].source.interruption == "budget.bytes"
    assert "budget.bytes" in result.diagnostics.budget.exhausted
    assert result.diagnostics.budget.retained_bytes == 8


@pytest.mark.parametrize("size,outcome", [(7, Outcome.SUCCESS), (8, Outcome.SUCCESS), (9, Outcome.PARTIAL)])
def test_total_byte_ceiling_boundary(make_fetcher, origins, size, outcome) -> None:
    origins["a"].route("/b", Reply(200, HTML, b"q" * size))
    result = make_fetcher(policy=_policy(max_total_bytes=8)).fetch(origins["a"].url("/b"), mode="http")
    assert result.outcome is outcome and len(result.response_body) == min(size, 8)


def test_smaller_of_source_and_total_ceiling_applies(make_fetcher, origins) -> None:
    origins["a"].route("/b", Reply(200, HTML, b"q" * 100))
    result = make_fetcher(policy=_policy(max_source_bytes=5, max_total_bytes=50)).fetch(origins["a"].url("/b"), mode="http")
    assert len(result.response_body) == 5


def test_later_attempt_cannot_exceed_bytes_already_retained(make_fetcher, origins, resolver) -> None:
    """A second attempt in the same acquisition sees only the remaining allowance."""
    from fetchward._http_curl import CurlHTTPAdapter
    from fetchward._safety import DestinationGuard, canonicalize

    origins["a"].route("/b", Reply(200, HTML, b"q" * 100))
    fetcher = make_fetcher(policy=_policy(max_total_bytes=30))
    policy = fetcher.policy
    admission = Admission(policy.budgets, 5, SystemClock())
    adapter = CurlHTTPAdapter(policy, DestinationGuard(policy.destinations, resolver))
    first = adapter.run("x1", canonicalize(origins["a"].url("/b")), admission, 0.0)
    assert len(first.source.body) == 30
    second = adapter.run("x2", canonicalize(origins["a"].url("/b")), admission, 0.0)
    assert second.source is None and second.reasons == ("budget.bytes",)
    assert origins["a"].log.paths() == ["/b"]  # no request was dispatched for the second attempt


# -- Finding 3: server-declared charsets cannot select non-text codecs ---------------------------
@pytest.mark.parametrize("codec", ["base64_codec", "rot13", "hex", "zlib_codec", "idna", "utf-7"])
def test_transport_non_text_charset_is_ignored(make_fetcher, origins, codec) -> None:
    origins["a"].route("/c", Reply(200, [("Content-Type", f"text/html; charset={codec}")], "<html>é</html>".encode()))
    result = make_fetcher().fetch(origins["a"].url("/c"), mode="http")
    assert result.ok and result.html == "<html>é</html>"
    assert result.encoding.source == "fallback" and "transport_charset_unknown" in result.encoding.conflicts


@pytest.mark.parametrize("codec", ["base64_codec", "rot13", "uu_codec"])
def test_meta_non_text_charset_is_ignored(make_fetcher, origins, codec) -> None:
    body = f'<html><meta charset="{codec}">é</html>'.encode()
    origins["a"].route("/m", Reply(200, HTML, body))
    result = make_fetcher().fetch(origins["a"].url("/m"), mode="http")
    assert result.ok and "é" in result.html
    assert result.encoding.source == "fallback" and "meta_charset_unknown" in result.encoding.conflicts


# -- Finding 4: a response without an observed peer address fails closed ---------------------------
def test_response_without_observed_peer_is_rejected(make_fetcher, origins, monkeypatch) -> None:
    from fetchward import _http_curl

    original = _http_curl.CurlHTTPAdapter._perform

    def without_peer(self, *args, **kwargs):
        response = original(self, *args, **kwargs)
        response.connected_address = None
        return response

    monkeypatch.setattr(_http_curl.CurlHTTPAdapter, "_perform", without_peer)
    origins["a"].route("/p", Reply(200, HTML, b"<html>unverified</html>"))
    result = make_fetcher().fetch(origins["a"].url("/p"), mode="http")
    assert result.outcome is Outcome.ERROR and result.response_body is None
    assert result.attempts[0].reasons == ("safety.destination_rejected",)
    assert any(e.code == "safety.connection_unverified" for e in result.diagnostics.evidence)


def test_connect_failure_without_peer_keeps_network_reason(make_fetcher) -> None:
    from harness import FixtureOrigin

    dead = FixtureOrigin("origin-b.test")
    url = dead.url("/")
    dead.close()
    result = make_fetcher(extra_trust=(dead.trusted(),)).fetch(url, mode="http")
    assert result.attempts[0].reasons == ("network.connect",)


# -- Re-review rounds 1-2: DNS stops at the deadline, observed from outside the resolver --------
# The production resolver (c-ares) is pointed at a UDP fixture server that logs every packet.
def _cares_fetcher(dns, origins, ca_bundle, **policy):
    from fetchward import AccessPolicy, DestinationPolicy, Fetcher, TransportPolicy
    from fetchward._dns import CaresResolver

    policy = AcquisitionPolicy(
        access=AccessPolicy(mode="user_initiated"),
        destinations=DestinationPolicy(trusted_local=(origins["a"].trusted(),)),
        transport=TransportPolicy(ca_bundle=ca_bundle),
        **policy,
    )
    return Fetcher(policy, _resolver=CaresResolver([dns.address], attempt_timeout=0.1, tries=10))


@pytest.fixture
def dns_server():
    from harness import DNSFixtureServer

    servers = []

    def make(**kwargs):
        server = DNSFixtureServer(**kwargs)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def test_real_resolver_path_end_to_end(dns_server, origins, ca_bundle) -> None:
    dns = dns_server(records={"origin-a.test": ("127.0.0.1",)})
    origins["a"].route("/", Reply(200, HTML, b"<html>via c-ares</html>"))
    result = _cares_fetcher(dns, origins, ca_bundle).fetch(origins["a"].url("/"), mode="http")
    assert result.ok and result.html == "<html>via c-ares</html>"
    assert {name for _, name in dns.packets} == {"origin-a.test"}


def test_real_resolver_nxdomain_is_dns_error(dns_server, origins, ca_bundle) -> None:
    dns = dns_server(records={})
    result = _cares_fetcher(dns, origins, ca_bundle).fetch(origins["a"].url("/"), mode="http")
    assert result.attempts[0].reasons == ("network.dns",)
    assert len(origins["a"].log) == 0


def test_no_resolver_traffic_after_deadline(dns_server, origins, ca_bundle) -> None:
    """A resolver that is retrying when the deadline hits must send nothing afterwards."""
    import os
    import threading

    dns = dns_server(blackhole=True)
    fetcher = _cares_fetcher(dns, origins, ca_bundle)
    open_fds = len(os.listdir("/dev/fd"))
    threads_before = {t.ident for t in threading.enumerate()}
    started = time.monotonic()
    result = fetcher.fetch(origins["a"].url("/"), mode="http", timeout=0.4)
    returned = time.monotonic()
    assert returned - started < 0.6
    assert result.attempts[0].reasons == ("budget.deadline",)
    assert dns.packets_after(0) >= 2  # it really was retrying before the deadline
    time.sleep(1.5)  # > many retry intervals (0.1 s each, 10 tries)
    assert dns.packets_after(started + 0.4 + _SEND_TOLERANCE) == 0  # nothing after the deadline
    assert dns.packets_after(returned) == 0
    assert len(os.listdir("/dev/fd")) <= open_fds  # resolver socket closed before return
    extra = [t for t in threading.enumerate() if t.ident not in threads_before and t.is_alive()]
    # pycares may start its daemon channel-destruction thread; nothing else may appear.
    assert all(t.daemon and "shutdown" in t.name for t in extra), [t.name for t in extra]
    assert len(origins["a"].log) == 0


class _HookedSelector:
    """Wraps the real selector so a test can delay, interrupt or rewrite a wait's result."""

    def __init__(self, real, hook, transform=None) -> None:
        self._real, self._hook, self._transform = real, hook, transform

    def select(self, timeout=None):
        ready = self._real.select(timeout)
        self._hook(timeout)
        return self._transform(ready) if self._transform else ready

    def __getattr__(self, name):
        return getattr(self._real, name)


def _hook_selector(monkeypatch, hook, transform=None) -> None:
    """Apply ``hook`` after every wait: selector waits and the no-socket sleep path alike."""
    import selectors

    from fetchward import _dns

    real_factory = selectors.DefaultSelector
    real_sleep = _dns._sleep
    monkeypatch.setattr(
        "fetchward._dns.selectors.DefaultSelector", lambda: _HookedSelector(real_factory(), hook, transform)
    )

    def hooked_sleep(seconds):
        ready = real_sleep(seconds)
        hook(seconds)
        return ready

    monkeypatch.setattr("fetchward._dns._sleep", hooked_sleep)


def _record_drives(
    monkeypatch,
    delay_after_first_fd_drive: float = 0.0,
    *,
    interrupt_after_packet_event=None,
    closed_event=None,
):
    """Replace pycares.Channel with a subclass logging each process_fd as (start, real-fd?).

    ``interrupt_after_packet_event`` blocks the first real-socket drive until the DNS
    observer has actually received the initial query, then raises KeyboardInterrupt. This
    avoids depending on native retry scheduling or a fixed drive count. ``closed_event`` is
    set when the resolver's channel close runs.
    """
    import pycares

    drives: list[tuple[float, bool]] = []
    completed: list[float] = []
    real_channel = pycares.Channel

    class RecordingChannel(real_channel):
        def getaddrinfo(self, *args, callback, **kwargs):
            def recording(result, error):
                completed.append(time.monotonic())
                callback(result, error)

            return super().getaddrinfo(*args, callback=recording, **kwargs)

        def process_fd(self, read_fd, write_fd):
            real_fd = read_fd != pycares.ARES_SOCKET_BAD or write_fd != pycares.ARES_SOCKET_BAD
            drives.append((time.monotonic(), real_fd))
            super().process_fd(read_fd, write_fd)
            if interrupt_after_packet_event is not None and len(drives) == 1:
                if not interrupt_after_packet_event.wait(2.0):
                    raise AssertionError("initial DNS query was not observed")
                raise KeyboardInterrupt
            if real_fd and sum(1 for _, fd in drives if fd) == 1 and delay_after_first_fd_drive:
                time.sleep(delay_after_first_fd_drive)  # processing/scheduling overrun inside a batch

        def close(self):
            if closed_event is not None:
                closed_event.set()
            return super().close()

    monkeypatch.setattr("fetchward._dns.pycares.Channel", RecordingChannel)
    return drives, completed


def test_interrupt_during_lookup_cancels_resolver(dns_server, monkeypatch) -> None:
    from fetchward._dns import CaresResolver

    dns = dns_server(blackhole=True)
    closed = threading.Event()
    drives, _ = _record_drives(
        monkeypatch,
        interrupt_after_packet_event=dns.packet_event,
        closed_event=closed,
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            CaresResolver([dns.address], attempt_timeout=0.05, tries=20).resolve("x.test", 80, 5)
    except BaseException as exc:
        pytest.fail(f"unexpected {type(exc).__name__}: drives={drives!r} packets={dns.packets!r}")
    interrupted = time.monotonic()
    assert len(drives) == 1
    assert closed.wait(1.0)
    time.sleep(0.5)
    assert dns.packets_after(interrupted) == 0
    assert dns.packets, "initial DNS query was not observed by the receiver"


# --  no query between the deadline and the return; high descriptors ----------
_SEND_TOLERANCE = 0.02  # observer stamps on receipt; allow loopback delivery latency


def test_delayed_wakeup_sends_nothing_after_deadline(dns_server, monkeypatch) -> None:
    """A scheduler overrun past the deadline must not let c-ares fire due retry timers."""
    from fetchward._dns import CaresResolver
    from fetchward._safety import DNSTimeout

    dns = dns_server(blackhole=True)
    _hook_selector(monkeypatch, lambda _timeout: time.sleep(0.2))  # every wake-up is 0.2 s late
    started = time.monotonic()
    with pytest.raises(DNSTimeout):
        CaresResolver([dns.address], attempt_timeout=0.1, tries=10).resolve("x.test", 80, 0.15)
    deadline = started + 0.15
    time.sleep(0.5)
    assert dns.packets_after(0) >= 1  # the initial queries were sent
    assert dns.packets_after(deadline + _SEND_TOLERANCE) == 0


def test_no_packets_between_deadline_and_return_through_fetch(dns_server, origins, ca_bundle) -> None:
    dns = dns_server(blackhole=True)
    fetcher = _cares_fetcher(dns, origins, ca_bundle)
    started = time.monotonic()
    result = fetcher.fetch(origins["a"].url("/"), mode="http", timeout=0.35)
    assert result.attempts[0].reasons == ("budget.deadline",)
    time.sleep(0.5)
    assert dns.packets_after(started + 0.35 + _SEND_TOLERANCE) == 0


def test_resolver_sockets_above_fd_setsize(dns_server, origins, ca_bundle) -> None:
    """select() cannot watch descriptors >= FD_SETSIZE (1024); resolution must still work."""
    import os
    import resource

    dns = dns_server(records={"origin-a.test": ("127.0.0.1",)})
    origins["a"].route("/", Reply(200, HTML, b"<html>high fd</html>"))
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = 1100
    if hard != resource.RLIM_INFINITY and hard < target + 64:
        pytest.skip(f"hard descriptor limit {hard} too low")
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, target + 64), hard))
    held = []
    try:
        base = os.open(os.devnull, os.O_RDONLY)
        held.append(base)
        while held[-1] < target:
            held.append(os.dup(base))
        result = _cares_fetcher(dns, origins, ca_bundle).fetch(origins["a"].url("/"), mode="http")
        assert result.ok and result.html == "<html>high fd</html>"
        assert dns.packets  # the resolver really ran on a descriptor above the select() limit
    finally:
        for fd in held:
            os.close(fd)
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


_SHUTDOWN_SCRIPT = r"""
import sys, time
from harness import DNSFixtureServer
from fetchward import AccessPolicy, AcquisitionPolicy, DestinationPolicy, Fetcher, TrustedOrigin
from fetchward._dns import CaresResolver

dns = DNSFixtureServer(blackhole=True)
policy = AcquisitionPolicy(
    access=AccessPolicy(mode="user_initiated"),
    destinations=DestinationPolicy(trusted_local=(TrustedOrigin("http", "origin-a.test", 9, ("127.0.0.1",)),)),
)
fetcher = Fetcher(policy, _resolver=CaresResolver([dns.address], attempt_timeout=0.1, tries=50))
started = time.monotonic()
result = fetcher.fetch("http://origin-a.test:9/", mode="http", timeout=0.3)
print(result.outcome.value, result.attempts[0].reasons[0], round(time.monotonic() - started, 3), flush=True)
"""


def test_deadline_lookup_does_not_block_interpreter_exit(tmp_path) -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path

    script = tmp_path / "shutdown_probe.py"
    script.write_text(_SHUTDOWN_SCRIPT)
    env = dict(
        os.environ,
        PYTHONPATH=os.pathsep.join(
            (str(Path(__file__).resolve().parents[1] / "src"), str(Path(__file__).parent))
        ),
    )
    started = time.monotonic()
    proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=20, env=env)
    total = time.monotonic() - started
    assert proc.returncode == 0, proc.stderr
    outcome, reason, fetch_elapsed = proc.stdout.split()
    assert (outcome, reason) == ("error", "budget.deadline")
    assert float(fetch_elapsed) < 0.5
    assert total < 5, total


# -- Re-review round 1 finding 2: valid web charset labels map to their standard encodings ------------------
_LABEL_CASES = [
    ("gb2312", "中文网页", "gb18030"),
    ("GBK", "中文网页", "gb18030"),
    ("iso-8859-9", "İstanbul Şehri", "cp1254"),
    ("latin5", "İstanbul Şehri", "cp1254"),
    ("shift_jis", "日本語ページ", "cp932"),
    ("euc-kr", "한국어 페이지", "cp949"),
    ("ks_c_5601-1987", "한국어 페이지", "cp949"),
    ("big5", "繁體中文", "big5hkscs"),
    ("koi8-r", "Привет", "koi8-r"),
    ("tis-620", "ภาษาไทย", "cp874"),
    ("iso-8859-1", "café €", "cp1252"),  # € only exists in windows-1252: WHATWG superset mapping
    ("x-mac-cyrillic", "Привет", "mac-cyrillic"),
]


@pytest.mark.parametrize("label,text,codec", _LABEL_CASES)
def test_transport_web_charset_label(make_fetcher, origins, label, text, codec) -> None:
    body = f"<html>{text}</html>".encode(codec)
    origins["a"].route("/l", Reply(200, [("Content-Type", f"text/html; charset={label}")], body))
    result = make_fetcher().fetch(origins["a"].url("/l"), mode="http")
    assert result.ok and result.html == f"<html>{text}</html>"
    assert (result.encoding.source, result.encoding.effective) == ("transport", codec)
    assert not result.encoding.replacement_used and not result.encoding.conflicts


@pytest.mark.parametrize("label,text,codec", _LABEL_CASES)
def test_meta_web_charset_label(make_fetcher, origins, label, text, codec) -> None:
    body = f'<html><meta charset="{label}">{text}</html>'.encode(codec)
    origins["a"].route("/m", Reply(200, HTML, body))
    result = make_fetcher().fetch(origins["a"].url("/m"), mode="http")
    assert result.ok and text in result.html
    assert (result.encoding.source, result.encoding.effective) == ("meta", codec)
    assert not result.encoding.replacement_used


def test_http_equiv_meta_and_python_only_names() -> None:
    from fetchward._representation import decode_html

    body = '<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-9">İ'.encode("cp1254")
    text, record = decode_html(body, None, (), False)
    assert "İ" in text and record.effective == "cp1254"
    # Python codec aliases that are not WHATWG labels are not honoured.
    for name in ("latin_1", "utf_8", "cp1252_", "base64_codec"):
        _, record = decode_html(b"x", name, (), False)
        assert record.source == "fallback" and "transport_charset_unknown" in record.conflicts


def test_replacement_labels_are_flagged() -> None:
    from fetchward._representation import decode_html

    _, record = decode_html(b"x", "iso-2022-kr", (), False)
    assert record.source == "fallback" and "replacement_encoding_label" in record.conflicts


# -- Re-review round 2 finding 2: x-user-defined -------------------------------------------------
def test_meta_x_user_defined_means_windows_1252(make_fetcher, origins) -> None:
    origins["a"].route("/x", Reply(200, HTML, b'<html><meta charset="x-user-defined">\x80</html>'))
    result = make_fetcher().fetch(origins["a"].url("/x"), mode="http")
    assert result.ok and "€" in result.html and "\ufffd" not in result.html
    assert (result.encoding.source, result.encoding.effective) == ("meta", "cp1252")
    assert "meta_charset_unknown" not in result.encoding.conflicts


def test_transport_x_user_defined_uses_its_own_mapping(make_fetcher, origins) -> None:
    origins["a"].route("/x", Reply(200, [("Content-Type", "text/html; charset=x-user-defined")], b"<p>A\x80\xff</p>"))
    result = make_fetcher().fetch(origins["a"].url("/x"), mode="http")
    assert result.ok and result.html == "<p>A\uf780\uf7ff</p>"
    assert (result.encoding.source, result.encoding.effective) == ("transport", "x-user-defined")
    assert not result.encoding.replacement_used


def test_observer_detects_an_abandoning_resolver(dns_server) -> None:
    """Harness self-check: the previous design (stop waiting, leave the lookup running) is visible."""
    import threading

    from fetchward._dns import CaresResolver
    from fetchward._safety import DNSTimeout

    dns = dns_server(blackhole=True)

    class Abandoning:
        def resolve(self, host, port, timeout):
            worker = threading.Thread(
                target=lambda: _swallow(lambda: CaresResolver([dns.address], attempt_timeout=0.1, tries=10).resolve(host, port, 5)),
                daemon=True,
            )
            worker.start()
            worker.join(timeout)
            raise DNSTimeout()

    with pytest.raises(DNSTimeout):
        Abandoning().resolve("x.test", 80, 0.2)
    returned = time.monotonic()
    time.sleep(0.6)
    assert dns.packets_after(returned) > 0


def _swallow(fn) -> None:
    try:
        fn()
    except Exception:
        pass


def test_default_resolver_uses_system_configuration() -> None:
    """Offline: /etc/hosts resolves localhost; the public policy then refuses it."""
    from fetchward import AccessPolicy, Fetcher
    from fetchward._dns import CaresResolver

    assert "127.0.0.1" in CaresResolver().resolve("localhost", 80, 2)
    result = Fetcher(AcquisitionPolicy(access=AccessPolicy(mode="user_initiated"))).fetch("http://localhost:9/", mode="http")
    assert result.attempts[0].reasons == ("safety.destination_rejected",)


def test_label_table_matches_whatwg_encoding_standard() -> None:
    import json
    from pathlib import Path

    from fetchward._representation import _LABEL_TO_CODEC, _REPLACEMENT_LABELS

    spec = json.loads((Path(__file__).parent / "data" / "whatwg-encodings.json").read_text())
    by_encoding: dict[str, set[str]] = {}
    for group in spec:
        for encoding in group["encodings"]:
            for label in encoding["labels"]:
                if encoding["name"] == "replacement":
                    assert label in _REPLACEMENT_LABELS and label not in _LABEL_TO_CODEC
                else:
                    by_encoding.setdefault(encoding["name"], set()).add(_LABEL_TO_CODEC[label])
    assert set(_LABEL_TO_CODEC) | _REPLACEMENT_LABELS == {l for g in spec for e in g["encodings"] for l in e["labels"]}
    assert all(len(codecs) == 1 for codecs in by_encoding.values())  # every label of one encoding → one decoder


# --  deadline re-checked before every event drive in a multi-event batch -------
def _duplicate(ready):
    return list(ready) * 2  # deterministic multi-event batch from one real readiness event


def test_multi_event_batch_rechecks_deadline_before_each_drive(dns_server, monkeypatch) -> None:
    from fetchward._dns import CaresResolver
    from fetchward._safety import DNSTimeout

    # AAAA is answered (a real readable event that does not complete the lookup); A never is.
    dns = dns_server(records={"x.test": ("127.0.0.1",)}, answer_qtypes=frozenset({28}))
    _hook_selector(monkeypatch, lambda _timeout: None, transform=_duplicate)
    drives, _ = _record_drives(monkeypatch, delay_after_first_fd_drive=0.25)
    started = time.monotonic()
    with pytest.raises(DNSTimeout):
        # The per-try timeout equals the deadline, so a late drive would fire the retry timer.
        CaresResolver([dns.address], attempt_timeout=5, tries=3).resolve("x.test", 80, 0.15)
    deadline = started + 0.15
    assert any(real for _, real in drives)  # the batch really contained a real-socket event
    late = [round(t - started, 3) for t, _ in drives if t >= deadline]
    assert late == [], f"process_fd driven after the deadline at {late}"
    time.sleep(0.3)
    assert dns.packets_after(deadline + _SEND_TOLERANCE) == 0


def test_completed_lookup_stops_driving_remaining_batch_events(dns_server, monkeypatch) -> None:
    from fetchward._dns import CaresResolver

    dns = dns_server(records={"x.test": ("127.0.0.1",)})
    _hook_selector(monkeypatch, lambda _timeout: None, transform=_duplicate)
    drives, completed = _record_drives(monkeypatch)
    assert CaresResolver([dns.address], attempt_timeout=5, tries=1).resolve("x.test", 80, 2) == ("127.0.0.1",)
    assert len(completed) == 1
    # The remaining (duplicated) events of the batch that completed the lookup are not driven.
    assert [t for t, _ in drives if t > completed[0]] == []


def test_public_http_huge_content_length_200_is_bounded(make_fetcher, origins) -> None:
    body = b"<html><body>ok</body></html>"
    origins["a"].route(
        "/huge-length",
        Reply(200, [("Content-Type", "text/html"), ("Content-Length", "9" * 5000)], body),
    )
    started = time.monotonic()
    result = make_fetcher().fetch(
        origins["a"].url("/huge-length"), mode="http", timeout=0.2
    )
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, elapsed
    assert result.outcome in (Outcome.PARTIAL, Outcome.ERROR)
    source = result.selected.source if result.selected is not None else None
    assert source is not None and source.status_code == 200
    assert source.complete is False
    assert source.interruption in {"budget.deadline", "network.timeout", "network.interrupted"}


def test_public_http_huge_content_length_429_keeps_cooldown(make_fetcher, origins) -> None:
    a = origins["a"]
    a.route(
        "/huge-rate",
        Reply(
            429,
            [
                ("Content-Type", "text/plain"),
                ("Content-Length", "9" * 5000),
                ("Retry-After", "60"),
            ],
            b"limited",
        ),
    )
    a.route("/after", Reply(200, HTML, b"<html>after</html>"))
    fetcher = make_fetcher()
    started = time.monotonic()
    result = fetcher.fetch(a.url("/huge-rate"), mode="http", timeout=0.2)
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, elapsed
    assert result.outcome is Outcome.RATE_LIMITED
    assert result.selected is not None and result.selected.source is not None
    assert result.selected.source.status_code == 429
    assert result.selected.source.complete is False
    assert a.log.paths() == ["/huge-rate"]

    blocked = fetcher.fetch(a.url("/after"), mode="http", timeout=0.2)
    assert blocked.outcome is Outcome.RATE_LIMITED
    assert blocked.diagnostics.stop_reason == "host.cooldown"
    assert a.log.paths() == ["/huge-rate"]
