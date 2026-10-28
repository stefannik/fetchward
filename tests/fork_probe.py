"""Isolated fork probe used by tests/test_fork_safety.py.

The parent intentionally holds one real library lock in another thread while forking. The
child must fail fast for inherited objects, must not touch the network, and must successfully
create new objects using child-local globals. The parent must remain usable after the lock is
released. The helper is not a pytest module.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from harness import FixtureOrigin, Reply, StaticResolver  # noqa: E402
from fetchward import (  # noqa: E402
    AccessPolicy,
    AcquisitionPolicy,
    DestinationPolicy,
    Fetcher,
    ForkedProcessError,
    Session,
    TransportPolicy,
)
from fetchward._browser import browser_status  # noqa: E402
from fetchward._robots import robots_authority  # noqa: E402
from fetchward._safety import canonicalize  # noqa: E402
from fetchward._safety_runtime import process_safety  # noqa: E402


def _fail(message: str) -> None:
    os.write(2, (message + "\n").encode())


def main() -> int:
    case = sys.argv[1]
    policy = AcquisitionPolicy(
        access=AccessPolicy(
            mode="automated" if case in {"robots", "robots_authority"} else "user_initiated"
        )
    )
    session = Session()
    session.add_cookie("http://origin.test", "probe", "one")
    resolver = StaticResolver({"origin.test": ("127.0.0.1",)})
    fetcher = Fetcher(policy, session=session, _resolver=resolver)
    old_safety = process_safety()
    old_robots = robots_authority()

    if case == "safety":
        lock = old_safety._condition
    elif case == "robots":
        lock = old_robots._cache._lock
    elif case == "robots_authority":
        lock = old_robots._condition
    elif case == "session":
        lock = session._lock
    elif case == "fetcher":
        lock = fetcher._lock
    elif case == "browser":
        lock = threading.Lock()  # browser status has no process lock to hold
    else:
        raise SystemExit(f"unknown case {case}")

    if case == "browser":
        # Populate the normal browser-status cache before fork; the child wrapper must not
        # take the inherited lru-cache lock or launch Chromium.
        browser_status()

    held = threading.Event()
    release = threading.Event()

    def holder() -> None:
        with lock:
            held.set()
            while not release.wait(0.05):
                pass

    thread = threading.Thread(target=holder, name="fork-lock-holder")
    thread.start()
    if not held.wait(2):
        _fail("parent could not acquire test lock")
        return 2

    pid = os.fork()
    if pid == 0:
        # Start a watchdog before any library lock operation. A hard hang exits 77.
        watchdog = threading.Timer(3.0, lambda: os._exit(77))
        watchdog.daemon = True
        watchdog.start()
        try:
            if case == "session":
                try:
                    session.snapshot()
                except ForkedProcessError:
                    pass
                else:
                    _fail("inherited Session did not fail fast")
                    os._exit(3)
            elif case == "fetcher":
                try:
                    fetcher.close()
                except ForkedProcessError:
                    pass
                else:
                    _fail("inherited Fetcher.close did not fail fast")
                    os._exit(4)
            else:
                try:
                    fetcher.fetch("http://origin.test:9/", mode="http", timeout=1)
                except ForkedProcessError:
                    pass
                else:
                    _fail("inherited Fetcher.fetch did not fail fast")
                    os._exit(5)

            if resolver.calls:
                _fail("inherited child performed DNS work before fail-fast")
                os._exit(6)
            if process_safety() is old_safety:
                _fail("child reused inherited SafetyRuntime")
                os._exit(6)
            if robots_authority() is old_robots:
                _fail("child reused inherited RobotsAuthority")
                os._exit(7)

            # New objects after fork must work without inherited locks.
            new_session = Session()
            new_session.add_cookie("http://origin.test", "child", "two")
            new_session.close()
            new_fetcher = Fetcher(
                policy,
                _resolver=StaticResolver({"origin.test": ("127.0.0.1",)}),
            )
            new_fetcher.close()

            # A new HTTP object must use the child-local runtime and can acquire a loopback
            # fixture; this is not an external/live request.
            child_origin = FixtureOrigin("fork-child.test")
            try:
                child_origin.route(
                    "/", Reply(200, [("Content-Type", "text/plain")], b"child-ok")
                )
                child_policy = AcquisitionPolicy(
                    access=AccessPolicy(mode="user_initiated"),
                    destinations=DestinationPolicy(
                        trusted_local=(child_origin.trusted(),)
                    ),
                    transport=TransportPolicy(),
                )
                child_fetcher = Fetcher(
                    child_policy,
                    _resolver=StaticResolver({"fork-child.test": ("127.0.0.1",)}),
                )
                try:
                    child_result = child_fetcher.fetch(
                        child_origin.url("/"), mode="http", timeout=2
                    )
                    if not child_result.ok or child_result.response_body != b"child-ok":
                        _fail("new child HTTP object did not acquire loopback fixture")
                        os._exit(13)
                finally:
                    child_fetcher.close()
            finally:
                child_origin.close()

            status = browser_status()
            if status.code != "backend.fork_unsafe":
                _fail(f"child browser status was {status.code!r}, expected backend.fork_unsafe")
                os._exit(8)

            child_browser = Fetcher(
                policy,
                _resolver=StaticResolver({"origin.test": ("127.0.0.1",)}),
            )
            try:
                browser_result = child_browser.fetch(
                    "http://origin.test:9/", mode="browser", timeout=1
                )
                if (
                    browser_result.outcome.value != "error"
                    or browser_result.diagnostics.stop_reason != "backend.fork_unsafe"
                    or browser_result.diagnostics.budget.requests != 0
                ):
                    _fail("new child browser mode did not fail closed before dispatch")
                    os._exit(14)
            finally:
                child_browser.close()

            os._exit(0)
        except BaseException as exc:  # report type only; child must exit
            _fail(f"child failure: {type(exc).__name__}")
            os._exit(9)

    # The parent deliberately keeps the inherited lock held while the child runs.
    deadline = time.monotonic() + 5
    status = None
    while time.monotonic() < deadline:
        waited, raw = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            status = raw
            break
        time.sleep(0.02)
    if status is None:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        release.set()
        thread.join(timeout=2)
        _fail("child hung while the parent held an inherited lock")
        return 10
    release.set()
    thread.join(timeout=2)

    # Parent objects and child-local identity must remain intact after fork.
    try:
        if process_safety() is not old_safety or robots_authority() is not old_robots:
            _fail("parent process globals changed")
            return 11
        snapshot = session.snapshot()
        headers = snapshot.headers_for(canonicalize("http://origin.test/"))
        if not any(name.lower() == "cookie" and "probe=one" in value for name, value in headers):
            _fail("parent session credentials changed across fork")
            return 11
        fetcher.close()
    except BaseException as exc:
        _fail(f"parent failure: {type(exc).__name__}")
        return 12

    code = os.waitstatus_to_exitcode(status)
    if code != 0:
        _fail(f"child exited {code}")
        return code
    print("OK", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
