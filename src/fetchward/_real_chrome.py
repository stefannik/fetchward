"""Owned installed-Chrome process and its CDP attachment."""
from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

from ._browser import _HARDENING

DEFAULT_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def _terminate(process):
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    except ProcessLookupError:
        pass


class RealChrome:
    def __init__(self, pool, path: str | None, profile: Path, proxy: str, deadline: float, *, headless: bool):
        self.pool = pool
        self.path = path or DEFAULT_CHROME
        self.profile = profile
        self.proxy = proxy
        self.deadline = deadline
        self.headless = headless
        self.ownership = "unknown"
        self._lock = threading.Lock()
        self._process = None
        self._stopped = False
        self._stop_done = threading.Event()

    def start(self, manager):
        from playwright.sync_api import Error as PlaywrightError

        if not os.path.isfile(self.path) or not os.access(self.path, os.X_OK):
            raise FileNotFoundError(f"Google Chrome executable unavailable: {self.path}")
        self.pool.register_chrome(self)
        try:
            previous_port = None
            for attempt in range(2):
                if time.monotonic() >= self.deadline:
                    break
                while True:
                    with socket.socket() as listener:
                        listener.bind(("127.0.0.1", 0))
                        port = listener.getsockname()[1]
                    if port != previous_port:
                        break
                previous_port = port
                args = [self.path, f"--user-data-dir={self.profile}", f"--remote-debugging-port={port}",
                        "--no-first-run", "--no-default-browser-check", f"--proxy-server={self.proxy}",
                        "--proxy-bypass-list=<-loopback>", *_HARDENING]
                if self.headless:
                    args.append("--headless=new")
                with self._lock:
                    if self._stopped:
                        raise RuntimeError("Chrome launch cancelled")
                    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self._process = process
                browser = None
                try:
                    while time.monotonic() < self.deadline and process.poll() is None:
                        with self._lock:
                            if self._stopped:
                                raise RuntimeError("Chrome launch cancelled")
                        remaining = self.deadline - time.monotonic()
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=min(0.25, max(0.001, remaining)))
                        try:
                            conn.request("GET", "/json/version")
                            response = conn.getresponse()
                            data = json.loads(response.read(65536)) if response.status == 200 else {}
                            ready = isinstance(data, dict) and bool(data.get("webSocketDebuggerUrl"))
                            response.close()
                        except (OSError, http.client.HTTPException, ValueError):
                            ready = False
                        finally:
                            conn.close()
                        if ready and process.poll() is None:
                            browser = manager.chromium.connect_over_cdp(
                                f"http://127.0.0.1:{port}",
                                timeout=max(1, int((self.deadline - time.monotonic()) * 1000)))
                            session = browser.new_browser_cdp_session()
                            try:
                                try:
                                    info = session.send("SystemInfo.getProcessInfo")
                                except PlaywrightError as exc:
                                    text = str(exc).lower()
                                    if "wasn't found" not in text and "not supported" not in text and "not available" not in text:
                                        raise
                                    self.ownership = "endpoint_and_liveness"
                                else:
                                    if not any(item.get("type") == "browser" and item.get("id") == process.pid
                                               for item in info.get("processInfo", [])):
                                        raise RuntimeError("Chrome debugging port belongs to another process")
                                    self.ownership = "browser_pid"
                                session.send("Browser.setDownloadBehavior", {"behavior": "deny"})
                            finally:
                                session.detach()
                            if process.poll() is not None:
                                raise RuntimeError("Chrome exited during attachment")
                            return browser, browser.contexts[0]
                        time.sleep(min(0.05, max(0.0, self.deadline - time.monotonic())))
                    raise RuntimeError("Chrome debugging endpoint unavailable before deadline or child exit")
                except (PlaywrightError, RuntimeError, OSError, IndexError):
                    if browser is not None:
                        browser.close()
                    _terminate(process)
                    with self._lock:
                        if self._process is process:
                            self._process = None
                        if self._stopped:
                            raise RuntimeError("Chrome launch cancelled")
                    if attempt == 1 or time.monotonic() >= self.deadline:
                        raise RuntimeError("Google Chrome debugging endpoint unavailable")
            raise RuntimeError("Google Chrome debugging endpoint unavailable before deadline")
        except BaseException:
            self.stop()
            raise

    def stop(self):
        with self._lock:
            if self._stopped:
                process = None
                already_stopping = True
            else:
                self._stopped = True
                process = self._process
                already_stopping = False
        if already_stopping:
            self._stop_done.wait(2.5)
            return
        try:
            _terminate(process)
        finally:
            self.pool.unregister_chrome(self)
            self._stop_done.set()
