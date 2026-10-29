"""Caller-owned persistent Chromium profiles.

A profile is a Chromium user-data directory the library creates and owns, so that cookies,
consent choices and logins persist between browser acquisitions. It is never the caller's
everyday browser profile: the library refuses a directory that looks like one, and a profile
is only opened by an acquisition that holds its exclusive lock.

The directory holds sensitive session data in plaintext (cookies, storage, history). The
library does not encrypt it; the caller is responsible for protecting it, and removes it only
through :meth:`BrowserProfile.delete`.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import shutil
import time
from pathlib import Path

from .errors import ConfigurationError, FetchwardError

PROFILE_MARKER = "fetchward-profile.json"
_LEGACY_PROFILE_MARKER = "ot_fetch-profile.json"
PROFILE_LOCK = "fetchward.lock"
SCHEMA_VERSION = 2
_FOREIGN_PROFILE_FILE = "Local State"
_LOCK_POLL_SECONDS = 0.02


class _ProfileLocked(Exception):
    """Another acquisition or process holds the profile lock until the deadline."""


class _ProfileMissing(Exception):
    """The profile directory disappeared after the object accepted it."""


class _ProfileLock:
    """One held exclusive advisory lock; releasing twice is a no-op."""

    __slots__ = ("_fd",)

    def __init__(self, fd: int) -> None:
        self._fd = fd

    def release(self) -> None:
        fd, self._fd = self._fd, -1
        if fd >= 0:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)


class BrowserProfile:
    """A caller-chosen directory the library owns for persistent browser state.

    Constructing it creates the directory with mode ``0700`` when missing and writes the
    ``fetchward-profile.json`` marker that identifies it as a fetchward profile. An existing
    directory is adopted only when it is empty or already carries a supported marker; a
    non-empty foreign directory, and anything that looks like a real browser profile root,
    is refused with :class:`~fetchward.ConfigurationError`.

    The directory is not encrypted and holds sensitive session data; the caller must protect
    it. :meth:`delete` removes it and refuses while an acquisition holds the profile.
    """

    __slots__ = ("_path",)

    def __init__(self, path: str | os.PathLike[str]) -> None:
        if isinstance(path, (bytes, bytearray)):
            raise ConfigurationError("profile path must be a str or os.PathLike[str]")
        try:
            raw = os.fspath(path)
        except TypeError as exc:
            raise ConfigurationError("profile path must be a str or os.PathLike[str]") from exc
        if not isinstance(raw, str) or not raw:
            raise ConfigurationError("profile path must be a non-empty path")
        self._path = Path(raw)
        self._prepare()

    def __repr__(self) -> str:
        # Directory name only: a full path may identify the caller.
        return f"BrowserProfile({self._path.name!r})"

    @property
    def path(self) -> Path:
        """The profile directory. Chromium uses it as its user-data directory."""
        return self._path

    @property
    def exists(self) -> bool:
        return self._path.is_dir()

    def delete(self) -> None:
        """Remove the profile directory, refusing while another acquisition holds it."""
        if not self._path.exists():
            return
        try:
            fd = self._open_lock_file()
        except _ProfileMissing:
            return
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                    raise FetchwardError("profile is locked by an acquisition") from exc
                raise
            marker = next(
                (self._path / name for name in (PROFILE_MARKER, _LEGACY_PROFILE_MARKER)
                 if (self._path / name).is_file()),
                None,
            )
            if marker is None:
                # Only ever remove a directory this library still recognises as its profile.
                raise FetchwardError("refusing to delete: profile marker is missing")
            try:
                self._check_marker(marker)
            except ConfigurationError as exc:
                raise FetchwardError("refusing to delete: profile marker is not ours") from exc
            try:
                shutil.rmtree(self._path)
            except OSError as exc:
                raise FetchwardError("profile directory could not be removed") from exc
        finally:
            os.close(fd)

    # -- internals ---------------------------------------------------------------------

    def _prepare(self) -> None:
        path = self._path
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ConfigurationError("profile path exists and is not a directory")
        if not path.exists():
            try:
                path.mkdir(mode=0o700, parents=True)
            except FileExistsError:
                pass  # another process created it first; adopt it below
            else:
                os.chmod(path, 0o700)
                self._write_marker()
                return
        marker = path / PROFILE_MARKER
        if marker.exists() or marker.is_symlink():
            self._check_marker(marker)
            return
        legacy_marker = path / _LEGACY_PROFILE_MARKER
        if legacy_marker.exists() or legacy_marker.is_symlink():
            self._check_marker(legacy_marker)
            return
        # `Local State` is the file every Chromium-derived profile root carries. Someone
        # pointing us at their everyday profile must not get a library marker written into it.
        if (path / _FOREIGN_PROFILE_FILE).exists():
            raise ConfigurationError("profile path is a browser profile, not a fetchward profile")
        try:
            occupied = any(path.iterdir())
        except OSError as exc:
            raise ConfigurationError("profile path is not readable") from exc
        if occupied:
            raise ConfigurationError("profile path is not empty and has no fetchward marker")
        self._write_marker()

    def _check_marker(self, marker: Path) -> None:
        try:
            payload = json.loads(marker.read_text("utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigurationError("profile marker is unreadable") from exc
        schema = payload.get("schema") if isinstance(payload, dict) else None
        if type(schema) is not int or schema not in (1, SCHEMA_VERSION):
            raise ConfigurationError("profile marker has an unsupported schema version")
        if schema == SCHEMA_VERSION and payload.get("engine") not in (None, "playwright-chromium", "real-chrome"):
            raise ConfigurationError("profile marker has an unsupported engine")

    def _use_engine(self, engine: str) -> None:
        """Called under the profile lock before launching a browser."""
        marker = next(self._path / name for name in (PROFILE_MARKER, _LEGACY_PROFILE_MARKER)
                      if (self._path / name).is_file())
        self._check_marker(marker)
        payload = json.loads(marker.read_text("utf-8"))
        previous = payload.get("engine")
        if previous is None and payload["schema"] == 1 and (self._path / _FOREIGN_PROFILE_FILE).exists():
            previous = "playwright-chromium"
        if previous is not None and previous != engine:
            raise ConfigurationError(f"profile engine mismatch: profile uses {previous}, requested {engine}")
        if previous is None or payload["schema"] != SCHEMA_VERSION:
            self._write_marker(engine)

    def _write_marker(self, engine: str | None = None) -> None:
        payload = json.dumps({"schema": SCHEMA_VERSION, "created_by": "fetchward", "engine": engine}) + "\n"
        temporary = self._path / f".{PROFILE_MARKER}.{os.getpid()}"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(temporary, self._path / PROFILE_MARKER)

    def _open_lock_file(self) -> int:
        try:
            return os.open(self._path / PROFILE_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
        except FileNotFoundError as exc:
            raise _ProfileMissing from exc
        except OSError as exc:
            raise FetchwardError("profile lock file could not be opened") from exc

    def _acquire(self, deadline: float) -> _ProfileLock:
        """Take the exclusive lock, waiting no longer than ``deadline`` (monotonic)."""
        fd = self._open_lock_file()
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return _ProfileLock(fd)
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                    os.close(fd)
                    raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                os.close(fd)
                raise _ProfileLocked
            time.sleep(min(_LOCK_POLL_SECONDS, remaining))


__all__ = ["BrowserProfile", "PROFILE_MARKER", "SCHEMA_VERSION"]
