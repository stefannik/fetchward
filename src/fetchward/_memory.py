"""Opt-in per-host acquisition memory (v0.2 U3).

A small advisory store keyed by host only: whether ``auto`` had to fall back to the browser,
whether plain HTTP was enough, the last outcome, and a server-requested cooldown lower bound.
It never stores URLs, paths, query strings, bodies or credentials, and it never authorizes
anything: routing advice only reorders the attempt that policy already permits, and a
remembered cooldown can only delay a request, never unlock one.

``path=None`` keeps the store in process memory (SQLite ``:memory:``), so the same code path
runs with or without persistence. A path is a real SQLite file created ``0600`` with an
in-memory rollback journal (no ``-journal``/``-wal`` side files). Writes are transactional.
A corrupt or incompatible file is reported once as diagnostics evidence and then recreated.
"""

from __future__ import annotations

import math
import os
import sqlite3
import threading
from typing import Any

from ._types import Evidence, EvidenceCategory, Outcome
from .errors import ConfigurationError

MEMORY_SCHEMA_VERSION = 1

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS memory_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS host_state (
        host TEXT PRIMARY KEY,
        needs_browser_at REAL,
        http_sufficient_at REAL,
        last_outcome TEXT,
        last_outcome_at REAL,
        cooldown_until REAL,
        cooldown_delay REAL,
        cooldown_recorded_at REAL
    )""",
)

_COLUMNS = (
    "host, needs_browser_at, http_sufficient_at, last_outcome, last_outcome_at, "
    "cooldown_until, cooldown_delay, cooldown_recorded_at"
)

_CREATE_META = "INSERT OR REPLACE INTO memory_meta (key, value) VALUES ('schema_version', ?)"

_UPSERT = f"""
INSERT INTO host_state ({_COLUMNS})
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(host) DO UPDATE SET
    needs_browser_at = COALESCE(excluded.needs_browser_at, host_state.needs_browser_at),
    http_sufficient_at = COALESCE(excluded.http_sufficient_at, host_state.http_sufficient_at),
    last_outcome = COALESCE(excluded.last_outcome, host_state.last_outcome),
    last_outcome_at = COALESCE(excluded.last_outcome_at, host_state.last_outcome_at),
    cooldown_until = CASE
        WHEN excluded.cooldown_until IS NULL THEN host_state.cooldown_until
        ELSE max(COALESCE(host_state.cooldown_until, 0), excluded.cooldown_until) END,
    cooldown_delay = CASE
        WHEN excluded.cooldown_until IS NULL THEN host_state.cooldown_delay
        WHEN COALESCE(host_state.cooldown_until, 0) > excluded.cooldown_until
            THEN host_state.cooldown_delay
        ELSE excluded.cooldown_delay END,
    cooldown_recorded_at = CASE
        WHEN excluded.cooldown_until IS NULL THEN host_state.cooldown_recorded_at
        WHEN COALESCE(host_state.cooldown_until, 0) > excluded.cooldown_until
            THEN host_state.cooldown_recorded_at
        ELSE excluded.cooldown_recorded_at END
"""

_PRUNE = """
DELETE FROM host_state
WHERE max(
        COALESCE(needs_browser_at, 0),
        COALESCE(http_sufficient_at, 0),
        COALESCE(last_outcome_at, 0),
        COALESCE(cooldown_recorded_at, 0)
    ) < ?
  AND COALESCE(cooldown_until, 0) <= ?
"""


class AcquisitionMemory:
    """Advisory per-host acquisition memory, optionally persisted to one SQLite file.

    ``ttl_days`` bounds how long an entry is used; expired entries are ignored when read and
    pruned on the next write. A persisted cooldown keeps its wall-clock deadline across
    processes; within the process that recorded it a monotonic deadline also applies, so a
    wall-clock change cannot shorten the wait below the server-requested delay. Across
    process restarts only the wall clock is available.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None, ttl_days: float = 7) -> None:
        if path is not None:
            try:
                path = os.fspath(path)
            except TypeError as exc:
                raise TypeError("path must be a str, os.PathLike or None") from exc
            if not isinstance(path, str):
                raise TypeError("path must be a str, os.PathLike or None")
            if not path:
                raise ConfigurationError("path must not be empty")
        if (
            isinstance(ttl_days, bool)
            or not isinstance(ttl_days, (int, float))
            or not math.isfinite(ttl_days)
            or ttl_days <= 0
        ):
            raise ConfigurationError("ttl_days must be finite and positive")
        self._path = path
        self._ttl = float(ttl_days) * 86400.0
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._degraded = False
        self._pid = os.getpid()
        self._notices: list[Evidence] = []
        self._problem_reported = False
        # (monotonic deadline, wall time recorded) for cooldowns this object recorded, so a
        # wall-clock change cannot shorten a wait the server already asked for.
        self._local_cooldowns: dict[str, tuple[float, float]] = {}

    # -- public API ----------------------------------------------------------------------

    def clear(self) -> None:
        """Forget every host."""
        with self._lock:
            self._local_cooldowns.clear()
            conn = self._ensure()
            if conn is not None:
                self._write(conn, "DELETE FROM host_state", ())

    def forget(self, host: str) -> None:
        """Forget one host."""
        if not isinstance(host, str):
            raise TypeError("host must be a str")
        with self._lock:
            self._local_cooldowns.pop(host, None)
            conn = self._ensure()
            if conn is not None:
                self._write(conn, "DELETE FROM host_state WHERE host = ?", (host,))

    # -- fetcher-facing API (package-private) ---------------------------------------------

    def _browser_first_age(self, host: str, now_wall: float) -> float | None:
        """Age in seconds of a fresh ``needs_browser`` with no newer ``http_sufficient``."""
        row = self._row(host)
        if row is None:
            return None
        needed = _number(row["needs_browser_at"])
        if needed is None or not self._fresh(needed, now_wall):
            return None
        sufficient = _number(row["http_sufficient_at"])
        if sufficient is not None and self._fresh(sufficient, now_wall) and sufficient >= needed:
            return None
        return max(0.0, now_wall - needed)

    def _cooldown_remaining(self, host: str, now_wall: float, now_monotonic: float) -> float:
        """Seconds still to wait for ``host``, never negative."""
        remaining = 0.0
        row = self._row(host)
        if row is not None:
            until = _number(row["cooldown_until"])
            recorded = _number(row["cooldown_recorded_at"])
            if until is not None and recorded is not None and self._fresh(recorded, now_wall):
                remaining = max(remaining, until - now_wall)
        with self._lock:
            local = self._local_cooldowns.get(host)
            if local is not None:
                until_monotonic, recorded_wall = local
                left = until_monotonic - now_monotonic
                if left > 0 and self._fresh(recorded_wall, now_wall):
                    remaining = max(remaining, left)
                else:
                    self._local_cooldowns.pop(host, None)
        return max(0.0, remaining)

    def _record(
        self,
        host: str,
        *,
        now_wall: float,
        needs_browser_at: float | None = None,
        http_sufficient_at: float | None = None,
        outcome: Outcome | None = None,
        cooldown_delay: float | None = None,
        now_monotonic: float | None = None,
    ) -> None:
        """One transactional upsert for ``host``."""
        if not isinstance(host, str) or not host:
            return
        delay = cooldown_delay if cooldown_delay is not None and cooldown_delay > 0 else None
        cooldown_until = None if delay is None else now_wall + delay
        with self._lock:
            if delay is not None and now_monotonic is not None:
                self._local_cooldowns[host] = (now_monotonic + delay, now_wall)
            conn = self._ensure()
            if conn is None:
                return
            self._write(
                conn,
                _UPSERT,
                (
                    host,
                    needs_browser_at,
                    http_sufficient_at,
                    None if outcome is None else outcome.value,
                    None if outcome is None else now_wall,
                    cooldown_until,
                    delay,
                    None if cooldown_until is None else now_wall,
                ),
            )
            self._prune(conn, now_wall)

    def _drain_notices(self) -> tuple[Evidence, ...]:
        with self._lock:
            notices = tuple(self._notices)
            self._notices.clear()
            return notices

    # -- store internals -----------------------------------------------------------------

    def _fresh(self, at: float, now_wall: float) -> bool:
        return now_wall - at < self._ttl

    def _row(self, host: str) -> sqlite3.Row | None:
        with self._lock:
            conn = self._ensure()
            if conn is None:
                return None
            try:
                return conn.execute(
                    f"SELECT {_COLUMNS} FROM host_state WHERE host = ?", (host,)
                ).fetchone()
            except sqlite3.Error as exc:
                self._degrade(exc)
                return None

    def _ensure(self) -> sqlite3.Connection | None:
        # An inherited connection and its lock may be unusable in a forked child.
        if os.getpid() != self._pid:
            self._lock = threading.RLock()
            self._conn = None
            self._local_cooldowns = {}
            self._pid = os.getpid()
        with self._lock:
            if self._conn is None:
                self._conn = self._open()
            return self._conn

    def _open(self) -> sqlite3.Connection | None:
        if self._path is None or self._degraded:
            return self._open_ephemeral()
        conn: sqlite3.Connection | None = None
        try:
            self._create_file()
            conn = self._connect(self._path)
            self._prepare(conn)
            return conn
        except (sqlite3.Error, OSError) as exc:
            _close(conn)
            if isinstance(exc, sqlite3.DatabaseError) and _is_corrupt(exc):
                self._notice("memory.corrupt", reason="not a database")
                try:
                    self._remove_files()
                    self._create_file()
                    retry = self._connect(self._path)
                    self._prepare(retry)
                    return retry
                except (sqlite3.Error, OSError) as retry_exc:
                    exc = retry_exc
            self._degrade(exc)
            return self._open_ephemeral()

    def _open_ephemeral(self) -> sqlite3.Connection | None:
        conn: sqlite3.Connection | None = None
        try:
            conn = self._connect(None)
            self._prepare(conn)
            return conn
        except sqlite3.Error as exc:
            _close(conn)
            self._notice("memory.unavailable", reason=type(exc).__name__)
            self._conn = None
            return None

    def _connect(self, path: str | None) -> sqlite3.Connection:
        conn = sqlite3.connect(
            ":memory:" if path is None else path,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            conn.row_factory = sqlite3.Row
            # MEMORY keeps rollback data off disk, so no world-readable journal side file.
            conn.execute("PRAGMA journal_mode=MEMORY")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")
        except sqlite3.Error:
            _close(conn)
            raise
        return conn

    def _create_file(self) -> None:
        assert self._path is not None
        descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(descriptor)
        os.chmod(self._path, 0o600)

    def _remove_files(self) -> None:
        assert self._path is not None
        for suffix in ("", "-journal", "-wal", "-shm"):
            try:
                os.remove(self._path + suffix)
            except FileNotFoundError:
                pass

    def _prepare(self, conn: sqlite3.Connection) -> None:
        try:
            row = conn.execute(
                "SELECT value FROM memory_meta WHERE key = 'schema_version'"
            ).fetchone()
            row_ready = row is not None and _table_exists(conn, "host_state")
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc).lower():
                raise
            row, row_ready = None, False
        if row is None or not row_ready:
            _create_schema(conn)
            return
        version = str(row["value"])
        if version != str(MEMORY_SCHEMA_VERSION):
            self._notice("memory.corrupt", reason="incompatible schema", schema_version=version)
            conn.execute("DROP TABLE IF EXISTS host_state")
            conn.execute("DROP TABLE IF EXISTS memory_meta")
            _create_schema(conn)

    def _write(self, conn: sqlite3.Connection, sql: str, parameters: tuple) -> None:
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(sql, parameters)
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
        except sqlite3.Error as exc:
            self._degrade(exc)

    def _prune(self, conn: sqlite3.Connection, now_wall: float) -> None:
        self._write(conn, _PRUNE, (now_wall - self._ttl, now_wall))

    def _degrade(self, exc: BaseException) -> None:
        _close(self._conn)
        self._conn = None
        self._degraded = True
        self._notice("memory.unavailable", reason=type(exc).__name__)

    def _notice(self, code: str, **facts: str) -> None:
        if self._problem_reported:
            return
        self._problem_reported = True
        self._notices.append(
            Evidence(
                code,
                EvidenceCategory.OBSERVATION,
                True,
                facts=tuple((key, str(value)) for key, value in facts.items()),
            )
        )

    def __repr__(self) -> str:
        where = "in-process" if self._path is None else "sqlite"
        return f"AcquisitionMemory({where}, ttl_days={self._ttl / 86400:g})"


def _create_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)
    conn.execute(_CREATE_META, (str(MEMORY_SCHEMA_VERSION),))


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
        ).fetchone()
        is not None
    )


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _close(conn: sqlite3.Connection | None) -> None:
    if conn is None:
        return
    try:
        conn.close()
    except sqlite3.Error:
        pass


def _is_corrupt(exc: sqlite3.DatabaseError) -> bool:
    text = str(exc).lower()
    return "not a database" in text or "malformed" in text


__all__ = ["AcquisitionMemory"]
