"""The storage thread: sole owner of the sqlite3 connection (docs/11 §2, §6).

Every database access is a function submitted to this thread and runs inside one explicit
transaction. The queue is bounded: when it is full the caller gets StorageBusy (-> HTTP 503), the
request is not accepted, and nothing is half-written. Async handlers await the future; they never
touch sqlite themselves.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import fcntl
import os
import queue
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

T = TypeVar("T")

_SENTINEL = object()


class StorageBusy(RuntimeError):
    """The storage queue is full; the request was not accepted."""


class StorageFault(RuntimeError):
    """The database is unusable (corrupt, locked by another process, schema mismatch).

    Never "repaired" by recreating an empty database (docs/11 §7).
    """


class StorageThread:
    def __init__(self, db_path: Path, schema_path: Path, max_queue: int = 256) -> None:
        self._db_path = db_path
        self._schema_path = schema_path
        self._queue: queue.Queue[object] = queue.Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        self._lock_fd: int | None = None
        self._ready = threading.Event()
        self._start_error: BaseException | None = None
        self.journal_id: bytes = b""

    # ---- lifecycle -------------------------------------------------------------------------
    def start(self) -> None:
        """Takes the singleton lock, opens/initialises the DB, starts the thread.

        Raises StorageFault when another host process owns the database (H07) or the database
        fails its integrity check.
        """
        self._lock_fd = _acquire_singleton_lock(self._db_path)
        self._thread = threading.Thread(target=self._run, name="leanmesh-storage", daemon=True)
        self._thread.start()
        self._ready.wait()
        if self._start_error is not None:
            self._release_lock()
            raise StorageFault(str(self._start_error)) from self._start_error

    def stop(self, timeout_s: float = 10.0) -> None:
        """Stops accepting work, drains queued transactions, checkpoints and closes."""
        if self._thread is None:
            return
        self._queue.put(_SENTINEL)
        self._thread.join(timeout_s)
        self._thread = None
        self._release_lock()

    # ---- work submission -------------------------------------------------------------------
    def submit(self, fn: Callable[[sqlite3.Connection], T]) -> concurrent.futures.Future[T]:
        """Queues fn(conn) to run in its own transaction. Raises StorageBusy when full."""
        fut: concurrent.futures.Future[T] = concurrent.futures.Future()
        try:
            self._queue.put_nowait((fn, fut))
        except queue.Full:
            raise StorageBusy("storage queue full") from None
        return fut

    async def run(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        return await asyncio.wrap_future(self.submit(fn))

    # ---- thread body -----------------------------------------------------------------------
    def _run(self) -> None:
        try:
            conn = _open(self._db_path, self._schema_path)
            self.journal_id = _journal_id(conn)
        except (sqlite3.Error, StorageFault, OSError) as exc:
            self._start_error = exc
            self._ready.set()
            return
        self._ready.set()
        try:
            while True:
                item = self._queue.get()
                if item is _SENTINEL:
                    break
                fn, fut = item  # type: ignore[misc]
                if not fut.set_running_or_notify_cancel():
                    continue
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    result = fn(conn)
                    conn.execute("COMMIT")
                except BaseException as exc:  # the transaction must end either way
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    fut.set_exception(exc)
                else:
                    fut.set_result(result)
        finally:
            # Safe checkpoint on shutdown (docs/11 §6); failures are left to the next start.
            try:
                conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            finally:
                conn.close()

    def _release_lock(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None


def _acquire_singleton_lock(db_path: Path) -> int:
    fd = os.open(f"{db_path}.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise StorageFault(f"{db_path} is owned by another host process") from None
    return fd


def _open(db_path: Path, schema_path: Path) -> sqlite3.Connection:
    # isolation_level=None: transactions are explicit (BEGIN/COMMIT above).
    conn = sqlite3.connect(str(db_path), isolation_level=None, check_same_thread=True)
    for pragma in ("journal_mode=WAL", "synchronous=FULL", "foreign_keys=ON", "busy_timeout=1000"):
        conn.execute(f"PRAGMA {pragma}")
    if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        conn.close()
        raise StorageFault("database failed quick_check; quarantine and recover explicitly")
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
    ).fetchone()
    if exists is None:
        _apply_schema(conn, schema_path.read_text())
    return conn


def _apply_schema(conn: sqlite3.Connection, schema_sql: str) -> None:
    """Creates all tables and the durable journal_id in ONE transaction (PRAGMAs are set above)."""
    statements: list[str] = []
    current = ""
    for line in schema_sql.splitlines(keepends=True):
        if not current and line.lstrip().upper().startswith("PRAGMA"):
            continue
        current += line
        if sqlite3.complete_statement(current):
            statements.append(current)
            current = ""
    if current.strip():
        raise StorageFault("schema.sql ends with an incomplete statement")
    conn.execute("BEGIN IMMEDIATE")
    try:
        for stmt in statements:
            conn.execute(stmt)
        # journal_id: durable 128-bit identity of this event journal (docs/11 §5).
        conn.execute("INSERT INTO meta(key, value) VALUES('journal_id', ?)", (os.urandom(16),))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def _journal_id(conn: sqlite3.Connection) -> bytes:
    row = conn.execute("SELECT value FROM meta WHERE key='journal_id'").fetchone()
    if row is None or len(row[0]) != 16:
        raise StorageFault("meta.journal_id missing: database was not created by this service")
    return bytes(row[0])
