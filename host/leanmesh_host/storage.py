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
import logging
import os
import queue
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

T = TypeVar("T")
log = logging.getLogger(__name__)

_SENTINEL = object()


class StorageBusy(RuntimeError):
    """The storage queue is full; the request was not accepted."""


class StorageFull(RuntimeError):
    """SQLite reported SQLITE_FULL (disk or page budget). The transaction was rolled back."""


class StorageFault(RuntimeError):
    """The database is unusable (corrupt, locked by another process, schema mismatch).

    Never "repaired" by recreating an empty database (docs/11 §7).
    """


class StorageThread:
    def __init__(self, db_path: Path, schema_path: Path, max_queue: int = 256,
                 max_page_count: int | None = None) -> None:
        self._max_page_count = max_page_count
        self._db_path = db_path
        self._schema_path = schema_path
        self._queue: queue.Queue[object] = queue.Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        self._lock_fd: int | None = None
        self._closing = False  # set by stop(): no new work is accepted
        self._sentinel_queued = False
        self._ready = threading.Event()
        self._start_error: BaseException | None = None
        self._state_lock = threading.Lock()
        self._fatal: BaseException | None = None
        self.journal_id: bytes = b""
        # Runs on the storage thread right after COMMIT (never inside a transaction).
        self.after_commit: Callable[[sqlite3.Connection], None] | None = None
        # Test seam: hook(stage, fn_name) with stage "before_commit"/"after_commit". Crash tests
        # use it to kill the process at a transaction boundary; production leaves it None.
        self.fault_hook: Callable[[str, str], None] | None = None

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def failed(self) -> bool:
        with self._state_lock:
            return self._fatal is not None

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
        """Stops accepting work, drains queued transactions, checkpoints and closes.

        The singleton lock is released only after the thread has really exited. When it has not
        (a stuck transaction, a full queue that does not drain) this raises StorageFault and keeps
        the lock: another process must not open a database this one may still commit to.
        """
        if self._thread is None:
            return
        with self._state_lock:
            self._closing = True
        deadline = time.monotonic() + timeout_s
        if self._thread.is_alive() and not self._sentinel_queued:
            try:
                self._queue.put(_SENTINEL, timeout=timeout_s)
            except queue.Full:
                raise StorageFault("storage queue did not drain; lock kept") from None
            self._sentinel_queued = True
        self._thread.join(max(0.0, deadline - time.monotonic()))
        if self._thread.is_alive():
            raise StorageFault("storage thread did not stop in time; lock kept")
        self._thread = None
        self._release_lock()

    # ---- work submission -------------------------------------------------------------------
    def submit(self, fn: Callable[[sqlite3.Connection], T]) -> concurrent.futures.Future[T]:
        """Queues fn(conn) to run in its own transaction. Raises StorageBusy when full."""
        fut: concurrent.futures.Future[T] = concurrent.futures.Future()
        with self._state_lock:
            if self._fatal is not None:
                raise StorageFault("storage failed; explicit recovery required") from self._fatal
            if self._closing:
                raise StorageBusy("storage is shutting down")
            try:
                self._queue.put_nowait((fn, fut))
            except queue.Full:
                raise StorageBusy("storage queue full") from None
        return fut

    async def run(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        return await asyncio.wrap_future(self.submit(fn))

    # ---- thread body -----------------------------------------------------------------------
    def _run(self) -> None:
        conn = None
        active = None
        try:
            conn = _open(self._db_path, self._schema_path)
            if self._max_page_count is not None:
                conn.execute(f"PRAGMA max_page_count={int(self._max_page_count)}")
            self.journal_id = _journal_id(conn)
        except BaseException as exc:
            self._start_error = exc
            self._fail(exc)
            try:
                if conn is not None:
                    conn.close()
            except BaseException as close_error:
                exc.add_note(f"startup close failed: {close_error}")
            finally:
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
                active = fut
                self._run_one(conn, fn, fut)
                active = None
        except BaseException as exc:
            self._fail(exc, active)
        finally:
            # Safe checkpoint on shutdown (docs/11 §6); failures are left to the next start.
            try:
                conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            except BaseException as exc:
                self._fail(exc)
            finally:
                try:
                    conn.close()
                except BaseException as exc:
                    self._fail(exc)

    def _fail(self, cause: BaseException, active: concurrent.futures.Future | None = None) -> None:
        # Serialize with submit: no future can be queued after the fatal drain.
        pending = []
        with self._state_lock:
            if self._fatal is None:
                self._fatal = cause
                log.error("storage thread failed; explicit recovery required", exc_info=cause)
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                if item is not _SENTINEL:
                    pending.append(item[1])
        if active is not None:
            pending.append(active)
        for fut in pending:
            if not fut.done():
                fault = StorageFault("storage failed; transaction outcome may be unknown")
                fault.__cause__ = self._fatal
                try:
                    fut.set_exception(fault)
                except concurrent.futures.InvalidStateError:  # caller cancelled during the drain
                    pass

    def _run_one(self, conn: sqlite3.Connection, fn: Callable[[sqlite3.Connection], T],
                 fut: concurrent.futures.Future[T]) -> None:
        """One transaction: BEGIN IMMEDIATE, fn, COMMIT. The future completes only after COMMIT."""
        name = getattr(fn, "__name__", "")
        try:
            conn.execute("BEGIN IMMEDIATE")
            result = fn(conn)
            if self.fault_hook:
                self.fault_hook("before_commit", name)
            conn.execute("COMMIT")
        except BaseException as exc:  # the transaction must end either way
            try:
                _rollback(conn)
            except BaseException as rollback_error:
                exc.add_note(f"rollback failed: {rollback_error}")
                raise StorageFault("transaction could not be rolled back") from exc
            full = isinstance(exc, sqlite3.Error) and (
                getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL)
            code = (getattr(exc, "sqlite_errorcode", 0) or 0) & 0xff
            if code in (sqlite3.SQLITE_IOERR, sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB) or (
                isinstance(exc, sqlite3.ProgrammingError) and "closed" in str(exc)
            ):
                raise StorageFault("database failed; transaction outcome may be unknown") from exc
            fut.set_exception(StorageFull(str(exc)) if full else exc)
            return
        if self.fault_hook:
            self.fault_hook("after_commit", name)
        if self.after_commit:
            try:
                self.after_commit(conn)
            except (sqlite3.Error, OSError) as exc:
                # The rollback floor is a best-effort sidecar; the commit itself is durable.
                log.warning("post-commit hook failed: %s", exc)
        fut.set_result(result)

    def _release_lock(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None


def _rollback(conn: sqlite3.Connection) -> None:
    if conn.in_transaction:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            raise


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
    try:
        for pragma in ("journal_mode=WAL", "synchronous=FULL", "foreign_keys=ON", "busy_timeout=1000"):
            conn.execute(f"PRAGMA {pragma}")
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise StorageFault("database failed quick_check; quarantine and recover explicitly")
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if exists is None:
            _apply_schema(conn, schema_path.read_text())
        return conn
    except BaseException as exc:
        try:
            conn.close()
        except BaseException as close_error:
            exc.add_note(f"startup close failed: {close_error}")
        raise


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
