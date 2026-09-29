"""Startup recovery and the database rollback floor (docs/11 §4, docs/12 storage table, H05).

Floor: a 32-byte sidecar `<db>.floor` = journal_id(16) | max event sequence(8) | boot counter(8).
It is written (pwrite, no fsync) after every commit and fsynced at start. A database restored from
an older backup has a lower counter/sequence, or another journal id. Then the Host:
  * sets health fault DB_ROLLBACK (active) and rotates journal_id (old cursors -> 410),
  * closes every client epoch (clients must open a new one; nothing renews them silently),
  * turns every unfinished operation into INDETERMINATE + quarantined outbox: after a restore the
    Host cannot know what the lost run already sent, so it never re-sends blindly,
  * appends a critical HOST_DB_ROLLBACK event per domain.
Without a floor file (first start, or the sidecar lost too) a rollback cannot be detected: that is
stated, not hidden. The root/fleet high-water comparison belongs to the serial bridge (S13).
"""

from __future__ import annotations

import os
import sqlite3
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..api.codec import canonical_json
from ..events import journal
from ..events.journal import now_ms
from ..settings import Settings

_FLOOR = struct.Struct(">16sQQ")


@dataclass(frozen=True)
class Floor:
    journal_id: bytes
    max_sequence: int
    boot_counter: int


class FloorFile:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._fd: int | None = None

    def read(self) -> Floor | None:
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            return None
        return Floor(*_FLOOR.unpack(raw)) if len(raw) == _FLOOR.size else None

    def write(self, floor: Floor, sync: bool = False) -> None:
        if self._fd is None:
            self._fd = os.open(self._path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.pwrite(self._fd, _FLOOR.pack(floor.journal_id, floor.max_sequence, floor.boot_counter), 0)
        if sync:
            os.fsync(self._fd)

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def _meta_int(conn: sqlite3.Connection, key: str) -> int:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return int.from_bytes(row[0], "big") if row else 0


def current_floor(conn: sqlite3.Connection) -> Floor:
    jid = bytes(conn.execute("SELECT value FROM meta WHERE key='journal_id'").fetchone()[0])
    return Floor(jid, journal.max_sequence(conn), _meta_int(conn, "boot_counter"))


def set_fault(conn: sqlite3.Connection, code: str, detail: dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO health_faults(code,active,first_seen_utc_ms,last_seen_utc_ms,detail_json) "
        "VALUES(?,1,?,?,?) ON CONFLICT(code) DO UPDATE SET active=1, last_seen_utc_ms=excluded."
        "last_seen_utc_ms, detail_json=excluded.detail_json",
        (code, now_ms(), now_ms(), canonical_json(detail)))


def recover(conn: sqlite3.Connection, cfg: Settings, floor: Floor | None) -> str | None:
    """One transaction at start. Returns the rollback reason when one was detected."""
    reason = None
    now = current_floor(conn)
    if floor is not None:
        if floor.journal_id != now.journal_id:
            reason = "journal_mismatch"
        elif now.max_sequence < floor.max_sequence or now.boot_counter < floor.boot_counter:
            reason = "database_older_than_floor"
    conn.execute("INSERT INTO meta(key,value) VALUES('boot_counter',?) ON CONFLICT(key) DO UPDATE "
                 "SET value=excluded.value", ((now.boot_counter + 1).to_bytes(8, "big"),))
    # Written before the bridge exists: a possibly-sent operation waits for reconciliation.
    conn.execute("UPDATE outbox SET state='RECONCILE' WHERE state='SENDING'")
    if reason is not None:
        _quarantine(conn, cfg, reason)
    return reason


def _quarantine(conn: sqlite3.Connection, cfg: Settings, reason: str) -> None:
    set_fault(conn, "DB_ROLLBACK", {"reason": reason})
    conn.execute("UPDATE meta SET value=? WHERE key='journal_id'", (os.urandom(16),))
    conn.execute("UPDATE client_epochs SET state='CLOSED', closed_utc_ms=? WHERE state='OPEN'", (now_ms(),))
    evidence = canonical_json({"kind": "HOST_DB_ROLLBACK", "assurance": "UNKNOWN",
                               "details": {"reason": "DB_ROLLBACK_QUARANTINE"}})
    conn.execute("UPDATE outbox SET state='QUARANTINED' WHERE state IN ('QUEUED','SENDING','RECONCILE')")
    conn.execute("UPDATE operations SET state='FINAL', outcome='INDETERMINATE', "
                 "evidence_json=json_insert(evidence_json,'$[#]',json(?)) WHERE state!='FINAL'", (evidence,))
    for (domain,) in conn.execute("SELECT id FROM domains").fetchall():
        journal.append(conn, cfg, bytes(domain), "HOST_DB_ROLLBACK", True,
                       {"evidence": {"kind": "HOST_DB_ROLLBACK", "assurance": "UNKNOWN",
                                     "details": {"reason": reason}}}, admission=False)
