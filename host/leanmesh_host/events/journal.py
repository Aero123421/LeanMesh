"""Event journal, consumer ACK and the root->Host inbox (docs/11 §5, §7). All functions run inside
one storage-thread transaction (`conn` is inside BEGIN IMMEDIATE); none commits.

Event cursor = `journal_id:seq`, seq = AUTOINCREMENT. Retention rules:
  * critical events (operation progress of DURABLE/RECEIVED/APPLIED messages, all controls, inbox
    messages) are protected until every consumer of the domain acknowledged them; a full journal
    with only protected events rejects new admissions (507) and never deletes them;
  * non-critical events are dropped first, replaced in place by one EVENT_GAP tombstone per domain,
    so a reader sees the loss inline instead of a silent skip;
  * events <= min(consumer ack) may be deleted; that prefix deletion moves the per-domain floor
    (`meta.purged:<domain>`) and a reader behind it gets 410 CURSOR_GAP with oldest/latest.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from ..api.codec import U63_MAX, canonical_json, encode_b64
from ..api.errors import ApiError, invalid, no_capacity
from ..settings import Settings

_CURSOR = re.compile(r"^([0-9a-f]{32}):([0-9]+)$")
_PAGE_BYTES = 256 * 1024
_PRUNE_BATCH = 512


def now_ms() -> int:
    return int(time.time() * 1000)


def _journal_hex(conn: sqlite3.Connection) -> str:
    return bytes(conn.execute("SELECT value FROM meta WHERE key='journal_id'").fetchone()[0]).hex()


def max_sequence(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name='events'").fetchone()
    return row[0] if row else 0


def _purged(conn: sqlite3.Connection, domain: bytes) -> int:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (f"purged:{domain.hex()}",)).fetchone()
    return int.from_bytes(row[0], "big") if row else 0


def _set_purged(conn: sqlite3.Connection, domain: bytes, seq: int) -> None:
    conn.execute(
        "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value "
        "WHERE length(excluded.value)=8 AND excluded.value>meta.value",  # big-endian: monotonic
        (f"purged:{domain.hex()}", seq.to_bytes(8, "big")))


def _oldest_position(conn: sqlite3.Connection, domain: bytes) -> int:
    row = conn.execute("SELECT MIN(sequence) FROM events WHERE domain=?", (domain,)).fetchone()
    return row[0] - 1 if row[0] is not None else _purged(conn, domain)


def cursor_text(conn: sqlite3.Connection, seq: int) -> str:
    return f"{_journal_hex(conn)}:{seq}"


def _gap(conn: sqlite3.Connection, domain: bytes, why: str) -> ApiError:
    return ApiError(410, "CURSOR_GAP", f"cursor is not readable: {why}",
                    journal_id=_journal_hex(conn),
                    oldest_cursor=cursor_text(conn, _oldest_position(conn, domain)),
                    latest_cursor=cursor_text(conn, max_sequence(conn)))


def parse_cursor(conn: sqlite3.Connection, domain: bytes, text: str) -> int:
    """Validates a cursor against this journal: wrong journal, behind the floor or in the future
    -> 410 with the current journal id (never silently continue from "now")."""
    m = _CURSOR.match(text)
    if m is None or int(m.group(2)) > U63_MAX:
        raise invalid("malformed cursor")
    seq = int(m.group(2))
    if m.group(1) != _journal_hex(conn):
        raise _gap(conn, domain, "other journal")
    if seq > max_sequence(conn):
        raise _gap(conn, domain, "cursor is ahead of the journal")
    if seq < _purged(conn, domain):
        raise _gap(conn, domain, "events before the cursor were deleted")
    return seq


# ---- append and capacity ---------------------------------------------------------------------
def _count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def make_room(conn: sqlite3.Connection, limit: int) -> None:
    """Ensures one more event fits under `limit`, deleting only what the rules above allow."""
    if max_sequence(conn) < limit or _count(conn) < limit:  # seq >= row count: cheap common case
        return
    _compact_noncritical(conn)
    if _count(conn) >= limit:
        _delete_acknowledged(conn, retention_ms=0)
    if _count(conn) >= limit:
        raise no_capacity("events")


def _compact_noncritical(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        "SELECT domain, sequence FROM events WHERE critical=0 ORDER BY sequence LIMIT ?",
        (_PRUNE_BATCH,)).fetchall()
    per_domain: dict[bytes, list[int]] = {}
    for domain, seq in rows:
        per_domain.setdefault(bytes(domain), []).append(seq)
    for seqs in per_domain.values():
        if len(seqs) < 2:
            continue  # nothing to free: a lone event or lone tombstone
        keep = seqs[-1]
        conn.execute("UPDATE events SET kind='EVENT_GAP', operation=NULL, origin=NULL, "
                     "message_id=NULL, payload_json='{}' WHERE sequence=?", (keep,))
        conn.executemany("DELETE FROM events WHERE sequence=?", [(s,) for s in seqs[:-1]])


def _min_ack(conn: sqlite3.Connection, domain: bytes) -> int | None:
    row = conn.execute("SELECT MIN(ack_sequence), COUNT(*) FROM consumers WHERE domain=?",
                       (domain,)).fetchone()
    return row[0] if row[1] else None  # no consumer: nothing is acknowledged


def _delete_acknowledged(conn: sqlite3.Connection, retention_ms: int) -> None:
    """Prefix deletion of events every consumer of the domain has acknowledged."""
    cutoff = now_ms() - retention_ms
    for (raw,) in conn.execute("SELECT DISTINCT domain FROM consumers").fetchall():
        domain = bytes(raw)
        ack = _min_ack(conn, domain)
        if ack is None:
            continue
        last = conn.execute(
            "SELECT MAX(sequence) FROM (SELECT sequence FROM events WHERE domain=? AND sequence<=? "
            "AND created_utc_ms<=? ORDER BY sequence LIMIT ?)",
            (domain, ack, cutoff, _PRUNE_BATCH)).fetchone()[0]
        if last is not None:
            conn.execute("DELETE FROM events WHERE domain=? AND sequence<=?", (domain, last))
            _set_purged(conn, domain, last)


def append(conn: sqlite3.Connection, cfg: Settings, domain: bytes, kind: str, critical: bool,
           payload: dict[str, Any], operation: bytes | None = None, origin: bytes | None = None,
           message_id: bytes | None = None, admission: bool = True) -> int:
    """Adds one event. `admission=False` (progress of an accepted operation) may use the margin."""
    make_room(conn, cfg.max_events if admission else cfg.max_events + cfg.event_margin)
    cur = conn.execute(
        "INSERT INTO events(domain,kind,operation,origin,message_id,critical,payload_json,created_utc_ms)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (domain, kind, operation, origin, message_id, int(critical), canonical_json(payload), now_ms()))
    assert cur.lastrowid is not None
    return cur.lastrowid


# ---- reading ----------------------------------------------------------------------------------
_EVENT_FIELDS = ("intent_hash", "assignment_generation", "payload_b64", "evidence")


def _event_json(conn: sqlite3.Connection, journal: str, row: tuple[Any, ...]) -> dict[str, Any]:
    seq, kind, domain, origin, message_id, payload_json = row
    body = json.loads(payload_json)
    out: dict[str, Any] = {"cursor": f"{journal}:{seq}", "kind": kind, "domain_id": bytes(domain).hex()}
    if origin is not None:
        out["origin"] = bytes(origin).hex()
    if message_id is not None:
        out["message_id"] = bytes(message_id).hex()
    out.update({k: body[k] for k in _EVENT_FIELDS if k in body})
    return out


def read_page(conn: sqlite3.Connection, domain: bytes, after: str | None, limit: int,
              byte_budget: int = _PAGE_BYTES) -> dict[str, Any]:
    _require_domain(conn, domain)
    start = parse_cursor(conn, domain, after) if after is not None else 0
    journal = _journal_hex(conn)
    rows = conn.execute(
        "SELECT sequence,kind,domain,origin,message_id,payload_json FROM events "
        "WHERE domain=? AND sequence>? ORDER BY sequence LIMIT ?", (domain, start, limit)).fetchall()
    events: list[dict[str, Any]] = []
    used = 0
    for row in rows:
        event = _event_json(conn, journal, row)
        used += len(row[5]) + 200
        if events and used > byte_budget:
            break
        events.append(event)
    last = int(events[-1]["cursor"].rpartition(":")[2]) if events else start
    return {"events": events, "next_cursor": f"{journal}:{last}",
            "oldest_cursor": cursor_text(conn, _oldest_position(conn, domain))}


def _require_domain(conn: sqlite3.Connection, domain: bytes) -> None:
    if conn.execute("SELECT 1 FROM domains WHERE id=?", (domain,)).fetchone() is None:
        raise ApiError(404, "NOT_FOUND", "domain not found")


# ---- consumer ACK -------------------------------------------------------------------------------
def ack(conn: sqlite3.Connection, principal: str, name: str, domain: bytes, journal_hex: str,
        sequence: int) -> dict[str, Any]:
    """Monotonic, idempotent. Owner = the (principal, name) primary key. Rejects a foreign journal
    (410) and a position the journal never reached (409): a future ACK would let the Host delete
    events nobody has read."""
    _require_domain(conn, domain)
    if journal_hex != _journal_hex(conn):
        raise _gap(conn, domain, "other journal")
    top = conn.execute("SELECT MAX(sequence) FROM events WHERE domain=?", (domain,)).fetchone()[0]
    if sequence > max(top or 0, _purged(conn, domain)):
        raise ApiError(409, "CONFLICT", "acknowledgement is ahead of the journal",
                       latest_cursor=cursor_text(conn, max(top or 0, _purged(conn, domain))))
    conn.execute(
        "INSERT INTO consumers(principal,name,domain,journal_id,ack_sequence) VALUES(?,?,?,?,?) "
        "ON CONFLICT(principal,name,domain) DO UPDATE SET ack_sequence=max(ack_sequence, excluded.ack_sequence), "
        "journal_id=excluded.journal_id",
        (principal, name, domain, bytes.fromhex(journal_hex), sequence))
    current = conn.execute("SELECT ack_sequence FROM consumers WHERE principal=? AND name=? AND domain=?",
                           (principal, name, domain)).fetchone()[0]
    return {"events": [], "next_cursor": cursor_text(conn, current),
            "oldest_cursor": cursor_text(conn, _oldest_position(conn, domain))}


def prune_acknowledged(conn: sqlite3.Connection, cfg: Settings) -> None:
    _delete_acknowledged(conn, cfg.event_retention_ms)


# ---- root -> Host inbox (called by the serial bridge before HOST_STORE_ACK) ---------------------
class InboxConflict(Exception):
    """Same (domain, origin, assignment_generation, message_id) with a different intent_hash."""


@dataclass(frozen=True)
class InboxCommit:
    cursor: str
    duplicate: bool


def ingest(conn: sqlite3.Connection, cfg: Settings, domain: bytes, origin: bytes,
           assignment_generation: int, message_id: bytes, intent_hash: bytes, payload: bytes,
           assurance: dict[str, Any]) -> InboxCommit:
    """Dedup + inbox row + consumer-visible event in the caller's single transaction. The bridge
    sends HOST_STORE_ACK only after this returns and the transaction committed. A redelivery after
    ACK loss returns the stored commit; a full journal raises ApiError(507) so no ACK is sent."""
    _require_domain(conn, domain)
    key = (domain, origin, assignment_generation, message_id)
    row = conn.execute("SELECT intent_hash FROM inbox WHERE domain=? AND origin=? AND "
                       "assignment_generation=? AND message_id=?", key).fetchone()
    if row is not None:
        if bytes(row[0]) != intent_hash:
            raise InboxConflict("message id reused with another intent")
        ev = conn.execute("SELECT sequence FROM events WHERE domain=? AND kind='MESSAGE_RECEIVED' "
                          "AND origin=? AND message_id=?", (domain, origin, message_id)).fetchone()
        return InboxCommit(cursor_text(conn, ev[0]) if ev else cursor_text(conn, 0), True)
    seq = append(conn, cfg, domain, "MESSAGE_RECEIVED", True, {
        "intent_hash": intent_hash.hex(), "assignment_generation": str(assignment_generation),
        "payload_b64": encode_b64(payload), "evidence": assurance,
    }, origin=origin, message_id=message_id)
    conn.execute("INSERT INTO inbox(domain,origin,assignment_generation,message_id,intent_hash,payload,"
                 "assurance_json,committed_utc_ms) VALUES(?,?,?,?,?,?,?,?)",
                 (domain, origin, assignment_generation, message_id, intent_hash, payload,
                  canonical_json(assurance), now_ms()))
    return InboxCommit(cursor_text(conn, seq), False)
