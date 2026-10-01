"""Plug point of the serial bridge (S13): the Host->root outbox and result recording.

The bridge is a consumer of these functions (run through `Hub.write`, one transaction each):
    items = claim(...)            # COMMIT first: external_write_possible=1 is durable BEFORE bytes leave
    ... write to the root ...
    record(...)                   # HOP/root evidence, receipts, APPLIED, EXPIRED, INDETERMINATE
    pending_reconcile(...)        # after a Host restart: ask the root by MessageId, then record()
Nothing here talks to the root and nothing invents evidence; a missing receipt stays missing.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from ..api.codec import canonical_json
from ..api.errors import ApiError, invalid, no_capacity
from ..events.journal import now_ms
from ..settings import Settings
from .ops import is_critical, operation_event, view_any

STATES = ("HOST_COMMITTED", "PENDING", "SENDING", "WAITING_RECEIPT", "FINAL", "WAIT_WAKE")
OUTCOMES = ("PENDING", "RECEIVED", "APPLIED", "REJECTED", "EXPIRED", "CANCELLED_NOT_SENT",
            "INDETERMINATE", "SUPERSEDED", "PARTIAL", "SUBMITTED")
ASSURANCES = ("END_VERIFIED", "LINK_VERIFIED", "SELF_REPORTED", "UNKNOWN")
# Late evidence never rolls the current outcome back (docs/08 §4). Rank 4 is final: a receipt
# arriving after REJECTED/EXPIRED is kept as history only. INDETERMINATE and CANCELLED_NOT_SENT
# (rank 1) are "we do not know / we did not send" and yield to real evidence.
_RANK = {"PENDING": 0, "CANCELLED_NOT_SENT": 1, "INDETERMINATE": 1, "SUBMITTED": 2, "PARTIAL": 3,
         "RECEIVED": 3, "APPLIED": 4, "REJECTED": 4, "EXPIRED": 4, "SUPERSEDED": 4}
# Explicit transition graph (S7-D17). WAIT_WAKE is a waiting phase, not a rank: it is entered from
# any live state and left towards sending, waiting for a receipt or the end. Nothing leaves FINAL;
# a request for any other transition is ignored (late/reordered reports never move a state back).
_NEXT = {
    "HOST_COMMITTED": {"PENDING", "SENDING", "WAITING_RECEIPT", "WAIT_WAKE", "FINAL"},
    "PENDING": {"SENDING", "WAITING_RECEIPT", "WAIT_WAKE", "FINAL"},
    "SENDING": {"WAITING_RECEIPT", "WAIT_WAKE", "FINAL"},
    "WAITING_RECEIPT": {"WAIT_WAKE", "FINAL"},
    "WAIT_WAKE": {"SENDING", "WAITING_RECEIPT", "FINAL"},
    "FINAL": set(),
}
# Evidence history per operation (S7-D18). Identical redelivered evidence is not added again. Past
# MAX_EVIDENCE - 1 entries only evidence that changes state/outcome is kept (up to
# EVIDENCE_TERMINAL_EXTRA more); the rest is dropped and one HOST_EVIDENCE_TRUNCATED marker says so.
MAX_EVIDENCE = 64
EVIDENCE_TERMINAL_EXTRA = 16


@dataclass(frozen=True)
class OutboxItem:
    operation: bytes
    domain: bytes
    op_type: str
    request: dict[str, Any]
    payload: bytes | None
    target: bytes | None
    message_id: bytes | None
    attempts: int


def claim(conn: sqlite3.Connection, cfg: Settings, adapter_incarnation: bytes,
          limit: int = 16, domain: bytes | None = None) -> list[OutboxItem]:
    """Takes due QUEUED entries by bounded weighted priority, FIFO within each class. Expired UTC deadlines are finalised as EXPIRED and
    never sent (the deadline is checked before the first transmission). Each returned entry is
    marked external_write_possible so that a crash after this commit is reconciled, not re-sent.
    With `domain` only that domain's entries are taken: the connected root serves one domain (FIX11-D14)."""
    expire_unsent(conn, cfg)
    items: list[OutboxItem] = []
    # A durable weighted round robin: controls and URGENT have reserved slots,
    # NORMAL/BULK still progress under a continuous urgent load. FIFO within a class.
    slots = ("CONTROL", "URGENT", "NORMAL", "URGENT", "URGENT", "BULK", "URGENT", "NORMAL")
    cursor_row = conn.execute("SELECT value FROM meta WHERE key='dispatch_cursor'").fetchone()
    cursor = int.from_bytes(cursor_row[0], "big") % len(slots) if cursor_row else 0
    for _ in range(max(0, min(limit, 64))):
        row = None
        for offset in range(len(slots)):
            pos = (cursor + offset) % len(slots)
            row = conn.execute(
                "SELECT o.id,o.domain,o.type,o.request_json,o.payload,o.target_device,o.message_id,"
                "o.expiry_utc_ms,b.attempts FROM outbox b JOIN operations o ON o.id=b.operation "
                "WHERE b.state='QUEUED' AND b.external_write_possible=0 AND o.state!='FINAL' "
                "AND (b.next_attempt_utc_ms IS NULL OR b.next_attempt_utc_ms<=:now) "
                "AND (:domain IS NULL OR o.domain=:domain) "
                "AND (CASE WHEN o.type!='MESSAGE' THEN 'CONTROL' ELSE "
                "json_extract(o.request_json,'$.priority') END)=:class "
                "AND (o.expiry_utc_ms IS NULL OR o.expiry_utc_ms>:now) "
                "ORDER BY o.rowid LIMIT 1", # committed insertion order survives UTC ties/corrections
                {"now": now_ms(), "domain": domain, "class": slots[pos]}).fetchone()
            if row is not None:
                cursor = (pos + 1) % len(slots)
                break
        if row is None:
            break
        op, item_domain, typ, req_json, payload, target, mid, expiry, attempts = row
        op, item_domain = bytes(op), bytes(item_domain)
        conn.execute("UPDATE outbox SET state='SENDING', adapter_incarnation=?, external_write_possible=1,"
                     " attempts=attempts+1 WHERE operation=?", (adapter_incarnation, op))
        conn.execute("UPDATE operations SET state='SENDING' WHERE id=?", (op,))
        items.append(OutboxItem(op, item_domain, typ, json.loads(req_json),
                                bytes(payload) if payload is not None else None,
                                bytes(target) if target is not None else None,
                                bytes(mid) if mid is not None else None, attempts + 1))
    if items:
        conn.execute("INSERT INTO meta(key,value) VALUES('dispatch_cursor',?) ON CONFLICT(key) "
                     "DO UPDATE SET value=excluded.value", (cursor.to_bytes(1, "big"),))
    return items


def expire_unsent(conn: sqlite3.Connection, cfg: Settings, limit: int = 64) -> int:
    """Only UTC deadlines whose outbox proves no external write. Bounded, indexed, offline-safe."""
    rows = conn.execute(
        "SELECT o.id FROM operations o JOIN outbox b ON b.operation=o.id "
        "WHERE o.state!='FINAL' AND o.expiry_utc_ms IS NOT NULL AND o.expiry_utc_ms<=? "
        "AND b.state='QUEUED' AND b.external_write_possible=0 ORDER BY o.expiry_utc_ms LIMIT ?",
        (now_ms(), limit)).fetchall()
    for (op,) in rows:
        record(conn, cfg, bytes(op), state="FINAL", outcome="EXPIRED", outbox_state="DONE",
               evidence={"kind": "HOST_DEADLINE_EXPIRED", "assurance": "SELF_REPORTED",
                         "details": {"reason": "deadline passed before first transmission"}})
    return len(rows)


def next_expiry(conn: sqlite3.Connection) -> int | None:
    row = conn.execute(
        "SELECT o.expiry_utc_ms FROM operations o JOIN outbox b ON b.operation=o.id "
        "WHERE o.state!='FINAL' AND o.expiry_utc_ms IS NOT NULL "
        "AND b.state='QUEUED' AND b.external_write_possible=0 ORDER BY o.expiry_utc_ms LIMIT 1").fetchone()
    return row[0] if row else None


def release_unwritten(conn: sqlite3.Connection, cfg: Settings, op_id: bytes) -> None:
    """The bridge proves that not a single byte of the request reached the root (e.g. the frame
    was refused before the write). Only then is it safe to queue it again, unless the owner asked
    to cancel meanwhile: then the durable cancel request is honoured and the operation ends as
    CANCELLED_NOT_SENT (S7-D7)."""
    row = conn.execute("SELECT o.evidence_json FROM operations o JOIN outbox b ON b.operation=o.id "
                       "WHERE o.id=? AND b.state='SENDING'", (op_id,)).fetchone()
    if row is None:
        return
    conn.execute("UPDATE outbox SET external_write_possible=0 WHERE operation=?", (op_id,))
    if any(e["kind"] == "HOST_CANCEL_REQUESTED" for e in json.loads(row[0])):
        record(conn, cfg, op_id, state="FINAL", outcome="CANCELLED_NOT_SENT", outbox_state="CANCELLED",
               evidence={"kind": "HOST_CANCELLED_NOT_SENT", "assurance": "SELF_REPORTED",
                         "details": {"reason": "cancel requested; the bridge proved nothing was written"}})
        return
    conn.execute("UPDATE outbox SET state='QUEUED' WHERE operation=?", (op_id,))
    conn.execute("UPDATE operations SET state='HOST_COMMITTED' WHERE id=?", (op_id,))


def pending_reconcile(conn: sqlite3.Connection, domain: bytes | None = None) -> list[tuple[bytes, bytes | None]]:
    """(operation, message_id) that were possibly written before a Host restart. Do NOT re-send:
    query the root by MessageId; with no answer record INDETERMINATE. Only the connected root's domain
    is asked (FIX11-D14): another domain's root cannot vouch for these."""
    return [(bytes(o), bytes(m) if m is not None else None) for o, m in conn.execute(
        "SELECT b.operation,o.message_id FROM outbox b JOIN operations o ON o.id=b.operation "
        "WHERE b.state='RECONCILE' AND (:domain IS NULL OR o.domain=:domain)", {"domain": domain})]


def cancel_requests(conn: sqlite3.Connection, domain: bytes | None = None) -> list[bytes]:
    """Operations whose owner asked to cancel while they may already be on the wire (of `domain` if given)."""
    return [bytes(r[0]) for r in conn.execute(
        "SELECT o.id FROM operations o WHERE o.state!='FINAL' AND (:domain IS NULL OR o.domain=:domain) AND EXISTS "
        "(SELECT 1 FROM json_each(o.evidence_json) WHERE json_extract(value,'$.kind')='HOST_CANCEL_REQUESTED')",
        {"domain": domain})]


def record(conn: sqlite3.Connection, cfg: Settings, op_id: bytes, *, state: str | None = None,
           outcome: str | None = None, evidence: dict[str, Any] | None = None,
           message_id: bytes | None = None, outbox_state: str | None = None) -> dict[str, Any]:
    """Appends evidence and advances state/outcome monotonically, emitting one journal event when
    something changed. Evidence is history: it is added even to a FINAL or cancelled operation.
    A message_id that differs from the one the operation already has is a receipt for another
    message: ApiError 409 before anything is written (the caller's transaction rolls back)."""
    if state is not None and state not in STATES or outcome is not None and outcome not in OUTCOMES:
        raise invalid("unknown operation state/outcome")
    if evidence is not None and evidence.get("assurance") not in ASSURANCES:
        raise invalid("evidence needs a valid assurance")
    row = conn.execute("SELECT domain,type,request_json,state,outcome,evidence_json,message_id "
                       "FROM operations WHERE id=?", (op_id,)).fetchone()
    if row is None:
        raise ApiError(404, "NOT_FOUND", "operation not found")
    domain, typ, req_json, cur_state, cur_outcome, ev_json, cur_mid = row
    if message_id is not None and cur_mid is not None and bytes(cur_mid) != message_id:
        raise ApiError(409, "CONFLICT", "receipt belongs to another message id")
    ev_list = json.loads(ev_json)
    changed = False
    if state is not None and state in _NEXT[cur_state]:
        changed = True
        cur_state = state
    if outcome is not None and _RANK[outcome] > _RANK[cur_outcome]:
        changed = True
        cur_outcome = outcome
    if message_id is not None and cur_mid is None:
        cur_mid, changed = message_id, True
    stored = None  # the evidence that really went into the row (and goes into the event)
    marker = False
    if evidence is not None and evidence not in ev_list:  # redelivery of the same report adds nothing
        if changed and len(ev_list) < MAX_EVIDENCE + EVIDENCE_TERMINAL_EXTRA or len(ev_list) < MAX_EVIDENCE - 1:
            stored = evidence
        elif changed:
            raise no_capacity("evidence")  # never accept an outcome whose proof cannot be kept
        else:
            marker = all(e["kind"] != "HOST_EVIDENCE_TRUNCATED" for e in ev_list)
    if stored is None and not changed and not marker:
        return view_any(conn, op_id)
    if stored is not None:
        ev_list.append(stored)
    if marker:
        ev_list.append({"kind": "HOST_EVIDENCE_TRUNCATED", "assurance": "SELF_REPORTED",
                        "details": {"reason": "evidence history is full; later reports were not kept"}})
    conn.execute("UPDATE operations SET state=?, outcome=?, evidence_json=?, message_id=? WHERE id=?",
                 (cur_state, cur_outcome, canonical_json(ev_list), cur_mid, op_id))
    if outbox_state is not None:
        conn.execute("UPDATE outbox SET state=? WHERE operation=?", (outbox_state, op_id))
    elif cur_state == "FINAL":
        conn.execute("UPDATE outbox SET state='DONE' WHERE operation=? AND state IN ('SENDING','RECONCILE')",
                     (op_id,))
    if stored is not None or changed:
        operation_event(conn, cfg, op_id, bytes(domain), is_critical(typ, json.loads(req_json)),
                        stored["kind"] if stored else cur_state, evidence=stored)
    return view_any(conn, op_id)
