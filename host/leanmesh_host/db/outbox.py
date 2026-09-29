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
from ..api.errors import ApiError, invalid
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
_STATE_RANK = {s: i for i, s in enumerate(STATES)}


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
          limit: int = 16) -> list[OutboxItem]:
    """Takes due QUEUED entries, oldest first. Expired UTC deadlines are finalised as EXPIRED and
    never sent (the deadline is checked before the first transmission). Each returned entry is
    marked external_write_possible so that a crash after this commit is reconciled, not re-sent."""
    items: list[OutboxItem] = []
    rows = conn.execute(
        "SELECT o.id,o.domain,o.type,o.request_json,o.payload,o.target_device,o.message_id,"
        "o.expiry_utc_ms,b.attempts FROM outbox b JOIN operations o ON o.id=b.operation "
        "WHERE b.state='QUEUED' AND (b.next_attempt_utc_ms IS NULL OR b.next_attempt_utc_ms<=?) "
        "ORDER BY o.created_utc_ms, o.id LIMIT ?", (now_ms(), limit)).fetchall()
    for op, domain, typ, req_json, payload, target, mid, expiry, attempts in rows:
        op, domain = bytes(op), bytes(domain)
        if expiry is not None and expiry <= now_ms():
            record(conn, cfg, op, state="FINAL", outcome="EXPIRED",
                   evidence={"kind": "HOST_DEADLINE_EXPIRED", "assurance": "SELF_REPORTED",
                             "details": {"reason": "deadline passed before first transmission"}},
                   outbox_state="DONE")
            continue
        conn.execute("UPDATE outbox SET state='SENDING', adapter_incarnation=?, external_write_possible=1,"
                     " attempts=attempts+1 WHERE operation=?", (adapter_incarnation, op))
        conn.execute("UPDATE operations SET state='SENDING' WHERE id=?", (op,))
        items.append(OutboxItem(op, domain, typ, json.loads(req_json),
                                bytes(payload) if payload is not None else None,
                                bytes(target) if target is not None else None,
                                bytes(mid) if mid is not None else None, attempts + 1))
    return items


def release_unwritten(conn: sqlite3.Connection, op_id: bytes) -> None:
    """The bridge proves that not a single byte of the request reached the root (e.g. the frame
    was refused before the write). Only then is it safe to queue it again."""
    conn.execute("UPDATE outbox SET state='QUEUED', external_write_possible=0 WHERE operation=? "
                 "AND state='SENDING'", (op_id,))
    conn.execute("UPDATE operations SET state='HOST_COMMITTED' WHERE id=? AND state='SENDING'", (op_id,))


def pending_reconcile(conn: sqlite3.Connection) -> list[tuple[bytes, bytes | None]]:
    """(operation, message_id) that were possibly written before a Host restart. Do NOT re-send:
    query the root by MessageId; with no answer record INDETERMINATE."""
    return [(bytes(o), bytes(m) if m is not None else None) for o, m in conn.execute(
        "SELECT b.operation,o.message_id FROM outbox b JOIN operations o ON o.id=b.operation "
        "WHERE b.state='RECONCILE'")]


def cancel_requests(conn: sqlite3.Connection) -> list[bytes]:
    """Operations whose owner asked to cancel while they may already be on the wire."""
    return [bytes(r[0]) for r in conn.execute(
        "SELECT o.id FROM operations o WHERE o.state!='FINAL' AND EXISTS "
        "(SELECT 1 FROM json_each(o.evidence_json) WHERE json_extract(value,'$.kind')='HOST_CANCEL_REQUESTED')")]


def record(conn: sqlite3.Connection, cfg: Settings, op_id: bytes, *, state: str | None = None,
           outcome: str | None = None, evidence: dict[str, Any] | None = None,
           message_id: bytes | None = None, outbox_state: str | None = None) -> dict[str, Any]:
    """Appends evidence and advances state/outcome monotonically, emitting one journal event when
    something changed. Evidence is history: it is added even to a FINAL or cancelled operation."""
    if state is not None and state not in STATES or outcome is not None and outcome not in OUTCOMES:
        raise invalid("unknown operation state/outcome")
    if evidence is not None and evidence.get("assurance") not in ASSURANCES:
        raise invalid("evidence needs a valid assurance")
    row = conn.execute("SELECT domain,type,request_json,state,outcome,evidence_json,message_id "
                       "FROM operations WHERE id=?", (op_id,)).fetchone()
    if row is None:
        raise ApiError(404, "NOT_FOUND", "operation not found")
    domain, typ, req_json, cur_state, cur_outcome, ev_json, cur_mid = row
    changed = evidence is not None
    ev_list = json.loads(ev_json) + ([evidence] if evidence is not None else [])
    if state is not None and cur_state != "FINAL" and _STATE_RANK[state] >= _STATE_RANK[cur_state]:
        changed |= state != cur_state
        cur_state = state
    if outcome is not None and _RANK[outcome] > _RANK[cur_outcome]:
        changed = True
        cur_outcome = outcome
    if message_id is not None and cur_mid is None:
        cur_mid, changed = message_id, True
    if not changed:
        return view_any(conn, op_id)
    conn.execute("UPDATE operations SET state=?, outcome=?, evidence_json=?, message_id=? WHERE id=?",
                 (cur_state, cur_outcome, canonical_json(ev_list), cur_mid, op_id))
    if outbox_state is not None:
        conn.execute("UPDATE outbox SET state=? WHERE operation=?", (outbox_state, op_id))
    elif cur_state == "FINAL":
        conn.execute("UPDATE outbox SET state='DONE' WHERE operation=? AND state IN ('SENDING','RECONCILE')",
                     (op_id,))
    operation_event(conn, cfg, op_id, bytes(domain), is_critical(typ, json.loads(req_json)),
                    evidence["kind"] if evidence else cur_state)
    return view_any(conn, op_id)
