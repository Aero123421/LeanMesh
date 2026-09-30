"""Client epochs, operation admission (docs/11 §3-§4) and operation reads/cancel.

`accept()` is one storage-thread transaction: idempotency lookup -> epoch check -> capacity ->
INSERT operation + outbox + event. The HTTP 202 is sent only after this transaction COMMITs; the
bridge hears about the outbox row only after that (Hub.write bumps after commit).
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..api.codec import canonical_json
from ..api.errors import ApiError, no_capacity, not_found
from ..events import journal
from . import budget
from ..events.journal import now_ms
from ..settings import Settings

MAX_OPEN_EPOCHS_PER_PRINCIPAL = 64
_UNFINISHED = "state!='FINAL'"


# ---- epochs -----------------------------------------------------------------------------------
def open_epoch(conn: sqlite3.Connection, cfg: Settings, principal: str, idem_key: str,
               request_id: str) -> dict[str, str]:
    """Host-issued 16 B epoch. Retries with the same Idempotency-Key + request_id return the same
    epoch (meta row `epoch-open:<principal>:<key>` = request_hash || epoch id); a different
    request_id under that key is a 409."""
    key = f"epoch-open:{principal}:{idem_key}"
    want = bytes.fromhex(request_id)
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    if row is not None:
        stored = bytes(row[0])
        if stored[:16] != want:
            raise ApiError(409, "CONFLICT", "Idempotency-Key reused with a different request")
        epoch = stored[16:]
        state = conn.execute("SELECT state FROM client_epochs WHERE id=?", (epoch,)).fetchone()[0]
        return {"id": epoch.hex(), "state": state}
    open_count, total = conn.execute(
        "SELECT COALESCE(SUM(state='OPEN'),0), COUNT(*) FROM client_epochs WHERE principal=?",
        (principal,)).fetchone()
    if open_count >= MAX_OPEN_EPOCHS_PER_PRINCIPAL:
        raise no_capacity("open_epochs", 429, retry_after_ms=1000)
    if total >= cfg.max_epochs_per_principal:
        total -= _prune_epochs(conn, cfg)
        if total >= cfg.max_epochs_per_principal:
            raise no_capacity("epochs", 429, retry_after_ms=60000)
    budget.room(conn, cfg)
    epoch = os.urandom(16)
    conn.execute("INSERT INTO client_epochs(id,principal,state,created_utc_ms) VALUES(?,?,'OPEN',?)",
                 (epoch, principal, now_ms()))
    conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", (key, want + epoch))
    return {"id": epoch.hex(), "state": "OPEN"}


def _prune_epochs(conn: sqlite3.Connection, cfg: Settings) -> int:
    """Drops closed epochs that no operation refers to once past retention, with their
    idempotency record. An epoch that has operations is history and stays (S7-D15)."""
    old = conn.execute(
        "SELECT id FROM client_epochs e WHERE state='CLOSED' AND closed_utc_ms<=? AND NOT EXISTS "
        "(SELECT 1 FROM operations o WHERE o.client_epoch=e.id) ORDER BY closed_utc_ms LIMIT 64",
        (now_ms() - cfg.epoch_retention_ms,)).fetchall()
    for (epoch,) in old:
        conn.execute("DELETE FROM meta WHERE key LIKE 'epoch-open:%' AND substr(value,17)=?", (epoch,))
        conn.execute("DELETE FROM client_epochs WHERE id=?", (epoch,))
    return len(old)


def prune_finished(conn: sqlite3.Connection, cfg: Settings, limit: int = 64) -> int:
    """Bounded retention of terminal operations (FIX11-D8): a FINAL operation of an epoch that was closed more than
    cfg.operation_retention_ms ago is deleted with its outbox row and group targets; journal events stay (they have
    their own retention and consumer pins) and only lose their operation link. A replay of its Idempotency-Key then
    meets a closed epoch (410 EPOCH_CLOSED): the window in which a replay returns the stored result is that
    retention, and a pruned operation can never be sent a second time."""
    old = conn.execute(
        "SELECT o.id FROM operations o JOIN client_epochs e ON e.id=o.client_epoch "
        "WHERE o.state='FINAL' AND e.state='CLOSED' AND e.closed_utc_ms<=? LIMIT ?",
        (now_ms() - cfg.operation_retention_ms, limit)).fetchall()
    for (op,) in old:
        conn.execute("UPDATE operations SET superseded_by=NULL WHERE superseded_by=?", (op,))
        conn.execute("UPDATE events SET operation=NULL WHERE operation=?", (op,))
        conn.execute("DELETE FROM group_targets WHERE operation=?", (op,))
        conn.execute("DELETE FROM outbox WHERE operation=?", (op,))
        conn.execute("DELETE FROM operations WHERE id=?", (op,))
    return len(old)


def close_epoch(conn: sqlite3.Connection, principal: str, epoch: bytes) -> dict[str, str]:
    """Monotonic and idempotent. Closing never cancels operations already committed."""
    row = conn.execute("SELECT state FROM client_epochs WHERE id=? AND principal=?",
                       (epoch, principal)).fetchone()
    if row is None:
        raise not_found("epoch")
    if row[0] == "OPEN":
        conn.execute("UPDATE client_epochs SET state='CLOSED', closed_utc_ms=? WHERE id=?",
                     (now_ms(), epoch))
    return {"id": epoch.hex(), "state": "CLOSED"}


# ---- views ------------------------------------------------------------------------------------
_OP_COLUMNS = "id,state,outcome,message_id,evidence_json,superseded_by"


def _view(row: tuple[Any, ...]) -> dict[str, Any]:
    op_id, state, outcome, message_id, evidence_json, superseded_by = row
    evidence = json.loads(evidence_json)
    out: dict[str, Any] = {"id": bytes(op_id).hex(), "state": state, "outcome": outcome,
                           "evidence": evidence}
    reason = next((e["details"]["reason"] for e in reversed(evidence)
                   if "reason" in e.get("details", {})), None)
    if reason:
        out["reason"] = reason
    if message_id is not None:
        out["message_id"] = bytes(message_id).hex()
    if superseded_by is not None:
        out["superseded_by"] = bytes(superseded_by).hex()
    return out


def get_operation(conn: sqlite3.Connection, principal: str, op_id: bytes) -> dict[str, Any]:
    row = conn.execute(f"SELECT {_OP_COLUMNS} FROM operations WHERE id=? AND principal=?",
                       (op_id, principal)).fetchone()
    if row is None:
        raise not_found("operation")
    return _view(row)


def view_any(conn: sqlite3.Connection, op_id: bytes) -> dict[str, Any]:
    return _view(conn.execute(f"SELECT {_OP_COLUMNS} FROM operations WHERE id=?", (op_id,)).fetchone())


# ---- admission --------------------------------------------------------------------------------
@dataclass(frozen=True)
class Submission:
    principal: str
    domain: bytes
    epoch: bytes
    idem_key: str
    op_type: str  # "MESSAGE" or the control type
    request: dict[str, Any]  # canonical, secret-free request document (stored as request_json)
    request_hash: bytes
    payload: bytes | None
    target: bytes | None
    expiry_utc_ms: int | None
    critical: bool
    latest_key: str | None = None  # set for LATEST: coalesce_key (u63 string)


def accept(conn: sqlite3.Connection, cfg: Settings, sub: Submission,
           precheck: Callable[[sqlite3.Connection], None] | None = None) -> tuple[dict[str, Any], bool]:
    """Returns (operation view, created). created=False is an idempotent replay: nothing was
    written, so nothing is re-sent."""
    if conn.execute("SELECT 1 FROM domains WHERE id=?", (sub.domain,)).fetchone() is None:
        raise not_found("domain")
    row = conn.execute(
        f"SELECT {_OP_COLUMNS},request_hash FROM operations WHERE principal=? AND domain=? AND type=? "
        "AND client_epoch=? AND idempotency_key=?",
        (sub.principal, sub.domain, sub.op_type, sub.epoch, sub.idem_key)).fetchone()
    if row is not None:
        if bytes(row[6]) != sub.request_hash:
            raise ApiError(409, "CONFLICT", "Idempotency-Key reused with a different request")
        return _view(row[:6]), False
    epoch = conn.execute("SELECT state FROM client_epochs WHERE id=? AND principal=?",
                         (sub.epoch, sub.principal)).fetchone()
    if epoch is None:
        raise not_found("client epoch")
    if epoch[0] != "OPEN":
        raise ApiError(410, "EPOCH_CLOSED", "client epoch is closed; open a new epoch")
    if precheck is not None:  # request-specific state checks (destination, revision), replay excluded
        precheck(conn)
    prune_finished(conn, cfg)
    open_ops = conn.execute(f"SELECT COUNT(*) FROM operations WHERE {_UNFINISHED}").fetchone()[0]
    if open_ops >= cfg.max_open_operations:
        raise no_capacity("open_operations", 429, retry_after_ms=1000)
    journal.check_reserve(conn, cfg, open_ops)  # every open op keeps room for its progress/terminal events
    budget.room(conn, cfg)
    op_id = os.urandom(16)
    conn.execute(
        "INSERT INTO operations(id,principal,domain,type,client_epoch,idempotency_key,request_hash,"
        "target_device,request_json,payload,state,outcome,expiry_utc_ms,created_utc_ms) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,'HOST_COMMITTED','PENDING',?,?)",
        (op_id, sub.principal, sub.domain, sub.op_type, sub.epoch, sub.idem_key, sub.request_hash,
         sub.target, canonical_json(sub.request), sub.payload, sub.expiry_utc_ms, now_ms()))
    conn.execute("INSERT INTO outbox(operation,state) VALUES(?,'QUEUED')", (op_id,))
    operation_event(conn, cfg, op_id, sub.domain, sub.critical, "HOST_COMMITTED", admission=True)
    if sub.latest_key is not None:
        _supersede_unsent(conn, cfg, sub, op_id)
    return view_any(conn, op_id), True


def operation_event(conn: sqlite3.Connection, cfg: Settings, op_id: bytes, domain: bytes,
                    critical: bool, kind: str, admission: bool = False,
                    evidence: dict[str, Any] | None = None) -> None:
    """One OPERATION_UPDATE event. Host-generated evidence (HOST_COMMITTED, cancel, ...) is the
    Host's own DB fact (SELF_REPORTED). Evidence handed in by the bridge is never re-labelled: the
    event carries it verbatim inside a HOST_RECORDED wrapper (S7-D24).

    Each operation may use at most cfg.op_event_reserve events: progress events beyond that are
    coalesced (the operation row keeps every evidence entry), the terminal event is always kept
    (S7-D14)."""
    state, outcome, message_id = conn.execute(
        "SELECT state,outcome,message_id FROM operations WHERE id=?", (op_id,)).fetchone()
    if not admission:
        used = conn.execute("SELECT COUNT(*) FROM events WHERE operation=?", (op_id,)).fetchone()[0]
        if used >= cfg.op_event_reserve - (0 if state == "FINAL" else 1):
            return
    details: dict[str, Any] = {"operation_id": op_id.hex(), "state": state, "outcome": outcome}
    if evidence is not None:
        details["recorded_evidence"] = evidence
        kind = "HOST_RECORDED"
    journal.append(conn, cfg, domain, "OPERATION_UPDATE", critical, {"evidence": {
        "kind": kind, "assurance": "SELF_REPORTED", "details": details}},
        operation=op_id, message_id=bytes(message_id) if message_id is not None else None,
        admission=admission)


def _supersede_unsent(conn: sqlite3.Connection, cfg: Settings, sub: Submission, new_id: bytes) -> None:
    """LATEST replaces only records that were never handed to the root (docs/08 §1); the cause is
    kept in superseded_by."""
    req = sub.request
    rows = conn.execute(
        "SELECT o.id FROM operations o JOIN outbox b ON b.operation=o.id "
        "WHERE o.principal=? AND o.domain=? AND o.type='MESSAGE' AND b.state='QUEUED' AND o.id!=? "
        "AND json_extract(o.request_json,'$.queue_mode')='LATEST' "
        "AND json_extract(o.request_json,'$.destination')=json(?) "
        "AND json_extract(o.request_json,'$.app_port')=? "
        "AND json_extract(o.request_json,'$.coalesce_key')=?",
        (sub.principal, sub.domain, new_id, canonical_json(req["destination"]), req["app_port"],
         req["coalesce_key"])).fetchall()
    for (old,) in rows:
        conn.execute("UPDATE operations SET state='FINAL', outcome='SUPERSEDED', superseded_by=? "
                     "WHERE id=?", (new_id, old))
        conn.execute("UPDATE outbox SET state='SUPERSEDED' WHERE operation=?", (old,))
        operation_event(conn, cfg, bytes(old), sub.domain, False, "SUPERSEDED")


# ---- cancel -----------------------------------------------------------------------------------
def cancel(conn: sqlite3.Connection, cfg: Settings, principal: str, op_id: bytes) -> dict[str, Any]:
    """Unsent -> CANCELLED_NOT_SENT. Possibly sent -> only a recorded request: the wire cannot be
    recalled, so the outcome stays open and late receipts are still added (never deleted).
    Idempotent: repeating it changes nothing and emits nothing."""
    row = conn.execute(
        "SELECT o.domain,o.state,o.evidence_json,o.request_json,o.type,b.state,b.external_write_possible "
        "FROM operations o JOIN outbox b ON b.operation=o.id WHERE o.id=? AND o.principal=?",
        (op_id, principal)).fetchone()
    if row is None:
        raise not_found("operation")
    domain, state, evidence_json, request_json, op_type, box_state, written = row
    critical = is_critical(op_type, json.loads(request_json))
    if state != "FINAL":
        if box_state == "QUEUED" and not written:
            conn.execute("UPDATE operations SET state='FINAL', outcome='CANCELLED_NOT_SENT' WHERE id=?", (op_id,))
            conn.execute("UPDATE outbox SET state='CANCELLED' WHERE operation=?", (op_id,))
            operation_event(conn, cfg, op_id, bytes(domain), critical, "CANCELLED_NOT_SENT")
        elif not any(e["kind"] == "HOST_CANCEL_REQUESTED" for e in json.loads(evidence_json)):
            evidence = json.loads(evidence_json) + [{"kind": "HOST_CANCEL_REQUESTED",
                                                     "assurance": "SELF_REPORTED"}]
            conn.execute("UPDATE operations SET evidence_json=? WHERE id=?", (canonical_json(evidence), op_id))
            operation_event(conn, cfg, op_id, bytes(domain), critical, "HOST_CANCEL_REQUESTED")
    return get_operation(conn, principal, op_id)


def is_critical(op_type: str, request: dict[str, Any]) -> bool:
    """Protected in the journal unless it is a BEST_EFFORT + VOLATILE message."""
    return op_type != "MESSAGE" or request["delivery"] != "BEST_EFFORT" or request["storage"] != "VOLATILE"
