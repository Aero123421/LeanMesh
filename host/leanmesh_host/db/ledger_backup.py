"""The root's ledger backup at the Host (issue #5, docs/12 §5, docs/21 §8, protocol/control.cddl 34).

The Host keeps ONE backup per domain, the one with the highest sequence number, and refuses a lower one: an older backup
would give back members and revocations of an earlier day. A backup is the signed header (control type 34, signed by the
root that cut it) and the records it fixes by a hash chain. This module knows the shape and the chain; the SIGNATURE
(fleet -> the root's delegation -> the root) is verified by the root that is restored from it, never by the Host: the Host
is the conveyor and checks that what it stores is what the header says, so that damage is caught when it is made.

Host format (the base64 blob of the API): CBOR [1, header COSE, [[record id, state, payload, next link], ...]].
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ..api.codec import encode_b64
from ..api.errors import ApiError, invalid, not_found
from ..events.journal import now_ms
from ..wire import WireError, cbor_decode, cbor_encode
from ..wire.control import decode_control_body, decode_cose_sign1

FORMAT = 1
CONTROL_TYPE = 34
CHAIN_LABEL = b"LMBK1"
MAX_RECORDS = 68            # floors + groups + policy + 64 slots + the manifest
MAX_PAYLOAD = 672           # store::k_max_payload
ENTRY_BASE = 0x100
SLOTS = 64
ID_MANIFEST, ID_POLICY, ID_FLOORS, ID_GROUPS = 9, 8, 10, 20
EXTRAS = ((1, ID_FLOORS), (2, ID_GROUPS), (4, ID_POLICY))   # canonical order: floors, groups, policy
ZERO = bytes(32)
U63 = (1 << 63) - 1


class BackupError(ValueError):
    """A backup that is not what its header says (or no header at all); `reason` is for the operator."""


@dataclass(frozen=True)
class Record:
    id: int
    state: int
    payload: bytes
    next: bytes


@dataclass(frozen=True)
class Backup:
    header: bytes                   # the signed COSE
    records: tuple[Record, ...]
    domain: bytes
    root: bytes                     # the DeviceId that signed it
    sequence: int
    term: int
    generation: int
    head: bytes

    def blob(self) -> bytes:
        return cbor_encode([FORMAT, self.header,
                            [[r.id, r.state, r.payload, r.next] for r in self.records]])

    @property
    def count(self) -> int:
        return len(self.records)


def chain_link(record_id: int, state: int, payload: bytes, nxt: bytes) -> bytes:
    """H(i) = SHA256("LMBK1" || id u16be || state u8 || len u16be || payload || H(i+1))."""
    return hashlib.sha256(CHAIN_LABEL + record_id.to_bytes(2, "big") + bytes([state])
                          + len(payload).to_bytes(2, "big") + payload + nxt).digest()


def canonical_ids(entries: int, extras: int) -> list[int]:
    """The records of a backup in the order of the header: floors, groups, policy, the masked slots, the manifest."""
    ids = [rid for bit, rid in EXTRAS if extras & bit]
    ids += [ENTRY_BASE + slot for slot in range(SLOTS) if entries >> slot & 1]
    return ids + [ID_MANIFEST]


def parse_header(cose: bytes) -> dict[str, Any]:
    """The fields of a header COSE (structure only: no signature is checked here)."""
    try:
        sign1 = decode_cose_sign1(cose)
        body = decode_control_body(sign1.payload, "signed")
        data = cbor_decode(body.data)
    except WireError as exc:
        raise BackupError(f"the header is not a signed control object ({exc.status})") from exc
    if body.type != CONTROL_TYPE:
        raise BackupError(f"the header is control type {body.type}, not {CONTROL_TYPE}")
    seq, term, generation, _delegation, change, entries, extras, head = data
    if seq == 0 or body.revision != seq or body.issuer != sign1.kid:
        raise BackupError("the header's sequence, revision or issuer do not agree")
    return {"domain": body.domain, "root": body.issuer, "sequence": seq, "term": term, "generation": generation,
            "change": change, "entries": entries, "extras": extras, "head": head}


def build(header: bytes, pages: list[tuple[int, int, bytes]]) -> Backup:
    """The backup of a header and the (id, state, payload) records the root served, in order: the chain links are
    computed from the end and must give the head the header signs."""
    info = parse_header(header)
    want = canonical_ids(info["entries"], info["extras"])
    if [rid for rid, _, _ in pages] != want or len(want) > MAX_RECORDS:
        raise BackupError("the records are not the ones the header names, in its order")
    nxt = ZERO
    links: list[bytes] = []
    for rid, state, payload in reversed(pages):
        if not 0 <= state <= 255 or len(payload) > MAX_PAYLOAD:
            raise BackupError(f"record {rid:#x} is out of bounds")
        links.append(nxt)
        nxt = chain_link(rid, state, payload, nxt)
    if nxt != info["head"]:
        raise BackupError("the records do not match the hash chain of the header (the ledger changed, or a record is damaged)")
    links.reverse()
    return Backup(header, tuple(Record(rid, st, pl, nx) for (rid, st, pl), nx in zip(pages, links, strict=True)),
                  info["domain"], info["root"], info["sequence"], info["term"], info["generation"], nxt)


def decode_blob(blob: bytes) -> Backup:
    """The Host format back into a backup, every check of `build` applied (and the links as stored must be the computed ones)."""
    try:
        doc = cbor_decode(blob)
    except WireError as exc:
        raise BackupError(f"not a backup blob ({exc.status})") from exc
    if (not isinstance(doc, list) or len(doc) != 3 or doc[0] != FORMAT or not isinstance(doc[1], bytes)
            or not isinstance(doc[2], list) or not 1 <= len(doc[2]) <= MAX_RECORDS):
        raise BackupError("not a backup blob of format 1")
    pages: list[tuple[int, int, bytes]] = []
    for rec in doc[2]:
        if (not isinstance(rec, list) or len(rec) != 4 or not isinstance(rec[0], int) or not isinstance(rec[1], int)
                or not isinstance(rec[2], bytes) or not isinstance(rec[3], bytes) or len(rec[3]) != 32):
            raise BackupError("a record of the backup is malformed")
        pages.append((rec[0], rec[1], rec[2]))
    backup = build(doc[1], pages)
    if [r.next for r in backup.records] != [rec[3] for rec in doc[2]]:
        raise BackupError("the chain links of the records are not the ones of their content")
    return backup


# ---- storage: the newest sequence per domain ----------------------------------------------------------
STORED, SAME, STALE = "STORED", "SAME", "STALE"


def store(conn: sqlite3.Connection, domain: bytes, backup: Backup) -> str:
    """Keeps the backup with the highest sequence. STALE: a higher one is held (nothing written). SAME: this very one is
    held. The same sequence with other content is refused (BackupError): a sequence is made once."""
    if backup.domain != domain:
        raise BackupError("the backup is of another domain")
    blob = backup.blob()
    row = conn.execute("SELECT sequence,blob FROM ledger_backups WHERE domain=?", (domain,)).fetchone()
    if row is not None:
        if backup.sequence < row[0]:
            return STALE
        if backup.sequence == row[0]:
            if bytes(row[1]) != blob:
                raise BackupError("a backup with this sequence number is held already, with other content")
            return SAME
    conn.execute(
        "INSERT INTO ledger_backups(domain,sequence,root_device,root_term,records,taken_utc_ms,blob) "
        "VALUES(?,?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET sequence=excluded.sequence, "
        "root_device=excluded.root_device, root_term=excluded.root_term, records=excluded.records, "
        "taken_utc_ms=excluded.taken_utc_ms, blob=excluded.blob WHERE excluded.sequence>ledger_backups.sequence",
        (domain, backup.sequence, backup.root, backup.term, backup.count, now_ms(), blob))
    return STORED


def meta(conn: sqlite3.Connection, domain: bytes) -> dict[str, Any] | None:
    """What is held for the domain, without the blob."""
    row = conn.execute("SELECT sequence,root_device,root_term,records,taken_utc_ms FROM ledger_backups WHERE domain=?",
                       (domain,)).fetchone()
    if row is None:
        return None
    return {"sequence": row[0], "root": bytes(row[1]), "term": row[2], "records": row[3], "taken_utc_ms": row[4]}


def load(conn: sqlite3.Connection, domain: bytes) -> Backup | None:
    row = conn.execute("SELECT blob FROM ledger_backups WHERE domain=?", (domain,)).fetchone()
    return None if row is None else decode_blob(bytes(row[0]))


def view(conn: sqlite3.Connection, domain: bytes) -> dict[str, Any]:
    """GET /v1/ledger/backup: the newest backup of the domain, its facts and the blob."""
    row = conn.execute("SELECT sequence,root_device,root_term,records,taken_utc_ms,blob FROM ledger_backups WHERE domain=?",
                       (domain,)).fetchone()
    if row is None:
        if conn.execute("SELECT 1 FROM domains WHERE id=?", (domain,)).fetchone() is None:
            raise not_found("domain")
        raise not_found("ledger backup")
    taken = datetime.fromtimestamp(row[4] / 1000, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {"domain_id": domain.hex(), "sequence": str(row[0]), "root_device_id": bytes(row[1]).hex(),
            "root_term": row[2], "records": row[3], "taken_at": taken, "backup_b64": encode_b64(bytes(row[5]))}


def admit_restore(conn: sqlite3.Connection, domain: bytes, old_root: bytes, new_root: bytes,
                  supplied: Backup | None, expected: int) -> None:
    """The Host's rules for LEDGER_RESTORE, inside the admission transaction. `expected` is the sequence of the backup that is
    restored: of the supplied one, or of the one held (a compare-and-set: the operator saw this sequence). The handover must
    hand over from the root that made the backup, and the domain must not be bound to some other root. A supplied backup
    becomes the held one (it is at least as new), so that the restore reads it from there."""
    held = meta(conn, domain)
    if supplied is not None:
        if supplied.domain != domain:
            raise invalid("the backup is of another domain")
        if supplied.sequence != expected:
            raise invalid("expected_revision must be the sequence of the supplied backup")
        if held is not None and supplied.sequence < held["sequence"]:
            raise ApiError(409, "CONFLICT", "the Host holds a newer backup of this domain",
                           current_revision=str(held["sequence"]))
        backup_root = supplied.root
    else:
        if held is None:
            raise not_found("ledger backup")
        if held["sequence"] != expected:
            raise ApiError(409, "CONFLICT", "expected_revision is not the sequence of the backup the Host holds",
                           current_revision=str(held["sequence"]))
        backup_root = held["root"]
    if backup_root != old_root:
        raise ApiError(409, "CONFLICT", "the handover hands over from another root than the one that made the backup")
    bound = conn.execute("SELECT root_device FROM domains WHERE id=?", (domain,)).fetchone()
    if bound is None:
        raise not_found("domain")
    if bound[0] is not None and bytes(bound[0]) not in (ZERO, old_root, new_root):
        raise ApiError(409, "CONFLICT", "the domain is bound to another root than the handover's old root")
    if supplied is not None:
        try:
            store(conn, domain, supplied)
        except BackupError as exc:
            raise ApiError(409, "CONFLICT", str(exc)) from exc

