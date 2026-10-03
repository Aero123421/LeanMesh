"""Issue #5: the Host's ledger backup store - the shape of a backup, its hash chain, the newest-sequence rule, the view and the
additive migration of an existing database. No root and no signature here: the Host checks that what it keeps is what the
signed header names (db/ledger_backup.py); the root verifies the signature when it is restored.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest
from leanmesh_host.api.errors import ApiError
from leanmesh_host.db import ledger_backup as lb
from leanmesh_host.storage import StorageThread
from backup_util import DOMAIN, OTHER_ROOT, ROOT, head_of, header, make, pages
from leanmesh_host.wire import cbor_encode
from leanmesh_host.wire.control import ControlBody, encode_cose_sign1, encode_control_body

REPO = Path(__file__).resolve().parents[3]


def test_canonical_order_is_floors_groups_policy_slots_then_the_manifest() -> None:
    assert lb.canonical_ids(0, 0) == [lb.ID_MANIFEST]
    assert lb.canonical_ids(1 << 5 | 1 << 1, 7) == [lb.ID_FLOORS, lb.ID_GROUPS, lb.ID_POLICY,
                                                    lb.ENTRY_BASE + 1, lb.ENTRY_BASE + 5, lb.ID_MANIFEST]
    assert len(lb.canonical_ids((1 << 64) - 1, 7)) == lb.MAX_RECORDS


def test_the_chain_of_the_header_is_the_one_the_records_make() -> None:
    # fixed vector of the definition in control.cddl: H = SHA256("LMBK1" || id u16be || state u8 || len u16be || payload || next)
    want = hashlib.sha256(b"LMBK1" + (0x101).to_bytes(2, "big") + b"\x03" + (3).to_bytes(2, "big") + b"abc" + bytes(32)).digest()
    assert lb.chain_link(0x101, 3, b"abc", bytes(32)) == want
    backup = make([1, 2], extras=7)
    assert backup.head == head_of(pages([1, 2], 7)) and backup.count == 6
    # each record carries the link that follows it; the last one carries zero
    assert backup.records[-1].next == lb.ZERO
    assert backup.records[0].next == lb.chain_link(*[getattr(backup.records[1], f) for f in ("id", "state", "payload")],
                                                   backup.records[1].next)


def test_a_blob_round_trips_and_every_kind_of_damage_is_refused() -> None:
    backup = make([0, 3, 63], extras=5)
    assert lb.decode_blob(backup.blob()) == backup
    recs = pages([0, 3, 63], 5)
    entries, extras = 1 | 1 << 3 | 1 << 63, 5
    good = header(entries, extras, head_of(recs))
    with pytest.raises(lb.BackupError, match="hash chain"):  # one record damaged
        lb.build(good, [(i, s, p[:-1] + bytes([p[-1] ^ 1])) if i == lb.ENTRY_BASE + 3 else (i, s, p) for i, s, p in recs])
    with pytest.raises(lb.BackupError, match="in its order"):  # a record missing / twice / out of order
        lb.build(good, recs[:-2] + recs[-1:])
    with pytest.raises(lb.BackupError, match="in its order"):
        lb.build(good, recs[1:] + recs[:1])
    with pytest.raises(lb.BackupError, match="in its order"):  # the manifest is not part of the mask: a record too many
        lb.build(good, recs + [recs[0]])
    with pytest.raises(lb.BackupError, match="out of bounds"):
        lb.build(header(0, 0, head_of([(9, 0, bytes(673))])), [(9, 0, bytes(673))])
    handover = encode_cose_sign1(ROOT, encode_control_body(ControlBody(
        31, 1, bytes(16), DOMAIN, 1, ROOT, cbor_encode([bytes(16), ROOT, OTHER_ROOT, 1, 2, bytes(32), 2, 0]))), bytes(64))
    with pytest.raises(lb.BackupError, match="control type 31"):  # another signed object is no backup header
        lb.parse_header(handover)
    with pytest.raises(lb.BackupError, match="do not agree"):  # revision is not the sequence
        lb.parse_header(header(0, 0, bytes(32), seq=5, revision=6))
    with pytest.raises(lb.BackupError, match="do not agree"):  # issuer is not the kid
        lb.parse_header(header(0, 0, bytes(32), kid=OTHER_ROOT))
    with pytest.raises(lb.BackupError, match="not a signed control object"):
        lb.parse_header(b"\x00" * 10)
    # the blob: links that are not the content's, format number, record shape, trailing bytes, not CBOR at all
    doc = [1, backup.header, [[r.id, r.state, r.payload, r.next] for r in backup.records]]
    bad = [list(r) for r in doc[2]]
    bad[0][3] = bytes(32)
    with pytest.raises(lb.BackupError, match="chain links"):
        lb.decode_blob(cbor_encode([1, backup.header, bad]))
    for blob in (cbor_encode([2, backup.header, doc[2]]), cbor_encode([1, backup.header, []]),
                 cbor_encode([1, backup.header, [[1, 2, b"x"]]]), backup.blob() + b"\x00", b"\xff\xff"):
        with pytest.raises(lb.BackupError):
            lb.decode_blob(blob)


def test_the_newest_sequence_per_domain_wins_and_a_lower_one_never_replaces_it() -> None:
    conn = sqlite3.connect(":memory:")
    conn.executescript((REPO / "db" / "schema.sql").read_text())
    conn.execute("INSERT INTO domains(id) VALUES(?)", (DOMAIN,))
    b1, b2, b3 = make([1], seq=1), make([1, 2], seq=2), make([1, 2, 3], seq=3)
    assert lb.store(conn, DOMAIN, b2) == lb.STORED
    assert lb.store(conn, DOMAIN, b1) == lb.STALE                    # older: refused, nothing written
    assert lb.meta(conn, DOMAIN)["sequence"] == 2  # type: ignore[index]
    assert lb.store(conn, DOMAIN, b2) == lb.SAME                     # the same one again: nothing to do
    forged = make([1, 2, 9], seq=2)
    with pytest.raises(lb.BackupError, match="other content"):       # a sequence is made once
        lb.store(conn, DOMAIN, forged)
    assert lb.store(conn, DOMAIN, b3) == lb.STORED
    held = lb.meta(conn, DOMAIN)
    assert held is not None and held["sequence"] == 3 and held["root"] == ROOT and held["records"] == 4
    assert lb.load(conn, DOMAIN) == b3
    assert conn.execute("SELECT COUNT(*) FROM ledger_backups").fetchone()[0] == 1   # one row per domain
    with pytest.raises(lb.BackupError, match="another domain"):
        lb.store(conn, bytes(16), b3)
    other = make([1], seq=1, domain=bytes([0xE0]) * 16)
    conn.execute("INSERT INTO domains(id) VALUES(?)", (bytes([0xE0]) * 16,))
    assert lb.store(conn, bytes([0xE0]) * 16, other) == lb.STORED    # each domain has its own
    # the sequence is bounded by the table, not by the Host's good will
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE ledger_backups SET sequence=0")


def test_the_api_view_and_the_restore_admission_rules() -> None:
    conn = sqlite3.connect(":memory:")
    conn.executescript((REPO / "db" / "schema.sql").read_text())
    conn.execute("INSERT INTO domains(id,root_device) VALUES(?,?)", (DOMAIN, ROOT))
    with pytest.raises(ApiError) as e:
        lb.view(conn, DOMAIN)
    assert e.value.http_status == 404                                 # no backup yet
    with pytest.raises(ApiError) as e:
        lb.view(conn, bytes(16))
    assert e.value.http_status == 404                                 # no such domain
    b = make([1, 2], seq=4)
    lb.store(conn, DOMAIN, b)
    v = lb.view(conn, DOMAIN)
    assert v["sequence"] == "4" and v["records"] == 3 and v["root_device_id"] == ROOT.hex() and v["domain_id"] == DOMAIN.hex()
    assert v["taken_at"].endswith("Z") and lb.decode_blob(__import__("base64").b64decode(v["backup_b64"])) == b

    def admit(**kw: object) -> int:
        args: dict[str, object] = {"old_root": ROOT, "new_root": OTHER_ROOT, "supplied": None, "expected": 4}
        args.update(kw)
        try:
            lb.admit_restore(conn, DOMAIN, args["old_root"], args["new_root"], args["supplied"], args["expected"])  # type: ignore[arg-type]
        except ApiError as exc:
            return exc.http_status
        return 0

    assert admit() == 0                                               # the held one, its sequence, its root
    assert admit(expected=3) == 409                                   # not the sequence the Host holds
    assert admit(old_root=OTHER_ROOT) == 409                          # a handover from another root than the backup's
    conn.execute("UPDATE domains SET root_device=?", (bytes([0x33]) * 32,))
    assert admit() == 409                                             # the domain is bound to a third root
    conn.execute("UPDATE domains SET root_device=?", (OTHER_ROOT,))
    assert admit() == 0                                               # bound to the new root already (a fresh Host)
    conn.execute("UPDATE domains SET root_device=?", (ROOT,))
    assert admit(supplied=make([1], seq=3), expected=3) == 409        # a supplied backup older than the held one
    assert admit(supplied=make([1, 2, 3], seq=5), expected=4) == 400  # its sequence is not expected_revision
    assert admit(supplied=make([1, 2, 3], seq=5, domain=bytes([1]) * 16), expected=5) == 400
    assert admit(supplied=make([1, 2, 3], seq=5, root=OTHER_ROOT), expected=5) == 409  # not made by the handover's old root
    assert admit(supplied=make([1, 2, 3], seq=5), expected=5) == 0
    assert lb.meta(conn, DOMAIN)["sequence"] == 5                      # type: ignore[index]  # the supplied one is the held one now
    conn.execute("DELETE FROM ledger_backups")
    assert admit() == 404                                             # nothing held, nothing supplied


def test_an_existing_database_gains_the_table_and_keeps_everything_else(tmp_path: Path) -> None:
    schema = REPO / "db" / "schema.sql"
    db = tmp_path / "old.db"
    first = StorageThread(db, schema)
    first.start()
    try:
        first.submit(lambda c: c.execute("INSERT INTO domains(id,root_device) VALUES(?,?)", (DOMAIN, ROOT))).result()
        first.submit(lambda c: c.execute("INSERT INTO meta(key,value) VALUES('kept',x'01')")).result()
        # a database made before the table existed
        first.submit(lambda c: c.execute("DROP TABLE ledger_backups")).result()
        journal = first.journal_id
    finally:
        first.stop()
    second = StorageThread(db, schema)
    second.start()
    try:
        assert second.journal_id == journal                           # the same database, not a re-run of schema.sql
        assert second.submit(lambda c: c.execute("SELECT COUNT(*) FROM ledger_backups").fetchone()[0]).result() == 0
        assert second.submit(lambda c: bytes(c.execute("SELECT value FROM meta WHERE key='kept'").fetchone()[0])).result() == b"\x01"
        assert second.submit(lambda c: bytes(c.execute("SELECT root_device FROM domains").fetchone()[0])).result() == ROOT
        second.submit(lambda c: lb.store(c, DOMAIN, make([1]))).result()
    finally:
        second.stop()
    third = StorageThread(db, schema)                                 # opened again: idempotent, the backup is still there
    third.start()
    try:
        assert third.submit(lambda c: lb.meta(c, DOMAIN)["sequence"]).result() == 1  # type: ignore[index]
    finally:
        third.stop()
