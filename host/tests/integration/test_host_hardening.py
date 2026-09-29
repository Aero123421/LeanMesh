"""Regression tests for the S7 review findings (numbers are the finding ids in the S7 review).

Everything runs through the real FastAPI app + SQLite file, except the storage-thread shutdown
test, which drives the real StorageThread directly (there is no HTTP path to a stuck shutdown).
"""

from __future__ import annotations

import dataclasses
import os
import threading
from pathlib import Path
from typing import Any

import pytest
from host_util import DOMAIN, NODE, check, make_settings, message, rows, running
from leanmesh_host.api.errors import ApiError
from leanmesh_host.db import ops, outbox
from leanmesh_host.events import journal
from leanmesh_host.storage import StorageFault, StorageThread

REPO = Path(__file__).resolve().parents[3]


ROOT_DEADLINE = {"mode": "root", "root_term": 1, "expires_root_ms": "9000"}


def ev(kind: str, assurance: str = "END_VERIFIED", **details: Any) -> dict[str, Any]:
    return {"kind": kind, "assurance": assurance, **({"details": details} if details else {})}


def sent(h: Any, key: str = "a", **over: Any) -> tuple[str, bytes]:
    """Admits one message and claims it (it may now be on the wire)."""
    e = h.epoch(key=f"e-{key}")
    op = h.post("/v1/messages", message(e, delivery="APPLIED", **{"deadline": ROOT_DEADLINE, **over}), key).json()["id"]
    items = h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x07" * 16))
    assert [i.operation for i in items] == [bytes.fromhex(op)]
    return op, bytes.fromhex(op)


def view(h: Any, op: str) -> dict[str, Any]:
    r = h.get(f"/v1/operations/{op}")
    check("get_operation", r)
    return dict(r.json())


def op_events(h: Any, op: str) -> list[dict[str, Any]]:
    return list(h.get("/v1/events", domain_id=DOMAIN, limit=200).json()["events"])


# ---- 6 ---------------------------------------------------------------------------------------
def test_6_receipt_for_another_message_id_is_rejected_and_rolled_back(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        op, raw = sent(h)
        m1, m2 = b"\x01" * 16, b"\x02" * 16
        h.db(lambda c: outbox.record(c, h.hub.cfg, raw, state="WAITING_RECEIPT", outcome="SUBMITTED",
                                     evidence=ev("HOP_ACCEPTED", "LINK_VERIFIED"), message_id=m1))
        before = view(h, op)
        events = h.db(lambda c: c.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        with pytest.raises(ApiError) as bad:  # a stale receipt of M2 must not touch M1's operation
            h.db(lambda c: outbox.record(c, h.hub.cfg, raw, state="FINAL", outcome="APPLIED",
                                         evidence=ev("APP_APPLIED"), message_id=m2))
        assert bad.value.http_status == 409
        assert view(h, op) == before and before["message_id"] == m1.hex()
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM events").fetchone()[0]) == events
        # the matching id is fine
        got = h.db(lambda c: outbox.record(c, h.hub.cfg, raw, outcome="RECEIVED",
                                           evidence=ev("END_RECEIVED"), message_id=m1))
        assert got["outcome"] == "RECEIVED"


# ---- 7 ---------------------------------------------------------------------------------------
def test_7_cancel_after_claim_survives_release_unwritten(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        op, raw = sent(h)
        r = h.post(f"/v1/operations/{op}/cancel", {}, "-")
        assert r.status_code == 202 and r.json()["outcome"] == "PENDING"  # maybe on the wire: only a request
        h.db(lambda c: outbox.release_unwritten(c, h.hub.cfg, raw))  # bridge proves nothing was written
        v = view(h, op)
        assert v["state"] == "FINAL" and v["outcome"] == "CANCELLED_NOT_SENT"
        assert h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x08" * 16)) == []  # never transmitted later
        assert h.db(lambda c: c.execute("SELECT state FROM outbox").fetchone()[0]) == "CANCELLED"
        assert h.db(outbox.cancel_requests) == []


def test_7_release_without_cancel_still_requeues(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        op, raw = sent(h)
        h.db(lambda c: outbox.release_unwritten(c, h.hub.cfg, raw))
        assert view(h, op)["state"] == "HOST_COMMITTED"
        assert [i.operation for i in h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x08" * 16))] == [raw]


# ---- 8 ---------------------------------------------------------------------------------------
def test_8_exact_retry_returns_the_stored_operation_despite_later_state(tmp_path: Path,
                                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    with running(make_settings(tmp_path)) as h:
        e = h.epoch()
        h.hub.set_root(True, ["OBJECT_4K", "SIGNED_TRANSFER"])
        obj = message(e, object_transfer=True)
        first = h.post("/v1/messages", obj, "obj")
        assert first.status_code == 202
        signed = {"domain_id": DOMAIN, "client_epoch": e, "expected_revision": "0", "request_id": "ab" * 16,
                  "type": "TRANSFER", "device_id": NODE, "signed_cbor_b64": "AAEC"}
        ctl = h.post("/v1/control", signed, "ctl")
        assert ctl.status_code == 202
        soon = "2999-01-01T00:00:00Z"
        timed = message(e, delivery="APPLIED", deadline={"mode": "utc", "expires_at": soon})
        third = h.post("/v1/messages", timed, "timed")
        assert third.status_code == 202
        # the response was lost; meanwhile the root disconnected and the deadline passed
        h.hub.set_root(False)
        monkeypatch.setattr(journal, "now_ms", lambda: 32_503_680_000_000 + 1000)  # year 3000
        count = rows(tmp_path / "host.db", "SELECT COUNT(*) FROM operations")[0][0]
        for key, path, body, want in (("obj", "/v1/messages", obj, first), ("ctl", "/v1/control", signed, ctl),
                                      ("timed", "/v1/messages", timed, third)):
            again = h.post(path, body, key)
            assert again.status_code == 202 and again.json() == want.json(), (key, again.text)
        assert rows(tmp_path / "host.db", "SELECT COUNT(*) FROM operations")[0][0] == count
        # a NEW operation is still subject to the current capability / deadline
        assert h.post("/v1/messages", obj, "obj2").status_code == 503
        assert h.post("/v1/messages", timed, "timed2").status_code == 400


# ---- 12 --------------------------------------------------------------------------------------
def test_12_stop_that_times_out_keeps_the_lock_and_fails(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    schema = REPO / "db" / "schema.sql"
    st = StorageThread(db, schema, max_queue=2)
    st.start()
    release = threading.Event()
    started = threading.Event()

    def blocker(_: Any) -> None:
        started.set()
        release.wait(20)

    fut = st.submit(blocker)
    assert started.wait(5)
    st.submit(lambda c: None)  # queue is now full behind the running job
    st.submit(lambda c: None)
    with pytest.raises(StorageFault):
        st.stop(timeout_s=0.3)  # must neither hang on the full queue nor pretend it stopped
    with pytest.raises(StorageFault, match="owned by another host process"):
        StorageThread(db, schema).start()  # the singleton lock is still held
    with pytest.raises(Exception, match="storage"):
        st.submit(lambda c: None)  # stopped accepting work
    release.set()
    fut.result(timeout=5)
    st.stop(timeout_s=5)  # now it can finish, and only then is the lock released
    again = StorageThread(db, schema)
    again.start()
    again.stop()


# ---- 13 --------------------------------------------------------------------------------------
@pytest.mark.parametrize("junk", [b"\x01" * 10, b"", os.urandom(33)])
def test_13_malformed_floor_file_is_a_rollback_not_a_first_start(tmp_path: Path, junk: bytes) -> None:
    s = make_settings(tmp_path)
    with running(s) as h:
        op = h.post("/v1/messages", message(h.epoch()), "k").json()["id"]
        jid = h.get("/v1/status").json()["journal_id"]
    floor = Path(str(s.db_path) + ".floor")
    assert floor.exists()
    floor.write_bytes(junk)
    with running(s, domain=False) as h:
        assert view(h, op)["outcome"] == "INDETERMINATE"
        rotated = h.get("/v1/status").json()["journal_id"]
        assert rotated != jid
        assert h.db(lambda c: c.execute("SELECT code,active FROM health_faults").fetchall()) == [("DB_ROLLBACK", 1)]
    with running(s, domain=False) as h:  # the floor was rewritten: the next start is not a rollback again
        assert h.get("/v1/status").json()["journal_id"] == rotated


def test_13_unreadable_floor_file_fails_closed(tmp_path: Path) -> None:
    s = make_settings(tmp_path)
    with running(s):
        pass
    floor = Path(str(s.db_path) + ".floor")
    floor.unlink()
    floor.mkdir()  # exists but cannot be read as a file: not FileNotFoundError
    with pytest.raises(OSError):
        with running(s, domain=False):
            pass


# ---- 14 --------------------------------------------------------------------------------------
def test_14_every_admitted_operation_can_always_record_its_terminal_event(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, max_events=6, event_margin=5, max_open_operations=100)) as h:
        e = h.epoch()
        accepted: list[str] = []
        for i in range(30):
            r = h.post("/v1/messages", message(e, delivery="APPLIED", deadline=ROOT_DEADLINE), f"k{i}")
            if r.status_code != 202:
                check("submit_message", r)
                assert r.status_code == 507
                break
            accepted.append(r.json()["id"])
        else:
            raise AssertionError("admission never refused")
        assert accepted
        items = h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x07" * 16, 64))
        assert len(items) == len(accepted)
        first = True
        for op in accepted:
            raw = bytes.fromhex(op)
            extra = 6 if first else 2  # the first op is chatty: coalesced, never crowding out terminals
            first = False
            for n in range(extra):
                h.db(lambda c, n=n: outbox.record(c, h.hub.cfg, raw, evidence=ev("HOP_ACCEPTED", "LINK_VERIFIED", n=n)))
            done = h.db(lambda c: outbox.record(c, h.hub.cfg, raw, state="FINAL", outcome="APPLIED",
                                                evidence=ev("APP_APPLIED")))
            assert done["state"] == "FINAL" and done["outcome"] == "APPLIED"
            per_op = h.db(lambda c: c.execute("SELECT COUNT(*),MAX(sequence) FROM events WHERE operation=?",
                                              (raw,)).fetchone())
            last = h.db(lambda c: c.execute("SELECT payload_json FROM events WHERE sequence=?",
                                            (per_op[1],)).fetchone()[0])
            assert '"state":"FINAL"' in last  # the terminal event is really in the journal
            assert per_op[0] <= h.hub.cfg.op_event_reserve
        total = h.db(lambda c: c.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        assert total <= h.hub.cfg.max_events + h.hub.cfg.event_margin


# ---- 15 --------------------------------------------------------------------------------------
def test_15_default_settings_have_a_hard_sqlite_page_limit(tmp_path: Path) -> None:
    s = make_settings(tmp_path)
    assert s.max_page_count is not None
    with running(s) as h:
        assert h.db(lambda c: c.execute("PRAGMA max_page_count").fetchone()[0]) == s.max_page_count
    assert s.max_page_count * 4096 > s.max_db_bytes  # headroom above the soft budget, never below


def _used_bytes(h: Any) -> int:
    return int(h.db(lambda c: (c.execute("PRAGMA page_count").fetchone()[0]
                               - c.execute("PRAGMA freelist_count").fetchone()[0])
                    * c.execute("PRAGMA page_size").fetchone()[0]))


def _ingest_args(i: int, payload: bytes) -> dict[str, Any]:
    return dict(domain=bytes.fromhex(DOMAIN), origin=bytes.fromhex(NODE), assignment_generation=1,
                message_id=i.to_bytes(16, "big"), intent_hash=bytes([i % 250 + 1]) * 32, payload=payload,
                assurance={"kind": "END_RECEIVED", "assurance": "END_VERIFIED"})


def test_15_inbox_ingest_and_epochs_honour_the_byte_budget(tmp_path: Path) -> None:
    s = make_settings(tmp_path, free_reserve_bytes=0)
    with running(s) as h:
        base = _used_bytes(h)
    tight = dataclasses.replace(s, max_db_bytes=base + 200_000)
    with running(tight, domain=False) as h:
        refused = 0
        for i in range(1, 200):
            try:
                h.db(lambda c, i=i: journal.ingest(c, h.hub.cfg, **_ingest_args(i, b"x" * 3000)))
            except ApiError as err:
                assert err.http_status == 507 and err.details["resource"] == "db_bytes"
                refused += 1
                break
        assert refused == 1  # the inbox (no outbound op involved) hit the byte budget
        with pytest.raises(ApiError) as e2:  # so does every other externally-driven insert
            h.db(lambda c: ops.open_epoch(c, h.hub.cfg, "alice", "k", "ab" * 16))
        assert e2.value.details["resource"] == "db_bytes"


def test_15_inbox_rows_are_removed_with_their_acknowledged_events(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, event_retention_ms=0)) as h:
        for i in range(1, 4):
            h.db(lambda c, i=i: journal.ingest(c, h.hub.cfg, **_ingest_args(i, b"p")))
        page = h.get("/v1/events", domain_id=DOMAIN, limit=200).json()
        jid, _, top = page["next_cursor"].partition(":")
        r = h.post("/v1/consumers/kg/ack", {"domain_id": DOMAIN, "journal_id": jid, "sequence": top}, "-")
        assert r.status_code == 200
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM events").fetchone()[0]) == 0
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM inbox").fetchone()[0]) == 0


def test_15_epoch_rows_are_bounded_per_principal(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, max_epochs_per_principal=8, epoch_retention_ms=0)) as h:
        for i in range(30):
            eid = h.epoch(key=f"k{i}")
            assert h.post(f"/v1/epochs/{eid}/close", {}, "-").status_code == 200
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM client_epochs").fetchone()[0]) <= 8
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM meta WHERE key LIKE 'epoch-open:%'").fetchone()[0]) <= 8
    other = tmp_path / "x"
    other.mkdir()
    with running(make_settings(other, max_epochs_per_principal=3)) as h:  # long retention: closed ones are kept
        for i in range(3):
            eid = h.epoch(key=f"k{i}")
            h.post(f"/v1/epochs/{eid}/close", {}, "-")
        r = h.post("/v1/epochs", {"request_id": "cd" * 16}, "new")
        assert r.status_code == 429 and r.json()["details"]["resource"] == "epochs"


# ---- 16 --------------------------------------------------------------------------------------
def _ack_all(h: Any, name: str, who: str = "alice") -> Any:
    page = h.get("/v1/events", domain_id=DOMAIN, limit=200).json()
    jid, _, top = page["next_cursor"].partition(":")
    return h.post(f"/v1/consumers/{name}/ack", {"domain_id": DOMAIN, "journal_id": jid, "sequence": top}, "-", who=who)


def test_16_consumers_are_bounded_per_principal_and_globally(tmp_path: Path) -> None:
    s = make_settings(tmp_path, max_consumers_per_principal=2, max_consumers=3)
    with running(s) as h:
        h.post("/v1/messages", message(h.epoch()), "k")
        assert _ack_all(h, "c1").status_code == 200
        assert _ack_all(h, "c2").status_code == 200
        third = _ack_all(h, "c3")
        check("ack_consumer", third)
        assert third.status_code == 429 and third.json()["details"]["resource"] == "consumers"
        assert _ack_all(h, "c1").status_code == 200  # existing consumers are never locked out
        assert _ack_all(h, "c1", who="bob").status_code == 200
        assert _ack_all(h, "c2", who="bob").status_code == 429  # global limit (3)
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM consumers").fetchone()[0]) == 3


@pytest.mark.parametrize("how", ["lease expired", "principal disabled"])
def test_16_dead_consumers_do_not_pin_the_journal(tmp_path: Path, how: str) -> None:
    with running(make_settings(tmp_path, event_retention_ms=0)) as h:
        h.post("/v1/messages", message(h.epoch()), "k")
        h.post("/v1/messages", message(h.epoch("alice", "e2")), "k2")
        assert h.post("/v1/consumers/stale/ack", {"domain_id": DOMAIN, "journal_id": h.get(
            "/v1/events", domain_id=DOMAIN).json()["next_cursor"].partition(":")[0], "sequence": "0"},
            "-", who="bob").status_code == 200
        if how == "lease expired":
            h.db(lambda c: c.execute("UPDATE consumers SET lease_expires_utc_ms=1 WHERE principal='bob'"))
        else:
            h.db(lambda c: c.execute("UPDATE principals SET enabled=0 WHERE id='bob'"))
        assert _ack_all(h, "live").status_code == 200
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM events").fetchone()[0]) == 0  # bob no longer pins
        if how == "lease expired":
            assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM consumers WHERE principal='bob'").fetchone()[0]) == 0


# ---- 17 --------------------------------------------------------------------------------------
def test_17_wait_wake_is_a_phase_that_can_be_left(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        op, raw = sent(h)
        rec = lambda **kw: h.db(lambda c: outbox.record(c, h.hub.cfg, raw, **kw))  # noqa: E731
        assert rec(state="WAIT_WAKE", evidence=ev("TARGET_SLEEPING", "LINK_VERIFIED"))["state"] == "WAIT_WAKE"
        assert rec(state="WAITING_RECEIPT", outcome="SUBMITTED")["state"] == "WAITING_RECEIPT"
        assert rec(state="WAIT_WAKE")["state"] == "WAIT_WAKE"
        done = rec(state="FINAL", outcome="APPLIED", evidence=ev("APP_APPLIED"))  # terminal receipt from WAIT_WAKE
        assert done["state"] == "FINAL" and done["outcome"] == "APPLIED"
        assert h.db(lambda c: c.execute("SELECT state FROM outbox").fetchone()[0]) == "DONE"
        assert rec(state="WAIT_WAKE")["state"] == "FINAL"  # nothing leaves FINAL


def test_17_backward_transitions_are_ignored(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        op, raw = sent(h)
        rec = lambda **kw: h.db(lambda c: outbox.record(c, h.hub.cfg, raw, **kw))  # noqa: E731
        rec(state="WAITING_RECEIPT")
        assert rec(state="PENDING")["state"] == "WAITING_RECEIPT"
        assert rec(state="HOST_COMMITTED")["state"] == "WAITING_RECEIPT"


# ---- 18 --------------------------------------------------------------------------------------
def test_18_redelivered_evidence_is_deduplicated(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        op, raw = sent(h)
        one = ev("END_RECEIVED", observer=NODE, n=1)
        one = {**one, "observed_mono_ms": "5"}
        for _ in range(5):
            h.db(lambda c: outbox.record(c, h.hub.cfg, raw, outcome="RECEIVED", evidence=one))
        v = view(h, op)
        assert v["evidence"] == [one]
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM events WHERE operation=?", (raw,)).fetchone()[0]) == 2
        # a different receipt is different evidence
        h.db(lambda c: outbox.record(c, h.hub.cfg, raw, evidence={**one, "observed_mono_ms": "6"}))
        assert len(view(h, op)["evidence"]) == 2


def test_18_evidence_history_is_bounded_but_outcomes_still_apply(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        op, raw = sent(h)
        for n in range(200):
            h.db(lambda c, n=n: outbox.record(c, h.hub.cfg, raw, evidence=ev("HOP_ACCEPTED", "LINK_VERIFIED", n=n)))
        v = view(h, op)
        assert len(v["evidence"]) <= outbox.MAX_EVIDENCE
        assert [e["kind"] for e in v["evidence"]].count("HOST_EVIDENCE_TRUNCATED") == 1  # loss is stated
        done = h.db(lambda c: outbox.record(c, h.hub.cfg, raw, state="FINAL", outcome="APPLIED",
                                            evidence=ev("APP_APPLIED")))
        assert done["outcome"] == "APPLIED" and done["evidence"][-1]["kind"] == "APP_APPLIED"
        assert len(done["evidence"]) <= outbox.MAX_EVIDENCE + outbox.EVIDENCE_TERMINAL_EXTRA


# ---- 24 --------------------------------------------------------------------------------------
def test_24_journal_event_carries_the_exact_evidence(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        op, raw = sent(h)
        mid = b"\x33" * 16
        real = {**ev("END_RECEIVED", "END_VERIFIED", receipt="r-1"), "observer": NODE, "observed_mono_ms": "77",
                "root_term": 4}
        h.db(lambda c: outbox.record(c, h.hub.cfg, raw, outcome="RECEIVED", evidence=real, message_id=mid))
        events = op_events(h, op)
        last = events[-1]
        check("read_events", h.get("/v1/events", domain_id=DOMAIN))
        assert last["message_id"] == mid.hex()
        wrapper = last["evidence"]
        assert wrapper["assurance"] == "SELF_REPORTED" and wrapper["kind"] == "HOST_RECORDED"
        assert wrapper["details"]["recorded_evidence"] == real  # exact, incl. END_VERIFIED + observer
        assert wrapper["details"]["operation_id"] == op
