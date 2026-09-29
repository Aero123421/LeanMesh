"""Event journal, cursors, consumer ACK, inbox dedup and the rollback floor (H02, H05)."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from host_util import DOMAIN, NODE, check, make_settings, message, running
from leanmesh_host.api.errors import ApiError
from leanmesh_host.db import outbox
from leanmesh_host.events import journal


def cursor(page: dict[str, Any]) -> tuple[str, int]:
    jid, _, seq = page["next_cursor"].partition(":")
    return jid, int(seq)


def ack(h: Any, name: str, jid: str, seq: int, who: str = "alice") -> Any:
    r = h.post(f"/v1/consumers/{name}/ack", {"domain_id": DOMAIN, "journal_id": jid, "sequence": str(seq)}, "-", who=who)
    check("ack_consumer", r)
    return r


@pytest.mark.scenario("H02")
def test_stale_or_foreign_cursors_are_410_with_oldest_and_latest(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, event_retention_ms=0)) as h:
        e = h.epoch()
        for i in range(6):
            h.post("/v1/messages", message(e), f"k{i}")
        page = h.get("/v1/events", domain_id=DOMAIN, limit=200).json()
        jid, top = cursor(page)
        assert len(page["events"]) == 6 and top == max(int(x["cursor"].split(":")[1]) for x in page["events"])
        # explicit cursor that belongs to another journal
        other = h.get("/v1/events", domain_id=DOMAIN, after="00" * 16 + ":1")
        check("read_events", other)
        assert other.status_code == 410 and other.json()["code"] == "CURSOR_GAP"
        assert other.json()["details"]["journal_id"] == jid
        # a cursor from the future is not accepted either
        assert h.get("/v1/events", domain_id=DOMAIN, after=f"{jid}:{top + 5}").status_code == 410
        assert h.get("/v1/events", domain_id=DOMAIN, after="junk").status_code == 400
        # events at/below the slowest consumer's ACK may be deleted: older cursors become a gap
        ack(h, "kg", jid, top - 1)
        gap = h.get("/v1/events", domain_id=DOMAIN, after=f"{jid}:0")
        check("read_events", gap)
        assert gap.status_code == 410
        d = gap.json()["details"]
        assert d["oldest_cursor"] == f"{jid}:{top - 1}" and d["latest_cursor"] == f"{jid}:{top}"
        # resuming at the advertised oldest cursor works and reaches the latest event
        resumed = h.get("/v1/events", domain_id=DOMAIN, after=d["oldest_cursor"]).json()
        assert cursor(resumed) == (jid, top) and len(resumed["events"]) == 1
        # omitted `after` starts at the oldest retained position, never at "now"
        assert len(h.get("/v1/events", domain_id=DOMAIN).json()["events"]) == 1
        assert h.get("/v1/events", domain_id="cc" * 16).status_code == 404


def test_consumer_ack_is_monotonic_owned_and_never_ahead(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        e = h.epoch()
        for i in range(4):
            h.post("/v1/messages", message(e), f"k{i}")
        jid, top = cursor(h.get("/v1/events", domain_id=DOMAIN, limit=200).json())
        assert ack(h, "kg", jid, 2).json()["next_cursor"] == f"{jid}:2"
        assert ack(h, "kg", jid, 1).json()["next_cursor"] == f"{jid}:2"  # never moves backwards
        assert ack(h, "kg", jid, 2).json() == ack(h, "kg", jid, 2).json()  # idempotent
        assert ack(h, "kg", jid, 2).json()["events"] == []
        future = h.post("/v1/consumers/kg/ack", {"domain_id": DOMAIN, "journal_id": jid, "sequence": str(top + 1)}, "-")
        check("ack_consumer", future)
        assert future.status_code == 409
        wrong = h.post("/v1/consumers/kg/ack", {"domain_id": DOMAIN, "journal_id": "11" * 16, "sequence": "1"}, "-")
        assert wrong.status_code == 410 and wrong.json()["details"]["journal_id"] == jid
        assert h.post("/v1/consumers/kg/ack", {"domain_id": "cc" * 16, "journal_id": jid, "sequence": "0"}, "-").status_code == 404
        assert h.post("/v1/consumers/bad name/ack", {"domain_id": DOMAIN, "journal_id": jid, "sequence": "0"}, "-").status_code == 400
        # the same name under another principal is a different consumer (owner = principal)
        assert ack(h, "kg", jid, 4, who="bob").json()["next_cursor"] == f"{jid}:4"
        assert ack(h, "kg", jid, 1).json()["next_cursor"] == f"{jid}:2"
        assert h.hub.storage.submit(lambda c: c.execute(
            "SELECT principal,ack_sequence FROM consumers ORDER BY principal").fetchall()).result() == [("alice", 2), ("bob", 4)]


def test_inbox_commit_dedups_conflicts_and_refuses_when_full(tmp_path: Path) -> None:
    """Node->Host: one commit for inbox + event before HOST_STORE_ACK; an ACK loss redelivers the same id."""
    args: dict[str, Any] = dict(domain=bytes.fromhex(DOMAIN), origin=bytes.fromhex(NODE), assignment_generation=3,
                                message_id=b"\x05" * 16, intent_hash=b"\x06" * 32, payload=b"reading",
                                assurance={"kind": "END_RECEIVED", "assurance": "END_VERIFIED"})
    with running(make_settings(tmp_path, max_events=3)) as h:
        first = h.db(lambda c: journal.ingest(c, h.hub.cfg, **args))
        again = h.db(lambda c: journal.ingest(c, h.hub.cfg, **args))
        assert not first.duplicate and again.duplicate and again.cursor == first.cursor
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM inbox").fetchone()[0]) == 1
        page = h.get("/v1/events", domain_id=DOMAIN)
        check("read_events", page)
        ev = page.json()["events"][0]
        assert ev["kind"] == "MESSAGE_RECEIVED" and ev["origin"] == NODE and ev["payload_b64"] == "cmVhZGluZw=="
        assert ev["assignment_generation"] == "3" and ev["evidence"]["assurance"] == "END_VERIFIED"
        with pytest.raises(journal.InboxConflict):
            h.db(lambda c: journal.ingest(c, h.hub.cfg, **{**args, "intent_hash": b"\x07" * 32}))
        # another assignment generation is another identity, not a duplicate
        h.db(lambda c: journal.ingest(c, h.hub.cfg, **{**args, "assignment_generation": 4}))
        h.db(lambda c: journal.ingest(c, h.hub.cfg, **{**args, "message_id": b"\x08" * 16}))
        with pytest.raises(ApiError) as full:  # protected events only: refuse, so no ACK is sent
            h.db(lambda c: journal.ingest(c, h.hub.cfg, **{**args, "message_id": b"\x09" * 16}))
        assert full.value.http_status == 507
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM inbox").fetchone()[0]) == 3


@pytest.mark.scenario("H05")
def test_restored_older_database_quarantines_and_never_resends(tmp_path: Path) -> None:
    s = make_settings(tmp_path)
    backup = tmp_path / "backup.db"
    with running(s) as h:
        e_old = h.epoch()
        sent = h.post("/v1/messages", message(e_old), "old-sent").json()["id"]
        queued = h.post("/v1/messages", message(e_old), "old-queued").json()["id"]
        h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x01" * 16, 1))  # `sent` may be on the wire
        journal_before = h.get("/v1/status").json()["journal_id"]
    shutil.copy(s.db_path, backup)  # backup taken at a clean stop (WAL checkpointed)
    with running(s, domain=False) as h:
        post_backup = h.post("/v1/messages", message(h.epoch()), "after-backup").json()["id"]
    # operator restores the old file
    for suffix in ("-wal", "-shm"):
        Path(str(s.db_path) + suffix).unlink(missing_ok=True)
    shutil.copy(backup, s.db_path)
    with running(s, domain=False) as h:
        status = h.get("/v1/status").json()
        assert status["journal_id"] != journal_before  # old cursors are 410, not silently continued
        assert h.get("/v1/events", domain_id=DOMAIN, after=f"{journal_before}:1").status_code == 410
        for op in (sent, queued):
            view = h.get(f"/v1/operations/{op}").json()
            assert view["outcome"] == "INDETERMINATE" and view["state"] == "FINAL"
            assert view["reason"] == "DB_ROLLBACK_QUARANTINE"
        assert h.get(f"/v1/operations/{post_backup}").status_code == 404  # lost with the newer file
        assert h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x02" * 16)) == []  # blind resend impossible
        late = h.post("/v1/messages", message(e_old), "new")
        assert late.status_code == 410 and late.json()["code"] == "EPOCH_CLOSED"
        assert h.post("/v1/messages", message(h.epoch()), "new").status_code == 202  # new epoch works
        kinds = [x["kind"] for x in h.get("/v1/events", domain_id=DOMAIN, limit=200).json()["events"]]
        assert "HOST_DB_ROLLBACK" in kinds
        fault = h.db(lambda c: c.execute("SELECT code,active FROM health_faults").fetchall())
        assert fault == [("DB_ROLLBACK", 1)]
    # a normal restart afterwards is not a rollback and keeps the new epoch/journal
    with running(s, domain=False) as h:
        assert h.get("/v1/status").json()["journal_id"] == status["journal_id"]
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM client_epochs WHERE state='OPEN'").fetchone()[0]) == 1


def test_clean_restart_keeps_epochs_journal_and_operations(tmp_path: Path) -> None:
    s = make_settings(tmp_path)
    with running(s) as h:
        e = h.epoch()
        op = h.post("/v1/messages", message(e), "k").json()
        jid = h.get("/v1/status").json()["journal_id"]
    with running(s, domain=False) as h:
        assert h.get("/v1/status").json()["journal_id"] == jid
        assert h.post("/v1/messages", message(e), "k").json() == op  # replay across restart
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM health_faults").fetchone()[0]) == 0
