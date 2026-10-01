"""Review R02-R06: fault propagation, offline admission and bounded dispatch."""
from __future__ import annotations

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from host_util import DOMAIN, NODE, make_settings, message, running
from leanmesh_host import storage
from leanmesh_host.db import mirror, ops, outbox


def test_rollback_failure_completes_active_and_queued_futures(tmp_path: Path, monkeypatch) -> None:
    st = storage.StorageThread(tmp_path / "db", Path(__file__).resolve().parents[3] / "db/schema.sql")
    st.start()
    entered, release = threading.Event(), threading.Event()

    def fail(conn):
        entered.set()
        assert release.wait(3)
        raise sqlite3.OperationalError("write I/O error")

    def bad_rollback(conn):
        raise sqlite3.OperationalError("rollback I/O error")

    monkeypatch.setattr(storage, "_rollback", bad_rollback)
    first = st.submit(fail)
    assert entered.wait(3)
    queued = st.submit(lambda c: c.execute("SELECT 1").fetchone())
    cancelled = st.submit(lambda c: None)
    cancelled.cancel()
    release.set()
    try:
        for fut in (first, queued):
            with pytest.raises(storage.StorageFault):
                fut.result(timeout=3)
        assert st.failed and cancelled.cancelled()
        with pytest.raises(storage.StorageFault):
            st.submit(lambda c: None)
    finally:
        st.stop()


def test_storage_failure_health_and_api_return_without_db_roundtrip(tmp_path: Path, monkeypatch) -> None:
    with running(make_settings(tmp_path)) as h:
        def bad_rollback(conn):
            raise sqlite3.OperationalError("rollback I/O error")
        monkeypatch.setattr(storage, "_rollback", bad_rollback)
        def fail(conn):
            raise sqlite3.OperationalError("write I/O error")
        with pytest.raises(storage.StorageFault):
            h.db(fail)
        assert h.get("/v1/health").json()["database"] == "FAILED"
        assert h.get("/v1/status").json()["ready"] is False
        assert h.get("/v1/nodes", domain_id=DOMAIN).status_code == 503


@pytest.mark.parametrize("stage", ["COMMIT", "closed", "checkpoint"])
def test_connection_failures_are_fatal_and_restart_requires_a_new_owner(tmp_path: Path, monkeypatch, stage) -> None:
    real_open = storage._open

    class Connection:
        def __init__(self, conn):
            self.conn = conn
            self.armed = False

        def __getattr__(self, name):
            return getattr(self.conn, name)

        def execute(self, sql, *args):
            if self.armed and ((stage == "COMMIT" and sql == "COMMIT") or
                               (stage == "checkpoint" and sql.startswith("PRAGMA wal_checkpoint"))):
                error = sqlite3.OperationalError("injected disk I/O error")
                error.sqlite_errorcode = sqlite3.SQLITE_IOERR
                raise error
            return self.conn.execute(sql, *args)

    holder = []

    def opening(*args):
        conn = Connection(real_open(*args))
        holder.append(conn)
        return conn

    monkeypatch.setattr(storage, "_open", opening)
    st = storage.StorageThread(tmp_path / "db", Path(__file__).resolve().parents[3] / "db/schema.sql")
    st.start()
    holder[0].armed = True
    if stage == "checkpoint":
        assert st.submit(lambda c: 7).result(timeout=3) == 7
        st.stop()
        assert st.failed
    else:
        entered, release = threading.Event(), threading.Event()

        def work(conn):
            entered.set()
            assert release.wait(3)
            if stage == "closed":
                conn.close()
            return 7

        active = st.submit(work)
        assert entered.wait(3)
        queued = st.submit(lambda c: 8)
        release.set()
        for future in (active, queued):
            with pytest.raises(storage.StorageFault):
                future.result(timeout=3)
        st.stop()
    with pytest.raises(storage.StorageFault):
        st.submit(lambda c: None)
    monkeypatch.setattr(storage, "_open", real_open)
    fresh = storage.StorageThread(st.db_path, st._schema_path)
    fresh.start()
    try:
        assert fresh.submit(lambda c: c.execute("SELECT 1").fetchone()[0]).result(timeout=3) == 1
    finally:
        fresh.stop()


def test_startup_failure_releases_waiter_even_when_close_fails(tmp_path: Path, monkeypatch) -> None:
    class Connection:
        def close(self):
            raise OSError("close failed")

    monkeypatch.setattr(storage, "_open", lambda *args: Connection())
    monkeypatch.setattr(storage, "_journal_id", lambda c: (_ for _ in ()).throw(ValueError("schema failed")))
    st = storage.StorageThread(tmp_path / "db", Path(__file__).resolve().parents[3] / "db/schema.sql")
    with ThreadPoolExecutor() as pool:
        future = pool.submit(st.start)
        with pytest.raises(storage.StorageFault, match="schema failed"):
            future.result(timeout=3)
    assert st.failed
    st.stop()


def test_offline_deadline_releases_capacity_without_claim(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, max_open_operations=1)) as h:
        epoch = h.epoch()
        expiry = (datetime.now(UTC) + timedelta(milliseconds=300)).isoformat()
        op = h.post("/v1/messages", message(epoch, deadline={"mode": "utc", "expires_at": expiry}), "first")
        assert op.status_code == 202
        end = time.monotonic() + 3
        while True:
            state = h.get(f"/v1/operations/{op.json()['id']}").json()
            if state["state"] == "FINAL":
                break
            assert time.monotonic() < end
            time.sleep(.02)
        assert state["outcome"] == "EXPIRED"
        assert h.post("/v1/messages", message(epoch), "second").status_code == 202
        assert h.db(lambda c: c.execute("SELECT external_write_possible FROM outbox WHERE operation=?",
                                        (bytes.fromhex(op.json()["id"]),)).fetchone())[0] == 0


def test_expiry_does_not_finalize_possibly_written_or_root_deadlines(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        epoch = h.epoch()
        op = h.post("/v1/messages", message(epoch), "sent").json()["id"]
        h.db(lambda c: outbox.claim(c, h.hub.cfg, b"x" * 16))
        h.db(lambda c: c.execute("UPDATE operations SET expiry_utc_ms=0 WHERE id=?", (bytes.fromhex(op),)))
        root = h.post("/v1/messages", message(epoch, deadline={"mode": "root", "root_term": 1,
                                                             "expires_root_ms": "1"}), "root-clock").json()["id"]
        assert h.db(lambda c: outbox.expire_unsent(c, h.hub.cfg)) == 0
        assert h.get(f"/v1/operations/{op}").json()["state"] == "SENDING"
        assert h.get(f"/v1/operations/{root}").json()["state"] != "FINAL"


def test_full_latest_replaces_only_same_unsent_stream(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, max_open_operations=1)) as h:
        epoch = h.epoch()
        latest = dict(queue_mode="LATEST", coalesce_key="7", delivery="BEST_EFFORT", storage="VOLATILE",
                      deadline={"mode": "root", "root_term": 1, "expires_root_ms": "99999"})
        first = h.post("/v1/messages", message(epoch, **latest), "old")
        assert first.status_code == 202, first.text
        different = h.post("/v1/messages", message(epoch, app_port=8, **latest), "other-port")
        assert different.status_code == 429
        second = h.post("/v1/messages", message(epoch, payload_b64="bmV3", **latest), "new")
        assert second.status_code == 202, second.text
        old = h.get(f"/v1/operations/{first.json()['id']}").json()
        assert old["outcome"] == "SUPERSEDED" and old["superseded_by"] == second.json()["id"]
        h.db(lambda c: outbox.claim(c, h.hub.cfg, b"x" * 16))
        assert h.post("/v1/messages", message(epoch, **latest), "third").status_code == 429


def test_dispatch_reserves_urgent_and_preserves_bulk_progress(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        epoch = h.epoch()
        bulk = [h.post("/v1/messages", message(epoch, priority="BULK"), f"b{i}").json()["id"] for i in range(10)]
        urgent = [h.post("/v1/messages", message(epoch, priority="URGENT"), f"u{i}").json()["id"] for i in range(12)]
        normal = h.post("/v1/messages", message(epoch), "normal").json()["id"]
        # Clock corrections/ties must never reorder accepted entries within a class.
        h.db(lambda c: c.execute("UPDATE operations SET created_utc_ms=-rowid"))
        picked = [h.db(lambda c: outbox.claim(c, h.hub.cfg, b"x" * 16, 1))[0].operation.hex() for _ in range(8)]
        assert picked[0] in urgent
        assert normal in picked and any(op in bulk for op in picked)
        assert [op for op in picked if op in urgent] == urgent[:sum(op in urgent for op in picked)]


def test_latest_scope_failure_and_concurrent_replacements_are_atomic(tmp_path: Path, monkeypatch) -> None:
    with running(make_settings(tmp_path, max_open_operations=1)) as h:
        epoch, bob_epoch = h.epoch(), h.epoch("bob")
        latest = dict(queue_mode="LATEST", coalesce_key="7", delivery="BEST_EFFORT", storage="VOLATILE",
                      deadline={"mode": "root", "root_term": 1, "expires_root_ms": "99999"})
        first = h.post("/v1/messages", message(epoch, **latest), "old").json()["id"]
        assert h.post("/v1/messages", message(bob_epoch, **latest), "bob", "bob").status_code == 429
        other = "02" * 32
        h.db(lambda c: mirror.upsert_node(c, bytes.fromhex(DOMAIN), bytes.fromhex(other),
                                         assignment_generation=1, membership_generation=1,
                                         membership="ACTIVE", connectivity="REACHABLE", confirmed=True))
        assert h.post("/v1/messages", message(epoch, destination={"kind": "node", "device_id": other},
                                             **latest), "other-dest").status_code == 429
        original = ops.operation_event

        def fail_after_replacement(*args, **kwargs):
            if kwargs.get("admission"):
                raise storage.StorageFull("no room for admission evidence")
            return original(*args, **kwargs)

        monkeypatch.setattr(ops, "operation_event", fail_after_replacement)
        assert h.post("/v1/messages", message(epoch, **latest), "no-room").status_code == 507
        assert h.get(f"/v1/operations/{first}").json()["state"] != "FINAL"
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM operations").fetchone()[0]) == 1
        monkeypatch.setattr(ops, "operation_event", original)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda i: h.post("/v1/messages", message(epoch, **latest), f"new{i}"), range(2)))
        assert all(r.status_code == 202 for r in results)
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM operations WHERE state!='FINAL'").fetchone()[0]) == 1


@pytest.mark.parametrize("kind", ["LEAVE", "root_app"])
def test_unsupported_public_operation_is_rejected_before_commit(tmp_path: Path, kind: str) -> None:
    with running(make_settings(tmp_path)) as h:
        epoch = h.epoch()
        if kind == "root_app":
            body = message(epoch, destination={"kind": "root_app"})
            response = h.post("/v1/messages", body, "unsupported")
        else:
            body = {"domain_id": DOMAIN, "client_epoch": epoch, "expected_revision": "0", "type": "LEAVE",
                    "request_id": "01" * 16, "device_id": NODE, "leave_mode": "DRAIN"}
            response = h.post("/v1/control", body, "unsupported")
        assert response.status_code == 503 and response.json()["code"] == "UNSUPPORTED", response.text
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM operations").fetchone())[0] == 0
