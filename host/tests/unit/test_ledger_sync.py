"""Issue #5: the Host's rules of when to ask the root for a ledger backup, how a failed ask is retried, how the end of a root
operation is found by the coroutine that waits for it, and which queued LEDGER_RESTORE a connecting replacement root runs."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from backup_util import DOMAIN, OTHER_ROOT, ROOT, handover_cose
from leanmesh_host.bridge import ledger as sync
from leanmesh_host.settings import Settings
from leanmesh_host.wire import WireError

REPO = Path(__file__).resolve().parents[3]


def bridge(debounce: float = 5.0, gap: float = 30.0) -> Any:
    cfg = Settings(db_path=Path("x"), tokens_path=Path("y"), schema_path=Path("z"),
                   ledger_backup_debounce_s=debounce, ledger_backup_min_interval_s=gap)
    return SimpleNamespace(cfg=cfg, link=None, info=None)


def test_a_change_arms_one_pull_after_the_debounce_and_never_closer_than_the_gap() -> None:
    s = sync.LedgerSync(bridge())
    assert s.due is None                              # nothing is wanted while nothing changed: no timer, no polling
    t0 = time.monotonic()
    s.changed()
    assert s.due is not None and 4.9 <= s.due - t0 <= 5.5
    armed = s.due
    s.changed()                                       # a burst of changes is one pull, at the first one's time
    assert s.due == armed
    s2 = sync.LedgerSync(bridge(debounce=1.0, gap=30.0))
    s2._last = time.monotonic()                       # a pull was made just now: the gap holds the next one back
    s2.changed()
    assert s2.due is not None and s2.due - time.monotonic() > 28.0
    s3 = sync.LedgerSync(bridge())
    s3.supported = False                              # a root that does not know the methods is not asked again
    s3.changed()
    assert s3.due is None
    s4 = sync.LedgerSync(bridge())
    s4.new_session()                                  # once per session, soon
    assert s4.due is not None and s4.due - time.monotonic() <= sync.BACKUP_FIRST_S + 0.1


def test_a_failed_pull_is_retried_with_growing_pauses_and_then_given_up_until_the_next_change() -> None:
    s = sync.LedgerSync(bridge())
    gaps = []
    for _ in range(sync.BACKUP_ATTEMPTS - 1):
        s._later("busy")
        assert s.due is not None
        gaps.append(round(s.due - time.monotonic()))
    assert gaps[:5] == [5, 10, 20, 40, 60] and set(gaps[5:]) == {60}   # grows to a minute and stays
    s._later("busy")                                  # the tenth failure in a row
    assert s.due is None                              # nothing more is tried until the ledger changes again
    s.changed()
    assert s.due is not None and s._failures == 0     # (a change starts the count again)
    assert all(g >= 5 for g in gaps)                  # never faster than the bridge's own one-second poll


def test_the_end_of_a_root_operation_is_found_whether_it_comes_before_or_after_the_wait() -> None:
    async def run() -> None:
        ops = sync.RootOps()
        ops.note(7, 0)                                # the event beat the coroutine to it
        assert await ops.wait(7, 1.0) == 0
        assert await ops.wait(7, 0.05) is None        # taken once; nothing else is made up
        waiter = asyncio.create_task(ops.wait(9, 2.0))
        await asyncio.sleep(0.05)
        ops.note(8, 3)                                # another operation's end does not end this wait
        ops.note(9, 24)
        assert await waiter == 24
        for op in range(sync.OWN_OPS + 10):           # bounded: the oldest entries make room
            ops.note(1000 + op, 0)
        assert len(ops._results) == sync.OWN_OPS
        ops.mine(5)
        ops.clear()                                   # a new root boot: its numbers start again
        assert not ops._results and not ops.own

    asyncio.run(run())


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript((REPO / "db" / "schema.sql").read_text())
    conn.execute("INSERT INTO principals VALUES('p',?, '[\"CONFIGURE\"]',1)", (bytes(32),))
    conn.execute("INSERT INTO client_epochs(id,principal,state) VALUES(?,'p','OPEN')", (bytes([1]) * 16,))
    conn.execute("INSERT INTO domains(id,root_device) VALUES(?,?)", (DOMAIN, ROOT))
    return conn


def _queue(conn: sqlite3.Connection, n: int, handover: bytes, *, state: str = "QUEUED", written: int = 0,
           next_at: int | None = None, seq: str = "3", typ: str = "LEDGER_RESTORE") -> bytes:
    op = bytes([n]) * 16
    conn.execute("INSERT INTO operations(id,principal,domain,type,client_epoch,idempotency_key,request_hash,request_json,"
                 "payload,state,outcome) VALUES(?,?,?,?,?,?,?,?,?,?, 'PENDING')",
                 (op, "p", DOMAIN, typ, bytes([1]) * 16, f"k{n}", bytes(32), f'{{"expected_revision":"{seq}"}}', handover,
                  "HOST_COMMITTED" if state == "QUEUED" else "FINAL"))
    conn.execute("INSERT INTO outbox(operation,state,external_write_possible,next_attempt_utc_ms) VALUES(?,?,?,?)",
                 (op, state, written, next_at))
    return op


def test_a_connecting_replacement_root_runs_only_the_restore_queued_for_exactly_that_change() -> None:
    conn = _db()
    handover = handover_cose(ROOT, OTHER_ROOT)
    assert sync.queued_restore(conn, DOMAIN, OTHER_ROOT) is None                      # nothing queued
    other = _queue(conn, 1, handover_cose(bytes([9]) * 32, OTHER_ROOT))               # hands over from another root
    _queue(conn, 2, handover_cose(ROOT, bytes([8]) * 32))                             # to another new root
    _queue(conn, 3, handover, state="DONE")                                           # already finished
    _queue(conn, 4, handover, state="SENDING", written=1)                             # already claimed
    _queue(conn, 5, handover, typ="MESSAGE")                                          # not a restore
    _queue(conn, 6, handover, next_at=int(time.time() * 1000) + 60_000)               # waits for its retry time
    assert sync.queued_restore(conn, DOMAIN, OTHER_ROOT) is None
    op = _queue(conn, 7, handover, seq="12")                                          # the one
    assert sync.queued_restore(conn, DOMAIN, OTHER_ROOT) == (op, handover, 12)
    assert sync.queued_restore(conn, DOMAIN, ROOT) is None                            # the bound root itself: nothing to bind
    conn.execute("UPDATE domains SET root_device=?", (bytes(32),))
    assert sync.queued_restore(conn, DOMAIN, OTHER_ROOT) is None                      # a domain with no root yet: no mismatch
    conn.execute("UPDATE domains SET root_device=?", (bytes([9]) * 32,))
    assert sync.queued_restore(conn, DOMAIN, OTHER_ROOT) == (other, handover_cose(bytes([9]) * 32, OTHER_ROOT), 3)
    assert sync.handover_roots(handover) == (ROOT, OTHER_ROOT)
    with pytest.raises(WireError):  # anything that is not a handover is not accepted as one
        sync.handover_roots(b"\x00" * 8)
