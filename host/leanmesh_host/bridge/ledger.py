"""Ledger backup (pull) and restore (push) over the serial methods 18..22 (issue #5, docs/19 §9, docs/12 §5, docs/21 §8).

Pull. The Host asks the root for a backup when a ledger change has been reported (a membership event, the end of a root
control operation) and once per session, never faster than BACKUP_MIN_INTERVAL_S and not before BACKUP_DEBOUNCE_S after the
change (a burst of joins is one backup). A failed pull (the root is busy, a join changed the ledger meanwhile, an answer is
missing) is tried again after a growing pause and given up after BACKUP_ATTEMPTS: nothing polls while nothing changed. What
is stored is what the header says (db/ledger_backup.py); a lower sequence never replaces a higher one.

Restore. LEDGER_RESTORE is one Host operation that drives three root steps (handover, header, records), each ended by the
root's OPERATION event, to a replacement root that has no ledger. It runs from the outbox like any control, or - when the
connected root is not the one the domain is bound to - at session start, BEFORE the bridge is ready, because the root is
accepted as the domain's only when a handover from the bound root to it has been carried out (FIX11-D15): the operator's
queued restore names exactly that pair, and its success is what lets the root be bound.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from ..db import ledger_backup, outbox
from ..events.journal import now_ms
from ..serial import SessionChanged, SessionGone
from ..serial.link import SerialBusy
from ..wire import WireError, cbor_decode, cbor_encode
from ..wire.control import decode_control_body, decode_cose_sign1
from . import mapping
from .mapping import status_name

if TYPE_CHECKING:
    from ..serial import SerialLink
    from .bridge import Bridge, RootInfo

log = logging.getLogger(__name__)

M_BACKUP_BEGIN, M_BACKUP_GET = 18, 19
M_RESTORE_HANDOVER, M_RESTORE_HEADER, M_RESTORE_RECORD = 20, 21, 22
CTL_OP_TAG = 1 << 62

# (the debounce after a change and the minimum gap between two pulls are Settings: 5 s and 30 s, never below 1 s)
BACKUP_FIRST_S = 2.0           # after the session came up
BACKUP_RETRY_S = (5.0, 10.0, 20.0, 40.0, 60.0)
BACKUP_ATTEMPTS = 10           # consecutive failures before the Host waits for the next change
RESTORE_ATTEMPTS = 5           # a restore the serial session interrupted is started again (it clears its own traces) this often
RESTORE_RETRY_S = 2.0
BUSY_PAUSE_S = 0.02            # a record is one Flash read at the root; the answer is BUSY until it is in
BUSY_TRIES = 150
OP_WAIT_S = 30.0               # the end of a root operation (a backup's scan and signature, a record's write)
OWN_OPS = 512                  # root operation numbers of this Host's own backup/restore steps (their events are not changes)


class Retry(Exception):
    """A pull that did not end: the reason is the log line, the caller schedules the next attempt."""


class RootOps:
    """The ends of the root's control operations (OPERATION events), kept for the coroutine that waits for one. An event that
    arrives before the wait begins is found (bounded table)."""

    def __init__(self) -> None:
        self._results: OrderedDict[int, int] = OrderedDict()
        self._evt = asyncio.Event()
        self.own: OrderedDict[int, None] = OrderedDict()

    def note(self, op: int, reason: int) -> None:
        self._results[op] = reason
        while len(self._results) > OWN_OPS:
            self._results.popitem(last=False)
        self._evt.set()

    def mine(self, op: int) -> None:
        self.own[op] = None
        while len(self.own) > OWN_OPS:
            self.own.popitem(last=False)

    def clear(self) -> None:  # a new root boot: its operation numbers start again
        self._results.clear()
        self.own.clear()

    async def wait(self, op: int, timeout: float) -> int | None:
        deadline = time.monotonic() + timeout
        while True:
            self._evt.clear()  # (no await between this and the check: an event cannot slip in)
            if op in self._results:
                return self._results.pop(op)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._evt.wait(), remaining)


def handover_roots(cose: bytes) -> tuple[bytes, bytes]:
    """(old root, new root) of a RootHandover COSE: structure only, the root verifies the signature."""
    data = cbor_decode(decode_control_body(decode_cose_sign1(cose).payload, "signed").data)
    return bytes(data[1]), bytes(data[2])


def queued_restore(conn: sqlite3.Connection, domain: bytes, root: bytes) -> tuple[bytes, bytes, int] | None:
    """A LEDGER_RESTORE the operator queued whose handover hands the domain over from the root it is bound to
    to `root` (the root that is connected now): (operation, handover COSE, backup sequence). None: no such operation."""
    row = conn.execute("SELECT root_device FROM domains WHERE id=?", (domain,)).fetchone()
    bound = bytes(row[0]) if row is not None and row[0] is not None else b"\0" * 32
    if bound in (b"\0" * 32, root):
        return None
    for op, payload, req in conn.execute(
            "SELECT o.id,o.payload,json_extract(o.request_json,'$.expected_revision') FROM operations o "
            "JOIN outbox b ON b.operation=o.id WHERE o.domain=? AND o.type='LEDGER_RESTORE' AND b.state='QUEUED' "
            "AND b.external_write_possible=0 AND o.state!='FINAL' "
            "AND (b.next_attempt_utc_ms IS NULL OR b.next_attempt_utc_ms<=?) ORDER BY o.rowid", (domain, now_ms())).fetchall():
        try:
            old, new = handover_roots(bytes(payload))
        except (WireError, TypeError, IndexError):
            continue
        if old == bound and new == root:
            return bytes(op), bytes(payload), int(req)
    return None


class LedgerSync:
    def __init__(self, bridge: Bridge) -> None:
        self.bridge = bridge
        self.ops = RootOps()
        self.due: float | None = None      # monotonic time of the next pull (None: nothing is wanted)
        self.supported = True              # the root answered the methods (an older firmware does not know them)
        self.restoring = False
        self.restore_evt = asyncio.Event()  # set while a restore runs before the bridge is ready (the event loop serves it)
        self._last = -1e9
        self._failures = 0

    # ---- when ----------------------------------------------------------------------------------
    def new_session(self) -> None:
        self.supported = True
        self._failures = 0
        self.due = time.monotonic() + BACKUP_FIRST_S

    def changed(self) -> None:
        """The root reported a change of its ledger (or of what a restore may have to carry)."""
        if not self.supported:
            return
        self._failures = 0
        if self.due is None:
            cfg = self.bridge.cfg
            self.due = max(time.monotonic() + cfg.ledger_backup_debounce_s, self._last + cfg.ledger_backup_min_interval_s)

    def _later(self, why: str) -> None:
        self._failures += 1
        if self._failures >= BACKUP_ATTEMPTS:
            log.error("ledger backup: given up after %d attempts (%s); the next ledger change tries again", self._failures, why)
            self.due = None
            return
        gap = BACKUP_RETRY_S[min(self._failures - 1, len(BACKUP_RETRY_S) - 1)]
        self.due = time.monotonic() + gap
        log.info("ledger backup: %s; again in %.0f s", why, gap)

    # ---- pull ----------------------------------------------------------------------------------
    async def maybe_pull(self) -> None:
        b = self.bridge
        if self.due is None or time.monotonic() < self.due or not self.supported or b.link is None or b.info is None:
            return
        self.due = None
        try:
            await self._pull(b.link, b.info)
        except Retry as exc:
            self._later(str(exc))
        except (SessionChanged, SessionGone, SerialBusy):
            self._later("the serial session changed")
        except TimeoutError:
            # An answer that never comes: a root whose firmware does not know the methods drops them as malformed.
            self.supported = False
            log.warning("ledger backup: the root did not answer method %d; no backup is asked for this session", M_BACKUP_BEGIN)

    async def _pull(self, link: SerialLink, info: RootInfo) -> None:
        res = await link.request(M_BACKUP_BEGIN, None)
        if res.status == mapping.UNSUPPORTED:
            self.supported = False
            log.warning("ledger backup: the root does not support it")
            return
        if res.status != mapping.OK or res.operation_id is None:
            raise Retry(f"the root answered BACKUP_BEGIN with {status_name(res.status)}")
        self.ops.mine(res.operation_id)
        ended = await self.ops.wait(res.operation_id, OP_WAIT_S)
        if ended is None or ended != mapping.OK:
            raise Retry("the backup did not end at the root" if ended is None else f"the root ended the backup with {status_name(ended)}")
        first = await self._page(link, 0, 0)  # seq 0: the header of the backup the root holds (its sequence is inside)
        header = bytes(first["data"])
        seq = int(ledger_backup.parse_header(header)["sequence"])
        count = int(first["count"])
        pages: list[tuple[int, int, bytes]] = []
        for index in range(1, count + 1):
            page = await self._page(link, seq, index)
            pages.append((int(page["id"]), int(page["state"]), bytes(page["data"])))
        try:
            backup = ledger_backup.build(header, pages)
        except ledger_backup.BackupError as exc:
            raise Retry(f"the backup of sequence {seq} is damaged ({exc})") from exc
        if backup.domain != info.domain or backup.root != info.root:
            raise Retry("the backup is not of this root and domain")

        def keep(conn: sqlite3.Connection) -> str:
            return ledger_backup.store(conn, info.domain, backup)

        try:
            kept = await self.bridge.hub.write(keep)
        except ledger_backup.BackupError as exc:
            raise Retry(str(exc)) from exc
        self._last = time.monotonic()
        self._failures = 0
        log.info("ledger backup: sequence %d (%d records) %s", backup.sequence, backup.count, kept.lower())

    async def _page(self, link: SerialLink, seq: int, index: int) -> dict[str, Any]:
        for _ in range(BUSY_TRIES):
            res = await link.request(M_BACKUP_GET, [seq, index])
            if res.status == mapping.OK and res.result is not None:
                return dict(cbor_decode(res.result))
            if res.status != mapping.BUSY:
                raise Retry(f"the root answered BACKUP_GET {index} with {status_name(res.status)}")
            await asyncio.sleep(BUSY_PAUSE_S)
        raise Retry(f"the root kept record {index} busy")

    # ---- restore -------------------------------------------------------------------------------
    async def restore_new_root(self, link: SerialLink, info: RootInfo) -> bool:
        """The connected root is not the domain's bound root: when the operator queued a LEDGER_RESTORE for exactly this
        change of root, run it now (before the bridge is ready). True: it ran (the handover mark is written when it succeeded)."""
        b = self.bridge
        found = await b.hub.read(lambda conn: queued_restore(conn, info.domain, info.root))
        if found is None:
            return False
        op, handover, seq = found
        incarnation = b.incarnation(info)

        def claim(conn: sqlite3.Connection) -> int | None:
            return outbox.claim_one(conn, op, incarnation)

        attempt = await b.hub.write(claim)
        if attempt is None:
            return False
        self.restoring = True
        self.restore_evt.set()
        try:
            await self.run_restore(link, info, op, handover, seq, attempt, bind=True)
        finally:
            self.restoring = False
            self.restore_evt.clear()
        return True

    async def run_restore(self, link: SerialLink, info: RootInfo, op: bytes, handover: bytes, seq: int, attempt: int,
                          *, bind: bool) -> None:
        """The three steps; the operation ends with what the root said. `bind`: the root is not bound to the domain yet:
        the handover old -> new is remembered when the restore succeeded, so that `_register_root` accepts it."""
        b = self.bridge
        backup = await b.hub.read(lambda conn: ledger_backup.load(conn, info.domain))
        if backup is None or backup.sequence != seq:
            await b.hub.write(lambda conn: b.finish(conn, op, "REJECTED", "SELF_REPORTED", "HOST_REFUSED",
                                                    "the stored backup is not the one the request named"))
            return
        steps: list[tuple[int, Any, str]] = [(M_RESTORE_HANDOVER, [handover], "handover"),
                                             (M_RESTORE_HEADER, [backup.header], "header")]
        steps += [(M_RESTORE_RECORD, [i, r.id, r.state, r.payload, r.next], f"record {i}") for i, r in enumerate(backup.records)]
        done = 0
        try:
            for method, params, what in steps:
                refused = await self._step(link, method, params)
                if refused is not None:
                    await self._ended(op, refused, what, done, info, attempt)
                    return
                done += 1
        except (SessionChanged, SessionGone, SerialBusy, TimeoutError) as exc:
            # The serial session ended (or the root fell silent) in the middle: what the root wrote is not known. A restore
            # starts by clearing its own traces and refuses a root that has a ledger, so it is simply started again, a few
            # times, on the next session; only then is the operation ended as unknown.
            cause = exc.__class__.__name__
            log.warning("ledger restore interrupted after %d of %d steps: %r", done, len(steps), exc)

            def lost(conn: sqlite3.Connection) -> None:
                if attempt < RESTORE_ATTEMPTS:
                    outbox.release_unwritten(conn, b.cfg, op)  # (back to QUEUED: nothing else of the Host depends on it)
                    conn.execute("UPDATE outbox SET next_attempt_utc_ms=? WHERE operation=? AND state='QUEUED'",
                                 (now_ms() + int(RESTORE_RETRY_S * 1000), op))
                    return
                b.finish(conn, op, "INDETERMINATE", "UNKNOWN", "ROOT_OUTCOME_UNKNOWN",
                         f"the restore was interrupted after {done} of {len(steps)} steps ({cause}), {attempt} times; "
                         "ask the root (GET /v1/nodes): with no ledger the same request can be made again")

            await b.hub.write(lost)
            b.hub.outbox_ready.set()
            return

        def applied(conn: sqlite3.Connection) -> None:
            if bind:
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                             (f"handover:{info.domain.hex()}", cbor_encode([backup.root, info.root])))
            b.finish(conn, op, "APPLIED", "SELF_REPORTED", "ROOT_APPLIED",
                     f"ledger of sequence {backup.sequence} restored ({backup.count} records); the root is ready")

        await b.hub.write(applied)

    async def _step(self, link: SerialLink, method: int, params: Any) -> int | None:
        """One root step: asked again while BUSY, then the end of its operation. None: it succeeded; else the status."""
        for _ in range(BUSY_TRIES):
            res = await link.request(method, params)
            if res.status == mapping.BUSY:
                await asyncio.sleep(BUSY_PAUSE_S * 5)
                continue
            if res.status != mapping.OK or res.operation_id is None:
                return res.status
            self.ops.mine(res.operation_id)
            ended = await self.ops.wait(res.operation_id, OP_WAIT_S)
            if ended is None:
                raise TimeoutError("the root did not end the restore step")
            return None if ended == mapping.OK else ended
        raise TimeoutError("the root stayed busy")  # (not a refusal: the restore is started again, as after a lost session)

    async def _ended(self, op: bytes, status: int, what: str, done: int, info: RootInfo, attempt: int) -> None:
        b = self.bridge
        name = status_name(status)

        def refused(conn: sqlite3.Connection) -> None:
            if status == mapping.CONFLICT and what == "handover" and attempt > 1:
                # The root has a ledger now, and an earlier attempt of this very restore was cut: it may have finished.
                b.finish(conn, op, "INDETERMINATE", "UNKNOWN", "ROOT_OUTCOME_UNKNOWN",
                         "the root has a ledger now; an earlier attempt of this restore was interrupted and may have completed "
                         "(compare GET /v1/nodes with the backup)", observer=info.root)
            elif status in mapping.UNKNOWN_STATE:  # the root cannot vouch for what it holds (a failed write)
                b.finish(conn, op, "INDETERMINATE", "UNKNOWN", "ROOT_OUTCOME_UNKNOWN",
                         f"the root answered {name} at the {what} (after {done} steps); with no ledger the same request can be made again",
                         observer=info.root)
            else:
                b.finish(conn, op, "REJECTED", "SELF_REPORTED", "ROOT_REFUSED", f"the root refused the {what}: {name}",
                         observer=info.root)

        await b.hub.write(refused)
