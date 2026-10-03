"""The Host bridge (S13): outbox consumer, inbox producer and crash reconciler for the root over the
authenticated USB session (docs/11 §4-§5, docs/19 §4-§7). It runs on the event loop; sqlite work goes
through `Hub.write` (one storage-thread transaction each), serial work through `SerialLink.request`.

The rules that make it safe (each is exercised by host/tests/e2e/test_bridge*.py):
  * `outbox.claim` commits external_write_possible=1 BEFORE bytes leave; the MessageId, the derived
    deadline and the intent_hash are committed in that same transaction, so "a message id exists" and
    "a write may have happened" cannot diverge.
  * A request whose outcome is unknown (crash, timeout, session lost after the write) is never sent again
    blindly: after a restart or a new session the root is asked by MessageId (GET_MESSAGE). Unknown to
    the root -> INDETERMINATE; the Host cannot tell "never arrived" from "arrived and forgotten".
  * root -> Host messages are committed in SQLite (inbox + event journal, one transaction) BEFORE
    HOST_STORE_ACK; EVENT_ACK is only progress. A redelivery after a lost ACK returns the stored commit.
  * Evidence is copied from what the root reports, with the assurance that fact has (mapping.py); a
    missing receipt stays missing.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import sqlite3
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from ..api.errors import ApiError
from ..db import mirror, ops, outbox, startup
from ..events import journal
from ..events.hub import Hub
from ..events.journal import now_ms
from ..power_state import now_ms as power_now_ms
from ..serial import SerialLink, SessionChanged, SessionGone
from ..serial.link import SerialBusy
from ..settings import Settings
from ..wire import WireError, cbor_decode, cbor_encode
from ..wire.control import decode_cose_sign1, decode_control_body
from . import channel as chan_status
from . import diag as diag_status
from . import power as power_status
from . import groups, mapping
from .mapping import status_name

log = logging.getLogger(__name__)

M_CAPABILITIES, M_SEND, M_GET_MESSAGE, M_CANCEL, M_JOIN_DECIDE, M_INSTALL = 1, 2, 3, 4, 5, 6
M_NODE_QUERY, M_HOST_STORE_ACK, M_EVENT_ACK, M_CHANNEL, M_GET_REQUEST, M_GROUP_SET = 7, 9, 10, 11, 13, 14
M_DIAGNOSTICS = 16
M_POLICY_SET = 17  # HIL-F5
CTL_OP_TAG = 1 << 62  # member::k_op_tag: the root's control operations (lifecycle, policy, group set, stop)
EV_MESSAGE, EV_OPERATION, EV_MEMBERSHIP, EV_GAP, EV_FAULT = 2, 3, 4, 7, 8
EV_GROUP_PROGRESS = groups.EV_GROUP_PROGRESS
EV_CHANNEL = chan_status.EV_CHANNEL

MAX_ATTEMPTS = 30          # transient refusals of one operation before it is refused for good
RETRY_S = 1.0              # pause between attempts after a transient refusal of the root
POLL_S = 1.0               # first GET_MESSAGE interval of open operations (only while there are any) ...
POLL_MAX_S = 30.0          # ... doubling while nothing new happens; events and new sends reset it
CAPS_MAX_AGE_S = 5.0       # root clock estimate used for UTC deadlines is refreshed when older
EVENT_QUEUE = 256          # bounded hand-over from the serial thread; overflow is re-sent by the root
POLL_BATCH = 16
MAX_OP_MAP = 4096          # per-boot operation maps (FIX11-D4): as many as open operations; the oldest entry is dropped, and the
                           # fallback is a GET_MESSAGE by MessageId (numbers) or a repeated, idempotent CANCEL
DIAG_MIN_INTERVAL_S = 1.0  # one DIAGNOSTICS exchange per second at most, however many clients ask (S19)
RECONCILE_RETRY_S = 2.0    # pause before an unfinished reconciliation is tried again
JOIN_WAIT_S = 180.0        # a JOIN_DECIDE the root accepted must show durable ledger state within this time
LEDGER_PREPARED = 2        # root EntryState: Prepared (reserved and stored); 3 Active .. 6 Blocked also imply an entry
REQUEST_PENDING = 16       # GET_REQUEST state: waiting for the operator
SIGNED_CONTROLS = ("REVOKE", "TRANSFER", "INSTALL_CONTROL", "POWER_POLICY_SET",
                   "COMMISSIONING_WINDOW_SET", "ROOT_HANDOVER")


@dataclass
class RootInfo:
    """What the authenticated root said about itself (CAPABILITIES)."""
    domain: bytes
    root: bytes
    assignment: int
    boot: int
    enabled: frozenset[str]
    term: int
    time_ms: tuple[int, int] | None  # (earliest, latest) root ms at `fetched`
    fetched: float = field(default_factory=time.monotonic)
    lists: dict[str, frozenset[str]] = field(default_factory=dict)  # docs/18 §6: build, implemented, qualified (S19)

    def root_now_lo(self) -> int | None:
        """Lower bound of the root clock now (never later than the truth: deadlines derived from it
        are never longer than asked for)."""
        if self.time_ms is None:
            return None
        return self.time_ms[0] + int((time.monotonic() - self.fetched) * 1000)

    def root_now_hi(self) -> int | None:
        """Upper bound of the root clock now (a report is never judged younger than it is)."""
        if self.time_ms is None:
            return None
        return self.time_ms[1] + int((time.monotonic() - self.fetched) * 1000)


@dataclass
class Plan:
    op: bytes
    typ: str
    method: int
    params: Any
    mid: bytes | None = None
    attempts: int = 1
    request_id: bytes | None = None  # JOIN_DECISION: the root's pending request
    group: bool = False              # MESSAGE to a group: the root's per-target results are mirrored
    approve: bool = False


class Bridge:
    def __init__(self, hub: Hub, cfg: Settings) -> None:
        self.hub = hub
        self.cfg = cfg
        self.link: SerialLink | None = None
        self.info: RootInfo | None = None
        self.ready = False
        self.stats = {"sent": 0, "refused": 0, "reconciled": 0, "inbox": 0, "duplicates": 0, "events": 0}
        self._gen = 0
        self._events: asyncio.Queue[tuple[bytes, int]] = asyncio.Queue(EVENT_QUEUE)
        self._tasks: list[asyncio.Task[None]] = []
        self._session = asyncio.Event()
        self._ready_evt = asyncio.Event()
        self._need_reconcile = False
        self._next_reconcile = 0.0
        self._next_poll = 0.0
        self._poll_gap = POLL_S
        self._poll_now = False
        # EVENT_ACK is cumulative at the root (FIX2-D9): it may only cover events this Host finished. Every
        # event seen (or dropped on overflow) is "open" until its handling succeeded; the ACK sent never
        # reaches the lowest open sequence number.
        self._open_events: set[tuple[int, int]] = set()   # (root boot, seq)
        self._ack_top: dict[int, int] = {}                # boot -> highest finished seq
        self._ack_sent: dict[int, int] = {}               # boot -> highest EVENT_ACK the root accepted
        self._ctl_ops: OrderedDict[int, tuple[bytes, ...]] = OrderedDict()  # root control-operation number -> Host operations (this boot; a repeated freeze shares its number)
        self._opnum: OrderedDict[bytes, int] = OrderedDict()     # Host operation -> root operation number (this boot)
        self.groups = groups.Groups()          # group operations of this boot and their per-target mirror
        self._cancel_taken: OrderedDict[bytes, None] = OrderedDict()  # operations whose CANCEL the root accepted (idempotent: not repeated)
        self._diag: tuple[float, dict[str, Any], int] | None = None  # (at, body, serial generation) of the last DIAGNOSTICS
        self._diag_lock = asyncio.Lock()

    # ---- wiring ------------------------------------------------------------------------------
    def attach(self, link: SerialLink) -> None:
        self.link = link

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._main(), name="bridge-main"),
                       asyncio.create_task(self._event_loop(), name="bridge-events")]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await t
        self._tasks = []

    def on_state(self, connected: bool, gen: int) -> None:
        """Serial thread -> loop. root_connected is true from ACTIVE; capabilities only after the root
        answered CAPABILITIES (never guessed)."""
        self.hub.set_root(connected, ())
        self.ready = False
        self._ready_evt.clear()
        self._gen = gen if connected else 0
        self._session.set()
        self.hub.outbox_ready.set()

    def on_event(self, payload: bytes, gen: int) -> None:
        try:
            boot, seq = cbor_decode(payload)[:2]
            self._open_events.add((int(boot), int(seq)))
        except Exception:  # not a well-formed EVENT: dropped below; nothing to keep open
            log.warning("malformed root event dropped")
            return
        try:
            self._events.put_nowait((payload, gen))
        except asyncio.QueueFull:  # stays open: no EVENT_ACK reaches it, the root sends it again
            log.warning("root event dropped (queue full): the root sends it again")

    # ---- main loop ---------------------------------------------------------------------------
    async def _main(self) -> None:
        while not self.hub.closing:
            try:
                self.hub.outbox_ready.clear()
                self._session.clear()
                link = self.link
                if link is None or not link.connected:
                    await self._sleep(1.0)
                    continue
                if not self.ready:
                    await self._session_up(link)
                    if not self.ready:
                        await self._sleep(2.0)
                    continue
                progressed = await self._drain_outbox()
                if self._need_reconcile and time.monotonic() >= self._next_reconcile:
                    await self._reconcile()
                await self._cancels()
                await self._poll_open()
                await self.groups.sync(self)
                if not progressed:
                    await self._idle()
            except asyncio.CancelledError:
                raise
            except (SessionChanged, SessionGone, SerialBusy, TimeoutError) as exc:
                log.info("bridge: serial exchange interrupted (%s)", exc)
                await self._sleep(0.2)
            except Exception:  # top of the loop: record, then keep serving (docs/15 §3)
                log.exception("bridge loop error")
                await self._sleep(1.0)

    async def _sleep(self, seconds: float) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._session.wait(), seconds)

    async def _idle(self) -> None:
        """Waits for a commit (new operation, cancel), the next poll of open operations or the next attempt of a
        request the root refused for a moment (FIX5: a transient refusal was retried only at an unrelated wake-up;
        with nothing else open the loop slept without a timeout). No timer runs while nothing is open or waiting."""
        due = min(self._next_poll, self._next_reconcile if self._need_reconcile else float("inf"))
        retry_utc_ms = await self.hub.read(_next_attempt)
        if retry_utc_ms is not None:
            due = min(due, time.monotonic() + max(0.0, (retry_utc_ms - now_ms()) / 1000))
        timeout = max(0.05, due - time.monotonic()) if due < float("inf") else None
        waits = [asyncio.ensure_future(self.hub.outbox_ready.wait()), asyncio.ensure_future(self._session.wait())]
        try:
            await asyncio.wait(waits, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for w in waits:
                w.cancel()

    # ---- session -----------------------------------------------------------------------------
    async def _caps(self, link: SerialLink) -> RootInfo | None:
        res = await link.request(M_CAPABILITIES, None)
        if res.status != mapping.OK or res.result is None:
            log.warning("root answered CAPABILITIES with %s: no bridge on that root", status_name(res.status))
            return None
        m = cbor_decode(res.result)
        t = m["root_time"]
        return RootInfo(m["domain"], m["root"], m["assignment"], m["gateway_boot"],
                        frozenset(m["enabled"]), m["root_term"], (t[0], t[1]) if t else None,
                        lists={k: frozenset(m.get(k, ())) for k in ("build", "implemented", "qualified")})

    async def _session_up(self, link: SerialLink) -> None:
        info = await self._caps(link)
        if info is None:
            return
        old = self.info
        if old is not None and old.boot != info.boot:  # the root restarted: its operation numbers are void
            self._forget_boot()
        self._open_events = {e for e in self._open_events if e[0] == info.boot}
        self._ack_top = {b: v for b, v in self._ack_top.items() if b == info.boot}
        self._ack_sent = {b: v for b, v in self._ack_sent.items() if b == info.boot}
        self.info = info

        if not await self.hub.write(lambda conn: self._register_root(conn, info)):
            log.error("another root claims domain %s: the bridge stays down", info.domain.hex())
            return
        self.hub.set_root(True, info.enabled, info.lists)
        await self._refresh_nodes()
        self._need_reconcile = True
        self.ready = True
        self._ready_evt.set()
        self.hub.outbox_ready.set()

    def _register_root(self, conn: sqlite3.Connection, info: RootInfo) -> bool:
        """Binds the domain to the root that answered. A different root DeviceId is accepted only as the
        completion of a ROOT_HANDOVER this Host saw the old root apply (`handover:<domain>` = [old, new],
        FIX11-D15); the transition is consumed. Any other root for a known domain is ROOT_MISMATCH."""
        row = conn.execute("SELECT root_device FROM domains WHERE id=?", (info.domain,)).fetchone()
        bound = bytes(row[0]) if row is not None and row[0] is not None else b"\0" * 32
        if bound not in (b"\0" * 32, info.root):
            key = f"handover:{info.domain.hex()}"
            mark = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            if mark is None or cbor_decode(bytes(mark[0])) != [bound, info.root]:
                startup.set_fault(conn, "ROOT_MISMATCH", {"domain": info.domain.hex()})
                return False
            conn.execute("DELETE FROM meta WHERE key=?", (key,))
            log.warning("domain %s: the root changed by a completed ROOT_HANDOVER", info.domain.hex())
        mirror.register_domain(conn, info.domain, info.root)
        return True

    def _note_handover(self, conn: sqlite3.Connection, op: bytes) -> None:
        """A ROOT_HANDOVER the old root reported APPLIED: remember old -> new for the next session's binding."""
        row = conn.execute("SELECT domain,payload FROM operations WHERE id=? AND type='ROOT_HANDOVER'", (op,)).fetchone()
        if row is None or row[1] is None:
            return
        try:
            data = cbor_decode(decode_control_body(decode_cose_sign1(bytes(row[1])).payload, "signed").data)
        except WireError:
            return
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                     (f"handover:{bytes(row[0]).hex()}", cbor_encode([data[1], data[2]])))

    def _forget_boot(self) -> None:
        """Operations known only by a root boot's numbers end as INDETERMINATE (docs/19 §3)."""
        lost = [o for ops_ in self._ctl_ops.values() for o in ops_]
        self._ctl_ops.clear()
        self._opnum.clear()
        self._cancel_taken.clear()
        self.groups.clear()
        if lost:
            asyncio.get_running_loop().create_task(self._indeterminate(lost, "root restarted"))

    async def _indeterminate(self, ops_: list[bytes], why: str) -> None:
        def apply_lost(conn: sqlite3.Connection) -> None:
            for op in ops_:
                self._finish(conn, op, "INDETERMINATE", "UNKNOWN", "ROOT_RESTARTED", why)

        await self.hub.write(apply_lost)

    # ---- outbox ------------------------------------------------------------------------------
    async def _drain_outbox(self) -> bool:
        link, info = self.link, self.info
        assert link is not None and info is not None
        domain = info.domain  # the connected root serves one domain; other domains' requests wait (FIX11-D14)

        def count(conn: sqlite3.Connection) -> int:
            return int(conn.execute(
                "SELECT COUNT(*) FROM outbox b JOIN operations o ON o.id=b.operation WHERE b.state='QUEUED' AND "
                "o.domain=? AND (b.next_attempt_utc_ms IS NULL OR b.next_attempt_utc_ms<=?)",
                (domain, now_ms())).fetchone()[0])

        if await self.hub.read(count) == 0:
            return False
        if time.monotonic() - self.info.fetched > CAPS_MAX_AGE_S:
            fresh = await self._caps(link)
            if fresh is not None and fresh.boot == self.info.boot:
                self.info = fresh
        incarnation = hashlib.sha256(self.info.root + self.info.boot.to_bytes(8, "big")
                                     + self._gen.to_bytes(4, "big")).digest()[:16]

        def claim_batch(conn: sqlite3.Connection) -> list[Plan]:
            plans = [self._plan(conn, item) for item in outbox.claim(conn, self.cfg, incarnation, 8, domain)]
            return [p for p in plans if p is not None]

        plans = await self.hub.write(claim_batch)  # committed: external_write_possible=1, ids fixed
        for plan in plans:
            await self._execute(link, plan)
        return True

    def _plan(self, conn: sqlite3.Connection, item: outbox.OutboxItem) -> Plan | None:
        """Runs inside the claim transaction. A request the root can never take is finished here; a
        request that must wait is put back (nothing was written, so that is safe)."""
        try:
            if self.info is None or item.domain != self.info.domain:  # never plan for another domain's root (FIX11-D14)
                raise _Later("ROOT_DOMAIN_MISMATCH")
            if item.op_type == "MESSAGE":
                return self._plan_message(conn, item)
            return self._plan_control(conn, item)
        except _Refused as exc:
            self._finish(conn, item.operation, "REJECTED", "SELF_REPORTED", "HOST_REFUSED", exc.reason,
                         terminal=exc.outcome)
        except _Later as exc:
            self._later(conn, item.operation, item.attempts, exc.reason)
        return None

    def _plan_message(self, conn: sqlite3.Connection, item: outbox.OutboxItem) -> Plan:
        info = self.info
        assert info is not None
        req = item.request
        dest, target = req["destination"], item.target
        if dest["kind"] == "group":  # the root is the origin of the fan-out; a group is a marker value (groups.py)
            target = groups.group_dest(int(dest["group_id"]), int(dest["revision"]))
        elif dest["kind"] != "node" or target is None:
            raise _Refused("UNSUPPORTED", "only node and group destinations are deliverable from the Host")
        assert item.payload is not None
        key = f"send:{item.operation.hex()}"
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if row is not None:  # a repeated attempt keeps its id, deadline and hash (the root de-duplicates)
            mid, term, expires, digest = _load_plan(bytes(row[0]))
        else:
            term, expires = self._deadline(conn, item.operation, req["deadline"])
            mid = item.message_id or os.urandom(16)
            digest = mapping.intent_hash(info.root, target, info.domain, req, term, expires, item.payload)
            conn.execute("UPDATE operations SET message_id=? WHERE id=? AND message_id IS NULL",
                         (mid, item.operation))
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                         (key, cbor_encode([mid, term, expires, digest])))
        params = [target, mid, digest, req["app_port"], mapping.send_flags(req), term, expires,
                  bool(req.get("object_transfer", False)), item.payload]
        return Plan(item.operation, "MESSAGE", M_SEND, params, mid, item.attempts, group=dest["kind"] == "group")

    def _deadline(self, conn: sqlite3.Connection, op: bytes, dl: dict[str, Any]) -> tuple[int, int]:
        info = self.info
        assert info is not None
        if dl["mode"] == "none":
            return 0, 0
        if dl["mode"] == "root":
            return int(dl["root_term"]), int(dl["expires_root_ms"])
        expiry = conn.execute("SELECT expiry_utc_ms FROM operations WHERE id=?", (op,)).fetchone()[0]
        lo = info.root_now_lo()
        if lo is None or info.term == 0:
            raise _Later("TIME_UNCERTAIN")  # the root has no clock bound to convert the UTC deadline with
        remaining = expiry - now_ms()
        if remaining <= 0:
            raise _Refused("EXPIRED", "deadline passed before the first transmission", outcome="EXPIRED")
        return info.term, lo + remaining

    def _plan_control(self, conn: sqlite3.Connection, item: outbox.OutboxItem) -> Plan:
        req, typ = item.request, item.op_type
        rev = int(req["expected_revision"])
        if typ == "JOIN_DECISION":
            row = conn.execute("SELECT id,object_hash FROM lifecycle_requests WHERE domain=? AND device=? "
                               "AND state='PENDING_APPROVAL'", (item.domain, item.target)).fetchone()
            if row is None:
                raise _Refused("NOT_FOUND", "no join request of that device is waiting for a decision")
            approve = req["decision"] == "APPROVE"
            # Kept until the decision is definite (FIX2-D12): the lookup key of a reconciliation after a crash.
            conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)", (f"join:{item.operation.hex()}", cbor_encode(
                [bytes(row[0]), item.target, int(approve), now_ms() + int(JOIN_WAIT_S * 1000)])))
            return Plan(item.operation, typ, M_JOIN_DECIDE,
                        [bytes(row[0]), item.target, bytes(row[1]), int(approve), rev],
                        attempts=item.attempts, request_id=bytes(row[0]), approve=approve)
        if typ in SIGNED_CONTROLS:
            assert item.payload is not None
            try:
                ctype = decode_control_body(decode_cose_sign1(item.payload).payload, "signed").type
            except WireError as exc:
                raise _Refused("INVALID_ARGUMENT", f"signed object is malformed ({exc.status})") from exc
            return Plan(item.operation, typ, M_INSTALL, [ctype, item.payload], attempts=item.attempts)
        if typ in ("CHANNEL_FREEZE", "CHANNEL_RECALCULATE"):
            action = 2 if typ == "CHANNEL_RECALCULATE" else int(bool(req["freeze"]))
            return Plan(item.operation, typ, M_CHANNEL, [action, rev], attempts=item.attempts)
        if typ == "POLICY_SET":  # HIL-F5: the root's join mode, compare-and-set on its policy revision
            return Plan(item.operation, typ, M_POLICY_SET, [mirror.JOIN_MODES.index(req["join_mode"]), rev],
                        attempts=item.attempts)
        if typ == "GROUP_SET":
            members = sorted(bytes.fromhex(m) for m in req["members"])
            return Plan(item.operation, typ, M_GROUP_SET, [int(req["group_id"]), rev, members],
                        attempts=item.attempts)
        raise _Refused("UNSUPPORTED", f"the root has no serial method for {typ}")

    def _later(self, conn: sqlite3.Connection, op: bytes, attempts: int, reason: str) -> None:
        """Nothing was accepted by the root: put the request back after a pause, or refuse it for good
        once the attempt budget (never re-granted per layer) is used up."""
        if attempts >= MAX_ATTEMPTS:
            self._finish(conn, op, "REJECTED", "SELF_REPORTED", "HOST_REFUSED", reason)
            return
        outbox.release_unwritten(conn, self.cfg, op)
        conn.execute("UPDATE outbox SET next_attempt_utc_ms=? WHERE operation=? AND state='QUEUED'",
                     (now_ms() + int(RETRY_S * 1000), op))

    def _finish(self, conn: sqlite3.Connection, op: bytes, outcome: str, assurance: str, kind: str,
                reason: str, *, terminal: str | None = None, observer: bytes | None = None) -> None:
        """Ends an operation with one piece of evidence and drops its stored send plan."""
        ev: dict[str, Any] = {"kind": kind, "assurance": assurance, "details": {"reason": reason}}
        if observer is not None:
            ev["observer"] = observer.hex()
        outbox.record(conn, self.cfg, op, state="FINAL", outcome=terminal or outcome, evidence=ev,
                      outbox_state="DONE")
        conn.execute("DELETE FROM meta WHERE key IN (?,?)", (f"send:{op.hex()}", f"join:{op.hex()}"))

    async def _execute(self, link: SerialLink, plan: Plan) -> None:
        try:
            res = await link.request(plan.method, plan.params)
        except SessionChanged as exc:
            await (self._unknown(plan.op, str(exc)) if exc.sent else self._release(plan.op))
            return
        except (SessionGone, SerialBusy):
            await self._release(plan.op)  # the request never left the Host
            return
        except TimeoutError:
            await self._unknown(plan.op, "no response within 5 s")
            return
        await self._on_result(plan, res.status, res.operation_id, res.result)

    async def _release(self, op: bytes) -> None:
        def release_unsent(conn: sqlite3.Connection) -> None:
            outbox.release_unwritten(conn, self.cfg, op)
            conn.execute("UPDATE outbox SET next_attempt_utc_ms=? WHERE operation=? AND state='QUEUED'",
                         (now_ms() + int(RETRY_S * 1000), op))

        await self.hub.write(release_unsent)

    async def _unknown(self, op: bytes, why: str) -> None:
        """The write may have happened: never repeat it; ask the root by MessageId next (docs/11 §4)."""
        def mark_unknown(conn: sqlite3.Connection) -> None:
            conn.execute("UPDATE outbox SET state='RECONCILE' WHERE operation=? AND state='SENDING'", (op,))
            outbox.record(conn, self.cfg, op, evidence={
                "kind": "HOST_SEND_OUTCOME_UNKNOWN", "assurance": "UNKNOWN", "details": {"reason": why[:120]}})

        await self.hub.write(mark_unknown)
        self._need_reconcile = True

    async def _on_result(self, plan: Plan, status: int, op_number: int | None, result: bytes | None) -> None:
        info = self.info
        assert info is not None
        snap = cbor_decode(result) if status == mapping.OK and result else None
        if status == mapping.OK and op_number is not None:
            if plan.typ == "MESSAGE":
                _remember(self._opnum, plan.op, op_number)
                if plan.group:
                    self.groups.track(plan.op, op_number)
            else:
                _remember(self._ctl_ops, op_number, (*self._ctl_ops.get(op_number, ()), plan.op))  # its end arrives as an OPERATION event

        def apply_send(conn: sqlite3.Connection) -> None:
            if status == mapping.OK:
                self._accepted(conn, plan, snap)
            elif status in mapping.TRANSIENT:
                self._later(conn, plan.op, plan.attempts, status_name(status))
            elif plan.typ != "MESSAGE" and status in mapping.UNKNOWN_STATE:  # SEC-D7: the root cannot vouch for it
                self._finish(conn, plan.op, "INDETERMINATE", "UNKNOWN", "ROOT_OUTCOME_UNKNOWN", status_name(status),
                             observer=info.root)
            else:
                terminal = "EXPIRED" if status == mapping.EXPIRED else "REJECTED"
                self._finish(conn, plan.op, "REJECTED", "SELF_REPORTED", "ROOT_REFUSED", status_name(status),
                             terminal=terminal, observer=info.root)

        await self.hub.write(apply_send)
        self.stats["sent" if status == mapping.OK else "refused"] += 1
        self._next_poll, self._poll_gap = 0.0, POLL_S

    def _accepted(self, conn: sqlite3.Connection, plan: Plan, snap: dict[str, Any] | None) -> None:
        info = self.info
        assert info is not None
        if plan.typ == "MESSAGE":
            assert snap is not None
            self._apply_snapshot(conn, plan.op, snap, plan.mid)
            return
        ev = {"kind": "ROOT_ACCEPTED", "assurance": "SELF_REPORTED", "observer": info.root.hex()}
        if snap is not None or plan.request_id is not None:
            # INSTALL_CONTROL: an operation whose end arrives as an OPERATION event. JOIN_DECIDE: a bare OK
            # says the root took the decision, not that it is stored (FIX2-D10): final only when
            # GET_REQUEST shows the ledger state (_query_join).
            outbox.record(conn, self.cfg, plan.op, state="WAITING_RECEIPT", evidence=ev)
            return
        # FIX12-D6: a RECALCULATE that was accepted has started the root's survey - that is all it says; the channel it
        # may choose is reported as channel state, so its evidence is the acceptance, never "applied".
        kind = "ROOT_ACCEPTED" if plan.typ == "CHANNEL_RECALCULATE" else "ROOT_APPLIED"
        outbox.record(conn, self.cfg, plan.op, state="FINAL", outcome="APPLIED", outbox_state="DONE",
                      evidence={"kind": kind, "assurance": "SELF_REPORTED", "observer": info.root.hex(),
                                **({"details": {"reason": "survey started; the result is channel state"}}
                                   if kind == "ROOT_ACCEPTED" else {})})

    def _apply_snapshot(self, conn: sqlite3.Connection, op: bytes, snap: dict[str, Any],
                        mid: bytes | None) -> None:
        """Copies what the root reports about one operation (result of SEND/GET_MESSAGE/CANCEL or an
        OPERATION event). Evidence is only added, state and outcome only advance (outbox.record)."""
        info = self.info
        assert info is not None
        conn.execute("UPDATE outbox SET state='SENDING' WHERE operation=? AND state='RECONCILE'", (op,))
        have = {e["kind"] for e in ops.view_any(conn, op)["evidence"]}
        for ev in mapping.snapshot_evidence(info.root, snap, have):
            outbox.record(conn, self.cfg, op, evidence=ev, message_id=mid)
        view = outbox.record(conn, self.cfg, op, state=mapping.PHASES[snap["phase"]],
                             outcome=mapping.OUTCOMES[snap["outcome"]],
                             evidence=mapping.outcome_evidence(info.root, snap), message_id=mid)
        if view["state"] == "FINAL":
            conn.execute("DELETE FROM meta WHERE key=?", (f"send:{op.hex()}",))

    # ---- reconciliation, polling, cancel -----------------------------------------------------
    async def _reconcile(self) -> None:
        """After a Host restart or a lost outcome: ask the root by the operation's own key (MessageId for a
        message, request id for a join decision), never send again. A row that is still unknown afterwards
        (busy root, interrupted exchange) arms the next attempt instead of being forgotten (FIX2-D12)."""
        link, info = self.link, self.info
        assert link is not None and info is not None
        self._need_reconcile = False
        try:
            pending = await self.hub.read(lambda conn: outbox.pending_reconcile(conn, info.domain))
            for op, mid in pending:
                join = await self.hub.read(lambda conn, o=op: _stored_join(conn, o))
                plan = await self.hub.read(lambda conn, o=op: _stored_plan(conn, o))
                if join is not None:
                    await self._query_join(link, op, join)
                elif mid is None or plan is None:  # a control without a lookup key: explicitly unknown
                    await self._indeterminate([op], "the outcome of the write is unknown and cannot be looked up")
                else:
                    await self._query(link, op, mid, plan[3])
                self.stats["reconciled"] += 1
        except BaseException:
            self._need_reconcile = True
            raise
        if await self.hub.read(lambda conn: outbox.pending_reconcile(conn, info.domain)):
            self._need_reconcile = True
            self._next_reconcile = time.monotonic() + RECONCILE_RETRY_S

    async def _query_join(self, link: SerialLink, op: bytes, join: tuple[bytes, bytes, bool, int]) -> None:
        """GET_REQUEST for a join decision; final only on durable ledger state, INDETERMINATE when the
        root cannot show it in time. Waiting rows stay open for _poll_open."""
        info = self.info
        assert info is not None
        request_id, _device, approve, deadline = join
        accepted = await self.hub.read(lambda conn: any(
            e["kind"] == "ROOT_ACCEPTED" for e in ops.view_any(conn, op)["evidence"]))
        res = await link.request(M_GET_REQUEST, [request_id])
        state = cbor_decode(res.result)["state"] if res.status == mapping.OK and res.result else None
        verdict = join_verdict(approve, accepted, res.status, state, now_ms() >= deadline)

        def apply_join(conn: sqlite3.Connection) -> None:
            conn.execute("UPDATE outbox SET state='SENDING' WHERE operation=? AND state='RECONCILE'", (op,))
            if verdict is None:
                return
            outcome, kind, reason = verdict
            ev = {"kind": kind, "assurance": "SELF_REPORTED" if outcome == "APPLIED" else "UNKNOWN",
                  "observer": info.root.hex(), "details": {"reason": reason}}
            outbox.record(conn, self.cfg, op, state="FINAL", outcome=outcome, evidence=ev, outbox_state="DONE")
            conn.execute("DELETE FROM meta WHERE key=?", (f"join:{op.hex()}",))
            if outcome == "APPLIED":
                conn.execute("UPDATE lifecycle_requests SET state=? WHERE id=?",
                             ("APPROVED" if approve else "REJECTED", request_id))

        await self.hub.write(apply_join)

    async def _query(self, link: SerialLink, op: bytes, mid: bytes, digest: bytes) -> int | None:
        """GET_MESSAGE for one operation; applies the answer. Returns the root's operation number."""
        info = self.info
        assert info is not None
        res = await link.request(M_GET_MESSAGE, [info.root, info.assignment, mid, digest])
        if res.status == mapping.OK and res.result is not None:
            snap = cbor_decode(res.result)
            if res.operation_id is not None:
                _remember(self._opnum, op, res.operation_id)
                if await self.hub.read(lambda conn: _is_group(conn, op)):  # found again after a restart
                    self.groups.track(op, res.operation_id)

            def apply_query(conn: sqlite3.Connection) -> None:
                self._apply_snapshot(conn, op, snap, mid)

            await self.hub.write(apply_query)
            return res.operation_id
        if res.status == mapping.NOT_FOUND:
            def apply_unknown(conn: sqlite3.Connection) -> None:
                self._finish(conn, op, "INDETERMINATE", "UNKNOWN", "ROOT_UNKNOWN_MESSAGE",
                             "the root does not know this message id",
                             observer=info.root)

            await self.hub.write(apply_unknown)
            return None
        log.warning("GET_MESSAGE answered %s", status_name(res.status))
        return None

    async def _poll_open(self) -> None:
        link, info = self.link, self.info
        assert link is not None and info is not None
        now = time.monotonic()
        if now < self._next_poll and not self._poll_now:
            return
        self._poll_now = False

        def open_ops(conn: sqlite3.Connection) -> list[tuple[bytes, bytes, bytes]]:
            rows = conn.execute(
                "SELECT o.id,o.message_id,m.value FROM operations o JOIN outbox b ON b.operation=o.id "
                "JOIN meta m ON m.key='send:'||lower(hex(o.id)) WHERE o.type='MESSAGE' AND o.state!='FINAL' "
                "AND o.domain=? AND b.state='SENDING' AND o.message_id IS NOT NULL ORDER BY o.created_utc_ms LIMIT ?",
                (info.domain, POLL_BATCH)).fetchall()
            return [(bytes(r[0]), bytes(r[1]), _load_plan(bytes(r[2]))[3]) for r in rows]

        def open_joins(conn: sqlite3.Connection) -> list[tuple[bytes, tuple[bytes, bytes, bool, int]]]:
            rows = conn.execute(
                "SELECT o.id,m.value FROM operations o JOIN outbox b ON b.operation=o.id "
                "JOIN meta m ON m.key='join:'||lower(hex(o.id)) WHERE o.state!='FINAL' AND o.domain=? "
                "AND b.state IN ('SENDING','RECONCILE') ORDER BY o.created_utc_ms LIMIT ?",
                (info.domain, POLL_BATCH)).fetchall()
            return [(bytes(r[0]), _load_join(bytes(r[1]))) for r in rows]

        rows = await self.hub.read(open_ops)
        for op, mid, digest in rows:
            await self._query(link, op, mid, digest)
        joins = await self.hub.read(open_joins)
        for op, join in joins:
            await self._query_join(link, op, join)
        self._next_poll = time.monotonic() + self._poll_gap if rows or joins else float("inf")
        self._poll_gap = min(POLL_MAX_S, self._poll_gap * 2)

    async def _cancels(self) -> None:
        link, info = self.link, self.info
        assert link is not None and info is not None
        for op in await self.hub.read(lambda conn: outbox.cancel_requests(conn, info.domain)):
            plan = await self.hub.read(lambda conn, o=op: _stored_plan(conn, o))
            done = await self.hub.read(lambda conn, o=op: any(
                e["kind"] == "ROOT_CANCEL_TOO_LATE" for e in ops.view_any(conn, o)["evidence"]))
            if plan is None or done or op in self._cancel_taken:
                continue
            number = self._opnum.get(op) or await self._query(link, op, plan[0], plan[3])
            if number is None:
                continue
            res = await link.request(4, [info.boot, number])
            snap = cbor_decode(res.result) if res.result else None
            if res.status == mapping.OK:
                _remember(self._cancel_taken, op, None) # a group finishes after its cancel: asking again changes nothing

            def apply_cancel(conn: sqlite3.Connection, o: bytes = op, st: int = res.status,
                             s: dict[str, Any] | None = snap, m: bytes = plan[0]) -> None:
                if st == mapping.OK and s is not None:
                    self._apply_snapshot(conn, o, s, m)
                elif st == mapping.CANCEL_TOO_LATE:  # a frame already left: the wire cannot be recalled
                    outbox.record(conn, self.cfg, o, evidence={
                        "kind": "ROOT_CANCEL_TOO_LATE", "assurance": "SELF_REPORTED",
                        "observer": info.root.hex()})

            await self.hub.write(apply_cancel)

    # ---- diagnostics (S19) -------------------------------------------------------------------
    async def diagnostics(self) -> dict[str, Any]:
        """One DIAGNOSTICS exchange for the client requests of a second: concurrent and repeated asks share it (the
        root answers on request only, and no client can turn that into polling load). Nothing calls this on a timer."""
        link = self.link
        if link is None or not link.connected or not self.ready:
            raise ApiError(503, "ROOT_UNAVAILABLE", "no authenticated root session")
        now = time.monotonic()
        cached = self._diag
        if cached is not None and cached[2] == self._gen and now - cached[0] < DIAG_MIN_INTERVAL_S:
            return {**cached[1], "age_ms": int((now - cached[0]) * 1000)}
        async with self._diag_lock:  # concurrent askers wait for the one exchange and then read its answer
            now = time.monotonic()
            cached = self._diag
            if cached is not None and cached[2] == self._gen and now - cached[0] < DIAG_MIN_INTERVAL_S:
                return {**cached[1], "age_ms": int((now - cached[0]) * 1000)}
            try:
                res = await link.request(M_DIAGNOSTICS, None)
            except (SessionChanged, SessionGone, SerialBusy, TimeoutError) as exc:
                raise ApiError(503, "ROOT_UNAVAILABLE", f"root did not answer ({exc.__class__.__name__})") from exc
            if res.status != mapping.OK or res.result is None:
                raise ApiError(503, "UNSUPPORTED" if res.status == mapping.UNSUPPORTED else "ROOT_UNAVAILABLE",
                               f"root answered DIAGNOSTICS with {status_name(res.status)}")
            body = diag_status.diagnostics(cbor_decode(res.result))
            self._diag = (time.monotonic(), body, self._gen)
            return {**body, "age_ms": 0}

    # ---- nodes -------------------------------------------------------------------------------
    async def _refresh_nodes(self) -> None:
        link, info = self.link, self.info
        assert link is not None and info is not None
        if info.time_ms is None or time.monotonic() - info.fetched > CAPS_MAX_AGE_S:
            fresh = await self._caps(link)  # the root clock ages the power reports it relays (power_state)
            if fresh is not None and fresh.boot == info.boot:
                self.info = info = fresh
        res = await link.request(M_NODE_QUERY, [None])
        if res.status != mapping.OK or res.result is None:
            return
        m = cbor_decode(res.result)

        def apply_nodes(conn: sqlite3.Connection) -> None:
            if isinstance(m.get("policy"), list) and len(m["policy"]) == 2:  # HIL-F5: [revision, join mode]
                mirror.put_policy(conn, info.domain, int(m["policy"][0]), int(m["policy"][1]))
            if m.get("channel", {}).get("current"):  # S17: what the root's coordinator reports (a member the ledger lists, by address)
                mirror.put_channel(conn, info.domain, chan_status.status(
                    m["channel"], {a: bytes(d) for d, _, _, _, _, a in m["nodes"] if a}))
            for device, ag, mg, state, confirmed, address in m["nodes"]:
                mirror.upsert_node(conn, info.domain, device, assignment_generation=ag,
                                   membership_generation=mg, membership=mapping.MEMBERSHIP.get(state, "UNKNOWN"),
                                   connectivity="UNKNOWN", confirmed=bool(confirmed),
                                   short_address=address or None)
            hi = info.root_now_hi()
            offset = hi - power_now_ms() if hi is not None else None
            mirror.sync_power(conn, info.domain, [(bytes(row[0]), *power_status.snapshot(row, offset))
                                                  for row in m.get("power", [])],  # S16: schedule hints of the members
                              info.boot, info.term)
            waiting = {bytes(r[0]) for r in conn.execute(
                "SELECT id FROM lifecycle_requests WHERE domain=? AND state='PENDING_APPROVAL'", (info.domain,))}
            for request, device, credential in m["pending"]:
                if request in waiting:
                    waiting.discard(request)
                    continue
                conn.execute("INSERT OR IGNORE INTO lifecycle_requests(id,domain,device,kind,state,"
                             "expected_revision,object_hash,evidence_json) VALUES(?,?,?,'JOIN',"
                             "'PENDING_APPROVAL',?,?,'[]')", (request, info.domain, device, m["revision"], credential))
                journal.append(conn, self.cfg, info.domain, "JOIN_PENDING", True, {"evidence": {
                    "kind": "JOIN_PENDING", "assurance": "SELF_REPORTED", "observer": info.root.hex(),
                    "details": {"request_id": request.hex(), "revision": str(m["revision"])}}}, origin=device)
            for request in waiting:  # no longer pending at the root (decided elsewhere, timed out)
                conn.execute("UPDATE lifecycle_requests SET state='CLOSED' WHERE id=?", (request,))

        await self.hub.write(apply_nodes)

    # ---- root -> Host events -----------------------------------------------------------------
    async def _event_loop(self) -> None:
        while True:
            payload, gen = await self._events.get()
            await self._ready_evt.wait()  # nothing is committed before the root identity is known
            if self.link is None or gen != self.link.gen:
                continue  # an old session's record: the root sends unsettled events again
            try:
                await self._handle_event(payload)
            except asyncio.CancelledError:
                raise
            except (SessionChanged, SessionGone, SerialBusy, TimeoutError) as exc:
                log.info("event acknowledgement interrupted (%s): the root sends it again", exc)
            except Exception:  # not acknowledged, so the root delivers it again
                log.exception("root event not processed")

    async def _handle_event(self, payload: bytes) -> None:
        link, info = self.link, self.info
        assert link is not None and info is not None
        boot, seq, kind, body = cbor_decode(payload)
        m = cbor_decode(body) if body else {}
        self.stats["events"] += 1
        self._next_poll, self._poll_gap = 0.0, POLL_S  # something happened: look at open operations soon
        self.hub.outbox_ready.set()
        if boot != info.boot:
            return
        if kind == EV_MESSAGE:
            if not await self._store_message(link, m):
                return  # not committed: no HOST_STORE_ACK, no EVENT_ACK, and no later ACK may cover it
            self._open_events.discard((boot, seq))  # the root settled it at HOST_STORE_ACK
        elif kind == EV_OPERATION:
            await self._on_operation_event(m)
            if int(m.get("operation", 0)) & CTL_OP_TAG:  # a root control operation ended (e.g. POLICY_SET, HIL-F5):
                await self._refresh_nodes()             # the state it changed is mirrored from NODE_QUERY
        elif kind in (EV_MEMBERSHIP, EV_CHANNEL, power_status.EV_POWER):  # (S17: channel state; S16: a schedule report)
            await self._refresh_nodes()
        elif kind == EV_GROUP_PROGRESS:
            self.groups.touched(int(m["operation"]))
        elif kind == EV_GAP:
            self._poll_now = True
            self.hub.outbox_ready.set()
        elif kind == EV_FAULT:
            log.error("root reported a fault (reason %s)", m.get("reason"))
        self._open_events.discard((boot, seq))
        self._ack_top[boot] = max(self._ack_top.get(boot, 0), seq)
        upto = self._ack_top[boot]
        lowest = min((q for b, q in self._open_events if b == boot), default=None)
        if lowest is not None:
            upto = min(upto, lowest - 1)  # an event below was dropped or failed: never settle it
        if upto > self._ack_sent.get(boot, 0):
            res = await link.request(M_EVENT_ACK, [boot, upto])
            if res.status == mapping.OK:
                self._ack_sent[boot] = upto

    async def _store_message(self, link: SerialLink, m: dict[str, Any]) -> bool:
        info = self.info
        assert info is not None
        origin, mid, digest, ag = m["origin"], m["message_id"], m["intent_hash"], m["assignment_generation"]
        assurance = {"kind": "ROOT_DELIVERED", "assurance": "END_VERIFIED", "observer": info.root.hex(),
                     "details": {"app_port": m["app_port"], "recovered": bool(m["recovered"])}}

        def commit_inbox(conn: sqlite3.Connection) -> journal.InboxCommit:
            return journal.ingest(conn, self.cfg, info.domain, origin, ag, mid, digest, m["payload"], assurance)

        try:
            commit = await self.hub.write(commit_inbox)  # returns after COMMIT
        except journal.InboxConflict:
            # FIX11-D3: a MessageId reused with another intent is one message's fault, not the link's. It is settled
            # with evidence (one journal event, no inbox row, no HOST_STORE_ACK: the root keeps the message until it
            # expires and the origin is never told "stored"), and EVENT_ACK moves on so later events are not held back.
            log.error("inbox conflict: message id %s reused with another intent hash", mid.hex())
            await self.hub.write(lambda conn: self._record_conflict(conn, info.domain, origin, mid, digest, info.root))
            self.stats["conflicts"] = self.stats.get("conflicts", 0) + 1
            return True
        self.stats["duplicates" if commit.duplicate else "inbox"] += 1
        committed = int(commit.cursor.rpartition(":")[2])
        res = await link.request(M_HOST_STORE_ACK, [origin, ag, mid, digest, self.hub.storage.journal_id, committed])
        if res.status not in (mapping.OK, mapping.NOT_FOUND):
            log.warning("HOST_STORE_ACK answered %s", status_name(res.status))
        return True

    def _record_conflict(self, conn: sqlite3.Connection, domain: bytes, origin: bytes, mid: bytes, digest: bytes,
                         root: bytes) -> None:
        seen = conn.execute("SELECT 1 FROM events WHERE domain=? AND kind='MESSAGE_CONFLICT' AND origin=? AND "
                            "message_id=? AND payload_json LIKE ?", (domain, origin, mid, f'%"{digest.hex()}"%')).fetchone()
        if seen is not None:  # the root sends the same event again in every session: one record is enough
            return
        journal.append(conn, self.cfg, domain, "MESSAGE_CONFLICT", True, {
            "intent_hash": digest.hex(),
            "evidence": {"kind": "HOST_INBOX_CONFLICT", "assurance": "SELF_REPORTED", "observer": root.hex(),
                         "details": {"reason": "message id reused with another intent; not stored, not acknowledged"}}},
                       origin=origin, message_id=mid)

    async def _on_operation_event(self, m: dict[str, Any]) -> None:
        info = self.info
        assert info is not None

        def apply_event(conn: sqlite3.Connection) -> None:
            mid = m.get("message_id")
            row = conn.execute("SELECT id,state FROM operations WHERE message_id=? AND type='MESSAGE'",
                               (mid,)).fetchone() if mid else None
            if row is not None and {"phase", "outcome", "evidence_bits", "reason"} <= m.keys():
                # FIX11-D2: also for an operation the Host already closed (INDETERMINATE after a timeout, ...): late
                # evidence is added and the outcome advances by rank (outbox.record); a definite negative stays.
                self._apply_snapshot(conn, bytes(row[0]), m, mid)
                return
            for host_op in self._ctl_ops.pop(int(m["operation"]), ()) if "operation" in m else ():
                # the end of an accepted control operation (root-local, SELF_REPORTED)
                outcome, kind = mapping.control_outcome(int(m["outcome"]), int(m["reason"]))
                self._finish(conn, host_op, outcome, "SELF_REPORTED" if outcome != "INDETERMINATE" else "UNKNOWN",
                             kind, status_name(int(m["reason"])), observer=info.root)
                if outcome == "APPLIED":
                    self._note_handover(conn, host_op)

        await self.hub.write(apply_event)


def _remember(table: OrderedDict[Any, Any], key: Any, value: Any) -> None:
    """A bounded per-boot table: the oldest entry makes room (MAX_OP_MAP)."""
    table[key] = value
    table.move_to_end(key)
    while len(table) > MAX_OP_MAP:
        table.popitem(last=False)


class _Refused(Exception):
    def __init__(self, reason: str, detail: str = "", outcome: str = "REJECTED") -> None:
        super().__init__(detail or reason)
        self.reason = reason if not detail else f"{reason}: {detail}"
        self.outcome = outcome


class _Later(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _is_group(conn: sqlite3.Connection, op: bytes) -> bool:
    row = conn.execute("SELECT json_extract(request_json,'$.destination.kind') FROM operations WHERE id=?",
                       (op,)).fetchone()
    return row is not None and row[0] == "group"


def _load_plan(raw: bytes) -> tuple[bytes, int, int, bytes]:
    mid, term, expires, digest = cbor_decode(raw)
    return mid, term, expires, digest


def _load_join(raw: bytes) -> tuple[bytes, bytes, bool, int]:
    request_id, device, approve, deadline = cbor_decode(raw)
    return request_id, device, bool(approve), deadline


def _stored_join(conn: sqlite3.Connection, op: bytes) -> tuple[bytes, bytes, bool, int] | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (f"join:{op.hex()}",)).fetchone()
    return _load_join(bytes(row[0])) if row is not None else None


def join_verdict(approve: bool, accepted: bool, status: int, state: int | None,
                 past_deadline: bool) -> tuple[str, str, str] | None:
    """What a GET_REQUEST answer proves about a JOIN_DECIDE (FIX2-D10/12): (outcome, evidence kind, reason)
    when definite, None to keep waiting. An approval is applied only when the ledger holds an entry
    (Prepared or later: durable). A rejection leaves no ledger state, so "no longer pending" proves it only
    when the root also said OK to it. A bare OK or an unanswered query is never promoted."""
    if status == mapping.OK and state == REQUEST_PENDING:
        if not accepted:
            return ("INDETERMINATE", "ROOT_DECISION_UNCONFIRMED",
                    "the root still lists the request as pending: the decision may not have arrived")
    elif status == mapping.OK and state is not None and approve and state >= LEDGER_PREPARED:
        return ("APPLIED", "ROOT_APPLIED", f"ledger state {state}")
    elif status in (mapping.OK, mapping.NOT_FOUND) and not approve:
        if accepted:
            return ("APPLIED", "ROOT_APPLIED", "the request is no longer pending")
        return ("INDETERMINATE", "ROOT_DECISION_UNCONFIRMED", "the request is closed; the rejection is not proven")
    if past_deadline:
        return ("INDETERMINATE", "ROOT_DECISION_UNCONFIRMED", "no durable ledger state within the wait limit")
    return None


def _stored_plan(conn: sqlite3.Connection, op: bytes) -> tuple[bytes, int, int, bytes] | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (f"send:{op.hex()}",)).fetchone()
    return _load_plan(bytes(row[0])) if row is not None else None


def _next_attempt(conn: sqlite3.Connection) -> int | None:
    """The earliest scheduled attempt (UTC ms) of a request waiting in the outbox after a transient refusal, if any."""
    row = conn.execute("SELECT MIN(next_attempt_utc_ms) FROM outbox WHERE state='QUEUED'").fetchone()
    return int(row[0]) if row is not None and row[0] is not None else None
