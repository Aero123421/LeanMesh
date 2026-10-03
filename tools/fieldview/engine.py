"""The fieldview engine: one asyncio process that consumes the Host's event journal (telemetry, operation progress),
keeps per-node statistics, runs pings and display commands through POST /v1/messages, and records everything.

How it reads the Host (api/SEMANTICS.md, 'Cursor/consumer'):
  * telemetry arrives as MESSAGE_RECEIVED events (`origin`, `payload_b64`, `evidence.details.app_port`);
  * the journal is read by cursor with long polls (GET /v1/events?after=&wait_ms=) as a registered consumer: after the
    records are queued the cursor is acknowledged (POST /v1/consumers/{name}/ack), so the Host keeps what we have not
    read (critical events are protected until every consumer acknowledged them) and a restart resumes where we stopped;
  * the ACK follows the records, not the reading: a page is acknowledged only when its records are fsynced (the
    recorder's barrier) and the operations it reports as FINAL have been read and recorded; when the recorder lost lines
    the engine writes an explicit gap record first, and while it cannot write, nothing is acknowledged (the Host keeps
    the events and a restart reads them again);
  * a CURSOR_GAP (410) or an EVENT_GAP event is shown and logged, never skipped quietly: the telemetry baseline restarts;
  * client epochs rotate: the Host prunes the finished operations of an epoch only after it is CLOSED, so one epoch for a
    whole session would let the Host's database grow with every ping. A new epoch is opened every EPOCH_ROTATE_S / every
    EPOCH_ROTATE_OPS requests; the old one serves only what is already in flight (a retry of a request keeps the epoch it
    was sent under) and is closed when that is final. The ids of the epochs this tool holds are kept in a small state
    file, so epochs a crashed run left open are closed at the next start (the Host allows 64 open per principal);
  * what a finished operation shows LATER (a receipt that reached the Host after the deadline: the Host adds evidence to
    an operation that already ended) is read again on its next event, a bounded number of times, and recorded as "late"
    next to the on-time result, which stays as it was;
  * operation progress comes from OPERATION_UPDATE events: GET /v1/operations/{id} is called only for an operation whose
    event says it ended (a display command: at every change), plus a slow safety poll after its deadline."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import time
from collections import Counter, OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import protocol as pr
from .hostclient import HostClient, HostUnreachable, Reply, SendUnknown
from .recorder import Recorder, utc_text
from .stats import PingTrack, TelemetryTrack
from .topology import NodeView, build_tree, short_id

ACK_EVERY_S = 2.0
RECORD_SYNC_S = 5.0           # how long the engine waits for the recorder's fsync barrier
SEGMENTS_MAX = 64             # unacknowledged pages kept apart (more are merged: the ack gets coarser, never wrong)
HOLD_MAX_S = 20.0             # an ack waits at most this long for the operations of a page to be read
EPOCH_ROTATE_S = 1800.0       # a client epoch serves new requests for this long ...
EPOCH_ROTATE_OPS = 5000       # ... or this many requests (the Host keeps 7 days of closed epochs: ~48..300 a day)
EPOCH_CLOSE_MARGIN_S = 2.0    # a retired epoch is closed when its requests are final, at the earliest this much later
EPOCH_CLOSE_RETRY_S = 10.0
EVENT_PAUSE_S = 0.1           # between two event reads: at most ~10 requests/s even under a flood
PENDING_MAX = 512             # open operations we follow at once
GIVE_UP_S = 8.0               # after its deadline an operation is polled, and given up on after this
PING_OPEN_MAX = 3             # open pings per node: a round that finds this many still open skips the node
FINAL_HINTS = 4096
FINISHED_KEEP = 2048          # finished operations remembered for late evidence
LATE_READS_MAX = 3            # re-reads of one finished operation
DEVICES_MAX = 256             # per-node tables: nodes that are not listed any more are forgotten beyond this
EVENT_LOG_KEEP = 500
LOSS_FACTOR = 3               # telemetry older than this many intervals = lost
REQUEST_BUDGET_RPS = 14.0     # what fieldview allows itself of the Host's 20 req/s per principal
POLL_OVERHEAD_RPS = 3.0       # events, nodes, status in the background


@dataclass
class Config:
    socket: str
    token: str
    domain: str
    logs_dir: Path = Path("logs/fieldview")
    interval_s: float = 10.0          # telemetry interval assumed for "lost" (the node reports its own when it can)
    consumer: str = "fieldview"
    names: dict[str, str] = field(default_factory=dict)
    root_id: str | None = None
    root_name: str = "root"
    state_file: Path | None = None    # tools/hil's state file: names are read again when it changes (boards provisioned later)
    epoch_file: Path | None = None    # the epochs this tool holds open (default: <logs_dir>/epochs-<consumer>-<domain>.json)
    net: str | None = None
    nodes_poll_s: float = 5.0
    summary_s: float = 10.0
    events_wait_ms: int = 15000
    tick_s: float = 1.0


@dataclass
class Segment:
    """One page of events read but not yet acknowledged: its cursor, and the operations whose FINAL event is in it and
    whose result is not read and recorded yet (the ack waits for them)."""
    cursor: str
    created: float
    holds: set[str] = field(default_factory=set)


@dataclass
class Finished:
    """What the engine remembers of an operation that ended: enough to read it again when the Host adds evidence."""
    op_id: str
    kind: str                         # "ping" | "display"
    device: str
    round_no: int
    result: str                       # the on-time result (never rewritten)
    kinds: frozenset[str]             # evidence seen when it ended
    outcome: str
    entry: dict[str, Any] | None = None
    candidate: bool = False           # an on-time "no answer": late evidence may still show it was answered
    reads: int = 0
    checking: bool = False
    last_read: float = 0.0


@dataclass
class Pending:
    op_id: str
    kind: str                         # "ping" | "display"
    device: str
    round_no: int
    t_post: float                     # monotonic, when the request went out
    deadline: float                   # monotonic, when the Host's deadline passes
    epoch: str = ""                   # the client epoch the request was sent under
    entry: dict[str, Any] | None = None   # a display command's record (kept by operation id: see send_display)
    fetch_any: bool = False           # fetch at every change (display), not only at the end
    fetching: bool = False
    last_fetch: float = 0.0
    seen_kinds: set[str] = field(default_factory=set)


def ping_load(nodes: int, interval_s: float) -> tuple[float, float]:
    """(requests/s a ping loop needs, the interval that fits the budget): per ping one POST and one GET (at its final
    event), so rounds that overlap (a 3 s deadline under a 1 s loop) cost no more per second than rounds that do not -
    what overlaps is the number of OPEN operations, see open_ops_max."""
    need = 2.0 * nodes / interval_s + POLL_OVERHEAD_RPS
    fit = 2.0 * nodes / max(REQUEST_BUDGET_RPS - POLL_OVERHEAD_RPS, 1.0)
    return need, max(1.0, fit)


def open_ops_max(nodes: int, interval_s: float) -> int:
    """Most pings that can be open at once: the rounds that fit in the deadline (up to PING_OPEN_MAX per node)."""
    rounds = min(PING_OPEN_MAX, max(1, -(-int(pr.PING_DEADLINE_S * 1000) // int(interval_s * 1000))))
    return min(nodes * rounds, PENDING_MAX)


def load_bench(path: Path, net: str | None = None) -> dict[str, Any]:
    """tools/hil's state file: board names, the root, the domain (and the Host socket) of a network. Empty when absent."""
    try:
        state = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    names: dict[str, str] = {}
    for scope in [state, *state.get("nets", {}).values()]:
        for name, rec in (scope.get("leaves") or {}).items():
            if isinstance(rec, dict) and rec.get("device"):
                names[rec["device"]] = name
    chosen = state if net is None else (state.get("nets") or {}).get(net, {})
    root = (chosen.get("root") or {}).get("device")
    if root:
        names[root] = "root"
    return {"names": names, "root_id": root, "domain": chosen.get("domain")}


class FieldView:
    def __init__(self, cfg: Config, client: HostClient, recorder: Recorder, *,
                 clock: Callable[[], float] = time.monotonic,
                 utcnow: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.cfg, self.client, self.rec = cfg, client, recorder
        self.mono, self.utcnow = clock, utcnow
        self.started_utc = utc_text(utcnow())
        self.epoch: str | None = None
        self._epoch_lock = asyncio.Lock()
        self._epoch_since = 0.0
        self._epoch_ops = 0
        self._rotate_retry_at = 0.0
        self._retiring: dict[str, float] = {}      # epochs that take no new request: id -> earliest close time
        self._epoch_users: Counter[str] = Counter()  # requests being sent right now, per epoch
        self._tracked: set[str] = set()            # every epoch id this tool may have open (also those of a crashed run)
        self._closing: set[str] = set()
        self._epoch_file = cfg.epoch_file or cfg.logs_dir / f"epochs-{cfg.consumer}-{cfg.domain[:8]}.json"
        self.api_nodes: dict[str, dict[str, Any]] = {}
        self.nodes_seen = False
        self.first_listed: dict[str, float] = {}
        self.tele: dict[str, TelemetryTrack] = {}
        self.ping: dict[str, PingTrack] = {}
        self.node_state: dict[str, str] = {}
        self.silent_noted: set[str] = set()
        self.log: deque[dict[str, Any]] = deque(maxlen=EVENT_LOG_KEEP)
        self.warnings: dict[str, str] = {}
        self.host: dict[str, Any] = {"ok": None, "ready": None, "root_connected": None, "journal_id": None}
        self.pending: dict[str, Pending] = {}
        self.finished: OrderedDict[str, Finished] = OrderedDict()
        self._open_pings: Counter[str] = Counter()   # per node: pings posted (or being posted) and not final
        self.final_hint: OrderedDict[str, None] = OrderedDict()
        self.round_no = 0
        self.rounds: deque[dict[str, Any]] = deque(maxlen=30)
        self._round_of: dict[int, dict[str, Any]] = {}
        self.loop_interval: float | None = None
        self._loop_task: asyncio.Task[None] | None = None
        self.display: dict[str, dict[str, Any]] = {}
        self.command_seq = int(utcnow().timestamp()) & 0xFFFFFFFF  # rises across sessions: a node may keep the last
        self.cursor: str | None = None
        self._backlog = True              # events before this session / after a lost place only set the baseline
        self.backlog_events = 0
        self.live_events = 0
        self.other_messages = 0
        self.bad_telemetry = 0
        self._segments: deque[Segment] = deque()
        self._page_holds: set[str] = set()
        self._ack_lock = asyncio.Lock()
        self._posting = 0                 # POSTs in flight: an operation event may be faster than their answer
        self._last_ack = 0.0
        self._tasks: list[asyncio.Task[None]] = []
        self._bg: set[asyncio.Task[None]] = set()
        self._last_summary = clock()
        self.recorder_warn_seen: str | None = None
        recorder.log("events", {"kind": "session", "text": "fieldview started", "domain": cfg.domain,
                                "socket": cfg.socket, "logs": str(recorder.directory)})

    # ---- helpers ------------------------------------------------------------------------------------------------
    def name_of(self, device: str) -> str:
        return self.cfg.names.get(device) or short_id(device)

    def note(self, kind: str, text: str, device: str | None = None) -> None:
        """One line of the event log on the page and in events.ndjson."""
        entry: dict[str, Any] = {"t": utc_text(self.utcnow()), "kind": kind, "text": text}
        if device:
            entry.update(device=device, name=self.name_of(device))
        self.log.append(entry)
        self.rec.log("events", {k: v for k, v in entry.items() if k != "t"})

    def warn(self, key: str, text: str | None) -> None:
        if text is None:
            self.warnings.pop(key, None)
        elif self.warnings.get(key) != text:
            self.warnings[key] = text

    def _spawn(self, coro: Any) -> None:
        task = asyncio.ensure_future(coro)
        self._bg.add(task)
        task.add_done_callback(self._bg.discard)

    # ---- run / stop ---------------------------------------------------------------------------------------------
    async def start(self) -> None:
        self._load_epoch_file()
        for epoch in sorted(self._tracked):
            self.note("session", f"client epoch {epoch[:8]} was left open by an earlier run: closing it")
            self._spawn(self._close_epoch(epoch, retry=True))
        self._tasks = [asyncio.ensure_future(self._guard(f, n)) for f, n in
                       ((self._events_loop, "events"), (self._nodes_loop, "nodes"), (self._tick_loop, "tick"))]

    async def stop(self) -> None:
        await self.stop_ping_loop()
        for t in [*self._tasks, *self._bg]:
            t.cancel()
        for t in [*self._tasks, *self._bg]:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        with contextlib.suppress(Exception):
            await self._ack(force=True)
        for epoch in sorted(self._tracked):
            with contextlib.suppress(Exception):
                await self._close_epoch(epoch)
        self.note("session", "fieldview stopped")
        self.rec.summary(self.summary_rows())
        self.rec.close()

    async def _guard(self, fn: Callable[[], Any], name: str) -> None:
        """A background loop never ends on its own: an error is shown and the loop starts again."""
        while True:
            try:
                await fn()
            except asyncio.CancelledError:
                raise
            except HostUnreachable as exc:
                self.host["ok"] = False
                self.warn("host", f"the Host does not answer ({exc})")
            except Exception as exc:  # a bug here must not freeze the page
                self.warn(f"loop-{name}", f"{name} loop failed: {type(exc).__name__}: {exc}")
                self.rec.log("events", {"kind": "error", "text": f"{name} loop: {type(exc).__name__}: {exc}"})
            await asyncio.sleep(2.0)

    # ---- the journal --------------------------------------------------------------------------------------------
    async def _init_cursor(self) -> str:
        """The consumer's acknowledged position (ACK 0 is monotonic and idempotent and answers with the current
        position), so that a restart does not read, or lose, what an earlier run already took."""
        st = await self.client.status()
        if not st.ok:
            raise HostUnreachable(f"GET /v1/status answered {st.status}")
        self._note_status(st.body)
        journal = str(st.body["journal_id"])
        r = await self.client.ack(self.cfg.consumer, journal, 0)
        if not r.ok:
            raise HostUnreachable(f"consumer ACK answered {r.status} {r.code}")
        return str(r.body["next_cursor"])

    def _note_status(self, body: dict[str, Any]) -> None:
        self.host.update(ok=True, ready=body.get("ready"), root_connected=body.get("root_connected"),
                         journal_id=body.get("journal_id"))
        self.warn("host", None)
        self.warn("root", None if body.get("root_connected") else "the Host has no root connected (USB)")

    async def _events_loop(self) -> None:
        while True:
            if self.cursor is None:
                self.cursor = await self._init_cursor()
                self._backlog = True
            backlog = self._backlog
            r = await self.client.events(self.cursor, 200, 0 if backlog else self.cfg.events_wait_ms)
            self.host["ok"] = True if r.status else self.host["ok"]
            if r.status == 410 and r.code == "CURSOR_GAP":
                await self._cursor_gap(r)
                self._backlog = True
                continue
            if not r.ok:
                self.warn("events", f"event read failed: HTTP {r.status} {r.code}")
                await asyncio.sleep(2.0)
                continue
            self.warn("events", None)
            self.warn("host", None)
            page = r.body
            events = page.get("events", [])
            self._page_holds = set()
            for ev in events:
                self._on_event(ev, backlog)
            if events:
                self.cursor = str(page["next_cursor"])
                self._add_segment(self.cursor, self._page_holds)
            elif backlog:
                self._backlog = False  # an empty page without waiting: everything older than now has been taken
                self.note("session", f"event backlog read: {self.backlog_events} events before this session")
            await self._ack(force=backlog)
            if events and not backlog:
                await asyncio.sleep(EVENT_PAUSE_S)

    @property
    def ack_pending(self) -> bool:
        """Events were read that the Host has not been told about yet."""
        return bool(self._segments)

    def _add_segment(self, cursor: str, holds: set[str]) -> None:
        if len(self._segments) >= SEGMENTS_MAX:  # a stuck ack must not grow without bound: the newest pages merge
            last = self._segments[-1]
            last.cursor, last.holds = cursor, last.holds | holds
            return
        self._segments.append(Segment(cursor, self.mono(), set(holds)))

    def _hold_cleared(self, op_id: str, seg: Segment) -> bool:
        if self.mono() - seg.created > HOLD_MAX_S:
            return True
        if op_id in self.pending:  # its result is still being read
            return False
        return not (op_id in self.final_hint and self._posting > 0)  # the answer of a POST in flight may name it

    def _ackable(self) -> Segment | None:
        """The last page of the leading run of pages that need nothing more before they are acknowledged."""
        ready = None
        for seg in self._segments:
            if not all(self._hold_cleared(o, seg) for o in seg.holds):
                break
            ready = seg
        return ready

    async def _records_safe(self, through: str) -> bool:
        """True when everything recorded so far is on disk and every lost line is covered by a gap record."""
        if not await asyncio.to_thread(self.rec.sync, RECORD_SYNC_S):
            self.warn("ack-records", "acknowledgement held: the records are not safely on disk")
            return False
        lost = self.rec.lost
        if lost:
            text = (f"{lost} record line(s) were lost (queue full or disk write failed) before the events up to "
                    f"{through} were acknowledged: telemetry, ping and display records of that window are incomplete")
            self.note("recorder-gap", text)
            if not await asyncio.to_thread(self.rec.sync, RECORD_SYNC_S) or self.rec.lost != lost:
                self.warn("ack-records", "acknowledgement held: the records are not safely on disk")
                return False
            self.rec.resolve_lost(lost)
            self.warn("records-gap", f"records incomplete: {text}")
        self.warn("ack-records", None)
        return True

    async def _ack(self, force: bool = False) -> None:
        if not self._segments or self.cursor is None:
            return
        if not force and self.mono() - self._last_ack < ACK_EVERY_S:
            return
        async with self._ack_lock:
            seg = self._ackable()
            if seg is None:
                return
            self._last_ack = self.mono()
            if not await self._records_safe(seg.cursor):
                return
            journal, _, seq = seg.cursor.partition(":")
            r = await self.client.ack(self.cfg.consumer, journal, int(seq))
            if r.ok:
                while self._segments and self._segments[0] is not seg:
                    self._segments.popleft()
                if self._segments:
                    self._segments.popleft()
                self._last_ack = self.mono()
                self.warn("ack", None)
            else:
                self.warn("ack", f"consumer ACK failed: HTTP {r.status} {r.code}")

    async def _cursor_gap(self, r: Reply) -> None:
        details = r.body.get("details") or {}
        text = (f"CURSOR_GAP: the Host no longer holds the events after {self.cursor}; events between "
                f"{self.cursor} and {details.get('oldest_cursor')} were not seen (telemetry loss counts restart)")
        self.note("gap", text)
        self.warn("gap", text)
        for t in self.tele.values():
            t.rebaseline()
        self._segments.clear()
        journal, oldest = details.get("journal_id"), details.get("oldest_cursor")
        if journal and oldest:
            if journal != str(self.cursor).partition(":")[0]:  # another journal (a new database): register in it
                await self.client.ack(self.cfg.consumer, str(journal), 0)
            self.cursor = str(oldest)
            self._add_segment(self.cursor, set())
        else:
            self.cursor = None

    def _on_event(self, ev: dict[str, Any], backlog: bool) -> None:
        kind = ev.get("kind", "")
        if backlog:
            self.backlog_events += 1
        else:
            self.live_events += 1
        if kind == "MESSAGE_RECEIVED":
            if pr.event_app_port(ev) == pr.TELEMETRY_PORT:
                self._on_telemetry(ev, backlog)
            else:
                self.other_messages += 1
        elif kind == "OPERATION_UPDATE":
            if not backlog:
                self._on_operation_event(ev)
        elif kind == "EVENT_GAP":
            for t in self.tele.values():
                t.rebaseline()
            self.note("gap", "EVENT_GAP: the Host dropped events it was not asked to keep; telemetry counts restart")
            self.warn("gap", "EVENT_GAP seen: some events are missing (see the event log)")
        else:
            self.note("host-event", f"{kind}" + (f" from {self.name_of(ev['origin'])}" if ev.get("origin") else ""),
                      ev.get("origin"))

    # ---- telemetry ----------------------------------------------------------------------------------------------
    def _on_telemetry(self, ev: dict[str, Any], backlog: bool) -> None:
        device = ev.get("origin", "")
        try:
            t = pr.decode_telemetry(pr.event_payload(ev))
        except (pr.TelemetryError, ValueError) as exc:
            self.bad_telemetry += 1
            self.note("telemetry", f"unreadable telemetry from {self.name_of(device)}: {exc}", device)
            return
        track = self.tele.setdefault(device, TelemetryTrack())
        was_lost = self.node_state.get(device) == "lost"
        before_lost = track.lost
        happened = track.feed(t, self.mono(), live=not backlog)
        self.rec.log("telemetry", {"device": device, "name": self.name_of(device), "cursor": ev.get("cursor"),
                                   "backlog": backlog, "events": happened, **t.as_dict()})
        if backlog:
            return
        if "reboot" in happened:
            self.note("reboot", f"{self.name_of(device)} rebooted (boot {t.boot_count}, reset reason "
                                f"{t.reset_reason}, seq {t.seq})", device)
        if "gap" in happened and track.lost > before_lost:
            self.note("loss", f"{self.name_of(device)}: {track.lost - before_lost} telemetry message(s) missing "
                              f"(seq {t.seq})", device)
        if was_lost:
            self.node_state[device] = "ok"
            self.note("back", f"{self.name_of(device)} sends telemetry again", device)

    # ---- operations ---------------------------------------------------------------------------------------------
    def _on_operation_event(self, ev: dict[str, Any]) -> None:
        d = (ev.get("evidence") or {}).get("details") or {}
        op_id, state = d.get("operation_id"), d.get("state")
        if not op_id:
            return
        p = self.pending.get(op_id)
        if p is None:
            fin = self.finished.get(op_id)
            if fin is not None:
                if fin.candidate:
                    self._late_check(fin)
                return
            if state == "FINAL":  # the event may be faster than the POST answer that tells us the id
                self.final_hint[op_id] = None
                while len(self.final_hint) > FINAL_HINTS:
                    self.final_hint.popitem(last=False)
                if self._posting:
                    self._page_holds.add(op_id)
            return
        if state == "FINAL":
            self._page_holds.add(op_id)  # this page is not acknowledged before the result is read and recorded
        if state == "FINAL" or p.fetch_any:
            self._fetch(p)

    def _fetch(self, p: Pending) -> None:
        if not p.fetching:
            p.fetching = True
            self._spawn(self._resolve(p))

    async def _resolve(self, p: Pending) -> None:
        try:
            r = await self.client.operation(p.op_id)
        except HostUnreachable:
            p.fetching = False
            return
        finally:
            p.last_fetch = self.mono()
        p.fetching = False
        if p.op_id not in self.pending:
            return
        if not r.ok:
            if r.status == 404:
                self._finish_unknown(p, "the Host no longer knows the operation")
            return
        op = r.body
        if p.kind == "display":
            self._display_progress(p, op)
        if op.get("state") == "FINAL":
            self._finish(p, op)

    def _finish(self, p: Pending, op: dict[str, Any]) -> None:
        self.pending.pop(p.op_id, None)
        elapsed_ms = int((self.mono() - p.t_post) * 1000)
        if p.kind == "ping":
            res = pr.classify_ping(op, elapsed_ms)
            self._ping_done(p, res, op)
            self._remember(p, res.kind, op)
        else:
            self._display_done(p, op, elapsed_ms)
            self._remember(p, str((p.entry or {}).get("result")), op)

    def _finish_unknown(self, p: Pending, why: str) -> None:
        self.pending.pop(p.op_id, None)
        op = {"id": p.op_id, "outcome": "INDETERMINATE", "reason": why, "evidence": []}
        if p.kind == "ping":
            self._ping_done(p, pr.PingResult("noanswer", why), {"id": p.op_id})
            self._remember(p, "noanswer", op)
        else:
            self._display_done(p, op, 0)
            self._remember(p, str((p.entry or {}).get("result")), op)

    def _remember(self, p: Pending, result: str, op: dict[str, Any]) -> None:
        self.finished[p.op_id] = Finished(
            p.op_id, p.kind, p.device, p.round_no, result, frozenset(pr.evidence_kinds(op)), str(op.get("outcome", "")),
            p.entry, candidate=result == "noanswer")
        while len(self.finished) > FINISHED_KEEP:
            self.finished.popitem(last=False)

    def _late_check(self, fin: Finished) -> None:
        if fin.checking or fin.reads >= LATE_READS_MAX or self.mono() - fin.last_read < 1.0:
            return
        fin.checking = True
        self._spawn(self._late_read(fin))

    async def _late_read(self, fin: Finished) -> None:
        """Read a finished "no answer" again after the Host reported news about it. The on-time result stays; an answer
        that shows up now is recorded as "late" beside it (counted apart: noanswer + late)."""
        try:
            r = await self.client.operation(fin.op_id)
        except HostUnreachable:
            return
        finally:
            fin.checking, fin.reads, fin.last_read = False, fin.reads + 1, self.mono()
        if not r.ok:
            return
        op = r.body
        kinds, outcome = frozenset(pr.evidence_kinds(op)), str(op.get("outcome", ""))
        if kinds == fin.kinds and outcome == fin.outcome:
            return  # nothing new
        fin.kinds, fin.outcome = kinds, outcome
        name = self.name_of(fin.device)
        if fin.kind == "ping":
            res = pr.classify_ping(op)
            if res.kind not in ("alive", "rejected"):
                return
            fin.candidate = False
            self.ping.setdefault(fin.device, PingTrack()).late += 1
            rnd = self._round_of.get(fin.round_no)
            if rnd is not None:
                rnd["late"] += 1
            self.rec.log("ping", {"event": "late", "round": fin.round_no, "device": fin.device, "name": name,
                                  "op": fin.op_id, "on_time": fin.result, "late_result": res.kind,
                                  "rtt_ms": res.rtt_ms if res.rtt_src == "root" else None, "outcome": outcome,
                                  "evidence": sorted(kinds)})
            self.note("late", f"{name}: ping of round {fin.round_no} was '{fin.result}' on time, but the Host now shows "
                              f"{res.kind} ({outcome})", fin.device)
        elif fin.entry is not None:
            entry = fin.entry
            late = "drawn" if outcome == "APPLIED" or "APP_APPLIED" in kinds else (
                "arrived" if "END_RECEIVED" in kinds else None)
            if late is None or entry.get("late_result") == late:
                return
            entry["late_result"] = late
            entry["arrived"] = entry["arrived"] or "END_RECEIVED" in kinds or "APP_APPLIED" in kinds
            entry["drawn"] = entry["drawn"] or "APP_APPLIED" in kinds
            if late == "drawn":
                fin.candidate = False
            self.rec.log("display", {"event": "late", "device": fin.device, "name": name, "op": fin.op_id,
                                     "seq": entry["seq"], "on_time": fin.result, "late_result": late, "outcome": outcome,
                                     "evidence": sorted(kinds)})
            self.note("late", f"{name}: display command #{entry['seq']} was '{fin.result}' on time, but the Host now "
                              f"shows it {late}", fin.device)

    async def _watch_pending(self) -> None:
        """Safety net for an operation whose final event never came: poll it after its deadline, give up later."""
        now = self.mono()
        for p in list(self.pending.values()):
            if now < p.deadline + 1.0 or p.fetching:
                continue
            if now >= p.deadline + GIVE_UP_S:
                self._finish_unknown(p, "no final result from the Host (gave up waiting)")
            elif now - p.last_fetch >= 1.5:
                self._fetch(p)

    # ---- ping ---------------------------------------------------------------------------------------------------
    def active_nodes(self) -> list[str]:
        return [d for d, n in self.api_nodes.items() if n.get("membership") == "ACTIVE"]

    def ping_status(self) -> dict[str, Any]:
        n = len(self.active_nodes())
        interval = self.loop_interval
        warning = None
        if interval is not None:
            need, fit = ping_load(n, interval)
            if need > REQUEST_BUDGET_RPS:
                warning = (f"{n} nodes every {interval:g} s need about {need:.0f} requests/s; the Host allows 20 per "
                           f"principal: use {fit:.1f} s or more")
        return {"running": self.loop_interval is not None, "interval_s": self.loop_interval, "round": self.round_no,
                "nodes": n, "warning": warning, "rounds": list(self.rounds)[-10:], "open": len(self.pending),
                "open_max": 0 if interval is None else open_ops_max(n, interval)}

    # ---- client epochs ------------------------------------------------------------------------------------------
    def _load_epoch_file(self) -> None:
        try:
            doc = json.loads(self._epoch_file.read_text())
            self._tracked |= {e for e in doc.get("epochs", []) if isinstance(e, str)}
        except (OSError, ValueError, AttributeError):
            pass

    def _save_epoch_file(self) -> None:
        try:
            self._epoch_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._epoch_file.with_name(self._epoch_file.name + ".tmp")
            tmp.write_text(json.dumps({"domain": self.cfg.domain, "consumer": self.cfg.consumer,
                                       "epochs": sorted(self._tracked)}))
            os.replace(tmp, self._epoch_file)
            self.warn("epoch-file", None)
        except OSError as exc:
            self.warn("epoch-file", f"cannot write {self._epoch_file}: {exc} (epochs of a crash would stay open)")

    def _rotation_due(self) -> bool:
        return self.mono() - self._epoch_since >= EPOCH_ROTATE_S or self._epoch_ops >= EPOCH_ROTATE_OPS

    async def _open_epoch(self) -> str | None:
        try:
            r = await self.client.open_epoch()
        except HostUnreachable as exc:  # SendUnknown too: the replays with the same key got no answer either
            self.warn("epoch", f"cannot open a client epoch: {exc}")
            return None
        if not r.ok:
            self.warn("epoch", f"cannot open a client epoch: HTTP {r.status} {r.code}")
            return None
        self.warn("epoch", None)
        epoch = str(r.body["id"])
        self._tracked.add(epoch)
        self._save_epoch_file()  # written before the first request is made under it
        return epoch

    async def ensure_epoch(self) -> str | None:
        """The epoch new requests are sent under; opens a new one when there is none or the current one is due."""
        async with self._epoch_lock:
            if self.epoch and (not self._rotation_due() or self.mono() < self._rotate_retry_at):
                return self.epoch
            new = await self._open_epoch()
            if new is None:
                self._rotate_retry_at = self.mono() + 30.0  # keep serving from the old one, do not hammer the Host
                return self.epoch
            old, self.epoch = self.epoch, new
            self._epoch_since, self._epoch_ops, self._rotate_retry_at = self.mono(), 0, 0.0
            if old:
                self._retiring[old] = self.mono() + EPOCH_CLOSE_MARGIN_S
            self.note("session", f"client epoch {new[:8]} opened" + (f" (replaces {old[:8]})" if old else ""))
            return self.epoch

    def _take_epoch(self) -> str:
        epoch = self.epoch or ""
        self._epoch_users[epoch] += 1
        self._epoch_ops += 1
        return epoch

    def _release_epoch(self, epoch: str | None) -> None:
        if epoch is not None:
            self._epoch_users[epoch] -= 1
            if self._epoch_users[epoch] <= 0:
                del self._epoch_users[epoch]

    async def _close_epoch(self, epoch: str, retry: bool = False) -> bool:
        """Close one epoch (monotonic and idempotent on the Host; it never cancels operations already committed)."""
        if epoch in self._closing:
            return False
        self._closing.add(epoch)
        done = False
        try:
            while True:
                try:
                    r = await self.client.close_epoch(epoch)
                    done = r.ok or r.status == 404  # 404: the Host does not know it any more
                except HostUnreachable:
                    done = False
                if done or not retry:
                    break
                await asyncio.sleep(EPOCH_CLOSE_RETRY_S)
        finally:
            self._closing.discard(epoch)
        if done:
            self._tracked.discard(epoch)
            self._retiring.pop(epoch, None)
            if epoch == self.epoch:
                self.epoch = None
            self._save_epoch_file()
        return done

    def _close_retired(self) -> None:
        """A retired epoch is closed when no request of it is being sent and no operation of it is open."""
        now = self.mono()
        busy = {p.epoch for p in self.pending.values()}
        for epoch, due in list(self._retiring.items()):
            if now < due or epoch in busy or self._epoch_users.get(epoch) or epoch in self._closing:
                continue
            self._retiring[epoch] = now + EPOCH_CLOSE_RETRY_S  # next attempt if this one fails
            self._spawn(self._close_epoch(epoch))

    def _epoch_refused(self, r: Reply, sent_under: str | None) -> None:
        if r.status == 410 and r.code == "EPOCH_CLOSED" and sent_under:
            self._tracked.discard(sent_under)
            self._retiring.pop(sent_under, None)
            if self.epoch == sent_under:
                self.epoch = None  # the next request opens a new one
            self._save_epoch_file()

    async def _post(self, build: Callable[[str], dict[str, Any]], max_wait: float) -> tuple[Reply, str, float]:
        """One POST /v1/messages under the current epoch -> (reply, the epoch it was sent under, laptop time of the
        send). The epoch is fixed when the body is made: a replay of the same request keeps it."""
        used: dict[str, Any] = {"epoch": None, "t": 0.0}

        def body() -> dict[str, Any]:
            used["t"] = self.mono()
            used["epoch"] = self._take_epoch()
            return build(used["epoch"])

        self._posting += 1
        try:
            r = await self.client.post_message(body, max_wait=max_wait)
        finally:
            self._posting -= 1
            self._release_epoch(used["epoch"])
        return r, used["epoch"] or "", used["t"]

    async def start_ping_loop(self, interval_s: float) -> None:
        if interval_s < 1.0:
            raise ValueError("the loop interval is at least 1 s")
        need, fit = ping_load(len(self.active_nodes()), interval_s)
        if need > REQUEST_BUDGET_RPS:
            raise ValueError(f"{len(self.active_nodes())} nodes every {interval_s:g} s need about {need:.0f} requests/s "
                             f"(the Host allows 20 per principal): use {fit:.1f} s or more")
        await self.stop_ping_loop()
        self.loop_interval = interval_s
        self._loop_task = asyncio.ensure_future(self._guard_ping(interval_s))
        self.note("ping", f"ping loop started, every {interval_s:g} s")

    async def stop_ping_loop(self) -> None:
        task, self._loop_task = self._loop_task, None
        if self.loop_interval is not None:
            self.note("ping", "ping loop stopped")
        self.loop_interval = None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    async def _guard_ping(self, interval: float) -> None:
        nxt = self.mono()
        while True:
            try:
                await self.ping_round(interval, max_wait=interval / 2)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.warn("ping", f"ping round failed: {type(exc).__name__}: {exc}")
            nxt += interval
            now = self.mono()
            if nxt < now:  # we are behind (the Host or the budget was slow): do not catch up with a burst
                nxt = now
            await asyncio.sleep(nxt - now)

    async def ping_round(self, interval_s: float = 3.0, max_wait: float = 2.0) -> dict[str, Any]:
        """One request per ACTIVE node; returns when all requests were made (the results follow as operations end).
        A request that would wait longer than `max_wait` s for the laptop's own request budget is not made: it is
        counted as "not sent" (a late ping would only measure the queue)."""
        targets = sorted(self.active_nodes(), key=self.name_of)
        self.round_no += 1
        rnd = {"round": self.round_no, "t": utc_text(self.utcnow()), "nodes": len(targets), "alive": 0, "noanswer": 0,
               "rejected": 0, "notsent": 0, "unknown": 0, "skipped": 0, "late": 0, "open": len(targets),
               "interval_s": interval_s}
        self.rounds.append(rnd)
        self._round_of[self.round_no] = rnd
        while len(self._round_of) > 40:
            self._round_of.pop(next(iter(self._round_of)))
        self.rec.log("ping", {"event": "round", "round": self.round_no, "nodes": len(targets), "interval_s": interval_s})
        if not targets:
            return rnd
        if await self.ensure_epoch() is None:
            for d in targets:
                self._ping_refused(d, rnd, pr.PingResult("notsent", "no client epoch"))
            return rnd
        await asyncio.gather(*(self._ping_one(d, rnd, max_wait) for d in targets))
        return rnd

    def _open_ping(self, device: str, delta: int) -> None:
        n = self._open_pings[device] + delta
        if n > 0:
            self._open_pings[device] = n
        else:
            self._open_pings.pop(device, None)

    async def _ping_one(self, device: str, rnd: dict[str, Any], max_wait: float) -> None:
        if len(self.pending) >= PENDING_MAX:
            self._ping_refused(device, rnd, pr.PingResult("notsent", "too many open operations on the laptop"))
            return
        if self._open_pings[device] >= PING_OPEN_MAX:  # a slow or dead node must not pile up requests on the Host
            res = pr.PingResult("skipped", f"busy: {PING_OPEN_MAX} pings of this node are still open")
            self.ping.setdefault(device, PingTrack()).skip(rnd["round"], res)
            self._count_round(rnd, res)
            self.rec.log("ping", {"round": rnd["round"], "device": device, "name": self.name_of(device),
                                  "result": "skipped", "detail": res.detail, "op": None})
            return
        self._open_ping(device, +1)
        registered = False
        try:
            registered = await self._ping_post(device, rnd, max_wait)
        finally:
            if not registered:
                self._open_ping(device, -1)  # refused, unknown or failed: nothing of it stays open on our side

    async def _ping_post(self, device: str, rnd: dict[str, Any], max_wait: float) -> bool:
        """POST one ping; True when the Host accepted it (it is then followed as an operation until it is final)."""

        def build(epoch: str) -> dict[str, Any]:
            return pr.ping_request(self.cfg.domain, epoch, device, rnd["round"], self.utcnow())

        try:
            r, epoch, t_post = await self._post(build, max_wait)
        except SendUnknown as exc:  # the answer is lost and the replays with the same key got none either
            self.warn("post-unknown", "a POST /v1/messages got no answer: those pings are 'unknown' (see the ping log)")
            self._ping_refused(device, rnd, pr.classify_post_unknown(str(exc)), key=exc.key)
            return False
        except HostUnreachable as exc:  # failed before anything was sent
            self._ping_refused(device, rnd, pr.classify_post_error(None, exc=str(exc)))
            return False
        if r.status == 0:
            self.warn("rate", "the laptop's request budget is used up: pings were not sent (see 'not sent')")
            self._ping_refused(device, rnd, pr.PingResult("notsent", "local request budget (rate limit guard)"))
            return False
        if not r.ok:
            self._epoch_refused(r, epoch)
            if r.status == 429:
                self.warn("rate", f"the Host rate-limits us (HTTP 429, retry after {r.retry_after_ms} ms)")
            self._ping_refused(device, rnd, pr.classify_post_error(r.status, r.body))
            return False
        self.warn("post-unknown", None)
        op_id = str(r.body["id"])
        self.ping.setdefault(device, PingTrack()).accepted()
        p = Pending(op_id, "ping", device, rnd["round"], t_post, t_post + pr.PING_DEADLINE_S, epoch=epoch)
        self.pending[op_id] = p
        self.rec.log("ping", {"event": "posted", "round": rnd["round"], "device": device, "name": self.name_of(device),
                              "op": op_id, "epoch": epoch})
        if op_id in self.final_hint or r.body.get("state") == "FINAL":
            self.final_hint.pop(op_id, None)
            self._fetch(p)
        return True

    def _ping_refused(self, device: str, rnd: dict[str, Any], res: pr.PingResult, key: str | None = None) -> None:
        self.ping.setdefault(device, PingTrack()).refused(rnd["round"], res)
        self._count_round(rnd, res)
        extra = {"idempotency_key": key} if key else {}
        self.rec.log("ping", {"round": rnd["round"], "device": device, "name": self.name_of(device),
                              "result": res.kind, "detail": res.detail, "op": None, **extra})

    def _ping_done(self, p: Pending, res: pr.PingResult, op: dict[str, Any]) -> None:
        self._open_ping(p.device, -1)
        self.ping.setdefault(p.device, PingTrack()).finish(p.round_no, res)
        rnd = self._round_of.get(p.round_no)
        if rnd is not None:
            self._count_round(rnd, res)
        self.rec.log("ping", {"round": p.round_no, "device": p.device, "name": self.name_of(p.device), "op": p.op_id,
                              "result": res.kind, "detail": res.detail, "rtt_ms": res.rtt_ms, "rtt_src": res.rtt_src,
                              "outcome": op.get("outcome"), "evidence": sorted(pr.evidence_kinds(op))})

    @staticmethod
    def _count_round(rnd: dict[str, Any], res: pr.PingResult) -> None:
        rnd[res.kind] += 1
        rnd["open"] = max(0, rnd["open"] - 1)

    # ---- display ------------------------------------------------------------------------------------------------
    def display_nodes(self) -> list[str]:
        return [d for d, t in self.tele.items() if t.last is not None and t.last.role == pr.ROLE_DISPLAY]

    async def send_display(self, device: str, state: str) -> dict[str, Any]:
        track = self.tele.get(device)
        if device not in self.api_nodes and (track is None or track.last is None):
            raise LookupError("unknown node")
        if track is None or track.last is None or track.last.role != pr.ROLE_DISPLAY:
            raise ValueError("that node does not report the display role in its telemetry")
        if state not in ("USABLE", "FORBID"):
            raise ValueError("state is USABLE or FORBID")
        if len(self.pending) >= PENDING_MAX:
            raise RuntimeError("too many open operations on the laptop")
        if await self.ensure_epoch() is None:
            raise RuntimeError("cannot open a client epoch")
        self.command_seq = (self.command_seq + 1) & 0xFFFFFFFF
        seq = self.command_seq

        def build(epoch: str) -> dict[str, Any]:
            return pr.display_request(self.cfg.domain, epoch, device, state, seq, self.utcnow())

        r, epoch, t_post = Reply(0, {}), "", 0.0
        unknown: SendUnknown | None = None
        for _ in range(3):  # a 429 stops the budget for what the Host asked, then the next try goes out
            try:
                r, epoch, t_post = await self._post(build, 5.0)
            except SendUnknown as exc:
                unknown = exc
                break
            except HostUnreachable as exc:  # failed before anything was sent
                r = Reply(0, {"code": "UNREACHABLE", "message": str(exc)})
                break
            if r.status != 429:
                break
        if not r.ok:
            self._epoch_refused(r, epoch)
        entry = {"device": device, "name": self.name_of(device), "state": state, "seq": seq,
                 "posted": utc_text(self.utcnow()), "op": None, "arrived": False, "drawn": False,
                 "arrived_ms": None, "drawn_ms": None, "result": "pending", "detail": ""}
        self.display[device] = entry
        if unknown is not None:  # the Host may have the command: neither "sent" nor "not sent"
            res = pr.classify_post_unknown(str(unknown))
            entry.update(result="unknown", detail=res.detail)
            self.rec.log("display", {"event": "unknown", "idempotency_key": unknown.key, **entry})
            return entry
        if not r.ok:
            entry.update(result="notsent", detail=f"HTTP {r.status} {r.code}".strip())
            self.rec.log("display", {"event": "refused", **entry})
            return entry
        op_id = str(r.body["id"])
        entry["op"] = op_id
        self.rec.log("display", {"event": "posted", **entry})
        self.note("display", f"display {self.name_of(device)} -> {state} (seq {seq}) sent", device)
        p = Pending(op_id, "display", device, 0, t_post, t_post + pr.DISPLAY_DEADLINE_S, epoch=epoch, entry=entry,
                    fetch_any=True)
        self.pending[op_id] = p
        if op_id in self.final_hint:
            self.final_hint.pop(op_id, None)
            self._fetch(p)
        return entry

    def _display_progress(self, p: Pending, op: dict[str, Any]) -> None:
        entry = p.entry  # every accepted command keeps its own record; self.display[device] is only what the page shows
        if entry is None:
            return
        kinds = pr.evidence_kinds(op)
        elapsed = int((self.mono() - p.t_post) * 1000)
        for flag, kind in (("arrived", "END_RECEIVED"), ("drawn", "APP_APPLIED")):
            if kind in kinds and not entry[flag]:
                entry[flag] = True
                entry[f"{flag}_ms"] = elapsed
                self.rec.log("display", {"event": flag, "device": p.device, "name": self.name_of(p.device),
                                         "op": p.op_id, "seq": entry["seq"], "laptop_ms": elapsed,
                                         "root_ms": pr.rtt_from_evidence(op), "latest": self.display.get(p.device) is entry})

    def _display_done(self, p: Pending, op: dict[str, Any], elapsed_ms: int) -> None:
        entry = p.entry
        if entry is None:
            return
        outcome = op.get("outcome", "")
        kinds = pr.evidence_kinds(op)
        entry["arrived"] = entry["arrived"] or "END_RECEIVED" in kinds or "APP_APPLIED" in kinds
        entry["drawn"] = entry["drawn"] or "APP_APPLIED" in kinds
        if outcome == "APPLIED":
            entry.update(result="drawn")
        elif kinds & {"APP_REJECTED", "DESTINATION_REFUSED"}:
            entry.update(result="rejected", detail="the display answered REJECTED (it could not draw)")
        else:
            res = pr.classify_ping(op, arrival_is_alive=False)
            entry.update(result=res.kind, detail=res.detail)
        self.rec.log("display", {"event": "final", "device": p.device, "name": self.name_of(p.device), "op": p.op_id,
                                 "seq": entry["seq"], "outcome": outcome, "result": entry["result"],
                                 "detail": entry["detail"], "arrived": entry["arrived"], "drawn": entry["drawn"],
                                 "latest": self.display.get(p.device) is entry, "evidence": sorted(kinds)})
        self.note("display", f"display {self.name_of(p.device)} {entry['state']} (seq {entry['seq']}): "
                             f"{entry['result']}", p.device)

    # ---- nodes / topology ---------------------------------------------------------------------------------------
    def _reload_names(self) -> None:
        """Board names of boards provisioned after the start: the state file is read again when its mtime changes."""
        path = self.cfg.state_file
        if path is None:
            return
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return
        if mtime == getattr(self, "_state_mtime", None):
            return
        self._state_mtime = mtime
        bench = load_bench(path, self.cfg.net)
        if bench.get("names"):
            self.cfg.names = bench["names"]
        if bench.get("root_id"):
            self.cfg.root_id = bench["root_id"]

    async def _nodes_loop(self) -> None:
        while True:
            self._reload_names()
            st = await self.client.status()
            if st.ok:
                self._note_status(st.body)
            r = await self.client.nodes()
            if r.ok:
                self._on_nodes(r.body.get("items", []))
                self.warn("nodes", None)
            else:
                self.warn("nodes", f"GET /v1/nodes failed: HTTP {r.status} {r.code}")
            await asyncio.sleep(self.cfg.nodes_poll_s)

    def _on_nodes(self, items: list[dict[str, Any]]) -> None:
        now = self.mono()
        new = {n["device_id"]: n for n in items}
        old = self.api_nodes
        if self.nodes_seen:
            for d, n in new.items():
                o = old.get(d)
                if o is None:
                    self.note("join", f"{self.name_of(d)} listed by the root ({n.get('membership')})", d)
                    continue
                if o.get("membership") != n.get("membership"):
                    kind = "join" if n.get("membership") == "ACTIVE" else "leave"
                    self.note(kind, f"{self.name_of(d)} membership {o.get('membership')} -> {n.get('membership')}", d)
                if o.get("parent_device_id") != n.get("parent_device_id"):
                    self.note("parent", f"{self.name_of(d)} parent {self._parent_name(o)} -> {self._parent_name(n)}", d)
                elif o.get("root_depth") != n.get("root_depth"):
                    self.note("depth", f"{self.name_of(d)} depth {o.get('root_depth')} -> {n.get('root_depth')}", d)
                if o.get("connectivity") != n.get("connectivity"):
                    self.note("link", f"{self.name_of(d)} connectivity {o.get('connectivity')} -> "
                                      f"{n.get('connectivity')}", d)
            for d in old.keys() - new.keys():
                self.note("leave", f"{self.name_of(d)} is no longer listed by the root", d)
        self.nodes_seen = True
        for d in new:
            self.first_listed.setdefault(d, now)
        self.api_nodes = new

    def _parent_name(self, n: dict[str, Any]) -> str:
        p = n.get("parent_device_id")
        return "-" if not p else ("root" if p == self.cfg.root_id else self.name_of(p))

    # ---- the clock tick: lost/back, safety net, summary ----------------------------------------------------------
    async def _tick_loop(self) -> None:
        while True:
            await asyncio.sleep(self.cfg.tick_s)
            self._check_lost()
            await self._watch_pending()
            self._close_retired()
            with contextlib.suppress(HostUnreachable):  # the events loop shows an unreachable Host
                await self._ack()
            now = self.mono()
            if now - self._last_summary >= self.cfg.summary_s:
                self._last_summary = now
                self.rec.summary(self.summary_rows())
            self._forget_stale_devices()
            w = self.rec.warning
            if w != self.recorder_warn_seen:
                self.recorder_warn_seen = w
                self.warn("records", None if w is None else f"records: {w}")

    def _forget_stale_devices(self) -> None:
        """The per-node tables follow what the Host lists; a node that is not listed any more (revoked, replaced) is
        dropped, oldest first, once a table is beyond DEVICES_MAX (a Host holds at most 64 members)."""
        tables: list[dict[str, Any]] = [self.tele, self.ping, self.node_state, self.display, self.first_listed]
        for table in tables:
            extra = len(table) - DEVICES_MAX
            if extra > 0:
                for d in [d for d in table if d not in self.api_nodes][:extra]:
                    del table[d]
        if len(self.silent_noted) > DEVICES_MAX:
            self.silent_noted &= set(self.api_nodes)

    def _interval_of(self, device: str) -> float:
        t = self.tele.get(device)
        return float(t.last.interval_s) if t and t.last and t.last.interval_s else self.cfg.interval_s

    def _check_lost(self) -> None:
        now = self.mono()
        for d, track in self.tele.items():
            age = track.age(now)
            if age is None:
                continue
            if age > LOSS_FACTOR * self._interval_of(d):
                if self.node_state.get(d) != "lost":
                    self.node_state[d] = "lost"
                    self.note("lost", f"{self.name_of(d)}: no telemetry for {age:.0f} s", d)
            elif self.node_state.get(d) in (None, "lost"):
                self.node_state[d] = "ok"
        for d in self.active_nodes():
            if d in self.silent_noted or (d in self.tele and self.tele[d].last_seen is not None):
                continue
            if now - self.first_listed.get(d, now) > LOSS_FACTOR * self.cfg.interval_s:
                self.silent_noted.add(d)
                self.note("silent", f"{self.name_of(d)}: listed by the root, but no telemetry yet", d)

    # ---- the picture ----------------------------------------------------------------------------------------------
    def devices(self) -> list[str]:
        return sorted(set(self.api_nodes) | {d for d, t in self.tele.items() if t.last is not None},
                      key=lambda d: (self.name_of(d), d))

    def state_of(self, device: str) -> str:
        item, track = self.api_nodes.get(device), self.tele.get(device)
        if item is None:
            return "unlisted"
        if item.get("membership") != "ACTIVE":
            return "left"
        if track is None or track.last_seen is None:
            return "silent"
        return "lost" if self.node_state.get(device) == "lost" else "ok"

    def node_row(self, device: str) -> dict[str, Any]:
        now = self.mono()
        item = self.api_nodes.get(device) or {}
        track = self.tele.get(device) or TelemetryTrack()
        t = track.last
        ping = self.ping.get(device) or PingTrack()
        state = self.state_of(device)
        fresh = state == "ok"
        rssi = t.parent_rssi_dbm if (t is not None and fresh) else item.get("parent_rssi_dbm")
        depth = item.get("root_depth") if item.get("root_depth") is not None else (t.depth if t else None)
        return {
            "device": device, "name": self.name_of(device), "short": short_id(device), "state": state,
            "membership": item.get("membership"), "connectivity": item.get("connectivity"),
            "chip": t.chip_name if t else None, "role": t.role_name if t else None, "depth": depth,
            "parent_id": item.get("parent_device_id"),
            "parent": None if not item.get("parent_device_id") else self._parent_name(item),
            "rssi_dbm": rssi, "age_s": track.age(now), "seq": t.seq if t else None,
            "boot_count": t.boot_count if t else None, "uptime_s": t.uptime_s if t else None,
            "reset_reason": t.reset_reason if t else None, "reboots": track.reboots,
            "received": track.received, "lost": track.lost,
            "loss_pct": track.loss_pct, "recent_loss_pct": track.recent_loss_pct,
            "tx_frames": t.tx_frames if t else None, "rx_frames": t.rx_frames if t else None,
            "rf_failures": t.rf_failures if t else None, "local_busy": t.local_busy if t else None,
            "min_heap_bytes": t.min_heap_bytes if t else None,
            "display_state": t.display_state if t else None, "display_seq": t.display_seq if t else None,
            "render_fault": t.render_fault if t else None, "ping": ping.as_dict(),
        }

    def snapshot(self) -> dict[str, Any]:
        rows = [self.node_row(d) for d in self.devices()]
        views = {r["device"]: NodeView(
            name=r["name"], role=r["role"], rssi=r["rssi_dbm"], loss_pct=r["recent_loss_pct"],
            silent=r["state"] not in ("ok",), lost=r["state"] == "lost", depth=r["depth"]) for r in rows}
        tree = build_tree(list(self.api_nodes.values()), views, self.cfg.root_id, self.cfg.root_name)
        unlisted = [r["device"] for r in rows if r["state"] == "unlisted"]
        warnings = list(self.warnings.values())
        ps = self.ping_status()
        if ps["warning"]:
            warnings.append(ps["warning"])
        if self.client.bucket.throttled:
            warnings.append(f"the laptop's request budget delayed {self.client.bucket.throttled} requests")
        return {
            "now": utc_text(self.utcnow()), "started": self.started_utc, "logs": str(self.rec.directory),
            "domain": self.cfg.domain, "interval_assumed_s": self.cfg.interval_s,
            "host": {**self.host, "requests": self.client.requests, "rate_limited": self.client.rate_limited,
                     "cursor": self.cursor, "backlog_events": self.backlog_events, "live_events": self.live_events,
                     "other_messages": self.other_messages, "bad_telemetry": self.bad_telemetry},
            "warnings": warnings, "tree": tree, "nodes": rows, "unlisted": unlisted,
            "events": list(self.log)[-200:], "ping": ps, "display": self.display,
            "display_nodes": [{"device": d, "name": self.name_of(d)} for d in self.display_nodes()],
        }

    def summary_rows(self) -> list[dict[str, Any]]:
        stamp = utc_text(self.utcnow())
        out = []
        for d in self.devices():
            r = self.node_row(d)
            p = r["ping"]
            out.append({"utc": stamp, "name": r["name"], "device": d, "depth": r["depth"], "parent": r["parent"],
                        "rssi_dbm": r["rssi_dbm"],
                        "telemetry_loss_pct": None if r["loss_pct"] is None else f"{r['loss_pct']:.1f}",
                        "ping_sent": p["sent"], "ping_alive": p["alive"], "ping_lost": p["noanswer"],
                        "ping_notsent": p["notsent"], "ping_unknown": p["unknown"], "ping_skipped": p["skipped"],
                        "ping_late": p["late"],
                        "ping_rtt_median_ms": None if p["rtt_median_ms"] is None else f"{p['rtt_median_ms']:.0f}",
                        "last_seen_age_s": None if r["age_s"] is None else f"{r['age_s']:.0f}"})
        return out
