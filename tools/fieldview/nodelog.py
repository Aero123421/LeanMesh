"""What the node event log (docs/field/protocol.md §3.4, app port 213) says about one node: the boots, the join / attach
timeline of the current boot, record loss from the per-boot sequence numbers, the last radio facts, and the plain text of
the records that matter. Pure state, no I/O, no clock: the engine feeds it decoded records and writes what comes out."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import protocol as pr

LATE_MAX = 16          # a record this many sequence numbers behind (or fewer) is a late arrival, not a restart
LATE_T_MS = 60_000     # a record whose boot time is this much behind the last one is from another boot
MAX_GAP = 1000         # a bigger sequence jump is not a count of lost records we can trust


@dataclass
class Fed:
    """What one record did to the track (the engine turns it into log lines)."""
    late: bool = False             # a duplicate or an older record than one already seen: it changed no state
    new_boot: bool = False         # a BOOT record
    unseen_boot: bool = False      # sequence / boot time fell back with no BOOT: the BOOT record never arrived
    missing: int = 0               # records missing before this one (sequence gap)
    jump: bool = False             # a gap too big to count
    first_reachable: bool = False  # the first REACHABLE of this boot
    first_member: bool = False
    prev_radio: dict[str, Any] | None = None


@dataclass
class NodeLogTrack:
    """Bounded: a fixed set of scalars per node, no record history (the history is nodelog.ndjson)."""
    records: int = 0
    late: int = 0
    unknown_types: int = 0
    # boots
    boots_seen: int = 0
    boots_unseen: int = 0
    sdk_restarts: int = 0
    boot: dict[str, Any] | None = None       # the last BOOT record's fields
    boot_count: int | None = None            # None until a BOOT is seen, and after a boot whose BOOT never arrived
    # the current boot
    boot_seq: int | None = None
    last_seq: int | None = None
    last_t_ms: int = 0
    member_ms: int | None = None
    reachable_ms: int | None = None
    time_valid_ms: int | None = None
    reachable: bool | None = None
    depth: int | None = None
    parent_rssi_dbm: int | None = None
    radio: dict[str, Any] | None = None
    # all boots of the session
    unreachable: int = 0
    last_unreachable: dict[str, Any] | None = None
    last_join_end: dict[str, Any] | None = None
    display_faults: int = 0
    records_lost: int = 0                    # sequence gaps: records that never reached us (or the ring dropped)
    log_lost: int = 0                        # LOG_LOST: records the node's ring dropped, as the node counted them

    def _new_boot(self) -> None:
        self.member_ms = self.reachable_ms = self.time_valid_ms = None
        self.reachable = self.depth = self.parent_rssi_dbm = None
        self.radio = None

    def feed(self, rec: pr.NodeRecord) -> Fed:
        fed = Fed()
        self.records += 1
        if not rec.known:
            self.unknown_types += 1
        if rec.type == pr.T_BOOT:
            f = rec.fields or {}
            if self.boot_seq == rec.seq and self.boot_count == f.get("boot_count") and self.last_seq is not None:
                fed.late = True            # the same BOOT again
                self.late += 1
                return fed
            fed.new_boot = True
            self.boots_seen += 1
            if f.get("sdk_restart_cause"):
                self.sdk_restarts += 1
            self._new_boot()
            self.boot, self.boot_count = f, f.get("boot_count")
            self.boot_seq = self.last_seq = rec.seq
            self.last_t_ms = rec.t_ms
            return fed
        if self.last_seq is not None:
            ahead = (rec.seq - self.last_seq) & 0xFFFF   # u16 sequence: modular distance, so a wrap is no restart
            behind = (0x10000 - ahead) & 0xFFFF
            if (ahead >= 0x8000 and behind > LATE_MAX) or rec.t_ms + LATE_T_MS < self.last_t_ms:
                fed.unseen_boot = True     # the sequence (or the boot time) started over without a BOOT
                self.boots_unseen += 1
                self._new_boot()
                self.boot_count = self.boot_seq = None
            elif ahead == 0 or ahead >= 0x8000:
                fed.late = True            # a duplicate, or older than one already seen: it changes no state
                self.late += 1
                if ahead:                  # older, not a duplicate: it was counted as missing when its successor came
                    self.records_lost = max(0, self.records_lost - 1)
                return fed
            elif ahead > 1:
                if ahead - 1 > MAX_GAP:
                    fed.jump = True
                else:
                    fed.missing = ahead - 1
                    self.records_lost += fed.missing
        self.last_seq, self.last_t_ms = rec.seq, rec.t_ms
        self._apply(rec, fed)
        return fed

    def _apply(self, rec: pr.NodeRecord, fed: Fed) -> None:
        f = rec.fields or {}
        t = rec.type
        if t == pr.T_MEMBER and self.member_ms is None:
            self.member_ms, fed.first_member = rec.t_ms, True
        elif t == pr.T_REACHABLE:
            if self.reachable_ms is None:
                self.reachable_ms, fed.first_reachable = rec.t_ms, True
            self.reachable = True
            self.depth, self.parent_rssi_dbm = f["depth"], f["parent_rssi_dbm"]
        elif t == pr.T_DEPTH:
            self.depth, self.parent_rssi_dbm = f["depth"], f["parent_rssi_dbm"]
        elif t == pr.T_UNREACHABLE:
            self.unreachable += 1
            self.reachable = False
            self.last_unreachable = f
        elif t == pr.T_TIME_VALID and self.time_valid_ms is None:
            self.time_valid_ms = rec.t_ms
        elif t == pr.T_JOIN_END:
            self.last_join_end = f
        elif t == pr.T_RADIO:
            fed.prev_radio, self.radio = self.radio, f
        elif t == pr.T_DISPLAY_FAULT:
            self.display_faults += 1
        elif t == pr.T_LOG_LOST:
            self.log_lost += f["records_dropped"]

    # ---- what the page and the summary show ---------------------------------------------------------------------
    @property
    def boot_cause(self) -> str | None:
        """Last BOOT's cause as one short text: the reset reason, and the SDK's own cause when there was one."""
        if self.boot is None:
            return None
        text = pr.reset_reason_name(self.boot["reset_reason"])
        sdk = pr.sdk_cause_text(self.boot["sdk_restart_cause"])
        return f"{text}; SDK: {sdk}" if sdk else text

    @property
    def attach_s(self) -> float | None:
        return None if self.reachable_ms is None else self.reachable_ms / 1000.0

    def as_dict(self) -> dict[str, Any]:
        """The fields of one node row (engine.node_row); every value is None when the node's log has not said it."""
        r = self.radio or {}
        return {"boot_cause": self.boot_cause, "boot_detail": self._boot_detail(), "attach_s": self.attach_s,
                "member_s": None if self.member_ms is None else self.member_ms / 1000.0,
                "time_valid_s": None if self.time_valid_ms is None else self.time_valid_ms / 1000.0,
                "boots_logged": self.boots_seen, "sdk_restarts": self.sdk_restarts, "unreachable": self.unreachable,
                "tx_done_max_ms": r.get("tx_done_max_ms"), "tx_late": r.get("tx_late"),
                "tx_stall_waits": r.get("tx_stall_waits"), "records_lost": self.records_lost,
                "log_lost": self.log_lost, "log_records": self.records}

    def _boot_detail(self) -> str | None:
        b = self.boot
        if b is None:
            return None
        text = f"boot #{b['boot_count']}, previous run {b['prev_uptime_ms'] / 1000:.0f} s"
        if b["sdk_restart_cause"]:
            text += f", SDK restart detail {b['detail_ms']} ms"
        return text


# ---- the words ------------------------------------------------------------------------------------------------------

BOOT_REASON_TEXT = {"unknown": "unknown reset reason", "power on": "power on", "software": "software restart",
                    "panic": "panic restart", "watchdog": "watchdog reset", "brownout": "brownout",
                    "deep sleep wake": "wake from deep sleep", "external": "external reset"}


def _span(ms: int) -> str:
    s = ms / 1000.0
    return f"{s:.0f} s" if s >= 10 else f"{s:.1f} s"


def boot_text(f: dict[str, Any]) -> str:
    reason = pr.reset_reason_name(f["reset_reason"])
    cause, detail = f["sdk_restart_cause"], f["detail_ms"]
    if cause == pr.SDK_RESTART_RADIO_STALL:
        what = "software restart by the SDK (radio stall" + (f", TX completion outstanding {detail} ms)" if detail else ")")
    elif cause:
        what = f"restart by the SDK (cause {cause}" + (f", detail {detail} ms)" if detail else ")")
    else:
        what = BOOT_REASON_TEXT.get(reason, reason)
    after = f" after {_span(f['prev_uptime_ms'])}" if f["prev_uptime_ms"] else ""
    return f"booted: {what}{after}"


def _where(depth: int | None, rssi: int | None) -> str:
    parts = ([] if depth is None else [f"depth {depth}"]) + ([] if rssi is None else [f"{rssi} dBm"])
    return f" ({', '.join(parts)})" if parts else ""


def describe(name: str, rec: pr.NodeRecord, fed: Fed, track: NodeLogTrack) -> tuple[str, str] | None:
    """(event kind, text) of a record that is worth a line in the event log, else None. A late record changed no
    state and says nothing; an unknown type has no words."""
    if fed.late or not rec.known:
        return None
    f = rec.fields or {}
    t = rec.type
    if t == pr.T_BOOT:
        return "boot", f"{name} {boot_text(f)}"
    if t == pr.T_MEMBER and fed.first_member:
        return "attach", f"{name} became a member {_span(rec.t_ms)} after boot"
    if t == pr.T_REACHABLE:
        where = _where(track.depth, track.parent_rssi_dbm)
        if fed.first_reachable:
            return "attach", f"{name} attached {_span(rec.t_ms)} after boot{where}"
        return "attach", f"{name} reachable again {_span(rec.t_ms)} after boot{where}"
    if t == pr.T_DEPTH:
        return "depth", f"{name} parent changed{_where(track.depth, track.parent_rssi_dbm)}"
    if t == pr.T_UNREACHABLE:
        state = pr.CONNECTIVITY_NAMES.get(f["connectivity_state"], f"state {f['connectivity_state']}")
        return "unreachable", f"{name} unreachable ({state}, reason {f['reason']}) {_span(rec.t_ms)} after boot"
    if t == pr.T_RADIO:
        prev = fed.prev_radio or {"tx_late": 0, "tx_stall_waits": 0}
        if f["tx_late"] > prev["tx_late"] or f["tx_stall_waits"] > prev["tx_stall_waits"]:
            text = f"{name} radio: longest TX completion {f['tx_done_max_ms']} ms, {f['tx_late']} late"
            if f["tx_stall_waits"]:
                text += f", {f['tx_stall_waits']} stall wait(s)"
            return "radio", text
        return None
    if t == pr.T_DISPLAY_FAULT:
        return "panel", f"{name} display fault: {pr.DISPLAY_FAULTS.get(f['code'], 'code ' + str(f['code']))}"
    if t == pr.T_LOG_LOST:
        return "nodelog", f"{name}: the node's log ring dropped {f['records_dropped']} record(s)"
    return None
