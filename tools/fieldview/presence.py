"""Bounded browser evidence for the approved display application. No sensor inference."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from . import protocol as pr

STALE_S = 30.0
SAMPLE_MAX_MS = 10000
BOOT_KEEP = 8
PRESS_WINDOW = 256
HISTORY_KEEP = 20


def receipt_utc(event: dict[str, Any]) -> datetime | None:
    """Only an explicit Host timestamp; processing/recorder time is never a substitute."""
    text = event.get("received_utc")
    if not isinstance(text, str):
        return None
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return when.astimezone(UTC) if when.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def fresh_time(received: datetime | None, now: datetime) -> bool:
    return received is not None and 0 <= (now - received).total_seconds() < STALE_S


@dataclass
class PressWindow:
    high: int = 0
    bits: int = 0

    def feed(self, seq: int) -> str:
        if seq > self.high:
            shift = seq - self.high
            self.bits = 0 if shift >= PRESS_WINDOW else (self.bits << shift) & ((1 << PRESS_WINDOW) - 1)
            self.high = seq
        offset = self.high - seq
        if offset >= PRESS_WINDOW:
            return "outside_window"
        bit = 1 << offset
        if self.bits & bit:
            return "duplicate"
        self.bits |= bit
        return "received"


@dataclass
class PresenceTrack:
    last: pr.PresenceSnapshot | None = None
    received: datetime | None = None
    observed: datetime | None = None
    capture_base: datetime | None = None   # earliest receipt minus capture uptime within this boot
    live: bool = False
    invalid: str | None = None
    retired: set[int] = field(default_factory=set)  # never evict: overflow stays ambiguous
    tele: pr.Telemetry | None = None
    tele_received: datetime | None = None
    tele_live: bool = False
    tele_retired: set[int] = field(default_factory=set)
    reboot_pending: bool = False
    presses: dict[int, PressWindow] = field(default_factory=dict)
    k3_count: int = 0
    k3_history: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=HISTORY_KEEP))
    limited: bool = False

    def invalidate(self, reason: str) -> None:
        self.invalid = reason
        self.live = False
        for entry in self.k3_history:
            entry["fresh"] = False  # new snapshots cannot reauthorize evidence whose proof was lost

    def telemetry(self, t: pr.Telemetry, received: datetime | None, now: datetime, backlog: bool) -> None:
        if (backlog and self.tele_live) or t.boot_count in self.tele_retired:
            return
        prev = self.tele
        if received is not None and self.tele_received is not None and received < self.tele_received:
            return
        if prev is not None:
            if t.boot_count == prev.boot_count:
                if prev.seq - t.seq > 5 and t.uptime_s < prev.uptime_s:
                    self.reboot_pending = True
                    self.invalidate("reboot")
                    self.tele, self.tele_received = t, received
                    self.tele_live = not backlog
                    return
                if t.seq <= prev.seq or t.uptime_s < prev.uptime_s:
                    return
            else:
                # An old backlog boot may have a shorter uptime than the current boot. In that
                # case require separated UTC boot-start bounds, allowing 30s delivery lag + rounding.
                later_start = (fresh_time(received, now) and self.tele_received is not None and
                               received - timedelta(seconds=t.uptime_s) >
                               self.tele_received - timedelta(seconds=prev.uptime_s) + timedelta(seconds=STALE_S + 1))
                if (t.uptime_s >= prev.uptime_s and not later_start) or len(self.tele_retired) >= BOOT_KEEP:
                    self.invalidate("boot_ambiguous")
                    return
                self.tele_retired.add(prev.boot_count)
                self.reboot_pending = True
                self.invalidate("reboot")
        self.tele, self.tele_received = t, received
        self.tele_live = not backlog

    def _boot_proven(self, s: pr.PresenceSnapshot, received: datetime | None, now: datetime) -> bool:
        if not self.reboot_pending or not self.tele_live or self.tele is None or not fresh_time(self.tele_received, now):
            return False
        if not fresh_time(received, now) or received < self.tele_received:
            return False
        elapsed_ms = (received - self.tele_received).total_seconds() * 1000
        # telemetry's uptime is rounded to seconds; transmission may lag, bounded by the 30s app budget.
        delta = s.uptime_ms - (self.tele.uptime_s * 1000 + elapsed_ms)
        return -STALE_S * 1000 <= delta <= 1000

    def snapshot(self, s: pr.PresenceSnapshot, received: datetime | None, now: datetime, backlog: bool) -> str:
        prev = self.last
        disposition = "accepted"
        if prev is not None:
            if (not backlog and received is not None and self.received is not None and received < self.received and
                    s.boot_id == prev.boot_id and s.seq > prev.seq and s.uptime_ms >= prev.uptime_ms):
                self.invalidate("clock_reversal")
                return "clock_reversal"
            if (received is not None and self.received is not None and received < self.received) or (
                    backlog and self.live):
                return "old_receipt"
            if s.boot_id == prev.boot_id:
                if s.seq <= prev.seq or s.uptime_ms < prev.uptime_ms:
                    return "old_or_duplicate"
                if self.reboot_pending or self.invalid == "boot_ambiguous":
                    return "boot_ambiguous"
            else:
                if s.boot_id in self.retired:
                    return "old_boot"
                if backlog or not self._boot_proven(s, received, now) or len(self.retired) >= BOOT_KEEP:
                    self.invalidate("boot_ambiguous")
                    return "boot_ambiguous"
                self.retired.add(prev.boot_id)
                self.capture_base = None
                self.reboot_pending = False
                disposition = "new_boot"
        self.last, self.received, self.observed = s, received, now
        self.live = not backlog and fresh_time(received, now) and disposition != "new_boot"
        self.invalid = "reboot" if disposition == "new_boot" else None
        if s.sample_age_ms is not None and s.sample_age_ms > s.uptime_ms:
            self.invalidate("invalid_sample_age")
            return "invalid_sample_age"
        if received is not None and received <= now:
            base = received - timedelta(milliseconds=s.uptime_ms)
            self.capture_base = min(self.capture_base, base) if self.capture_base is not None else base
        return disposition

    def k3(self, p: pr.K3Press, received: datetime | None, now: datetime, backlog: bool) -> tuple[str, dict[str, Any]]:
        window = self.presses.get(p.boot_id)
        if window is None:
            if len(self.presses) >= BOOT_KEEP:
                self.limited = True
                return "boot_limit", {}
            window = self.presses[p.boot_id] = PressWindow()
        disposition = window.feed(p.seq)
        if disposition != "received":
            if disposition == "outside_window":
                self.limited = True
            return disposition, {}
        # Proof of a press reception is separate from proof that it is a recent press in the current boot.
        s = self.last
        capture = (self.capture_base + timedelta(milliseconds=s.uptime_ms)
                   if s is not None and self.capture_base is not None else None)
        pressed = (self.capture_base + timedelta(milliseconds=p.uptime_ms)
                   if self.capture_base is not None and s is not None and s.boot_id == p.boot_id else None)
        fresh = (not backlog and fresh_time(received, now) and s is not None and self.live and
                 fresh_time(self.received, now) and fresh_time(capture, now) and fresh_time(pressed, now) and
                 received is not None and self.received is not None and received >= self.received and
                 self.invalid is None and s.boot_id == p.boot_id)
        entry = {**p.as_dict(), "received_utc": received.isoformat() if received else None,
                 "estimated_press_utc": pressed.isoformat() if pressed is not None else None,
                 "observed_utc": now.isoformat(), "backlog": backlog, "fresh": fresh}
        self.k3_count += 1
        self.k3_history.append(entry)
        return disposition, entry

    def as_dict(self, now: datetime) -> dict[str, Any]:
        if self.observed is not None and now < self.observed:
            self.invalidate("clock_reversal")
        s = self.last
        age = None if self.received is None else (now - self.received).total_seconds()
        stale = s is not None and (not self.live or self.invalid is not None or not fresh_time(self.received, now))
        sample_age = None
        if s is not None and s.sample_age_ms is not None and self.capture_base is not None:
            capture = self.capture_base + timedelta(milliseconds=s.uptime_ms)
            sample_age = s.sample_age_ms + max(0, (now - capture).total_seconds() * 1000)
        reported = pr.PRESENCE_STATES[s.presence] if s else None
        state = "unknown" if s is None or stale else reported
        if state in ("vacant", "occupied") and (s.flags & 3 != 3 or s.faults & 3 or s.distance_mm is None or
                                                s.background_mm is None or sample_age is None or
                                                sample_age >= SAMPLE_MAX_MS):
            state = "unknown"
            stale = stale or sample_age is None or sample_age >= SAMPLE_MAX_MS
        history = []
        for entry in self.k3_history:
            receipt = receipt_utc(entry)
            pressed = datetime.fromisoformat(entry["estimated_press_utc"]) if entry["estimated_press_utc"] else None
            same_boot = s is not None and entry["boot_id"] == f"{s.boot_id:016x}"
            if same_boot and pressed is not None and self.capture_base is not None:
                pressed = min(pressed, self.capture_base + timedelta(milliseconds=entry["uptime_ms"]))
                entry["estimated_press_utc"] = pressed.isoformat()
            entry["fresh"] = bool(entry["fresh"] and self.live and self.invalid is None and same_boot and
                                  fresh_time(self.received, now) and fresh_time(receipt, now) and fresh_time(pressed, now))
            history.append(dict(entry))
        return {"state": state, "reported": reported, "stale": stale, "invalid": self.invalid,
                "boot_id": f"{s.boot_id:016x}" if s else None, "seq": s.seq if s else None,
                "uptime_ms": s.uptime_ms if s else None, "snapshot_age_s": age,
                "received_utc": self.received.isoformat() if self.received else None,
                "observed_utc": self.observed.isoformat() if self.observed else None,
                "learning": pr.LEARNING_STATES[s.learning] if s else None,
                "learning_request": s.learning_request if s else None,
                "sample_age_ms": sample_age, "distance_mm": s.distance_mm if s else None,
                "background_mm": s.background_mm if s else None, "noise_mm": s.noise_mm if s else None,
                "flags": s.flags if s else None, "faults": s.faults if s else None,
                "last_k3_seq": s.last_k3_seq if s else None,
                "k3_result": pr.K3_RESULTS[s.k3_result] if s else None, "k3_count": self.k3_count,
                "k3_history": history, "k3_last": history[-1] if history else None, "limited": self.limited}
