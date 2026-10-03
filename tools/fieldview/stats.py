"""Per-node statistics: telemetry sequence/loss/reboots and ping results. Pure state, no I/O, no clock of its own."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .protocol import PingResult, Telemetry, median

WINDOW = 30       # telemetry slots of the recent-loss window (the link colour uses it)
LATE_MAX = 5      # a message this many sequence numbers behind is a restart, not a late arrival
MAX_GAP = 1000    # a bigger sequence jump is a lost place of ours (or a long outage), not a count of lost frames
RTT_KEEP = 200


@dataclass
class TelemetryTrack:
    """What the sequence numbers of one node say. Loss is counted from sequence gaps, never from receipts
    (§3.1). The first telemetry seen (and the first after we lost our place) is only a baseline."""

    last: Telemetry | None = None
    last_seen: float | None = None   # laptop monotonic seconds of the last LIVE telemetry
    first_seen: float | None = None
    received: int = 0
    lost: int = 0
    late: int = 0
    reboots: int = 0
    gaps: int = 0
    window: deque[int] = field(default_factory=lambda: deque(maxlen=WINDOW))  # 1 received, 0 lost

    def rebaseline(self) -> None:
        """We lost our place in the event journal (CURSOR_GAP / EVENT_GAP): the next telemetry is a new baseline."""
        self.last = None

    def feed(self, t: Telemetry, now: float, live: bool = True) -> list[str]:
        """Takes one decoded telemetry; returns what happened: "reboot", "gap", "dup", "late". `live` False is a
        backlog event of an earlier session: it only sets the baseline."""
        out: list[str] = []
        prev = self.last
        if live:
            if self.first_seen is None:
                self.first_seen = now
            self.last_seen = now
        if prev is None:
            self.last = t
            if live:
                self.received += 1
                self.window.append(1)
            return out
        # boot_count (an NVS counter) is the truth; a restart that did not change it (NVS failed) is seen from a seq that
        # fell back by more than a message can be late.
        rebooted = t.boot_count != prev.boot_count or prev.seq - t.seq > LATE_MAX
        if rebooted:
            # A boot sends seq 1, 2, ...: the first one we see after a reboot says how many it sent before.
            missed = min(max(t.seq - 1, 0), MAX_GAP) if live else 0
            self.reboots += 1
            out.append("reboot")
            self._count(1, missed, live)
            self.last = t
            return out
        if t.seq == prev.seq:
            out.append("dup")
            return out
        if t.seq < prev.seq:  # an older one arriving late: it was counted as lost
            self.late += 1
            out.append("late")
            if live and self.lost > 0:
                self.lost -= 1
                self.received += 1
            return out
        missed = t.seq - prev.seq - 1
        if missed > MAX_GAP:
            missed = 0  # not a loss count we can trust: start over from here
            self.gaps += 1
            out.append("gap")
        elif missed:
            self.gaps += 1
            out.append("gap")
        self._count(1, missed if live else 0, live)
        self.last = t
        return out

    def _count(self, received: int, lost: int, live: bool) -> None:
        if not live:
            return
        self.received += received
        self.lost += lost
        for _ in range(min(lost, WINDOW)):
            self.window.append(0)
        self.window.append(1)

    @property
    def loss_pct(self) -> float | None:
        total = self.received + self.lost
        return None if total == 0 else 100.0 * self.lost / total

    @property
    def recent_loss_pct(self) -> float | None:
        return None if len(self.window) < 3 else 100.0 * self.window.count(0) / len(self.window)

    def age(self, now: float) -> float | None:
        return None if self.last_seen is None else max(0.0, now - self.last_seen)


@dataclass
class PingTrack:
    sent: int = 0        # requests the Host accepted (alive + noanswer + rejected + still open)
    alive: int = 0
    noanswer: int = 0
    rejected: int = 0
    notsent: int = 0     # refused / never left: counted apart, never RF loss
    last: PingResult | None = None
    last_round: int = 0
    rtts: deque[int] = field(default_factory=lambda: deque(maxlen=RTT_KEEP))
    history: deque[tuple[int, str]] = field(default_factory=lambda: deque(maxlen=20))  # (round, kind)

    def accepted(self) -> None:
        self.sent += 1

    def finish(self, round_no: int, result: PingResult) -> None:
        self.last, self.last_round = result, round_no
        self.history.append((round_no, result.kind))
        if result.kind == "notsent":
            self.notsent += 1
            if self.sent > 0:  # it had been counted as sent when the Host accepted it (it never left)
                self.sent -= 1
            return
        if result.kind == "alive":
            self.alive += 1
            if result.rtt_ms is not None:
                self.rtts.append(result.rtt_ms)
        elif result.kind == "noanswer":
            self.noanswer += 1
        elif result.kind == "rejected":
            self.rejected += 1

    def refused(self, round_no: int, result: PingResult) -> None:
        """The POST itself was refused: it was never accepted, so it was never counted as sent."""
        self.last, self.last_round = result, round_no
        self.history.append((round_no, result.kind))
        self.notsent += 1

    @property
    def loss_pct(self) -> float | None:
        answered = self.alive + self.noanswer + self.rejected
        return None if answered == 0 else 100.0 * self.noanswer / answered

    @property
    def rtt_median_ms(self) -> float | None:
        return median(list(self.rtts))

    def as_dict(self) -> dict[str, Any]:
        return {"sent": self.sent, "alive": self.alive, "noanswer": self.noanswer, "rejected": self.rejected,
                "notsent": self.notsent, "loss_pct": self.loss_pct, "rtt_median_ms": self.rtt_median_ms,
                "last": None if self.last is None else {"kind": self.last.kind, "detail": self.last.detail,
                                                        "rtt_ms": self.last.rtt_ms, "rtt_src": self.last.rtt_src,
                                                        "round": self.last_round},
                "history": [k for _, k in self.history]}
