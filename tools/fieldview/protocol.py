"""The wire of the field test kit (docs/field/protocol.md §3) and the pure rules around it: telemetry decoding, the
bodies of Host requests, the classification of a ping from the Host's operation evidence. No I/O here."""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

TELEMETRY_PORT, PING_PORT, DISPLAY_PORT = 210, 211, 212
TELEMETRY_LEN = 44
# version role chip flags | seq uptime | boot reset depth rssi reserved | interval | tx rx rf busy heap display_seq
_TELEMETRY = struct.Struct(">BBBBIIHBBbBHIIIIII")
assert _TELEMETRY.size == TELEMETRY_LEN

ROLES = {1: "leaf", 2: "relay", 3: "display"}
CHIPS = {0: "other", 1: "esp32s3", 2: "esp32c3", 3: "esp32c6"}
ROLE_DISPLAY = 3
FLAG_DISPLAY_VALID, FLAG_DISPLAY_FORBID, FLAG_RENDER_FAULT = 1, 2, 4
U32_UNKNOWN = 0xFFFFFFFF


class TelemetryError(ValueError):
    pass


@dataclass(frozen=True)
class Telemetry:
    role: int
    chip: int
    flags: int
    seq: int
    uptime_s: int
    boot_count: int
    reset_reason: int | None
    depth: int | None
    parent_rssi_dbm: int | None
    interval_s: int
    tx_frames: int | None
    rx_frames: int | None
    rf_failures: int | None
    local_busy: int | None
    min_heap_bytes: int
    display_seq: int

    @property
    def role_name(self) -> str:
        return ROLES.get(self.role, f"role{self.role}")

    @property
    def chip_name(self) -> str:
        return CHIPS.get(self.chip, f"chip{self.chip}")

    @property
    def display_state(self) -> str | None:
        """USABLE / FORBID as the node reports it (flags bit0 valid, bit1 FORBID), None while it has none."""
        if not self.flags & FLAG_DISPLAY_VALID:
            return None
        return "FORBID" if self.flags & FLAG_DISPLAY_FORBID else "USABLE"

    @property
    def render_fault(self) -> bool:
        return bool(self.flags & FLAG_RENDER_FAULT)

    def as_dict(self) -> dict[str, Any]:
        return {"role": self.role_name, "chip": self.chip_name, "flags": self.flags, "seq": self.seq,
                "uptime_s": self.uptime_s, "boot_count": self.boot_count, "reset_reason": self.reset_reason,
                "depth": self.depth, "parent_rssi_dbm": self.parent_rssi_dbm, "interval_s": self.interval_s,
                "tx_frames": self.tx_frames, "rx_frames": self.rx_frames, "rf_failures": self.rf_failures,
                "local_busy": self.local_busy, "min_heap_bytes": self.min_heap_bytes,
                "display_seq": self.display_seq, "display_state": self.display_state,
                "render_fault": self.render_fault}


def decode_telemetry(data: bytes) -> Telemetry:
    """44 bytes big-endian (§3.1). An unknown version or another length is refused (the receiver ignores it)."""
    if len(data) != TELEMETRY_LEN:
        raise TelemetryError(f"telemetry is {len(data)} bytes, expected {TELEMETRY_LEN}")
    (version, role, chip, flags, seq, uptime, boot, reset, depth, rssi, _reserved, interval,
     tx, rx, rf, busy, heap, display_seq) = _TELEMETRY.unpack(data)
    if version != 1:
        raise TelemetryError(f"unknown telemetry version {version}")

    def counter(v: int) -> int | None:
        return None if v == U32_UNKNOWN else v

    return Telemetry(
        role=role, chip=chip, flags=flags, seq=seq, uptime_s=uptime, boot_count=boot,
        reset_reason=None if reset == 0xFF else reset, depth=None if depth == 0xFF else depth,
        parent_rssi_dbm=None if rssi == -128 else rssi, interval_s=interval, tx_frames=counter(tx),
        rx_frames=counter(rx), rf_failures=counter(rf), local_busy=counter(busy), min_heap_bytes=heap,
        display_seq=display_seq)


def encode_telemetry(*, role: int = 1, chip: int = 1, flags: int = 0, seq: int = 1, uptime_s: int = 0,
                     boot_count: int = 1, reset_reason: int = 0xFF, depth: int = 1, rssi: int = -60,
                     interval_s: int = 10, tx: int = 0, rx: int = 0, rf: int = 0, busy: int = 0,
                     heap: int = 100000, display_seq: int = 0) -> bytes:
    """The node's side of §3.1, for tests and the fake Host (raw values: 0xFF / -128 / 0xFFFFFFFF mean unknown)."""
    return _TELEMETRY.pack(1, role, chip, flags, seq, uptime_s, boot_count, reset_reason, depth, rssi, 0,
                           interval_s, tx, rx, rf, busy, heap, display_seq)


# ---- Host requests -----------------------------------------------------------------------------------------------

def ping_payload(round_no: int) -> bytes:
    return struct.pack(">BI", 1, round_no)


def display_payload(state: str, command_seq: int) -> bytes:
    if state not in ("USABLE", "FORBID"):
        raise ValueError("display state is USABLE or FORBID")
    return struct.pack(">BBI", 1, 1 if state == "FORBID" else 0, command_seq)


def utc_deadline(now: datetime, seconds: float) -> dict[str, str]:
    """A UTC deadline: the Host turns it into a root deadline with its bound of the root's clock (bridge._deadline),
    so the laptop needs no root term or root time. RFC 3339 with an explicit offset, millisecond resolution."""
    when = (now + timedelta(seconds=seconds)).astimezone(UTC)
    return {"mode": "utc", "expires_at": when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"}


def ping_deadline_s(interval_s: float) -> float:
    """§3.2: min(loop interval, 3 s); a ping is never kept."""
    return min(float(interval_s), 3.0)


def _message(domain: str, epoch: str, device: str, port: int, payload: bytes,
             deadline: dict[str, str]) -> dict[str, Any]:
    # §3.2 / §3.3 ask for queue_mode LATEST + coalesce_key, but the Host admits LATEST only for BEST_EFFORT + VOLATILE
    # (api/models.py; SEMANTICS 'Message': APPLIED is not LATEST) and refuses a coalesce_key with FIFO. An APPLIED
    # request is therefore FIFO without a key; the finite deadline is what keeps an old one from lingering.
    return {"domain_id": domain, "client_epoch": epoch, "destination": {"kind": "node", "device_id": device},
            "app_port": port, "payload_b64": base64.b64encode(payload).decode(), "delivery": "APPLIED",
            "storage": "VOLATILE", "queue_mode": "FIFO", "priority": "NORMAL", "deadline": deadline}


def ping_request(domain: str, epoch: str, device: str, round_no: int, interval_s: float,
                 now: datetime) -> dict[str, Any]:
    return _message(domain, epoch, device, PING_PORT, ping_payload(round_no),
                    utc_deadline(now, ping_deadline_s(interval_s)))


DISPLAY_DEADLINE_S = 10.0


def display_request(domain: str, epoch: str, device: str, state: str, command_seq: int,
                    now: datetime) -> dict[str, Any]:
    return _message(domain, epoch, device, DISPLAY_PORT, display_payload(state, command_seq),
                    utc_deadline(now, DISPLAY_DEADLINE_S))


# ---- operation evidence -----------------------------------------------------------------------------------------

def evidence_kinds(op: dict[str, Any]) -> set[str]:
    return {e.get("kind", "") for e in op.get("evidence", [])}


def _mono(op: dict[str, Any], *kinds: str) -> int | None:
    """observed_mono_ms (root clock, u63 string) of the first piece of evidence of one of `kinds`, in that order."""
    for kind in kinds:
        for e in op.get("evidence", []):
            if e.get("kind") == kind and e.get("observed_mono_ms") is not None:
                try:
                    return int(e["observed_mono_ms"])
                except (TypeError, ValueError):
                    return None
    return None


def rtt_from_evidence(op: dict[str, Any]) -> int | None:
    """§3.2: APP_APPLIED.observed_mono_ms - ROOT_SENT.observed_mono_ms, both on the root's clock; END_RECEIVED when
    APP_APPLIED has no time. None when the Host reports no time (the bridge does not fill observed_mono_ms yet)."""
    sent = _mono(op, "ROOT_SENT")
    end = _mono(op, "APP_APPLIED", "END_RECEIVED")
    if sent is None or end is None or end < sent:
        return None
    return end - sent


@dataclass(frozen=True)
class PingResult:
    kind: str  # alive | noanswer | rejected | notsent | unknown | skipped
    detail: str = ""
    rtt_ms: int | None = None
    rtt_src: str | None = None  # "root" (evidence on the root clock) or "laptop" (POST to the final event)


def classify_ping(op: dict[str, Any], laptop_rtt_ms: int | None = None) -> PingResult:
    """One finished ping operation -> alive / no answer / rejected by the node / not sent.

    alive      APPLIED (APP_APPLIED evidence): the node's application answered.
    rejected   the node answered, but REJECTED (APP_REJECTED / DESTINATION_REFUSED): reachable, so not RF loss.
    noanswer   it left the root (ROOT_SENT) and nothing came back before the deadline: EXPIRED / INDETERMINATE / ...
    notsent    it never left: the Host or the root refused or expired it (HOST_*, BUSY, NO_CAPACITY, TIME_UNCERTAIN ...),
               cancelled, superseded. Local, never RF loss."""
    outcome, kinds = op.get("outcome", ""), evidence_kinds(op)
    reason = str(op.get("reason", ""))
    if outcome == "APPLIED":
        rtt = rtt_from_evidence(op)
        if rtt is not None:
            return PingResult("alive", "", rtt, "root")
        return PingResult("alive", "", laptop_rtt_ms, "laptop" if laptop_rtt_ms is not None else None)
    if kinds & {"APP_REJECTED", "DESTINATION_REFUSED"}:
        return PingResult("rejected", reason or outcome)
    if outcome in ("CANCELLED_NOT_SENT", "SUPERSEDED"):
        return PingResult("notsent", outcome)
    if "ROOT_SENT" in kinds:
        return PingResult("noanswer", outcome if not reason else f"{outcome}: {reason}")
    if outcome == "INDETERMINATE":  # whether it left is unknown: that is no proof of "not sent"
        return PingResult("noanswer", f"INDETERMINATE: {reason}" if reason else "INDETERMINATE")
    if outcome == "REJECTED" or any(k.startswith("HOST_") for k in kinds):
        return PingResult("notsent", reason or outcome)
    return PingResult("notsent", f"{outcome} before leaving the root" + (f": {reason}" if reason else ""))


def classify_post_error(status: int | None, body: dict[str, Any] | None = None, exc: str = "") -> PingResult:
    """A POST /v1/messages that provably did not get admitted: the Host refused it (a 4xx / 429 / 5xx answer) or the
    request failed before it was sent (connect refused). Not sent, with the Host's code as the detail."""
    if status is None:
        return PingResult("notsent", f"could not reach the Host: {exc}"[:120])
    code = (body or {}).get("code", "")
    return PingResult("notsent", f"HTTP {status} {code}".strip())


def classify_post_unknown(exc: str) -> PingResult:
    """A POST /v1/messages whose answer never came (also on the replays with the same Idempotency-Key): the Host may
    have admitted it. Neither "sent and lost" nor "not sent"."""
    return PingResult("unknown", f"no answer to the POST (it may have been admitted): {exc}"[:160])


def event_payload(event: dict[str, Any]) -> bytes:
    return base64.b64decode(event.get("payload_b64", ""), validate=True)


def event_app_port(event: dict[str, Any]) -> int | None:
    """Where the app port of a MESSAGE_RECEIVED event is: evidence.details.app_port (bridge._store_message)."""
    port = ((event.get("evidence") or {}).get("details") or {}).get("app_port")
    return port if isinstance(port, int) else None


def median(values: list[int]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    mid = len(s) // 2
    return float(s[mid]) if len(s) % 2 else (s[mid - 1] + s[mid]) / 2
