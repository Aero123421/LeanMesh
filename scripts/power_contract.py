"""Executable specification helpers, NOT an ESP32 power manager or Mesh SDK.

Pure functions expose policy boundaries for independent implementation tests.
They make no claim about RF performance or measured energy.
"""
from __future__ import annotations

from collections import Counter
from math import ceil
from typing import Any, Mapping, Sequence
import json
from pathlib import Path
import struct

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
POLL = struct.Struct(">BBHQIIHHI")
GRANT = struct.Struct(">BBHQIHHI")
OUTCOMES = ("PENDING", "SUBMITTED", "RECEIVED", "APPLIED", "REJECTED",
            "EXPIRED", "CANCELLED_NOT_SENT", "INDETERMINATE", "SUPERSEDED")


def validate_policy(policy: Mapping[str, Any], role: str = "LEAF") -> None:
    """Check JSON shape and the cross-field constraints from chapter 20."""
    schema = json.loads((ROOT / "config/power.schema.json").read_text())
    Draft202012Validator(schema).validate(policy)
    if role not in {"LEAF", "RELAY", "ROOT"}:
        raise ValueError("unknown role")
    if int(policy["revision"]) > (1 << 63) - 1:
        raise ValueError("revision exceeds u63")
    mode = policy["mode"]
    if role != "LEAF" and mode != "ALWAYS_RX":
        raise ValueError("ROLE_NOT_ALLOWED")
    if policy["shutdown_reserve_ms"] >= policy["awake_budget_ms"]:
        raise ValueError("no usable awake budget")
    if policy["search_budget_ms"] > policy["awake_budget_ms"] - policy["shutdown_reserve_ms"]:
        raise ValueError("search exceeds episode budget")
    if policy["retry_min_ms"] > policy["retry_max_ms"]:
        raise ValueError("backoff bounds reversed")
    if policy["mailbox_frames_per_child"] > policy["mailbox_frames_total"]:
        raise ValueError("child mailbox exceeds total")
    if mode == "ALWAYS_RX":
        if any(policy[k] for k in ("wake_interval_ms", "rx_window_ms", "max_rx_window_ms")):
            raise ValueError("ALWAYS_RX has no periodic sleep window")
    else:
        if not 2 * policy["guard_ms"] < policy["rx_window_ms"] <= policy["max_rx_window_ms"]:
            raise ValueError("window cannot contain its guards")
        if policy["max_rx_window_ms"] > policy["awake_budget_ms"] - policy["shutdown_reserve_ms"]:
            raise ValueError("receive window exceeds awake budget")
        if mode == "WINDOWED_RX" and policy["wake_interval_ms"] <= policy["max_rx_window_ms"] + 2 * policy["guard_ms"]:
            raise ValueError("no sleep time remains")


def can_start_work(policy: Mapping[str, Any], elapsed_ms: int, estimated_job_ms: int) -> bool:
    if elapsed_ms < 0 or estimated_job_ms < 0:
        raise ValueError("negative duration")
    return elapsed_ms + estimated_job_ms + policy["shutdown_reserve_ms"] <= policy["awake_budget_ms"]


def required_guard_ms(elapsed_ms: int, local_ppm: int, peer_ppm: int,
                      timestamp_error_ms: int, wakeup_error_ms: int) -> int:
    args = (elapsed_ms, local_ppm, peer_ppm, timestamp_error_ms, wakeup_error_ms)
    if any(x < 0 for x in args):
        raise ValueError("negative uncertainty")
    return ceil(elapsed_ms * (local_ppm + peer_ppm) / 1_000_000) + timestamp_error_ms + wakeup_error_ms


def session_path(*, reset_cause: str, complete_ram_state: bool,
                 peer_session_valid: bool, elapsed_upper_ms: int | None,
                 authorization_remaining_ms: int, key_remaining_ms: int) -> str:
    """Decision model only. Does not resume keys or implement authentication."""
    if reset_cause not in {"LIGHT_WAKE", "MODEM_WINDOW"}:
        return "FRESH_EDHOC"
    if not complete_ram_state or not peer_session_valid or elapsed_upper_ms is None:
        return "FRESH_EDHOC"
    if elapsed_upper_ms < 0 or authorization_remaining_ms < 0 or key_remaining_ms < 0:
        raise ValueError("negative lifetime")
    if elapsed_upper_ms >= min(authorization_remaining_ms, key_remaining_ms):
        return "FRESH_EDHOC"
    return "RAM_REUSE"


def target_wait(*, now_ms: int, deadline_ms: int | None, next_wake_earliest_ms: int | None,
                awake: bool, previously_sent: bool, generation_matches: bool) -> str:
    if not generation_matches:
        return "REJECTED"
    if deadline_ms is not None and now_ms >= deadline_ms:
        return "INDETERMINATE" if previously_sent else "EXPIRED"
    if awake:
        return "READY"
    if deadline_ms is not None and next_wake_earliest_ms is not None and next_wake_earliest_ms >= deadline_ms:
        return "INDETERMINATE" if previously_sent else "DEADLINE_UNREACHABLE"
    return "WAIT_WAKE"


def group_counts(outcomes: Sequence[str]) -> dict[str, int]:
    if len(outcomes) > 64 or any(x not in OUTCOMES for x in outcomes):
        raise ValueError("invalid group target outcome")
    counts = Counter(outcomes)
    return {"total": len(outcomes), **{k: counts[k] for k in OUTCOMES}}


def validate_poll(raw: bytes) -> tuple[int, ...]:
    if len(raw) != POLL.size:
        raise ValueError("BAD_FRAME")
    fields = POLL.unpack(raw)
    subtype, version, _, nonce, _, interval, window, flags, reserved = fields
    if subtype != 1 or version != 1 or not nonce or not 1 <= window <= 65535:
        raise ValueError("BAD_FRAME")
    if interval > 86400000 or flags or reserved:
        raise ValueError("BAD_FRAME")
    return fields


def validate_grant(raw: bytes, poll: bytes) -> tuple[int, ...]:
    request = validate_poll(poll)
    if len(raw) != GRANT.size:
        raise ValueError("BAD_FRAME")
    fields = GRANT.unpack(raw)
    subtype, version, _, nonce, ttl, credit, reserved, _ = fields
    if subtype != 2 or version != 1 or nonce != request[3] or reserved:
        raise ValueError("BAD_FRAME")
    if not 1 <= ttl <= request[6] or credit > request[2]:
        raise ValueError("GRANT_EXCEEDS_REQUEST")
    return fields
