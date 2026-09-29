"""Root-reported power state of a node (GET /v1/nodes/{id}/power): what the root's NODE_QUERY says the member reported.

A report is a schedule hint made by the member before it slept (docs/20 section 4): mode, its planned wake
interval and, when it named a timer, the earliest/latest next wake on the ROOT clock. It is not a live state and
carries no counters: fields the root never received (radio time, cpu time, energy) are absent, never zero, and the
validity bits say which ones are present. `state` is SLEEPING only because the last thing the member said was that
it was going to sleep; the Host has no wake fact.
"""
from __future__ import annotations

from typing import Any

EV_POWER = 9  # LM_EVENT_POWER
MODES = ("ALWAYS_RX", "WINDOWED_RX", "REPORT_ONLY")
QUALITY = ("UNKNOWN", "ESTIMATED", "BOUNDED")
VALID_NEXT_WAKE = 1 << 5  # power.hpp valid::next_wake


def snapshot(row: list[Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """(policy json, PowerSnapshot) for one entry [device, mode, quality, kind, policy_rev, interval_s, earliest_s, latest_s, reported_s]."""
    _, mode, quality, kind, revision, interval_s, earliest_s, latest_s, reported_s = row
    known = quality != 0
    snap: dict[str, Any] = {
        "mode": MODES[mode], "state": "RUNNING" if mode == 0 else "SLEEPING", "policy_revision": str(revision),
        "validity_bits": str(VALID_NEXT_WAKE if known else 0), "next_wake_quality": QUALITY[quality]}
    if known:
        snap["next_wake_earliest_root_ms"] = str(earliest_s * 1000)
        snap["next_wake_latest_root_ms"] = str(latest_s * 1000)
    return {"mode": MODES[mode], "planned_interval_ms": interval_s * 1000, "reported_root_ms": reported_s * 1000,
            "sleep_kind": "DEEP" if kind else "LIGHT"}, snap
