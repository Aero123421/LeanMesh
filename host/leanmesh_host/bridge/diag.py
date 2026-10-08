"""Root diagnostics for GET /v1/diagnostics (serial method 16, S19/T19).

The root answers only what it knows: a value it cannot know is ABSENT from its map (never 0), and the three sources
stay separate: `driver` (what the platform reports), `sdk` (what the owner counts), `app` (the application's own view).
The Host adds the list of names that are unknown, so a reader sees "not measured" instead of a quiet zero. The Host
adds nothing else: no derived rates, no energy, and it asks the root only when a client asks (no background polling).
"""
from __future__ import annotations

from typing import Any

RESET_REASONS = ("UNKNOWN", "POWER_ON", "SOFTWARE", "PANIC", "WATCHDOG", "BROWNOUT", "DEEP_SLEEP_WAKE", "EXTERNAL")
RADIO_STATES = ("STOPPED", "RUNNING", "RECOVERING", "FAULTED", "ASLEEP")

# name -> True when the value is a u64 counter (a U63 decimal string in the API), False for a small integer.
DRIVER = {"reset_reason": False, "min_heap_bytes": False, "stack_free_bytes": False, "owner_cpu_us": True,
          "rx_ring_depth": False, "rx_ring_dropped": False, "tx_power_qdbm": False,
          "radio_recovery_uptime_ms": False, "radio_recovery_reason": False, "radio_recovery_status": False,
          "radio_recovery_attempts": False, "radio_recovery_tx": False, "radio_recovery_rx": False,
          "radio_recovery_previous_boot": False}
SDK = {"root_term": False, "channel_epoch": False, "current_channel": False, "pending_channel": False,
       "regular_peers": False, "transient_peers": False, "tx_depth": False, "radio_state": False,
       "tx_frames": True, "rx_frames": True, "link_retries": True, "rf_failures": True, "local_busy": True,
       "mac_unknown": True, "interval_us": True}
APP = {"events_pending": False, "events_lost": True, "ops_active": False, "ops_uncommitted": False,
       "ops_owed": False}


def _group(name: str, spec: dict[str, bool], raw: dict[str, Any], unknown: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, big in spec.items():
        if key not in raw:
            unknown.append(f"{name}.{key}")
        elif key == "reset_reason":
            out[key] = RESET_REASONS[raw[key]] if raw[key] < len(RESET_REASONS) else "UNKNOWN"
        elif key == "radio_state":
            out[key] = RADIO_STATES[raw[key]] if raw[key] < len(RADIO_STATES) else "UNKNOWN"
        else:
            out[key] = str(raw[key]) if big else int(raw[key])
    return out


def diagnostics(m: dict[str, Any]) -> dict[str, Any]:
    """The root's DIAGNOSTICS map -> the API `Diagnostics` object."""
    unknown: list[str] = []
    result = {"validity_bits": str(m["validity"]),
              "driver": _group("driver", DRIVER, m["driver"], unknown),
              "sdk": _group("sdk", SDK, m["sdk"], unknown),
              "app": _group("app", APP, m["app"], unknown),
              "features": []}
    for name, built, implemented, enabled, qualified, note in m["features"]:
        row: dict[str, Any] = {"name": name, "build": bool(built), "implemented": bool(implemented),
                               "enabled": bool(enabled), "qualified": bool(qualified)}
        if note is not None:
            row["note"] = note
        result["features"].append(row)
    result["unknown"] = unknown
    return result
