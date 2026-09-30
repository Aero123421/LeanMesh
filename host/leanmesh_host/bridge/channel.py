"""Channel state as the root reports it (S17). The root's coordinator is the only issuer of channel plans; the Host
mirrors what it reports in NODE_QUERY (`channel`) and asks again on every LM_EVENT_CHANNEL. Nothing is guessed: no
report yet is 503 ROOT_UNAVAILABLE (mirror.get_channel). The sets are by short address at the root and become
device ids here through the same NODE_QUERY answer; an address the root's ledger does not list is left out
(the root itself is never a member of its own sets)."""

from __future__ import annotations

from typing import Any

EV_CHANNEL = 6
# root::CState order
STATES = ("MONITOR", "SURVEY", "PREPARING", "COMMITTED", "SWITCHING", "SETTLING", "ABORTED", "RECOVERING")


def status(report: dict[str, Any], devices: dict[int, bytes]) -> dict[str, Any]:
    """`report` = the `channel` map of NODE_QUERY, `devices` = short address -> DeviceId of the same answer.
    STORED (not a field of the API) is what `required` minus `unreachable` means once RECOVERING; APPLIED is the
    root's own count of members that told it they are on the new channel."""

    def ids(addresses: list[int]) -> list[str]:
        return [devices[a].hex() for a in addresses if a in devices]

    out: dict[str, Any] = {
        "current_channel": int(report["current"]),
        "channel_epoch": int(report["epoch"]),
        "state": STATES[int(report["state"])] if 0 <= int(report["state"]) < len(STATES) else "UNKNOWN",
        "required": ids(report["required"]),
        "applied": ids(report["applied"]),
        "unreachable": ids(report["unreachable"]),
    }
    if any(report["plan_id"]):
        out["plan_id"] = bytes(report["plan_id"]).hex()
    return out
