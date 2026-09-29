"""What the Host may say about the power STATE of a node (GET /v1/nodes/{id}/power).

The root only relays what a member reported before it slept (docs/20 section 4): the mode, the planned wake
interval and, for a timer, the earliest/latest next wake on the ROOT clock. That is a schedule, not an
observation. `SLEEPING` is therefore claimed only while the report is still in force; once the reported latest
wake has passed (or an untimed report is older than the schedule's maximum age) the node may be awake, and the
Host says `UNKNOWN` together with the age of the report. The root-minus-Host clock offset is stored with the report (`_root_offset_ms`) and the state is recomputed
whenever the report is read, so it ages without a new report. The offset is an upper bound of the root clock when
the root has one; when it has none (or the offset is missing) the report is aged from the moment the Host first
saw it, which can only under-estimate the age. Without any anchor nothing can be judged: `UNKNOWN`.
"""
from __future__ import annotations

from typing import Any

MAX_REPORT_AGE_MS = 86_400_000  # config/defaults.json power_limits.schedule_max_age_ms


def resolve(snap: dict[str, Any], host_now_ms: int) -> dict[str, Any]:
    """The snapshot as served: internal keys removed, `state` and `report_age_ms` evaluated at `host_now_ms`."""
    out = dict(snap)
    offset = out.pop("_root_offset_ms", None)
    reported = out.get("reported_root_ms")
    if reported is not None and offset is not None:
        now_hi = host_now_ms + int(offset)  # never earlier than the root clock
        age = max(0, now_hi - int(reported))
        out["report_age_ms"] = str(age)
        if out["mode"] == "ALWAYS_RX":
            out["state"] = "RUNNING"
        elif out.get("next_wake_quality", "UNKNOWN") != "UNKNOWN":
            out["state"] = "SLEEPING" if now_hi <= int(out["next_wake_latest_root_ms"]) else "UNKNOWN"
        else:
            out["state"] = "SLEEPING" if age <= MAX_REPORT_AGE_MS else "UNKNOWN"
    elif out["mode"] != "ALWAYS_RX":
        out["state"] = "UNKNOWN"  # no clock to age the report with
    return out
