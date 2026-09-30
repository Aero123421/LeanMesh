"""FIX3-19: the Host does not call a node SLEEPING for ever because its last report said it would sleep."""

from __future__ import annotations

from leanmesh_host.bridge import power as power_status
from leanmesh_host.power_state import MAX_REPORT_AGE_MS, resolve

DEV = b"\x11" * 32


def _row(mode: int, quality: int, earliest_s: int = 100, latest_s: int = 110, reported_s: int = 40) -> list:
    return [DEV, mode, quality, 0, 2, 60, earliest_s, latest_s, reported_s]


def _serve(row: list, root_now_ms: int, host_now_ms: int = 1_000_000) -> dict:
    """Stored at host_now with the root clock at root_now, served at host_now."""
    _, snap = power_status.snapshot(row, root_now_ms - host_now_ms)
    return resolve(snap, host_now_ms)


def test_a_timed_report_is_sleeping_only_until_the_reported_wake_has_passed() -> None:
    row = _row(2, 2)  # REPORT_ONLY, BOUNDED, wake between 100 s and 110 s of the root clock
    inside = _serve(row, 60_000)
    assert inside["state"] == "SLEEPING" and inside["reported_root_ms"] == "40000" and inside["report_age_ms"] == "20000"
    assert "_root_offset_ms" not in inside
    late = _serve(row, 110_001)
    assert late["state"] == "UNKNOWN" and late["report_age_ms"] == "70001"  # the reported wake is over: it may be awake
    assert late["mode"] == "REPORT_ONLY" and late["next_wake_quality"] == "BOUNDED"


def test_an_untimed_report_ages_out_and_no_clock_means_unknown() -> None:
    row = _row(2, 0)  # sleeps until an external event: no wake bound
    assert _serve(row, 40_000 + MAX_REPORT_AGE_MS)["state"] == "SLEEPING"
    assert _serve(row, 40_001 + MAX_REPORT_AGE_MS)["state"] == "UNKNOWN"
    _, snap = power_status.snapshot(row, None)
    unknown = resolve(snap, 1_000_000)
    assert unknown["state"] == "UNKNOWN" and "report_age_ms" not in unknown


def test_an_always_rx_report_is_running_and_the_state_moves_without_a_new_report() -> None:
    assert _serve(_row(0, 0), 999_000_000)["state"] == "RUNNING"
    _, snap = power_status.snapshot(_row(2, 2), 0)
    assert resolve(snap, 60_000)["state"] == "SLEEPING"
    assert resolve(snap, 200_000)["state"] == "UNKNOWN"  # the same stored report, read later


def test_without_a_root_clock_the_report_is_aged_from_when_the_host_first_saw_it(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import sqlite3
    from pathlib import Path

    from leanmesh_host import storage
    from leanmesh_host.db import mirror

    conn = sqlite3.connect(":memory:")
    conn.isolation_level = None
    storage._apply_schema(conn, (Path(__file__).resolve().parents[3] / "db" / "schema.sql").read_text())
    domain = b"\x22" * 16
    mirror.register_domain(conn, domain, None)
    clock = {"now": 5_000_000}
    monkeypatch.setattr(mirror, "now_ms", lambda: clock["now"])
    policy, snap = power_status.snapshot(_row(2, 2), None)  # reported at root 40 s, wake 100..110 s
    mirror.put_power(conn, domain, DEV, policy, snap)
    assert mirror.get_power(conn, domain, DEV)["state"] == "SLEEPING"
    clock["now"] += 60_000  # seen again, same report: the anchor is kept, 60 s later it still is in force
    _, again = power_status.snapshot(_row(2, 2), None)
    mirror.put_power(conn, domain, DEV, policy, again)
    served = mirror.get_power(conn, domain, DEV)
    assert served["state"] == "SLEEPING" and served["report_age_ms"] == "60000"
    clock["now"] += 60_000  # 120 s after the Host first saw it: the reported wake (110 s of root clock) is over
    assert mirror.get_power(conn, domain, DEV)["state"] == "UNKNOWN"


# ---- FIX7-D9 / D11 ----------------------------------------------------------------------------------------------------
def _db():  # type: ignore[no-untyped-def]
    import sqlite3
    from pathlib import Path

    from leanmesh_host import storage
    from leanmesh_host.db import mirror

    conn = sqlite3.connect(":memory:")
    conn.isolation_level = None
    storage._apply_schema(conn, (Path(__file__).resolve().parents[3] / "db" / "schema.sql").read_text())
    domain = b"\x22" * 16
    mirror.register_domain(conn, domain, None)
    return conn, domain


def _nodes(conn, domain, *devices):  # type: ignore[no-untyped-def]
    from leanmesh_host.db import mirror
    for d in devices:
        mirror.upsert_node(conn, domain, d, assignment_generation=1, membership_generation=1, membership="ACTIVE",
                           connectivity="UNKNOWN", confirmed=True)


def test_a_full_node_query_absence_and_a_root_restart_make_stored_power_unknown(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from leanmesh_host.db import mirror

    conn, domain = _db()
    other = b"\x33" * 32
    _nodes(conn, domain, DEV, other)
    monkeypatch.setattr(mirror, "now_ms", lambda: 1_000_000)
    rows = [(d, *power_status.snapshot([d, 2, 2, 0, 2, 60, 100, 110, 40], -940_000)) for d in (DEV, other)]
    mirror.sync_power(conn, domain, rows, boot=5, term=1)
    assert mirror.get_power(conn, domain, DEV)["state"] == "SLEEPING"
    # the next complete query lists only DEV: the other node's old report is stale, never SLEEPING
    mirror.sync_power(conn, domain, rows[:1], boot=5, term=1)
    assert mirror.get_power(conn, domain, other)["state"] == "UNKNOWN"
    assert mirror.get_power(conn, domain, DEV)["state"] == "SLEEPING"
    # a root restart (new boot) whose query lists nobody: nothing of the old term survives as SLEEPING
    mirror.sync_power(conn, domain, [], boot=6, term=2)
    assert mirror.get_power(conn, domain, DEV)["state"] == "UNKNOWN"
    # without a root clock the anchor of the old boot is not reused for the same reported value
    def nodev():  # type: ignore[no-untyped-def]
        return [(DEV, *power_status.snapshot([DEV, 2, 2, 0, 2, 60, 100, 110, 40], None))]

    mirror.sync_power(conn, domain, nodev(), boot=6, term=2)
    monkeypatch.setattr(mirror, "now_ms", lambda: 1_100_000)
    mirror.sync_power(conn, domain, nodev(), boot=7, term=3)  # another boot: the age restarts at the Host's first sight
    assert mirror.get_power(conn, domain, DEV)["report_age_ms"] == "0"
    # the last observed root metadata is persisted
    assert conn.execute("SELECT value FROM meta WHERE key=?", (f"powerroot:{domain.hex()}",)).fetchone()[0] == b"7:3"


def test_a_host_clock_that_moved_backwards_never_revives_a_sleeping_report(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from leanmesh_host.db import mirror

    conn, domain = _db()
    _nodes(conn, domain, DEV)
    monkeypatch.setattr(mirror, "now_ms", lambda: 5_000_000)
    mirror.sync_power(conn, domain, [(DEV, *power_status.snapshot(_row(2, 2), -4_940_000))], boot=1, term=1)
    monkeypatch.setattr(mirror, "now_ms", lambda: 4_000_000)  # wall time stepped back (e.g. after a restart)
    assert mirror.get_power(conn, domain, DEV)["state"] == "UNKNOWN"


def test_the_power_clock_is_monotonic_against_wall_steps(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import time

    from leanmesh_host import power_state

    a = power_state.now_ms()
    monkeypatch.setattr(time, "time", lambda: 0.0)  # a wall-clock step does not reach it
    assert power_state.now_ms() >= a
