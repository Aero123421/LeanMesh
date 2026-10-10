"""Approved presence wire and browser evidence, exercised through the real recorder/engine."""
from __future__ import annotations

import asyncio
import base64
import json
import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.fieldview import protocol as pr  # noqa: E402
from tools.fieldview.engine import Config, FieldView  # noqa: E402
from tools.fieldview.hostclient import Reply  # noqa: E402
from tools.fieldview.recorder import Recorder  # noqa: E402

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)
DEV = "a1" * 32


def snapshot(**kw: int) -> bytes:
    v = dict(version=1, presence=2, learning=2, flags=7, boot=900, seq=1, uptime=10000,
             age=40, distance=2400, background=2400, noise=10, request=1, faults=0, press=0, result=0)
    v.update(kw)
    return struct.pack(">BBBBQIIHHHHIIIB3s", *v.values(), b"\0\0\0")


def press(boot: int = 900, seq: int = 1, uptime: int = 9000) -> bytes:
    return struct.pack(">BBHQII", 1, 3, 0, boot, seq, uptime)


def event(data: bytes, port: int = 214, device: str = DEV, receipt: datetime | None = NOW) -> dict:
    ev = dict(kind="MESSAGE_RECEIVED", origin=device, cursor="j:1", payload_b64=base64.b64encode(data).decode(),
              evidence={"kind": "ROOT_DELIVERED", "details": {"app_port": port}})
    if receipt is not None:
        ev["received_utc"] = receipt.isoformat()
    return ev


@pytest.fixture
def viewer(tmp_path: Path):
    now = [NOW]
    client = SimpleNamespace(bucket=SimpleNamespace(throttled=0), requests=0, rate_limited=0)
    rec = Recorder(tmp_path / "records")
    fv = FieldView(Config(socket="x", token="x", domain="ab" * 16), client, rec,
                   utcnow=lambda: now[0], clock=lambda: (now[0] - NOW).total_seconds())
    fv._on_nodes([dict(device_id=DEV, membership="ACTIVE", parent_device_id="ff" * 32)])
    yield fv, rec, now
    rec.close()


def state(fv: FieldView, device: str = DEV) -> dict:
    return fv.node_row(device)["presence"]


def test_exact_wire_offsets_and_unknown_sentinels():
    data = snapshot(boot=0xFEDCBA9876543210, seq=0x12345678, uptime=0x11223344, press=0x87654321, result=4)
    s = pr.decode_presence(data)
    assert (len(data), s.boot_id, s.seq, s.uptime_ms, s.last_k3_seq, s.k3_result) == (
        44, 0xFEDCBA9876543210, 0x12345678, 0x11223344, 0x87654321, 4)
    assert (s.distance_mm, s.background_mm, s.sample_age_ms, s.noise_mm) == (2400, 2400, 40, 10)
    s = pr.decode_presence(snapshot(presence=1, learning=0, flags=4, age=65535, distance=65535,
                                    background=65535, noise=0))
    assert (s.distance_mm, s.background_mm, s.sample_age_ms) == (None, None, None)
    p = pr.decode_k3(press(0xFEDCBA9876543210, 0x12345678, 0x11223344))
    assert (p.boot_id, p.seq, p.uptime_ms) == (0xFEDCBA9876543210, 0x12345678, 0x11223344)


@pytest.mark.parametrize("kw", [dict(version=0), dict(presence=4), dict(learning=5), dict(flags=8),
    dict(boot=0), dict(seq=0), dict(distance=99), dict(distance=4001), dict(background=99),
    dict(background=4001), dict(faults=8), dict(result=5), dict(background=65535, noise=1)])
def test_bad_snapshot_fields_never_change_state(viewer, kw):
    fv, rec, _ = viewer
    fv._on_event(event(snapshot(**kw)), False)
    assert state(fv)["state"] == "unknown"
    assert fv.snapshot()["host"]["bad_presence"] == 1
    assert rec.sync()
    line = json.loads((rec.directory / "presence.ndjson").read_text().splitlines()[0])
    assert line["error"] and line["payload_b64"]


@pytest.mark.parametrize("port,data", [(214, snapshot()[:-1]), (214, snapshot() + b"\0"),
    (214, snapshot()[:-1] + b"\1"), (215, press()[:-1]), (215, press() + b"\0"),
    (215, b"\2" + press()[1:]), (215, b"\1\1" + press()[2:]),
    (215, b"\1\3\0\1" + press()[4:]), (215, press(0)), (215, press(seq=0))])
def test_bad_lengths_reserved_and_k3_identity(viewer, port, data):
    fv, _, _ = viewer
    fv._on_event(event(data, port), False)
    assert fv.snapshot()["host"]["bad_presence" if port == 214 else "bad_k3"] == 1
    assert state(fv)["k3_count"] == 0


def test_presence_learning_tree_and_receipt_age(viewer):
    fv, _, now = viewer
    fv._on_event(event(snapshot(learning=1, request=12)), False)
    s = state(fv)
    assert (s["state"], s["learning"], s["learning_request"], s["sample_age_ms"]) == ("vacant", "running", 12, 40)
    assert fv.snapshot()["tree"]["root"]["children"][0]["presence"]["state"] == "vacant"
    now[0] += timedelta(seconds=9)
    fv._on_event(event(snapshot(seq=2, uptime=19000, presence=3, learning=2), receipt=now[0]), False)
    assert state(fv)["state"] == "occupied"
    now[0] += timedelta(seconds=31)
    assert state(fv)["state"] == "unknown" and state(fv)["stale"]


@pytest.mark.parametrize("kw", [dict(age=30001), dict(age=65535), dict(faults=1), dict(faults=2), dict(flags=4)])
def test_old_or_faulty_measurements_do_not_prove_vacant(viewer, kw):
    fv, _, _ = viewer
    fv._on_event(event(snapshot(**kw)), False)
    assert state(fv)["state"] == "unknown"


def test_disabled_unknown_and_stale_are_distinct(viewer):
    fv, _, now = viewer
    fv._on_event(event(snapshot(presence=0, learning=4, flags=4, distance=65535, background=65535, noise=0)), False)
    assert (state(fv)["state"], state(fv)["learning"], state(fv)["stale"]) == ("disabled", "no_sensor", False)
    fv._on_event(event(snapshot(seq=2, uptime=11000, presence=1)), False)
    assert state(fv)["state"] == "unknown" and not state(fv)["stale"]
    now[0] += timedelta(seconds=31)
    assert state(fv)["stale"]


@pytest.mark.parametrize("backlog,receipt", [(True, NOW), (False, NOW - timedelta(seconds=31)),
                                            (False, None), (False, NOW + timedelta(seconds=1))])
def test_history_missing_or_future_receipt_cannot_become_current(viewer, backlog, receipt):
    fv, _, _ = viewer
    fv._on_event(event(snapshot(), receipt=receipt), backlog)
    assert state(fv)["state"] == "unknown" and state(fv)["stale"]
    assert state(fv)["reported"] == "vacant"


def test_duplicates_old_sequence_and_uptime_do_not_refresh(viewer):
    fv, _, now = viewer
    fv._on_event(event(snapshot(seq=3)), False)
    now[0] += timedelta(seconds=31)
    for data in (snapshot(seq=3), snapshot(seq=2, presence=3), snapshot(seq=4, uptime=9999)):
        fv._on_event(event(data, receipt=now[0]), False)
    assert state(fv)["seq"] == 3 and state(fv)["state"] == "unknown"


def test_gap_and_reboot_invalidate_without_erasing_received_k3(viewer):
    fv, _, _ = viewer
    fv._on_event(event(snapshot()), False)
    fv._on_event(event(press(), 215), False)
    fv._on_event(dict(kind="EVENT_GAP"), False)
    assert state(fv)["state"] == "unknown" and state(fv)["k3_count"] == 1
    fv._on_event(event(snapshot(seq=2, uptime=11000)), False)
    assert state(fv)["state"] == "vacant"
    fv._on_event(event(pr.encode_telemetry(seq=1, uptime_s=11, boot_count=7), 210), False)
    fv._on_event(event(pr.encode_telemetry(seq=1, uptime_s=1, boot_count=8), 210), False)
    assert state(fv)["state"] == "unknown"
    # A random smaller ID is newer only with the uptime/UTC proof from the reboot telemetry.
    fv._on_event(event(snapshot(boot=5, uptime=1000)), False)
    assert state(fv)["boot_id"] == "0000000000000005" and state(fv)["stale"]
    fv._on_event(event(snapshot(boot=5, seq=2, uptime=2000)), False)
    assert state(fv)["state"] == "vacant"
    fv._on_event(event(snapshot(seq=99, uptime=99000, presence=3)), False)
    assert state(fv)["boot_id"] == "0000000000000005" and state(fv)["reported"] == "vacant"
    assert state(fv)["k3_count"] == 1


def test_unproved_boot_change_stays_unknown_and_cannot_flip_back(viewer):
    fv, _, _ = viewer
    fv._on_event(event(snapshot()), False)
    fv._on_event(event(snapshot(boot=999999, presence=3)), False)
    assert state(fv)["boot_id"] == "0000000000000384" and state(fv)["state"] == "unknown"
    fv._on_event(event(snapshot(seq=2, uptime=11000)), False)
    assert state(fv)["state"] == "unknown"


def test_k3_dedup_full_identity_history_and_node_result_separation(viewer):
    fv, rec, _ = viewer
    fv._on_event(event(press(), 215), True)
    fv._on_event(event(press(), 215), False)
    fv._on_event(event(press(seq=3), 215), False)
    fv._on_event(event(press(seq=2), 215), False)
    fv._on_event(event(press(seq=2), 215), False)
    fv._on_event(event(press(boot=5), 215), False)
    fv._on_event(event(press(), 215, device="a1" * 31 + "a2"), False)
    fv._on_event(event(snapshot(press=3, result=3)), False)
    s = state(fv)
    assert s["k3_count"] == 4 and s["k3_result"] == "not_sent"
    assert s["k3_last"]["received_utc"] == NOW.isoformat()
    assert s["k3_history"][0]["fresh"] is False
    assert len([x for x in fv.log if x["kind"] == "k3-received"]) == 5
    assert rec.sync()
    lines = [json.loads(x) for x in (rec.directory / "k3.ndjson").read_text().splitlines()]
    assert len(lines) == 7 and sum(x["disposition"] == "duplicate" for x in lines) == 2


def test_k3_backlog_is_history_without_fresh_alert(viewer):
    fv, _, _ = viewer
    fv._on_event(event(press(), 215), True)
    assert state(fv)["k3_count"] == 1 and not state(fv)["k3_last"]["fresh"]
    assert "履歴" in next(x["text"] for x in fv.log if x["kind"] == "k3-received")


def test_new_streams_are_fsynced_before_ack(viewer):
    fv, rec, _ = viewer
    fv._on_event(event(snapshot()), False)
    fv._on_event(event(press(), 215), False)
    calls = []
    async def ack(*args):
        for name in ("presence", "k3"):
            assert json.loads((rec.directory / f"{name}.ndjson").read_text().splitlines()[0])["cursor"] == "j:1"
        calls.append(args)
        return Reply(200, {})
    fv.client.ack = ack
    fv.cursor = "j:1"
    fv._add_segment(fv.cursor, set())
    asyncio.run(fv._ack(force=True))
    assert calls == [("fieldview", "j", 1)] and not fv.ack_pending


def test_device_and_press_memory_bounds(viewer):
    fv, _, _ = viewer
    for i in range(300):
        fv._on_event(event(press(), 215, device=f"{i:064x}"), False)
    fv._forget_stale_devices()
    assert len(fv.presence) <= 256
    for i in range(1, 1001):
        fv._on_event(event(press(seq=i), 215), False)
    assert len(state(fv)["k3_history"]) == 20
    count = state(fv)["k3_count"]
    fv._on_event(event(press(seq=1), 215), False)
    assert state(fv)["k3_count"] == count


def test_delayed_snapshot_capture_and_old_press_never_look_current(viewer):
    fv, _, now = viewer
    fv._on_event(event(snapshot()), False)
    now[0] += timedelta(seconds=31)
    # Newly observed and newly received, but capture uptime only advanced one second.
    fv._on_event(event(snapshot(seq=2, uptime=11000), receipt=now[0]), False)
    assert state(fv)["state"] == "unknown" and state(fv)["stale"]
    fv._on_event(event(press(uptime=12000), 215, receipt=now[0]), False)
    assert not state(fv)["k3_last"]["fresh"]


def test_k3_old_snapshot_cannot_authorize_a_fresh_alert(viewer):
    fv, _, now = viewer
    fv._on_event(event(snapshot()), False)
    now[0] += timedelta(seconds=31)
    fv._on_event(event(press(uptime=11000), 215, receipt=now[0]), False)
    assert not state(fv)["k3_last"]["fresh"]


def test_cursor_gap_also_invalidates_presence(viewer):
    fv, _, _ = viewer
    fv._on_event(event(snapshot()), False)
    fv.cursor = "j:1"
    asyncio.run(fv._cursor_gap(Reply(410, {"details": {"journal_id": "j", "oldest_cursor": "j:2"}})))
    assert state(fv)["stale"] and state(fv)["state"] == "unknown"


def test_boot_scope_overflow_is_explicit_and_never_counts_replays(viewer):
    fv, rec, _ = viewer
    for boot in range(1, 30):
        fv._on_event(event(press(boot=boot), 215), False)
    assert state(fv)["k3_count"] == 8 and state(fv)["limited"]
    fv._on_event(event(press(boot=1), 215), False)
    assert state(fv)["k3_count"] == 8
    assert rec.sync()
    lines = [json.loads(x) for x in (rec.directory / "k3.ndjson").read_text().splitlines()]
    assert len(lines) == 30 and sum(x["disposition"] == "boot_limit" for x in lines) == 21


def test_actual_fsync_failure_holds_ack_until_gap_is_durable(viewer, monkeypatch):
    fv, rec, _ = viewer
    fv._on_event(event(snapshot()), False)
    fv._on_event(event(press(), 215), False)
    calls = []
    async def ack(*args):
        calls.append(args)
        return Reply(200, {})
    fv.client.ack = ack
    fv.cursor = "j:1"
    fv._add_segment(fv.cursor, set())
    import tools.fieldview.recorder as recorder_mod
    fsync = recorder_mod.os.fsync
    def broken_fsync(fd):
        raise OSError("test disk failure")
    monkeypatch.setattr(recorder_mod.os, "fsync", broken_fsync)
    asyncio.run(fv._ack(force=True))
    assert not calls and fv.ack_pending
    monkeypatch.setattr(recorder_mod.os, "fsync", fsync)
    asyncio.run(fv._ack(force=True))
    assert calls and not fv.ack_pending
    assert any(json.loads(x).get("kind") == "recorder-gap"
               for x in (rec.directory / "events.ndjson").read_text().splitlines())


def test_recent_matching_k3_is_a_fresh_notification_and_expires(viewer):
    fv, _, now = viewer
    fv._on_event(event(snapshot()), False)
    now[0] += timedelta(seconds=1)
    fv._on_event(event(press(uptime=11000), 215, receipt=now[0]), False)
    assert state(fv)["k3_last"]["fresh"]
    assert "新着" in next(x["text"] for x in fv.log if x["kind"] == "k3-received")
    now[0] += timedelta(seconds=30)
    assert not state(fv)["k3_last"]["fresh"] and state(fv)["k3_count"] == 1


def test_old_receipt_cannot_replace_a_newer_snapshot_even_with_higher_seq(viewer):
    fv, _, now = viewer
    now[0] += timedelta(seconds=5)
    fv._on_event(event(snapshot(), receipt=now[0]), False)
    fv._on_event(event(snapshot(seq=2, presence=3), receipt=NOW), False)
    assert state(fv)["reported"] == "vacant" and state(fv)["seq"] == 1


@pytest.mark.parametrize("receipt", ["garbage", "2026-10-09T12:00:00", "2026-10-09T12:00:00+99:00"])
def test_bad_or_unzoned_utc_is_unknown_not_processing_time(viewer, receipt):
    fv, _, _ = viewer
    ev = event(snapshot())
    ev["received_utc"] = receipt
    fv._on_event(ev, False)
    assert state(fv)["received_utc"] is None and state(fv)["stale"]


def test_telemetry_reboot_with_failed_boot_counter_invalidates_current_presence(viewer):
    fv, _, now = viewer
    fv._on_event(event(pr.encode_telemetry(seq=50, uptime_s=100, boot_count=7), 210), False)
    fv._on_event(event(snapshot(uptime=100000)), False)
    assert state(fv)["state"] == "vacant"
    now[0] += timedelta(seconds=1)
    fv._on_event(event(pr.encode_telemetry(seq=1, uptime_s=1, boot_count=7), 210, receipt=now[0]), False)
    assert state(fv)["state"] == "unknown" and state(fv)["stale"]


def test_older_unknown_boot_backlog_does_not_invalidate_live_snapshot(viewer):
    fv, _, _ = viewer
    fv._on_event(event(snapshot()), False)
    fv._on_event(event(snapshot(boot=42, presence=3), receipt=NOW - timedelta(seconds=60)), True)
    assert state(fv)["reported"] == "vacant" and state(fv)["state"] == "vacant"


def test_newer_snapshot_with_reversed_host_utc_invalidates_current_without_rewriting_history(viewer):
    fv, _, _ = viewer
    fv._on_event(event(snapshot()), False)
    fv._on_event(event(snapshot(seq=2, uptime=11000, presence=3), receipt=NOW - timedelta(seconds=1)), False)
    assert state(fv)["reported"] == "vacant" and state(fv)["seq"] == 1
    assert state(fv)["state"] == "unknown" and state(fv)["stale"]
    fv._on_event(event(press(uptime=10000), 215), False)
    assert state(fv)["k3_count"] == 1 and not state(fv)["k3_last"]["fresh"]


def test_browser_clock_reversal_does_not_revive_occupancy_without_new_evidence(viewer):
    fv, _, now = viewer
    fv._on_event(event(snapshot()), False)
    fv._on_event(event(press(uptime=10000), 215), False)
    assert state(fv)["k3_last"]["fresh"]
    now[0] -= timedelta(seconds=1)
    assert state(fv)["state"] == "unknown" and state(fv)["stale"]
    now[0] += timedelta(seconds=2)
    assert state(fv)["state"] == "unknown" and state(fv)["stale"]
    assert not state(fv)["k3_last"]["fresh"]
    fv._on_event(event(snapshot(seq=2, uptime=11000), receipt=now[0]), False)
    assert state(fv)["state"] == "vacant" and not state(fv)["stale"]


def test_k3_reception_utc_before_current_boot_proof_is_history_not_a_fresh_alert(viewer):
    fv, _, _ = viewer
    fv._on_event(event(snapshot()), False)
    fv._on_event(event(press(uptime=10000), 215, receipt=NOW - timedelta(seconds=1)), False)
    assert state(fv)["k3_count"] == 1 and not state(fv)["k3_last"]["fresh"]


def test_sample_before_application_boot_is_unknown_and_cannot_authorize_k3(viewer):
    fv, rec, _ = viewer
    fv._on_event(event(snapshot(uptime=1000, age=5000)), False)
    row = state(fv)
    assert row["state"] == "unknown" and row["stale"]
    fv._on_event(event(press(uptime=1000), 215), False)
    assert state(fv)["k3_count"] == 1 and not state(fv)["k3_last"]["fresh"]
    assert rec.sync()  # the impossible report is retained for diagnosis, never current evidence
    assert (rec.directory / "presence.ndjson").exists()


def test_unknown_sample_age_at_startup_is_not_an_impossible_timestamp(viewer):
    fv, _, _ = viewer
    fv._on_event(event(snapshot(uptime=0, age=65535, presence=0, learning=4, flags=4,
                               distance=65535, background=65535, noise=0)), False)
    assert state(fv)["state"] == "disabled" and not state(fv)["stale"]


@pytest.mark.parametrize("old_uptime", [100, 1])
def test_startup_backlog_boot_then_live_new_boot_recovers_without_resurrection(viewer, old_uptime):
    fv, _, now = viewer
    old_receipt = NOW - timedelta(seconds=60)
    fv._on_event(event(pr.encode_telemetry(seq=10, uptime_s=old_uptime, boot_count=7), 210,
                       receipt=old_receipt), True)
    fv._on_event(event(snapshot(uptime=old_uptime * 1000), receipt=old_receipt), True)
    assert state(fv)["state"] == "unknown" and state(fv)["stale"]
    fv._on_event(event(pr.encode_telemetry(seq=1, uptime_s=2, boot_count=8), 210), False)
    fv._on_event(event(snapshot(boot=5, uptime=2000, presence=3)), False)
    assert state(fv)["boot_id"] == "0000000000000005" and state(fv)["stale"]
    now[0] += timedelta(seconds=1)
    fv._on_event(event(snapshot(boot=5, seq=2, uptime=3000, presence=3), receipt=now[0]), False)
    assert state(fv)["state"] == "occupied" and not state(fv)["stale"]
    # Late old data cannot flip the random ID back, even with higher sequence/new receipt UTC.
    fv._on_event(event(pr.encode_telemetry(seq=100, uptime_s=old_uptime + 1, boot_count=7), 210,
                       receipt=now[0]), False)
    fv._on_event(event(snapshot(seq=100, uptime=(old_uptime + 1) * 1000), receipt=now[0]), False)
    assert state(fv)["boot_id"] == "0000000000000005" and state(fv)["state"] == "occupied"


def test_backlog_telemetry_never_authorizes_current_boot(viewer):
    fv, _, _ = viewer
    fv._on_event(event(pr.encode_telemetry(seq=10, uptime_s=100, boot_count=7), 210), True)
    fv._on_event(event(snapshot(uptime=100000)), True)
    fv._on_event(event(pr.encode_telemetry(seq=1, uptime_s=2, boot_count=8), 210), True)
    fv._on_event(event(snapshot(boot=5, uptime=2000)), False)
    fv._on_event(event(snapshot(boot=5, seq=2, uptime=3000)), False)
    assert state(fv)["state"] == "unknown" and state(fv)["stale"]


def test_received_k3_from_previous_boot_never_becomes_fresh_again(viewer):
    fv, _, now = viewer
    fv._on_event(event(pr.encode_telemetry(seq=10, uptime_s=10, boot_count=7), 210), False)
    fv._on_event(event(snapshot()), False)
    fv._on_event(event(press(uptime=10000), 215), False)
    assert state(fv)["k3_last"]["fresh"]
    now[0] += timedelta(seconds=1)
    fv._on_event(event(pr.encode_telemetry(seq=1, uptime_s=1, boot_count=8), 210, receipt=now[0]), False)
    fv._on_event(event(snapshot(boot=5, uptime=1000), receipt=now[0]), False)
    assert not state(fv)["k3_last"]["fresh"]
    now[0] += timedelta(seconds=1)
    fv._on_event(event(snapshot(boot=5, seq=2, uptime=2000), receipt=now[0]), False)
    assert state(fv)["state"] == "vacant" and not state(fv)["stale"]
    assert state(fv)["k3_count"] == 1 and not state(fv)["k3_last"]["fresh"]


def test_delayed_press_expires_by_press_age_not_only_host_receipt_age(viewer):
    fv, _, now = viewer
    fv._on_event(event(snapshot(uptime=60000)), False)
    fv._on_event(event(press(uptime=31000), 215), False)  # already 29s old when Host receives it
    assert state(fv)["k3_last"]["fresh"]
    now[0] += timedelta(seconds=20)
    fv._on_event(event(snapshot(seq=2, uptime=80000), receipt=now[0]), False)
    assert state(fv)["state"] == "vacant" and not state(fv)["stale"]
    assert state(fv)["k3_count"] == 1 and not state(fv)["k3_last"]["fresh"]  # press age 49s, receipt age 20s


def test_gap_or_clock_ambiguity_never_reauthorizes_an_old_press(viewer):
    fv, _, now = viewer
    fv._on_event(event(snapshot()), False)
    fv._on_event(event(press(uptime=10000), 215), False)
    assert state(fv)["k3_last"]["fresh"]
    fv._on_event(dict(kind="EVENT_GAP"), False)
    assert not state(fv)["k3_last"]["fresh"]
    now[0] += timedelta(seconds=1)
    fv._on_event(event(snapshot(seq=2, uptime=11000), receipt=now[0]), False)
    assert state(fv)["state"] == "vacant" and not state(fv)["k3_last"]["fresh"]
    fv._on_event(event(press(seq=2, uptime=11000), 215, receipt=now[0]), False)
    assert state(fv)["k3_last"]["fresh"]
    now[0] -= timedelta(seconds=1)
    assert state(fv)["state"] == "unknown" and not state(fv)["k3_last"]["fresh"]
    now[0] += timedelta(seconds=2)
    fv._on_event(event(snapshot(seq=3, uptime=12000), receipt=now[0]), False)
    assert state(fv)["state"] == "vacant" and not state(fv)["k3_last"]["fresh"]


def test_failed_relearn_keeps_valid_background_evidence(viewer):
    fv, _, _ = viewer
    fv._on_event(event(snapshot(learning=3, faults=4)), False)
    assert state(fv)["state"] == "vacant" and state(fv)["learning"] == "failed"
