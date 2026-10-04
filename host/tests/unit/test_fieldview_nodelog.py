"""The node event log of docs/field/protocol.md §3.4 (app port 213) in tools/fieldview, without a Host: the wire, what a
node's records add up to (boots, the join / attach timeline of one boot, record loss), the lines they leave in
nodelog.ndjson / events.ndjson / summary.csv, and the bounds. The ack-after-disk rule and the real journal path are in
test_fieldview_fake_host.py."""

from __future__ import annotations

import base64
import csv
import json
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from tools.fieldview import engine as engine_mod  # noqa: E402
from tools.fieldview import nodelog as nl  # noqa: E402
from tools.fieldview import protocol as pr  # noqa: E402
from tools.fieldview.engine import Config, FieldView  # noqa: E402
from tools.fieldview.recorder import SUMMARY_COLUMNS, Recorder  # noqa: E402

DOMAIN = "d0" * 16
DEV = {c: c * 64 for c in "abcdef"}
NOW = datetime(2026, 10, 4, 12, 0, 0, 250_000, tzinfo=UTC)

BOOT_STALL = dict(reset_reason=2, sdk_restart_cause=1, boot_count=7, prev_uptime_ms=52_300, detail_ms=3012)


def rec(rtype: int, seq: int, t_ms: int, **payload: int) -> tuple[int, int, int, bytes]:
    return rtype, seq, t_ms, pr.nodelog_payload(rtype, **payload)


def boot(seq: int = 1, t_ms: int = 10, **kw: int) -> tuple[int, int, int, bytes]:
    return rec(pr.T_BOOT, seq, t_ms, **{**BOOT_STALL, **kw})


def bare(rtype: int, seq: int, t_ms: int) -> tuple[int, int, int, bytes]:
    return rtype, seq, t_ms, b""


def reachable(seq: int, t_ms: int, depth: int = 2, rssi: int = -61) -> tuple[int, int, int, bytes]:
    return rec(pr.T_REACHABLE, seq, t_ms, depth=depth, parent_rssi_dbm=rssi)


# ---- the wire --------------------------------------------------------------------------------------------------------

def test_a_boot_record_is_read_at_the_offsets_of_the_table() -> None:
    # written byte by byte, independent of the codec: reset_reason, sdk cause, boot_count, prev_uptime_ms, detail_ms
    payload = bytes([3, 1]) + (513).to_bytes(2, "big") + (86_400_000).to_bytes(4, "big") + (3012).to_bytes(4, "big")
    data = bytes([1, 1, 1, 12]) + (9).to_bytes(2, "big") + (40).to_bytes(4, "big") + payload
    [r] = pr.decode_nodelog(data)
    assert (r.type, r.name, r.seq, r.t_ms) == (1, "BOOT", 9, 40)
    assert r.fields == {"reset_reason": 3, "sdk_restart_cause": 1, "boot_count": 513, "prev_uptime_ms": 86_400_000,
                        "detail_ms": 3012}
    assert pr.encode_nodelog([(1, 9, 40, payload)]) == data


def test_the_first_ten_types_round_trip_with_their_named_fields() -> None:
    records = [
        boot(),
        bare(pr.T_MEMBER, 2, 1200),
        reachable(3, 8400, depth=2, rssi=-61),
        rec(pr.T_UNREACHABLE, 4, 20_000, connectivity_state=3, reason=9),
        bare(pr.T_TIME_VALID, 5, 21_000),
        rec(pr.T_JOIN_END, 6, 22_000, outcome=0x0100_0001, reason=0xFFFF_FFFE),
        rec(pr.T_RADIO, 7, 23_000, tx_done_max_ms=1350, tx_late=2, tx_stall_waits=1),
        rec(pr.T_DEPTH, 8, 24_000, depth=3, parent_rssi_dbm=-80),
        rec(pr.T_DISPLAY_FAULT, 9, 25_000, code=2),
        rec(pr.T_LOG_LOST, 10, 26_000, records_dropped=65_535),
    ]
    out = pr.decode_nodelog(pr.encode_nodelog(records[:5]))
    assert [r.name for r in out] == ["BOOT", "MEMBER", "REACHABLE", "UNREACHABLE", "TIME_VALID"]
    # at most 160 bytes a message: the other five in a second one
    out += pr.decode_nodelog(pr.encode_nodelog(records[5:]))
    assert [(r.type, r.seq, r.t_ms) for r in out] == [(r[0], r[1], r[2]) for r in records]
    by = {r.name: r.fields for r in out}
    assert by["BOOT"] == BOOT_STALL
    assert by["MEMBER"] == {} and by["TIME_VALID"] == {}
    assert by["REACHABLE"] == {"depth": 2, "parent_rssi_dbm": -61}
    assert by["UNREACHABLE"] == {"connectivity_state": 3, "reason": 9}
    assert by["JOIN_END"] == {"outcome": 0x0100_0001, "reason": 0xFFFF_FFFE}
    assert by["RADIO"] == {"tx_done_max_ms": 1350, "tx_late": 2, "tx_stall_waits": 1}
    assert by["DEPTH"] == {"depth": 3, "parent_rssi_dbm": -80}
    assert by["DISPLAY_FAULT"] == {"code": 2}
    assert by["LOG_LOST"] == {"records_dropped": 65_535}


def test_an_unknown_rssi_is_none_as_in_telemetry() -> None:
    [r] = pr.decode_nodelog(pr.encode_nodelog([reachable(1, 5, rssi=-128)]))
    assert r.fields == {"depth": 2, "parent_rssi_dbm": None}


def test_an_unknown_type_is_skipped_by_its_length_and_the_next_record_is_read() -> None:
    data = pr.encode_nodelog([boot(), (200, 2, 50, b"\x01\x02\x03\x04\x05"), (201, 3, 60, b""), bare(pr.T_MEMBER, 4, 70)])
    out = pr.decode_nodelog(data)
    assert [(r.type, r.name, r.known) for r in out] == [(1, "BOOT", True), (200, "type200", False), (201, "type201", False),
                                                        (2, "MEMBER", True)]
    assert out[1].fields is None and out[3].seq == 4


def test_a_known_type_with_a_longer_payload_is_read_as_a_prefix() -> None:
    [r] = pr.decode_nodelog(pr.encode_nodelog([(pr.T_DISPLAY_FAULT, 1, 5, b"\x02\xAA\xBB")]))
    assert r.fields == {"code": 2}


def good() -> bytes:
    return pr.encode_nodelog([boot(), bare(pr.T_MEMBER, 2, 100)])


MALFORMED = {
    "empty": b"",
    "header only half": b"\x01",
    "unknown version": b"\x02" + good()[1:],
    "version 0": b"\x00" + good()[1:],
    "count too big": bytes([1, 3]) + good()[2:],
    "record cut in its header": good()[:-3],
    "payload runs past the end": good()[:15],
    "known type, payload too short": pr.encode_nodelog([(pr.T_BOOT, 1, 5, b"\x00" * 11)]),
    "bytes left after count records": bytes([1, 1]) + good()[2:],
    "more than 160 bytes": pr.encode_nodelog([(200, i, i, b"\x00" * 10) for i in range(11)]),
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_a_malformed_message_is_refused_as_a_whole(name: str) -> None:
    with pytest.raises(pr.NodeLogError):
        pr.decode_nodelog(MALFORMED[name])


def test_exactly_160_bytes_is_still_a_message() -> None:
    records = [(200, i, i, b"\x00" * 11) for i in range(7)] + [(201, 9, 9, b"\x00" * 17)]   # 2 + 7 * 19 + 25 = 160
    data = pr.encode_nodelog(records)
    assert len(data) == 160 and len(pr.decode_nodelog(data)) == 8


def test_an_empty_message_has_no_records() -> None:
    assert pr.decode_nodelog(struct.pack(">BB", 1, 0)) == []


# ---- one node: boots, the timeline of a boot, record loss ------------------------------------------------------------

def feed(track: nl.NodeLogTrack, *records: tuple[int, int, int, bytes]) -> list[nl.Fed]:
    return [track.feed(r) for r in pr.decode_nodelog(pr.encode_nodelog(list(records)))]


def test_the_attach_timeline_belongs_to_the_current_boot_and_a_reboot_resets_it() -> None:
    t = nl.NodeLogTrack()
    feed(t, boot(1, 10, boot_count=7, sdk_restart_cause=0, detail_ms=0, prev_uptime_ms=0, reset_reason=1),
         bare(pr.T_MEMBER, 2, 1200), bare(pr.T_TIME_VALID, 3, 3000), reachable(4, 8400))
    assert (t.member_ms, t.time_valid_ms, t.reachable_ms, t.attach_s) == (1200, 3000, 8400, 8.4)
    assert (t.boots_seen, t.boot_count, t.reachable, t.depth, t.parent_rssi_dbm) == (1, 7, True, 2, -61)
    feed(t, reachable(5, 9000, depth=1, rssi=-55))              # a second REACHABLE: the first one stays the attach time
    assert t.attach_s == 8.4 and (t.depth, t.parent_rssi_dbm) == (1, -55)
    # the node restarts: seq starts over, the old timeline is gone and cannot be mistaken for the new boot
    feed(t, boot(1, 12, boot_count=8, sdk_restart_cause=0, detail_ms=0, reset_reason=4))
    assert (t.member_ms, t.time_valid_ms, t.reachable_ms, t.attach_s, t.reachable, t.depth) == (None,) * 6
    assert (t.boots_seen, t.boot_count, t.last_seq) == (2, 8, 1)
    assert t.as_dict()["attach_s"] is None and t.boot_cause == "watchdog"
    feed(t, bare(pr.T_MEMBER, 2, 900), reachable(3, 4100, depth=3, rssi=-70))
    assert (t.attach_s, t.member_ms) == (4.1, 900) and t.records_lost == 0


def test_sdk_restarts_and_the_cause_text() -> None:
    t = nl.NodeLogTrack()
    feed(t, boot(1, 10, **BOOT_STALL))
    assert t.sdk_restarts == 1
    assert t.boot_cause == "software; SDK: radio stall (TX completion never came)"
    feed(t, boot(1, 10, reset_reason=1, sdk_restart_cause=0, detail_ms=0, boot_count=8))
    assert (t.sdk_restarts, t.boots_seen, t.boot_cause) == (1, 2, "power on")
    feed(t, boot(1, 10, reset_reason=0xFF, sdk_restart_cause=0, detail_ms=0, boot_count=9))
    assert t.boot_cause == "unknown"


def test_sequence_gaps_count_lost_records_per_boot_and_a_late_one_takes_its_place_back() -> None:
    t = nl.NodeLogTrack()
    fed = feed(t, boot(5, 10), bare(pr.T_MEMBER, 6, 100))          # the first record seen is only a baseline
    assert t.records_lost == 0 and not any(f.missing for f in fed)
    fed = feed(t, bare(pr.T_TIME_VALID, 10, 200))                  # 7, 8, 9 missing
    assert (fed[0].missing, t.records_lost) == (3, 3)
    fed = feed(t, bare(pr.T_TIME_VALID, 8, 150))                   # one of them arrives late: it changes nothing else
    assert fed[0].late and t.records_lost == 2 and t.last_seq == 10 and t.time_valid_ms == 200
    fed = feed(t, bare(pr.T_TIME_VALID, 10, 200))                  # a duplicate is not a record that was missing
    assert fed[0].late and t.records_lost == 2 and t.late == 2
    # a new boot: its gap is its own, the count of the old boot stays
    before = t.records_lost
    feed(t, boot(1, 5, boot_count=9), bare(pr.T_MEMBER, 4, 100))   # 2, 3 missing
    assert t.records_lost == before + 2 and t.boots_seen == 2


def test_the_sequence_wraps_without_being_a_restart() -> None:
    t = nl.NodeLogTrack()
    feed(t, boot(65_534, 10), bare(pr.T_MEMBER, 65_535, 100))
    fed = feed(t, bare(pr.T_TIME_VALID, 0, 200), reachable(1, 300))
    assert [f.unseen_boot for f in fed] == [False, False] and t.records_lost == 0 and t.boots_unseen == 0
    assert t.member_ms == 100 and t.reachable_ms == 300


def test_a_restart_whose_boot_record_never_arrived_is_seen_and_not_mixed_into_the_old_boot() -> None:
    t = nl.NodeLogTrack()
    feed(t, boot(1, 10), bare(pr.T_MEMBER, 2, 100), reachable(3, 200), bare(pr.T_TIME_VALID, 40, 40_000))
    [fed] = feed(t, bare(pr.T_MEMBER, 3, 700))                     # seq fell back from 40 to 3, boot time from 40 s to 0.7 s
    assert fed.unseen_boot and not fed.late
    assert (t.boots_unseen, t.boot_count, t.reachable_ms, t.time_valid_ms, t.member_ms) == (1, None, None, None, 700)
    assert t.records_lost == 36                                    # the old boot's own gap 3 -> 40; the restart adds none


def test_a_huge_jump_is_not_a_count_of_lost_records() -> None:
    t = nl.NodeLogTrack()
    feed(t, boot(1, 10))
    [fed] = feed(t, bare(pr.T_MEMBER, 5000, 100))
    assert fed.jump and fed.missing == 0 and t.records_lost == 0


def test_totals_unreachable_radio_and_lost_log_records() -> None:
    t = nl.NodeLogTrack()
    feed(t, boot(1, 10), reachable(2, 5000),
         rec(pr.T_UNREACHABLE, 3, 9000, connectivity_state=3, reason=1), reachable(4, 12_000),
         rec(pr.T_UNREACHABLE, 5, 15_000, connectivity_state=2, reason=2),
         rec(pr.T_RADIO, 6, 16_000, tx_done_max_ms=900, tx_late=0, tx_stall_waits=0),
         rec(pr.T_RADIO, 7, 26_000, tx_done_max_ms=1350, tx_late=2, tx_stall_waits=1),
         rec(pr.T_LOG_LOST, 8, 27_000, records_dropped=4), rec(pr.T_LOG_LOST, 9, 28_000, records_dropped=3))
    d = t.as_dict()
    assert (t.unreachable, t.reachable, t.attach_s) == (2, False, 5.0)
    assert (d["tx_done_max_ms"], d["tx_late"], d["tx_stall_waits"], d["log_lost"]) == (1350, 2, 1, 7)
    assert t.records_lost == 0                                     # LOG_LOST is the node's count, not a sequence gap
    feed(t, boot(1, 10, boot_count=8))
    assert t.unreachable == 2 and t.as_dict()["tx_done_max_ms"] is None   # radio counters belong to a boot


def test_the_words_of_the_records() -> None:
    t = nl.NodeLogTrack()
    said = []
    for r in pr.decode_nodelog(pr.encode_nodelog([
            boot(1, 10), bare(pr.T_MEMBER, 2, 1_200), reachable(3, 8_400),
            rec(pr.T_UNREACHABLE, 4, 20_000, connectivity_state=3, reason=9),
            reachable(5, 31_000, depth=2, rssi=-128),
            rec(pr.T_DEPTH, 6, 32_000, depth=3, parent_rssi_dbm=-80),
            rec(pr.T_RADIO, 7, 33_000, tx_done_max_ms=900, tx_late=0, tx_stall_waits=0),
            rec(pr.T_RADIO, 8, 43_000, tx_done_max_ms=1350, tx_late=2, tx_stall_waits=0)])):
        said.append(nl.describe("display2", r, t.feed(r), t))
    assert said[0] == ("boot", "display2 booted: software restart by the SDK (radio stall, TX completion outstanding "
                               "3012 ms) after 52 s")
    assert said[1] == ("attach", "display2 became a member 1.2 s after boot")
    assert said[2] == ("attach", "display2 attached 8.4 s after boot (depth 2, -61 dBm)")
    assert said[3] == ("unreachable", "display2 unreachable (ISOLATED, reason 9) 20 s after boot")
    assert said[4] == ("attach", "display2 reachable again 31 s after boot (depth 2)")
    assert said[5] == ("depth", "display2 parent changed (depth 3, -80 dBm)")
    assert said[6] is None                                          # nothing late: no line
    assert said[7] == ("radio", "display2 radio: longest TX completion 1350 ms, 2 late")


def test_a_radio_fault_record_round_trips_and_says_how_the_app_recovered() -> None:
    t = nl.NodeLogTrack()
    out = pr.decode_nodelog(pr.encode_nodelog([
        boot(1, 10), rec(pr.T_RADIO_FAULT, 2, 95_000, reason=0x0000_0010, restart_status=0),
        rec(pr.T_RADIO_FAULT, 3, 140_000, reason=0x0000_0010, restart_status=7)]))
    assert out[1].name == "RADIO_FAULT" and out[1].fields == {"reason": 16, "restart_status": 0}
    said = [nl.describe("relay-c6a", r, t.feed(r), t) for r in out]
    assert said[1] == ("radio", "relay-c6a radio fault (reason 16) 95 s after boot: SDK restarted")
    assert said[2] == ("radio", "relay-c6a radio fault (reason 16) 140 s after boot: SDK restart failed (status 7), "
                                "rebooted")


def test_boot_texts_for_the_plain_reset_reasons() -> None:
    plain = dict(sdk_restart_cause=0, detail_ms=0, boot_count=1)
    assert nl.boot_text(dict(reset_reason=1, prev_uptime_ms=0, **plain)) == "booted: power on"
    assert nl.boot_text(dict(reset_reason=3, prev_uptime_ms=125_000, **plain)) == "booted: panic restart after 125 s"
    assert nl.boot_text(dict(reset_reason=0xFF, prev_uptime_ms=0, **plain)) == "booted: unknown reset reason"
    assert nl.boot_text(dict(reset_reason=2, sdk_restart_cause=7, detail_ms=0, boot_count=1, prev_uptime_ms=4_000)) == \
        "booted: restart by the SDK (cause 7) after 4.0 s"


# ---- the engine: records, event log, rows, summary, bounds -----------------------------------------------------------

def make_engine(tmp_path: Path, clock: list[float], **cfg: object) -> tuple[FieldView, Recorder]:
    rec_ = Recorder(tmp_path / "rec")
    config = Config(socket="x", token="t", domain=DOMAIN, names={DEV["a"]: "relay-1", DEV["b"]: "display-2"},
                    root_id="ff" * 32, **cfg)  # type: ignore[arg-type]
    client = SimpleNamespace(bucket=SimpleNamespace(throttled=0), requests=0, rate_limited=0)
    return FieldView(config, client, rec_, clock=lambda: clock[0], utcnow=lambda: NOW), rec_  # type: ignore[arg-type]


def event(device: str, payload: bytes, n: int, port: int = pr.NODELOG_PORT) -> dict:
    return {"cursor": f"j:{n}", "kind": "MESSAGE_RECEIVED", "origin": device, "message_id": "00" * 16,
            "payload_b64": base64.b64encode(payload).decode(),
            "evidence": {"kind": "ROOT_DELIVERED", "details": {"app_port": port, "recovered": False}}}


def ndjson(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines()]


def test_records_become_nodelog_lines_events_row_and_summary(tmp_path: Path) -> None:
    clock = [100.0]
    fv, rec_ = make_engine(tmp_path, clock)
    fv._on_nodes([{"device_id": DEV["b"], "membership": "ACTIVE", "connectivity": "REACHABLE",
                   "parent_device_id": "ff" * 32, "root_depth": 1}])
    fv._on_event(event(DEV["b"], pr.encode_nodelog([
        boot(1, 10), bare(pr.T_MEMBER, 2, 1_200), reachable(3, 8_400, depth=1, rssi=-52),
        bare(pr.T_TIME_VALID, 4, 9_000)]), 1), backlog=False)
    fv._on_event(event(DEV["b"], pr.encode_nodelog([
        rec(pr.T_RADIO, 7, 20_000, tx_done_max_ms=1350, tx_late=2, tx_stall_waits=0),  # 5, 6 never arrived
        rec(pr.T_UNREACHABLE, 8, 21_000, connectivity_state=3, reason=4), (222, 9, 22_000, b"xyz")]), 2), backlog=False)
    assert fv.other_messages == 0 and fv.bad_nodelog == 0
    texts = [(e["kind"], e["text"]) for e in fv.log if e.get("device") == DEV["b"]]
    assert ("boot", "display-2 booted: software restart by the SDK (radio stall, TX completion outstanding 3012 ms) "
                    "after 52 s") in texts
    assert ("attach", "display-2 attached 8.4 s after boot (depth 1, -52 dBm)") in texts
    assert ("nodelog", "display-2: node log record(s) missing before seq 7 (2)") in texts
    assert ("radio", "display-2 radio: longest TX completion 1350 ms, 2 late") in texts
    assert ("unreachable", "display-2 unreachable (ISOLATED, reason 4) 21 s after boot") in texts
    assert not any("type222" in x[1] or "TIME_VALID" in x[1] for x in texts)      # an unknown type has no words
    row = {r["name"]: r for r in fv.snapshot()["nodes"]}["display-2"]
    assert row["boot_cause"] == "software; SDK: radio stall (TX completion never came)"
    assert (row["attach_s"], row["tx_done_max_ms"], row["tx_late"], row["unreachable"], row["records_lost"]) == (
        8.4, 1350, 2, 1, 2)
    assert (row["boots_logged"], row["sdk_restarts"], row["time_valid_s"]) == (1, 1, 9.0)
    json.dumps(fv.snapshot())                                                    # the page's JSON stays serialisable
    rec_.summary(fv.summary_rows())
    rec_.close()
    lines = ndjson(tmp_path / "rec" / "nodelog.ndjson")
    assert len(lines) == 7                                                       # every record, the unknown one too
    assert all(x["t"].endswith("Z") and x["device"] == DEV["b"] and x["name"] == "display-2" for x in lines)
    first, radio, unknown = lines[0], lines[4], lines[6]
    assert (first["type"], first["seq"], first["t_ms"], first["boot_count"], first["backlog"]) == ("BOOT", 1, 10, 7, False)
    assert first["fields"] == BOOT_STALL and first["new_boot"] is True
    assert (radio["type"], radio["boot_count"], radio["missing_before"]) == ("RADIO", 7, 2)
    assert radio["fields"] == {"tx_done_max_ms": 1350, "tx_late": 2, "tx_stall_waits": 0}
    assert (unknown["type"], unknown["type_id"], unknown["fields"]) == ("type222", 222, None)
    events = [x for x in ndjson(tmp_path / "rec" / "events.ndjson") if x["kind"] == "boot"]
    assert events and events[0]["name"] == "display-2" and events[0]["device"] == DEV["b"]
    summary = list(csv.DictReader((tmp_path / "rec" / "summary.csv").read_text().splitlines()))
    assert SUMMARY_COLUMNS[-4:] == ("attach_s", "boots", "sdk_restarts", "tx_done_max_ms")
    s = {r["name"]: r for r in summary}["display-2"]
    assert (s["attach_s"], s["boots"], s["sdk_restarts"], s["tx_done_max_ms"]) == ("8.4", "1", "1", "1350")


def test_a_node_without_a_log_has_empty_columns_not_zeros(tmp_path: Path) -> None:
    fv, rec_ = make_engine(tmp_path, [0.0])
    fv._on_nodes([{"device_id": DEV["a"], "membership": "ACTIVE", "connectivity": "REACHABLE", "root_depth": 1}])
    s = fv.summary_rows()[0]
    assert (s["attach_s"], s["boots"], s["sdk_restarts"], s["tx_done_max_ms"]) == (None, None, None, None)
    row = fv.snapshot()["nodes"][0]
    assert (row["boot_cause"], row["attach_s"], row["tx_done_max_ms"]) == (None, None, None)
    rec_.close()


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_a_malformed_message_is_counted_recorded_and_never_crashes_the_engine(tmp_path: Path, name: str) -> None:
    fv, rec_ = make_engine(tmp_path, [0.0])
    fv._on_event(event(DEV["a"], MALFORMED[name], 1), backlog=False)
    fv._on_event(event(DEV["a"], pr.encode_nodelog([boot()]), 2), backlog=False)       # the next message is read normally
    assert fv.bad_nodelog == 1 and fv.nodelog[DEV["a"]].boots_seen == 1
    assert fv.snapshot()["host"]["bad_nodelog"] == 1
    assert any(e["kind"] == "nodelog" and "unreadable node log" in e["text"] for e in fv.log)
    rec_.close()
    lines = ndjson(tmp_path / "rec" / "nodelog.ndjson")
    assert lines[0]["type"] == "BAD_MESSAGE" and lines[0]["error"] and lines[1]["type"] == "BOOT"


def test_a_message_that_is_not_base64_is_bad_not_a_crash(tmp_path: Path) -> None:
    fv, rec_ = make_engine(tmp_path, [0.0])
    ev = event(DEV["a"], b"", 1)
    ev["payload_b64"] = "!!not base64!!"
    fv._on_event(ev, backlog=False)
    assert fv.bad_nodelog == 1
    rec_.close()


def test_a_backlog_message_updates_the_node_but_says_nothing_in_the_event_log(tmp_path: Path) -> None:
    fv, rec_ = make_engine(tmp_path, [0.0])
    fv._on_event(event(DEV["a"], pr.encode_nodelog([boot(), reachable(2, 6_000)]), 1), backlog=True)
    assert fv.nodelog[DEV["a"]].attach_s == 6.0 and fv.nodelog[DEV["a"]].boots_seen == 1
    assert not [e for e in fv.log if e["kind"] in ("boot", "attach")]
    rec_.close()
    assert all(x["backlog"] is True for x in ndjson(tmp_path / "rec" / "nodelog.ndjson"))


def test_a_port_213_message_is_not_telemetry_and_telemetry_is_not_a_node_log(tmp_path: Path) -> None:
    fv, rec_ = make_engine(tmp_path, [0.0])
    fv._on_event(event(DEV["a"], pr.encode_telemetry(seq=1), 1, port=210), backlog=False)
    fv._on_event(event(DEV["a"], pr.encode_nodelog([boot()]), 2), backlog=False)
    assert (fv.tele[DEV["a"]].received, fv.bad_telemetry, fv.bad_nodelog, fv.other_messages) == (1, 0, 0, 0)
    fv._on_event(event(DEV["a"], pr.encode_nodelog([boot()]), 3, port=210), backlog=False)   # a log on the telemetry port
    assert fv.bad_telemetry == 1
    rec_.close()


def test_the_per_node_state_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "DEVICES_MAX", 5)
    fv, rec_ = make_engine(tmp_path, [0.0])
    for i in range(40):                                  # 40 nodes that the root does not list any more
        fv._on_event(event(f"{i:064x}", pr.encode_nodelog([boot(), reachable(2, 100)]), i), backlog=False)
    assert len(fv.nodelog) == 40
    fv._forget_stale_devices()
    assert len(fv.nodelog) <= 5
    # what one node keeps does not grow with its records: a flood of records changes numbers, not the size of the state
    one = DEV["a"]
    fv._on_event(event(one, pr.encode_nodelog([boot()]), 100), backlog=False)
    size = len(vars(fv.nodelog[one]))
    for n in range(300):
        fv._on_event(event(one, pr.encode_nodelog([rec(pr.T_RADIO, 2 + n, 100 + n, tx_done_max_ms=n, tx_late=n,
                                                       tx_stall_waits=0)]), 200 + n), backlog=False)
    assert len(vars(fv.nodelog[one])) == size
    assert len(fv.log) <= engine_mod.EVENT_LOG_KEEP
    rec_.close()
