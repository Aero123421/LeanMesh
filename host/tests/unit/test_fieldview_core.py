"""tools/fieldview without a Host: the telemetry layout of docs/field/protocol.md §3.1, loss from sequence numbers, the
classification of a ping from operation evidence, the exact request bodies (also against the real Host admission model),
the tree with and without parent fields, the records."""

from __future__ import annotations

import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from leanmesh_host.api.models import MessageRequest

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from tools.fieldview import protocol as pr  # noqa: E402
from tools.fieldview import topology as topo  # noqa: E402
from tools.fieldview.engine import Config, FieldView, load_bench, ping_load  # noqa: E402
from tools.fieldview.hostclient import RateBucket  # noqa: E402
from tools.fieldview.recorder import SUMMARY_COLUMNS, Recorder  # noqa: E402
from tools.fieldview.stats import PingTrack, TelemetryTrack  # noqa: E402

DOMAIN, EPOCH = "d0" * 16, "e1" * 16
DEV = {c: c * 64 for c in "abcdef"}
NOW = datetime(2026, 10, 4, 12, 0, 0, 250_000, tzinfo=UTC)


# ---- telemetry (§3.1) ---------------------------------------------------------------------------------------------

def raw_telemetry() -> bytes:
    """44 bytes written field by field at the offsets of the table in §3.1, independent of the codec's struct."""
    b = bytearray(44)
    b[0], b[1], b[2], b[3] = 1, 3, 2, 0b011                     # version, role display, chip esp32c3, flags valid+FORBID
    b[4:8] = (0x01020304).to_bytes(4, "big")                    # seq
    b[8:12] = (86_400).to_bytes(4, "big")                       # uptime_s
    b[12:14] = (513).to_bytes(2, "big")                         # boot_count
    b[14], b[15] = 3, 2                                         # reset reason, depth
    b[16] = (-67) & 0xFF                                        # parent RSSI
    b[17] = 0                                                   # reserved
    b[18:20] = (10).to_bytes(2, "big")                          # interval
    for off, v in ((20, 1000), (24, 2000), (28, 3), (32, 4), (36, 123_456), (40, 77)):
        b[off:off + 4] = v.to_bytes(4, "big")
    return bytes(b)


def test_telemetry_layout_follows_the_table() -> None:
    t = pr.decode_telemetry(raw_telemetry())
    assert (t.role, t.role_name, t.chip, t.chip_name) == (3, "display", 2, "esp32c3")
    assert (t.flags, t.display_state, t.render_fault) == (3, "FORBID", False)
    assert (t.seq, t.uptime_s, t.boot_count, t.reset_reason, t.depth) == (0x01020304, 86_400, 513, 3, 2)
    assert (t.parent_rssi_dbm, t.interval_s) == (-67, 10)
    assert (t.tx_frames, t.rx_frames, t.rf_failures, t.local_busy) == (1000, 2000, 3, 4)
    assert (t.min_heap_bytes, t.display_seq) == (123_456, 77)
    assert pr.encode_telemetry(role=3, chip=2, flags=3, seq=0x01020304, uptime_s=86_400, boot_count=513,
                               reset_reason=3, depth=2, rssi=-67, tx=1000, rx=2000, rf=3, busy=4, heap=123_456,
                               display_seq=77) == raw_telemetry()


def test_telemetry_unknown_values_and_flags() -> None:
    raw = bytearray(raw_telemetry())
    raw[3] = 0b100  # no display state, render fault
    raw[14], raw[15], raw[16] = 0xFF, 0xFF, 0x80
    for off in (20, 24, 28, 32):
        raw[off:off + 4] = b"\xff\xff\xff\xff"
    t = pr.decode_telemetry(bytes(raw))
    assert (t.reset_reason, t.depth, t.parent_rssi_dbm) == (None, None, None)
    assert (t.tx_frames, t.rx_frames, t.rf_failures, t.local_busy) == (None, None, None, None)
    assert t.display_state is None and t.render_fault is True


def test_telemetry_refuses_a_wrong_version_or_length() -> None:
    raw = bytearray(raw_telemetry())
    with pytest.raises(pr.TelemetryError, match="expected 44"):
        pr.decode_telemetry(bytes(raw[:43]))
    with pytest.raises(pr.TelemetryError, match="expected 44"):
        pr.decode_telemetry(bytes(raw) + b"\0")
    raw[0] = 2
    with pytest.raises(pr.TelemetryError, match="version 2"):
        pr.decode_telemetry(bytes(raw))


def test_event_app_port_and_payload_come_from_the_journal_event_shape() -> None:
    ev = {"kind": "MESSAGE_RECEIVED", "payload_b64": "AQID",
          "evidence": {"kind": "ROOT_DELIVERED", "details": {"app_port": 210, "recovered": False}}}
    assert pr.event_app_port(ev) == 210 and pr.event_payload(ev) == b"\x01\x02\x03"
    assert pr.event_app_port({"kind": "MESSAGE_RECEIVED"}) is None


# ---- loss, reboots ------------------------------------------------------------------------------------------------

def tel(seq: int, boot: int = 1, uptime: int | None = None) -> pr.Telemetry:
    return pr.decode_telemetry(pr.encode_telemetry(seq=seq, boot_count=boot, uptime_s=seq * 10 if uptime is None else uptime))


def test_loss_comes_from_sequence_gaps() -> None:
    track = TelemetryTrack()
    for seq in (5, 6, 8, 11):  # the first is only the baseline; 7, 9, 10 are missing
        track.feed(tel(seq), now=float(seq))
    assert (track.received, track.lost, track.reboots) == (4, 3, 0)
    assert track.loss_pct == pytest.approx(100 * 3 / 7)
    assert track.age(20.0) == 9.0


def test_duplicate_is_ignored_and_a_late_message_repairs_the_count() -> None:
    track = TelemetryTrack()
    track.feed(tel(1), 1.0)
    track.feed(tel(3), 3.0)
    assert track.lost == 1
    assert track.feed(tel(3), 3.5) == ["dup"]
    assert track.feed(tel(2), 4.0) == ["late"]
    assert (track.received, track.lost) == (3, 0)


def test_reboot_by_boot_count_counts_what_the_new_boot_sent_before() -> None:
    track = TelemetryTrack()
    for seq in (1, 2, 3):
        track.feed(tel(seq, boot=7), float(seq))
    out = track.feed(tel(4, boot=8, uptime=40), 5.0)  # a new boot: seq 1..3 of it were lost, 4 arrived
    assert out == ["reboot"] and track.reboots == 1
    assert (track.received, track.lost) == (4, 3)
    track.feed(tel(5, boot=8, uptime=50), 6.0)  # continues in the new boot without a false gap
    assert (track.received, track.lost) == (5, 3)


def test_reboot_without_a_boot_count_change_is_seen_from_a_seq_that_fell_back() -> None:
    track = TelemetryTrack()
    track.feed(tel(40, uptime=400), 1.0)
    track.feed(tel(41, uptime=410), 2.0)
    assert track.feed(tel(1, uptime=5), 3.0) == ["reboot"]
    assert (track.received, track.lost, track.reboots) == (3, 0, 1)


def test_backlog_and_a_lost_place_only_set_the_baseline() -> None:
    track = TelemetryTrack()
    track.feed(tel(10), 1.0, live=False)
    track.feed(tel(11), 1.0, live=False)
    assert (track.received, track.lost, track.last_seen) == (0, 0, None)
    track.feed(tel(12), 2.0)  # the first live one continues the baseline: no loss counted
    assert (track.received, track.lost) == (1, 0)
    track.rebaseline()
    track.feed(tel(90), 3.0)  # events were missed (CURSOR_GAP): not RF loss
    assert (track.received, track.lost) == (2, 0)


def test_recent_loss_window() -> None:
    track = TelemetryTrack()
    for seq in (1, 2, 3, 4):
        track.feed(tel(seq), float(seq))
    assert track.recent_loss_pct == 0.0
    track.feed(tel(8), 8.0)  # 5, 6, 7 missing
    assert track.recent_loss_pct == pytest.approx(100 * 3 / 8)


# ---- ping evidence --------------------------------------------------------------------------------------------------

def ev(kind: str, mono: int | None = None) -> dict:
    e = {"kind": kind, "assurance": "SELF_REPORTED", "observer": "aa" * 32}
    if mono is not None:
        e["observed_mono_ms"] = str(mono)
    return e


def op(outcome: str, *kinds: dict, reason: str | None = None) -> dict:
    out = {"id": "01" * 16, "state": "FINAL", "outcome": outcome, "evidence": list(kinds)}
    if reason:
        out["reason"] = reason
    return out


def test_alive_with_rtt_from_the_root_clock() -> None:
    r = pr.classify_ping(op("APPLIED", ev("ROOT_SENT", 1000), ev("END_RECEIVED", 1040), ev("APP_APPLIED", 1062)), 900)
    assert r == pr.PingResult("alive", "", 62, "root")


def test_rtt_falls_back_to_end_received_when_app_applied_has_no_time() -> None:
    r = pr.classify_ping(op("APPLIED", ev("ROOT_SENT", 1000), ev("END_RECEIVED", 1040), ev("APP_APPLIED")), 900)
    assert (r.kind, r.rtt_ms, r.rtt_src) == ("alive", 40, "root")


def test_rtt_falls_back_to_the_laptop_when_the_host_reports_no_time() -> None:
    r = pr.classify_ping(op("APPLIED", ev("ROOT_SENT"), ev("APP_APPLIED")), 321)
    assert (r.kind, r.rtt_ms, r.rtt_src) == ("alive", 321, "laptop")
    assert pr.classify_ping(op("APPLIED", ev("APP_APPLIED")), None).rtt_ms is None


def test_a_negative_root_time_difference_is_not_an_rtt() -> None:
    r = pr.classify_ping(op("APPLIED", ev("ROOT_SENT", 2000), ev("APP_APPLIED", 1000)), 50)
    assert (r.rtt_ms, r.rtt_src) == (50, "laptop")


@pytest.mark.parametrize(("operation", "kind"), [
    (op("EXPIRED", ev("ROOT_ACCEPTED"), ev("ROOT_SENT")), "noanswer"),                      # left the root, silence
    (op("INDETERMINATE", ev("ROOT_ACCEPTED"), ev("ROOT_SENT")), "noanswer"),
    (op("INDETERMINATE", ev("HOST_SEND_OUTCOME_UNKNOWN"), reason="unknown"), "noanswer"),   # unknown is not "not sent"
    (op("RECEIVED", ev("ROOT_SENT"), ev("END_RECEIVED")), "noanswer"),                       # arrived, never answered
    (op("EXPIRED", ev("HOST_DEADLINE_EXPIRED"), reason="deadline passed before first transmission"), "notsent"),
    (op("EXPIRED", ev("ROOT_ACCEPTED")), "notsent"),                                         # the root never sent it
    (op("REJECTED", ev("HOST_REFUSED"), reason="TIME_UNCERTAIN"), "notsent"),
    (op("REJECTED", ev("ROOT_ACCEPTED"), reason="BUSY"), "notsent"),
    (op("CANCELLED_NOT_SENT"), "notsent"),
    (op("SUPERSEDED"), "notsent"),
    (op("REJECTED", ev("ROOT_SENT"), ev("END_RECEIVED"), ev("APP_REJECTED")), "rejected"),   # the node answered
    (op("REJECTED", ev("ROOT_SENT"), ev("DESTINATION_REFUSED")), "rejected"),
])
def test_ping_classification(operation: dict, kind: str) -> None:
    assert pr.classify_ping(operation).kind == kind


@pytest.mark.parametrize(("status", "code", "text"), [
    (429, "RATE_LIMITED", "HTTP 429 RATE_LIMITED"), (507, "NO_CAPACITY", "HTTP 507 NO_CAPACITY"),
    (503, "UNSUPPORTED", "HTTP 503 UNSUPPORTED"), (400, "INVALID_ARGUMENT", "HTTP 400 INVALID_ARGUMENT"),
    (500, "", "HTTP 500"),
])
def test_a_refused_post_is_not_sent(status: int, code: str, text: str) -> None:
    assert pr.classify_post_error(status, {"code": code}) == pr.PingResult("notsent", text)
    assert pr.classify_post_error(None, exc="refused").kind == "notsent"


def test_ping_counters_keep_not_sent_apart_from_no_answer() -> None:
    t = PingTrack()
    for _ in range(4):
        t.accepted()
    t.finish(1, pr.PingResult("alive", "", 40, "root"))
    t.finish(2, pr.PingResult("alive", "", 60, "root"))
    t.finish(3, pr.PingResult("noanswer", "EXPIRED"))
    t.finish(4, pr.PingResult("notsent", "BUSY"))   # accepted by the Host, never left: not a sent ping
    t.refused(5, pr.PingResult("notsent", "HTTP 429 RATE_LIMITED"))
    assert (t.sent, t.alive, t.noanswer, t.notsent) == (3, 2, 1, 2)
    assert t.loss_pct == pytest.approx(100 / 3) and t.rtt_median_ms == 50.0
    assert [k for _, k in t.history] == ["alive", "alive", "noanswer", "notsent", "notsent"]


# ---- request bodies -------------------------------------------------------------------------------------------------

def test_ping_request_body_is_exact() -> None:
    body = pr.ping_request(DOMAIN, EPOCH, DEV["a"], 258, 5.0, NOW)
    assert body == {
        "domain_id": DOMAIN, "client_epoch": EPOCH, "destination": {"kind": "node", "device_id": DEV["a"]},
        "app_port": 211, "payload_b64": "AQAAAQI=", "delivery": "APPLIED", "storage": "VOLATILE",
        "queue_mode": "FIFO", "priority": "NORMAL",
        "deadline": {"mode": "utc", "expires_at": "2026-10-04T12:00:03.250Z"}}
    assert pr.ping_payload(258) == bytes([1, 0, 0, 1, 2])


def test_ping_deadline_is_the_interval_but_never_more_than_3_s() -> None:
    assert pr.ping_request(DOMAIN, EPOCH, DEV["a"], 1, 1.0, NOW)["deadline"]["expires_at"] == "2026-10-04T12:00:01.250Z"
    assert pr.ping_request(DOMAIN, EPOCH, DEV["a"], 1, 2.5, NOW)["deadline"]["expires_at"] == "2026-10-04T12:00:02.750Z"
    assert pr.ping_request(DOMAIN, EPOCH, DEV["a"], 1, 60.0, NOW)["deadline"]["expires_at"] == "2026-10-04T12:00:03.250Z"


def test_display_request_body_is_exact() -> None:
    body = pr.display_request(DOMAIN, EPOCH, DEV["b"], "FORBID", 0x01020304, NOW)
    assert body == {
        "domain_id": DOMAIN, "client_epoch": EPOCH, "destination": {"kind": "node", "device_id": DEV["b"]},
        "app_port": 212, "payload_b64": "AQEBAgME", "delivery": "APPLIED", "storage": "VOLATILE",
        "queue_mode": "FIFO", "priority": "NORMAL",
        "deadline": {"mode": "utc", "expires_at": "2026-10-04T12:00:10.250Z"}}
    assert pr.display_payload("USABLE", 7) == bytes([1, 0, 0, 0, 0, 7])
    with pytest.raises(ValueError):
        pr.display_payload("BLINK", 1)


def test_bodies_pass_the_real_host_admission_rules() -> None:
    for body in (pr.ping_request(DOMAIN, EPOCH, DEV["a"], 1, 5.0, NOW),
                 pr.display_request(DOMAIN, EPOCH, DEV["b"], "USABLE", 1, NOW)):
        MessageRequest.model_validate(body)


def test_the_latest_form_of_the_protocol_text_is_refused_by_the_host() -> None:
    """docs/field/protocol.md §3.2 / §3.3 say APPLIED + LATEST + coalesce_key; the Host admits LATEST only with
    BEST_EFFORT + VOLATILE (api/models.py), so fieldview sends FIFO. This pins the reason."""
    body = {**pr.ping_request(DOMAIN, EPOCH, DEV["a"], 1, 5.0, NOW), "queue_mode": "LATEST", "coalesce_key": "211"}
    with pytest.raises(ValidationError, match="LATEST requires BEST_EFFORT"):
        MessageRequest.model_validate(body)
    fifo_with_key = {**pr.ping_request(DOMAIN, EPOCH, DEV["a"], 1, 5.0, NOW), "coalesce_key": "211"}
    with pytest.raises(ValidationError, match="coalesce_key"):
        MessageRequest.model_validate(fifo_with_key)


def test_load_estimate_of_a_ping_loop() -> None:
    need, fit = ping_load(10, 1.0)
    assert need == 23.0 and fit == pytest.approx(20 / 11)
    assert ping_load(10, 5.0)[0] == 7.0
    assert ping_load(0, 1.0) == (3.0, 1.0)


# ---- topology -------------------------------------------------------------------------------------------------------

def item(device: str, parent: str | None = None, depth: int | None = None, membership: str = "ACTIVE") -> dict:
    n = {"device_id": device, "domain_id": DOMAIN, "membership": membership, "connectivity": "REACHABLE"}
    if parent is not None:
        n["parent_device_id"] = parent
    if depth is not None:
        n["root_depth"] = depth
    return n


def names(tree: dict) -> dict[str, list[str]]:
    return {n["name"]: [c["name"] for c in n["children"]] for n in topo.flatten(tree["root"]) if n["children"]}


def views() -> dict[str, topo.NodeView]:
    return {d: topo.NodeView(name=f"n-{c}", role="leaf", rssi=-70, loss_pct=0.0) for c, d in DEV.items()}


def test_tree_follows_parent_device_id() -> None:
    root = "ff" * 32
    nodes = [item(DEV["a"], root, 1), item(DEV["b"], DEV["a"], 2), item(DEV["c"], DEV["a"], 2), item(DEV["d"], DEV["c"], 3)]
    tree = topo.build_tree(nodes, views(), root)
    assert tree["has_parent_info"] is True
    assert names(tree) == {"root": ["n-a"], "n-a": ["n-b", "n-c"], "n-c": ["n-d"]}


def test_without_parent_fields_every_node_hangs_under_the_unknown_parent_group() -> None:
    nodes = [item(DEV["a"], depth=2), item(DEV["b"], depth=1), item(DEV["c"])]
    tree = topo.build_tree(nodes, views(), "ff" * 32)
    assert tree["has_parent_info"] is False
    assert names(tree) == {"root": ["parent unknown"], "parent unknown": ["n-b", "n-a", "n-c"]}  # by depth, unknown last
    group = tree["root"]["children"][0]
    assert group["group"] is True and group["quality"] == "unknown"


def test_a_mixed_listing_keeps_known_parents_and_groups_the_rest() -> None:
    root = "ff" * 32
    nodes = [item(DEV["a"], root, 1), item(DEV["b"], DEV["a"], 2), item(DEV["c"])]
    tree = topo.build_tree(nodes, views(), root)
    assert names(tree) == {"root": ["n-a", "parent unknown"], "n-a": ["n-b"], "parent unknown": ["n-c"]}


def test_the_root_is_inferred_from_the_parent_that_is_not_listed() -> None:
    root = "ff" * 32
    nodes = [item(DEV["a"], root), item(DEV["b"], root), item(DEV["c"], DEV["a"])]
    assert topo.infer_root(nodes) == root
    assert names(topo.build_tree(nodes, views()))["root"] == ["n-a", "n-b"]
    assert topo.infer_root([item(DEV["a"])]) is None


def test_a_parent_the_host_does_not_list_gets_a_grey_stand_in() -> None:
    root = "ff" * 32
    nodes = [item(DEV["b"], DEV["e"], 2)]
    tree = topo.build_tree(nodes, views(), root)
    stand_in = next(n for n in topo.flatten(tree["root"]) if n["id"] == DEV["e"])
    assert stand_in["placeholder"] is True and stand_in["silent"] is True and stand_in["listed"] is False
    assert [c["name"] for c in stand_in["children"]] == ["n-b"]


def test_a_parent_cycle_is_cut_and_nothing_is_lost() -> None:
    nodes = [item(DEV["a"], DEV["b"]), item(DEV["b"], DEV["a"]), item(DEV["c"], DEV["c"])]
    tree = topo.build_tree(nodes, views(), "99" * 32)
    seen = [n["id"] for n in topo.flatten(tree["root"]) if n["id"] in DEV.values()]
    assert sorted(seen) == sorted([DEV["a"], DEV["b"], DEV["c"]])
    assert any(n.get("group") for n in topo.flatten(tree["root"]))


@pytest.mark.parametrize(("rssi", "loss", "silent", "want"), [
    (-60, 0.0, False, "good"), (-85, 0.0, False, "fair"), (-95, 0.0, False, "poor"),
    (-60, 10.0, False, "fair"), (-60, 30.0, False, "poor"), (-60, None, False, "good"), (None, 2.0, False, "good"),
    (None, None, False, "unknown"), (-60, 0.0, True, "unknown"),
])
def test_link_quality(rssi: int | None, loss: float | None, silent: bool, want: str) -> None:
    assert topo.link_quality(rssi, loss, silent) == want


# ---- the engine's picture and the records, without a Host ---------------------------------------------------------

def dummy_client() -> SimpleNamespace:
    return SimpleNamespace(bucket=SimpleNamespace(throttled=0), requests=0, rate_limited=0)


def make_engine(tmp_path: Path, clock: list[float], **cfg: object) -> tuple[FieldView, Recorder]:
    rec = Recorder(tmp_path / "rec")
    config = Config(socket="x", token="t", domain=DOMAIN, names={DEV["a"]: "relay-1"}, root_id="ff" * 32, **cfg)  # type: ignore[arg-type]
    return FieldView(config, dummy_client(), rec, clock=lambda: clock[0], utcnow=lambda: NOW), rec  # type: ignore[arg-type]


def message_event(device: str, payload: bytes, seq: int) -> dict:
    import base64
    return {"cursor": f"j:{seq}", "kind": "MESSAGE_RECEIVED", "origin": device, "message_id": "00" * 16,
            "payload_b64": base64.b64encode(payload).decode(),
            "evidence": {"kind": "ROOT_DELIVERED", "details": {"app_port": 210, "recovered": False}}}


def test_summary_rows_and_csv(tmp_path: Path) -> None:
    clock = [100.0]
    fv, rec = make_engine(tmp_path, clock)
    fv._on_nodes([item(DEV["a"], "ff" * 32, 1), item(DEV["b"], DEV["a"], 2)])
    for seq in (1, 2, 4):  # one telemetry message missing from relay-1
        clock[0] += 10
        fv._on_event(message_event(DEV["a"], pr.encode_telemetry(seq=seq, depth=1, rssi=-72), seq), backlog=False)
    fv.ping[DEV["a"]] = PingTrack()
    for rnd, (kind, rtt) in enumerate([("alive", 40), ("alive", 60), ("noanswer", None), ("notsent", None)], start=1):
        fv.ping[DEV["a"]].accepted()
        fv.ping[DEV["a"]].finish(rnd, pr.PingResult(kind, "", rtt, "root" if rtt else None))
    clock[0] += 5
    rows = fv.summary_rows()
    by = {r["name"]: r for r in rows}
    a = by["relay-1"]
    assert (a["device"], a["depth"], a["parent"], a["rssi_dbm"]) == (DEV["a"], 1, "root", -72)
    assert a["telemetry_loss_pct"] == "25.0" and a["last_seen_age_s"] == "5"
    assert (a["ping_sent"], a["ping_alive"], a["ping_lost"], a["ping_notsent"], a["ping_rtt_median_ms"]) == (2 + 1, 2, 1, 1, "50")
    b = by[DEV["b"][:8]]  # listed by the root, no name in the bench file, never sent telemetry
    assert (b["parent"], b["telemetry_loss_pct"], b["ping_sent"]) == ("relay-1", None, 0)
    rec.summary(rows)
    rec.close()
    lines = list(csv.reader((tmp_path / "rec" / "summary.csv").read_text().splitlines()))
    assert tuple(lines[0]) == SUMMARY_COLUMNS
    assert len(lines) == 3 and lines[2][1] == "relay-1"  # (rows are ordered by name)
    assert lines[2][SUMMARY_COLUMNS.index("telemetry_loss_pct")] == "25.0"


def test_snapshot_draws_silent_and_lost_nodes_and_logs_it(tmp_path: Path) -> None:
    clock = [0.0]
    fv, rec = make_engine(tmp_path, clock, interval_s=10.0)
    fv._on_nodes([item(DEV["a"], "ff" * 32, 1), item(DEV["b"], "ff" * 32, 1)])
    fv._on_event(message_event(DEV["a"], pr.encode_telemetry(seq=1, interval_s=10), 1), backlog=False)
    snap = fv.snapshot()
    rows = {r["name"]: r for r in snap["nodes"]}
    assert rows["relay-1"]["state"] == "ok" and rows[DEV["b"][:8]]["state"] == "silent"
    tree_nodes = {n["id"]: n for n in topo.flatten(snap["tree"]["root"])}
    assert tree_nodes[DEV["b"]]["silent"] is True and tree_nodes[DEV["b"]]["quality"] == "unknown"  # drawn, greyed
    clock[0] = 31.0  # three intervals without telemetry
    fv._check_lost()
    assert fv.snapshot()["nodes"][0]["state"] in ("lost", "silent")
    kinds = [e["kind"] for e in fv.log]
    assert "lost" in kinds and "silent" in kinds
    fv._on_event(message_event(DEV["a"], pr.encode_telemetry(seq=2, interval_s=10), 2), backlog=False)
    assert fv.log[-1]["kind"] == "back"
    rec.close()


def test_topology_and_telemetry_events_are_logged(tmp_path: Path) -> None:
    clock = [0.0]
    fv, rec = make_engine(tmp_path, clock)
    fv._on_nodes([item(DEV["a"], "ff" * 32, 1)])
    fv._on_nodes([item(DEV["a"], "ff" * 32, 1), item(DEV["b"], DEV["a"], 2)])                    # b appears
    fv._on_nodes([item(DEV["a"], "ff" * 32, 1), item(DEV["b"], "ff" * 32, 1)])                   # b moves to the root
    fv._on_nodes([item(DEV["a"], "ff" * 32, 1), item(DEV["b"], "ff" * 32, 1, "REVOKED")])        # b is revoked
    fv._on_nodes([item(DEV["a"], "ff" * 32, 1)])                                                 # b is gone
    texts = [(e["kind"], e["text"]) for e in fv.log]
    assert [k for k, _ in texts] == ["join", "parent", "leave", "leave"]
    assert any("parent relay-1 -> root" in t for _, t in texts)
    fv._on_event(message_event(DEV["a"], pr.encode_telemetry(seq=1, boot_count=1), 1), backlog=False)
    clock[0] += 10
    fv._on_event(message_event(DEV["a"], pr.encode_telemetry(seq=1, boot_count=2, reset_reason=4), 2), backlog=False)
    assert fv.log[-1]["kind"] == "reboot" and "reset reason 4" in fv.log[-1]["text"]
    rec.close()
    events = [json.loads(line) for line in (tmp_path / "rec" / "events.ndjson").read_text().splitlines()]
    assert all("t" in e and e["t"].endswith("Z") for e in events)
    assert [e["kind"] for e in events if e["kind"] != "session"][-1] == "reboot"


# ---- records --------------------------------------------------------------------------------------------------------

def test_every_ndjson_line_has_the_laptop_utc_time(tmp_path: Path) -> None:
    rec = Recorder(tmp_path / "r")
    for stream in ("telemetry", "ping", "display", "events"):
        rec.log(stream, {"x": stream})
    rec.close()
    for stream in ("telemetry", "ping", "display", "events"):
        (line,) = (tmp_path / "r" / f"{stream}.ndjson").read_text().splitlines()
        doc = json.loads(line)
        assert doc["x"] == stream and datetime.strptime(doc["t"], "%Y-%m-%dT%H:%M:%S.%fZ")


def test_a_failing_disk_becomes_a_warning_and_never_raises(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    warnings: list[str] = []
    rec = Recorder(blocker / "sub", on_warning=warnings.append)  # mkdir fails: a file is in the way
    rec.log("events", {"a": 1})
    rec.summary([{"name": "x"}])
    rec.close()
    assert rec.warning is not None and warnings


def test_load_bench_names_the_boards(tmp_path: Path) -> None:
    state = {"domain": DOMAIN, "root": {"device": "ff" * 32, "port": "/dev/x"},
             "leaves": {"leaf1": {"device": DEV["a"]}, "relay": {"device": DEV["b"], "role": "relay"}},
             "nets": {"netB": {"domain": "bb" * 16, "root": {"device": "ee" * 32}, "leaves": {"far": {"device": DEV["c"]}}}}}
    path = tmp_path / "state.json"
    path.write_text(json.dumps(state))
    first = load_bench(path)
    assert first["domain"] == DOMAIN and first["root_id"] == "ff" * 32
    assert first["names"][DEV["a"]] == "leaf1" and first["names"][DEV["c"]] == "far" and first["names"]["ff" * 32] == "root"
    second = load_bench(path, "netB")
    assert second["domain"] == "bb" * 16 and second["root_id"] == "ee" * 32
    assert load_bench(tmp_path / "missing.json") == {}


def test_names_of_boards_provisioned_after_the_start_are_read_again(tmp_path: Path) -> None:
    # HIL 2026-10-04: boards provisioned while fieldview ran showed short ids only (the state file was read once).
    import os

    path = tmp_path / "state.json"
    path.write_text(json.dumps({"domain": DOMAIN, "root": {"device": "ff" * 32}, "leaves": {}}))
    fv, rec = make_engine(tmp_path, [0.0], state_file=path)
    fv._reload_names()
    assert fv.name_of(DEV["b"]) == DEV["b"][:8]
    path.write_text(json.dumps({"domain": DOMAIN, "root": {"device": "ff" * 32}, "leaves": {"late": {"device": DEV["b"]}}}))
    os.utime(path, (1, 2))  # a different mtime even within the file system's resolution
    fv._reload_names()
    assert fv.name_of(DEV["b"]) == "late"
    rec.close()


# ---- the request-rate guard (review finding 6) --------------------------------------------------------------------------

def test_the_rate_guard_enforces_its_total_wait_also_behind_the_lock() -> None:
    """A request queued behind a long cooldown must give up at its own budget, and must not take a token that happens
    to be free once it finally gets the lock."""
    import asyncio
    import time

    async def scenario() -> None:
        bucket = RateBucket(50.0, 4)
        bucket.penalize(600)                                    # a 429 stops everything for 0.6 s
        holder = asyncio.ensure_future(bucket.acquire(None))    # a request without budget limit holds the lock for that
        await asyncio.sleep(0.05)
        t0 = time.monotonic()
        got = await bucket.acquire(0.2)                          # queued behind it, budget 0.2 s
        assert got is False and time.monotonic() - t0 < 0.4     # gave up at its budget, not after the cooldown
        assert await holder is True
        t1 = time.monotonic()
        assert await bucket.acquire(0.05) is True                # a free token is still taken by a fresh request
        assert time.monotonic() - t1 < 0.1
        assert bucket.refused == 1

    asyncio.run(scenario())


def test_a_token_that_became_free_after_the_budget_is_not_taken() -> None:
    import asyncio

    async def scenario() -> None:
        bucket = RateBucket(100.0, 1)
        bucket.tokens = 0.0
        t = [0.0]
        bucket.clock = lambda: t[0]
        bucket.at = 0.0
        bucket.blocked_until = 0.0
        # the lock is free but the clock says the budget (0.1 s) ran out before the token check: refuse, keep the token
        t[0] = 0.0
        task = asyncio.ensure_future(bucket.acquire(0.1))
        await asyncio.sleep(0)
        t[0] = 5.0                                               # 5 s later a token has refilled ...
        assert await task is False                               # ... but this request is long past its budget
        assert bucket.tokens >= 0.99

    asyncio.run(scenario())


def test_the_recorder_counts_dropped_lines_as_lost_and_syncs_only_what_is_on_disk(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    from tools.fieldview import recorder as recorder_mod

    monkeypatch.setattr(recorder_mod, "QUEUE_MAX", 3)
    gate = threading.Event()
    rec = Recorder(tmp_path / "r")
    original = rec._open
    rec._open = lambda name: (gate.wait(5), original(name))[1]  # type: ignore[method-assign]  # a slow disk
    for i in range(12):
        rec.log("events", {"n": i})
    assert rec.lost > 0 and rec.dropped == rec.lost and rec.warning and "queue is full" in rec.warning
    dropped = rec.lost
    gate.set()
    assert rec.sync(5.0) is True
    written = [json.loads(x)["n"] for x in (tmp_path / "r" / "events.ndjson").read_text().splitlines()]
    assert len(written) + dropped == 12                    # nothing is silently missing: lost counts the rest
    rec.resolve_lost(dropped)
    assert rec.lost == 0
    rec.close()


def test_recorder_sync_fails_when_the_writer_cannot_confirm(tmp_path: Path) -> None:
    import threading

    rec = Recorder(tmp_path / "r")
    release = threading.Event()
    original = rec._open
    rec._open = lambda name: (release.wait(5), original(name))[1]  # type: ignore[method-assign]  # a hung disk
    rec.log("events", {"a": 1})
    assert rec.sync(0.2) is False                          # the barrier did not come back in time: not safe
    release.set()
    assert rec.sync(5.0) is True
    rec.close()
