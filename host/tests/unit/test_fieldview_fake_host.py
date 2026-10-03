"""tools/fieldview against a fake Host on a Unix socket (fieldview_fake.py): the real HTTP client, the event journal read
by cursor as a consumer, pings and display commands through POST /v1/messages and operation events, the rate-limit guard,
the web page and its API. The fake's request validation and rate limiter are the Host's own modules."""

from __future__ import annotations

import asyncio
import base64
import json
import shutil
import sys
import tempfile
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx2 as httpx
import pytest
import uvicorn
from fieldview_fake import DOMAIN, ROOT, TOKEN, FakeHost, hex_id

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from tools.fieldview import protocol as pr  # noqa: E402
from tools.fieldview import engine as engine_mod  # noqa: E402
from tools.fieldview.engine import Config, FieldView  # noqa: E402
from tools.fieldview.hostclient import HostClient, HostUnreachable, SendUnknown  # noqa: E402
from tools.fieldview.recorder import Recorder  # noqa: E402
from tools.fieldview.web import make_app  # noqa: E402

A, B, C, D, E, F = (c * 64 for c in "abcdef")


@pytest.fixture
def fake() -> Iterator[FakeHost]:
    short = Path(tempfile.mkdtemp(prefix="fv", dir="/tmp"))  # AF_UNIX paths are short on macOS
    host = FakeHost(short / "h.sock")
    host.start()
    yield host
    host.stop()
    shutil.rmtree(short, ignore_errors=True)


async def until(pred: Callable[[], Any], what: str, timeout: float = 8.0) -> Any:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        value = pred()
        if value:
            return value
        await asyncio.sleep(0.02)
    raise AssertionError(f"timeout waiting for {what}")


@asynccontextmanager
async def view(fake: FakeHost, tmp: Path, **cfg: Any) -> AsyncIterator[FieldView]:
    cfg.setdefault("nodes_poll_s", 0.1)
    cfg.setdefault("events_wait_ms", 300)
    cfg.setdefault("tick_s", 0.05)
    cfg.setdefault("summary_s", 0.3)
    rps = cfg.pop("rps", 14.0)
    post_timeout = cfg.pop("post_timeout", 5.0)
    rec_dir = cfg.pop("rec_dir", None)
    config = Config(socket=str(fake.socket), token=TOKEN, domain=DOMAIN, logs_dir=tmp, root_id=ROOT,
                    names={A: "relay-1", B: "leaf-1", C: "display-1"}, **cfg)
    client = HostClient(config.socket, TOKEN, DOMAIN, rps=rps, post_timeout=post_timeout)
    rec = Recorder(rec_dir or tmp / f"rec{len(list(tmp.glob('rec*')))}")
    fv = FieldView(config, client, rec)
    await fv.start()
    try:
        yield fv
    finally:
        await fv.stop()
        await client.aclose()


def lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text().splitlines()]


def telemetry(fake: FakeHost, device: str, seq: int, **kw: Any) -> None:
    fake.emit_telemetry(device, pr.encode_telemetry(seq=seq, uptime_s=seq * 10, **kw))


# ---- telemetry through the journal ---------------------------------------------------------------------------------

def test_telemetry_is_consumed_by_cursor_and_acknowledged(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT, root_depth=1)
    fake.add_node(B, parent_device_id=A, root_depth=2)

    async def scenario() -> None:
        telemetry(fake, A, 1, depth=1, rssi=-61)  # (older than this run: the backlog sets the baseline only)
        async with view(fake, tmp_path) as fv:
            await until(lambda: not fv._backlog, "the backlog is read")
            assert fv.backlog_events == 1 and fv.tele[A].received == 0
            for seq in (2, 3, 5):  # 4 is missing
                telemetry(fake, A, seq, depth=1, rssi=-63)
            telemetry(fake, B, 1, depth=2, rssi=-80, role=2)
            await until(lambda: fv.tele.get(A) and fv.tele[A].received == 3 and B in fv.tele, "telemetry")
            row = {r["name"]: r for r in fv.snapshot()["nodes"]}
            assert (row["relay-1"]["lost"], row["relay-1"]["received"]) == (1, 3)
            assert row["relay-1"]["loss_pct"] == pytest.approx(25.0) and row["relay-1"]["rssi_dbm"] == -63
            assert row["leaf-1"]["role"] == "relay" and row["leaf-1"]["parent"] == "relay-1"
            await until(lambda: fake.acks.get("fieldview") == len(fake.events), "the cursor is acknowledged")
            assert fv.host["ok"] and fv.snapshot()["host"]["rate_limited"] == 0

    asyncio.run(scenario())
    first = lines(next(tmp_path.glob("rec*/telemetry.ndjson")))
    assert [(x["backlog"], x["seq"]) for x in first] == [(True, 1), (False, 2), (False, 3), (False, 5), (False, 1)]
    assert all(x["t"].endswith("Z") for x in first) and first[3]["events"] == ["gap"]

    async def second_run() -> None:  # a restart resumes at the acknowledged position: nothing is read twice
        async with view(fake, tmp_path) as fv:
            await until(lambda: not fv._backlog, "the backlog is read")
            assert fv.backlog_events == 0
            telemetry(fake, A, 6, depth=1)
            await until(lambda: A in fv.tele and fv.tele[A].received == 1, "a new message")

    asyncio.run(second_run())


def test_a_lost_place_is_shown_and_never_skipped_silently(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT)

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: not fv._backlog, "the backlog is read")
            for seq in (1, 2, 3):
                telemetry(fake, A, seq)
            await until(lambda: A in fv.tele and fv.tele[A].received == 3, "three messages")
            await until(lambda: fake.acks.get("fieldview", 0) >= 3, "acknowledged")
            fv.cursor = f"{fake.journal}:1"  # the Host purged what we were about to read:
            fv._segments.clear()
            for seq in (4, 5, 6):
                telemetry(fake, A, seq)
            fake.purge(4)
            await until(lambda: "gap" in fv.warnings, "CURSOR_GAP shown")
            assert any(e["kind"] == "gap" and "CURSOR_GAP" in e["text"] for e in fv.log)
            await until(lambda: fv.tele[A].received == 3 and fv.cursor == f"{fake.journal}:6", "reading resumes")
            telemetry(fake, A, 9)  # and 7, 8 missing is counted again from the new baseline
            await until(lambda: fv.tele[A].lost == 2, "loss after the gap")

    asyncio.run(scenario())


# ---- ping ----------------------------------------------------------------------------------------------------------

def test_a_ping_round_classifies_every_node_and_measures_rtt(fake: FakeHost, tmp_path: Path) -> None:
    for d in (A, B, C, D, E):
        fake.add_node(d, parent_device_id=ROOT, root_depth=1)
    fake.add_node(F, membership="REVOKED", parent_device_id=ROOT)  # not ACTIVE: not pinged
    fake.responders = {
        A: {"mode": "apply", "rtt": 0.06, "observed": True},   # root clock evidence: RTT = END_RECEIVED - ROOT_SENT
        B: {"mode": "apply", "rtt": 0.10},                      # no time in the evidence: laptop RTT
        C: {"mode": "silent", "after": 1.0},                    # left the root, no answer
        D: {"mode": "unsent", "after": 1.0},                    # expired before it could leave
        E: {"mode": "refuse", "status": 507, "code": "NO_CAPACITY"},
    }

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: len(fv.active_nodes()) == 5, "nodes")
            rnd = await fv.ping_round(5.0)
            await until(lambda: rnd["open"] == 0, "the round ends", timeout=10)
            assert (rnd["alive"], rnd["noanswer"], rnd["rejected"], rnd["notsent"]) == (2, 1, 0, 2)
            p = {fv.name_of(d): fv.ping[d] for d in (A, B, C, D, E)}
            assert p["relay-1"].alive == 1
            assert (p["relay-1"].last.kind, p["relay-1"].last.rtt_src) == ("alive", "root")
            assert p["relay-1"].last.rtt_ms == 60
            assert (p["leaf-1"].last.kind, p["leaf-1"].last.rtt_src) == ("alive", "laptop")
            assert 90 <= p["leaf-1"].last.rtt_ms < 600
            assert p["display-1"].last.kind == "noanswer" and p[fv.name_of(D)].last.kind == "notsent"
            assert p[fv.name_of(E)].last.kind == "notsent" and "507 NO_CAPACITY" in p[fv.name_of(E)].last.detail
            assert (p[fv.name_of(E)].sent, p[fv.name_of(E)].notsent) == (0, 1)  # refused: never counted as sent
            assert (p[fv.name_of(D)].sent, p[fv.name_of(D)].notsent) == (0, 1)
            assert fake.get_ops == 4  # one GET per accepted operation, none for the refused one, no polling
        done = lines(next(tmp_path.glob("rec*/ping.ndjson")))
        results = {x["name"]: x["result"] for x in done if "result" in x}
        assert results == {"relay-1": "alive", "leaf-1": "alive", "display-1": "noanswer",
                           fv.name_of(D): "notsent", fv.name_of(E): "notsent"}

    asyncio.run(scenario())
    # what went on the wire: RECEIVED, FIFO, a UTC deadline of 3 s whatever the interval, round in the payload
    assert len(fake.posts) == 5
    for post in fake.posts:
        assert post["app_port"] == 211 and post["delivery"] == "RECEIVED" and post["queue_mode"] == "FIFO"
        assert post["deadline"]["mode"] == "utc" and "coalesce_key" not in post
        assert pr.ping_payload(1) == base64.b64decode(post["payload_b64"])


def test_the_ping_loop_runs_and_stops_and_refuses_a_load_the_host_would_refuse(fake: FakeHost, tmp_path: Path) -> None:
    for d in (A, B):
        fake.add_node(d, parent_device_id=ROOT)

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: len(fv.active_nodes()) == 2, "nodes")
            with pytest.raises(ValueError, match="at least 1 s"):
                await fv.start_ping_loop(0.5)
            await fv.start_ping_loop(1.0)
            await until(lambda: fv.ping.get(A) and fv.ping[A].alive >= 2 and fv.ping[B].alive >= 2, "two rounds", 8)
            assert fv.ping_status()["running"] is True and fv.round_no >= 2
            await fv.stop_ping_loop()
            rounds = fv.round_no
            await asyncio.sleep(1.3)
            assert fv.round_no == rounds and fv.ping_status()["running"] is False
            # many nodes at a short interval: refused with the interval that fits, nothing is sent
            for i in range(30):
                fake.add_node(f"{i:02x}" * 32, parent_device_id=ROOT)
            await until(lambda: len(fv.active_nodes()) == 32, "30 more nodes")
            posts = len(fake.posts)
            with pytest.raises(ValueError, match=r"need about \d+ requests/s.*use [\d.]+ s or more"):
                await fv.start_ping_loop(1.0)
            assert len(fake.posts) == posts and fv.ping_status()["running"] is False

    asyncio.run(scenario())
    assert fake.limiter.refused == {"principal": 0, "global": 0}


def test_many_nodes_are_paced_under_the_host_rate_limit(fake: FakeHost, tmp_path: Path) -> None:
    for i in range(40):
        fake.add_node(f"{i + 16:02x}" * 32, parent_device_id=ROOT)
        fake.responders[f"{i + 16:02x}" * 32] = {"mode": "apply", "rtt": 0.02}

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: len(fv.active_nodes()) == 40, "40 nodes")
            rnd = await fv.ping_round(3.0, max_wait=8.0)  # what "ping all now" does: paced, not a burst
            await until(lambda: rnd["open"] == 0, "the round ends", timeout=20)
            assert (rnd["alive"], rnd["notsent"], rnd["noanswer"]) == (40, 0, 0)
            assert fv.client.bucket.throttled > 0  # some requests had to wait for the laptop's own budget

    asyncio.run(scenario())
    assert fake.limiter.refused == {"principal": 0, "global": 0}  # the Host never had to say 429


def test_a_round_that_cannot_be_sent_in_time_is_not_sent_and_warns(fake: FakeHost, tmp_path: Path) -> None:
    for i in range(30):
        fake.add_node(f"{i + 16:02x}" * 32, parent_device_id=ROOT)

    async def scenario() -> None:
        async with view(fake, tmp_path, rps=8.0) as fv:
            await until(lambda: len(fv.active_nodes()) == 30, "30 nodes")
            rnd = await fv.ping_round(3.0, max_wait=0.3)
            await until(lambda: rnd["open"] == 0, "the round ends", timeout=15)
            assert rnd["notsent"] > 0 and rnd["alive"] > 0 and rnd["noanswer"] == 0  # local budget, never "no answer"
            assert any("budget" in w for w in fv.snapshot()["warnings"])
            assert sum(p.notsent for p in fv.ping.values()) == rnd["notsent"]
            assert all("budget" in p.last.detail for p in fv.ping.values() if p.last.kind == "notsent")

    asyncio.run(scenario())
    assert fake.limiter.refused == {"principal": 0, "global": 0}


def test_a_429_from_the_host_is_not_sent_and_stops_the_budget(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT)
    fake.responders[A] = {"mode": "refuse", "status": 429, "code": "RATE_LIMITED"}

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: fv.active_nodes(), "node")
            rnd = await fv.ping_round(3.0)
            assert (rnd["notsent"], rnd["noanswer"], rnd["alive"]) == (1, 0, 0)
            assert "HTTP 429" in fv.ping[A].last.detail

    asyncio.run(scenario())


# ---- display -------------------------------------------------------------------------------------------------------

def test_display_command_shows_arrived_and_drawn_apart(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(C, parent_device_id=ROOT)
    fake.add_node(B, parent_device_id=ROOT)
    fake.responders[C] = {"mode": "apply", "rtt": 0.6}

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            telemetry(fake, C, 1, role=3, flags=0b001)           # a display showing USABLE
            telemetry(fake, B, 1, role=1)
            await until(lambda: fv.display_nodes() == [C], "the display is known from telemetry")
            with pytest.raises(ValueError, match="display role"):
                await fv.send_display(B, "FORBID")
            entry = await fv.send_display(C, "FORBID")
            assert entry["state"] == "FORBID" and entry["op"] and not entry["arrived"] and not entry["drawn"]
            await until(lambda: fv.display[C]["arrived"], "arrived (END_RECEIVED)", 5)
            assert fv.display[C]["drawn"] is False and fv.display[C]["result"] == "pending"
            await until(lambda: fv.display[C]["result"] == "drawn", "drawn (APP_APPLIED)", 5)
            assert fv.display[C]["arrived_ms"] is not None and fv.display[C]["drawn_ms"] >= fv.display[C]["arrived_ms"]
            telemetry(fake, C, 2, role=3, flags=0b011, display_seq=entry["seq"])  # the node reports it back
            await until(lambda: fv.tele[C].last.display_state == "FORBID", "reported state")
            row = next(r for r in fv.snapshot()["nodes"] if r["device"] == C)
            assert (row["display_state"], row["display_seq"]) == ("FORBID", entry["seq"])
            second = await fv.send_display(C, "USABLE")
            assert second["seq"] == entry["seq"] + 1

    asyncio.run(scenario())
    post = fake.posts[0]
    assert post["app_port"] == 212 and post["delivery"] == "APPLIED" and post["storage"] == "VOLATILE"
    assert post["queue_mode"] == "FIFO" and post["priority"] == "NORMAL"
    raw = base64.b64decode(post["payload_b64"])
    assert raw[:2] == bytes([1, 1]) and len(raw) == 6  # version 1, FORBID, u32 command_seq
    events = [x["event"] for x in lines(next(tmp_path.glob("rec*/display.ndjson")))]
    assert events[:4] == ["posted", "arrived", "drawn", "final"]


def test_a_display_that_cannot_draw_answers_rejected(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(C, parent_device_id=ROOT)
    fake.responders[C] = {"mode": "app_reject", "rtt": 0.05}

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            telemetry(fake, C, 1, role=3)
            await until(lambda: fv.display_nodes() == [C], "display")
            await fv.send_display(C, "USABLE")
            await until(lambda: fv.display[C]["result"] == "rejected", "REJECTED", 5)
            assert fv.display[C]["arrived"] is True and fv.display[C]["drawn"] is False

    asyncio.run(scenario())


# ---- the picture: membership, parents, lost / back, reboots ----------------------------------------------------------

def test_joins_parent_changes_lost_back_and_reboots_reach_the_event_log(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT, root_depth=1)

    async def scenario() -> None:
        async with view(fake, tmp_path, interval_s=0.3) as fv:
            await until(lambda: fv.nodes_seen, "first listing")
            fake.add_node(B, parent_device_id=A, root_depth=2)
            await until(lambda: any(e["kind"] == "join" for e in fv.log), "join")
            fake.add_node(B, parent_device_id=ROOT, root_depth=1)
            await until(lambda: any(e["kind"] == "parent" for e in fv.log), "parent change")
            fake.add_node(B, membership="REVOKED", parent_device_id=ROOT, root_depth=1)
            await until(lambda: any(e["kind"] == "leave" for e in fv.log), "leave")
            telemetry(fake, A, 1, boot_count=3, interval_s=0)  # 0: the node names no interval, the assumed one counts
            await until(lambda: A in fv.tele and fv.tele[A].last_seen is not None, "telemetry")
            await until(lambda: any(e["kind"] == "lost" for e in fv.log), "node lost", 5)
            telemetry(fake, A, 2, boot_count=3, interval_s=0)
            await until(lambda: any(e["kind"] == "back" for e in fv.log), "node back")
            telemetry(fake, A, 1, boot_count=4, reset_reason=1, interval_s=0)
            await until(lambda: any(e["kind"] == "reboot" for e in fv.log), "reboot")
            snap = fv.snapshot()
            assert [e["kind"] for e in snap["events"] if e["kind"] in ("join", "parent", "leave", "lost", "back", "reboot")] \
                == ["join", "parent", "leave", "lost", "back", "reboot"]

    asyncio.run(scenario())
    events = lines(next(tmp_path.glob("rec*/events.ndjson")))
    assert {"join", "parent", "leave", "lost", "back", "reboot"} <= {e["kind"] for e in events}


def test_the_summary_is_written_every_period(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT, root_depth=1)

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            telemetry(fake, A, 1)
            await until(lambda: A in fv.tele, "telemetry")
            await asyncio.sleep(0.8)

    asyncio.run(scenario())
    rows = (next(tmp_path.glob("rec*/summary.csv"))).read_text().splitlines()
    assert rows[0].startswith("utc,name,device,depth,parent") and len(rows) >= 3
    assert all(r.split(",")[1] == "relay-1" for r in rows[1:])


def test_the_host_not_answering_is_a_warning_not_a_crash(tmp_path: Path) -> None:
    class Gone:
        socket = tmp_path / "nothing.sock"

    async def scenario() -> None:
        async with view(Gone(), tmp_path) as fv:  # type: ignore[arg-type]
            await until(lambda: "host" in fv.warnings, "the warning", 6)
            assert fv.snapshot()["host"]["ok"] is False

    asyncio.run(scenario())


# ---- the page --------------------------------------------------------------------------------------------------------

def test_the_page_and_its_api(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT, root_depth=1)
    fake.add_node(C, parent_device_id=A, root_depth=2)
    fake.responders[C] = {"mode": "apply", "rtt": 0.05}
    port_holder: dict[str, int] = {}

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            app = make_app(fv, 18091)
            server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
            task = asyncio.ensure_future(server.serve())
            await until(lambda: server.started, "web server")
            port_holder["port"] = server.servers[0].sockets[0].getsockname()[1]
            base = f"http://127.0.0.1:{port_holder['port']}"
            telemetry(fake, C, 1, role=3, depth=2, rssi=-70)
            await until(lambda: fv.display_nodes() == [C], "display known")
            local = {"Host": "127.0.0.1:18091"}  # the app expects its configured port in the Host header
            async with httpx.AsyncClient(base_url=base, headers=local) as c:
                page = await c.get("/")
                assert page.status_code == 200 and "LeanMesh field view" in page.text
                for url in ("/app.js", "/style.css"):
                    assert (await c.get(url)).status_code == 200
                # no external resource anywhere in the page, the script or the style
                blob = page.text + (await c.get("/app.js")).text + (await c.get("/style.css")).text
                assert "http://" not in blob.replace("http://www.w3.org/2000/svg", "")
                assert "https://" not in blob and "//cdn" not in blob and "@import" not in blob
                state = (await c.get("/api/state")).json()
                assert {n["name"] for n in state["nodes"]} == {"relay-1", "display-1"}
                assert state["tree"]["has_parent_info"] is True
                # the guard: no custom header, or another Host header, and nothing happens
                assert (await c.post("/api/ping/now")).status_code == 403
                assert (await c.get("/api/state", headers={"Host": "evil.example"})).status_code == 403
                ok = {"X-Fieldview": "1"}
                assert (await c.post("/api/ping/now", headers=ok)).status_code == 200
                bad = await c.post("/api/ping/loop", headers=ok, json={"action": "start", "interval_s": 0.2})
                assert bad.status_code == 409 and "at least 1 s" in bad.json()["error"]
                good = await c.post("/api/ping/loop", headers=ok, json={"action": "start", "interval_s": 2})
                assert good.status_code == 200 and good.json()["running"] is True
                assert (await c.post("/api/ping/loop", headers=ok, json={"action": "stop"})).json()["running"] is False
                shown = await c.post("/api/display", headers=ok, json={"device": C, "state": "USABLE"})
                assert shown.status_code == 200 and shown.json()["state"] == "USABLE"
                assert (await c.post("/api/display", headers=ok, json={"device": A, "state": "USABLE"})).status_code in (404, 409)
            server.should_exit = True
            await task

    asyncio.run(scenario())


# ---- a POST whose answer is lost (review finding 3) -------------------------------------------------------------------

def test_a_lost_post_answer_is_recovered_by_replaying_the_same_request(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT)
    fake.fault = {"mode": "after", "count": 1, "delay": 1.5}   # admitted, the answer never arrives in time

    async def scenario() -> None:
        async with view(fake, tmp_path, post_timeout=0.3) as fv:
            await until(lambda: fv.active_nodes(), "node")
            rnd = await fv.ping_round(3.0, max_wait=5.0)
            await until(lambda: rnd["open"] == 0, "the round ends", 10)
            assert (rnd["alive"], rnd["notsent"], rnd["unknown"]) == (1, 0, 0)
            assert fv.ping[A].unknown == 0 and fv.ping[A].sent == 1

    asyncio.run(scenario())
    assert len(fake.posts) == 1 and fake.replays >= 1       # one admission; the retry got the stored operation
    assert len({k for k in fake.keys}) == 1                 # the replay used the key of the first request


def test_a_post_that_is_never_answered_is_unknown_not_notsent(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT)
    fake.add_node(C, parent_device_id=ROOT)
    fake.fault = {"mode": "blackhole", "count": 20, "delay": 1.0}   # admitted; no answer, to the replays neither

    async def scenario() -> None:
        async with view(fake, tmp_path, post_timeout=0.2) as fv:
            await until(lambda: len(fv.active_nodes()) == 2, "nodes")
            rnd = await fv.ping_round(3.0, max_wait=5.0)
            assert (rnd["unknown"], rnd["notsent"], rnd["noanswer"], rnd["alive"]) == (2, 0, 0, 0)
            assert rnd["open"] == 0 and "post-unknown" in fv.warnings
            for d in (A, C):
                t = fv.ping[d]
                assert (t.unknown, t.notsent, t.noanswer, t.sent, t.last.kind) == (1, 0, 0, 0, "unknown")
            assert fv.pending == {}
            telemetry(fake, C, 1, role=3)
            await until(lambda: fv.display_nodes() == [C], "display known")
            entry = await fv.send_display(C, "FORBID")
            assert entry["result"] == "unknown" and entry["op"] is None
            assert "may have been admitted" in entry["detail"]

    asyncio.run(scenario())
    assert fake.replays >= 4                                 # every unknown POST was replayed with its key
    recs = lines(next(tmp_path.glob("rec*/ping.ndjson")))
    unknown = [x for x in recs if x.get("result") == "unknown"]
    assert len(unknown) == 2 and all(x["idempotency_key"] in fake.keys for x in unknown)
    shown = [x for x in lines(next(tmp_path.glob("rec*/display.ndjson"))) if x["event"] == "unknown"]
    assert len(shown) == 1 and shown[0]["idempotency_key"] in fake.keys


def test_a_post_the_host_never_received_is_still_unknown_after_the_replays_fail(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT)
    fake.fault = {"mode": "before", "count": 10, "delay": 1.0}   # lost on the way: never admitted, but we cannot know

    async def scenario() -> None:
        async with view(fake, tmp_path, post_timeout=0.2) as fv:
            await until(lambda: fv.active_nodes(), "node")
            rnd = await fv.ping_round(3.0, max_wait=5.0)
            assert (rnd["unknown"], rnd["notsent"]) == (1, 0)

    asyncio.run(scenario())
    assert fake.posts == []


def test_failures_before_anything_was_sent_are_not_unknown(tmp_path: Path) -> None:
    async def scenario() -> None:
        client = HostClient(str(tmp_path / "nothing.sock"), TOKEN, DOMAIN)
        try:
            with pytest.raises(HostUnreachable) as info:
                await client.post_message({"x": 1}, max_wait=1.0)
            assert not isinstance(info.value, SendUnknown) and info.value.maybe_sent is False
        finally:
            await client.aclose()

    asyncio.run(scenario())


def test_an_answer_is_the_end_of_the_doubt_a_refusal_is_not_unknown(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT)
    fake.responders[A] = {"mode": "refuse", "status": 507, "code": "NO_CAPACITY"}

    async def scenario() -> None:
        async with view(fake, tmp_path, post_timeout=0.2) as fv:
            await until(lambda: fv.active_nodes(), "node")
            rnd = await fv.ping_round(3.0)
            assert (rnd["notsent"], rnd["unknown"]) == (1, 0)

    asyncio.run(scenario())
    assert fake.replays == 0


# ---- the ACK follows the records (review finding 1) -------------------------------------------------------------------

def test_events_are_not_acknowledged_before_their_records_are_on_disk(
        fake: FakeHost, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "ACK_EVERY_S", 0.1)
    fake.add_node(A, parent_device_id=ROOT)

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: not fv._backlog, "the backlog is read")
            base = fake.acks.get("fieldview", 0)
            fv.rec.sync = lambda timeout=5.0: False          # the disk does not confirm (fsync fails / hangs)
            for seq in (1, 2, 3):
                telemetry(fake, A, seq)
            await until(lambda: A in fv.tele and fv.tele[A].received == 3, "telemetry read")
            await asyncio.sleep(0.6)                          # several ack periods
            assert fake.acks.get("fieldview", 0) == base       # nothing acknowledged
            assert "ack-records" in fv.warnings and fv.ack_pending
            del fv.rec.sync                                    # the disk is fine again
            await until(lambda: fake.acks.get("fieldview") == len(fake.events), "the ack catches up")
            assert "ack-records" not in fv.warnings and not fv.ack_pending

    asyncio.run(scenario())


def test_lost_record_lines_hold_the_ack_until_an_explicit_gap_record_is_on_disk(
        fake: FakeHost, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "ACK_EVERY_S", 0.1)
    fake.add_node(A, parent_device_id=ROOT)
    blocker = tmp_path / "blocked"
    blocker.write_text("a file where the records directory should be")   # every write fails

    async def scenario() -> None:
        async with view(fake, tmp_path, rec_dir=blocker / "sub") as fv:
            await until(lambda: not fv._backlog, "the backlog is read")
            for seq in (1, 2):
                telemetry(fake, A, seq)
            await until(lambda: A in fv.tele and fv.tele[A].received == 2, "telemetry read")
            await asyncio.sleep(0.6)
            assert fake.acks.get("fieldview", 0) == 0 and fv.rec.lost >= 2   # records lost: events stay with the Host
            assert any("cannot" in w for w in fv.warnings.values())
            blocker.unlink()                                                  # the disk comes back
            (tmp_path / "blocked").mkdir()
            (tmp_path / "blocked" / "sub").mkdir()
            await until(lambda: fake.acks.get("fieldview") == len(fake.events), "acknowledged after the gap record", 10)
            assert fv.rec.lost == 0 and "records-gap" in fv.warnings          # explicit and persistent

    asyncio.run(scenario())
    events = lines(tmp_path / "blocked" / "sub" / "events.ndjson")
    gaps = [e for e in events if e["kind"] == "recorder-gap"]
    assert len(gaps) == 1 and "record line(s) were lost" in gaps[0]["text"]


def test_a_page_with_a_final_operation_is_not_acknowledged_before_its_result_is_read(
        fake: FakeHost, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "ACK_EVERY_S", 0.1)
    fake.add_node(A, parent_device_id=ROOT)
    fake.responders[A] = {"mode": "silent", "after": 0.3}
    fake.get_delay = 1.0                                      # reading the result takes a second

    def final_seq() -> int:
        return next((i + 1 for i, e in enumerate(fake.events) if e["kind"] == "OPERATION_UPDATE"
                     and e["evidence"]["details"]["state"] == "FINAL"), 0)

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: fv.active_nodes() and not fv._backlog, "node")
            rnd = await fv.ping_round(3.0)
            seq = await until(final_seq, "the FINAL event")
            await until(lambda: fv.cursor and int(fv.cursor.rpartition(":")[2]) >= seq, "the FINAL event is read")
            await asyncio.sleep(0.5)                          # several ack periods; the GET is still on its way
            assert fv.pending and rnd["open"] == 1
            assert fake.acks.get("fieldview", 0) < seq        # the page of the FINAL event waits for the result
            await until(lambda: rnd["open"] == 0, "the result is read", 10)
            await until(lambda: fake.acks.get("fieldview", 0) >= seq, "then it is acknowledged")

    asyncio.run(scenario())
    rec = lines(next(tmp_path.glob("rec*/ping.ndjson")))
    assert [x for x in rec if x.get("event") == "posted"] and any(x.get("result") == "noanswer" for x in rec)


# ---- client epochs rotate so the Host can prune (review finding 2) ------------------------------------------------------

def test_epochs_rotate_and_the_old_one_is_closed_when_its_operations_are_final(
        fake: FakeHost, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "EPOCH_ROTATE_OPS", 3)
    monkeypatch.setattr(engine_mod, "EPOCH_CLOSE_MARGIN_S", 0.1)
    fake.add_node(A, parent_device_id=ROOT)
    fake.add_node(C, parent_device_id=ROOT)
    fake.responders[A] = fake.responders[C] = {"mode": "apply", "rtt": 1.0}   # operations stay open for a second
    e1, e2 = hex_id(0xE1), hex_id(0xE2)

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: len(fv.active_nodes()) == 2, "nodes")
            for _ in range(2):
                await fv.ping_round(3.0)
            assert fake.epochs == 1 and fv.epoch == e1
            rnd = await fv.ping_round(3.0)                               # the epoch has served 4 requests: a new one
            assert fake.epochs == 2 and fv.epoch == e2
            await asyncio.sleep(0.4)
            assert fake.epoch_state[e1] == "OPEN"                         # its operations are still in flight
            await until(lambda: rnd["open"] == 0 and fake.epoch_state[e1] == "CLOSED", "the old epoch is closed", 8)
            assert fake.epoch_state[e2] == "OPEN"

    asyncio.run(scenario())
    assert [p["client_epoch"] for p in fake.posts] == [e1, e1, e1, e1, e2, e2]
    assert set(fake.epoch_state.values()) == {"CLOSED"}                   # a graceful stop closes the last one too


def test_a_long_ping_loop_never_holds_more_than_a_few_epochs_open(
        fake: FakeHost, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "EPOCH_ROTATE_OPS", 1)
    monkeypatch.setattr(engine_mod, "EPOCH_CLOSE_MARGIN_S", 0.05)
    fake.add_node(A, parent_device_id=ROOT)
    most = 0

    async def scenario() -> None:
        nonlocal most
        async with view(fake, tmp_path) as fv:
            await until(lambda: fv.active_nodes(), "node")
            for _ in range(15):
                rnd = await fv.ping_round(3.0)
                await until(lambda: rnd["open"] == 0, "the round ends", 5)
                await asyncio.sleep(0.15)
                most = max(most, sum(1 for v in fake.epoch_state.values() if v == "OPEN"))
            assert fake.epochs == 15 and most <= 3
            assert len(fv._tracked) <= 3 and len(fv._retiring) <= 2

    asyncio.run(scenario())
    assert most < 15 and set(fake.epoch_state.values()) == {"CLOSED"}


def test_epochs_a_crashed_run_left_open_are_closed_at_the_next_start(fake: FakeHost, tmp_path: Path) -> None:
    left = [hex_id(0xAA), hex_id(0xAB)]
    for e in left:
        fake.epoch_state[e] = "OPEN"                                      # opened by the run that crashed
    state = tmp_path / f"epochs-fieldview-{DOMAIN[:8]}.json"
    state.write_text(json.dumps({"domain": DOMAIN, "consumer": "fieldview",
                                 "epochs": [*left, hex_id(0xFF)]}))      # 0xFF: the Host forgot it

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: all(fake.epoch_state[e] == "CLOSED" for e in left), "stale epochs closed")
            await until(lambda: not fv._tracked, "the state file is empty")
            epoch = await fv.ensure_epoch()                               # this run's own epoch is on file before use
            assert json.loads(state.read_text())["epochs"] == [epoch]

    asyncio.run(scenario())
    assert json.loads(state.read_text())["epochs"] == []
    assert any("left open by an earlier run" in e["text"] for e in lines(next(tmp_path.glob("rec*/events.ndjson"))))


def test_a_lost_answer_to_the_epoch_open_is_replayed_and_gives_the_same_epoch(fake: FakeHost, tmp_path: Path) -> None:
    fake.epoch_fault = 1

    async def scenario() -> None:
        async with view(fake, tmp_path, post_timeout=0.3) as fv:
            assert await fv.ensure_epoch() == hex_id(0xE1)
            assert fake.epochs == 1                                       # not a second epoch left open

    asyncio.run(scenario())


def test_a_replayed_request_keeps_its_epoch_and_holds_it_open_across_a_rotation(
        fake: FakeHost, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "EPOCH_ROTATE_OPS", 1)
    monkeypatch.setattr(engine_mod, "EPOCH_CLOSE_MARGIN_S", 0.05)
    fake.add_node(A, parent_device_id=ROOT)
    fake.add_node(C, parent_device_id=ROOT)
    fake.fault = {"mode": "after", "count": 1, "delay": 1.5}              # the first answer is lost; its replay is due soon
    e1, e2 = hex_id(0xE1), hex_id(0xE2)

    async def scenario() -> None:
        async with view(fake, tmp_path, post_timeout=0.3) as fv:
            await until(lambda: len(fv.active_nodes()) == 2, "nodes")
            first = asyncio.ensure_future(fv.ping_round(3.0))             # A and C: one of them meets the fault
            await asyncio.sleep(0.15)
            second = await fv.ping_round(3.0)                             # rotates to a new epoch meanwhile
            assert fv.epoch == e2
            await asyncio.sleep(0.2)
            assert fake.epoch_state[e1] == "OPEN"                         # the retry of a request of e1 is still due
            rnd = await first
            await until(lambda: rnd["open"] == 0 and second["open"] == 0, "both rounds end", 10)
            assert (rnd["alive"], rnd["unknown"], rnd["notsent"]) == (2, 0, 0)
            await until(lambda: fake.epoch_state[e1] == "CLOSED", "e1 is closed after its operations ended")

    asyncio.run(scenario())
    assert fake.replays >= 1
    assert {op["epoch"] for op in fake.ops.values()} <= {e1, e2} and fake.posts[0]["client_epoch"] == e1


# ---- pings: RECEIVED, 3 s, at most 3 open per node (review finding 7) -------------------------------------------------

def test_a_node_with_three_open_pings_is_skipped_not_piled_up(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT)
    fake.add_node(B, parent_device_id=ROOT)
    fake.responders[A] = {"mode": "silent", "after": 2.0}          # a dead node: its pings stay open until the deadline
    fake.responders[B] = {"mode": "apply", "rtt": 0.02}

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: len(fv.active_nodes()) == 2, "nodes")
            rounds = []
            for _ in range(5):                                        # a loop whose pings to A last 2 s
                rounds.append(await fv.ping_round(1.0))
                await asyncio.sleep(0.3)
            posted_to_a = [p for p in fake.posts if p["destination"]["device_id"] == A]
            assert len(posted_to_a) == 3                              # the 4th and 5th round did not post to A
            assert [r["skipped"] for r in rounds] == [0, 0, 0, 1, 1]
            assert fv.ping[A].skipped == 2 and fv.ping[A].last.kind == "skipped" and "busy" in fv.ping[A].last.detail
            assert fv._open_pings[A] == 3 and fv.ping_status()["open"] <= 3 + 2
            # skipped is its own class: not sent, not lost, nothing counted as RF loss
            assert (fv.ping[A].notsent, fv.ping[A].noanswer, fv.ping[A].unknown) == (0, 0, 0)
            await until(lambda: all(r["open"] == 0 for r in rounds), "all rounds end", 10)
            assert fv.ping[A].noanswer == 3 and fv.ping[A].sent == 3 and fv.ping[B].alive == 5
            assert fv._open_pings == {}                               # nothing stays counted open
            rnd = await fv.ping_round(1.0)                            # free again
            assert rnd["skipped"] == 0 and len([p for p in fake.posts if p["destination"]["device_id"] == A]) == 4
            await until(lambda: rnd["open"] == 0, "the round ends", 10)

    asyncio.run(scenario())
    skipped = [x for x in lines(next(tmp_path.glob("rec*/ping.ndjson"))) if x.get("result") == "skipped"]
    assert len(skipped) == 2 and all(x["op"] is None for x in skipped)


def test_a_ping_is_alive_when_the_operation_ends_received(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT)
    fake.responders[A] = {"mode": "apply", "rtt": 0.05, "observed": True}

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: fv.active_nodes(), "node")
            rnd = await fv.ping_round(1.0)
            await until(lambda: rnd["open"] == 0, "the round ends")
            assert (rnd["alive"], fv.ping[A].last.rtt_ms, fv.ping[A].last.rtt_src) == (1, 50, "root")

    asyncio.run(scenario())
    (post,) = fake.posts
    assert post["delivery"] == "RECEIVED" and post["queue_mode"] == "FIFO" and post["storage"] == "VOLATILE"
    done = [x for x in lines(next(tmp_path.glob("rec*/ping.ndjson"))) if x.get("result") == "alive"]
    assert done[0]["outcome"] == "RECEIVED" and done[0]["evidence"] == ["END_RECEIVED", "ROOT_ACCEPTED", "ROOT_SENT"]


# ---- late evidence, overlapping display commands, bounded tables (review findings 4, 5) --------------------------------

def test_an_answer_the_host_shows_after_the_final_result_is_recorded_as_late_beside_it(
        fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT)
    fake.responders[A] = {"mode": "silent", "after": 0.3}          # FINAL EXPIRED: no answer on time

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: fv.active_nodes(), "node")
            rnd = await fv.ping_round(3.0)
            await until(lambda: rnd["open"] == 0, "the round ends", 5)
            assert (rnd["noanswer"], rnd["alive"], rnd["late"], fv.ping[A].noanswer, fv.ping[A].late) == (1, 0, 0, 1, 0)
            (op_id,) = fake.ops
            fake.amend(op_id, "RECEIVED", "END_RECEIVED")             # the receipt reached the Host after the deadline
            await until(lambda: fv.ping[A].late == 1, "the late answer is seen", 5)
            assert (rnd["noanswer"], rnd["alive"], rnd["late"]) == (1, 0, 1)   # the on-time result is not rewritten
            assert fv.ping[A].noanswer == 1 and fv.ping[A].alive == 0 and fv.ping[A].last.kind == "noanswer"
            assert any(e["kind"] == "late" and "noanswer" in e["text"] for e in fv.log)
            gets = fake.get_ops
            fake.amend(op_id, "RECEIVED", "APP_APPLIED")              # more news: not counted twice
            await asyncio.sleep(0.5)
            assert fv.ping[A].late == 1 and fake.get_ops == gets      # an answered operation is not read again

    asyncio.run(scenario())
    recs = lines(next(tmp_path.glob("rec*/ping.ndjson")))
    late = [x for x in recs if x.get("event") == "late"]
    assert len(late) == 1 and late[0]["on_time"] == "noanswer" and late[0]["late_result"] == "alive"
    assert [x["result"] for x in recs if "result" in x and "event" not in x] == ["noanswer"]


def test_an_operation_given_up_on_is_still_read_when_the_host_reports_it_later(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(A, parent_device_id=ROOT)
    fake.responders[A] = {"mode": "silent", "after": 60.0}         # the Host does not finish it in time

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: fv.active_nodes(), "node")
            rnd = await fv.ping_round(3.0)
            (p,) = fv.pending.values()
            p.deadline -= 20.0                                      # the safety net gives up (deadline + 8 s have passed)
            await until(lambda: rnd["open"] == 0, "gave up", 5)
            assert rnd["noanswer"] == 1
            (op_id,) = fake.ops
            fake.ops[op_id].update(state="FINAL")
            fake.amend(op_id, "RECEIVED", "END_RECEIVED")
            await until(lambda: fv.ping[A].late == 1, "late", 5)
            assert fv.ping[A].noanswer == 1

    asyncio.run(scenario())


def test_overlapping_display_commands_each_keep_their_own_evidence_and_result(fake: FakeHost, tmp_path: Path) -> None:
    fake.add_node(C, parent_device_id=ROOT)
    fake.responders[C] = {"mode": "apply", "rtt": 0.6}

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            telemetry(fake, C, 1, role=3)
            await until(lambda: fv.display_nodes() == [C], "display known")
            first = await fv.send_display(C, "FORBID")
            second = await fv.send_display(C, "USABLE")              # A is still in flight when B replaces it on the page
            assert fv.display[C] is second and first["op"] != second["op"]
            await until(lambda: first["result"] == "drawn" and second["result"] == "drawn", "both are drawn", 10)
            assert first["arrived"] and first["drawn"] and second["arrived"] and second["drawn"]
            assert fv.display[C] is second and fv.pending == {}

    asyncio.run(scenario())
    recs = lines(next(tmp_path.glob("rec*/display.ndjson")))
    finals = {x["op"]: x for x in recs if x["event"] == "final"}
    assert len(finals) == 2 and {x["result"] for x in finals.values()} == {"drawn"}
    assert sorted(x["seq"] for x in finals.values()) == sorted(x["seq"] for x in recs if x["event"] == "posted")
    assert sorted(x["latest"] for x in finals.values()) == [False, True]       # only the page's own view differs
    for event in ("arrived", "drawn"):
        assert len([x for x in recs if x["event"] == event]) == 2


def test_the_tables_stay_bounded_in_a_long_session(
        fake: FakeHost, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "FINISHED_KEEP", 20)
    fake.add_node(A, parent_device_id=ROOT)
    fake.responders[A] = {"mode": "apply", "rtt": 0.01}

    async def scenario() -> None:
        async with view(fake, tmp_path) as fv:
            await until(lambda: fv.active_nodes(), "node")
            for _ in range(60):
                await fv.ping_round(1.0)
                await asyncio.sleep(0.06)
            await until(lambda: not fv.pending, "all final", 5)
            assert fv.ping[A].alive + fv.ping[A].skipped == 60 and fv.ping[A].alive >= 50
            assert len(fv.finished) <= 20 and len(fv._round_of) <= 40 and len(fv.rounds) <= 30
            assert len(fv.ping[A].history) <= 20 and len(fv.ping[A].rtts) <= 200
            assert not fv._open_pings and not fv._epoch_users and len(fv.final_hint) <= 4096

    asyncio.run(scenario())
