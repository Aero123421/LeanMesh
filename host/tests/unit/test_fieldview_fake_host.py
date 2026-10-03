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
from fieldview_fake import DOMAIN, ROOT, TOKEN, FakeHost

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from tools.fieldview import protocol as pr  # noqa: E402
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
    config = Config(socket=str(fake.socket), token=TOKEN, domain=DOMAIN, logs_dir=tmp, root_id=ROOT,
                    names={A: "relay-1", B: "leaf-1", C: "display-1"}, **cfg)
    client = HostClient(config.socket, TOKEN, DOMAIN, rps=rps, post_timeout=post_timeout)
    rec = Recorder(tmp / f"rec{len(list(tmp.glob('rec*')))}")
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
            fv._ack_dirty = False
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
        A: {"mode": "apply", "rtt": 0.06, "observed": True},   # root clock evidence: RTT = APP_APPLIED - ROOT_SENT
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
    # what went on the wire: FIFO APPLIED, UTC deadline min(interval, 3 s), round in the payload
    assert len(fake.posts) == 5
    for post in fake.posts:
        assert post["app_port"] == 211 and post["delivery"] == "APPLIED" and post["queue_mode"] == "FIFO"
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
