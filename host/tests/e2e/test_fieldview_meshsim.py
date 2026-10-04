"""tools/fieldview against the REAL Host and a meshsim root with a joined member (no fake): the telemetry the member
sends to the root application (app port 210) arrives as MESSAGE_RECEIVED events and is read by cursor with ACK; a ping and
a display command go out through POST /v1/messages (UTC deadline, FIFO) and are followed by the Host's events.
Protocol bench only: a pty is not USB and sim time is not timing evidence, so the RTT here proves the path, not a number."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from bridge_bench import Bench, db_rows
from harness import REPO_ROOT, MeshSim

sys.path.insert(0, str(REPO_ROOT))

from tools.fieldview import protocol as pr  # noqa: E402
from tools.fieldview.engine import Config, FieldView  # noqa: E402
from tools.fieldview.hostclient import HostClient  # noqa: E402
from tools.fieldview.recorder import Recorder  # noqa: E402


@pytest.fixture
def bench(meshsim: Callable[..., MeshSim], tmp_path: Path):  # type: ignore[no-untyped-def]
    made: list[Bench] = []

    def make(seed: int, **kw: object) -> Bench:
        b = Bench.build(meshsim, tmp_path, seed=seed, **kw)  # type: ignore[arg-type]
        made.append(b)
        return b

    yield make
    for b in made:
        b.close()


class Member:
    """The joined member's application, driven through meshsim's synchronous command line (one command at a time)."""

    def __init__(self, b: Bench) -> None:
        self.b = b
        self.lock = asyncio.Lock()
        self.mode = "apply"       # apply | reject | ignore: what the member's application does with a ping / display command
        self.seen: list[int] = []

    async def cmd(self, line: str) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(self.b.sim.cmd, line)

    async def telemetry(self, **kw: Any) -> None:
        now_ms = int((await self.cmd("status"))["now_us"]) // 1000
        payload = pr.encode_telemetry(**kw).hex()
        r = await self.cmd(f"send 1 root best_effort volatile 210 1 {now_ms + 60_000} {payload}")
        assert r.get("ok") and r["status"] == "OK", r

    async def nodelog(self, *records: tuple[int, int, int, bytes]) -> None:
        """One node event log message (§3.4, app port 213) to the root application."""
        now_ms = int((await self.cmd("status"))["now_us"]) // 1000
        payload = pr.encode_nodelog(list(records)).hex()
        r = await self.cmd(f"send 1 root best_effort volatile {pr.NODELOG_PORT} 1 {now_ms + 60_000} {payload}")
        assert r.get("ok") and r["status"] == "OK", r

    async def app(self) -> None:
        """Takes the messages the member receives and answers the ping / display ports as `mode` says."""
        while True:
            ev = (await self.cmd("msg-next 1")).get("event")
            if ev and ev["kind"] == 2 and ev["port"] in (pr.PING_PORT, pr.DISPLAY_PORT) and self.mode != "ignore":
                self.seen.append(ev["port"])
                await self.cmd(f"msg-report 1 {'applied' if self.mode == 'apply' else 'rejected'} -")
            await asyncio.sleep(0.05)


async def until(pred: Callable[[], Any], what: str, timeout: float = 30.0) -> Any:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = pred()
        if value:
            return value
        await asyncio.sleep(0.05)
    raise AssertionError(f"timeout ({timeout}s) waiting for {what}")


@pytest.mark.e2e
def test_fieldview_reads_telemetry_pings_and_drives_a_display_through_the_real_host(
        bench: Callable[..., Bench], tmp_path: Path) -> None:
    b = bench(41)
    b.link_and_routes()
    host = b.start_host()
    b.await_root()
    node = b.node

    async def scenario() -> dict[str, Any]:
        cfg = Config(socket=str(host.socket), token=host.token, domain=b.domain, logs_dir=tmp_path,
                     names={node: "member-1"}, nodes_poll_s=0.5, events_wait_ms=1000, tick_s=0.2, summary_s=1.0)
        client = HostClient(cfg.socket, cfg.token, cfg.domain)
        rec = Recorder(tmp_path / "fieldview")
        fv = FieldView(cfg, client, rec)
        member = Member(b)
        await fv.start()
        app = asyncio.ensure_future(member.app())
        found: dict[str, Any] = {}
        try:
            await until(lambda: not fv._backlog and fv.api_nodes.get(node, {}).get("membership") == "ACTIVE", "ACTIVE member")
            # telemetry: sequence 1, 2, 4 (3 is never sent): one message missing
            for seq in (1, 2, 4):
                await member.telemetry(seq=seq, uptime_s=seq * 10, role=3, chip=1, depth=1, rssi=-71)
            await until(lambda: node in fv.tele and fv.tele[node].received == 3, "three telemetry messages")
            assert (fv.tele[node].lost, fv.tele[node].last.parent_rssi_dbm) == (1, -71)
            # node log (§3.4): a BOOT with an SDK restart cause and a REACHABLE; record 3 never arrives
            await member.nodelog(
                (pr.T_BOOT, 1, 20, pr.nodelog_payload(pr.T_BOOT, reset_reason=2, sdk_restart_cause=1, boot_count=7,
                                                      prev_uptime_ms=52_300, detail_ms=3012)),
                (pr.T_REACHABLE, 2, 8400, pr.nodelog_payload(pr.T_REACHABLE, depth=1, parent_rssi_dbm=-71)),
                (pr.T_RADIO, 4, 9000, pr.nodelog_payload(pr.T_RADIO, tx_done_max_ms=1350, tx_late=2, tx_stall_waits=0)))
            await until(lambda: node in fv.nodelog and fv.nodelog[node].radio, "the node log")
            nrow = {r["device"]: r for r in fv.snapshot()["nodes"]}[node]
            found["nodelog"] = (nrow["boot_cause"], nrow["attach_s"], nrow["tx_done_max_ms"], nrow["records_lost"])
            assert found["nodelog"] == ("software; SDK: radio stall (TX completion never came)", 8.4, 1350, 1)
            # ping: delivery RECEIVED, the SDK's end-to-end receipt makes it alive (END_RECEIVED)
            rnd = await fv.ping_round(5.0)
            await until(lambda: rnd["open"] == 0, "the ping ends")
            ping = fv.ping[node]
            found["alive"] = (ping.last.kind, ping.last.rtt_ms, ping.last.rtt_src)
            assert ping.last.kind == "alive" and ping.last.rtt_ms is not None
            # ping: the application stays silent. A RECEIVED ping does not need it (§3.2: the node application's liveness
            # is shown by its telemetry), so the node is still alive
            member.mode = "ignore"
            rnd = await fv.ping_round(3.0)
            await until(lambda: rnd["open"] == 0, "the ping of a silent application ends", 40)
            found["app_silent"] = (ping.last.kind, ping.last.detail)
            assert ping.last.kind == "alive", ping.last
            # display: the member reports role 3 in its telemetry; it has the frame, then draws it
            member.mode = "apply"
            entry = await fv.send_display(node, "FORBID")
            await until(lambda: fv.display[node]["result"] == "drawn", "the display command is drawn", 40)
            assert entry["arrived"] is True and entry["drawn"] is True
            found["display"] = (entry["arrived_ms"], entry["drawn_ms"])
            await member.telemetry(seq=5, uptime_s=50, role=3, flags=0b011, display_seq=entry["seq"])
            await until(lambda: fv.tele[node].last.display_state == "FORBID", "reported display state")
            # the consumer's ACK reached the Host: a restart would resume after what was read
            await until(lambda: not fv.ack_pending, "acknowledged", 10)
            found["cursor"] = fv.cursor
            found["warnings"] = fv.snapshot()["warnings"]
        finally:
            app.cancel()
            await fv.stop()
            await client.aclose()
        return found

    found = asyncio.run(scenario())
    print("fieldview e2e:", found)
    assert found["warnings"] == []
    logged = [json.loads(x) for x in (tmp_path / "fieldview" / "nodelog.ndjson").read_text().splitlines()]
    assert [x["type"] for x in logged] == ["BOOT", "REACHABLE", "RADIO"] and logged[0]["boot_count"] == 7
    # what the real Host was sent: FIFO RECEIVED / APPLIED with a UTC deadline (the LATEST form would have been refused)
    ops = [r for r in (tmp_path / "fieldview" / "ping.ndjson").read_text().splitlines() if '"result"' in r]
    assert len(ops) == 2
    acked = db_rows(b.host.db, "SELECT name, ack_sequence FROM consumers")  # the Host kept our place
    assert len(acked) == 1 and acked[0][0] == "fieldview" and acked[0][1] >= 1
