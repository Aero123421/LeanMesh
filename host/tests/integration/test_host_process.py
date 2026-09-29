"""Real uvicorn process: kill at transaction boundaries (H01), a stalled SSE subscriber (H06),
and the singleton lock across processes (H07)."""

from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx2 as httpx
import pytest
from host_util import DOMAIN, HERE, NODE, HostProc, auth, check, message, rows

pytestmark = pytest.mark.e2e


@pytest.fixture
def workdir(tmp_path: Path) -> Iterator[Path]:
    yield tmp_path


def seeded(workdir: Path, crash: str | None = None, **limits: str) -> HostProc:
    """Start once to create the schema, seed a domain + node (test setup only), restart armed."""
    proc = HostProc(workdir).start()
    proc.stop()
    conn = sqlite3.connect(workdir / "host.db")
    conn.execute("INSERT INTO domains(id,root_device) VALUES(?,?)", (bytes.fromhex(DOMAIN), bytes(32)))
    conn.execute("INSERT INTO nodes VALUES(?,?,1,1,'ACTIVE','REACHABLE',NULL,1,'{}')",
                 (bytes.fromhex(DOMAIN), bytes.fromhex(NODE)))
    conn.commit()
    conn.close()
    return HostProc(workdir, crash=crash, **limits).start()


def open_epoch(c: httpx.Client) -> str:
    r = c.post("/v1/epochs", json={"request_id": "ab" * 16}, headers={**auth("alice"), "Idempotency-Key": "e"})
    assert r.status_code == 201
    return str(r.json()["id"])


def post(c: httpx.Client, epoch: str, key: str, **over: object) -> httpx.Response:
    return c.post("/v1/messages", json=message(epoch, **over), headers={**auth("alice"), "Idempotency-Key": key})


@pytest.mark.scenario("H01")
@pytest.mark.parametrize("stage", ["before_commit", "after_commit"])
def test_kill_at_the_commit_boundary_then_repost_yields_one_operation(workdir: Path, stage: str) -> None:
    proc = seeded(workdir, crash=stage)
    try:
        with proc.client() as c:
            epoch = open_epoch(c)
            with pytest.raises(httpx.TransportError):  # no 202 can have been sent
                post(c, epoch, "k")
        assert proc.wait_dead() == 9
        stored = rows(workdir / "host.db", "SELECT id FROM operations")
        assert len(stored) == (0 if stage == "before_commit" else 1)  # 202 only ever follows COMMIT
        assert rows(workdir / "host.db", "SELECT COUNT(*) FROM outbox")[0][0] == len(stored)
        proc = HostProc(workdir).start()
        with proc.client() as c:
            again = post(c, epoch, "k")
            check("submit_message", again)
            assert again.status_code == 202 and again.json()["state"] == "HOST_COMMITTED"
            if stored:
                assert bytes.fromhex(again.json()["id"]) == bytes(stored[0][0])
            assert post(c, epoch, "k").json() == again.json()
        assert rows(workdir / "host.db", "SELECT COUNT(*) FROM operations")[0][0] == 1
        assert rows(workdir / "host.db", "SELECT COUNT(*) FROM outbox WHERE state='QUEUED'")[0][0] == 1
        assert rows(workdir / "host.db", "SELECT COUNT(*) FROM events WHERE operation IS NOT NULL")[0][0] == 1
    finally:
        proc.stop()


@pytest.mark.scenario("H06")
def test_stalled_sse_subscriber_does_not_block_others_and_state_stays_bounded(workdir: Path) -> None:
    proc = seeded(workdir, T_MAX_EVENTS="200")
    telemetry = dict(delivery="BEST_EFFORT", storage="VOLATILE",
                     deadline={"mode": "root", "root_term": 1, "expires_root_ms": "9"})
    slow = socket.socket(socket.AF_UNIX)
    try:
        slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        slow.connect(str(proc.sock))
        slow.sendall((f"GET /v1/events/stream?domain_id={DOMAIN} HTTP/1.1\r\nHost: x\r\n"
                      f"Authorization: Bearer tok-alice\r\n\r\n").encode())
        with proc.client(timeout=5) as c:
            epoch = open_epoch(c)
            started = time.monotonic()
            ids = []
            for i in range(700):  # far more than the socket buffers of the stalled reader can hold
                r = post(c, epoch, f"t{i}", **telemetry)
                assert r.status_code == 202
                ids.append(r.json()["id"])
            assert time.monotonic() - started < 60
            page = c.get("/v1/events", params={"domain_id": DOMAIN, "limit": 200}, headers=auth("alice"))
            check("read_events", page)
            assert 0 < len(page.json()["events"]) <= 200
            assert c.get("/v1/operations/" + ids[-1], headers=auth("alice")).status_code == 200
        assert rows(workdir / "host.db", "SELECT COUNT(*) FROM events")[0][0] <= 200  # bounded journal
        # the stalled reader resumes: it is still served, in order, and sees the loss inline
        slow.settimeout(10)
        seen = b""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and ids[-1].encode() not in seen:
            seen += slow.recv(65536)
        assert ids[-1].encode() in seen and b"event: EVENT_GAP" in seen
        cursors = [int(x.split(b":")[-1]) for x in seen.split(b"\n") if x.startswith(b"id: ")]
        assert cursors == sorted(cursors)
    finally:
        slow.close()
        proc.stop()


def test_sse_replays_from_last_event_id_and_reports_gap_status(workdir: Path) -> None:
    proc = seeded(workdir)
    try:
        with proc.client() as c:
            epoch = open_epoch(c)
            post(c, epoch, "a")
            with c.stream("GET", "/v1/events/stream", params={"domain_id": DOMAIN}, headers=auth("alice")) as r:
                assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
                lines = []
                for line in r.iter_lines():
                    lines.append(line)
                    if line.startswith("data: "):
                        break
            frame = json.loads(lines[-1][6:])
            assert frame["kind"] == "OPERATION_UPDATE" and ":" in frame["cursor"]
            # unknown journal in Last-Event-ID: a normal 410, not a silent restart
            bad = c.get("/v1/events/stream", params={"domain_id": DOMAIN},
                        headers={**auth("alice"), "Last-Event-ID": "00" * 16 + ":0"})
            check("stream_events", bad)
            assert bad.status_code == 410
    finally:
        proc.stop()


@pytest.mark.scenario("H07")
def test_second_process_on_the_same_database_exits(workdir: Path) -> None:
    proc = HostProc(workdir).start()
    try:
        second = subprocess.run(
            [sys.executable, "-m", "uvicorn", "--factory", "crash_app:make", "--uds", str(workdir / "b.sock"),
             "--app-dir", str(HERE), "--log-level", "warning"],
            env=proc.env, capture_output=True, timeout=20, text=True)
        assert second.returncode != 0 and "owned by another host process" in second.stderr
        assert not (workdir / "b.sock").exists()  # it never listened; first host still serves
        with proc.client() as c:
            assert c.get("/v1/status", headers=auth("alice")).status_code == 200
    finally:
        proc.stop()
