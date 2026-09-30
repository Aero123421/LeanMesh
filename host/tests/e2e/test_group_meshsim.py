"""S15 end to end with the real processes: real FastAPI Host -> pty serial (authenticated session) -> meshsim
root with the bridge -> simulated mesh of provisioned members -> real node cores. A Host group send is expanded
by the ROOT (the origin) into ordinary unicast sends from one snapshot; the Host mirrors the root's per-target
results into `group_targets` and serves them at GET /v1/operations/{id}/targets.
Protocol bench only: sim results are not RF, timing, energy or real-Flash evidence.
"""

from __future__ import annotations

import base64
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from bridge_bench import Bench, db_rows, utc_in, wait_for
from harness import MeshSim

MEMBERS = 12


@pytest.fixture
def group_bench(meshsim: Callable[..., MeshSim], tmp_path: Path):  # type: ignore[no-untyped-def]
    made: list[Bench] = []

    def make(seed: int, members: int = MEMBERS) -> Bench:
        sim = meshsim("--nodes", str(members + 1), "--topology", "full", "--clock", "realtime", "--serial-pty",
                      "--serial-bridge", "--mesh", "--seed", str(seed))
        sim.ok("provision 0 1 root")
        kit = tmp_path / "kit.cbor"
        sim.ok(f"serial-kit {kit} 0")
        sim.ok("serial-pair 0 0")
        for i in range(1, members + 1):
            sim.ok(f"provision {i} {i + 1} leaf")  # listed ACTIVE by the root's provisioning (SEC-D2)
        for i in range(members + 1):
            assert sim.ok(f"start {i}")["status"] == "OK"
        b = Bench(sim, tmp_path, kit)
        made.append(b)
        time.sleep(1.0)
        sim.ok(f"root-time all 1 {int(sim.ok('status')['now_us']) // 1000}")
        wait_for(lambda: all(sim.ok(f"mesh {i}")["state"] == "ready" for i in range(1, members + 1)), 90,
                 "the mesh forms")
        m = sim.ok("membership 1")
        b.domain, b.node = m["domain"], m["device"]
        return b

    yield make
    for b in made:
        b.close()


def devices(b: Bench, members: int = MEMBERS) -> list[str]:
    return [b.sim.ok(f"membership {i}")["device"] for i in range(1, members + 1)]


def control(b: Bench, group_id: int, revision: int, members: list[str]) -> dict[str, Any]:
    epoch = b.epoch or b.open_epoch()
    return b.post("/v1/control", {"domain_id": b.domain, "client_epoch": epoch, "expected_revision": str(revision),
                                  "type": "GROUP_SET", "request_id": os.urandom(16).hex(), "group_id": group_id,
                                  "members": members})


def group_send(b: Bench, group_id: int, revision: int, *, delivery: str = "APPLIED", expect: int = 202,
               deadline_s: float = 120.0) -> dict[str, Any]:
    epoch = b.epoch or b.open_epoch()
    return b.post("/v1/messages", expect=expect, body={
        "domain_id": b.domain, "client_epoch": epoch,
        "destination": {"kind": "group", "group_id": group_id, "revision": str(revision)},
        "app_port": 100, "payload_b64": base64.b64encode(b"\x07" * 40).decode(), "delivery": delivery,
        "storage": "VOLATILE", "queue_mode": "FIFO", "priority": "NORMAL",
        "deadline": {"mode": "utc", "expires_at": utc_in(deadline_s)}})


def targets(b: Bench, op: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    offset = 0
    while offset is not None:
        page = b.get(f"/v1/operations/{op}/targets", offset=offset, limit=16)
        out += page["targets"]
        offset = page["next_offset"]
    return out


def apps(b: Bench, members: int = MEMBERS, skip: set[int] | None = None) -> int:
    """The applications of the members take their messages and report them APPLIED."""
    n = 0
    for i in range(1, members + 1):
        if skip and i in skip:
            continue
        while (ev := b.sim.ok(f"msg-next {i}")["event"]) is not None:
            if ev["kind"] == 2:
                assert b.sim.ok(f"msg-report {i} applied 0a")["status"] == "OK"
                n += 1
    return n


@pytest.mark.e2e
@pytest.mark.scenario("D11")
@pytest.mark.scenario("GS01")
@pytest.mark.scenario("GS10")
def test_host_group_send_root_fans_out_and_per_target_results_reach_the_api(
        group_bench: Callable[..., Bench]) -> None:
    b = group_bench(51)
    b.start_host()
    b.await_root()
    assert "GROUP_FANOUT_V2" in b.status()["capabilities"]["enabled"]
    ids = devices(b)
    ctl = control(b, 1, 0, ids)
    done = wait_for(lambda: (x := b.operation(ctl["id"]))["state"] == "FINAL" and x, 20, "GROUP_SET applied")
    assert done["outcome"] == "APPLIED"
    # an unknown revision is refused by the root; nothing is sent
    bad = group_send(b, 1, 9)
    o = wait_for(lambda: (x := b.operation(bad["id"]))["state"] == "FINAL" and x, 20, "stale revision refused")
    assert o["outcome"] == "REJECTED" and "CONFLICT" in str(o["evidence"])
    op = group_send(b, 1, 1)["id"]
    seen: set[str] = set()
    revisions: list[int] = []

    def progress() -> bool:
        apps(b)
        o = b.operation(op)
        try:
            page = b.get(f"/v1/operations/{op}/targets", limit=16)
        except AssertionError:
            return False  # the snapshot is not mirrored yet (409)
        revisions.append(int(page["progress_revision"]))
        seen.add(page["snapshot_token"])
        outs = [t["outcome"] for t in page["targets"]]
        assert len(outs) <= page["total"] == MEMBERS and len(page["snapshot_hash"]) == 64
        return o["state"] == "FINAL"

    wait_for(progress, 60, "the group operation ends", step=0.3)
    final = b.operation(op)
    assert final["outcome"] == "APPLIED", final
    ts = targets(b, op)
    assert len(ts) == MEMBERS
    assert {t["device_id"] for t in ts} == set(ids)
    assert all(t["outcome"] == "APPLIED" and t["phase"] == "FINAL" and t["message_id"] for t in ts)
    assert len(seen) == 1                       # one token for the whole run: the set was fixed at the start
    assert revisions == sorted(revisions)       # the revision only moves forward
    # the root, not the Host, expanded it: one Host request, twelve unicast deliveries at the members
    bridge = b.sim.ok("serial-status")["bridge"]
    assert bridge["send_accepted"] == 1 and bridge["send_refused"] == 1   # the stale revision was refused by the root
    assert sum(b.sim.ok(f"delivery {i}")["delivered"] for i in range(1, MEMBERS + 1)) == MEMBERS
    gt = b.get(f"/v1/operations/{op}/targets", snapshot_token=next(iter(seen)))
    assert gt["total"] == MEMBERS
    with b.host.client() as c:
        r = c.get(f"/v1/operations/{op}/targets", params={"snapshot_token": "00" * 16}, headers=b.host.auth)
    assert r.status_code == 409                # another snapshot: never a page of a different set


@pytest.mark.e2e
@pytest.mark.scenario("GS07")
@pytest.mark.scenario("GS03")
def test_host_cancel_keeps_sent_targets_open_and_a_late_result_updates_them(
        group_bench: Callable[..., Bench]) -> None:
    b = group_bench(52)
    b.start_host()
    b.await_root()
    ids = devices(b)
    wait_for(lambda: b.operation(control(b, 2, 0, ids)["id"])["state"] == "FINAL", 20, "GROUP_SET applied")
    op = group_send(b, 2, 1)["id"]
    # No application answers: four targets are in flight (stored, result outstanding), eight have not started.
    wait_for(lambda: sum(b.sim.ok(f"delivery {i}")["delivered"] for i in range(1, MEMBERS + 1)) >= 4, 40,
             "four deliveries")
    wait_for(lambda: len(targets_or_empty(b, op)) == MEMBERS, 20, "the targets are mirrored")
    # The group is edited meanwhile: the running operation keeps its set, the old revision is refused now.
    edit = control(b, 2, 1, ids[:-1])
    wait_for(lambda: b.operation(edit["id"])["state"] == "FINAL", 20, "edit applied")
    stale = group_send(b, 2, 1)
    o = wait_for(lambda: (x := b.operation(stale["id"]))["state"] == "FINAL" and x, 20, "stale revision refused")
    assert o["outcome"] == "REJECTED"
    assert len(targets_or_empty(b, op)) == MEMBERS
    with b.host.client() as c:
        assert c.post(f"/v1/operations/{op}/cancel", headers=b.host.auth).status_code == 202
    fin = wait_for(lambda: (x := b.operation(op))["state"] == "FINAL" and x, 40, "the cancelled operation ends")
    assert fin["outcome"] == "PARTIAL"
    ts = wait_for(lambda: (t := targets(b, op)) and all(x["phase"] == "FINAL" for x in t) and t, 30, "all final")
    by = {k: [t for t in ts if t["outcome"] == k] for k in ("CANCELLED_NOT_SENT", "INDETERMINATE", "APPLIED")}
    assert len(by["CANCELLED_NOT_SENT"]) == MEMBERS - 4 and len(by["INDETERMINATE"]) == 4
    before = int(b.get(f"/v1/operations/{op}/targets")["progress_revision"])
    assert apps(b) == 4                        # the four devices answer late
    late = wait_for(lambda: (t := targets(b, op)) and sum(x["outcome"] == "APPLIED" for x in t) == 4 and t, 30,
                    "late results")
    assert sum(x["outcome"] == "CANCELLED_NOT_SENT" for x in late) == MEMBERS - 4
    assert int(b.get(f"/v1/operations/{op}/targets")["progress_revision"]) > before
    assert b.operation(op)["outcome"] == "PARTIAL"  # the operation's own record is history: it is not rewritten
    assert db_rows(b.host.db, "SELECT COUNT(*) FROM group_targets WHERE operation=?", bytes.fromhex(op))[0][0] == MEMBERS


def targets_or_empty(b: Bench, op: str) -> list[dict[str, Any]]:
    try:
        return targets(b, op)
    except AssertionError:
        return []


@pytest.mark.e2e
@pytest.mark.scenario("GS09")
def test_host_restart_mid_operation_reconciles_by_message_id_and_never_resends(
        group_bench: Callable[..., Bench]) -> None:
    """The Host dies while the root is fanning out. The restarted Host asks the root by MessageId, finds the same
    group operation, mirrors its targets again and sees it end; no target receives a second message."""
    b = group_bench(53)
    b.start_host()
    b.await_root()
    ids = devices(b)
    wait_for(lambda: b.operation(control(b, 4, 0, ids)["id"])["state"] == "FINAL", 20, "GROUP_SET applied")
    op = group_send(b, 4, 1)["id"]
    wait_for(lambda: len(targets_or_empty(b, op)) == MEMBERS, 30, "the targets are mirrored")
    b.kill_host()
    assert db_rows(b.host.db, "SELECT COUNT(*) FROM group_targets WHERE operation=?", bytes.fromhex(op))[0][0] == MEMBERS
    b.start_host()
    b.await_root()

    def done() -> bool:
        apps(b)
        return b.operation(op)["state"] == "FINAL"

    wait_for(done, 90, "the operation ends after the restart", step=0.3)
    fin = b.operation(op)
    assert fin["outcome"] == "APPLIED", fin
    ts = wait_for(lambda: (t := targets_or_empty(b, op)) and all(x["outcome"] == "APPLIED" for x in t) and t, 30,
                  "targets re-mirrored")
    assert len(ts) == MEMBERS
    assert b.sim.ok("serial-status")["bridge"]["send_accepted"] == 1           # one SEND, never repeated
    assert sum(b.sim.ok(f"delivery {i}")["delivered"] for i in range(1, MEMBERS + 1)) == MEMBERS
