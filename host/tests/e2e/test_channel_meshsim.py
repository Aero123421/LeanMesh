"""S17 end to end with the real processes. (1) meshsim alone: a chain forms its mesh, the root's coordinator moves
every node to another channel through PREPARE / COMMIT, rolls back with a higher epoch and honours the freeze
revision. (2) The real FastAPI Host on the pty serial session: GET /v1/channel mirrors what the root reports,
CHANNEL_FREEZE / CHANNEL_RECALCULATE reach the root's coordinator, a rejected request ends REJECTED. Protocol
bench only: sim results are not RF, timing, energy or real-Flash evidence.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from bridge_bench import Bench, wait_for
from harness import MeshSim


def _form(sim: MeshSim, nodes: int, budget_steps: int = 400) -> None:
    for _ in range(budget_steps):
        sim.ok("run 500")
        if all(sim.ok(f"mesh {i}")["state"] == "ready" and sim.ok(f"channel status {i}")["time_updates"] > 0
               for i in range(1, nodes)):
            return
    raise AssertionError("the mesh did not form")


def _run_until(sim: MeshSim, pred: Callable[[], bool], limit_s: int, step_ms: int = 1000) -> None:
    for _ in range(limit_s * 1000 // step_ms):
        if pred():
            return
        sim.ok(f"run {step_ms}")
    raise AssertionError("condition not reached")


@pytest.mark.e2e
@pytest.mark.scenario("C12")
@pytest.mark.scenario("C07")
def test_plan_rollback_and_freeze_through_the_real_processes(meshsim: Callable[..., MeshSim]) -> None:
    nodes = 4
    sim = meshsim("--nodes", str(nodes), "--topology", "chain", "--clock", "virtual", "--seed", "9", "--mesh", "--channel",
                  "--no-boot")
    sim.ok("provision 0 1 root")
    for i in range(1, nodes):
        sim.ok(f"provision {i} {i + 1} relay")
    for i in range(nodes):
        sim.ok(f"boot {i}")
        assert sim.ok(f"start {i}")["status"] == "OK"
    _form(sim, nodes)
    assert all(sim.ok(f"channel status {i}")["radio"] == 6 for i in range(nodes))
    # A plan to channel 11: every attached member is required, nobody is dropped from the denominator.
    assert sim.ok("channel plan 11")["status"] == "OK"
    c = sim.ok("channel status 0")["coordinator"]
    assert c["state"] == "PREPARING" and c["required"] == [2, 3, 4]
    _run_until(sim, lambda: sim.ok("channel status 0")["coordinator"]["state"] == "MONITOR", 400)
    c = sim.ok("channel status 0")["coordinator"]
    assert c["applied"] == [2, 3, 4] and c["unreachable"] == [] and c["epoch"] == 1 and c["current"] == 11
    for i in range(nodes):
        s = sim.ok(f"channel status {i}")
        assert s["radio"] == 11 and s["epoch"] == 1 and s["mode"] == "normal"
    # Rollback: a new plan with a higher epoch, never a lone timeout on a node.
    assert sim.ok("channel rollback")["status"] == "OK"
    _run_until(sim, lambda: (x := sim.ok("channel status 0")["coordinator"])["state"] == "MONITOR" and x["epoch"] == 2, 400)
    for i in range(nodes):
        s = sim.ok(f"channel status {i}")
        assert s["radio"] == 6 and s["epoch"] == 2
    # Freeze is a compare-and-set on the policy revision and stops a plan that is only PREPARING.
    assert sim.ok("channel request 1 0")["status"] == "OK"
    assert sim.ok("channel request 1 0")["status"] == "CONFLICT"
    assert sim.ok("channel plan 11")["status"] == "CONFLICT"
    assert sim.ok("channel status 0")["coordinator"]["frozen"] is True


@pytest.fixture
def bench(meshsim: Callable[..., MeshSim], tmp_path: Path):  # type: ignore[no-untyped-def]
    made: list[Bench] = []

    def make(seed: int) -> Bench:
        sim = meshsim("--nodes", "2", "--topology", "full", "--clock", "realtime", "--serial-pty", "--serial-bridge",
                      "--seed", str(seed), "--mesh", "--channel")
        sim.ok("provision 0 1 root")
        kit = tmp_path / "kit.cbor"
        sim.ok(f"serial-kit {kit} 0")
        sim.ok("serial-pair 0 0")
        sim.ok("provision 1 2 unjoined")
        for i in range(2):
            assert sim.ok(f"start {i}")["status"] == "OK"
        sim.ok("join-mode preapproved")
        time.sleep(1.0)
        b = Bench(sim, tmp_path, kit)
        b.join_node(1, 0x60)
        made.append(b)
        return b

    yield make
    for b in made:
        b.close()


def _control(b: Bench, kind: str, revision: str, **extra: object) -> dict:  # type: ignore[type-arg]
    epoch = b.epoch or b.open_epoch()
    return b.post("/v1/control", {"domain_id": b.domain, "client_epoch": epoch, "expected_revision": revision,
                                  "type": kind, "request_id": os.urandom(16).hex(), **extra})


def _final(b: Bench, op: dict) -> dict:  # type: ignore[type-arg]
    return wait_for(lambda: (x := b.operation(op["id"]))["state"] == "FINAL" and x, 30, "operation final")


@pytest.mark.e2e
@pytest.mark.scenario("C07")
@pytest.mark.scenario("C03")
def test_host_channel_endpoint_mirrors_the_root_and_controls_reach_the_coordinator(bench: Callable[..., Bench]) -> None:
    b = bench(41)
    b.start_host()
    b.await_root()
    wait_for(lambda: b.sim.ok("mesh 1")["state"] == "ready" and b.sim.ok("channel status 1")["time_updates"] > 0, 60,
             "mesh and clock of the member")
    ch = wait_for(lambda: b.get("/v1/channel", domain_id=b.domain), 20, "channel state reported by the root")
    # The answer is the OpenAPI ChannelStatus: its required members, nothing else but the optional plan id.
    assert {"current_channel", "channel_epoch", "state", "required", "applied", "unreachable"} <= ch.keys()
    assert ch.keys() <= {"current_channel", "channel_epoch", "state", "plan_id", "required", "applied", "unreachable"}
    assert ch["state"] == "MONITOR" and ch["channel_epoch"] == 0 and ch["current_channel"] == 6
    assert ch["required"] == [] and ch["applied"] == [] and ch["unreachable"] == []
    # RECALCULATE: the root starts its evaluation; the Host learns it from the root's CHANNEL event.
    op = _control(b, "CHANNEL_RECALCULATE", "0")
    done = _final(b, op)
    assert done["outcome"] == "APPLIED" and "ROOT_APPLIED" in {e["kind"] for e in done["evidence"]}
    wait_for(lambda: b.get("/v1/channel", domain_id=b.domain)["state"] == "SURVEY", 20, "SURVEY reported")
    # FREEZE while surveying: the measurement is dropped, no plan follows.
    done = _final(b, _control(b, "CHANNEL_FREEZE", "0", freeze=True))
    assert done["outcome"] == "APPLIED"
    wait_for(lambda: b.get("/v1/channel", domain_id=b.domain)["state"] == "MONITOR", 20, "MONITOR after the freeze")
    assert b.sim.ok("channel status 0")["coordinator"]["frozen"] is True
    # A stale revision is refused by the root and ends REJECTED (never a silent success).
    stale = _final(b, _control(b, "CHANNEL_FREEZE", "0", freeze=False))
    assert stale["outcome"] == "REJECTED" and "ROOT_REFUSED" in {e["kind"] for e in stale["evidence"]}
    assert b.sim.ok("channel status 0")["coordinator"]["frozen"] is True
    assert _final(b, _control(b, "CHANNEL_FREEZE", "1", freeze=False))["outcome"] == "APPLIED"
    # A plan run by the root: the Host shows STORED-then-APPLIED members as required/applied, per device.
    b.sim.ok("channel timing 3000 6000")
    assert b.sim.ok("channel plan 11")["status"] == "OK"
    ch = wait_for(lambda: (x := b.get("/v1/channel", domain_id=b.domain))["current_channel"] == 11
                  and x["channel_epoch"] == 1 and x["required"] == [b.node] and x, 60, "the committed channel is reported")
    assert ch["channel_epoch"] == 1 and ch["state"] in ("SWITCHING", "SETTLING", "MONITOR")
    assert ch["required"] == [b.node]
    wait_for(lambda: b.get("/v1/channel", domain_id=b.domain)["applied"] == [b.node], 60, "APPLIED reported")
    assert b.get("/v1/channel", domain_id=b.domain)["unreachable"] == []
