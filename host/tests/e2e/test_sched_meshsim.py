"""Scheduler and admission through the real meshsim process (S14): the real core with the TEST-ONLY
fleet issuer, static routes and the simulated radio. Protocol bench only: airtime here is the
scheduler's own estimate on virtual time, not RF occupancy (docs/03 §5, docs/18 §3)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from harness import MeshSim

END_RECEIVED = 1 << 4
SENT = 1 << 2
OUTCOME_SUPERSEDED, OUTCOME_SUBMITTED = 7, 9
ROOT_MS0 = 1_000_000
LM_EVENT_MESSAGE, LM_EVENT_OPERATION = 2, 3
# scheduler constants (src/core/sched/sched.hpp): 300 ms/s, burst 600 ms, urgent debt 100 ms
RATE_US_PER_S, BURST_US, DEBT_US = 300_000, 600_000, 100_000


def _chain(meshsim: Callable[..., MeshSim], nodes: int, seed: int = 9) -> MeshSim:
    sim = meshsim("--nodes", str(nodes), "--topology", "chain", "--clock", "virtual", "--seed", str(seed))
    sim.ok("provision 0 1 root")
    for i in range(1, nodes):
        sim.ok(f"provision {i} {i + 1} relay")
    for i in range(nodes):
        assert sim.ok(f"start {i}")["status"] == "OK"
    sim.ok("run 100")
    for i in range(1, nodes):
        assert sim.ok(f"link-connect {i} {i - 1}")["status"] == "OK"
        sim.ok("run 2500")
    return sim


def _clock(sim: MeshSim) -> int:
    t0 = int(sim.ok("status")["now_us"])
    sim.ok(f"root-time all 1 {ROOT_MS0}")
    return t0


def _root_now(sim: MeshSim, t0: int) -> int:
    return ROOT_MS0 + (int(sim.ok("status")["now_us"]) - t0) // 1000


def _events(sim: MeshSim, node: int, kind: int | None = None) -> list[dict[str, Any]]:
    out = []
    while (ev := sim.ok(f"msg-next {node}")["event"]) is not None:
        if kind is None or ev["kind"] == kind:
            out.append(ev)
    return out


@pytest.mark.e2e
@pytest.mark.scenario("Q01")
def test_control_progresses_under_a_data_flood_and_no_class_starves(meshsim: Callable[..., MeshSim]) -> None:
    sim = _chain(meshsim, 4)
    t0 = _clock(sim)
    for cmd in ("route 1 2 2", "route 2 1 1", "route 1 3 2 3", "route 3 1 2 1"):
        assert sim.ok(cmd)["status"] == "OK"
    started = int(sim.ok("status")["now_us"])
    # Refill the queue of node 1 with BULK, NORMAL and URGENT sends to node 2 every 250 ms: the pool
    # stays loaded and the airtime bucket runs dry (640 frames would need 21 s of a 300 ms/s budget).
    exp = _root_now(sim, t0) + 120_000
    # A node it never talked to: end session set-up (control carriers) + one RECEIVED message, queued
    # right before the flood starts.
    control_op = sim.ok(f"send 1 3 received volatile 7 1 {exp} aa")["operation"]
    control_done_at = None
    refused = {"bulk": 0, "normal": 0, "urgent": 0}
    for _ in range(40):
        exp = _root_now(sim, t0) + 120_000
        for prio in ("urgent", "normal", "bulk"):  # 16 operation slots: every class gets a turn at them
            refused[prio] += sim.ok(f"flood 1 2 6 {prio} 100 1 {exp}")["refused"]
        sim.ok("run 250")
        _events(sim, 2)  # the application at node 2 keeps taking its messages (no receiver-side BUSY)
        if control_done_at is None:
            if sim.ok(f"op 1 {control_op}")["evidence_bits"] & END_RECEIVED:
                control_done_at = int(sim.ok("status")["now_us"])
    elapsed_us = int(sim.ok("status")["now_us"]) - started
    st = sim.ok("sched 1")
    control, urgent, normal, bulk = st["classes"]
    # (1) control progressed while the data classes were saturated: the handshake and the message
    # to node 3 completed inside the flood window, not after it.
    assert control_done_at is not None, "the control-plane work of node 1 starved"
    assert control["frames"] > 0 and control_done_at - started < elapsed_us
    # (2) nobody is starved, the weights order the classes (URGENT 8, NORMAL 4, BULK 1) ...
    assert urgent["frames"] > 0 and normal["frames"] > 0 and bulk["frames"] > 0
    assert urgent["frames"] > normal["frames"] > bulk["frames"]
    # (3) ... the refusals of the flooded classes are recorded under their class (operation slots
    # and the TX pool share) and the lowest class is refused most ...
    assert bulk["refused"] > 0 and refused["bulk"] > 0 and bulk["refused"] >= normal["refused"] >= urgent["refused"]
    # (4) ... and the gated classes stay inside the bucket: 300 ms/s + burst + the urgent debt. (CONTROL
    # and HOP_ACK airtime is charged but never refused; it is what makes the data classes wait.)
    data_us = urgent["airtime_us"] + normal["airtime_us"] + bulk["airtime_us"]
    assert st["token_waits"] > 0, "the flood never reached the airtime budget"
    assert data_us <= RATE_US_PER_S * elapsed_us // 1_000_000 + BURST_US + DEBT_US
    assert st["tokens_us"] >= -BURST_US


@pytest.mark.e2e
@pytest.mark.scenario("D05")
def test_latest_replaces_only_the_unsent_record_of_the_same_key(meshsim: Callable[..., MeshSim]) -> None:
    sim = _chain(meshsim, 3)
    t0 = _clock(sim)
    exp = _root_now(sim, t0) + 60_000
    # No route yet: nothing can leave node 1, so every record stays replaceable.
    a = sim.ok(f"flood 1 2 5 normal 4 1 {exp} 5")
    b = sim.ok(f"flood 1 2 5 normal 4 1 {exp} 6")
    assert a["accepted"] == b["accepted"] == 5
    fifo = sim.ok(f"flood 1 2 2 normal 4 1 {exp}")  # FIFO to the same destination and port: never coalesced
    assert fifo["accepted"] == 2
    assert sim.ok("sched 1")["superseded"] == 8
    # Every replaced record ended SUPERSEDED and names its replacement (operation event payload).
    ops = {ev["operation"]: ev["payload"] for ev in _events(sim, 1, LM_EVENT_OPERATION)}
    assert sorted(ops) == sorted(set(range(a["first_op"], a["last_op"])) | set(range(b["first_op"], b["last_op"])))
    for op, cause in ops.items():
        assert int(cause, 16) == op + 1  # key 5: 1->2->3->4->5 in order; key 6 likewise
        assert sim.ok(f"op 1 {op}")["outcome"] == OUTCOME_SUPERSEDED
    assert sim.ok("route 1 2 2")["status"] == "OK"
    assert sim.ok("route 2 1 1")["status"] == "OK"
    sim.ok("run 8000")
    got = [ev["payload"] for ev in _events(sim, 2, LM_EVENT_MESSAGE)]
    # the newest of each key, both FIFO records: nothing older survived, the other key was kept
    assert sorted(got) == sorted(["04000000", "04000000", "00000000", "01000000"]), got
    # A record that already left is never replaced: the newer value goes out next to it.
    first = sim.ok(f"flood 1 2 1 normal 4 1 {exp} 5")
    sim.ok("run 300")
    assert sim.ok(f"op 1 {first['first_op']}")["evidence_bits"] & SENT
    sim.ok(f"flood 1 2 1 normal 4 1 {exp} 5")
    sim.ok("run 3000")
    assert len(_events(sim, 2, LM_EVENT_MESSAGE)) == 2
    assert sim.ok(f"op 1 {first['first_op']}")["outcome"] != OUTCOME_SUPERSEDED


@pytest.mark.e2e
@pytest.mark.scenario("Q01")
def test_a_dead_neighbour_does_not_hold_up_the_traffic_to_a_live_one(meshsim: Callable[..., MeshSim]) -> None:
    sim = _chain(meshsim, 3)  # 0 - 1 - 2; node 1 talks to both ends
    t0 = _clock(sim)
    for cmd in ("route 1 0 0", "route 0 1 1", "route 1 2 2", "route 2 1 1"):
        assert sim.ok(cmd)["status"] == "OK"
    exp = _root_now(sim, t0) + 120_000
    # warm-up: end sessions with both neighbours exist before the radio to node 2 goes away
    for dest in (0, 2):
        op = sim.ok(f"send 1 {dest} received volatile 7 1 {exp} 00")["operation"]
        for _ in range(100):
            if sim.ok(f"op 1 {op}")["evidence_bits"] & END_RECEIVED:
                break
            sim.ok("run 100")
        else:
            raise AssertionError("warm-up did not complete")
        _events(sim, dest)
    sim.ok("link 1 2 down")
    flood = sim.ok(f"flood 1 2 12 urgent 100 1 {exp}")
    assert flood["accepted"] == 12
    sim.ok("run 50")
    assert sim.ok("sched 1")["pool_in_use"] >= 6  # the frames to the dead node hold pool slots ...
    op = sim.ok(f"send 1 0 received volatile 7 1 {exp} 01")["operation"]
    started = int(sim.ok("status")["now_us"])
    for _ in range(40):
        if sim.ok(f"op 1 {op}")["evidence_bits"] & END_RECEIVED:
            break
        sim.ok("run 50")
    else:
        raise AssertionError("traffic to the live neighbour was held up by the dead one")
    assert int(sim.ok("status")["now_us"]) - started < 1_500_000  # ... but the live one is served at once
    assert [ev["payload"] for ev in _events(sim, 0, LM_EVENT_MESSAGE)] == ["01"]
