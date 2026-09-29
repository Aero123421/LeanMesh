"""End-to-end delivery through the real meshsim process (no Host): the TEST-ONLY fleet issuer provisions
members, adjacent nodes open link sessions, static routes stand in for the mesh slice's resolver, and
lm_send runs over the simulated radio with the real end sessions (EDHOC purpose 2), receipts and journal.
Protocol bench only: sim results are not RF, timing, energy or real-Flash evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from harness import MeshSim

END_RECEIVED = 1 << 4
APP_APPLIED = 1 << 6
OUTCOME_PENDING, OUTCOME_RECEIVED, OUTCOME_APPLIED, OUTCOME_INDETERMINATE = 0, 1, 2, 6
ROOT_MS0 = 1_000_000


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


def _root_now(sim: MeshSim, t0_us: int) -> int:
    return ROOT_MS0 + (sim.ok("status")["now_us"] - t0_us) // 1000


def _set_clock(sim: MeshSim) -> int:
    t0 = sim.ok("status")["now_us"]
    sim.ok(f"root-time all 1 {ROOT_MS0}")
    return int(t0)


def _wait_op(sim: MeshSim, node: int, op: int, done: Callable[[dict[str, Any]], bool], max_s: int = 30) -> dict[str, Any]:
    for _ in range(max_s * 5):
        o = sim.ok(f"op {node} {op}")
        if done(o):
            return o
        sim.ok("run 200")
    raise AssertionError(f"operation {op} did not reach the expected state: {o}")


@pytest.mark.e2e
@pytest.mark.scenario("D01")
def test_applied_over_three_hops_through_meshsim(meshsim: Callable[..., MeshSim]) -> None:
    sim = _chain(meshsim, 4)
    t0 = _set_clock(sim)
    assert sim.ok("route 0 3 1 2 3")["status"] == "OK"
    assert sim.ok("route 3 0 2 1 0")["status"] == "OK"
    expires = _root_now(sim, t0) + 30_000
    sent = sim.ok(f"send 0 3 applied volatile 100 1 {expires} aabbcc")
    assert sent["status"] == "OK"
    op = sent["operation"]
    o = _wait_op(sim, 0, op, lambda x: bool(x["evidence_bits"] & END_RECEIVED))
    assert o["outcome"] == OUTCOME_PENDING and not (o["evidence_bits"] & APP_APPLIED)  # stored, not yet applied
    ev = sim.ok("msg-next 3")["event"]
    assert ev["payload"] == "aabbcc" and ev["reason"] == 0 and ev["port"] == 100
    assert sim.ok("msg-next 3")["event"] is None  # exactly one
    assert sim.ok("msg-report 3 applied 0102")["status"] == "OK"
    o = _wait_op(sim, 0, op, lambda x: x["outcome"] == OUTCOME_APPLIED)
    assert o["evidence_bits"] & APP_APPLIED
    done = sim.ok("msg-next 0")["event"]
    assert done["kind"] == 3 and done["payload"] == "0102" and done["operation"] == op
    st = sim.ok("delivery 3")
    assert st["delivered"] == 1 and st["rx_dup_end"] == 0
    assert sim.ok("delivery 1")["rx_forward"] >= 2  # a relay carried frames in both directions


@pytest.mark.e2e
@pytest.mark.scenario("D06")
def test_deadline_rules_and_cancel_through_meshsim(meshsim: Callable[..., MeshSim]) -> None:
    sim = _chain(meshsim, 2)
    assert sim.ok("route 0 1 1")["status"] == "OK"
    # No clock bound: a deadline cannot be proven, so the message is not accepted.
    r = sim.cmd(f"send 0 1 received volatile 100 1 {ROOT_MS0 + 5000} 01")
    assert r["status"] == "TIME_UNCERTAIN"
    t0 = _set_clock(sim)
    # A command without a deadline is refused (only RECEIVED+DURABLE history data may have none).
    assert sim.cmd("send 0 1 applied volatile 100 1 0 01")["status"] == "INVALID_ARGUMENT"
    # A first message sets the end session up.
    warm = sim.ok(f"send 0 1 received volatile 100 1 {_root_now(sim, t0) + 60_000} 00")["operation"]
    _wait_op(sim, 0, warm, lambda x: x["outcome"] == OUTCOME_RECEIVED)
    assert sim.ok("msg-next 1")["event"]["payload"] == "00"
    sim.ok("link 0 1 down")
    sent = sim.ok(f"send 0 1 received volatile 100 1 {_root_now(sim, t0) + 60_000} 01")
    op = sent["operation"]
    sim.ok("run 100")
    assert sim.cmd(f"msg-cancel 0 {op}")["status"] == "CANCEL_TOO_LATE"  # a frame already left
    o = _wait_op(sim, 0, op, lambda x: x["phase"] == 3, max_s=30)
    assert o["outcome"] == OUTCOME_INDETERMINATE  # never "not delivered": the far end may have it
    assert sim.cmd("msg-cancel 0 999")["status"] == "NOT_FOUND"


@pytest.mark.e2e
@pytest.mark.scenario("POWER-after-slot-commit")
def test_durable_send_survives_a_power_cut_through_meshsim(meshsim: Callable[..., MeshSim]) -> None:
    sim = _chain(meshsim, 2)
    t0 = _set_clock(sim)
    # No route yet: the durable message is persisted, cannot leave, and the origin loses power.
    sent = sim.ok(f"send 0 1 received durable 100 1 {_root_now(sim, t0) + 300_000} c0ffee")
    assert sent["status"] == "OK"
    sim.ok("run 200")
    assert sim.ok("delivery 0")["journal_live"] == 1
    sim.ok("power-cut 0")
    sim.ok("boot 0")
    assert sim.ok("start 0")["status"] == "OK"
    sim.ok("run 100")
    assert sim.ok("delivery 0")["journal_live"] == 1  # the record came back from Flash
    sim.ok("run 31000")  # per-peer full-handshake gates (docs/06 §8)
    assert sim.ok("link-connect 0 1")["status"] == "OK"
    sim.ok("run 3000")
    sim.ok(f"root-time all 1 {_root_now(sim, t0)}")
    sim.ok("route 0 1 1")
    sim.ok("route 1 0 0")
    for _ in range(100):
        if sim.ok("delivery 1")["delivered"] >= 1:
            break
        sim.ok("run 200")
    ev = sim.ok("msg-next 1")["event"]
    assert ev["payload"] == "c0ffee"
    assert sim.ok("msg-next 1")["event"] is None  # once
    sim.ok("run 3000")
    assert sim.ok("delivery 0")["journal_live"] == 0  # done: retired
