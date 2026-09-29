"""Fragmentation through the real meshsim process (no Host): a 512 B message over 5 hops, the optional
4096 B object (opt-in per process: --objects), control objects to a device with their sink, and the
refusals (4097 B, no opt-in). Protocol bench only: sim results are not RF, timing or energy evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from harness import MeshSim

OUTCOME_RECEIVED, OUTCOME_SUBMITTED = 1, 9
ROOT_MS0 = 1_000_000


def _chain(meshsim: Callable[..., MeshSim], nodes: int, *flags: str) -> tuple[MeshSim, int]:
    sim = meshsim("--nodes", str(nodes), "--topology", "chain", "--clock", "virtual", "--seed", "5", *flags)
    sim.ok("provision 0 1 root")
    for i in range(1, nodes):
        sim.ok(f"provision {i} {i + 1} relay")
    for i in range(nodes):
        assert sim.ok(f"start {i}")["status"] == "OK"
    sim.ok("run 100")
    for i in range(1, nodes):
        assert sim.ok(f"link-connect {i} {i - 1}")["status"] == "OK"
        sim.ok("run 2500")
    t0 = int(sim.ok("status")["now_us"])
    sim.ok(f"root-time all 1 {ROOT_MS0}")
    last = nodes - 1
    assert sim.ok(f"route 0 {last} " + " ".join(str(i) for i in range(1, nodes)))["status"] == "OK"
    assert sim.ok(f"route {last} 0 " + " ".join(str(i) for i in range(last - 1, -1, -1)))["status"] == "OK"
    return sim, t0


def _expires(sim: MeshSim, t0: int, ttl_ms: int) -> int:
    return ROOT_MS0 + (int(sim.ok("status")["now_us"]) - t0) // 1000 + ttl_ms


def _wait(sim: MeshSim, node: int, op: int, outcome: int, max_s: int = 240) -> dict[str, Any]:
    o: dict[str, Any] = {}
    for _ in range(max_s * 5):
        o = sim.ok(f"op {node} {op}")
        if o["outcome"] == outcome:
            return o
        sim.ok("run 200")
    raise AssertionError(f"operation {op} did not reach outcome {outcome}: {o}")


@pytest.mark.e2e
@pytest.mark.scenario("D07")
def test_512_bytes_over_five_hops_through_meshsim(meshsim: Callable[..., MeshSim]) -> None:
    sim, t0 = _chain(meshsim, 6)
    sent = sim.ok(f"gen-send 0 5 received 100 1 {_expires(sim, t0, 200_000)} 512 7 api")
    assert sent["status"] == "OK"
    _wait(sim, 0, sent["operation"], OUTCOME_RECEIVED)
    ev = sim.ok("gen-next 5 7")["event"]
    assert ev == {"port": 100, "length": 512, "pattern_ok": True}
    assert sim.ok("gen-next 5 7")["event"] is None  # exactly one
    dest, origin = sim.ok("frag 5"), sim.ok("frag 0")
    assert dest["completed"] == 1 and dest["rx_conflict"] == 0
    assert origin["tx"] >= -(-512 // 80) and origin["bitmap_rx"] > 0
    assert sim.ok("frag 2")["rx"] == 0  # relays forward fragments, they do not reassemble
    assert sim.cmd(f"gen-send 0 5 received 100 1 {_expires(sim, t0, 1000)} 513 7 api")["status"] == "PAYLOAD_TOO_LARGE"


@pytest.mark.e2e
@pytest.mark.scenario("D08")
def test_object_needs_opt_in_and_stops_at_4096_through_meshsim(meshsim: Callable[..., MeshSim]) -> None:
    sim, t0 = _chain(meshsim, 3, "--objects")
    assert sim.cmd(f"gen-send 0 2 received 100 1 {_expires(sim, t0, 60_000)} 4097 3 object")["status"] == "PAYLOAD_TOO_LARGE"
    sent = sim.ok(f"gen-send 0 2 received 100 1 {_expires(sim, t0, 250_000)} 4096 3 object")
    _wait(sim, 0, sent["operation"], OUTCOME_RECEIVED)
    assert sim.ok("gen-next 2 3")["event"] == {"port": 100, "length": 4096, "pattern_ok": True}
    assert sim.ok("frag 2")["completed"] == 1
    off, _ = _chain(meshsim, 3)  # no --objects: the application never enabled it
    assert off.cmd(f"gen-send 0 2 received 100 1 {ROOT_MS0 + 60_000} 600 3 object")["status"] == "UNSUPPORTED"


@pytest.mark.e2e
@pytest.mark.scenario("D07")
def test_control_object_over_two_hops_through_meshsim(meshsim: Callable[..., MeshSim]) -> None:
    sim, t0 = _chain(meshsim, 3)
    sim.ok("ctl-sink 2")
    warm = sim.ok(f"gen-send 0 2 received 100 1 {_expires(sim, t0, 60_000)} 4 1 api")["operation"]  # opens the end session
    _wait(sim, 0, warm, OUTCOME_RECEIVED)
    sim.ok("gen-next 2 1")
    sent = sim.ok(f"send-control 0 2 1 {_expires(sim, t0, 100_000)} 1000 9")
    assert sent["status"] == "OK"
    _wait(sim, 0, sent["operation"], OUTCOME_SUBMITTED)
    got = sim.ok("ctl-recv 2 9")["control"]
    assert got["length"] == 1000 and got["pattern_ok"]
    assert sim.ok("ctl-recv 2 9")["control"] is None  # dispatched once
    assert sim.cmd(f"send-control 0 2 1 {_expires(sim, t0, 1000)} 1025 9")["status"] == "PAYLOAD_TOO_LARGE"
