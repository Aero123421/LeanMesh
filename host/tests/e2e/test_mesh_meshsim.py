"""End-to-end mesh through the real meshsim process (no Host): provisioned members boot on a chain and form the
mesh by themselves (parent search, link sessions, end sessions with the root, REGISTER/LEASE/READY), then a message
crosses the formed mesh with no static route. Protocol bench only: sim results are not RF, timing, energy or
real-Flash evidence.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from harness import MeshSim

END_RECEIVED = 1 << 4


@pytest.mark.e2e
@pytest.mark.scenario("R01")
def test_chain_forms_by_itself_and_carries_a_message(meshsim: Callable[..., MeshSim]) -> None:
    nodes = 6
    sim = meshsim("--nodes", str(nodes), "--topology", "chain", "--clock", "virtual", "--seed", "5", "--mesh", "--no-boot")
    sim.ok("provision 0 1 root")
    for i in range(1, nodes):
        sim.ok(f"provision {i} {i + 1} relay")
    for i in range(nodes):
        sim.ok(f"boot {i}")
        assert sim.ok(f"start {i}")["status"] == "OK"
    formed = False
    for _ in range(120):
        sim.ok("run 500")
        if all(sim.ok(f"mesh {i}")["state"] == "ready" for i in range(1, nodes)):
            formed = True
            break
    assert formed
    for i in range(1, nodes):
        m = sim.ok(f"mesh {i}")
        assert m["depth"] == i and m["path"] == [1, *range(2, i + 2)]  # the root path is the chain
        assert m["attach_failed"] == 0
    assert sim.ok("mesh 0")["state"] == "root"
    sim.ok("root-time all 1 1000000")
    expires = 1_000_000 + 30_000
    sent = sim.ok(f"send {nodes - 1} 0 received volatile 100 1 {expires} aabbcc")
    assert sent["status"] == "OK"
    for _ in range(100):
        if sim.ok(f"op {nodes - 1} {sent['operation']}")["evidence_bits"] & END_RECEIVED:
            break
        sim.ok("run 200")
    else:
        raise AssertionError("no END_RECEIVED over the formed mesh")
    assert sim.ok("msg-next 0")["event"]["payload"] == "aabbcc"
