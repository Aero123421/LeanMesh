"""Identity + link sessions through the real meshsim process: the TEST-ONLY fleet issuer provisions
sealed records, nodes load them at `start`, open an EDHOC purpose-1 session with SESSION_BIND over the
simulated radio, and a power cycle gives fresh keys (new SIDs). Protocol bench only: sim results are
not RF, timing or energy evidence.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from harness import MeshSim


def _boot_network(meshsim: Callable[..., MeshSim]) -> MeshSim:
    sim = meshsim("--nodes", "3", "--topology", "full", "--clock", "virtual", "--seed", "5")
    sim.ok("provision 0 1 root")
    sim.ok("provision 1 2 relay")
    sim.ok("provision 2 3 leaf")
    for i in range(3):
        assert sim.ok(f"start {i}")["status"] == "OK"
    sim.ok("run 50")
    return sim


@pytest.mark.e2e
@pytest.mark.scenario("S05")
def test_link_session_and_cold_boot_through_meshsim(meshsim: Callable[..., MeshSim]) -> None:
    sim = _boot_network(meshsim)
    for i in range(3):
        st = sim.ok(f"link-status {i}")
        assert st["identity"] == "ready" and st["member"] is True and st["neighbors"] == []

    assert sim.ok("link-connect 1 0")["status"] == "OK"
    sim.ok("run 3000")
    a, b = sim.ok("link-status 0"), sim.ok("link-status 1")
    assert a["hs_completed"] == 1 and b["hs_completed"] == 1
    assert len(a["neighbors"]) == 1 and len(b["neighbors"]) == 1
    na, nb = a["neighbors"][0], b["neighbors"][0]
    assert na["active"] and nb["active"]
    assert na["rx_sid"] == nb["tx_sid"] and nb["rx_sid"] == na["tx_sid"]  # mirrored receiver-assigned SIDs
    assert na["address"] == 2 and nb["address"] == 1

    # A duplicate connect is refused while a live session exists; the third node is untouched.
    assert sim.cmd("link-connect 1 0")["status"] == "CONFLICT"
    assert sim.ok("link-status 2")["neighbors"] == []

    # Cold boot of node 1: RAM is gone, membership comes back from Flash, fresh EDHOC, new SIDs.
    sim.ok("power-cut 1")
    sim.ok("boot 1")
    assert sim.ok("start 1")["status"] == "OK"
    sim.ok("run 50")
    st = sim.ok("link-status 1")
    assert st["identity"] == "ready" and st["member"] is True and st["neighbors"] == []
    sim.ok("run 31000")  # per-peer full-handshake gate (docs/06 §8)
    assert sim.ok("link-connect 1 0")["status"] == "OK"
    sim.ok("run 3000")
    b2 = sim.ok("link-status 1")["neighbors"][0]
    a2 = sim.ok("link-status 0")["neighbors"][0]
    assert b2["active"] and a2["rx_sid"] == b2["tx_sid"] and b2["rx_sid"] == a2["tx_sid"]
    assert b2["rx_sid"] != nb["rx_sid"] and a2["rx_sid"] != na["rx_sid"]  # fresh keys, fresh SIDs


@pytest.mark.e2e
@pytest.mark.scenario("S07")
def test_unprovisioned_node_cannot_link_and_bad_commands_fail(meshsim: Callable[..., MeshSim]) -> None:
    sim = meshsim("--nodes", "2", "--topology", "full", "--clock", "virtual")
    sim.ok("provision 0 1 root")
    sim.ok("start 0")
    sim.ok("start 1")  # node 1 was never provisioned
    sim.ok("run 50")
    assert sim.ok("link-status 1")["identity"] == "unprovisioned"
    assert sim.cmd("link-connect 1 0")["status"] == "AUTH_PENDING"
    assert sim.cmd("provision 1 0 relay")["ok"] is False  # address out of range
    assert sim.cmd("provision 1 2 wizard")["ok"] is False
    assert sim.cmd("provision 9 2 relay")["ok"] is False
    assert sim.ok("link-status 0")["neighbors"] == []
