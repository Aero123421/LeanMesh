"""Join, resume, leave and power cuts through the real meshsim process (no Host involved): the TEST-ONLY fleet
issuer provisions an unjoined device and a root, a fleet-signed ticket + expected entry make the root approve
by itself, and every step runs over the simulated radio with the real EDHOC/record layers. The sweep cuts
power before/torn/after every durable record commit of the join on the device store and on the root store
(sim injection, docs/12 §4) and checks that only the permitted states appear and that both sides converge.
Protocol bench only: sim results are not RF, timing, energy or real-Flash evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from harness import MeshSim

ACTIVE, PREPARED, UNASSIGNED = 5, 4, 0
JOIN_SEED = 0x60  # request id seed of the first join


def _setup(meshsim: Callable[..., MeshSim], seed: int = 7) -> MeshSim:
    sim = meshsim("--nodes", "2", "--topology", "full", "--clock", "virtual", "--seed", str(seed))
    sim.ok("provision 0 1 root")
    sim.ok("provision 1 2 unjoined")
    sim.ok("start 0")
    sim.ok("start 1")
    sim.ok("run 50")
    sim.ok("join-mode preapproved")
    return sim


def _grant(sim: MeshSim, generation: int, revision: int) -> None:
    g = sim.ok(f"grant 1 {generation} {revision}")
    assert g["status"] == "OK"
    sim.ok("run 100")
    events0 = sim.ok("events 0")["events"]
    events1 = sim.ok("events 1")["events"]
    assert any(e["kind"] == 3 and e["operation"] == g["expected_op"] and e["reason"] == 0 for e in events0)
    assert any(e["kind"] == 3 and e["operation"] == g["ticket_op"] and e["reason"] == 0 for e in events1)


def _entry(sim: MeshSim) -> dict[str, Any] | None:
    entries = sim.ok("ledger")["entries"]
    return entries[0] if entries else None


@pytest.mark.e2e
@pytest.mark.scenario("T07")
@pytest.mark.scenario("J05")
@pytest.mark.scenario("M06")
def test_preapproved_join_resume_leave_without_host(meshsim: Callable[..., MeshSim]) -> None:
    sim = _setup(meshsim)
    assert sim.ok("membership 1")["state"] == UNASSIGNED
    _grant(sim, 1, 1)
    j = sim.ok(f"join 1 {JOIN_SEED}")
    assert j["status"] == "OK"
    sim.ok("run 6000")
    m = sim.ok("membership 1")
    assert (m["state"], m["assignment"], m["membership"]) == (ACTIVE, 1, 1)
    e = _entry(sim)
    assert e is not None and e["state"] == "active" and e["confirmed"] and e["address"] == 2
    assert e["device"] == m["device"]
    assert any(
        ev["kind"] == 3 and ev["operation"] == j["operation"] and ev["reason"] == 0
        for ev in sim.ok("events 1")["events"]
    )
    led = sim.ok("ledger")
    assert (led["prepared"], led["activated"], led["confirmed"], led["refused"]) == (1, 1, 1, 0)

    # Cold boot of the device: ACTIVE from its own record, resume needs no approval and no ledger change.
    sim.ok("run 31000")
    sim.ok("power-cut 1")
    sim.ok("boot 1")
    sim.ok("start 1")
    sim.ok("run 50")
    assert sim.ok("membership 1")["state"] == ACTIVE
    assert sim.ok(f"join 1 {JOIN_SEED + 1} resume")["status"] == "OK"
    sim.ok("run 3000")
    assert sim.ok("ledger")["prepared"] == 1
    assert sim.ok("link-status 1")["neighbors"] != []

    # A member cannot join again; IMMEDIATE leave erases the membership durably and the root records it.
    assert sim.cmd(f"join 1 {JOIN_SEED + 2}")["status"] == "CONFLICT"
    assert sim.ok("leave 1 immediate 0")["status"] == "OK"
    sim.ok("run 500")
    assert sim.ok("membership 1")["state"] == UNASSIGNED
    e = _entry(sim)
    assert e is not None and e["state"] == "left"
    sim.ok("power-cut 1")
    sim.ok("boot 1")
    sim.ok("start 1")
    sim.ok("run 50")
    assert sim.ok("membership 1")["state"] == UNASSIGNED


def _run_cut(meshsim: Callable[..., MeshSim], target: int, k: int, mode: str) -> tuple[bool, bool, str]:
    """One join with a cut at the k-th mutating store call of `target`. -> (fired, converged, why)."""
    sim = _setup(meshsim, seed=100 + k * 7 + target)
    _grant(sim, 1, 1)
    sim.ok(f"store-cut {target} {k} {mode}")
    assert sim.ok(f"join 1 {JOIN_SEED}")["status"] == "OK"
    fired = False
    for _ in range(30000):  # up to 60 s of virtual time in 2 ms steps
        sim.ok("run 2")
        if sim.ok(f"store-fired {target}")["cut_fired"]:
            fired = True
            break
    if not fired:
        return False, True, "no cut left"
    sim.ok(f"power-cut {target}")
    sim.ok(f"store-restore {target}")
    sim.ok(f"boot {target}")
    sim.ok(f"start {target}")
    sim.ok("run 50")
    if target == 0:
        sim.ok("join-mode preapproved")
    # ---- only the permitted states right after the restart (docs/12 §4) ----
    m, e = sim.ok("membership 1"), _entry(sim)
    if e is None:
        return True, False, "root lost the expected entry"
    if m["state"] == ACTIVE and not (e["state"] == "active" and e["membership"] == m["membership"] and e["address"] == 2):
        return True, False, f"device ACTIVE but root entry {e}"
    if e["state"] == "active" and m["state"] != ACTIVE and not m["prepared_record"]:
        return True, False, "root ACTIVE, device neither ACTIVE nor PREPARED"
    if e["state"] == "prepared" and m["state"] == ACTIVE:
        return True, False, "device ACTIVE while the root only reserved"
    if e["state"] not in ("expected", "prepared", "active", "aborted"):
        return True, False, f"root entry in a state no join produces: {e['state']}"
    # ---- convergence by durable evidence (or a clean restart) ----
    revision = 1
    for rnd in range(8):
        sim.ok("run 31000")
        m, e = sim.ok("membership 1"), _entry(sim)
        if m["state"] == ACTIVE and e and e["state"] == "active" and e["confirmed"] and not m["confirm_pending"]:
            break
        # BUSY means an earlier operation is still running (its own deadline settles it): wait a round.
        if m["state"] == ACTIVE:
            sim.cmd(f"join 1 {JOIN_SEED + 1} resume")
        elif m["prepared_record"]:
            sim.cmd(f"join 1 {JOIN_SEED}")  # the outstanding request, by its own id
        else:
            if e is None or e["state"] != "expected":
                revision += 1
                sim.cmd(f"grant 1 1 {1 + revision}")
                sim.ok("run 100")
            sim.cmd(f"join 1 {JOIN_SEED + 0x10 + rnd}")
        sim.ok("run 8000")
    m, e = sim.ok("membership 1"), _entry(sim)
    ok = (
        m["state"] == ACTIVE
        and e is not None
        and e["state"] == "active"
        and e["confirmed"]
        and not m["confirm_pending"]
        and e["membership"] == m["membership"]
        and e["address"] == 2
    )
    return True, ok, "" if ok else f"did not converge: {m} / {e}"


@pytest.mark.e2e
@pytest.mark.scenario("POWER-before-slot-write")
@pytest.mark.scenario("POWER-during-slot-write")
@pytest.mark.scenario("POWER-after-slot-commit")
@pytest.mark.scenario("POWER-before-marker")
@pytest.mark.scenario("POWER-after-marker")
def test_power_cut_at_every_join_commit_leaves_only_allowed_states(meshsim: Callable[..., MeshSim]) -> None:
    cuts = 0
    for target in (1, 0):  # device store, then root store
        for mode in ("before", "torn", "after"):
            for k in range(40):
                fired, converged, why = _run_cut(meshsim, target, k, mode)
                if not fired:
                    break  # fewer store calls than k in one join: this node/mode is fully swept
                cuts += 1
                assert converged, f"node {target} mode {mode} k {k}: {why}"
    assert cuts >= 30
