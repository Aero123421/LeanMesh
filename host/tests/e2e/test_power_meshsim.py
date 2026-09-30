"""S16 end to end with the real processes: a REPORT_ONLY leaf sleeps in meshsim, tells the root when it expects to
wake, and the real FastAPI Host shows exactly that (GET /v1/nodes/{id}/power is backed by what the root reports,
never by a guess). Also meshsim alone: a sleeping leaf takes no step until its timer. Protocol bench only: sim
results are not RF, timing, energy or real-Flash evidence.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import pytest
from bridge_bench import Bench, wait_for
from harness import MeshSim


@pytest.mark.e2e
@pytest.mark.scenario("P02")
def test_meshsim_sleeping_leaf_wakes_only_at_its_timer(meshsim: Callable[..., MeshSim]) -> None:
    sim = meshsim("--nodes", "3", "--topology", "chain", "--clock", "virtual", "--seed", "5", "--mesh", "--leaf-last",
                  "--no-boot")
    sim.ok("provision 0 1 root")
    sim.ok("provision 1 2 relay")
    sim.ok("provision 2 3 leaf")
    for i in range(3):
        sim.ok(f"boot {i}")
        assert sim.ok(f"start {i}")["status"] == "OK"
    for _ in range(200):
        sim.ok("run 500")
        if sim.ok("mesh 2")["state"] == "ready":
            break
    assert sim.ok("mesh 2")["state"] == "ready"
    sim.ok(f"root-time all 1 {int(sim.ok('status')['now_us']) // 1000}")  # the root clock estimate (no time slice here)
    assert sim.ok("power-set 2 report")["status"] == "OK"
    sim.ok("run 1000")
    assert sim.ok("power 2")["mode"] == 2
    assert sim.ok("sleep 2 light 60000")["status"] == "OK"
    sim.ok("run 10")
    p = sim.ok("power 2")
    assert p["asleep"] is True and p["state"] == 3
    grants = p["grants"]
    sim.ok("run 59000")
    assert sim.ok("power 2")["asleep"] is True  # the hello and lease timers of a leaf do not wake it
    sim.ok("run 2000")
    p = sim.ok("power 2")
    assert p["asleep"] is False and p["state"] == 0 and p["episodes"] >= 2
    wait_steps = 0
    while sim.ok("power 2")["grants"] == grants and wait_steps < 40:
        sim.ok("run 100")
        wait_steps += 1
    assert sim.ok("power 2")["grants"] > grants  # the poll of the new episode was answered by the parent


def _status(b: Bench, path: str, **params: object) -> tuple[int, dict]:  # type: ignore[type-arg]
    assert b.host is not None
    with b.host.client() as c:
        r = c.get(path, params=params, headers=b.host.auth)
    return r.status_code, (r.json() if r.status_code == 200 else {})


@pytest.fixture
def bench(meshsim: Callable[..., MeshSim], tmp_path: Path):  # type: ignore[no-untyped-def]
    made: list[Bench] = []

    def make(seed: int) -> Bench:
        sim = meshsim("--nodes", "2", "--topology", "full", "--clock", "realtime", "--serial-pty", "--serial-bridge",
                      "--seed", str(seed), "--mesh", "--leaf-last")
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


@pytest.mark.e2e
@pytest.mark.scenario("P02")
def test_host_power_endpoint_shows_what_the_root_was_told(bench: Callable[..., Bench]) -> None:
    b = bench(43)
    b.start_host()
    b.await_root()
    wait_for(lambda: b.sim.ok("mesh 1")["state"] == "ready", 60, "the member attached")
    # Never reported: the Host says so (404), it does not invent a default.
    assert _status(b, f"/v1/nodes/{b.node}/power", domain_id=b.domain)[0] == 404
    assert b.sim.ok("power-set 1 report")["status"] == "OK"
    time.sleep(1.5)
    assert b.sim.ok("sleep 1 light 60000")["status"] == "OK"
    snap = wait_for(lambda: _status(b, f"/v1/nodes/{b.node}/power", domain_id=b.domain)[1] or None, 60,
                    "the root's report reaches the Host")
    assert snap["mode"] == "REPORT_ONLY" and snap["state"] == "SLEEPING"
    assert snap["next_wake_quality"] == "BOUNDED"
    assert snap["policy_revision"] == "2"
    assert "radio_on_us" not in snap and "measured_energy_j" not in snap  # nothing that was not reported
    earliest, latest = int(snap["next_wake_earliest_root_ms"]), int(snap["next_wake_latest_root_ms"])
    assert 0 < earliest <= latest
