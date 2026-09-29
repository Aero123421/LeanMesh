"""S19 / T19 end to end with the real processes: meshsim root + the real FastAPI Host over the authenticated serial
session. The Host's /v1/health and /v1/diagnostics show exactly what the root reports: a value the root cannot know is
absent (and named in `unknown`), never 0; driver, sdk and app facts stay in separate groups; capabilities keep
build, implemented, qualified and enabled apart. Protocol bench only: the simulator has no heap, stack, CPU, RSSI or
energy, so those must be UNKNOWN here (a device would report them; nothing on a device was measured).
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from bridge_bench import Bench, wait_for
from harness import MeshSim

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integration"))
from host_util import violations  # noqa: E402  (the OpenAPI subset validator of the integration tests)
from host_util import CONTRACT  # noqa: E402


def _conforms(schema_name: str, body: object) -> None:
    bad = violations(CONTRACT["components"]["schemas"][schema_name], body)
    assert not bad, (schema_name, bad, body)


@pytest.mark.e2e
@pytest.mark.scenario("ME05")
def test_meshsim_diagnostics_queries_add_no_wakes(meshsim: Callable[..., MeshSim]) -> None:
    sim = meshsim("--nodes", "2", "--topology", "chain", "--clock", "virtual", "--seed", "19")
    for i in range(2):
        assert sim.ok(f"start {i}")["status"] == "OK"
    sim.ok("run 100")
    sim.ok("diag 0")
    sim.ok("run 10")  # the query's own owner step (the command notify) happens here
    steps = sim.ok("diag 0")["steps"]
    sim.ok("run 10")
    sim.ok("run 3600000")  # an hour with no query: the owner never wakes for diagnostics
    assert sim.ok("node 0")["steps"] == steps + 1  # only the step of the previous query itself
    for _ in range(50):
        sim.ok("diag 0")
    sim.ok("run 3600000")
    assert sim.ok("node 0")["steps"] <= steps + 51  # at most the command's own step per query; no timer
    d = sim.ok("diag 0")
    assert d["validity"] & 1 and d["qualified_bits"] == 0
    assert d["min_heap_bytes"] == 0 and not d["validity"] & 2  # unknown heap: bit clear, zero value
    assert sim.ok("diag 0 heap 52000")["min_heap_bytes"] == 52000  # a platform that has it: bit and value appear
    assert sim.ok("diag 0")["validity"] & 2


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
        b.join_node(1, 0x61)
        made.append(b)
        return b

    yield make
    for b in made:
        b.close()


@pytest.mark.e2e
@pytest.mark.scenario("ME05")
def test_host_health_and_diagnostics_show_only_what_the_root_reports(bench: Callable[..., Bench]) -> None:
    b = bench(44)
    # Before the Host runs there is no endpoint at all; once it does, health answers from committed state.
    b.start_host()
    b.await_root()
    health = b.get("/v1/health")
    _conforms("Health", health)
    assert health["database"] == "OK" and health["serial"] == "CONNECTED" and health["root"] == "READY"
    assert health["root_connected"] is True

    first = b.get("/v1/diagnostics")
    _conforms("Diagnostics", first)
    assert first["age_ms"] == 0
    # The simulator has no heap, stacks or CPU time: they are named unknown and are absent, not 0.
    for name in ("min_heap_bytes", "stack_free_bytes", "owner_cpu_us"):
        assert f"driver.{name}" in first["unknown"] and name not in first["driver"]
    assert first["driver"]["reset_reason"] == "POWER_ON"  # what the sim does know
    assert "rx_ring_dropped" in first["driver"]
    # Every field is either reported in its group or named unknown: nothing is silently dropped or zeroed.
    for group, names in (("driver", ("reset_reason", "min_heap_bytes", "stack_free_bytes", "owner_cpu_us",
                                     "rx_ring_depth", "rx_ring_dropped")),
                         ("app", ("events_pending", "events_lost", "ops_active", "ops_uncommitted", "ops_owed"))):
        for n in names:
            assert (n in first[group]) != (f"{group}.{n}" in first["unknown"]), (group, n)
    assert int(first["sdk"]["tx_frames"]) > 0 and first["sdk"]["radio_state"] == "RUNNING"
    assert first["sdk"]["local_busy"] is not None
    # A second ask inside the shared second is the same answer, not another exchange with the root.
    second = b.get("/v1/diagnostics")
    assert second["age_ms"] > 0 and second["sdk"] == first["sdk"]

    rows = {r["name"]: r for r in first["features"]}
    assert rows["SMALL_MESSAGE"]["build"] and rows["SMALL_MESSAGE"]["implemented"] and rows["SMALL_MESSAGE"]["enabled"]
    assert not any(r["qualified"] for r in rows.values())  # no hardware evidence exists
    assert rows["OTA"]["enabled"] is False and rows["OTA"]["implemented"] is False
    assert rows["RTC_SECURE_RESUME_RESERVED"]["implemented"] is False and rows["RTC_SECURE_RESUME_RESERVED"]["enabled"] is False

    status = b.status()
    caps = status["capabilities"]
    assert caps["qualified"] == []
    assert set(caps["enabled"]) <= set(caps["implemented"]) <= set(caps["build"])
    assert {n for n, r in rows.items() if r["enabled"] and n != "OTA"} == set(caps["enabled"])

    # The sensors are the platform's: give the sim a heap fact and the value moves from `unknown` to `driver`.
    b.sim.ok("diag 0 heap 52000")
    time.sleep(1.2)  # past the shared second
    third = b.get("/v1/diagnostics")
    assert third["driver"]["min_heap_bytes"] == 52000 and "driver.min_heap_bytes" not in third["unknown"]
    assert third["age_ms"] == 0


@pytest.mark.e2e
@pytest.mark.scenario("ME05")
def test_host_diagnostics_without_a_root_is_503_not_zeros(bench: Callable[..., Bench]) -> None:
    b = bench(45)
    b.start_host()
    b.await_root()
    b.sim.ok("stop 0")  # the root stops: its USB session ends and nothing is known about it any more
    assert b.host is not None
    wait_for(lambda: not b.status().get("root_connected"), 40, "root_connected false")
    with b.host.client() as c:
        r = c.get("/v1/diagnostics", headers=b.host.auth)
        h = c.get("/v1/health", headers=b.host.auth)
    assert r.status_code == 503 and r.json()["code"] == "ROOT_UNAVAILABLE"
    assert h.status_code == 200 and h.json()["root_connected"] is False
    assert b.status()["capabilities"]["build"] == []  # facts of a root that is gone are not kept
