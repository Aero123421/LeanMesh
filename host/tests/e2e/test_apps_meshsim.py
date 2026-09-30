"""LC12 (sim): two applications that have nothing to do with each other and nothing to do with any product run on the
same SDK, through the same Host: an equipment state controller (examples/apps/equipment_control.c: commands answered
APPLIED only after the driver confirmed) and a periodic battery measurement (examples/apps/battery_measurement.c:
readings sent LATEST to the Host). Both use only api/leanmesh.h; meshsim only supplies their platform. Protocol bench
only: sim results are not RF, timing, energy or real-Flash evidence, and a bench is not the G6 qualification.
"""

from __future__ import annotations

import base64
import re
import struct
from collections.abc import Callable
from pathlib import Path

import pytest
from bridge_bench import Bench, wait_for
from harness import REPO_ROOT, MeshSim

EQ, BAT = 1, 2  # meshsim node indexes: node 1 is the equipment controller, node 2 the battery-powered sensor


@pytest.fixture
def two_apps(meshsim: Callable[..., MeshSim], tmp_path: Path):  # type: ignore[no-untyped-def]
    made: list[Bench] = []
    b = Bench.build_mesh(meshsim, tmp_path, seed=0x1C12, nodes=3, topology="full")
    made.append(b)
    b.node = b.device(EQ)  # Bench.send() addresses the equipment
    yield b
    for x in made:
        x.close()


def command(revision: int, on: int) -> str:
    return base64.b64encode(struct.pack(">BBIB", 1, ord("S"), revision, on)).decode()


def answer(b: Bench, op: str, want: str) -> dict:  # type: ignore[type-arg]
    """The equipment application takes its commands; the operation ends on the application's own answer."""
    wait_for(lambda: b.sim.ok(f"app-equipment {EQ}")["answered"] >= 1 or b.operation(op)["outcome"] == want, 60,
             "the application answers")
    return wait_for(lambda: (x := b.operation(op))["outcome"] == want and x, 60, f"outcome {want}")


@pytest.mark.e2e
@pytest.mark.scenario("LC12")
@pytest.mark.scenario("D01")
def test_equipment_control_reports_only_what_the_driver_confirmed(two_apps: Bench) -> None:
    b = two_apps
    b.start_host()
    b.await_root()
    op = b.send(command(5, 1), delivery="APPLIED", port=100)["id"]
    done = answer(b, op, "APPLIED")
    assert done["state"] == "FINAL" and "APP_APPLIED" in {e["kind"] for e in done["evidence"]}
    st = b.sim.ok(f"app-equipment {EQ}")
    assert (st["on"], st["revision"], st["drive_calls"]) == (1, 5, 1)
    # The same command again is answered APPLIED without touching the driver a second time; an old revision or a
    # conflicting one is REJECTED and leaves the state alone.
    again = b.send(command(5, 1), delivery="APPLIED", port=100)["id"]
    answer(b, again, "APPLIED")
    old = b.send(command(3, 0), delivery="APPLIED", port=100)["id"]
    answer(b, old, "REJECTED")
    st = b.sim.ok(f"app-equipment {EQ}")
    assert (st["on"], st["revision"], st["drive_calls"]) == (1, 5, 1) and st["rejected"] == 1
    # The driver refuses: the answer is REJECTED, never "applied because it was asked".
    b.sim.ok(f"app-equipment {EQ} fail")
    refused = b.send(command(6, 0), delivery="APPLIED", port=100)["id"]
    answer(b, refused, "REJECTED")
    st = b.sim.ok(f"app-equipment {EQ}")
    assert (st["on"], st["revision"]) == (1, 5) and st["drive_calls"] == 2 and st["applied"] == 2


@pytest.mark.e2e
@pytest.mark.scenario("LC12")
def test_battery_readings_reach_the_host_and_only_the_newest_is_kept_when_queued(two_apps: Bench) -> None:
    b = two_apps
    b.start_host()
    b.await_root()
    seen: list[bytes] = []
    for k, (mv, pct) in enumerate([(3700, 81), (3690, 80), (3680, 79)], start=1):
        r = b.sim.ok(f"app-battery {BAT} {mv} {pct}")
        assert r["status"] == "OK" and r["sequence"] == k

    sensor = b.device(BAT)

    def readings() -> list[bytes]:
        return [base64.b64decode(e["payload_b64"]) for e in b.events()["events"]
                if e["kind"] == "MESSAGE_RECEIVED" and e["origin"] == sensor]

    got = wait_for(lambda: (r := readings()) and len(r) >= 1 and r, 60, "a reading at the Host")
    seen.extend(got)
    for reading in seen:
        version, seq, mv, pct = struct.unpack(">BIHB", reading)
        assert version == 1 and 1 <= seq <= 3 and 3680 <= mv <= 3700 and 79 <= pct <= 81
    # LATEST: a reading that had not left the node is replaced by the next; the newest one always arrives.
    assert struct.unpack(">BIHB", seen[-1])[1] == 3


@pytest.mark.scenario("LC12")
def test_example_applications_use_only_the_public_api_and_no_product_vocabulary() -> None:
    for f in (REPO_ROOT / "examples" / "apps").glob("*"):
        text = f.read_text()
        for inc in re.findall(r'#include\s+[<"]([^>"]+)[>"]', text):
            assert inc in {"leanmesh.h", "string.h", "equipment_control.h", "battery_measurement.h"}, (f.name, inc)
        assert not re.search(r"(?i)kguard|routeloom|https?://", text), f.name
