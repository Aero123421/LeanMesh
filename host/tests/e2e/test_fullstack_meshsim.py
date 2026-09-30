"""S20 full-stack end to end, the whole product path in one run: 21 real node cores on a 20-hop chain form the mesh by
themselves (no static routes), the real FastAPI Host drives the root over the authenticated serial session, and
  POST /v1/messages (APPLIED) to the leaf 20 hops away, a durable node -> Host message, a group send to all 20 members,
  a lifecycle operation (REVOKE through POST /v1/control) and the diagnostics endpoints
run against the same network. Every step is judged on evidence, never on an HTTP 202.
Timings are SIM timings (real-time pacing of a virtual radio, docs/18 §3): protocol bench numbers, never RF, range,
energy or real-Flash evidence. They are printed and, when LEANMESH_E2E_REPORT_DIR is set, written as JSON.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from bridge_bench import PERMS, Bench, db_rows, wait_for
from harness import MeshSim
from test_group_meshsim import apps, group_send, targets

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integration"))
from host_util import CONTRACT, violations  # noqa: E402

HOPS = 20
NODES = HOPS + 1


def _conforms(schema: str, body: object) -> None:
    bad = violations(CONTRACT["components"]["schemas"][schema], body)
    assert not bad, (schema, bad)


def _control(b: Bench, kind: str, **fields: object) -> dict[str, Any]:
    return b.post("/v1/control", {"domain_id": b.domain, "client_epoch": b.epoch or b.open_epoch(),
                                  "expected_revision": "0", "type": kind, "request_id": os.urandom(16).hex(),
                                  **fields})


def _final(b: Bench, op: str, what: str, timeout_s: float = 60) -> dict[str, Any]:
    return wait_for(lambda: (x := b.operation(op))["state"] == "FINAL" and x, timeout_s, what)


@pytest.fixture
def mesh21(meshsim: Callable[..., MeshSim], tmp_path: Path):  # type: ignore[no-untyped-def]
    made: list[Bench] = []

    def make(seed: int) -> Bench:
        b = Bench.build_mesh(meshsim, tmp_path, seed=seed, nodes=NODES, topology="chain")
        made.append(b)
        return b

    yield make
    for b in made:
        b.close()


@pytest.mark.e2e
@pytest.mark.scenario("R01")
@pytest.mark.scenario("D01")
@pytest.mark.scenario("D11")
@pytest.mark.scenario("H04")
@pytest.mark.scenario("ME05")
@pytest.mark.scenario("S06")
def test_21_nodes_20_hops_through_the_real_host(mesh21: Callable[..., Bench]) -> None:
    b = mesh21(0x5C)
    report: dict[str, Any] = {"nodes": NODES, "hops": HOPS, "seed": 0x5C, "clock": "sim (real-time paced virtual radio)",
                              "formation_s": round(b.formation_s, 1)}
    leaf = NODES - 1
    assert b.sim.ok(f"mesh {leaf}")["depth"] == HOPS
    b.start_host(perms=[*PERMS, "REVOKE"])
    b.await_root()
    st = b.status()
    assert st["root_connected"] is True and st["ready"] is True
    mirror = b.get("/v1/nodes", domain_id=b.domain)["items"]
    assert len(mirror) == HOPS and all(n["membership"] == "ACTIVE" for n in mirror)

    # ---- 1. Host -> the leaf 20 hops away: APPLIED only after the application said so ----------------------------
    t0 = time.monotonic()
    body = base64.b64encode(bytes(range(64))).decode()
    op = b.send(body, deadline_s=180)["id"]
    ev = wait_for(lambda: (e := b.sim.ok(f"msg-next {leaf}")["event"]) and e["kind"] == 2 and e, 90, "MESSAGE at the leaf")
    report["host_to_leaf_message_s"] = round(time.monotonic() - t0, 2)
    assert ev["payload"] == bytes(range(64)).hex() and ev["port"] == 100
    o = wait_for(lambda: (x := b.operation(op))["state"] == "WAITING_RECEIPT" and x, 60, "stored at the far end")
    assert o["outcome"] == "PENDING" and "END_RECEIVED" in b.kinds(op) and "APP_APPLIED" not in b.kinds(op)
    report["host_to_leaf_end_received_s"] = round(time.monotonic() - t0, 2)
    assert b.sim.ok(f"msg-report {leaf} applied 0a0b")["status"] == "OK"
    done = wait_for(lambda: (x := b.operation(op))["outcome"] == "APPLIED" and x, 60, "APPLIED")
    report["host_to_leaf_applied_s"] = round(time.monotonic() - t0, 2)
    kinds = {e["kind"]: e for e in done["evidence"]}
    assert {"ROOT_ACCEPTED", "ROOT_SENT", "HOP_ACCEPTED", "END_RECEIVED", "APP_APPLIED"} <= kinds.keys()
    assert kinds["APP_APPLIED"]["assurance"] == "END_VERIFIED"
    assert b.sim.ok("delivery 0")["accepted"] == 1 and b.sim.ok(f"delivery {leaf}")["delivered"] == 1

    # ---- 2. leaf -> Host, durable: the Host commits first, only then the origin hears END_RECEIVED ---------------
    t1 = time.monotonic()
    sent = b.sim.ok(f"send {leaf} root received durable 200 0 0 c0ffee")
    node_op = sent["operation"]
    o2 = wait_for(lambda: (x := b.sim.ok(f"op {leaf} {node_op}"))["evidence_bits"] & (1 << 4) and x, 90,
                  "END_RECEIVED at the leaf after the Host commit")
    report["leaf_to_host_durable_s"] = round(time.monotonic() - t1, 2)
    assert o2["outcome"] == 1  # RECEIVED
    rows = db_rows(b.host.db, "SELECT payload FROM inbox WHERE origin=?", bytes.fromhex(b.node))  # type: ignore[union-attr]
    assert len(rows) == 1 and bytes(rows[0][0]) == bytes.fromhex("c0ffee")
    got = [e for e in b.events()["events"] if e["kind"] == "MESSAGE_RECEIVED"]
    assert len(got) == 1 and got[0]["evidence"]["assurance"] == "END_VERIFIED" and got[0]["origin"] == b.node

    # ---- 3. group send to all 20 members: the root fans out, per-target evidence comes back ----------------------
    ids = [b.device(i) for i in range(1, NODES)]
    epoch = b.epoch
    ctl = b.post("/v1/control", {"domain_id": b.domain, "client_epoch": epoch, "expected_revision": "0",
                                 "type": "GROUP_SET", "request_id": os.urandom(16).hex(), "group_id": 1,
                                 "members": ids})
    assert _final(b, ctl["id"], "GROUP_SET applied", 30)["outcome"] == "APPLIED"
    t2 = time.monotonic()
    gop = group_send(b, 1, 1, deadline_s=300)["id"]

    def group_done() -> bool:
        apps(b, HOPS)
        return b.operation(gop)["state"] == "FINAL"

    wait_for(group_done, 240, "the group operation ends", step=0.5)
    report["group_20_targets_s"] = round(time.monotonic() - t2, 2)
    fin = b.operation(gop)
    assert fin["outcome"] == "APPLIED", fin
    ts = targets(b, gop)
    assert len(ts) == HOPS and {t["device_id"] for t in ts} == set(ids)
    assert all(t["outcome"] == "APPLIED" and t["phase"] == "FINAL" for t in ts)
    assert b.sim.ok("serial-status")["bridge"]["send_accepted"] == 2  # the leaf message and ONE group request

    # ---- 4. a lifecycle operation: REVOKE of the leaf, evidence from the root, node mirror follows ---------------
    signed = base64.b64encode(bytes.fromhex(b.sim.ok(f"lc-object revoke {leaf} 2 2")["cose"])).decode()
    rev = _control(b, "REVOKE", device_id=b.node, signed_cbor_b64=signed)
    r = _final(b, rev["id"], "revoke applied", 60)
    assert r["outcome"] == "APPLIED" and "ROOT_APPLIED" in {e["kind"] for e in r["evidence"]}
    wait_for(lambda: any(n["device_id"] == b.node and n["membership"] == "REVOKED"
                         for n in b.get("/v1/nodes", domain_id=b.domain)["items"]), 60, "REVOKED in the node mirror")

    # ---- 5. diagnostics: what the root reports, unknowns named, nothing invented ---------------------------------
    health = b.get("/v1/health")
    _conforms("Health", health)
    assert health["database"] == "OK" and health["serial"] == "CONNECTED" and health["root_connected"] is True
    diag = b.get("/v1/diagnostics")
    _conforms("Diagnostics", diag)
    assert int(diag["sdk"]["tx_frames"]) > 0 and "driver.min_heap_bytes" in diag["unknown"]
    assert not any(row["qualified"] for row in diag["features"])
    assert b.sim.ok("serial-status")["bridge"]["malformed"] == 0

    # ---- nothing was applied twice anywhere ---------------------------------------------------------------------
    delivered = [b.sim.ok(f"delivery {i}")["delivered"] for i in range(1, NODES)]
    assert delivered[leaf - 1] == 2 and sum(delivered) == HOPS + 1  # the leaf got two messages, everyone else one
    report["operations"] = {"host_to_leaf": op, "group": gop, "revoke": rev["id"]}
    print("\nS20 full-stack (SIM timings): " + json.dumps(report, sort_keys=True))
    out = os.environ.get("LEANMESH_E2E_REPORT_DIR")
    if out:
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / "e2e-fullstack.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
