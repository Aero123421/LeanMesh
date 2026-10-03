"""Issue #5 end to end with the real processes: real FastAPI Host -> pty serial (EDHOC purpose 3) -> meshsim root with the
bridge -> real node cores. The Host asks the root for a signed ledger backup after its ledger changed and keeps the newest;
the root board is then replaced (a NEW root identity, the fleet's delegation of generation 2, no ledger) and the Host restores
the backup onto it through POST /v1/control LEDGER_RESTORE - the three root steps and every record, ended by the root's
own events - and accepts the new root for the domain only because of that restore.
Protocol bench only: a pty is not a USB cable and sim time is not timing evidence."""

from __future__ import annotations

import base64
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from bridge_bench import Bench, db_rows, wait_for
from harness import MeshSim

PERMS = ["READ", "SEND", "APPROVE", "CONFIGURE", "TRANSFER"]
FAST = {"LEANMESH_BACKUP_DEBOUNCE_S": "1", "LEANMESH_BACKUP_MIN_INTERVAL_S": "2"}  # (5 s / 30 s by default)


@pytest.fixture
def bench(meshsim: Callable[..., MeshSim], tmp_path: Path):  # type: ignore[no-untyped-def]
    made: list[Bench] = []

    def make(seed: int, **kw: object) -> Bench:
        b = Bench.build(meshsim, tmp_path, seed=seed, **kw)  # type: ignore[arg-type]
        made.append(b)
        return b

    yield make
    for b in made:
        b.close()


def backup_of(b: Bench) -> dict[str, Any] | None:
    assert b.host is not None
    with b.host.client() as c:
        r = c.get("/v1/ledger/backup", params={"domain_id": b.domain}, headers=b.host.auth)
    return r.json() if r.status_code == 200 else None  # type: ignore[no-any-return]


def restore(b: Bench, handover_hex: str, sequence: str, key: str, request_id: str | None = None,
            **extra: Any) -> dict[str, Any]:
    return b.post("/v1/control", {  # type: ignore[no-any-return]
        "domain_id": b.domain, "client_epoch": b.epoch or b.open_epoch(), "type": "LEDGER_RESTORE",
        "request_id": request_id or key.encode().hex().ljust(32, "0")[:32], "expected_revision": sequence,
        "signed_cbor_b64": base64.b64encode(bytes.fromhex(handover_hex)).decode(), **extra}, key=key)


def entries(b: Bench) -> dict[str, dict[str, Any]]:
    """The root's own ledger (meshsim `ledger`: the bench's view of node 0), by device."""
    return {e["device"]: e for e in b.sim.ok("ledger")["entries"]}


def health(b: Bench) -> dict[str, Any]:
    return b.get("/v1/health")  # type: ignore[no-any-return]


def replace_root(b: Bench, term: str = "2") -> dict[str, Any]:
    """The old root is gone: the board comes back as a new root device without a ledger, paired with the Host again."""
    r = b.sim.ok(f"root-replace {term}")
    b.sim.ok("serial-pair 0 0")
    return r


@pytest.mark.e2e
@pytest.mark.scenario("LC09")
def test_the_host_keeps_the_roots_backup_and_restores_it_onto_a_replacement_root(bench: Callable[..., Bench]) -> None:
    b = bench(61, nodes=3)  # the root and node 1 (joined); node 2 joins later
    b.start_host(perms=PERMS, env_extra=FAST)
    b.await_root()
    # The root cuts a signed backup of its ledger for the Host (once per session, and after a ledger change).
    first = wait_for(lambda: backup_of(b), 40, "the first backup at the Host")
    old_root = first["root_device_id"]
    assert first["domain_id"] == b.domain and first["records"] == 2   # node 1's entry and the manifest
    assert db_rows(b.host.db, "SELECT COUNT(*) FROM ledger_backups")[0][0] == 1
    # A member joins: the root reports it, the Host asks again (after its debounce) and holds the newer one only.
    b.join_node(2, 0x62, revision=2)
    second = wait_for(lambda: (x := backup_of(b)) and int(x["sequence"]) > int(first["sequence"]) and x, 40,
                      "the backup after the join")
    assert second["records"] == 3 and second["root_device_id"] == old_root
    assert db_rows(b.host.db, "SELECT COUNT(*) FROM ledger_backups")[0][0] == 1
    before = entries(b)
    assert len(before) == 2 and all(e["state"] == "active" for e in before.values())
    # The root fails and its board is replaced: a new root identity (generation 2), and no ledger at all.
    replaced = replace_root(b)
    assert replaced["old_root"] == old_root and replaced["new_root"] != old_root
    op = restore(b, replaced["handover"], second["sequence"], "restore-1")
    assert op["state"] == "HOST_COMMITTED" and op["outcome"] == "PENDING"
    assert restore(b, replaced["handover"], second["sequence"], "restore-1")["id"] == op["id"]  # idempotent
    b.sim.ok("serial-reset")  # the replacement root starts: RECOVERY_REQUIRED until the Host restores it
    done = wait_for(lambda: (x := b.operation(op["id"]))["state"] == "FINAL" and x, 90, "the restore ends")
    assert done["outcome"] == "APPLIED", done
    kinds = {e["kind"]: e for e in done["evidence"]}
    assert kinds["ROOT_APPLIED"]["assurance"] == "SELF_REPORTED" and "3 records" in kinds["ROOT_APPLIED"]["details"]["reason"]
    # The root's own ledger is the old one: the same members, ACTIVE, the same generations; and the root is ready.
    after = entries(b)
    assert after.keys() == before.keys()
    for device, e in after.items():
        assert (e["state"], e["assignment"], e["membership"], e["confirmed"]) == (
            before[device]["state"], before[device]["assignment"], before[device]["membership"], before[device]["confirmed"])
    assert b.sim.ok("ledger")["ready"] is True
    # The Host accepted the new root for the domain because of the restore, and went on: ready, nodes still listed, and the
    # new root's backup is one sequence above the old root's (the sequence continues across roots).
    wait_for(lambda: health(b)["root"] == "READY", 60, "the bridge ready on the replacement root")
    assert db_rows(b.host.db, "SELECT lower(hex(root_device)) FROM domains")[0][0] == replaced["new_root"]
    assert len(b.get("/v1/nodes", domain_id=b.domain)["items"]) >= 2
    third = wait_for(lambda: (x := backup_of(b)) and x["root_device_id"] == replaced["new_root"] and x, 60,
                     "the replacement root's own backup")
    assert int(third["sequence"]) == int(second["sequence"]) + 1 and third["records"] == 3
    assert db_rows(b.host.db, "SELECT COUNT(*) FROM ledger_backups")[0][0] == 1


@pytest.mark.e2e
def test_a_refused_restore_leaves_the_root_without_a_ledger_and_the_corrected_one_still_works(
        bench: Callable[..., Bench]) -> None:
    b = bench(62, nodes=2)
    b.start_host(perms=PERMS, env_extra=FAST)
    b.await_root()
    held = wait_for(lambda: backup_of(b), 40, "the backup at the Host")
    # The fleet signed a handover that names a first term (5) the replacement root has not reached (it publishes 2).
    bad = replace_root(b, "2 5")
    b.sim.ok("serial-reset")
    wait_for(lambda: health(b)["root"] == "NOT_READY" and b.status().get("root_connected"), 40,
             "a root that is not the domain's: the bridge stays down")
    refused = restore(b, bad["handover"], held["sequence"], "restore-bad")
    done = wait_for(lambda: (x := b.operation(refused["id"]))["state"] == "FINAL" and x, 90, "the refused restore ends")
    assert done["outcome"] == "REJECTED"
    ev = {e["kind"]: e for e in done["evidence"]}
    assert ev["ROOT_REFUSED"]["details"]["reason"].endswith("NETWORK_MISMATCH"), done  # the root's own refusal, as it said it
    assert b.sim.ok("ledger")["ready"] is False and entries(b) == {}  # nothing was written that makes a ledger
    assert health(b)["root"] == "NOT_READY"
    assert db_rows(b.host.db, "SELECT COUNT(*) FROM meta WHERE key LIKE 'handover:%'")[0][0] == 0  # nothing was bound
    # The corrected handover (the board is provisioned again, the same replacement identity), asked after the root connected.
    good = replace_root(b, "2")
    assert good["new_root"] == bad["new_root"]
    b.sim.ok("serial-reset")
    ok = restore(b, good["handover"], held["sequence"], "restore-good")
    end = wait_for(lambda: (x := b.operation(ok["id"]))["state"] == "FINAL" and x, 90, "the restore ends")
    assert end["outcome"] == "APPLIED", end
    assert b.sim.ok("ledger")["ready"] is True and len(entries(b)) == 1
    wait_for(lambda: health(b)["root"] == "READY", 60, "the bridge ready on the replacement root")
