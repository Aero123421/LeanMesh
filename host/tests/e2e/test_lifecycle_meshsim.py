"""S18 lifecycle through the real processes: FastAPI Host -> pty serial -> meshsim root with the bridge. Signed
lifecycle objects of the TEST-ONLY fleet issuer (meshsim `lc-object`) are submitted with POST /v1/control like an
operator's signing service would; the root verifies and applies them and the Host records the root's own result.
A RECOVERY_REQUIRED of the root (a storage cut in the middle of its commit) is INDETERMINATE at the Host, never
REJECTED. Protocol bench only: sim results are not RF, timing, energy or real-Flash evidence.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Callable
from pathlib import Path

import pytest
from bridge_bench import PERMS, Bench, wait_for
from harness import MeshSim


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


def _signed(b: Bench, line: str) -> str:
    return base64.b64encode(bytes.fromhex(b.sim.ok(f"lc-object {line}")["cose"])).decode()


def _control(b: Bench, kind: str, **fields: object) -> dict:  # type: ignore[type-arg]
    return b.post("/v1/control", {"domain_id": b.domain, "client_epoch": b.epoch or b.open_epoch(),
                                  "expected_revision": "0", "type": kind, "request_id": os.urandom(16).hex(),
                                  **fields})


def _final(b: Bench, op: str, what: str) -> dict:  # type: ignore[type-arg]
    return wait_for(lambda: (x := b.operation(op))["state"] == "FINAL" and x, 30, what)


@pytest.mark.e2e
@pytest.mark.scenario("S06")
@pytest.mark.scenario("LC01")
def test_revoke_window_and_indeterminate_through_the_host(bench: Callable[..., Bench]) -> None:
    """REVOKE: the root blocks the member and the Host's node mirror says REVOKED. A cut of the root's storage in the
    middle of a revocation's commit is RECOVERY_REQUIRED at the root and INDETERMINATE at the Host. A commissioning
    window opens a CLOSED root for exactly the planned device."""
    b = bench(0x5A, nodes=3)
    b.start_host(perms=[*PERMS, "REVOKE"])
    b.await_root()
    # REVOKE of the joined member (fleet-signed floors above its generations).
    op = _control(b, "REVOKE", device_id=b.node, signed_cbor_b64=_signed(b, "revoke 1 2 2"))["id"]
    o = _final(b, op, "revoke applied")
    assert o["outcome"] == "APPLIED" and "ROOT_APPLIED" in {e["kind"] for e in o["evidence"]}
    entry = next(e for e in b.sim.ok("ledger")["entries"] if e["device"] == b.node)
    assert entry["state"] == "blocked"
    wait_for(lambda: any(n["device_id"] == b.node and n["membership"] == "REVOKED"
                         for n in b.get("/v1/nodes", domain_id=b.domain)["items"]), 30, "REVOKED in the node mirror")
    # The root's store dies at the floors commit of the next revocation: unknown durable state -> INDETERMINATE.
    b.sim.ok("store-cut 0 0 torn")
    op = _control(b, "REVOKE", device_id="ab" * 32, signed_cbor_b64=_signed(b, "revoke " + "ab" * 32 + " 1 1"))["id"]
    o = _final(b, op, "revoke with a storage cut")
    assert b.sim.ok("store-fired 0")["cut_fired"] is True
    assert o["outcome"] == "INDETERMINATE" and o["reason"] == "RECOVERY_REQUIRED"
    b.sim.ok("store-restore 0")
    # A commissioning window: a CLOSED root admits the planned device inside it.
    b.sim.ok("join-mode closed")
    assert b.sim.ok("grant 2 1 2")["status"] == "OK"
    op = _control(b, "COMMISSIONING_WINDOW_SET", signed_cbor_b64=_signed(b, "window 2 300000 1"))["id"]
    o = _final(b, op, "window applied")
    assert o["outcome"] == "APPLIED"
    assert b.sim.ok("join 2 112")["status"] == "OK"
    b.await_active(2, timeout_s=40)
