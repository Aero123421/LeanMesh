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
from bridge_bench import PERMS, Bench, db_rows, wait_for
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


def _final(b: Bench, op: str, what: str, timeout_s: float = 30) -> dict:  # type: ignore[type-arg]
    return wait_for(lambda: (x := b.operation(op))["state"] == "FINAL" and x, timeout_s, what)


def _mirror(b: Bench, device: str) -> str | None:
    """The membership the Host's node mirror shows for `device` (None: not listed)."""
    return next((n["membership"] for n in b.get("/v1/nodes", domain_id=b.domain)["items"] if n["device_id"] == device),
                None)


def _entry(b: Bench, device: str) -> str:
    """The root ledger's entry state of `device` as meshsim reads it (the RAM entry, not the effective view)."""
    return str(next(e for e in b.sim.ok("ledger")["entries"] if e["device"] == device)["state"])


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


@pytest.mark.e2e
@pytest.mark.scenario("S06")
def test_a_revocation_whose_entry_commit_failed_is_never_shown_active(bench: Callable[..., Bench]) -> None:
    """FIX5-D2: the root raised the member's floors and committed them; the commit of its entry then fails (the store is
    cut). The floors are the authorisation already: the Host's node mirror shows the member REVOKED at once (never ACTIVE
    while the ledger's entry still reads Active), and once the store answers the entry is made Blocked durably."""
    b = bench(0x5C, nodes=2)
    b.start_host(perms=[*PERMS, "REVOKE"])
    b.await_root()
    assert _mirror(b, b.node) == "ACTIVE"
    b.sim.ok("store-cut 0 1 before")  # the floors record (1 write since FIX10/FIX11 core changes) lands; the entry's first write is cut
    op = _control(b, "REVOKE", device_id=b.node, signed_cbor_b64=_signed(b, "revoke 1 2 2"))["id"]
    o = _final(b, op, "revoke with its entry commit cut")
    assert b.sim.ok("store-fired 0")["cut_fired"] is True
    assert o["outcome"] == "INDETERMINATE" and o["reason"] == "RECOVERY_REQUIRED"
    wait_for(lambda: _mirror(b, b.node) == "REVOKED", 30, "REVOKED in the node mirror while the store is down")
    # The root may already read the entry as Blocked in RAM or still as Active until its maintenance step commits it: either
    # way the floors refuse the member and the mirror says REVOKED (asserted above); the durable Blocked comes after the restore.
    assert _entry(b, b.node) in ("active", "blocked")
    b.sim.ok("store-restore 0")
    wait_for(lambda: _entry(b, b.node) == "blocked", 20, "the entry made Blocked once the store answers")
    assert _mirror(b, b.node) == "REVOKED"


@pytest.mark.e2e
@pytest.mark.scenario("LC01")
def test_a_control_the_root_refused_busy_is_retried_without_other_traffic(bench: Callable[..., Bench]) -> None:
    """Root cause of the CI failure of the test above ("timeout waiting for window applied"): the root installs one
    signed object at a time, so a window arriving while `grant` still installs its ExpectedSet page is refused BUSY
    (transient). The Host scheduled the retry (next_attempt = +RETRY_S) but slept until an unrelated wake-up: when
    nothing else was open its loop waited without a timeout. Here the root's worker is slowed so that the BUSY happens on
    purpose; the page's own completion event arrives before the retry is due, then nothing else happens."""
    b = bench(0x5D, nodes=3)
    b.start_host(perms=[*PERMS, "REVOKE"])
    b.await_root()
    signed = _signed(b, "window 2 300000 1")
    # Every root job 200 ms: the page install takes ~0.8 s - long enough for the window to meet it (BUSY), short enough to
    # end before the Host's retry is due (RETRY_S = 1 s), so that its completion event is the last wake-up there is.
    b.sim.ok("job-latency 0 200000")
    assert b.sim.ok("grant 2 1 2")["status"] == "OK"
    op = _control(b, "COMMISSIONING_WINDOW_SET", signed_cbor_b64=signed)["id"]

    def refused() -> bool:
        rows = db_rows(b.workdir / "host.db", "SELECT state,attempts FROM outbox WHERE operation=?", bytes.fromhex(op))
        return bool(rows) and rows[0][0] == "QUEUED" and int(rows[0][1]) >= 1

    wait_for(refused, 10, "the root's BUSY refusal of the window (precondition)", step=0.02)
    b.sim.ok("job-latency 0 2000")
    # Bounded by the Host's retry pause (RETRY_S = 1 s) and the root's own work, not by an unrelated event.
    o = _final(b, op, "window applied after the Host's own retry", timeout_s=8)
    assert o["outcome"] == "APPLIED", o
