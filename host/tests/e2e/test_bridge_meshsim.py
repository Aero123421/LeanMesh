"""S13 end to end with the real processes: real FastAPI Host -> pty serial (EDHOC purpose 3 session) -> meshsim
root with the bridge -> simulated radio -> real node cores. Evidence flows back into the Host DB and the /v1
event stream; root -> Host messages are committed in SQLite before the root hears HOST_STORE_ACK; crashes of
the Host between claim/send/record are reconciled by MessageId, never re-sent blindly; a root reset mid
operation ends as INDETERMINATE; external join approval goes through the Host.
Protocol bench only: sim results are not RF, timing, energy or real-Flash evidence.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from bridge_bench import Bench, db_rows, utc_in, wait_for
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


@pytest.mark.e2e
@pytest.mark.scenario("Q02")
@pytest.mark.scenario("D01")
def test_post_message_reaches_node_and_evidence_returns(bench: Callable[..., Bench]) -> None:
    b = bench(31)
    b.link_and_routes()
    b.start_host()
    b.await_root()
    st = b.status()
    assert st["root_connected"] is True and st["ready"] is True
    dl = {"mode": "utc", "expires_at": utc_in(120)}
    op = b.send(base64.b64encode(b"\x01\x02\x03\x04").decode(), key="same-key", deadline=dl)
    assert op["state"] == "HOST_COMMITTED" and op["outcome"] == "PENDING"
    op_id = op["id"]
    # Q02 (E2E part): the same Idempotency-Key 30 more times is the same operation and no new request at the root.
    for _ in range(30):
        again = b.send(base64.b64encode(b"\x01\x02\x03\x04").decode(), key="same-key", deadline=dl)
        assert again["id"] == op_id
    wait_for(lambda: "ROOT_ACCEPTED" in b.kinds(op_id), 20, "accepted by the root")
    bridge = b.sim.ok("serial-status")["bridge"]
    assert bridge["send_accepted"] == 1 and b.sim.ok("delivery 0")["accepted"] == 1
    # The node's application gets exactly the bytes the Host committed.
    ev = wait_for(lambda: (e := b.sim.ok("msg-next 1")["event"]) and e["kind"] == 2 and e, 30, "MESSAGE on the node")
    assert ev["payload"] == "01020304" and ev["port"] == 100
    o = wait_for(lambda: (x := b.operation(op_id))["state"] == "WAITING_RECEIPT" and x, 30, "waiting for the result")
    # Stored at the far end, application result still outstanding: never APPLIED yet.
    assert o["outcome"] == "PENDING" and {"ROOT_ACCEPTED", "END_RECEIVED"} <= b.kinds(op_id)
    assert "APP_APPLIED" not in b.kinds(op_id)
    assert b.sim.ok("msg-report 1 applied 0a0b")["status"] == "OK"
    done = wait_for(lambda: (x := b.operation(op_id))["outcome"] == "APPLIED" and x, 30, "APPLIED")
    assert done["state"] == "FINAL"
    kinds = {e["kind"]: e for e in done["evidence"]}
    assert {"ROOT_ACCEPTED", "ROOT_SENT", "HOP_ACCEPTED", "END_RECEIVED", "APP_APPLIED"} <= kinds.keys()
    assert kinds["APP_APPLIED"]["assurance"] == "END_VERIFIED" and kinds["ROOT_ACCEPTED"]["assurance"] == "SELF_REPORTED"
    assert kinds["HOP_ACCEPTED"]["assurance"] == "LINK_VERIFIED"
    # The same evidence is in the /v1 event stream (cursor GET).
    page = b.events()
    updates = [e for e in page["events"] if e["kind"] == "OPERATION_UPDATE"]
    assert updates and updates[-1]["evidence"]["details"]["outcome"] == "APPLIED"
    assert db_rows(b.host.db, "SELECT COUNT(*) FROM meta WHERE key LIKE 'send:%'")[0][0] == 0  # plan dropped at FINAL


def _node_op(b: Bench, op: int) -> dict:  # type: ignore[type-arg]
    return b.sim.ok(f"op 1 {op}")


@pytest.mark.e2e
@pytest.mark.scenario("H04")
@pytest.mark.scenario("Q02")
def test_node_to_host_message_is_committed_before_the_root_hears_the_ack(bench: Callable[..., Bench]) -> None:
    """A durable node -> Host message: the Host DB commit comes first. The Host is killed right after that
    commit (before HOST_STORE_ACK): the origin has NOT been told END_RECEIVED, the root still holds the message,
    and after the restart the same message is stored once and only then confirmed."""
    b = bench(32)
    b.link_and_routes()
    b.start_host(crash="after_commit:commit_inbox")
    b.await_root()
    sent = b.sim.ok("send 1 root received durable 200 0 0 c0ffee")
    op = sent["operation"]
    assert b.host.proc.wait(timeout=30) == 9  # killed by the seam right after the inbox commit
    rows = db_rows(b.host.db, "SELECT origin,payload FROM inbox")
    assert len(rows) == 1 and bytes(rows[0][1]) == bytes.fromhex("c0ffee")
    assert bytes(rows[0][0]).hex() == b.node
    time.sleep(3)  # ample time: nothing may claim the Host stored it
    o = _node_op(b, op)
    assert not (o["evidence_bits"] & (1 << 4)) and o["outcome"] == 0, o
    # The network keeps working without the Host: a volatile message to the root is confirmed by the root (its
    # declared store is RAM), and nothing the Host has not committed is reported as committed.
    now_ms = int(b.sim.ok("status")["now_us"]) // 1000
    vol = b.sim.ok(f"send 1 root received volatile 201 1 {now_ms + 120_000} 0a0b")["operation"]
    wait_for(lambda: _node_op(b, vol)["evidence_bits"] & (1 << 4), 30, "volatile message confirmed without the Host")
    assert not (_node_op(b, op)["evidence_bits"] & (1 << 4))
    b.start_host()
    b.await_root()
    o = wait_for(lambda: (x := _node_op(b, op))["evidence_bits"] & (1 << 4) and x, 40, "END_RECEIVED after the ACK")
    assert o["outcome"] == 1  # RECEIVED
    page = b.events()
    got = [e for e in page["events"] if e["kind"] == "MESSAGE_RECEIVED"]
    got = [e for e in got if base64.b64decode(e["payload_b64"]) == bytes.fromhex("c0ffee")]  # (+ the volatile one)
    assert len(got) == 1
    assert got[0]["origin"] == b.node and got[0]["evidence"]["assurance"] == "END_VERIFIED"
    assert len(db_rows(b.host.db, "SELECT 1 FROM inbox WHERE payload=?", bytes.fromhex("c0ffee"))) == 1  # not twice
    wait_for(lambda: b.sim.ok("serial-status")["bridge"]["ring_used"] == 0, 20, "root ring settled")


@pytest.mark.e2e
@pytest.mark.scenario("H04")
def test_host_crash_between_claim_and_send_is_never_resent(bench: Callable[..., Bench]) -> None:
    b = bench(33)
    b.link_and_routes()
    b.start_host(crash="after_commit:claim_batch")
    b.await_root()
    op = b.send()["id"]
    assert b.host.proc.wait(timeout=30) == 9
    assert db_rows(b.host.db, "SELECT external_write_possible,state FROM outbox") == [(1, "SENDING")]
    b.start_host()
    b.await_root()
    o = wait_for(lambda: (x := b.operation(op))["state"] == "FINAL" and x, 30, "reconciled")
    # The Host cannot tell "never arrived" from "arrived and forgotten": INDETERMINATE, not a re-send.
    assert o["outcome"] == "INDETERMINATE" and "ROOT_UNKNOWN_MESSAGE" in {e["kind"] for e in o["evidence"]}
    time.sleep(2)
    assert b.sim.ok("delivery 0")["accepted"] == 0  # the root never saw a request
    assert b.sim.ok("msg-next 1")["event"] is None or b.sim.ok("msg-next 1")["event"]["kind"] != 2


@pytest.mark.e2e
@pytest.mark.scenario("H04")
def test_host_crash_after_send_reconciles_by_message_id(bench: Callable[..., Bench]) -> None:
    b = bench(34)
    b.link_and_routes()
    b.start_host(crash="before_commit:apply_send")
    b.await_root()
    op = b.send()["id"]
    assert b.host.proc.wait(timeout=30) == 9  # the root has the request, the Host never recorded its answer
    assert db_rows(b.host.db, "SELECT state,external_write_possible FROM outbox")[0][1] == 1
    assert b.sim.ok("delivery 0")["accepted"] == 1
    b.start_host()
    b.await_root()
    ev = wait_for(lambda: (e := b.sim.ok("msg-next 1")["event"]) and e["kind"] == 2 and e, 40, "message on the node")
    assert b.sim.ok("msg-report 1 applied 0f")["status"] == "OK"
    o = wait_for(lambda: (x := b.operation(op))["outcome"] == "APPLIED" and x, 40, "APPLIED after reconciliation")
    assert o["state"] == "FINAL" and "APP_APPLIED" in {e["kind"] for e in o["evidence"]}
    assert ev["payload"] == "68656c6c6f"
    assert b.sim.ok("delivery 0")["accepted"] == 1  # still exactly one request at the root
    assert b.sim.ok("delivery 1")["delivered"] == 1  # and exactly one delivery at the node


@pytest.mark.e2e
@pytest.mark.scenario("H03")
def test_root_reset_mid_operation_ends_indeterminate(bench: Callable[..., Bench]) -> None:
    b = bench(35)
    b.link_and_routes()
    b.start_host()
    b.await_root()
    op = b.send()["id"]
    wait_for(lambda: "END_RECEIVED" in b.kinds(op), 30, "stored at the far end")
    assert b.operation(op)["outcome"] == "PENDING"
    old_boot = db_rows(b.host.db, "SELECT COUNT(*) FROM operations")[0][0]
    assert old_boot == 1
    b.sim.ok("serial-reset")  # the root MCU restarts: its operation table and gateway boot are gone
    o = wait_for(lambda: (x := b.operation(op))["state"] == "FINAL" and x, 60, "operation closed after the reset")
    assert o["outcome"] == "INDETERMINATE"
    kinds = {e["kind"] for e in o["evidence"]}
    assert "END_RECEIVED" in kinds and "APP_APPLIED" not in kinds  # what was proven stays, nothing is invented
    # The application answering afterwards does not resurrect an outcome the root no longer tracks.
    ev = b.sim.ok("msg-next 1")["event"]
    assert ev is None or ev["kind"] in (2, 3)
    assert b.operation(op)["outcome"] == "INDETERMINATE"


def _control(b: Bench, kind: str, **fields: object) -> dict:  # type: ignore[type-arg]
    return b.post("/v1/control", {"domain_id": b.domain, "client_epoch": b.epoch or b.open_epoch(),
                                  "type": kind, "request_id": __import__("os").urandom(16).hex(), **fields})


@pytest.mark.e2e
@pytest.mark.scenario("J04")
def test_external_join_is_approved_through_the_host(bench: Callable[..., Bench]) -> None:
    """External mode: nothing is reserved until the operator decides. The pending request reaches the Host
    (lifecycle list + event), the decision goes through POST /v1/control -> JOIN_DECIDE, a decision on stale
    or foreign state is refused by the root, and the join completes on both sides."""
    b = bench(36, join=False, mode="external")
    b.start_host()
    wait_for(lambda: b.status().get("root_connected"), 25, "root_connected")
    assert b.sim.ok("grant 1 1 1")["status"] == "OK"
    time.sleep(0.5)
    node = b.sim.ok("membership 1")["device"]
    assert b.sim.ok("join 1 96")["status"] == "OK"
    domain = wait_for(lambda: (r := db_rows(b.host.db, "SELECT id FROM domains")) and bytes(r[0][0]).hex(), 20, "domain")
    b.domain = domain
    item = wait_for(lambda: (i := b.get("/v1/lifecycle/requests", domain_id=domain)["items"]) and i[0], 40,
                    "pending join at the Host")
    assert item["device_id"] == node and item["state"] == "PENDING_APPROVAL"
    assert b.sim.ok("membership 1")["state"] != 5  # nothing happened without the operator
    assert any(e["kind"] == "JOIN_PENDING" for e in b.events()["events"])
    # The Host stops while the request is pending: no approval happens by itself and the request survives.
    b.kill_host()
    time.sleep(3)
    assert b.sim.ok("membership 1")["state"] != 5 and b.sim.ok("ledger")["activated"] == 0
    b.start_host()
    wait_for(lambda: b.status().get("root_connected"), 25, "root_connected again")
    item = wait_for(lambda: (i := b.get("/v1/lifecycle/requests", domain_id=domain)["items"]) and i[0], 20, "pending")
    assert item["state"] == "PENDING_APPROVAL" and item["device_id"] == node and len(b.get("/v1/lifecycle/requests", domain_id=domain)["items"]) == 1
    # A decision for a device with no pending request never reaches the root as an approval.
    other = _control(b, "JOIN_DECISION", device_id="ab" * 32, decision="APPROVE", expected_revision=item["revision"])
    o = wait_for(lambda: (x := b.operation(other["id"]))["state"] == "FINAL" and x, 20, "refusal")
    assert o["outcome"] == "REJECTED" and o["reason"].startswith("NOT_FOUND")
    # A stale ledger revision is refused by the root (CONFLICT) and the request stays pending.
    stale = _control(b, "JOIN_DECISION", device_id=node, decision="APPROVE", expected_revision="99")
    o = wait_for(lambda: (x := b.operation(stale["id"]))["state"] == "FINAL" and x, 20, "stale refusal")
    assert o["outcome"] == "REJECTED" and o["reason"] == "CONFLICT"
    assert b.sim.ok("membership 1")["state"] != 5
    # The real decision.
    ok = _control(b, "JOIN_DECISION", device_id=node, decision="APPROVE", expected_revision=item["revision"])
    o = wait_for(lambda: (x := b.operation(ok["id"]))["state"] == "FINAL" and x, 20, "decision applied")
    assert o["outcome"] == "APPLIED" and "ROOT_APPLIED" in {e["kind"] for e in o["evidence"]}
    b.await_active(1)
    nodes = wait_for(lambda: (n := b.get("/v1/nodes", domain_id=domain)["items"]) and n[0]["membership"] == "ACTIVE" and n, 30,
                     "node ACTIVE in the Host mirror")
    assert nodes[0]["device_id"] == node and nodes[0]["confirmed"] is True
    life = b.get("/v1/lifecycle/requests", domain_id=domain)["items"][0]
    assert life["state"] == "APPROVED"


@pytest.mark.e2e
@pytest.mark.scenario("H04")
def test_cancel_of_an_unsent_message_is_exact(bench: Callable[..., Bench]) -> None:
    """The route is down before any frame of this message left the root: CANCEL is exact (CANCELLED_NOT_SENT)."""
    b = bench(37)
    b.link_and_routes()
    b.sim.ok("link 0 1 down")
    b.start_host()
    b.await_root()
    op = b.send()["id"]
    wait_for(lambda: "ROOT_ACCEPTED" in b.kinds(op), 20, "accepted by the root")
    assert b.host and b.post(f"/v1/operations/{op}/cancel", {}, expect=202)["id"] == op
    o = wait_for(lambda: (x := b.operation(op))["state"] == "FINAL" and x, 20, "cancelled")
    assert o["outcome"] == "CANCELLED_NOT_SENT"
    assert "HOST_CANCEL_REQUESTED" in {e["kind"] for e in o["evidence"]}


# ---- methods 1..15 on the wire, with a raw Host session (no Host process) -----------------------------------
class _Raw:
    def __init__(self, port: str, kit: Path) -> None:
        import asyncio  # noqa: PLC0415

        from leanmesh_host.serial import SerialLink  # noqa: PLC0415

        self.loop = asyncio.new_event_loop()
        self.link = SerialLink(port, kit.read_bytes(), self.loop)
        self.link.start()
        deadline = time.monotonic() + 20
        while not self.link.connected and time.monotonic() < deadline:
            self.loop.run_until_complete(asyncio.sleep(0.05))
        assert self.link.connected

    def call(self, method: int, params: object = None) -> tuple[int, int | None, dict | None]:  # type: ignore[type-arg]
        from leanmesh_host.wire import cbor_decode  # noqa: PLC0415

        r = self.loop.run_until_complete(self.link.request(method, params))
        return r.status, r.operation_id, (cbor_decode(r.result) if r.result else None)

    def close(self) -> None:
        self.link.stop()
        self.loop.close()


@pytest.mark.e2e
@pytest.mark.scenario("T12")
def test_serial_methods_1_to_15_answer_typed_results_or_unsupported(
        meshsim: Callable[..., MeshSim], tmp_path: Path) -> None:
    import os  # noqa: PLC0415

    from leanmesh_host.bridge import mapping  # noqa: PLC0415

    sim = meshsim("--nodes", "1", "--clock", "realtime", "--serial-pty", "--serial-bridge", "--seed", "38")
    sim.ok("provision 0 1 root")
    kit = tmp_path / "kit.cbor"
    sim.ok(f"serial-kit {kit} 0")
    sim.ok("serial-pair 0 0")
    assert sim.ok("start 0")["status"] == "OK"
    time.sleep(1.0)
    raw = _Raw(sim.ready["serial_pty"], kit)
    try:
        UNSUP, INVALID, CONFLICT, NOT_FOUND = 2, 1, 9, 24
        st, _, caps = raw.call(1)
        assert st == 0 and caps is not None and caps["enabled"] == [] and caps["root_time"] is None
        assert len(caps["domain"]) == 16 and len(caps["root"]) == 32 and caps["gateway_boot"] >= 1
        assert raw.call(1, [1])[0] == INVALID  # CAPABILITIES takes no params
        st, _, nodes = raw.call(7, [None])
        assert st == 0 and nodes == {"nodes": [], "pending": [], "revision": 0}
        assert raw.call(7, [os.urandom(32)])[0] == 0 and raw.call(7, [b"short"])[0] == INVALID
        # SEND: the root recomputes the intent hash. A wrong one is CONFLICT; the right one is accepted, and the
        # same MessageId + hash again is the same operation (a retry after a lost answer), other hash: CONFLICT.
        dest, mid, payload = os.urandom(32), os.urandom(16), b"\x01\x02"
        req = {"app_port": 100, "delivery": "RECEIVED", "storage": "DURABLE", "priority": "NORMAL"}
        digest = mapping.intent_hash(caps["root"], dest, caps["domain"], req, 0, 0, payload)
        flags = mapping.send_flags(req)
        params = [dest, mid, digest, 100, flags, 0, 0, False, payload]
        assert raw.call(2, [dest, mid, bytes(32), 100, flags, 0, 0, False, payload])[0] == CONFLICT
        assert raw.call(2, [dest, mid, digest, 100, 31, 0, 0, False, payload])[0] == INVALID  # CONTROL priority
        assert raw.call(2, [dest, mid, digest, 100, flags, 0, 0, True, payload])[0] == UNSUP  # object transfer
        deadline = time.monotonic() + 15
        st, op, snap = raw.call(2, params)
        while st != 0 and time.monotonic() < deadline:  # the root's delivery module is still loading its journal
            time.sleep(0.2)
            st, op, snap = raw.call(2, params)
        assert st == 0 and op and snap is not None and snap["evidence_bits"] & 1  # accepted (RAM), nothing more
        assert snap["message_id"] == mid and snap["intent_hash"] == digest and snap["outcome"] == 0
        assert raw.call(2, params)[1] == op  # idempotent
        other = mapping.intent_hash(caps["root"], dest, caps["domain"], req, 0, 0, b"\x03")
        assert raw.call(2, [dest, mid, other, 100, flags, 0, 0, False, b"\x03"])[0] == CONFLICT
        # GET_MESSAGE by (origin, assignment, MessageId, hash) finds it and returns the operation number.
        def persisted() -> dict | None:  # type: ignore[type-arg]
            _, got, s2 = raw.call(3, [caps["root"], caps["assignment"], mid, digest])
            assert got == op and s2 is not None and s2["message_id"] == mid
            return s2 if s2["evidence_bits"] & 2 else None  # the journal commit is a separate, later fact

        assert wait_for(persisted, 10, "journal commit evidence")["outcome"] == 0
        assert raw.call(3, [caps["root"], caps["assignment"], os.urandom(16), digest])[0] == NOT_FOUND
        # CANCEL: an operation number is valid only in the gateway boot that issued it.
        assert raw.call(4, [caps["gateway_boot"] + 1, op])[0] == NOT_FOUND
        st, _, cancelled = raw.call(4, [caps["gateway_boot"], op])
        assert st == 0 and cancelled is not None and cancelled["outcome"] == 5  # CANCELLED_NOT_SENT
        # JOIN_DECIDE, INSTALL_CONTROL, HOST_STORE_ACK, EVENT_ACK, GET_REQUEST.
        req_id = os.urandom(16)
        assert raw.call(5, [req_id, os.urandom(32), os.urandom(32), 1, 5])[0] == CONFLICT  # not the ledger revision
        assert raw.call(5, [req_id, os.urandom(32), os.urandom(32), 1, 0])[0] == NOT_FOUND
        assert raw.call(6, [99, b"\x00"])[0] == UNSUP and raw.call(6, [1])[0] == INVALID
        assert raw.call(9, [os.urandom(32), 1, os.urandom(16), os.urandom(32), os.urandom(16), 1])[0] == NOT_FOUND
        assert raw.call(10, [caps["gateway_boot"] + 1, 0])[0] == CONFLICT
        assert raw.call(10, [caps["gateway_boot"], 999])[0] == INVALID  # ahead of anything ever sent
        assert raw.call(13, [req_id])[0] == NOT_FOUND
        # Methods of modules that have not landed: well-formed = UNSUPPORTED, malformed = INVALID_ARGUMENT.
        assert raw.call(8, [1, 0, 0, None])[0] == UNSUP and raw.call(8, [1])[0] == INVALID
        assert raw.call(11, [1, 0])[0] == UNSUP and raw.call(11, [3, 0])[0] == INVALID
        assert raw.call(12, [os.urandom(32), 0, 1])[0] == UNSUP
        assert raw.call(14, [1, 0, [os.urandom(32)]])[0] == UNSUP
        assert raw.call(15, [1, 1, os.urandom(16), 0, 16])[0] == UNSUP and raw.call(15, [1, 1, os.urandom(16), 0, 17])[0] == INVALID
    finally:
        raw.close()
    st = sim.ok("serial-status")
    assert st["bridge"]["malformed"] == 0 and st["bridge"]["replies_dropped"] == 0 and st["unsupported_replies"] == 0


def test_status_names_match_the_registry() -> None:
    import json  # noqa: PLC0415

    from harness import REPO_ROOT  # noqa: PLC0415
    from leanmesh_host.bridge import mapping  # noqa: PLC0415

    codes = json.loads((REPO_ROOT / "protocol" / "registry.json").read_text())["status_codes"]
    table = dict(codes) if isinstance(codes, dict) else {c["name"]: c["value"] for c in codes}
    assert all(mapping.STATUS_NAMES[v] == k for k, v in table.items()) and len(mapping.STATUS_NAMES) == len(table)
