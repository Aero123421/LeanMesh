"""Host API through the real FastAPI app and a real SQLite file. Every response is validated
against api/openapi.json; rejections are checked for "nothing was written"."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from host_util import (ALL_PERMS, DOMAIN, NODE, check, make_settings, message, rows, running)
from leanmesh_host.db import mirror, outbox


def op_count(h: Any) -> int:
    return int(h.db(lambda c: c.execute("SELECT COUNT(*) FROM operations").fetchone()[0]))


def test_every_endpoint_shape_matches_the_contract(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        check("get_status", h.get("/v1/status"))
        e = h.epoch()
        r = h.post("/v1/messages", message(e), "k1")
        check("submit_message", r)
        assert r.status_code == 202 and r.json()["state"] == "HOST_COMMITTED"
        assert r.json()["outcome"] == "PENDING" and r.json()["evidence"] == []
        op = r.json()["id"]
        check("get_operation", h.get(f"/v1/operations/{op}"))
        c = h.post("/v1/operations/" + op + "/cancel", {}, "ignored")
        check("cancel_operation", c)
        assert c.status_code == 202 and c.json()["outcome"] == "CANCELLED_NOT_SENT"
        check("list_nodes", h.get("/v1/nodes", domain_id=DOMAIN))
        node = h.get(f"/v1/nodes/{NODE}", domain_id=DOMAIN)
        check("get_node", node)
        assert node.json()["assignment_generation"] == "1" and node.json()["root_depth"] == 2
        # Unreported power / channel state: honest absence, never defaults.
        check("getNodePower", h.get(f"/v1/nodes/{NODE}/power", domain_id=DOMAIN))
        assert h.get(f"/v1/nodes/{NODE}/power", domain_id=DOMAIN).status_code == 404
        ch = h.get("/v1/channel", domain_id=DOMAIN)
        check("get_channel", ch)
        assert ch.status_code == 503 and ch.json()["code"] == "ROOT_UNAVAILABLE"
        power = {"mode": "REPORT_ONLY", "state": "SLEEPING", "policy_revision": "3",
                 "validity_bits": "5", "measured_energy_j": None}
        h.db(lambda c: mirror.put_power(c, bytes.fromhex(DOMAIN), bytes.fromhex(NODE), {}, power))
        h.db(lambda c: mirror.put_channel(c, bytes.fromhex(DOMAIN), {
            "current_channel": 6, "channel_epoch": 2, "state": "COMMITTED", "required": [NODE],
            "applied": [NODE], "unreachable": []}))
        got = h.get(f"/v1/nodes/{NODE}/power", domain_id=DOMAIN)
        check("getNodePower", got)
        assert got.json()["measured_energy_j"] is None
        check("get_channel", h.get("/v1/channel", domain_id=DOMAIN))
        check("get_node", h.get(f"/v1/nodes/{NODE}", domain_id=DOMAIN))
        h.db(lambda c: c.execute(
            "INSERT INTO lifecycle_requests VALUES(?,?,?,?,?,?,NULL,NULL,'[]')",
            (b"\x01" * 16, bytes.fromhex(DOMAIN), bytes.fromhex(NODE), "TRANSFER", "PENDING", 4)))
        lc = h.get("/v1/lifecycle/requests", domain_id=DOMAIN)
        check("list_lifecycle", lc)
        assert lc.json()["items"][0]["revision"] == "4"
        page = h.get("/v1/events", domain_id=DOMAIN)
        check("read_events", page)
        assert [x["kind"] for x in page.json()["events"]] == ["OPERATION_UPDATE"] * 2
        ack = h.post("/v1/consumers/kg.main/ack", {"domain_id": DOMAIN, "journal_id": page.json()["next_cursor"][:32],
                                                    "sequence": page.json()["next_cursor"].split(":")[1]}, "-")
        check("ack_consumer", ack)
        # Group targets: rows exist only once the GROUP slice writes them.
        gt = h.get(f"/v1/operations/{op}/targets")
        check("getGroupTargets", gt)
        assert gt.status_code == 400
        h.db(lambda c: c.execute(
            "INSERT INTO group_targets VALUES(?,?,?,?,?,?,?,?,'WAIT_ROUTE','PENDING','[]')",
            (bytes.fromhex(op), 0, b"\x02" * 16, b"\x03" * 32, bytes.fromhex(NODE), 1, 1, None)))
        gt = h.get(f"/v1/operations/{op}/targets")
        check("getGroupTargets", gt)
        assert gt.json()["total"] == 1 and gt.json()["targets"][0]["outcome"] == "PENDING"
        bad = h.get(f"/v1/operations/{op}/targets", snapshot_token="04" * 16)
        check("getGroupTargets", bad)
        assert bad.status_code == 409
        ctl = h.post("/v1/control", {"domain_id": DOMAIN, "client_epoch": e, "expected_revision": "0",
                                     "type": "CHANNEL_RECALCULATE", "request_id": "ab" * 16}, "c1")
        check("submit_control", ctl)
        assert ctl.status_code == 503  # AUTO_CHANNEL not reported by any root


def test_error_envelope_and_auth(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        e = h.epoch()
        for op_id, resp in (("submit_message", h.post("/v1/messages", message(e), "k", who="reader")),
                            ("submit_message", h.http.post("/v1/messages", json=message(e))),
                            ("get_operation", h.get("/v1/operations/" + "00" * 16)),
                            ("get_operation", h.get("/v1/operations/nothex")),
                            ("read_events", h.get("/v1/events")),
                            ("get_node", h.get(f"/v1/nodes/{NODE}", domain_id="AB" * 16))):
            check(op_id, resp)
            assert resp.status_code in (400, 401, 403, 404)
        assert h.post("/v1/messages", message(e), "k", who="reader").json()["details"]["required"] == "SEND"
        assert h.http.get("/nope").json()["code"] == "NOT_FOUND"
        assert op_count(h) == 0


BAD_MESSAGES = {
    "u63_number": dict(coalesce_key=5, queue_mode="LATEST", delivery="BEST_EFFORT", storage="VOLATILE"),
    "u63_leading_zero": dict(coalesce_key="01", queue_mode="LATEST", delivery="BEST_EFFORT", storage="VOLATILE"),
    "u63_too_big": dict(coalesce_key="9223372036854775808", queue_mode="LATEST", delivery="BEST_EFFORT", storage="VOLATILE"),
    "latest_needs_key": dict(queue_mode="LATEST", delivery="BEST_EFFORT", storage="VOLATILE"),
    "key_needs_latest": dict(coalesce_key="1"),
    "latest_applied": dict(queue_mode="LATEST", coalesce_key="1", delivery="APPLIED", storage="VOLATILE",
                           deadline={"mode": "root", "root_term": 1, "expires_root_ms": "9"}),
    "none_deadline_for_command": dict(delivery="APPLIED", deadline={"mode": "none"}),
    "none_deadline_best_effort": dict(delivery="BEST_EFFORT", storage="VOLATILE"),
    "root_deadline_zero": dict(deadline={"mode": "root", "root_term": 1, "expires_root_ms": "0"}),
    "priority_control": dict(priority="CONTROL"),
    "extra_field": dict(surprise=1),
    "b64_no_padding": dict(payload_b64="aGVsbG8"),
    "b64_whitespace": dict(payload_b64="aGVs bG8="),
    "b64_urlsafe": dict(payload_b64="_-8="),
    "b64_noncanonical_bits": dict(payload_b64="aGVsbG9="),
    "uppercase_device": dict(destination={"kind": "node", "device_id": "AA" * 32}),
    "short_domain": dict(domain_id="d0" * 15),
    "port_zero": dict(app_port=0),
    "utc_without_offset": dict(deadline={"mode": "utc", "expires_at": "2999-01-01T00:00:00"}),
}


@pytest.mark.parametrize("name", sorted(BAD_MESSAGES))
def test_message_validation_rejects_without_writing(tmp_path: Path, name: str) -> None:
    with running(make_settings(tmp_path)) as h:
        r = h.post("/v1/messages", message(h.epoch(), **BAD_MESSAGES[name]), "k")
        check("submit_message", r)
        assert r.status_code == 400 and r.json()["code"] == "INVALID_ARGUMENT", r.text
        assert "payload" not in json.dumps(r.json()["details"]).lower() or "fields" in r.json()["details"]
        assert op_count(h) == 0


def test_size_capability_and_destination_rules(tmp_path: Path) -> None:
    import base64
    with running(make_settings(tmp_path)) as h:
        e = h.epoch()
        b64 = lambda n: base64.b64encode(b"x" * n).decode()  # noqa: E731
        assert h.post("/v1/messages", message(e, payload_b64=b64(512)), "a").status_code == 202
        big = h.post("/v1/messages", message(e, payload_b64=b64(513)), "b")
        check("submit_message", big)
        assert big.status_code == 413 and big.json()["code"] == "PAYLOAD_TOO_LARGE"
        obj = h.post("/v1/messages", message(e, payload_b64=b64(4096), object_transfer=True), "c")
        assert obj.status_code == 503 and obj.json()["details"]["required_capability"] == "OBJECT_4K"
        h.hub.set_root(True, ["OBJECT_4K"])
        assert h.post("/v1/messages", message(e, payload_b64=b64(4096), object_transfer=True), "c").status_code == 202
        assert h.post("/v1/messages", message(e, payload_b64=b64(4097), object_transfer=True), "d").status_code == 413
        h.hub.set_root(False)
        assert h.get("/v1/status").json()["capabilities"]["enabled"] == []
        group = h.post("/v1/messages", message(e, destination={"kind": "group", "group_id": 1, "revision": "1"}), "g")
        assert group.status_code == 503 and group.json()["code"] == "UNSUPPORTED"
        unknown = h.post("/v1/messages", message(e, destination={"kind": "node", "device_id": "bb" * 32}), "n")
        assert unknown.status_code == 404
        past = h.post("/v1/messages", message(e, delivery="APPLIED", deadline={
            "mode": "utc", "expires_at": "2001-01-01T00:00:00Z"}), "p")
        assert past.status_code == 400 and past.json()["code"] == "EXPIRED"
        assert h.post("/v1/messages", message(e, destination={"kind": "root_app"}), "r").status_code == 202
        assert op_count(h) == 3


def test_control_rules_permissions_capabilities_and_revision(tmp_path: Path) -> None:
    perms = {"alice": ALL_PERMS, "sender": ["SEND", "READ"], "approver": ["APPROVE", "READ"]}
    with running(make_settings(tmp_path, perms)) as h:
        e = h.epoch()
        base = {"domain_id": DOMAIN, "client_epoch": e, "expected_revision": "0", "request_id": "ab" * 16}

        epochs = {"alice": e, "approver": h.epoch("approver"), "sender": h.epoch("sender")}

        def ctl(key: str, who: str = "alice", **body: Any) -> Any:
            r = h.post("/v1/control", {**base, "client_epoch": epochs[who], **body}, key, who=who)
            check("submit_control", r)
            return r

        assert ctl("1", type="JOIN_DECISION", device_id=NODE, decision="APPROVE").status_code == 202
        # mode-specific fields: missing and superfluous are both 400
        assert ctl("2", type="JOIN_DECISION", device_id=NODE).status_code == 400
        assert ctl("3", type="LEAVE", device_id=NODE, leave_mode="DRAIN", freeze=True).status_code == 400
        assert ctl("4", type="REVOKE", device_id=NODE, signed_cbor_b64="!!!").status_code == 400
        assert ctl("5", type="CHANNEL_FREEZE").status_code == 400
        # authority: IMMEDIATE needs REVOKE, not just APPROVE
        r = ctl("6", who="approver", type="LEAVE", device_id=NODE, leave_mode="IMMEDIATE")
        assert r.status_code == 403 and r.json()["details"]["required"] == ["REVOKE"]
        assert ctl("7", who="approver", type="LEAVE", device_id=NODE, leave_mode="DRAIN").status_code == 202
        assert ctl("8", who="sender", type="JOIN_DECISION", device_id=NODE, decision="REJECT").status_code == 403
        # capability gating: unknown mandatory capability -> 503 UNSUPPORTED, then allowed
        signed = {"type": "TRANSFER", "device_id": NODE, "signed_cbor_b64": "AAEC"}
        r = ctl("9", **signed)
        assert r.status_code == 503 and r.json()["details"]["required_capability"] == "SIGNED_TRANSFER"
        h.hub.set_root(True, ["SIGNED_TRANSFER"])
        assert ctl("9", **signed).status_code == 202
        # expected_revision is compared where the Host holds the current value
        h.db(lambda c: c.execute("UPDATE domains SET policy_revision=5"))
        stale = ctl("10", type="POLICY_SET", signed_cbor_b64="AAEC")
        assert stale.status_code == 409 and stale.json()["details"]["current_revision"] == "5"
        assert ctl("11", type="POLICY_SET", signed_cbor_b64="AAEC", expected_revision="5").status_code == 202
        # request_id/content mismatch under one Idempotency-Key is a conflict, not a new command
        assert ctl("11", type="POLICY_SET", signed_cbor_b64="AAEC", expected_revision="5",
                   request_id="cd" * 16).status_code == 409
        stored = rows(tmp_path / "host.db", "SELECT type,length(payload) FROM operations WHERE type='POLICY_SET'")
        assert stored == [("POLICY_SET", 3)]


def test_idempotency_replay_isolation_and_epochs(tmp_path: Path) -> None:
    """Q02 (host part) and H01: 100 replays of one key are one operation, one outbox row, one event.
    (The request-rate limit is off in these tests: it is covered in test_host_limits.py.)"""
    with running(make_settings(tmp_path)) as h:
        e = h.epoch()
        first = h.post("/v1/messages", message(e), "same")
        replies = [h.post("/v1/messages", message(e), "same") for _ in range(100)]
        assert all(r.status_code == 202 and r.json() == first.json() for r in replies)
        counts = h.db(lambda c: [c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                                 for t in ("operations", "outbox", "events")])
        assert counts == [1, 1, 1]
        changed = h.post("/v1/messages", message(e, app_port=8), "same")
        check("submit_message", changed)
        assert changed.status_code == 409 and changed.json()["code"] == "CONFLICT"
        # another principal with the same key and epoch id: not visible, not merged
        other_epoch = h.epoch("bob")
        assert h.post("/v1/messages", message(e), "same", who="bob").status_code == 404  # foreign epoch
        bob = h.post("/v1/messages", message(other_epoch), "same", who="bob")
        assert bob.status_code == 202 and bob.json()["id"] != first.json()["id"]
        assert h.get(f"/v1/operations/{first.json()['id']}", who="bob").status_code == 404
        assert h.post(f"/v1/operations/{first.json()['id']}/cancel", {}, "-", who="bob").status_code == 404
        # closing an epoch: replay still answers, anything new is EPOCH_CLOSED, idempotent close
        for _ in range(2):
            closed = h.post(f"/v1/epochs/{e}/close", {}, "-")
            check("close_epoch", closed)
            assert closed.json() == {"id": e, "state": "CLOSED"}
        assert h.post("/v1/messages", message(e), "same").json() == first.json()
        late = h.post("/v1/messages", message(e), "fresh")
        check("submit_message", late)
        assert late.status_code == 410 and late.json()["code"] == "EPOCH_CLOSED"
        # opening: same Idempotency-Key + request_id -> same epoch; other request_id -> 409
        a = h.http.post("/v1/epochs", json={"request_id": "11" * 16}, headers={"Authorization": "Bearer tok-alice", "Idempotency-Key": "op"})
        b = h.http.post("/v1/epochs", json={"request_id": "11" * 16}, headers={"Authorization": "Bearer tok-alice", "Idempotency-Key": "op"})
        c = h.http.post("/v1/epochs", json={"request_id": "22" * 16}, headers={"Authorization": "Bearer tok-alice", "Idempotency-Key": "op"})
        assert a.json() == b.json() and c.status_code == 409
        check("open_epoch", c)


def test_latest_supersedes_only_unsent_records(tmp_path: Path) -> None:
    latest = dict(queue_mode="LATEST", delivery="BEST_EFFORT", storage="VOLATILE", coalesce_key="7",
                  deadline={"mode": "root", "root_term": 1, "expires_root_ms": "5000"})
    with running(make_settings(tmp_path)) as h:
        e = h.epoch()
        a = h.post("/v1/messages", message(e, **latest), "a").json()
        b = h.post("/v1/messages", message(e, **latest), "b").json()
        other_key = h.post("/v1/messages", message(e, **{**latest, "coalesce_key": "8"}), "o").json()
        first = h.get(f"/v1/operations/{a['id']}").json()
        assert first["outcome"] == "SUPERSEDED" and first["superseded_by"] == b["id"]
        assert h.get(f"/v1/operations/{other_key['id']}").json()["outcome"] == "PENDING"
        h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x01" * 16, 16))  # b is now on the wire
        c2 = h.post("/v1/messages", message(e, **latest), "c").json()
        assert h.get(f"/v1/operations/{b['id']}").json()["outcome"] == "PENDING"  # sent: kept
        assert h.get(f"/v1/operations/{c2['id']}").json()["state"] == "HOST_COMMITTED"


def test_operation_evidence_is_monotonic_and_history_is_kept(tmp_path: Path) -> None:
    ev = lambda kind, assurance="END_VERIFIED", **d: {"kind": kind, "assurance": assurance,  # noqa: E731
                                                       **({"details": d} if d else {})}
    with running(make_settings(tmp_path)) as h:
        e = h.epoch()
        op = h.post("/v1/messages", message(e, delivery="APPLIED", deadline={
            "mode": "root", "root_term": 1, "expires_root_ms": "9000"}), "a").json()["id"]
        raw = bytes.fromhex(op)
        items = h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x07" * 16))
        assert [i.operation for i in items] == [raw] and items[0].payload == b"hello"
        assert h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x07" * 16)) == []  # never handed out twice
        mid = b"\x09" * 16
        h.db(lambda c: outbox.record(c, h.hub.cfg, raw, state="WAITING_RECEIPT", outcome="SUBMITTED",
                                     evidence=ev("HOP_ACCEPTED", "LINK_VERIFIED"), message_id=mid))
        h.db(lambda c: outbox.record(c, h.hub.cfg, raw, outcome="RECEIVED", evidence=ev("END_RECEIVED")))
        cancel = h.post(f"/v1/operations/{op}/cancel", {}, "-").json()
        # sent: cancel is only a recorded request; outcome and state are not rewritten
        assert cancel["outcome"] == "RECEIVED" and cancel["evidence"][-1]["kind"] == "HOST_CANCEL_REQUESTED"
        assert h.db(outbox.cancel_requests) == [raw]
        h.db(lambda c: outbox.record(c, h.hub.cfg, raw, state="FINAL", outcome="APPLIED", evidence=ev("APP_APPLIED")))
        late = h.db(lambda c: outbox.record(c, h.hub.cfg, raw, outcome="RECEIVED",
                                            evidence=ev("END_RECEIVED", "UNKNOWN", reason="late")))
        assert late["outcome"] == "APPLIED" and late["state"] == "FINAL" and late["reason"] == "late"
        assert [x["kind"] for x in late["evidence"]] == [
            "HOP_ACCEPTED", "END_RECEIVED", "HOST_CANCEL_REQUESTED", "APP_APPLIED", "END_RECEIVED"]
        view = h.get(f"/v1/operations/{op}")
        check("get_operation", view)
        assert view.json()["message_id"] == mid.hex()
        before = h.db(lambda c: c.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        h.post(f"/v1/operations/{op}/cancel", {}, "-")  # repeating changes nothing
        assert h.db(lambda c: c.execute("SELECT COUNT(*) FROM events").fetchone()[0]) == before


def test_deadline_is_checked_before_the_first_transmission(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        e = h.epoch()
        soon = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 30))
        op = h.post("/v1/messages", message(e, delivery="APPLIED", deadline={"mode": "utc", "expires_at": soon}),
                    "a").json()["id"]
        h.db(lambda c: c.execute("UPDATE operations SET expiry_utc_ms=1 WHERE id=?", (bytes.fromhex(op),)))
        assert h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x07" * 16)) == []
        view = h.get(f"/v1/operations/{op}").json()
        assert view["outcome"] == "EXPIRED" and view["state"] == "FINAL"
        assert h.db(lambda c: c.execute("SELECT external_write_possible FROM outbox").fetchone()[0]) == 0


def test_restart_after_claim_reconciles_and_never_resends(tmp_path: Path) -> None:
    s = make_settings(tmp_path)
    with running(s) as h:
        e = h.epoch()
        op = h.post("/v1/messages", message(e), "a").json()["id"]
        h.db(lambda c: outbox.claim(c, h.hub.cfg, b"\x07" * 16))
    with running(s, domain=False) as h2:
        assert h2.db(lambda c: [b for _, b in outbox.pending_reconcile(c)]) == [None]
        assert h2.db(lambda c: outbox.claim(c, h2.hub.cfg, b"\x08" * 16)) == []
        view = h2.get(f"/v1/operations/{op}").json()
        assert view["state"] == "SENDING" and view["outcome"] == "PENDING"  # no invented evidence
        got = h2.db(lambda c: outbox.record(c, h2.hub.cfg, bytes.fromhex(op), state="FINAL",
                                            outcome="INDETERMINATE", evidence={"kind": "ROOT_QUERY_NO_RECORD",
                                                                              "assurance": "UNKNOWN"}))
        assert got["outcome"] == "INDETERMINATE"
        assert h2.db(lambda c: c.execute("SELECT state FROM outbox").fetchone()[0]) == "DONE"


@pytest.mark.scenario("Q03")
def test_capacity_protects_critical_events_and_rejects_with_507(tmp_path: Path) -> None:
    """Q03: protected un-ACKed events fill the journal; new admissions get 507, nothing is deleted."""
    with running(make_settings(tmp_path, max_events=12)) as h:
        e = h.epoch()
        accepted: list[str] = []
        for i in range(30):
            r = h.post("/v1/messages", message(e), f"k{i}")
            if r.status_code == 202:
                accepted.append(r.json()["id"])
                continue
            check("submit_message", r)
            assert r.status_code == 507 and r.json()["details"]["resource"] == "events"
            break
        assert len(accepted) == 12  # one protected event per accepted durable message
        count = op_count(h)
        for i in range(5):
            assert h.post("/v1/messages", message(e), f"more{i}").status_code == 507
        assert op_count(h) == count == 12  # no false 202, no orphan rows
        page = h.get("/v1/events", domain_id=DOMAIN, limit=200).json()
        assert len(page["events"]) == 12  # every protected event is still there
        # replay of an accepted request is not a new admission
        assert h.post("/v1/messages", message(e), "k0").status_code == 202
        # a consumer acknowledges everything: space returns
        last = page["events"][-1]["cursor"]
        ack = h.post("/v1/consumers/kg/ack", {"domain_id": DOMAIN, "journal_id": last[:32], "sequence": last.split(":")[1]}, "-")
        assert ack.status_code == 200
        assert h.post("/v1/messages", message(e), "after-ack").status_code == 202


def test_noncritical_events_are_compacted_into_an_inline_gap(tmp_path: Path) -> None:
    telemetry = dict(delivery="BEST_EFFORT", storage="VOLATILE", deadline={"mode": "root", "root_term": 1, "expires_root_ms": "9"})
    with running(make_settings(tmp_path, max_events=10, max_open_operations=100)) as h:
        e = h.epoch()
        h.post("/v1/messages", message(e), "protected")  # critical, must survive everything below
        for i in range(40):
            assert h.post("/v1/messages", message(e, **telemetry), f"t{i}").status_code == 202
        events = h.get("/v1/events", domain_id=DOMAIN, limit=200).json()["events"]
        assert len(events) <= 10
        assert events[0]["evidence"]["kind"] == "HOST_COMMITTED"  # the protected event is first
        assert any(x["kind"] == "EVENT_GAP" for x in events)


@pytest.mark.scenario("Q03")
def test_real_database_full_is_507_and_never_a_false_202(tmp_path: Path) -> None:
    """SQLITE_FULL for real (page limit): every 202 has its rows, every failure is a clean 507."""
    with running(make_settings(tmp_path, max_page_count=64, free_reserve_bytes=0)) as h:
        e = h.epoch()
        accepted, refused = [], 0
        for i in range(400):
            r = h.post("/v1/messages", message(e, payload_b64="QUJD" * 100), f"k{i}")
            if r.status_code == 202:
                accepted.append(r.json()["id"])
            else:
                assert r.status_code in (507, 429), r.text
                check("submit_message", r)
                refused += 1
                if refused == 3:
                    break
        assert refused == 3 and accepted
        stored = {bytes(x[0]).hex() for x in rows(tmp_path / "host.db", "SELECT id FROM operations")}
        assert stored == set(accepted)
        for op in accepted[:3]:
            assert h.get(f"/v1/operations/{op}").status_code == 200  # reads still work when full
        assert h.get("/v1/events", domain_id=DOMAIN, limit=5).status_code == 200


def test_long_poll_wakes_on_commit_and_times_out_empty(tmp_path: Path) -> None:
    with running(make_settings(tmp_path)) as h:
        e = h.epoch()
        cursor = h.get("/v1/events", domain_id=DOMAIN).json()["next_cursor"]
        t0 = time.monotonic()
        empty = h.get("/v1/events", domain_id=DOMAIN, after=cursor, wait_ms=300)
        assert empty.json()["events"] == [] and empty.json()["next_cursor"] == cursor
        assert 0.25 < time.monotonic() - t0 < 2.0
        threading.Timer(0.3, lambda: h.post("/v1/messages", message(e), "wake")).start()
        t0 = time.monotonic()
        woke = h.get("/v1/events", domain_id=DOMAIN, after=cursor, wait_ms=10000)
        assert len(woke.json()["events"]) == 1 and time.monotonic() - t0 < 5.0
        assert h.get("/v1/events", domain_id=DOMAIN, wait_ms=15001).status_code == 400
        assert h.get("/v1/events", domain_id=DOMAIN, limit=201).status_code == 400


def test_only_the_mirror_writer_can_regress_nothing(tmp_path: Path) -> None:
    """Generations never move backwards through the root-state writer."""
    with running(make_settings(tmp_path)) as h:
        h.db(lambda c: mirror.upsert_node(
            c, bytes.fromhex(DOMAIN), bytes.fromhex(NODE), assignment_generation=0, membership_generation=9,
            membership="LEFT", connectivity="UNKNOWN", confirmed=False))
        node = h.get(f"/v1/nodes/{NODE}", domain_id=DOMAIN).json()
        assert node["assignment_generation"] == "1" and node["membership"] == "ACTIVE"


def test_event_readers_are_bounded(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, max_subscribers=1)) as h:
        with h.hub.subscription():  # one reader already attached
            assert h.get("/v1/events", domain_id=DOMAIN).status_code == 200  # plain reads are not readers
            waiting = h.get("/v1/events", domain_id=DOMAIN, wait_ms=100)
            check("read_events", waiting)
            assert waiting.status_code == 429 and waiting.json()["code"] == "RATE_LIMITED"
            assert h.get("/v1/events/stream", domain_id=DOMAIN).status_code == 429
        assert h.get("/v1/events", domain_id=DOMAIN, wait_ms=100).status_code == 200
