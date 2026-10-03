"""Issue #5 through the real FastAPI app and a real SQLite file: GET /v1/ledger/backup and POST /v1/control LEDGER_RESTORE.
Every response is validated against api/openapi.json; a refusal is checked for "nothing was written". The root is not
involved: what is tested is what the Host decides before anything is queued for it (permission, sequence compare-and-set,
the roots, the supplied backup), and that an accepted restore is an ordinary idempotent operation."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from backup_util import OTHER_ROOT, ROOT, make
from host_util import DOMAIN, check, make_settings, rows, running, signed_object
from leanmesh_host.db import ledger_backup as lb

D = bytes.fromhex(DOMAIN)
NEW_ROOT = OTHER_ROOT


def handover(old: bytes = ROOT, new: bytes = NEW_ROOT) -> str:
    return signed_object(31, [b"\x48" * 16, old, new, 1, 2, bytes(32), 2, 0])


def post(h: Any, key: str, epoch: str, who: str = "alice", **fields: Any) -> Any:
    body = {"domain_id": DOMAIN, "client_epoch": epoch, "type": "LEDGER_RESTORE", "request_id": "ab" * 16,
            "expected_revision": "1", "signed_cbor_b64": handover(), **fields}
    r = h.post("/v1/control", body, key, who=who)
    check("submit_control", r)
    return r


def blob(backup: lb.Backup) -> str:
    return base64.b64encode(backup.blob()).decode()


def test_the_backup_endpoint_needs_configure_and_shows_what_the_host_holds(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, {"alice": ["READ", "CONFIGURE"], "reader": ["READ"]}), node=False) as h:
        r = h.get("/v1/ledger/backup", domain_id=DOMAIN)
        check("get_ledger_backup", r)
        assert r.status_code == 404                                    # nothing was taken yet
        check("get_ledger_backup", h.get("/v1/ledger/backup", domain_id="ee" * 16))
        assert h.get("/v1/ledger/backup", domain_id="ee" * 16).status_code == 404
        b = make([1, 2], seq=7)
        h.db(lambda c: lb.store(c, D, b))
        got = h.get("/v1/ledger/backup", domain_id=DOMAIN)
        check("get_ledger_backup", got)
        assert got.status_code == 200
        j = got.json()
        assert j["sequence"] == "7" and j["records"] == 3 and j["root_device_id"] == ROOT.hex() and j["domain_id"] == DOMAIN
        assert lb.decode_blob(base64.b64decode(j["backup_b64"])) == b
        denied = h.get("/v1/ledger/backup", who="reader", domain_id=DOMAIN)  # READ is not enough: it lists the members
        check("get_ledger_backup", denied)
        assert denied.status_code == 403 and denied.json()["details"]["required"] == "CONFIGURE"
        assert h.get("/v1/ledger/backup", domain_id="xyz").status_code == 400


def test_a_restore_is_admitted_only_for_the_backup_the_operator_saw(tmp_path: Path) -> None:
    perms = {"alice": ["READ", "CONFIGURE", "TRANSFER"], "bob": ["READ", "CONFIGURE"], "carol": ["READ", "TRANSFER"]}
    with running(make_settings(tmp_path, perms), node=False) as h:
        e = h.epoch()
        assert post(h, "r0", e).status_code == 404                     # no backup held: nothing to restore
        h.db(lambda c: lb.store(c, D, make([1, 2], seq=3)))
        # the compare-and-set: expected_revision is the sequence the Host holds
        stale = post(h, "r1", e, expected_revision="2")
        assert stale.status_code == 409 and stale.json()["details"]["current_revision"] == "3"
        # the handover hands over from the root that made the backup
        wrong_root = post(h, "r2", e, expected_revision="3", signed_cbor_b64=handover(old=bytes([9]) * 32))
        assert wrong_root.status_code == 409
        # a RootHandover needs the permissions of the object it is: CONFIGURE and TRANSFER, not one of them
        assert post(h, "r3", e, who="bob", expected_revision="3").status_code == 403
        assert post(h, "r4", e, who="carol", expected_revision="3").status_code == 403
        # not a handover at all (a RevokeObject), not the object the type takes
        revoke = signed_object(11, [bytes(32), 1, 1, 0, 1])
        assert post(h, "r5", e, expected_revision="3", signed_cbor_b64=revoke).status_code == 400
        # the object names another domain than the request
        assert post(h, "r6", e, expected_revision="3",
                    signed_cbor_b64=signed_object(31, [b"\x48" * 16, ROOT, NEW_ROOT, 1, 2, bytes(32), 2, 0],
                                                  domain="ee" * 16)).status_code == 400
        # typed requests: no field of another type, the backup only as the optional one
        assert post(h, "r7", e, expected_revision="3", device_id="aa" * 32).status_code == 400
        assert rows(tmp_path / "host.db", "SELECT COUNT(*) FROM operations") == [(0,)]   # nothing of this was written
        ok = post(h, "r8", e, expected_revision="3")
        assert ok.status_code == 202 and ok.json()["state"] == "HOST_COMMITTED" and ok.json()["outcome"] == "PENDING"
        again = post(h, "r8", e, expected_revision="3")                # idempotent: the stored operation
        assert again.status_code == 202 and again.json() == ok.json()
        assert post(h, "r8", e, expected_revision="3", request_id="cd" * 16).status_code == 409
        stored = rows(tmp_path / "host.db", "SELECT type,json_extract(request_json,'$.expected_revision'),payload IS NOT NULL "
                      "FROM operations")
        assert stored == [("LEDGER_RESTORE", "3", 1)]                  # the handover is the operation's payload, no blob in the row
        assert rows(tmp_path / "host.db", "SELECT state FROM outbox") == [("QUEUED",)]


def test_a_supplied_backup_must_be_sound_current_and_become_the_held_one(tmp_path: Path) -> None:
    with running(make_settings(tmp_path, {"alice": ["READ", "CONFIGURE", "TRANSFER"]}), node=False) as h:
        e = h.epoch()
        held = make([1], seq=4)
        h.db(lambda c: lb.store(c, D, held))
        newer = make([1, 2, 3], seq=6)
        damaged = bytearray(newer.blob())
        damaged[len(damaged) // 2] ^= 0x01
        for key, fields, status in (
            ("s1", {"backup_b64": base64.b64encode(bytes(damaged)).decode(), "expected_revision": "6"}, 400),   # a damaged record
            ("s2", {"backup_b64": blob(newer), "expected_revision": "5"}, 400),     # its sequence is not expected_revision
            ("s3", {"backup_b64": blob(make([1], seq=3)), "expected_revision": "3"}, 409),  # older than the one held
            ("s4", {"backup_b64": blob(make([1], seq=6, domain=bytes([1]) * 16)), "expected_revision": "6"}, 400),  # another domain
            ("s5", {"backup_b64": blob(make([1], seq=6, root=bytes([9]) * 32)), "expected_revision": "6"}, 409),   # not the handover's old root
            ("s6", {"backup_b64": "!!!", "expected_revision": "6"}, 400),
        ):
            r = post(h, key, e, **fields)
            assert r.status_code == status, (key, r.status_code, r.text)
        assert h.db(lambda c: lb.meta(c, D)["sequence"]) == 4   # none of them replaced the held one
        ok = post(h, "s7", e, backup_b64=blob(newer), expected_revision="6")
        assert ok.status_code == 202
        assert h.db(lambda c: lb.meta(c, D)["sequence"]) == 6          # the supplied backup is the held one now
        got = h.get("/v1/ledger/backup", domain_id=DOMAIN).json()
        assert got["sequence"] == "6" and got["records"] == 4
        assert rows(tmp_path / "host.db", "SELECT length(request_json) < 400 FROM operations") == [(1,)]  # not the blob
