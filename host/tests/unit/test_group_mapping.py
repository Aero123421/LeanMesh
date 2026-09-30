"""S15 Host side of groups: the destination marker of the serial SEND and the tracking of group operations."""

from __future__ import annotations

from leanmesh_host.bridge import groups


def test_group_destination_marker_is_the_value_the_root_decodes() -> None:
    d = groups.group_dest(0xA1B2C3D4, 0x0102030405060708)
    assert len(d) == 32
    assert d[:12] == bytes(12) and d[24:] == bytes(8)
    assert d[12:16].hex() == "a1b2c3d4" and d[16:24].hex() == "0102030405060708"


def test_tracking_is_bounded_and_marks_only_known_operations() -> None:
    g = groups.Groups()
    for i in range(groups.MAX_TRACKED + 5):
        g.track(bytes([i]) * 16, 1000 + i)
    assert len(g._number) == groups.MAX_TRACKED         # the oldest are forgotten
    assert g.pending
    g._dirty.clear()
    assert g.touched(1000 + groups.MAX_TRACKED + 4) and g.pending
    g._dirty.clear()
    assert not g.touched(1000) and not g.pending          # forgotten: no mark
    g.clear()
    assert not g._number and not g.pending


# ---- FIX3-10: a partial root page is never reported as a complete group ----------------------------------------------
import asyncio  # noqa: E402
import sqlite3  # noqa: E402
from pathlib import Path  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from leanmesh_host import storage  # noqa: E402
from leanmesh_host.bridge import mapping  # noqa: E402
from leanmesh_host.wire import cbor_encode  # noqa: E402

_SCHEMA = Path(__file__).resolve().parents[3] / "db" / "schema.sql"


def _page(total: int, offset: int, count: int, token: bytes = b"\x01" * 16) -> bytes:
    targets = [{"phase": 6, "reason": 0, "outcome": 3, "device_id": bytes([offset + k + 1]) * 32,
                "message_id": bytes(16), "assignment_generation": 1, "membership_generation": 1} for k in range(count)]
    nxt = offset + count
    return cbor_encode({"total": total, "offset": offset, "targets": targets,
                        "next_offset": nxt if nxt < total else None, "snapshot_hash": b"\x02" * 32,
                        "snapshot_token": token, "progress_revision": 3})


class _Link:
    def __init__(self, pages: list[bytes]) -> None:
        self.pages, self.asked = pages, []

    async def request(self, method: int, params: list) -> SimpleNamespace:
        self.asked.append(params[3])
        assert len(self.asked) < 20, "the Host keeps asking for pages"
        if params[3] // 16 >= len(self.pages):
            return SimpleNamespace(status=mapping.CONFLICT, result=None)
        return SimpleNamespace(status=mapping.OK, result=self.pages[params[3] // 16])


def _run(pages: list[bytes]) -> tuple[sqlite3.Connection, groups.Groups, bytes]:
    conn = sqlite3.connect(":memory:")
    conn.isolation_level = None
    storage._apply_schema(conn, _SCHEMA.read_text())
    conn.commit()
    op = b"\x09" * 16

    class _Hub:
        async def write(self, fn):  # one transaction, like Storage.run
            conn.execute("BEGIN")
            try:
                fn(conn)
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    g = groups.Groups()
    g.track(op, 7)
    bridge = SimpleNamespace(link=_Link(pages), info=SimpleNamespace(boot=1, root=b"\xaa" * 32), hub=_Hub())
    asyncio.run(g.sync(bridge))
    return conn, g, op


def test_partial_root_page_is_not_stored_as_a_complete_group() -> None:
    # total=64, but the series ends after one target: nothing is written and the operation stays marked for a retry.
    conn, g, op = _run([_page(64, 0, 1)])
    assert conn.execute("SELECT COUNT(*) FROM group_targets").fetchone()[0] == 0
    assert g.pending


def test_series_short_of_its_total_is_not_stored_and_a_full_series_is_stored_whole() -> None:
    conn, g, op = _run([_page(20, 0, 16)])  # next_offset = 16 but the root has no page 2
    assert conn.execute("SELECT COUNT(*) FROM group_targets").fetchone()[0] == 0 and g.pending
    conn, g, op = _run([_page(20, 0, 16), _page(20, 16, 4)])
    assert conn.execute("SELECT COUNT(*) FROM group_targets").fetchone()[0] == 20 and not g.pending


def test_pages_of_different_snapshots_are_not_mixed() -> None:
    conn, g, op = _run([_page(20, 0, 16), _page(20, 16, 4, token=b"\x07" * 16)])
    assert conn.execute("SELECT COUNT(*) FROM group_targets").fetchone()[0] == 0 and g.pending


# ---- FIX7-D10: a later, different snapshot never mixes with the stored rows -----------------------------------------
def _decoded(total: int, count: int, token: bytes, outcome: int = 3) -> list[dict]:
    from leanmesh_host.wire import cbor_decode
    pages, offset = [], 0
    while offset < total:
        n = min(16, count - offset) if count < total else min(16, total - offset)
        page = cbor_decode(_page(total, offset, n, token))
        page["targets"] = [{**t, "outcome": outcome} for t in page["targets"]]
        pages.append(page)
        offset += n
    return pages


def test_a_different_snapshot_for_a_stored_operation_stores_nothing_and_marks_it_indeterminate() -> None:
    conn = sqlite3.connect(":memory:")
    conn.isolation_level = None
    storage._apply_schema(conn, _SCHEMA.read_text())
    op, root = b"\x09" * 16, b"\xaa" * 32
    groups.write_pages(conn, op, root, _decoded(20, 20, b"\x01" * 16, outcome=0))  # PENDING everywhere
    before = conn.execute("SELECT position,device,message_id,snapshot_token FROM group_targets ORDER BY position").fetchall()
    assert len(before) == 20
    groups.write_pages(conn, op, root, _decoded(1, 1, b"\x07" * 16))  # 1 target, another token
    rows = conn.execute("SELECT position,device,message_id,snapshot_token,outcome FROM group_targets ORDER BY position").fetchall()
    assert [r[:4] for r in rows] == before  # nothing of the new series stored, no mixed rows
    assert {r[4] for r in rows} == {"INDETERMINATE"}
    # same token and hash but a moved target identity is a conflict too
    other = _decoded(20, 20, b"\x01" * 16)
    other[0]["targets"][0]["device_id"] = b"\x63" * 32
    groups.write_pages(conn, op, root, other)
    assert conn.execute("SELECT device FROM group_targets WHERE position=0").fetchone()[0] == bytes([1]) * 32
