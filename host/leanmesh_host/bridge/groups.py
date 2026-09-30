"""Group operations on the Host side (S15, docs/22): the SEND destination marker and the mirror of the
root's per-target results into `group_targets`.

The root is the origin of a Host group send: it fixes the snapshot, fans out and keeps one current outcome
per target. The Host never expands a group. It reads the root's pages (GROUP_TARGETS) when it hears that
the operation changed (GROUP_PROGRESS event, acceptance) and copies them; a target's row is the root's
current word, its history stays in the evidence list. Nothing is inferred: a missing page stays missing.
"""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING, Any

from ..wire import cbor_decode
from . import mapping
from .mapping import status_name

if TYPE_CHECKING:
    from .bridge import Bridge

M_GROUP_TARGETS = 15
EV_GROUP_PROGRESS = 10
PHASES = ("WAIT_ROUTE", "WAIT_AUTH", "WAIT_WAKE", "READY", "SENDING", "WAIT_RECEIPT", "FINAL")
MAX_TRACKED = 64  # group operations followed per root boot (oldest are forgotten: their last page stays)
MAX_TARGET_EVIDENCE = 8
MAX_TARGETS = 64  # limits.members: group_targets.position is 0..63


def group_dest(group_id: int, revision: int) -> bytes:
    """protocol/serial.cddl has only a DeviceId as SEND destination: a group is 12 x 0 | group_id (u32 BE) |
    revision (u64 BE) | 8 x 0 (src/core/group/group.hpp)."""
    return bytes(12) + group_id.to_bytes(4, "big") + revision.to_bytes(8, "big") + bytes(8)


class Groups:
    """Which Host operations are group operations of the current root boot, and which need a look."""

    def __init__(self) -> None:
        self._number: dict[bytes, int] = {}  # Host operation -> root operation number
        self._dirty: set[bytes] = set()

    def track(self, op: bytes, number: int) -> None:
        if len(self._number) >= MAX_TRACKED and op not in self._number:
            oldest = next(iter(self._number))
            del self._number[oldest]
            self._dirty.discard(oldest)
        self._number[op] = number
        self._dirty.add(op)

    def touched(self, number: int) -> bool:
        for op, n in self._number.items():
            if n == number:
                self._dirty.add(op)
                return True
        return False

    def clear(self) -> None:
        self._number.clear()
        self._dirty.clear()

    @property
    def pending(self) -> bool:
        return bool(self._dirty)

    async def sync(self, bridge: Bridge) -> None:
        """Copies every page of every operation that changed, all pages in one transaction. One failed exchange, or a
        series that is short of its announced total, keeps the mark and stores nothing."""
        link, info = bridge.link, bridge.info
        assert link is not None and info is not None
        for op in list(self._dirty):
            number = self._number.get(op)
            if number is None:
                self._dirty.discard(op)
                continue
            self._dirty.discard(op)  # a change during the copy marks it again
            pages, gone = await self._fetch(link, info, number)
            if pages is None:  # a failed exchange keeps the mark; a partial or inconsistent series is never stored
                if gone:
                    self._number.pop(op, None)  # a restarted root: its numbers are void
                else:
                    self._dirty.add(op)
                continue
            await bridge.hub.write(lambda conn, o=op, ps=pages: write_pages(conn, o, info.root, ps))

    async def _fetch(self, link: Any, info: Any, number: int) -> tuple[list[dict[str, Any]] | None, bool]:
        """(all pages of one operation's snapshot | None, the root no longer knows the operation). One transaction
        writes them all later, so the mirror never shows a complete-looking prefix (a root that answers total=64
        with one target does not have a group of 1)."""
        token, offset, pages = bytes(16), 0, []  # a zero token names the operation's own snapshot
        first: dict[str, Any] | None = None
        got = 0
        while offset is not None:
            res = await link.request(M_GROUP_TARGETS, [info.boot, number, token, offset, 16])
            if res.status != mapping.OK or res.result is None:
                return None, res.status == mapping.NOT_FOUND
            page = cbor_decode(res.result)
            token = bytes(page["snapshot_token"])
            if first is None:
                first = page
            targets = page["targets"]
            nxt = page["next_offset"]
            consistent = (page["offset"] == offset and page["total"] == first["total"] and token == bytes(first["snapshot_token"])
                          and bytes(page["snapshot_hash"]) == bytes(first["snapshot_hash"])
                          and page["total"] <= MAX_TARGETS and (nxt is None or (targets and nxt == offset + len(targets))))
            if not consistent:
                return None, False
            got += len(targets)
            pages.append(page)
            offset = nxt
        if first is None or got != first["total"]:
            return None, False  # the series ended before the announced total
        return pages, False


def _same_snapshot(conn: sqlite3.Connection, op: bytes, pages: list[dict[str, Any]]) -> bool:
    """FIX7-D10: a stored operation keeps its snapshot: token, hash, total and every target's identity (device and
    generations) must match before any outcome is updated. Nothing stored yet: any series is the first."""
    stored = conn.execute("SELECT position,device,assignment_generation,membership_generation,snapshot_token,"
                          "snapshot_hash FROM group_targets WHERE operation=?", (op,)).fetchall()
    if not stored:
        return True
    first = pages[0]
    if len(stored) != first["total"]:
        return False
    fresh = {page["offset"] + k: t for page in pages for k, t in enumerate(page["targets"])}
    return all(bytes(tok) == bytes(first["snapshot_token"]) and bytes(h) == bytes(first["snapshot_hash"])
               and (t := fresh.get(pos)) is not None and bytes(t["device_id"]) == bytes(dev)
               and (t["assignment_generation"], t["membership_generation"]) == (ag, mg)
               for pos, dev, ag, mg, tok, h in stored)


def _mark_conflict(conn: sqlite3.Connection, op: bytes, root: bytes) -> None:
    """The root says something else about the same operation: rows without a settled outcome become INDETERMINATE."""
    entry = {"kind": "GROUP_SNAPSHOT_CONFLICT", "assurance": "SELF_REPORTED", "observer": root.hex(), "details": {}}
    for position, outcome, evidence in conn.execute(
            "SELECT position,outcome,evidence_json FROM group_targets WHERE operation=?", (op,)).fetchall():
        if outcome in ("PENDING", "SUBMITTED"):
            history = (json.loads(evidence) + [entry])[-MAX_TARGET_EVIDENCE:]
            conn.execute("UPDATE group_targets SET outcome='INDETERMINATE', evidence_json=? WHERE operation=? "
                         "AND position=?", (json.dumps(history, separators=(",", ":"), sort_keys=True), op, position))


def write_pages(conn: sqlite3.Connection, op: bytes, root: bytes, pages: list[dict[str, Any]]) -> None:
    if not pages:
        return
    if not _same_snapshot(conn, op, pages):
        _mark_conflict(conn, op, root)
        return
    for page in pages:
        write_page(conn, op, root, page)


def write_page(conn: sqlite3.Connection, op: bytes, root: bytes, page: dict[str, Any]) -> None:
    for k, t in enumerate(page["targets"]):
        position = page["offset"] + k
        outcome = mapping.OUTCOMES[t["outcome"]]
        phase = PHASES[t["phase"]]
        details: dict[str, Any] = {"outcome": outcome}
        if t["reason"]:
            details["reason"] = status_name(int(t["reason"]))
        entry = {"kind": "ROOT_TARGET_OUTCOME", "assurance": "SELF_REPORTED", "observer": root.hex(),
                 "details": details}
        row = conn.execute("SELECT evidence_json FROM group_targets WHERE operation=? AND position=?",
                           (op, position)).fetchone()
        history: list[dict[str, Any]] = json.loads(row[0]) if row is not None else []
        if not history or history[-1] != entry:
            history = (history + [entry])[-MAX_TARGET_EVIDENCE:]
        conn.execute(
            "INSERT INTO group_targets(operation,position,snapshot_token,snapshot_hash,device,"
            "assignment_generation,membership_generation,message_id,phase,outcome,evidence_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(operation,position) DO UPDATE SET "
            "message_id=excluded.message_id, phase=excluded.phase, outcome=excluded.outcome, "
            "evidence_json=excluded.evidence_json",
            (op, position, page["snapshot_token"], page["snapshot_hash"], t["device_id"],
             t["assignment_generation"], t["membership_generation"], t["message_id"], phase, outcome,
             json.dumps(history, separators=(",", ":"), sort_keys=True)))
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                 (f"gprog:{op.hex()}", int(page["progress_revision"]).to_bytes(8, "big")))
