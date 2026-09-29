"""Host copy of root-reported state (domains, nodes, power, channel, group targets, lifecycle).

Writers are called by the serial bridge with what the authenticated root reported. Readers serve
the GET endpoints. Nothing here is guessed: an unreported value is absent (404/503), never a
default that looks like a measurement.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..api.codec import canonical_json
from ..api.errors import ApiError, invalid, not_found
from ..events.journal import now_ms
from ..power_state import resolve as resolve_power

_NODE_EXTRAS = ("root_depth", "last_authenticated_rx_mono_ms", "parent_rssi_dbm")


# ---- writers (bridge) ---------------------------------------------------------------------------
def register_domain(conn: sqlite3.Connection, domain: bytes, root_device: bytes | None) -> None:
    conn.execute("INSERT INTO domains(id,root_device) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET "
                 "root_device=excluded.root_device", (domain, root_device))


def upsert_node(conn: sqlite3.Connection, domain: bytes, device: bytes, *, assignment_generation: int,
                membership_generation: int, membership: str, connectivity: str, confirmed: bool,
                short_address: int | None = None, extras: dict[str, Any] | None = None) -> None:
    """Generations never move backwards: a stale root report cannot roll a node back."""
    conn.execute(
        "INSERT INTO nodes(domain,device,assignment_generation,membership_generation,membership,"
        "connectivity,short_address,confirmed,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(domain,device) DO UPDATE SET assignment_generation=excluded.assignment_generation,"
        "membership_generation=excluded.membership_generation, membership=excluded.membership,"
        "connectivity=excluded.connectivity, short_address=excluded.short_address,"
        "confirmed=excluded.confirmed, snapshot_json=excluded.snapshot_json "
        "WHERE excluded.assignment_generation>=nodes.assignment_generation "
        "AND excluded.membership_generation>=nodes.membership_generation",
        (domain, device, assignment_generation, membership_generation, membership, connectivity,
         short_address, int(confirmed), canonical_json(extras or {})))


def put_power(conn: sqlite3.Connection, domain: bytes, device: bytes, policy: dict[str, Any],
              snapshot: dict[str, Any]) -> None:
    if "_root_offset_ms" not in snapshot:
        # No root clock: the report is aged from when the Host first saw it (the root stamped it no later than
        # that), and the anchor is kept while the same report is seen again. Stale is then detectable, never late-proof.
        prev = conn.execute("SELECT snapshot_json FROM node_power WHERE domain=? AND device=?", (domain, device)).fetchone()
        old = json.loads(prev[0]) if prev is not None else {}
        if old.get("reported_root_ms") == snapshot.get("reported_root_ms") and "_root_offset_ms" in old:
            snapshot["_root_offset_ms"] = old["_root_offset_ms"]
        elif "reported_root_ms" in snapshot:
            snapshot["_root_offset_ms"] = int(snapshot["reported_root_ms"]) - now_ms()
    conn.execute(
        "INSERT INTO node_power(domain,device,policy_revision,mode,policy_json,snapshot_json) "
        "VALUES(?,?,?,?,?,?) ON CONFLICT(domain,device) DO UPDATE SET policy_revision="
        "excluded.policy_revision, mode=excluded.mode, policy_json=excluded.policy_json, "
        "snapshot_json=excluded.snapshot_json",
        (domain, device, int(snapshot["policy_revision"]), snapshot["mode"], canonical_json(policy),
         canonical_json(snapshot)))


def put_channel(conn: sqlite3.Connection, domain: bytes, status: dict[str, Any]) -> None:
    conn.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value="
                 "excluded.value", (f"channel:{domain.hex()}", canonical_json(status).encode()))


# ---- readers ------------------------------------------------------------------------------------
def _require_domain(conn: sqlite3.Connection, domain: bytes) -> None:
    if conn.execute("SELECT 1 FROM domains WHERE id=?", (domain,)).fetchone() is None:
        raise not_found("domain")


def _node(row: tuple[Any, ...], power: str | None) -> dict[str, Any]:
    domain, device, ag, mg, membership, connectivity, confirmed, snapshot = row
    extras = json.loads(snapshot)
    out: dict[str, Any] = {
        "device_id": bytes(device).hex(), "domain_id": bytes(domain).hex(),
        "assignment_generation": str(ag), "membership_generation": str(mg),
        "membership": membership, "connectivity": connectivity, "confirmed": bool(confirmed)}
    out.update({k: extras[k] for k in _NODE_EXTRAS if k in extras})
    if power is not None:
        out["power"] = resolve_power(json.loads(power), now_ms())
    return out


_NODE_SQL = ("SELECT n.domain,n.device,n.assignment_generation,n.membership_generation,n.membership,"
             "n.connectivity,n.confirmed,n.snapshot_json,p.snapshot_json FROM nodes n LEFT JOIN "
             "node_power p ON p.domain=n.domain AND p.device=n.device WHERE n.domain=?")


def list_nodes(conn: sqlite3.Connection, domain: bytes) -> dict[str, Any]:
    """<= 64 members per domain (registry limits.members), so one page and no cursor."""
    _require_domain(conn, domain)
    rows = conn.execute(_NODE_SQL + " ORDER BY n.device LIMIT 200", (domain,)).fetchall()
    return {"items": [_node(r[:8], r[8]) for r in rows]}


def get_node(conn: sqlite3.Connection, domain: bytes, device: bytes) -> dict[str, Any]:
    _require_domain(conn, domain)
    row = conn.execute(_NODE_SQL + " AND n.device=?", (domain, device)).fetchone()
    if row is None:
        raise not_found("node")
    return _node(row[:8], row[8])


def get_power(conn: sqlite3.Connection, domain: bytes, device: bytes) -> dict[str, Any]:
    _require_domain(conn, domain)
    row = conn.execute("SELECT snapshot_json FROM node_power WHERE domain=? AND device=?",
                       (domain, device)).fetchone()
    if row is None:
        raise not_found("power state")  # not reported by the root: never a guessed default
    return resolve_power(json.loads(row[0]), now_ms())


def get_channel(conn: sqlite3.Connection, domain: bytes) -> dict[str, Any]:
    _require_domain(conn, domain)
    row = conn.execute("SELECT value FROM meta WHERE key=?", (f"channel:{domain.hex()}",)).fetchone()
    if row is None:
        raise ApiError(503, "ROOT_UNAVAILABLE", "channel state has not been reported by a root")
    return json.loads(bytes(row[0]))


def list_lifecycle(conn: sqlite3.Connection, domain: bytes) -> dict[str, Any]:
    _require_domain(conn, domain)
    items = []
    for rid, device, state, revision, evidence in conn.execute(
            "SELECT id,device,state,expected_revision,evidence_json FROM lifecycle_requests "
            "WHERE domain=? ORDER BY id LIMIT 200", (domain,)):
        item = {"request_id": bytes(rid).hex(), "device_id": bytes(device).hex(),
                "domain_id": domain.hex(), "state": state, "revision": str(revision)}
        ev = json.loads(evidence)
        reason = next((e["details"]["reason"] for e in reversed(ev)
                       if isinstance(e, dict) and "reason" in e.get("details", {})), None)
        if reason:
            item["reason"] = reason
        items.append(item)
    return {"items": items}


_TARGET_PAGE = 16


def group_targets(conn: sqlite3.Connection, principal: str, op_id: bytes, offset: int, limit: int,
                  token: str | None) -> dict[str, Any]:
    """Per-target results of a group operation (docs/22). snapshot_token pins the page series."""
    row = conn.execute("SELECT 1 FROM operations WHERE id=? AND principal=?", (op_id, principal)).fetchone()
    if row is None:
        raise not_found("operation")
    if not 1 <= limit <= _TARGET_PAGE or offset < 0:
        raise invalid("limit must be 1..16 and offset >= 0")
    head = conn.execute("SELECT snapshot_token,snapshot_hash FROM group_targets WHERE operation=? "
                        "LIMIT 1", (op_id,)).fetchone()
    if head is None:
        kind = conn.execute("SELECT json_extract(request_json,'$.destination.kind') FROM operations "
                            "WHERE id=?", (op_id,)).fetchone()[0]
        if kind == "group":  # accepted, but the root's snapshot has not been read yet
            raise ApiError(409, "CONFLICT", "the group snapshot is not known yet; retry")
        raise invalid("operation is not a group operation")
    if token is not None and token != bytes(head[0]).hex():
        raise ApiError(409, "CONFLICT", "snapshot_token does not match", snapshot_token=bytes(head[0]).hex())
    total = conn.execute("SELECT COUNT(*) FROM group_targets WHERE operation=?", (op_id,)).fetchone()[0]
    stored = conn.execute("SELECT value FROM meta WHERE key=?", (f"gprog:{op_id.hex()}",)).fetchone()
    progress = int.from_bytes(bytes(stored[0]), "big") if stored is not None else 0  # the root's own revision
    targets = []
    for device, ag, mg, mid, phase, outcome, evidence in conn.execute(
            "SELECT device,assignment_generation,membership_generation,message_id,phase,outcome,"
            "evidence_json FROM group_targets WHERE operation=? AND position>=? ORDER BY position "
            "LIMIT ?", (op_id, offset, limit)):
        t: dict[str, Any] = {"device_id": bytes(device).hex(), "assignment_generation": str(ag),
                             "membership_generation": str(mg), "phase": phase, "outcome": outcome}
        if mid is not None:
            t["message_id"] = bytes(mid).hex()
        reason = next((e["details"]["reason"] for e in reversed(json.loads(evidence))
                       if "reason" in e.get("details", {})), None)
        if reason:
            t["reason"] = reason
        targets.append(t)
    nxt = offset + len(targets)
    return {"snapshot_token": bytes(head[0]).hex(), "snapshot_hash": bytes(head[1]).hex(),
            "total": total, "offset": offset, "next_offset": nxt if nxt < total else None,
            "progress_revision": str(progress), "targets": targets}
