"""FIELD: GET /v1/nodes states parent_device_id / root_depth only from the root's NODE_QUERY `tree` rows."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from leanmesh_host import storage
from leanmesh_host.bridge.bridge import tree_extras
from leanmesh_host.db import mirror

ROOT = b"\xaa" * 32
RELAY = b"\x11" * 32
LEAF = b"\x22" * 32
LOST = b"\x33" * 32
DOMAIN = b"\x01" * 16
# [device, assignment, membership, state, confirmed, address]: the rows of a NODE_QUERY (addresses are 2 + ledger slot)
ROWS = [[RELAY, 1, 1, 3, True, 2], [LEAF, 1, 1, 3, True, 3], [LOST, 1, 1, 3, True, 4]]


def test_a_direct_child_names_the_root_and_a_deeper_node_names_its_parent_by_address() -> None:
    got = tree_extras(ROWS, [[2, 1, 1], [3, 2, 2]], ROOT)
    assert got == {2: {"root_depth": 1, "parent_device_id": ROOT.hex()},
                   3: {"root_depth": 2, "parent_device_id": RELAY.hex()}}
    assert 4 not in got  # no row: no approved parent, nothing is stated for it


def test_a_parent_the_node_rows_do_not_name_is_left_out_and_never_guessed() -> None:
    assert tree_extras(ROWS, [[3, 77, 2]], ROOT) == {3: {"root_depth": 2}}


def test_a_root_that_sends_no_tree_states_no_parent() -> None:
    assert tree_extras(ROWS, (), ROOT) == {}


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.isolation_level = None
    storage._apply_schema(conn, (Path(__file__).resolve().parents[3] / "db" / "schema.sql").read_text())
    mirror.register_domain(conn, DOMAIN, ROOT)
    return conn


def _node_query(conn: sqlite3.Connection, tree: list[list[int]]) -> None:
    extras = tree_extras(ROWS, tree, ROOT)
    for device, ag, mg, _state, confirmed, address in ROWS:
        mirror.upsert_node(conn, DOMAIN, device, assignment_generation=ag, membership_generation=mg,
                           membership="ACTIVE", connectivity="UNKNOWN", confirmed=bool(confirmed),
                           short_address=address, extras=extras.get(address))


def test_the_node_list_serves_the_tree_fields_and_drops_them_when_the_parent_goes() -> None:
    conn = _db()
    _node_query(conn, [[2, 1, 1], [3, 2, 2]])
    items = {n["device_id"]: n for n in mirror.list_nodes(conn, DOMAIN)["items"]}
    assert items[RELAY.hex()]["parent_device_id"] == ROOT.hex() and items[RELAY.hex()]["root_depth"] == 1
    assert items[LEAF.hex()]["parent_device_id"] == RELAY.hex() and items[LEAF.hex()]["root_depth"] == 2
    assert "parent_device_id" not in items[LOST.hex()] and "root_depth" not in items[LOST.hex()]
    # The next NODE_QUERY: the leaf re-attached under the root, the relay lost its parent.
    _node_query(conn, [[3, 1, 1]])
    leaf = mirror.get_node(conn, DOMAIN, LEAF)
    assert leaf["parent_device_id"] == ROOT.hex() and leaf["root_depth"] == 1
    relay = mirror.get_node(conn, DOMAIN, RELAY)
    assert "parent_device_id" not in relay and "root_depth" not in relay
