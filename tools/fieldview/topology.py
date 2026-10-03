"""The tree of the mesh from GET /v1/nodes (`parent_device_id`, `root_depth`) and the colour of each link.

The Host may not report `parent_device_id` yet (an older Host): a node without one is drawn under an "unknown parent"
group, never guessed under another node. Pure functions, no I/O."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Link colour. RSSI is the child's parent RSSI (telemetry, dBm); loss is the telemetry loss of the child over the recent
# window (%). The worse of the two grades wins. LR 250 kbps hears much weaker than these, so "poor" is a warning of a
# thin margin, not of a dead link.
RSSI_GOOD, RSSI_FAIR = -80, -90
LOSS_GOOD, LOSS_FAIR = 5.0, 20.0
UNKNOWN_PARENT_ID = "?"


def short_id(device: str) -> str:
    return device[:8]


def link_quality(rssi: int | None, loss_pct: float | None, silent: bool = False) -> str:
    """good / fair / poor / unknown ("unknown" when the node sends nothing or nothing is known of the link)."""
    if silent:
        return "unknown"
    grades = []
    if rssi is not None:
        grades.append(0 if rssi >= RSSI_GOOD else 1 if rssi >= RSSI_FAIR else 2)
    if loss_pct is not None:
        grades.append(0 if loss_pct < LOSS_GOOD else 1 if loss_pct < LOSS_FAIR else 2)
    if not grades:
        return "unknown"
    return ("good", "fair", "poor")[max(grades)]


@dataclass(frozen=True)
class NodeView:
    """What the tree needs to know about one node besides the Host's list entry."""

    name: str
    role: str | None = None
    rssi: int | None = None          # child's parent RSSI (telemetry first, then the Host's)
    loss_pct: float | None = None    # recent telemetry loss
    silent: bool = False             # no live telemetry (never seen, or lost)
    lost: bool = False               # telemetry age beyond 3 intervals after having been seen
    depth: int | None = None


def _leaf(device: str, item: dict[str, Any] | None, view: NodeView | None) -> dict[str, Any]:
    v = view or NodeView(name=short_id(device), silent=True)
    depth = (item or {}).get("root_depth")
    return {
        "id": device, "name": v.name, "short": short_id(device), "role": v.role,
        "depth": depth if depth is not None else v.depth,
        "membership": (item or {}).get("membership"), "connectivity": (item or {}).get("connectivity"),
        "listed": item is not None, "silent": v.silent, "lost": v.lost, "rssi": v.rssi, "loss_pct": v.loss_pct,
        "quality": link_quality(v.rssi, v.loss_pct, v.silent), "children": [],
    }


def infer_root(nodes: list[dict[str, Any]]) -> str | None:
    """The root's DeviceId when the caller does not know it: the one parent_device_id that is not a listed node."""
    listed = {n["device_id"] for n in nodes}
    outside = [n["parent_device_id"] for n in nodes if n.get("parent_device_id") and n["parent_device_id"] not in listed]
    if not outside:
        return None
    return max(set(outside), key=outside.count)


def _break_cycles(parents: dict[str, str | None]) -> None:
    """A parent chain that loops back on itself is cut at its smallest DeviceId (that node becomes "parent unknown")."""
    for start in list(parents):
        seen: list[str] = []
        cur: str | None = start
        while cur is not None and cur in parents and cur not in seen:
            seen.append(cur)
            cur = parents[cur]
        if cur is not None and cur in seen:  # `cur` is on the cycle
            cycle = seen[seen.index(cur):]
            parents[min(cycle)] = None


def build_tree(nodes: list[dict[str, Any]], views: dict[str, NodeView], root_id: str | None = None,
               root_name: str = "root") -> dict[str, Any]:
    """{"root": node, "has_parent_info": bool}: the root with its children; nodes whose parent is not known hang under
    one `unknown parent` group (id "?"). A node whose parent is not listed gets a greyed placeholder for that parent;
    a parent cycle is cut at one node, which goes to the unknown group.

    `nodes` are the Host's /v1/nodes items; `views` adds telemetry-derived data by DeviceId."""
    by_id = {n["device_id"]: n for n in nodes}
    root_id = root_id or infer_root(nodes) or ""
    made: dict[str, dict[str, Any]] = {d: _leaf(d, n, views.get(d)) for d, n in by_id.items()}
    parents: dict[str, str | None] = {}
    for device, item in by_id.items():
        p = item.get("parent_device_id")
        parents[device] = p if isinstance(p, str) and p and p != device else None
    _break_cycles(parents)
    root: dict[str, Any] = {"id": root_id, "name": root_name, "short": short_id(root_id) if root_id else "",
                            "root": True, "children": [], "role": "root", "depth": 0, "quality": "unknown",
                            "listed": True}
    unknown: list[dict[str, Any]] = []
    for device, parent in parents.items():
        if parent is None:
            unknown.append(made[device])
        elif parent == root_id:
            root["children"].append(made[device])
        else:
            if parent not in made:  # a parent the Host does not list (left, revoked): keep the child under a grey stand-in
                ghost = _leaf(parent, None, NodeView(name=short_id(parent), silent=True))
                ghost["placeholder"] = True
                made[parent] = ghost
                root["children"].append(ghost)
            made[parent]["children"].append(made[device])
    if unknown:
        def key(n: dict[str, Any]) -> tuple[bool, int, str]:
            return n["depth"] is None, n["depth"] or 0, n["name"]

        root["children"].append({"id": UNKNOWN_PARENT_ID, "name": "parent unknown", "short": "?", "group": True,
                                 "role": None, "depth": None, "quality": "unknown", "silent": True, "listed": True,
                                 "children": sorted(unknown, key=key)})
    _sort(root)
    return {"root": root, "has_parent_info": any(isinstance(p, str) and p for p in
                                                  (n.get("parent_device_id") for n in nodes))}


def _sort(node: dict[str, Any]) -> None:
    if not node.get("group"):  # (the unknown-parent group keeps its order by depth)
        node["children"].sort(key=lambda n: (bool(n.get("group")), n.get("name", "")))
    for c in node["children"]:
        _sort(c)


def flatten(tree_node: dict[str, Any]) -> list[dict[str, Any]]:
    """Every node of the tree (parents first), for tests and the table."""
    out = [tree_node]
    for c in tree_node["children"]:
        out.extend(flatten(c))
    return out
