"""Builders of ledger backups for the Host tests (issue #5): a structurally valid signed header (the signature is a
placeholder: the root verifies it) and the records its hash chain fixes."""

from __future__ import annotations

from leanmesh_host.db import ledger_backup as lb
from leanmesh_host.wire import cbor_encode
from leanmesh_host.wire.control import ControlBody, encode_cose_sign1, encode_control_body

DOMAIN = bytes([0xD0]) * 16
ROOT = bytes([0x11]) * 32
OTHER_ROOT = bytes([0x22]) * 32
DELEGATION = b"\xd2" + bytes(60)  # (opaque here: the Host does not open the delegation)


def header(entries: int, extras: int, head: bytes, *, seq: int = 1, domain: bytes = DOMAIN, root: bytes = ROOT,
           revision: int | None = None, kid: bytes | None = None) -> bytes:
    data = cbor_encode([seq, 4, 1, DELEGATION, 9, entries, extras, head])
    body = ControlBody(lb.CONTROL_TYPE, 1, bytes(16), domain, seq if revision is None else revision, root, data)
    return encode_cose_sign1(root if kid is None else kid, encode_control_body(body), bytes(64))


def pages(slots: list[int], extras: int = 0) -> list[tuple[int, int, bytes]]:
    """A ledger's records: floors/groups/policy as asked, one entry per slot, the manifest last."""
    out: list[tuple[int, int, bytes]] = []
    if extras & 1:
        out.append((lb.ID_FLOORS, 0, bytes([0])))
    if extras & 2:
        out.append((lb.ID_GROUPS, 0, bytes([1, 0])))
    if extras & 4:
        out.append((lb.ID_POLICY, 0, bytes([1, 1]) + bytes(8)))
    out += [(lb.ENTRY_BASE + s, 3, bytes([s]) * 100) for s in slots]
    out.append((lb.ID_MANIFEST, 0, bytes([7]) * 150))
    return out


def head_of(recs: list[tuple[int, int, bytes]]) -> bytes:
    nxt = lb.ZERO
    for rid, state, payload in reversed(recs):
        nxt = lb.chain_link(rid, state, payload, nxt)
    return nxt


def make(slots: list[int], extras: int = 0, **kw: object) -> lb.Backup:
    recs = pages(slots, extras)
    entries = sum(1 << s for s in slots)
    return lb.build(header(entries, extras, head_of(recs), **kw), recs)  # type: ignore[arg-type]
