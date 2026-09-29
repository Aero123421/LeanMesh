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
