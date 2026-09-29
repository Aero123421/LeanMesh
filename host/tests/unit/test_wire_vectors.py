"""Host wire codec: spec-consistency checks against the normative files and negative vectors.
The cross-implementation agreement (C++ vs Python vs fixture) is in test_wire_differential.py."""

from __future__ import annotations

import json
import re

import pytest
from harness import REPO_ROOT
from leanmesh_host.wire import control as C
from leanmesh_host.wire import frames as F
from leanmesh_host.wire.cbor import WireError, cbor_decode, cbor_encode

REGISTRY = json.loads((REPO_ROOT / "protocol/registry.json").read_text())
GOLDEN = json.loads((REPO_ROOT / "tests/golden.json").read_text())
POWER_GOLDEN = json.loads((REPO_ROOT / "tests/power_golden.json").read_text())


def test_struct_formats_and_offsets_match_registry() -> None:
    fmt = REGISTRY["struct_formats"]
    pairs = {"link": F.LINK, "route": F.ROUTE, "end": F.END, "hop_ack": F.HOP_ACK, "fragment": F.FRAG,
             "serial": F.SERIAL, "power_poll": F.POWER_POLL, "power_grant": F.POWER_GRANT}
    for name, s in pairs.items():
        assert s.format == fmt[name], name
    for name, s in (("link", F.LINK), ("route", F.ROUTE), ("end", F.END)):
        assert REGISTRY["fields"][name]["bytes"] == s.size
        offset = 0
        for item in REGISTRY["fields"][name]["items"]:
            assert item["offset"] == offset, (name, item)
            offset += item["size"]
    assert F.POWER_POLL.size == REGISTRY["power_frames"]["poll"]["bytes"] == 28
    assert F.POWER_GRANT.size == REGISTRY["power_frames"]["grant"]["bytes"] == 24
    assert F.LINK.size + 12 + F.TAG == 52  # HOP_ACK frame


def test_frame_kinds_and_control_types_match_registry_and_cddl() -> None:
    kinds = REGISTRY["frame_kinds"]
    assert (kinds["DISCOVERY"], kinds["HOP_ACK"], kinds["DATA"], kinds["ROUTE"], kinds["CONTROL"],
            kinds["EDHOC"], kinds["JOIN_PROXY"], kinds["POWER"]) == (
        F.DISCOVERY, F.HOP_ACK_KIND, F.DATA, F.ROUTE_KIND, F.CONTROL, F.EDHOC, F.JOIN_PROXY, F.POWER)
    assert REGISTRY["record_kinds"] == {"DATA": 1, "RECEIPT": 2, "FRAGMENT": 3, "CONTROL": 4,
                                        "TRANSFER_BITMAP": 5}
    types = set(REGISTRY["control_types"].values())
    assert set(C.SHAPES) == types
    assert not {22, 23, 24} & types and set(REGISTRY["reserved_control_types"]) == {22, 23, 24}
    assert set(C.SIGNED_TYPES) == set(REGISTRY["signed_control_types"])
    cddl = (REPO_ROOT / "protocol/control.cddl").read_text()
    assert "type: (1..21 / 25..33)" in re.sub(r"\s+", " ", cddl)
    lim = REGISTRY["limits"]
    assert (F.MAX_FRAME, F.MAX_PATH) == (lim["rf_body_bytes"], lim["path_hops"])
    assert lim["serial_decoded_bytes"] == 18 + lim["serial_payload_bytes"] + 16 + 4


def test_golden_frames_and_power_vectors() -> None:
    for f in GOLDEN["frames"]:
        packet = bytes.fromhex(f["packet_hex"])
        h, payload = F.decode_link_frame(packet)
        assert (h.kind, h.link_sid, h.link_counter, h.encrypted) == (F.DATA, 0x50607080, 1, True)
        assert len(packet) == 250 and h.body_length == 210 and len(payload) == 226
        assert len(bytes.fromhex(f["payload_hex"])) == F.data_capacity(f["hops"])
        for n in range(251):
            if n != 250:
                with pytest.raises(WireError):
                    F.decode_link_frame(packet[:n])
    poll = F.decode_power_poll(bytes.fromhex(POWER_GOLDEN["poll_hex"]))
    grant = F.decode_power_grant(bytes.fromhex(POWER_GOLDEN["grant_hex"]))
    F.check_grant_against_poll(poll, grant)
    assert F.encode_power_poll(poll).hex() == POWER_GOLDEN["poll_hex"]
    assert F.encode_power_grant(grant).hex() == POWER_GOLDEN["grant_hex"]
    for tweak in ({"granted_credit": 3}, {"window_ttl_ms": 251}, {"poll_nonce": 2}):
        bad = F.PowerGrant(**{**grant.__dict__, **tweak})
        with pytest.raises(WireError):
            F.check_grant_against_poll(poll, bad)


@pytest.mark.parametrize("h", ["1800", "190000", "1a0000ffff", "5800", "9f01ff", "f90000", "f7",
                               "c074323030", "a201020102", "a202010101", "a1f401", "6180", "62c0af",
                               "63eda080", "0000", "", "8301"])
def test_cbor_rejects_non_deterministic(h: str) -> None:
    with pytest.raises(WireError):
        cbor_decode(bytes.fromhex(h))


def test_cbor_limits_and_roundtrip() -> None:
    assert cbor_decode(b"\x81" * 16 + b"\x00")
    with pytest.raises(WireError):
        cbor_decode(b"\x81" * 17 + b"\x00")
    assert len(cbor_decode(bytes([0x99, 0x10, 0x00]) + bytes(4096))) == 4096
    with pytest.raises(WireError):
        cbor_decode(bytes([0x99, 0x10, 0x01]) + bytes(4097))
    v = {1: 2, -1: [b"x", "é", None, True], b"k": {"a": 2**64 - 1, "b": -(2**64)}}
    assert cbor_decode(cbor_encode(v)) == v
    with pytest.raises(WireError):
        cbor_encode(2**64)


@pytest.mark.scenario("R04")
def test_r04_python_codec_rejects_duplicate_and_looping_paths() -> None:
    def route(path: list[int], origin: int, final: int) -> bytes:
        h = F.RouteHeader(origin, final, len(path), 0, len(path), 1, 1, path)
        return F.encode_route(h) + bytes(58)

    F.decode_route(route([3, 4, 5], 2, 5))
    for path, origin, final in (([3, 4, 3, 5], 2, 5), ([3, 4, 4], 2, 4), ([2, 5], 2, 5),
                                ([3, 0, 5], 2, 5), ([3, 65535, 5], 2, 5), ([3, 4, 5], 0, 5),
                                ([3, 4, 5], 2, 4)):
        with pytest.raises(WireError):
            F.decode_route(route(path, origin, final))
    with pytest.raises(WireError):
        F.encode_route(F.RouteHeader(1, 2, 41, 0, 41, 1, 1, list(range(2, 43))))


def test_control_type_table_and_carrier_rules() -> None:
    probe = [b"\x00" * 16, 1, 2, False, 0, 0]
    base = (b"\x00" * 16, bytes(range(16)), 1, bytes(range(32)))
    ok = cbor_encode([16, 1, *base, probe])
    assert C.decode_control_body(ok, "session").type == 16
    with pytest.raises(WireError) as e:
        C.decode_control_body(ok, "signed")
    assert e.value.status == "AUTH_REJECTED"
    for t in (0, 22, 23, 24, 34):
        with pytest.raises(WireError) as e:
            C.decode_control_body(cbor_encode([t, 1, *base, probe]), "session")
        assert e.value.status == "UNSUPPORTED"
    with pytest.raises(WireError) as e:
        C.decode_control_body(cbor_encode([15, 1, *base, probe]), "session")  # RouteQuery shape
    assert e.value.status == "BAD_FRAME"
