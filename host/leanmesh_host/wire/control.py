"""ControlObject envelope and COSE_Sign1 structure (docs/09 §8, docs/19 §1, protocol/control.cddl).

Structure only: signatures and authority are never checked here. Mirrors src/core/wire/control.cpp.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .cbor import WireError, _bad, cbor_decode, cbor_encode

COSE_MAX_BYTES = 4096
SIGNED_TYPES = frozenset({1, 2, 3, 4, 5, 11, 12, 19, 21, 26, 29, 30, 31, 32, 34})
SOCS = ("esp32c3", "esp32s3", "esp32c5", "esp32c6")
U32, U63, U64 = 2**32 - 1, 2**63 - 1, 2**64 - 1

# Field specs: ("u", lo, hi) ("b", lo, hi) ("t", lo, hi) ("bool",) ("list", lo, hi, elem)
# ("tuple", [fields]) ("null", inner) ("key",) ("soc",)
_U32, _U63, _U64 = ("u", 0, U32), ("u", 0, U63), ("u", 0, U64)
_ID16, _ID32 = ("b", 16, 16), ("b", 32, 32)
_BOOL, _KEY, _SOC = ("bool",), ("key",), ("soc",)
_ADDR, _CH = ("u", 1, 65534), ("u", 1, 13)
_ADDRS = ("list", 1, 21, _ADDR)

SHAPES: dict[int, list[Any]] = {
    1: [_ID32, _KEY, _ID16, ("t", 1, 48), _U63, _ID32],
    2: [_ID16, _ID32, _KEY, _ID16, _U63, ("u", 0, 63)],
    3: [_ID32, _ID16, _ID16, _ID16, _ID32, _U63, _U63, _ID16, ("u", 0, 1), _ID16, _ID32],
    4: [_ID32, _ADDR, _U63, _U63, ("u", 0, 2), _BOOL, _U32, _U64, _ID32, _ID32],
    5: [("u", 0, 15), ("u", 1, 16), _ID32, ("list", 0, 8, ("tuple", [_ID32, _U63, _ID32, _BOOL]))],
    6: [("b", 1, 1024), ("b", 1, 1024), _ID16, _U64],
    7: [("b", 1, 1024), _ID32, _ADDR, _U63, _U32, ("u", 1, 120000)],
    8: [_ID32, _U63],
    9: [_ID32, _U63, ("b", 0, 64)],  # JoinCommit + the withheld member signature (SEC-D1; none in a refusal)
    10: [_ID32, _U63],
    11: [_ID32, _U63, _U63, _U32, _U63],
    12: [_U63, _U63, _ID32, ("b", 1, 3072)],
    13: [_ID32, _U63, _U63, _U32, _ADDR, _ADDRS, _U32, _ID16],
    14: [_ID32, _U32, _U32, _ADDRS, _U64],
    15: [_ID32, _U32],
    16: [_ID16, _ADDR, _ADDR, _BOOL, ("u", 0, 255), _U63],
    17: [_ID16, _U32, _U64],
    18: [_ID16, _U32, _U64, _U64, _U64],
    19: [_ID16, ("u", 0, 2), _U32, _U32, _CH, _CH, _ID32, _U64, _U32, _U32, _U63, _ID32],
    20: [_ID16, _ID32, _ID32, ("u", 0, 3), _U32, _U32],
    21: [_U32, _U32, _CH, _ID16, _ID32, _ID32],
    25: [_ID16, _ID32, ("u", 0, 6), _U32, _U32, ("b", 0, 32)],
    26: [_SOC, ("t", 1, 32), ("u", 1, 1900544), _ID32, ("t", 1, 32), _U32, _U32, _U32, _U32,
         ("u", 4096, 4096)],
    27: [_ID32, ("u", 0, 1), ("u", 0, 30000)],
    28: [_ID32, _U63, _U63, _U32, _U63, ("u", 0, 2), ("u", 0, 2), _U64, _U64,
         ("u", 0, 86400000), ("u", 0, 65535), ("u", 1, 86400000)],
    29: [_ID32, _U63, _U63, _ID32, ("b", 1, 1024)],
    30: [_ID16, _U32, _U63, _U64, _U64, ("u", 1, 64), ("u", 1, 3), _U63],
    31: [_ID16, _ID32, _ID32, _U63, _U63, _ID32, _U32, ("u", 0, 1)],
    32: [_U32, _U63, _ID16, _ID32, ("u", 0, 64), ("u", 0, 4), _ID32,
         ("list", 0, 16, ("tuple", [_ID32, _U63, _U63]))],
    33: [_U32, _U63, ("u", 0, 4), ("null", _ID16)],
    34: [_U63, _U32, _U63, ("b", 1, 448), _U63, _U64, ("u", 0, 7), _ID32],  # LedgerBackup (ISSUE5)
}


def is_signed_control_type(t: int) -> bool:
    return t in SIGNED_TYPES


def is_control_type_defined(t: int) -> bool:
    return t in SHAPES


def _is_int(x: Any) -> bool:
    return type(x) is int


def _check(x: Any, spec: Any) -> None:
    kind = spec[0]
    ok = False
    if kind == "u":
        ok = _is_int(x) and spec[1] <= x <= spec[2]
    elif kind == "b":
        ok = isinstance(x, bytes) and spec[1] <= len(x) <= spec[2]
    elif kind == "t":
        ok = isinstance(x, str) and spec[1] <= len(x.encode()) <= spec[2]
    elif kind == "bool":
        ok = isinstance(x, bool)
    elif kind == "list":
        ok = isinstance(x, list) and spec[1] <= len(x) <= spec[2]
        if ok:
            for y in x:
                _check(y, spec[3])
    elif kind == "tuple":
        ok = isinstance(x, list) and len(x) == len(spec[1])
        if ok:
            for y, s in zip(x, spec[1], strict=True):
                _check(y, s)
    elif kind == "null":
        if x is None:
            return
        _check(x, spec[1])
        return
    elif kind == "key":
        ok = (
            isinstance(x, dict)
            and list(x) == [1, -1, -2, -3]
            and _is_int(x[1])
            and x[1] == 2
            and _is_int(x[-1])
            and x[-1] == 1
            and isinstance(x[-2], bytes)
            and len(x[-2]) == 32
            and isinstance(x[-3], bytes)
            and len(x[-3]) == 32
        )
    elif kind == "soc":
        ok = isinstance(x, str) and x in SOCS
    if not ok:
        raise _bad("control data shape")


@dataclass
class ControlBody:
    type: int
    version: int
    request_id: bytes
    domain: bytes
    revision: int
    issuer: bytes
    data: bytes  # encoded control-data item


def decode_control_body(raw: bytes, carrier: str) -> ControlBody:
    """carrier is "signed" (inside COSE_Sign1) or "session" (inside a session AEAD)."""
    v = cbor_decode(raw)
    if not isinstance(v, list) or len(v) != 7:
        raise _bad("control-body array")
    typ, version = v[0], v[1]
    if not (_is_int(typ) and 0 <= typ <= U32 and _is_int(version) and 0 <= version <= U32):
        raise _bad("control-body type/version")
    if typ not in SHAPES or version != 1:
        raise WireError("UNSUPPORTED", "control type or version")
    _check(v[2], _ID16)
    _check(v[3], _ID16)
    _check(v[4], _U63)
    _check(v[5], _ID32)
    _check(v[6], ("tuple", SHAPES[typ]))
    if is_signed_control_type(typ) != (carrier == "signed"):
        raise WireError("AUTH_REJECTED", "carrier does not match type")
    return ControlBody(typ, version, v[2], v[3], v[4], v[5], cbor_encode(v[6]))


def encode_control_body(b: ControlBody) -> bytes:
    return (
        b"\x87"
        + cbor_encode(b.type)
        + cbor_encode(b.version)
        + cbor_encode(b.request_id)
        + cbor_encode(b.domain)
        + cbor_encode(b.revision)
        + cbor_encode(b.issuer)
        + b.data
    )


PROTECTED_PREFIX = bytes([0xA2, 0x01, 0x26, 0x04, 0x58, 0x20])


@dataclass
class CoseSign1:
    protected: bytes
    kid: bytes
    payload: bytes
    signature: bytes


def decode_cose_sign1(raw: bytes) -> CoseSign1:
    if len(raw) > COSE_MAX_BYTES or not raw or raw[0] != 0xD2:
        raise _bad("COSE tag 18")
    v = cbor_decode(raw[1:])
    if not isinstance(v, list) or len(v) != 4:
        raise _bad("COSE array")
    prot, unprot, payload, sig = v
    if (
        not isinstance(prot, bytes)
        or len(prot) != len(PROTECTED_PREFIX) + 32
        or unprot != {}
        or not isinstance(unprot, dict)
        or not isinstance(payload, bytes)
        or len(payload) > COSE_MAX_BYTES
        or not isinstance(sig, bytes)
        or len(sig) != 64
        or not prot.startswith(PROTECTED_PREFIX)
    ):
        raise _bad("COSE fields")
    return CoseSign1(prot, prot[len(PROTECTED_PREFIX) :], payload, sig)


def encode_cose_sign1(kid: bytes, payload: bytes, signature: bytes) -> bytes:
    if len(kid) != 32 or len(signature) != 64:
        raise WireError("INVALID_ARGUMENT")
    return b"\xd2" + cbor_encode([PROTECTED_PREFIX + kid, {}, payload, signature])


def sig_structure_prefix(protected: bytes, payload_len: int) -> bytes:
    """["Signature1", protected, h'LM1-CONTROL', payload] up to the payload bstr head."""
    full = cbor_encode(["Signature1", protected, b"LM1-CONTROL", b"\x00" * payload_len])
    return full[: len(full) - payload_len]
