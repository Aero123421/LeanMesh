"""The native USB session helper as the Host loads it (ctypes): ABI, kit validation, failure codes.
The protocol itself is exercised end to end in host/tests/e2e/test_usb_serial.py and natively in
tests/native/test_serial.cpp; this only guards the boundary Python owns."""

from __future__ import annotations

import ctypes

import pytest
from leanmesh_host.serial import NativeError, load_library
from leanmesh_host.serial import native as n
from leanmesh_host.wire import cbor_encode


def _create(kit: bytes) -> tuple[int, int]:
    lib = load_library()
    status = ctypes.c_int32(0)
    buf = (ctypes.c_uint8 * max(len(kit), 1)).from_buffer_copy(kit or b"\0")
    handle = lib.lmh_usb_create(buf, len(kit), 1, ctypes.byref(status))
    if handle:
        lib.lmh_usb_destroy(ctypes.c_void_p(handle))
    return int(handle or 0), status.value


def test_library_loads_with_expected_abi() -> None:
    assert load_library().lmh_abi_version() == n.ABI_VERSION


@pytest.mark.parametrize("kit", [
    b"garbage",
    cbor_encode([1, b"\x00" * 10, b"\x00" * 10, b"\x11" * 16]),   # records that do not decode
    cbor_encode([2, b"\x00" * 40, b"\x00" * 88, b"\x11" * 16]),   # unknown kit version
    cbor_encode([1, b"\x00" * 40, b"\x00" * 88, b"\x11" * 8]),    # domain must be 16 bytes
])
def test_bad_kit_is_refused_not_accepted(kit: bytes) -> None:
    handle, status = _create(kit)
    assert handle == 0 and status != n.OK


def test_load_error_type_carries_status() -> None:
    err = NativeError(7, "x")
    assert err.status == 7
