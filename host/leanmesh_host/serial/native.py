"""ctypes binding of libleanmesh_host (src/hostnative/lmh_api.h). No protocol logic lives here."""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import POINTER, Structure, c_int32, c_size_t, c_uint8, c_uint32, c_uint64, c_void_p
from pathlib import Path

ABI_VERSION = 2

EVENT_SESSION_UP = 1
EVENT_SESSION_DOWN = 2
EVENT_RECORD = 3
EVENT_TX_READY = 4

KIND_REQUEST = 3
KIND_RESPONSE = 4
KIND_EVENT = 5

# LM_STATUS_* values used by the serial layer (api/leanmesh.h).
OK = 0
UNSUPPORTED = 2
BUSY = 3
CONFLICT = 9
BUFFER_TOO_SMALL = 17

DOWN_REASONS = {0: "CLOSED", 1: "REPLACED", 2: "AEAD", 3: "SILENCE", 4: "CREDIT", 5: "PEER", 6: "EXPIRED"}
STAT_NAMES = (
    "rx_bytes", "rx_frames", "rx_cobs_bad", "rx_overflow", "rx_bad_frame", "rx_unsupported",
    "rx_unknown_session", "rx_auth_fail", "rx_replay", "rx_malformed", "rx_credit_violation",
    "rx_hello", "rx_edhoc_dropped", "tx_frames", "tx_partial", "tx_credit_blocked", "hs_started",
    "hs_failed", "hs_rejected", "sessions", "pings_rx", "events_dropped", "last_failure",
)


class NativeError(RuntimeError):
    def __init__(self, status: int, what: str) -> None:
        super().__init__(f"{what}: LM status {status}")
        self.status = status


class Event(Structure):
    _fields_ = [("kind", c_uint32), ("gen", c_uint32), ("aux", c_uint32), ("lane", c_uint32),
                ("frame_bytes", c_uint32), ("payload_len", c_uint32)]


class Stats(Structure):
    _fields_ = [("v", c_uint64 * 24)]


def library_path() -> Path:
    explicit = os.environ.get("LEANMESH_HOSTNATIVE")
    if explicit:
        return Path(explicit)
    build = Path(os.environ.get("LEANMESH_NATIVE_BUILD", Path.home() / ".cache/leanmesh/native"))
    # CMake names a SHARED library after the platform: .dylib on macOS, .so elsewhere.
    return build / ("libleanmesh_host.dylib" if sys.platform == "darwin" else "libleanmesh_host.so")


def load_library(path: Path | None = None) -> ctypes.CDLL:
    p = path or library_path()
    if not p.is_file():
        raise FileNotFoundError(f"{p} not found: build the native tree (cmake --build <native build dir>)")
    lib = ctypes.CDLL(str(p))
    lib.lmh_abi_version.restype = c_uint32
    if lib.lmh_abi_version() != ABI_VERSION:
        raise NativeError(2, f"libleanmesh_host ABI {lib.lmh_abi_version()} != {ABI_VERSION}")
    u8p = POINTER(c_uint8)
    lib.lmh_usb_create.restype = c_void_p
    lib.lmh_usb_create.argtypes = [u8p, c_size_t, c_uint64, POINTER(c_int32)]
    lib.lmh_usb_destroy.argtypes = [c_void_p]
    lib.lmh_usb_destroy.restype = None
    lib.lmh_usb_self.argtypes = [c_void_p, u8p]
    lib.lmh_usb_self.restype = c_int32
    lib.lmh_usb_open.argtypes = [c_void_p, c_uint64]
    lib.lmh_usb_open.restype = c_int32
    lib.lmh_usb_close.argtypes = [c_void_p]
    lib.lmh_usb_close.restype = None
    lib.lmh_usb_feed.argtypes = [c_void_p, u8p, c_size_t, c_uint64]
    lib.lmh_usb_feed.restype = c_int32
    lib.lmh_usb_peek_tx.argtypes = [c_void_p, u8p, c_size_t]
    lib.lmh_usb_peek_tx.restype = c_size_t
    lib.lmh_usb_consume_tx.argtypes = [c_void_p, c_size_t]
    lib.lmh_usb_consume_tx.restype = c_int32
    lib.lmh_usb_tick.argtypes = [c_void_p, c_uint64]
    lib.lmh_usb_tick.restype = c_int32
    lib.lmh_usb_deadline_us.argtypes = [c_void_p]
    lib.lmh_usb_deadline_us.restype = c_uint64
    lib.lmh_usb_poll_event.argtypes = [c_void_p, POINTER(Event), u8p, c_size_t, c_uint64]
    lib.lmh_usb_poll_event.restype = c_int32
    lib.lmh_usb_send.argtypes = [c_void_p, c_uint32, c_uint32, u8p, c_size_t, c_uint64]
    lib.lmh_usb_send.restype = c_int32
    lib.lmh_usb_active.argtypes = [c_void_p, POINTER(c_uint32), POINTER(c_uint32)]
    lib.lmh_usb_active.restype = c_int32
    lib.lmh_usb_stats.argtypes = [c_void_p, POINTER(Stats)]
    lib.lmh_usb_stats.restype = c_int32
    return lib
