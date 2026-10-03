"""FIX2-D13/D14: the serial thread's TX accounting and shutdown, against a scripted native library."""

from __future__ import annotations

import asyncio
import ctypes
import fcntl
import os
import sys
import threading
from typing import Any

import pytest
from leanmesh_host.serial.link import SerialLink, SessionChanged, _Pending

# F_SETPIPE_SZ (fcntl 1031) shrinks a pipe so a write is partial; only Linux has it.
linux_pipe = pytest.mark.skipif(sys.platform != "linux", reason="needs Linux F_SETPIPE_SZ")


class _Lib:
    """The TX queue of the native session and the calls that matter here."""

    def __init__(self, tx: bytes = b"") -> None:
        self.tx = bytearray(tx)
        self.destroyed = 0

    def lmh_usb_peek_tx(self, _h: Any, out: Any, cap: int) -> int:
        n = min(cap, len(self.tx))
        ctypes.memmove(out, bytes(self.tx[:n]), n)
        return n

    def lmh_usb_consume_tx(self, _h: Any, n: int) -> int:
        del self.tx[:n]
        return 0

    def lmh_usb_destroy(self, _h: Any) -> None:
        self.destroyed += 1


def _link(lib: _Lib) -> SerialLink:
    link = SerialLink.__new__(SerialLink)  # no port, no native handle: only the parts under test
    link._lib = lib  # type: ignore[assignment]
    link._h = ctypes.c_void_p(1)
    link._tx_blocked_since = None
    link._thread = None
    link._stop = threading.Event()
    link._wake_r, link._wake_w = os.pipe()
    link._lock = threading.Lock()
    link._queue = __import__("collections").deque()
    link._pending = {}
    return link


@linux_pipe
def test_tx_bytes_leave_the_native_queue_only_as_far_as_the_os_accepted_them() -> None:
    r, w = os.pipe()
    os.set_blocking(w, False)
    fcntl.fcntl(w, 1031, 4096)  # F_SETPIPE_SZ: the smallest pipe, so a write is partial
    lib = _Lib(bytes(range(256)) * 32)  # 8 KiB
    link = _link(lib)
    total = len(lib.tx)
    assert link._drain_tx(w) is True
    taken = total - len(lib.tx)
    assert 0 < taken < total  # the pipe took part of it: the rest is still queued
    assert os.read(r, 65536) == (bytes(range(256)) * 32)[:taken]  # exactly the accepted prefix left
    assert bytes(lib.tx) == (bytes(range(256)) * 32)[taken:]
    assert link._tx_blocked_since is not None  # the loop waits for writability instead of dropping bytes
    while lib.tx:  # once the reader drained the pipe, everything arrives in order
        link._drain_tx(w)
        os.read(r, 65536)
    assert link._drain_tx(w) is False and link._tx_blocked_since is None


@linux_pipe
def test_a_port_that_takes_nothing_keeps_every_byte_queued() -> None:
    r, w = os.pipe()
    os.set_blocking(w, False)
    fcntl.fcntl(w, 1031, 4096)
    while True:  # fill the pipe completely
        try:
            os.write(w, b"x" * 512)
        except BlockingIOError:
            break
    lib = _Lib(b"abc")
    link = _link(lib)
    assert link._drain_tx(w) is False
    assert bytes(lib.tx) == b"abc"
    os.close(r)


def test_stop_never_destroys_native_state_under_a_running_thread() -> None:
    lib = _Lib()
    link = _link(lib)
    release = threading.Event()
    link._thread = threading.Thread(target=release.wait, daemon=True)  # stuck in a native call
    link._thread.start()
    assert link.stop(timeout=0.05) is False
    assert lib.destroyed == 0 and link._h  # still valid for the thread
    release.set()
    link._thread.join()
    assert link.stop(timeout=1.0) is True
    assert lib.destroyed == 1 and not link._h


def test_every_waiting_request_learns_whether_it_was_written() -> None:
    async def run() -> list[Exception]:
        loop = asyncio.get_running_loop()
        link = _link(_Lib())
        link._loop = loop
        pend = []
        for i, sent in enumerate((True, False)):
            p = _Pending(bytes([i]) * 16, b"", 1, loop.create_future(), sent=sent)
            link._pending[p.request_id] = p
            pend.append(p)
        assert link.stop(timeout=0.1) is True
        errors: list[Exception] = []
        for p in pend:
            with pytest.raises(SessionChanged) as exc:
                await asyncio.wait_for(p.future, 1)
            errors.append(exc.value)
        return errors

    first, second = asyncio.run(run())
    assert first is not second and first.sent is True and second.sent is False
