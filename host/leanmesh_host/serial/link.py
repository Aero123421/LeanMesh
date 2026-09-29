"""The Host's serial thread (docs/11 §2): owns the port exclusively for read and write, reconnects
with backoff, and drives the native session helper. Nothing here parses COBS, checks a CRC, does
EDHOC or touches AEAD keys; that is one C++ implementation shared with the root.

Rules kept here:
  * nothing blocks the event loop: the thread hands results over with call_soon_threadsafe;
  * results of an old session are never applied to a new one: every request is tied to the session
    generation it was issued under and fails with SessionChanged when that session ends;
  * a request whose write might have happened is never silently repeated: the caller reconciles
    (GET_REQUEST/GET_MESSAGE, docs/19 §5); this module only reports "session changed";
  * bounded everything: 64 queued requests, the native side bounds the rest.
"""

from __future__ import annotations

import asyncio
import collections
import ctypes
import logging
import os
import random
import select
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import serial

from ..wire import WireError, cbor_decode, cbor_encode
from . import native

log = logging.getLogger(__name__)

MAX_QUEUED_REQUESTS = 64
REQUEST_TIMEOUT_S = 5.0  # docs/19 §5
BACKOFF_MIN_S = 0.5
BACKOFF_MAX_S = 30.0  # docs/11 §8: 0.5..30 s + jitter
_READ_CHUNK = 16384
_EVENT_BUF = 8192 + 64


class SessionGone(RuntimeError):
    """No ACTIVE session: nothing was sent."""


class SessionChanged(RuntimeError):
    """The session ended (or was replaced) before the response. `sent` False: the request never left
    the Host. `sent` True: the outcome is UNKNOWN and must be reconciled by MessageId/request id
    (GET_REQUEST/GET_MESSAGE), never assumed to have failed or succeeded."""

    def __init__(self, message: str, sent: bool = False) -> None:
        super().__init__(message)
        self.sent = sent


class SerialBusy(RuntimeError):
    """The bounded request queue is full (local shortage, not a lost request)."""


@dataclass(frozen=True)
class ResponseResult:
    status: int
    operation_id: int | None
    result: bytes | None
    gen: int


@dataclass
class _Pending:
    request_id: bytes
    payload: bytes
    gen: int
    future: asyncio.Future[ResponseResult]
    sent: bool = False


class SerialLink:
    def __init__(
        self,
        device: str,
        kit: bytes,
        loop: asyncio.AbstractEventLoop,
        *,
        on_state: Callable[[bool, int], None] | None = None,
        on_event: Callable[[bytes, int], None] | None = None,
        lib: Any = None,
    ) -> None:
        self.device = device
        self._loop = loop
        self._on_state = on_state
        self._on_event = on_event
        self._lib = lib or native.load_library()
        status = ctypes.c_int32(0)
        boot = int.from_bytes(os.urandom(8), "big")
        kit_buf = (ctypes.c_uint8 * len(kit)).from_buffer_copy(kit)
        handle = self._lib.lmh_usb_create(kit_buf, len(kit), boot, ctypes.byref(status))
        if not handle:
            raise native.NativeError(status.value, "USB kit rejected")
        self._h = ctypes.c_void_p(handle)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        rfd, wfd = os.pipe()
        os.set_blocking(rfd, False)
        os.set_blocking(wfd, False)
        self._wake_r, self._wake_w = rfd, wfd
        self._lock = threading.Lock()
        self._queue: collections.deque[_Pending] = collections.deque()
        self._pending: dict[bytes, _Pending] = {}
        # state visible to other threads (single-writer: the serial thread)
        self.connected = False
        self.gen = 0
        self.port_open = False
        self.last_error = ""

    # ---- lifecycle -------------------------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="leanmesh-serial", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        if not self._h:
            return  # already stopped
        self._stop.set()
        self._wake()
        if self._thread is not None:
            self._thread.join(timeout)
        self._fail_all(SessionGone("serial link stopped"))
        self._lib.lmh_usb_destroy(self._h)
        self._h = ctypes.c_void_p(0)
        os.close(self._wake_r)
        os.close(self._wake_w)

    def stats(self) -> dict[str, int]:
        st = native.Stats()
        if self._h and self._lib.lmh_usb_stats(self._h, ctypes.byref(st)) == native.OK:
            return {name: int(st.v[i]) for i, name in enumerate(native.STAT_NAMES)}
        return {}

    def device_id(self) -> bytes:
        out = (ctypes.c_uint8 * 32)()
        self._lib.lmh_usb_self(self._h, out)
        return bytes(out)

    # ---- API for the event loop ------------------------------------------------------------
    async def request(self, method: int, params: Any = None, timeout: float = REQUEST_TIMEOUT_S) -> ResponseResult:
        """Sends REQUEST [request_id, method, params] and waits for its RESPONSE. Raises
        SessionGone (nothing sent), SessionChanged (outcome unknown), SerialBusy, TimeoutError."""
        if not self.connected:
            raise SessionGone("no ACTIVE USB session")
        rid = os.urandom(16)
        fut: asyncio.Future[ResponseResult] = self._loop.create_future()
        pending = _Pending(rid, cbor_encode([rid, method, params]), self.gen, fut)
        with self._lock:
            if len(self._queue) >= MAX_QUEUED_REQUESTS:
                raise SerialBusy("request queue full")
            self._queue.append(pending)
            self._pending[rid] = pending
        self._wake()
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            with self._lock:
                self._pending.pop(rid, None)
                try:
                    self._queue.remove(pending)  # timed out before it was written: it is not sent late
                except ValueError:
                    pass

    # ---- thread ----------------------------------------------------------------------------
    def _wake(self) -> None:
        try:
            os.write(self._wake_w, b"x")
        except (BlockingIOError, OSError):
            pass  # a wake byte is already pending

    @staticmethod
    def _now_us() -> int:
        return time.monotonic_ns() // 1000

    def _run(self) -> None:
        backoff = BACKOFF_MIN_S
        while not self._stop.is_set():
            try:
                port = serial.Serial(self.device, baudrate=115200, timeout=0, write_timeout=2.0)
            except (serial.SerialException, OSError) as exc:
                self.last_error = f"open: {exc}"
                log.warning("cannot open %s (%s); retry in %.1fs", self.device, exc, backoff)
                if self._stop.wait(backoff * random.uniform(0.8, 1.2)):
                    break
                backoff = min(BACKOFF_MAX_S, backoff * 2)
                continue
            backoff = BACKOFF_MIN_S
            self.port_open = True
            try:
                self._session_loop(port)
            except (serial.SerialException, OSError) as exc:
                self.last_error = f"port: {exc}"
                log.warning("serial port lost (%s)", exc)
            finally:
                self.port_open = False
                self._lib.lmh_usb_close(self._h)
                self._link_down("port closed")
                try:
                    port.close()
                except (serial.SerialException, OSError):
                    pass
            if self._stop.wait(BACKOFF_MIN_S):
                break

    def _session_loop(self, port: serial.Serial) -> None:
        fd = port.fileno()
        self._lib.lmh_usb_open(self._h, self._now_us())
        buf = (ctypes.c_uint8 * _EVENT_BUF)()
        while not self._stop.is_set():
            self._pump(port, buf)
            deadline = self._lib.lmh_usb_deadline_us(self._h)
            timeout: float | None = None
            if deadline != 0xFFFFFFFFFFFFFFFF:
                timeout = max(0.0, (deadline - self._now_us()) / 1e6)
            readable, _, _ = select.select([fd, self._wake_r], [], [], timeout)
            if self._wake_r in readable:
                try:
                    os.read(self._wake_r, 4096)
                except BlockingIOError:
                    pass
            if fd in readable:
                data = os.read(fd, _READ_CHUNK)
                if not data:
                    raise serial.SerialException("EOF on the serial device")
                self._feed(data)
            now = self._now_us()
            if self._lib.lmh_usb_deadline_us(self._h) <= now:
                self._lib.lmh_usb_tick(self._h, now)

    def _feed(self, data: bytes) -> None:
        arr = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        self._lib.lmh_usb_feed(self._h, arr, len(data), self._now_us())

    def _pump(self, port: serial.Serial, buf: Any) -> None:
        """Writes queued requests, drains bytes to the port, dispatches events."""
        for _ in range(64):
            progressed = self._send_queued()
            progressed |= self._drain_tx(port)
            progressed |= self._dispatch_events(buf)
            if not progressed:
                return

    def _send_queued(self) -> bool:
        with self._lock:
            pending = self._queue[0] if self._queue else None
        if pending is None:
            return False
        arr = (ctypes.c_uint8 * len(pending.payload)).from_buffer_copy(pending.payload)
        st = self._lib.lmh_usb_send(self._h, native.KIND_REQUEST, pending.gen, arr, len(pending.payload),
                                    self._now_us())
        if st == native.BUSY:
            return False  # credit/TX: retried on TX_READY or the next tick (local flow control)
        with self._lock:
            if self._queue and self._queue[0] is pending:
                self._queue.popleft()
        if st == native.OK:
            pending.sent = True
        else:
            exc: Exception = SessionChanged("session ended before the request was written") \
                if st == native.CONFLICT else SessionGone(f"request refused: LM status {st}")
            self._resolve(pending, exc=exc)
        return True

    def _drain_tx(self, port: serial.Serial) -> bool:
        out = (ctypes.c_uint8 * 8192)()
        n = self._lib.lmh_usb_take_tx(self._h, out, 8192)
        if n == 0:
            return False
        port.write(bytes(out[:n]))  # bounded by write_timeout; raises SerialTimeoutException
        return True

    def _dispatch_events(self, buf: Any) -> bool:
        ev = native.Event()
        got = False
        while True:
            r = self._lib.lmh_usb_poll_event(self._h, ctypes.byref(ev), buf, _EVENT_BUF, self._now_us())
            if r <= 0:
                return got
            got = True
            payload = bytes(buf[: ev.payload_len])
            if ev.kind == native.EVENT_SESSION_UP:
                self.gen = ev.gen
                self.connected = True
                log.info("USB session ACTIVE (generation %d)", ev.gen)
                self._notify_state(True, ev.gen)
            elif ev.kind == native.EVENT_SESSION_DOWN:
                self.connected = False
                log.info("USB session ended: %s", native.DOWN_REASONS.get(ev.aux, str(ev.aux)))
                self._fail_generation(ev.gen, f"USB session ended ({native.DOWN_REASONS.get(ev.aux, ev.aux)})")
                self._notify_state(False, ev.gen)
            elif ev.kind == native.EVENT_RECORD:
                self._on_record(ev.aux, ev.gen, payload)

    def _on_record(self, kind: int, gen: int, payload: bytes) -> None:
        if kind == native.KIND_RESPONSE:
            try:
                item = cbor_decode(payload)
                rid, status, op, result = item
                if not (isinstance(rid, bytes) and len(rid) == 16 and isinstance(status, int)):
                    raise WireError("BAD_FRAME", "response shape")
            except (WireError, ValueError, TypeError):
                log.warning("malformed RESPONSE dropped")
                return
            with self._lock:
                pending = self._pending.get(rid)
            if pending is None or pending.gen != gen:
                return  # unknown or answered for another session: never applied
            self._resolve(pending, value=ResponseResult(status, op, result, gen))
        elif kind == native.KIND_EVENT and self._on_event is not None:
            self._call_soon(self._on_event, payload, gen)
        else:
            log.debug("record kind %d ignored (no bridge attached)", kind)

    # ---- hand-over to the loop -------------------------------------------------------------
    def _call_soon(self, fn: Callable[..., None], *args: Any) -> None:
        try:
            self._loop.call_soon_threadsafe(fn, *args)
        except RuntimeError:
            pass  # loop closed during shutdown

    def _notify_state(self, connected: bool, gen: int) -> None:
        if self._on_state is not None:
            self._call_soon(self._on_state, connected, gen)

    def _resolve(self, pending: _Pending, value: ResponseResult | None = None, exc: Exception | None = None) -> None:
        def set_result() -> None:
            if pending.future.done():
                return
            if exc is not None:
                pending.future.set_exception(exc)
            else:
                assert value is not None
                pending.future.set_result(value)

        self._call_soon(set_result)

    def _fail_generation(self, gen: int, why: str) -> None:
        with self._lock:
            victims = [p for p in self._pending.values() if p.gen == gen]
        for p in victims:
            self._resolve(p, exc=SessionChanged(why, sent=p.sent))

    def _fail_all(self, exc: Exception | str) -> None:
        with self._lock:
            victims = list(self._pending.values())
            self._queue.clear()
        for p in victims:
            self._resolve(p, exc=SessionChanged(exc, sent=p.sent) if isinstance(exc, str) else exc)

    def _link_down(self, why: str) -> None:
        was = self.connected
        self.connected = False
        self._fail_all(f"serial link down ({why})")
        if was:
            self._notify_state(False, self.gen)
