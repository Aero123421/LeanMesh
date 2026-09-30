"""Admission limits of the API: the 32 KiB request cap (docs/11 §3, an ASGI guard that rejects before
the body is buffered) and the request-rate buckets (docs/08 §8: per principal 20 req/s burst 40,
whole service 100 req/s burst 100, config/defaults.json scheduler.*).

The rate limit is about how fast requests are *accepted*; it is separate from the device's RF airtime
budget. An exact idempotent replay costs no RF, but it still costs a request slot here."""

from __future__ import annotations

import math
import os
import threading
import time
from collections.abc import Callable
from typing import Any

from .errors import ApiError

MAX_REQUEST_BYTES = 32 * 1024


class Bucket:
    """Token bucket in requests; `rate` per second up to `burst`. A rate of 0 disables it."""

    def __init__(self, rate: float, burst: int, now: float) -> None:
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.at = now

    def _refill(self, now: float) -> None:
        if now > self.at:
            self.tokens = min(float(self.burst), self.tokens + (now - self.at) * self.rate)
            self.at = now

    def wait_ms(self, now: float) -> int:
        """0 when one request may pass now, else the time until a token exists (never 0 then)."""
        if self.rate <= 0:
            return 0
        self._refill(now)
        # Refill is float arithmetic on monotonic seconds: after exactly retry_after_ms the bucket can
        # hold 0.9999999 of a token. A tolerance far below one request keeps the advertised wait honest.
        return 0 if self.tokens >= 1.0 - 1e-6 else max(1, math.ceil((1.0 - self.tokens) / self.rate * 1000))

    def take(self) -> None:
        if self.rate > 0:
            self.tokens -= 1.0


class RateLimiter:
    """Per-principal and global buckets. A request passes only when both have a token; it then takes
    one from each. A principal that is over its own rate is refused without touching the global bucket,
    so one noisy client cannot use up what the others need (fairness between clients). Principals are
    the configured token-file entries, so the table is bounded by construction."""

    def __init__(self, principal_rps: float, principal_burst: int, global_rps: float, global_burst: int,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self._lock = threading.Lock()  # sync dependencies run on the thread pool
        self._per = (principal_rps, principal_burst)
        self._global = Bucket(global_rps, global_burst, clock())
        self._principals: dict[str, Bucket] = {}
        self.refused = {"principal": 0, "global": 0}

    def admit(self, principal: str) -> None:
        with self._lock:
            now = self.clock()
            mine = self._principals.get(principal)
            if mine is None:
                mine = self._principals[principal] = Bucket(self._per[0], self._per[1], now)
            wait = mine.wait_ms(now)
            if wait:
                self.refused["principal"] += 1
                raise ApiError(429, "RATE_LIMITED", "principal request rate exceeded", retry_after_ms=wait,
                               scope="principal")
            wait = self._global.wait_ms(now)
            if wait:
                self.refused["global"] += 1
                raise ApiError(429, "RATE_LIMITED", "service request rate exceeded", retry_after_ms=wait,
                               scope="global")
            mine.take()
            self._global.take()


class BodyLimit:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_REQUEST_BYTES:
            await self._reject(send)
            return
        seen = 0
        rejected = False

        async def counted() -> Any:
            nonlocal seen, rejected
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > MAX_REQUEST_BYTES:
                    rejected = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def guarded_send(message: Any) -> None:
            if rejected:
                return
            await send(message)

        await self.app(scope, counted, guarded_send)
        if rejected:
            await self._reject(send)

    @staticmethod
    async def _reject(send: Any) -> None:
        body = (b'{"code":"PAYLOAD_TOO_LARGE","message":"request exceeds 32 KiB","request_id":"'
                + os.urandom(16).hex().encode() + b'"}')
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
