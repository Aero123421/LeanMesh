"""The Host API over its Unix socket with a bearer token (the same conventions as tools/hil/hil.py), and the request-rate
guard: the Host admits 20 req/s (burst 40) per principal across ALL endpoints, GETs included (api/limits.py), so every
request here takes a token from a bucket that stays below that."""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

try:  # the Host venv ships httpx2 (the tests use it too); a plain httpx works the same
    import httpx2 as httpx
except ImportError:  # pragma: no cover
    import httpx  # type: ignore[no-redef]


class HostUnreachable(Exception):
    """No answer from the Host (socket missing, connection refused, timeout)."""


@dataclass(frozen=True)
class Reply:
    status: int
    body: dict[str, Any]

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def code(self) -> str:
        return str(self.body.get("code", ""))

    @property
    def retry_after_ms(self) -> int | None:
        v = self.body.get("retry_after_ms")
        return v if isinstance(v, int) else None


class RateBucket:
    """Token bucket (requests). Fair (FIFO), and `penalize` stops it for what a 429 asked."""

    def __init__(self, rate: float, burst: int, clock: Any = time.monotonic) -> None:
        self.rate, self.burst, self.clock = rate, float(burst), clock
        self.tokens, self.at, self.blocked_until = float(burst), clock(), 0.0
        self.throttled = 0   # acquires that had to wait
        self.refused = 0     # acquires that gave up (max_wait)
        self._lock = asyncio.Lock()

    def _refill(self, now: float) -> None:
        if now > self.at:
            self.tokens = min(self.burst, self.tokens + (now - self.at) * self.rate)
            self.at = now

    def penalize(self, ms: int) -> None:
        self.tokens = 0.0
        self.blocked_until = max(self.blocked_until, self.clock() + ms / 1000)

    async def acquire(self, max_wait: float | None = None) -> bool:
        """True when a token was taken; False when getting one would take longer than `max_wait` seconds in all
        (counted from the call, the queue before us included)."""
        t0 = self.clock()
        async with self._lock:
            waited = False
            while True:
                now = self.clock()
                self._refill(now)
                if self.blocked_until > now:
                    wait = self.blocked_until - now
                elif self.tokens >= 1.0 - 1e-6:
                    self.tokens -= 1.0
                    if waited:
                        self.throttled += 1
                    return True
                else:
                    wait = (1.0 - self.tokens) / self.rate
                if max_wait is not None and now - t0 + wait > max_wait:
                    self.refused += 1
                    return False
                waited = True
                await asyncio.sleep(wait)


class HostClient:
    def __init__(self, socket_path: str, token: str, domain: str, *, rps: float = 14.0, burst: int = 24,
                 clock: Any = time.monotonic) -> None:
        self.domain = domain
        self.bucket = RateBucket(rps, burst, clock)
        self._token = token
        self._http = httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=socket_path),
                                       base_url="http://localhost", timeout=10.0)
        self.requests = 0
        self.rate_limited = 0   # 429 answers of the Host

    async def aclose(self) -> None:
        await self._http.aclose()

    async def call(self, method: str, path: str, *, params: dict[str, Any] | None = None,
                   body: dict[str, Any] | Callable[[], dict[str, Any]] | None = None, timeout: float = 10.0,
                   max_wait: float | None = None) -> Reply:
        """One request. A refusal is a Reply, not an exception; only "no answer at all" raises HostUnreachable.
        `max_wait`: do not wait longer than this for a rate token (None = as long as it takes): a Reply of status 0 /
        code LOCAL_RATE_LIMIT then says the request was never made. A callable `body` is called after the token was taken,
        so a deadline in it starts counting when the request really goes out."""
        if not await self.bucket.acquire(max_wait):
            return Reply(0, {"code": "LOCAL_RATE_LIMIT", "message": "the laptop's own request budget is used up"})
        headers = {"Authorization": f"Bearer {self._token}"}
        if callable(body):
            body = body()
        if body is not None:
            headers["Idempotency-Key"] = secrets.token_hex(12)
        self.requests += 1
        try:
            r = await self._http.request(method, path, params=params, json=body, headers=headers, timeout=timeout)
        except (httpx.TransportError, OSError) as exc:
            raise HostUnreachable(f"{type(exc).__name__}: {exc}"[:200]) from exc
        try:
            doc = r.json() if r.content else {}
        except ValueError:
            doc = {"code": "BAD_JSON", "message": r.text[:120]}
        reply = Reply(r.status_code, doc if isinstance(doc, dict) else {"value": doc})
        if r.status_code == 429:
            self.rate_limited += 1
            self.bucket.penalize(reply.retry_after_ms or 1000)
        return reply

    # ---- the endpoints fieldview uses -----------------------------------------------------------------------
    async def status(self) -> Reply:
        return await self.call("GET", "/v1/status")

    async def nodes(self) -> Reply:
        return await self.call("GET", "/v1/nodes", params={"domain_id": self.domain})

    async def open_epoch(self) -> Reply:
        return await self.call("POST", "/v1/epochs", body={"request_id": secrets.token_hex(16)})

    async def close_epoch(self, epoch: str) -> Reply:
        return await self.call("POST", f"/v1/epochs/{epoch}/close", body={})

    async def post_message(self, body: dict[str, Any] | Callable[[], dict[str, Any]],
                           max_wait: float | None = None) -> Reply:
        return await self.call("POST", "/v1/messages", body=body, max_wait=max_wait)

    async def operation(self, op_id: str) -> Reply:
        return await self.call("GET", f"/v1/operations/{op_id}")

    async def events(self, after: str | None, limit: int = 200, wait_ms: int = 0) -> Reply:
        params: dict[str, Any] = {"domain_id": self.domain, "limit": limit, "wait_ms": wait_ms}
        if after:
            params["after"] = after
        return await self.call("GET", "/v1/events", params=params, timeout=10.0 + wait_ms / 1000)

    async def ack(self, consumer: str, journal_id: str, sequence: int) -> Reply:
        return await self.call("POST", f"/v1/consumers/{consumer}/ack", body={
            "domain_id": self.domain, "journal_id": journal_id, "sequence": str(sequence)})
