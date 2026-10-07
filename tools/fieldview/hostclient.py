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
    """No answer from the Host (socket missing, connection refused, timeout). `maybe_sent` says whether the request may
    have reached the Host: False only for a failure that provably came before anything was sent (connect refused, no
    connection from the pool); a timeout or a broken connection after the request went out is True."""

    def __init__(self, message: str = "", *, maybe_sent: bool = False) -> None:
        super().__init__(message)
        self.maybe_sent = maybe_sent


class SendUnknown(HostUnreachable):
    """An idempotent POST whose answer never came, also on the same-key retries: the Host may or may not have admitted
    it. `key` and `body` are exactly what went out (a later replay of them is safe)."""

    def __init__(self, message: str, key: str, body: dict[str, Any]) -> None:
        super().__init__(message, maybe_sent=True)
        self.key, self.body = key, body


# a failure of these kinds happened before the request was written: the Host cannot have seen it
_BEFORE_SEND = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout, FileNotFoundError, ConnectionRefusedError)
# the retry of an unknown POST that meets one of these proves the Host never stored it: a replay of a stored operation
# is answered before any other check (api/routes.py submit_message -> ops.accept: lookup first, precheck after), so
# EXPIRED (deadline passed) / EPOCH_CLOSED can only come for a key it does not hold
_PROVEN_NOT_ADMITTED = {(400, "EXPIRED"), (410, "EPOCH_CLOSED")}
SEND_RETRIES = 2
SEND_RETRY_GAP_S = 0.5
RETRY_MAX_WAIT_S = 3.0


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
        (counted from the call, the queue before us and the wait for the lock included). A token is never taken after
        the budget ran out, also not when one happens to be free by then."""
        t0 = self.clock()
        try:
            if max_wait is None:
                await self._lock.acquire()
            else:
                async with asyncio.timeout(max(max_wait, 0.0)):
                    await self._lock.acquire()
        except TimeoutError:
            self.refused += 1
            return False
        try:
            waited = False
            while True:
                now = self.clock()
                self._refill(now)
                if max_wait is not None and now - t0 > max_wait:
                    self.refused += 1
                    return False
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
        finally:
            self._lock.release()


class HostClient:
    def __init__(self, socket_path: str, token: str, domain: str, *, rps: float = 14.0, burst: int = 24,
                 clock: Any = time.monotonic, post_timeout: float = 5.0) -> None:
        self.domain = domain
        self.bucket = RateBucket(rps, burst, clock)
        self.post_timeout = post_timeout   # a POST that takes longer is an unknown outcome (retried with its key)
        self._token = token
        self._http = httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=socket_path),
                                       base_url="http://localhost", timeout=10.0)
        self.requests = 0
        self.rate_limited = 0   # 429 answers of the Host

    async def aclose(self) -> None:
        await self._http.aclose()

    async def call(self, method: str, path: str, *, params: dict[str, Any] | None = None,
                   body: dict[str, Any] | Callable[[], dict[str, Any]] | None = None, timeout: float = 10.0,
                   max_wait: float | None = None, idem_key: str | None = None) -> Reply:
        """One request. A refusal is a Reply, not an exception; only "no answer at all" raises HostUnreachable (its
        `maybe_sent` tells whether the request may have gone out). `max_wait`: do not wait longer than this for a rate
        token (None = as long as it takes): a Reply of status 0 / code LOCAL_RATE_LIMIT then says the request was never
        made. A callable `body` is called after the token was taken, so a deadline in it starts counting when the request
        really goes out. A request with a body carries an Idempotency-Key (`idem_key`, else a new one)."""
        if not await self.bucket.acquire(max_wait):
            return Reply(0, {"code": "LOCAL_RATE_LIMIT", "message": "the laptop's own request budget is used up"})
        headers = {"Authorization": f"Bearer {self._token}"}
        if callable(body):
            body = body()
        if body is not None:
            headers["Idempotency-Key"] = idem_key or secrets.token_hex(12)
        self.requests += 1
        try:
            r = await self._http.request(method, path, params=params, json=body, headers=headers, timeout=timeout)
        except (httpx.TransportError, OSError) as exc:
            raise HostUnreachable(f"{type(exc).__name__}: {exc}"[:200], maybe_sent=not isinstance(exc, _BEFORE_SEND)) from exc
        try:
            doc = r.json() if r.content else {}
        except ValueError:
            doc = {"code": "BAD_JSON", "message": r.text[:120]}
        reply = Reply(r.status_code, doc if isinstance(doc, dict) else {"value": doc})
        if r.status_code == 429:
            self.rate_limited += 1
            self.bucket.penalize(reply.retry_after_ms or 1000)
        return reply

    async def post_idempotent(self, path: str, body: dict[str, Any] | Callable[[], dict[str, Any]], *,
                              max_wait: float | None = None, retries: int = SEND_RETRIES,
                              retry_gap_s: float = SEND_RETRY_GAP_S) -> Reply:
        """POST that may be repeated: the body is made once (after the first token) and keeps its Idempotency-Key. When
        the answer is lost (timeout, broken connection: HostUnreachable with maybe_sent) the SAME request is sent again
        up to `retries` times - the Host answers a replay with the stored result and never sends twice. Still no answer:
        SendUnknown carries the request. A failure that provably came before sending is raised as it is (HostUnreachable,
        maybe_sent False); a refusal of the first try is a Reply."""
        key = secrets.token_hex(12)
        made: dict[str, Any] | None = None

        def once() -> dict[str, Any]:
            nonlocal made
            made = body() if callable(body) else body
            return made

        try:
            return await self.call("POST", path, body=once, idem_key=key, max_wait=max_wait, timeout=self.post_timeout)
        except HostUnreachable as exc:
            if not exc.maybe_sent or made is None:
                raise
            last = str(exc)
        for _ in range(retries):
            await asyncio.sleep(retry_gap_s)
            try:  # the request is in doubt, not new: it gets its own small budget for a token
                r = await self.call("POST", path, body=made, idem_key=key, max_wait=RETRY_MAX_WAIT_S,
                                    timeout=self.post_timeout)
            except HostUnreachable as exc:
                last = str(exc)
                continue
            if r.ok or (r.status, r.code) in _PROVEN_NOT_ADMITTED:
                return r
            last = f"the retry answered {r.status} {r.code}".strip()  # 429 / 5xx / local budget: still not known
        assert made is not None
        raise SendUnknown(last, key, made)

    # ---- the endpoints fieldview uses -----------------------------------------------------------------------
    async def status(self) -> Reply:
        return await self.call("GET", "/v1/status")

    async def nodes(self) -> Reply:
        return await self.call("GET", "/v1/nodes", params={"domain_id": self.domain})

    async def open_epoch(self) -> Reply:
        return await self.post_idempotent("/v1/epochs", {"request_id": secrets.token_hex(16)})

    async def close_epoch(self, epoch: str) -> Reply:
        return await self.call("POST", f"/v1/epochs/{epoch}/close", body={})

    async def post_message(self, body: dict[str, Any] | Callable[[], dict[str, Any]],
                           max_wait: float | None = None) -> Reply:
        """POST /v1/messages (see post_idempotent): a Reply, HostUnreachable (never sent) or SendUnknown."""
        return await self.post_idempotent("/v1/messages", body, max_wait=max_wait)

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
