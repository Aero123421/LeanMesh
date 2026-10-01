"""Loop-side coordination: commit-after notifications, subscriber cap, and the root bridge state.

`Hub.write(fn)` is the only way handlers and the bridge change the database: it runs fn in one
storage-thread transaction and only after COMMIT wakes long-poll/SSE waiters and the outbox
consumer. The Hub is used from the event loop; the serial thread hands results over via
`loop.call_soon_threadsafe` (bounded by the bridge, not here).
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from typing import TypeVar

from ..api.errors import ApiError
from ..settings import Settings
from ..storage import StorageThread

T = TypeVar("T")


class Hub:
    def __init__(self, storage: StorageThread, cfg: Settings) -> None:
        self.storage = storage
        self.cfg = cfg
        self.closing = False
        self.full_reported = False  # log the first SQLITE_FULL, not one line per rejected request
        self.expiry_ready = asyncio.Event()
        self.outbox_ready = asyncio.Event()  # the bridge waits here; set after commit
        self._active = 0
        self.version = 0  # incremented by every commit; readers wait for it to move
        self._waiters: set[asyncio.Future[None]] = set()
        # Set by the bridge when an authenticated root session is ACTIVE (never by guesswork).
        self.root_connected = False
        self.capabilities: frozenset[str] = frozenset()
        # The other facts of docs/18 §6 (S19): what the root reported as built / implemented / qualified.
        self.feature_facts: dict[str, frozenset[str]] = {}

    # ---- root state (bridge plug point) ------------------------------------------------------
    def set_root(self, connected: bool, enabled_capabilities: Iterable[str] = (),
                 facts: dict[str, frozenset[str]] | None = None) -> None:
        self.root_connected = connected
        self.capabilities = frozenset(enabled_capabilities) if connected else frozenset()
        self.feature_facts = dict(facts or {}) if connected else {}

    # ---- database access ---------------------------------------------------------------------
    async def read(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        return await self.storage.run(fn)

    async def write(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        result = await self.storage.run(fn)  # returns only after COMMIT
        self.bump()
        return result

    # ---- notifications -----------------------------------------------------------------------
    def bump(self) -> None:
        self.version += 1
        self.outbox_ready.set()
        self.expiry_ready.set()
        for waiter in self._waiters:
            if not waiter.done():
                waiter.set_result(None)

    def check_subscriber_capacity(self) -> None:
        if self._active >= self.cfg.max_subscribers:
            raise ApiError(429, "RATE_LIMITED", "too many concurrent event readers", retry_after_ms=1000)

    @contextmanager
    def subscription(self) -> Iterator[None]:
        """Bounded number of concurrent long-poll/SSE readers; the excess gets 429, not a queue."""
        if self._active >= self.cfg.max_subscribers:
            raise ApiError(429, "RATE_LIMITED", "too many concurrent event readers", retry_after_ms=1000)
        self._active += 1
        try:
            yield
        finally:
            self._active -= 1

    async def wait(self, since: int, timeout_s: float) -> None:
        """Returns when a commit happened after `since` (read hub.version BEFORE querying, so a
        commit between the query and this call is not missed), on shutdown, or on timeout."""
        if self.closing or self.version != since:
            return
        waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._waiters.add(waiter)
        try:
            await asyncio.wait_for(waiter, timeout_s)
        except TimeoutError:
            pass
        finally:
            self._waiters.discard(waiter)

    def close(self) -> None:
        self.closing = True
        self.bump()
