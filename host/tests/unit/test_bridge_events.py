"""FIX2-D9: EVENT_ACK is cumulative at the root, so the Host may only acknowledge what it finished.
Protocol logic of the bridge against a scripted link (no process, no radio)."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any

from leanmesh_host.bridge.bridge import EV_FAULT, M_EVENT_ACK, Bridge, RootInfo
from leanmesh_host.wire import cbor_encode

BOOT = 7


class _Link:
    gen = 1
    connected = True

    def __init__(self) -> None:
        self.acks: list[int] = []

    async def request(self, method: int, params: Any) -> Any:
        assert method == M_EVENT_ACK and params[0] == BOOT
        self.acks.append(params[1])
        return SimpleNamespace(status=0, result=None, operation_id=None)


def _bridge() -> tuple[Bridge, _Link]:
    b = Bridge(SimpleNamespace(outbox_ready=threading.Event()), SimpleNamespace())  # type: ignore[arg-type]
    link = _Link()
    b.link = link  # type: ignore[assignment]
    b.info = RootInfo(b"d" * 16, b"r" * 32, 1, BOOT, frozenset(), 1, None)
    b._events = asyncio.Queue(2)
    return b, link


def _event(seq: int) -> bytes:
    return cbor_encode([BOOT, seq, EV_FAULT, b""])


def test_event_ack_never_covers_an_event_dropped_on_overflow() -> None:
    async def run() -> list[int]:
        b, link = _bridge()
        for seq in (1, 2, 3):  # the queue holds two: seq 3 is dropped
            b.on_event(_event(seq), 1)
        assert b._events.qsize() == 2
        await b._handle_event((await b._events.get())[0])
        await b._handle_event((await b._events.get())[0])
        b.on_event(_event(4), 1)
        await b._handle_event((await b._events.get())[0])  # 4 is finished, 3 is not: ACK stays at 2
        assert link.acks == [1, 2]
        b.on_event(_event(3), 1)  # the root sends the dropped one again
        await b._handle_event((await b._events.get())[0])
        return link.acks

    assert asyncio.run(run()) == [1, 2, 4]


def test_event_ack_never_covers_an_event_whose_handling_failed() -> None:
    async def run() -> list[int]:
        b, link = _bridge()
        b.on_event(_event(1), 1)
        b.on_event(_event(2), 1)
        await b._events.get()  # handling of 1 raised or was interrupted: nothing is acknowledged for it
        await b._handle_event((await b._events.get())[0])
        return link.acks

    assert asyncio.run(run()) == []


def test_fix11_m15_per_boot_operation_maps_are_bounded() -> None:
    from collections import OrderedDict  # noqa: PLC0415

    from leanmesh_host.bridge import bridge as mod  # noqa: PLC0415

    table: OrderedDict[int, int] = OrderedDict()
    for n in range(mod.MAX_OP_MAP * 3):
        mod._remember(table, n, n)
    assert len(table) == mod.MAX_OP_MAP and next(iter(table)) == mod.MAX_OP_MAP * 2  # the newest are kept
    mod._remember(table, mod.MAX_OP_MAP * 2, 0)  # re-adding an old key refreshes it, does not grow the table
    assert len(table) == mod.MAX_OP_MAP
