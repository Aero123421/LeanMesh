"""USB serial (S10) end to end: the real Python Host code (native session helper + pyserial thread)
talks over a pty to the real root core running in meshsim. HELLO -> EDHOC purpose 3 -> ACTIVE,
credits and the reserved control lane, PING, D6 pairing, reset/replug, fake root / fake host.
Protocol bench only: a pty is not a USB cable, and sim time is not timing evidence.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from harness import HostProcess, MeshSim
from leanmesh_host.serial import SerialLink, SessionChanged, SessionGone

UNSUPPORTED = 2


def _root(meshsim: Callable[..., MeshSim], tmp_path: Path, seed: int = 7, *, pair: int | None = 0,
          kit_index: int = 0, name: str = "kit.cbor") -> tuple[MeshSim, Path]:
    sim = meshsim("--nodes", "1", "--clock", "realtime", "--serial-pty", "--seed", str(seed))
    sim.ok("provision 0 1 root")
    kit = tmp_path / name
    sim.ok(f"serial-kit {kit} {kit_index}")
    if pair is not None:
        sim.ok(f"serial-pair 0 {pair}")
    assert sim.ok("start 0")["status"] == "OK"
    return sim, kit


def _wait(pred: Callable[[], bool], timeout_s: float, what: str) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.05)
    raise AssertionError(f"timeout waiting for {what}")


class Bench:
    """A SerialLink (the Host's serial thread) driven from a private event loop."""

    def __init__(self, port: str, kit: Path) -> None:
        self.loop = asyncio.new_event_loop()
        self.states: list[tuple[bool, int]] = []
        self.link = SerialLink(port, kit.read_bytes(), self.loop,
                               on_state=lambda c, g: self.states.append((c, g)))

    def run(self, coro: object) -> object:
        return self.loop.run_until_complete(coro)  # type: ignore[arg-type]

    def pump(self, seconds: float) -> None:
        self.loop.run_until_complete(asyncio.sleep(seconds))

    def wait_connected(self, timeout_s: float = 15.0, gen_above: int = 0) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            self.pump(0.05)
            if self.link.connected and self.link.gen > gen_above:
                return
        raise AssertionError(f"not connected: {self.link.stats()} error={self.link.last_error}")

    def close(self) -> None:
        self.link.stop()
        self.loop.close()


@pytest.fixture
def bench_factory() -> Callable[[str, Path], Bench]:
    made: list[Bench] = []

    def make(port: str, kit: Path) -> Bench:
        b = Bench(port, kit)
        made.append(b)
        b.link.start()
        return b

    yield make  # type: ignore[misc]
    for b in made:
        b.close()


@pytest.mark.e2e
@pytest.mark.scenario("S09")
def test_host_process_reaches_active_and_status_root_connected(
        meshsim: Callable[..., MeshSim], host_process: Callable[..., HostProcess], tmp_path: Path) -> None:
    sim, kit = _root(meshsim, tmp_path)
    host = host_process(serial=sim.ready["serial_pty"], usb_kit=kit)
    with host.client() as c:
        # ready = DB + USB credential + migrations; root_connected only after the authenticated
        # session is ACTIVE (never guessed).
        _wait(lambda: c.get("/v1/status", headers=host.auth).json()["root_connected"], 20, "root_connected")
        status = c.get("/v1/status", headers=host.auth).json()
        assert status["root_connected"] is True and status["ready"] is True
    st = sim.ok("serial-status")
    assert st["active"] is True and st["paired"] is True and st["sessions"] == 1 and st["gen"] == 1
    assert st["rx_auth_fail"] == 0 and st["rx_credit_violation"] == 0
    # The Host stops: the port closes; a restarted Host reconnects with a NEW session (new id).
    old_sid = st["session_id"]
    host.stop()
    host2 = host_process(serial=sim.ready["serial_pty"], usb_kit=kit)
    with host2.client() as c:
        _wait(lambda: c.get("/v1/status", headers=host2.auth).json()["root_connected"], 20, "reconnect")
    st2 = sim.ok("serial-status")
    assert st2["active"] is True and st2["session_id"] != old_sid and st2["sessions"] == 2


@pytest.mark.e2e
@pytest.mark.scenario("S09")
def test_ping_credits_and_reserved_control_lane(
        meshsim: Callable[..., MeshSim], bench_factory: Callable[[str, Path], Bench], tmp_path: Path) -> None:
    sim, kit = _root(meshsim, tmp_path, seed=8)
    b = bench_factory(sim.ready["serial_pty"], kit)
    b.wait_connected()

    async def flood() -> list[object]:
        # 40 requests against a data-lane window of 16: the rest waits for CREDIT, none is lost, and
        # every answer comes back through the reserved control lane (window 2).
        return list(await asyncio.gather(*(b.link.request(1 + i % 15, None) for i in range(40))))

    results = b.run(flood())
    assert len(results) == 40 and all(r.status == UNSUPPORTED and r.result is None for r in results)  # type: ignore[attr-defined]
    st = b.link.stats()
    assert st["tx_credit_blocked"] > 0 and st["rx_credit_violation"] == 0 and st["rx_auth_fail"] == 0
    root = sim.ok("serial-status")
    assert root["unsupported_replies"] == 40 and root["rx_credit_violation"] == 0
    assert root["replies_dropped"] == 0
    # PING every 5 s, silence limit 15 s: after 11 s both sides still hold the same session.
    b.pump(11.0)
    assert b.link.connected and b.link.gen == 1
    assert b.link.stats()["pings_rx"] >= 2
    assert sim.ok("serial-status")["pings_rx"] >= 2


@pytest.mark.e2e
@pytest.mark.scenario("H03")
def test_reset_and_replug_old_session_is_never_applied(
        meshsim: Callable[..., MeshSim], bench_factory: Callable[[str, Path], Bench], tmp_path: Path) -> None:
    sim, kit = _root(meshsim, tmp_path, seed=9)
    b = bench_factory(sim.ready["serial_pty"], kit)
    b.wait_connected()
    old_gen = b.link.gen
    sid1 = sim.ok("serial-status")["session_id"]

    # Root MCU reset with requests in flight: every one ends as an answer of the OLD session or as
    # SessionChanged (unknown outcome, to reconcile). Nothing hangs, nothing is answered by the new one.
    async def in_flight() -> list[object]:
        tasks = [asyncio.ensure_future(b.link.request(1, None, timeout=12.0)) for _ in range(5)]
        await asyncio.sleep(0)
        sim.ok("serial-reset")
        return list(await asyncio.gather(*tasks, return_exceptions=True))

    outcomes = b.run(in_flight())
    for o in outcomes:
        assert isinstance(o, SessionChanged) or (hasattr(o, "gen") and o.gen == old_gen)  # type: ignore[attr-defined]
    b.wait_connected(timeout_s=20.0, gen_above=old_gen)
    st = sim.ok("serial-status")
    assert st["active"] and st["session_id"] != sid1 and st["sessions"] == 1  # fresh boot of the root
    # (That a request bound to the old generation is refused with CONFLICT is asserted natively in
    # tests/native/test_serial.cpp; here the new session must simply serve new requests.)
    res = b.run(b.link.request(1, None))
    assert res.gen == b.link.gen and res.status == UNSUPPORTED  # type: ignore[attr-defined]

    # USB replug: the root drops its session and says HELLO; the Host re-handshakes on its own.
    gen2 = b.link.gen
    sim.ok("serial-drop")
    b.wait_connected(timeout_s=20.0, gen_above=gen2)
    assert b.link.gen == gen2 + 1
    res = b.run(b.link.request(2, None))
    assert res.status == UNSUPPORTED  # type: ignore[attr-defined]


@pytest.mark.e2e
@pytest.mark.scenario("S09")
def test_fake_host_and_unpaired_host_are_refused(
        meshsim: Callable[..., MeshSim], bench_factory: Callable[[str, Path], Bench], tmp_path: Path) -> None:
    # (1) a valid fleet device that is not the paired Host; (2) a Host of another fleet.
    sim, kit_other_index = _root(meshsim, tmp_path, seed=10, pair=0, kit_index=1, name="k1.cbor")
    foreign = meshsim("--nodes", "1", "--clock", "realtime", "--serial-pty", "--seed", "999")
    foreign.ok("provision 0 1 root")
    foreign_kit = tmp_path / "foreign.cbor"
    foreign.ok(f"serial-kit {foreign_kit} 0")
    pty = sim.ready["serial_pty"]
    for kit in (kit_other_index, foreign_kit):
        b = bench_factory(pty, kit)
        b.pump(6.0)
        assert not b.link.connected
        b.close()
    root = sim.ok("serial-status")
    assert root["active"] is False and root["sessions"] == 0 and root["hs_rejected"] >= 1
    assert root["unsupported_replies"] == 0
    # Control: the paired Host connects to the same root.
    good = tmp_path / "good.cbor"
    sim.ok(f"serial-kit {good} 0")
    b = bench_factory(pty, good)
    b.wait_connected()


@pytest.mark.e2e
@pytest.mark.scenario("S09")
def test_fake_root_never_becomes_active(
        meshsim: Callable[..., MeshSim], bench_factory: Callable[[str, Path], Bench], tmp_path: Path) -> None:
    # A root of another fleet (different seed): the Host, holding only its own fleet's trust anchor,
    # never reaches ACTIVE. (The Host-side chain checks are proven against a scripted malicious root
    # in tests/native/test_serial.cpp.)
    sim, _ = _root(meshsim, tmp_path, seed=11)
    _, host_kit = _root(meshsim, tmp_path, seed=12, name="other.cbor")  # a kit of fleet 12
    b = bench_factory(sim.ready["serial_pty"], host_kit)
    b.pump(6.0)
    assert not b.link.connected
    assert b.link.stats()["sessions"] == 0
    with pytest.raises(SessionGone):
        b.run(b.link.request(1, None))
