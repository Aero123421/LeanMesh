"""Harness plumbing: real meshsim (C++ core, simulated radio) + real uvicorn host over a pty.

This proves the E2E rig, not mesh behaviour: the serial session and routing are not implemented
yet, so the host must report root_connected=false and meshsim only counts serial bytes.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest
import serial
from harness import HostProcess, MeshSim


@pytest.mark.e2e
def test_meshsim_nodes_boot_and_power_cycle(meshsim: Callable[..., MeshSim]) -> None:
    sim = meshsim("--nodes", "3", "--topology", "chain", "--clock", "virtual")
    assert sim.ready["nodes"] == 3
    assert sim.ok("node 1")["powered"] is True
    sim.ok("power-cut 1")
    stats = sim.ok("node 1")
    assert stats["powered"] is False and stats["epoch"] == 1
    sim.ok("boot 1")
    assert sim.ok("node 1")["powered"] is True
    assert sim.ok("run 1000")["now_us"] == 1_000_000
    assert sim.cmd("run nope")["ok"] is False


@pytest.mark.e2e
def test_host_and_meshsim_pty_are_wired(meshsim: Callable[..., MeshSim],
                                        host_process: Callable[..., HostProcess]) -> None:
    sim = meshsim("--nodes", "2", "--clock", "realtime", "--serial-pty")
    pty = sim.ready["serial_pty"]
    assert pty.startswith("/dev/pts/")
    host = host_process(serial=pty)
    with host.client() as c:
        status = c.get("/v1/status", headers=host.auth).json()
    assert status["root_connected"] is False  # no authenticated USB session exists yet

    with serial.Serial(pty, baudrate=115200, timeout=1) as port:
        port.write(b"\x00hello\x00")
        port.flush()
    deadline = time.monotonic() + 5
    while sim.ok("serial")["rx_bytes"] < 7:
        assert time.monotonic() < deadline, "meshsim did not see the bytes written to the pty"
        time.sleep(0.05)
