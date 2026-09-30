"""Shared fixtures. E2E fixtures start real processes and always clean them up."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from harness import HostProcess, MeshSim, meshsim_binary


@pytest.fixture
def meshsim() -> Iterator[Callable[..., MeshSim]]:
    """Factory: meshsim(*args) starts a simulator; all are closed after the test."""
    started: list[MeshSim] = []
    binary = meshsim_binary()

    def start(*args: str) -> MeshSim:
        sim = MeshSim.start(binary, *args)
        started.append(sim)
        return sim

    yield start
    for sim in started:
        sim.close()


@pytest.fixture
def host_process(tmp_path: Path) -> Iterator[Callable[..., HostProcess]]:
    """Factory: host_process(serial=None, permissions=[...]) starts uvicorn on a Unix socket."""
    started: list[HostProcess] = []

    def start(serial: str | None = None, permissions: list[str] | None = None,
              usb_kit: Path | None = None) -> HostProcess:
        workdir = tmp_path / f"host{len(started)}"
        workdir.mkdir()
        host = HostProcess.start(workdir, serial=serial, permissions=permissions, usb_kit=usb_kit)
        started.append(host)
        return host

    yield start
    for host in started:
        host.stop()
