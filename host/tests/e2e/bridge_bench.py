"""Bench for the bridge E2E tests: a real meshsim (root with the S13 bridge on a pty, one joined member) and a
real uvicorn Host that drives it through the authenticated USB session. Nothing is mocked. The Host can be
killed (SIGKILL) and restarted on the same database; `crash_bridge_app` arms a kill at a named transaction.
Protocol bench only: a pty is not a USB cable and sim time is not timing evidence.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2 as httpx
from harness import HOST_DIR, HostProcess, MeshSim

PERMS = ["READ", "SEND", "APPROVE", "CONFIGURE"]
HERE = Path(__file__).resolve().parent


def wait_for(pred: Callable[[], Any], timeout_s: float, what: str, step: float = 0.1) -> Any:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = pred()
        if value:
            return value
        time.sleep(step)
    raise AssertionError(f"timeout ({timeout_s}s) waiting for {what}")


def utc_in(seconds: float) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()


def db_rows(db: Path, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


@dataclass
class Bench:
    sim: MeshSim
    workdir: Path
    kit: Path
    domain: str = ""
    node: str = ""
    root: str = ""
    host: HostProcess | None = None
    epoch: str = ""
    keys: int = 0
    procs: list[HostProcess] = field(default_factory=list)
    formation_s: float = 0.0

    # ---- the simulated network ------------------------------------------------------------------
    @staticmethod
    def build(meshsim: Callable[..., MeshSim], workdir: Path, *, seed: int, join: bool = True,
              mode: str = "preapproved", nodes: int = 2, flags: tuple[str, ...] = ()) -> Bench:
        sim = meshsim("--nodes", str(nodes), "--topology", "full", "--clock", "realtime", "--serial-pty",
                      "--serial-bridge", "--seed", str(seed), *flags)
        sim.ok("provision 0 1 root")
        kit = workdir / "kit.cbor"
        sim.ok(f"serial-kit {kit} 0")
        sim.ok("serial-pair 0 0")
        for i in range(1, nodes):
            sim.ok(f"provision {i} {i + 1} unjoined")
        for i in range(nodes):
            assert sim.ok(f"start {i}")["status"] == "OK"
        sim.ok(f"join-mode {mode}")
        time.sleep(1.0)  # identity/ledger loads run on the worker in real time
        b = Bench(sim, workdir, kit)
        if join:
            b.join_node(1, 0x60)
        return b

    @staticmethod
    def build_mesh(meshsim: Callable[..., MeshSim], workdir: Path, *, seed: int, nodes: int, topology: str = "full",
                   form_timeout_s: float = 120.0) -> Bench:
        """A mesh of provisioned members that forms by itself (parent search, link/end sessions, REGISTER/LEASE/READY):
        node 0 is the root with the bridge, 1..n-1 are members (relays, the last one a leaf), no static routes.
        `chain` puts them on a line (n-1 hops to the last one); `full` lets everyone hear everyone."""
        sim = meshsim("--nodes", str(nodes), "--topology", topology, "--clock", "realtime", "--serial-pty",
                      "--serial-bridge", "--mesh", "--leaf-last", "--seed", str(seed))
        sim.ok("provision 0 1 root")
        kit = workdir / "kit.cbor"
        sim.ok(f"serial-kit {kit} 0")
        sim.ok("serial-pair 0 0")
        for i in range(1, nodes):
            sim.ok(f"provision {i} {i + 1} {'leaf' if i == nodes - 1 else 'relay'}")
        for i in range(nodes):
            assert sim.ok(f"start {i}")["status"] == "OK"
        b = Bench(sim, workdir, kit)
        time.sleep(1.0)
        sim.ok(f"root-time all 1 {int(sim.ok('status')['now_us']) // 1000}")
        t0 = time.monotonic()
        wait_for(lambda: all(sim.ok(f"mesh {i}")["state"] == "ready" for i in range(1, nodes)), form_timeout_s,
                 "the mesh forms", step=0.5)
        b.formation_s = time.monotonic() - t0
        m = sim.ok(f"membership {nodes - 1}")
        b.domain, b.node = m["domain"], m["device"]
        return b

    def device(self, index: int) -> str:
        return str(self.sim.ok(f"membership {index}")["device"])

    def join_node(self, index: int, request_seed: int, generation: int = 1, revision: int = 1) -> None:
        sim = self.sim
        assert sim.ok(f"grant {index} {generation} {revision}")["status"] == "OK"
        time.sleep(0.5)
        assert sim.ok(f"join {index} {request_seed}")["status"] == "OK"
        self.await_active(index)

    def await_active(self, index: int, timeout_s: float = 25.0) -> None:
        m = wait_for(lambda: (r := self.sim.ok(f"membership {index}"))["state"] == 5 and r, timeout_s,
                     f"node {index} ACTIVE")
        if index == 1:
            self.domain, self.node = m["domain"], m["device"]

    def link_and_routes(self) -> None:
        sim = self.sim
        wait_for(lambda: sim.ok("link-status 1")["neighbors"] != [], 30, "link session after the join")
        # The ledger issues leases as "monotonic ms + 15 min" (root time = uptime until the time slice lands).
        sim.ok(f"root-time all 1 {int(sim.ok('status')['now_us']) // 1000}")
        assert sim.ok("route 0 1 1")["status"] == "OK"
        assert sim.ok("route 1 0 0")["status"] == "OK"

    # ---- the Host ----------------------------------------------------------------------------
    def start_host(self, crash: str | None = None, perms: list[str] | None = None,
                   env_extra: dict[str, str] | None = None) -> HostProcess:
        """Fresh uvicorn on the same directory/database. `crash` = "<stage>:<function>" arms a SIGKILL of
        the Host at that storage-transaction boundary (crash_bridge_app.py). `perms`: the token's permissions.
        `env_extra`: more environment (settings) for this Host."""
        from harness import native_build_dir  # noqa: PLC0415

        wd = self.workdir
        token = f"tok{len(self.procs)}{os.urandom(4).hex()}"
        HostProcess.write_tokens(wd / "tokens.json", token, perms or PERMS)
        sock = wd / "api.sock"
        sock.unlink(missing_ok=True)
        env = dict(os.environ, LEANMESH_DB=str(wd / "host.db"), LEANMESH_TOKENS=str(wd / "tokens.json"),
                   LEANMESH_SERIAL=self.sim.ready["serial_pty"], LEANMESH_USB_KIT=str(self.kit),
                   LEANMESH_NATIVE_BUILD=str(native_build_dir()),
                   PYTHONPATH=os.pathsep.join([str(HOST_DIR), str(HERE)]))
        env.update(env_extra or {})
        if crash:
            env["LEANMESH_BRIDGE_CRASH"] = crash
        proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "--factory", "crash_bridge_app:make",
                                 "--uds", str(sock), "--workers", "1", "--app-dir", str(HERE),
                                 "--log-level", "warning"], env=env)
        host = HostProcess(proc, sock, token, wd / "host.db", {"Authorization": f"Bearer {token}"})
        self.procs.append(host)
        self.host = host
        wait_for(lambda: sock.exists() and self._status(host) is not None, 20, "Host reachable")
        self.epoch = ""
        return host

    @staticmethod
    def _status(host: HostProcess) -> dict[str, Any] | None:
        try:
            with host.client() as c:
                r = c.get("/v1/status", headers=host.auth)
                return r.json() if r.status_code == 200 else None
        except httpx.TransportError:
            return None

    def status(self) -> dict[str, Any]:
        assert self.host is not None
        return self._status(self.host) or {}

    def await_root(self) -> None:
        """root_connected, the root's capabilities read and the member listed in the Host's node mirror."""
        wait_for(lambda: self.status().get("root_connected"), 25, "root_connected")
        wait_for(lambda: self.get("/v1/nodes", domain_id=self.domain).get("items"), 25, "node mirror")

    def kill_host(self) -> None:
        assert self.host is not None
        self.host.proc.kill()
        self.host.proc.wait()

    def close(self) -> None:
        for h in self.procs:
            h.stop()

    # ---- HTTP helpers -----------------------------------------------------------------------
    def get(self, path: str, **params: Any) -> Any:
        assert self.host is not None
        with self.host.client() as c:
            r = c.get(path, params=params, headers=self.host.auth)
        assert r.status_code == 200, (path, r.status_code, r.text)
        return r.json()

    def post(self, path: str, body: dict[str, Any], expect: int = 202, key: str | None = None) -> Any:
        assert self.host is not None
        self.keys += 1
        with self.host.client() as c:
            r = c.post(path, json=body, headers={**self.host.auth, "Idempotency-Key":
                                                 key or f"k{self.keys}-{os.urandom(3).hex()}"})
        assert r.status_code == expect, (path, r.status_code, r.text)
        return r.json()

    def open_epoch(self) -> str:
        r = self.post("/v1/epochs", {"request_id": os.urandom(16).hex()}, expect=201)
        self.epoch = r["id"]
        return self.epoch

    def send(self, payload_b64: str = "aGVsbG8=", *, delivery: str = "APPLIED", storage: str = "VOLATILE",
             deadline_s: float = 120.0, port: int = 100, deadline: dict[str, Any] | None = None,
             key: str | None = None) -> dict[str, Any]:
        epoch = self.epoch or self.open_epoch()
        return self.post("/v1/messages", key=key, body={
            "domain_id": self.domain, "client_epoch": epoch, "destination": {"kind": "node", "device_id": self.node},
            "app_port": port, "payload_b64": payload_b64, "delivery": delivery, "storage": storage,
            "queue_mode": "FIFO", "priority": "NORMAL",
            "deadline": deadline or {"mode": "utc", "expires_at": utc_in(deadline_s)}})

    def operation(self, op: str) -> dict[str, Any]:
        return self.get(f"/v1/operations/{op}")

    def events(self, after: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"domain_id": self.domain, "limit": 200}
        if after:
            params["after"] = after
        return self.get("/v1/events", **params)

    def kinds(self, op: str) -> set[str]:
        return {e["kind"] for e in self.operation(op)["evidence"]}
