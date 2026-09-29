"""E2E harness: real meshsim process (real C++ core on simulated radio) + real uvicorn host on a
Unix socket. Nothing here is mocked; tests fail (never skip) when a build output is missing.

    sim = MeshSim.start(bin, "--nodes", "3", "--serial-pty", "--clock", "realtime")
    sim.cmd("node 1")            -> dict (one JSON reply per command)
    host = HostProcess.start(tmp_path, serial=sim.ready["serial_pty"])
    host.client().get("/v1/status", headers=host.auth)
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import select
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx2 as httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
HOST_DIR = REPO_ROOT / "host"


def native_build_dir() -> Path:
    return Path(os.environ.get("LEANMESH_NATIVE_BUILD", Path.home() / ".cache/leanmesh/native"))


def meshsim_binary() -> Path:
    path = native_build_dir() / "meshsim"
    if not path.is_file():
        raise FileNotFoundError(
            f"{path} not found: build the native tree first "
            "(cmake -S . -B ~/.cache/leanmesh/native -G Ninja && ninja -C ~/.cache/leanmesh/native)"
        )
    return path


class MeshSimError(RuntimeError):
    pass


@dataclass
class MeshSim:
    proc: subprocess.Popen[str]
    ready: dict[str, Any]

    @staticmethod
    def start(binary: Path, *args: str, timeout_s: float = 10.0) -> MeshSim:
        proc = subprocess.Popen(
            [str(binary), *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        sim = MeshSim(proc, {})
        sim.ready = sim._read_line(timeout_s)
        if sim.ready.get("event") != "ready":
            sim.close()
            raise MeshSimError(f"unexpected first line: {sim.ready}")
        return sim

    def cmd(self, line: str, timeout_s: float = 30.0) -> dict[str, Any]:
        assert self.proc.stdin is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        return self._read_line(timeout_s)

    def ok(self, line: str, timeout_s: float = 30.0) -> dict[str, Any]:
        reply = self.cmd(line, timeout_s)
        if not reply.get("ok"):
            raise MeshSimError(f"{line!r} -> {reply}")
        return reply

    def _read_line(self, timeout_s: float) -> dict[str, Any]:
        assert self.proc.stdout is not None
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout_s)
        if not ready:
            raise MeshSimError(f"meshsim did not answer within {timeout_s}s")
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise MeshSimError(f"meshsim exited ({self.proc.poll()}): {err}")
        return json.loads(line)

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.cmd("quit", timeout_s=5)
            except (MeshSimError, BrokenPipeError, OSError):
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if stream is not None:
                stream.close()


@dataclass
class HostProcess:
    proc: subprocess.Popen[bytes]
    socket: Path
    token: str
    db: Path
    auth: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def write_tokens(path: Path, token: str, permissions: list[str]) -> None:
        doc = {"principals": [{"id": "e2e", "permissions": permissions,
                               "token_sha256": hashlib.sha256(token.encode()).hexdigest()}]}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f)

    @staticmethod
    def start(workdir: Path, serial: str | None = None, timeout_s: float = 20.0,
              permissions: list[str] | None = None, usb_kit: Path | None = None) -> HostProcess:
        token = secrets.token_hex(16)
        tokens = workdir / "tokens.json"
        HostProcess.write_tokens(tokens, token, permissions or ["READ"])
        sock = workdir / "api.sock"
        db = workdir / "host.db"
        env = dict(os.environ, LEANMESH_DB=str(db), LEANMESH_TOKENS=str(tokens))
        if serial:
            env["LEANMESH_SERIAL"] = serial
        if usb_kit:
            env["LEANMESH_USB_KIT"] = str(usb_kit)
            env.setdefault("LEANMESH_NATIVE_BUILD", str(native_build_dir()))
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "leanmesh_host.main:app", "--uds", str(sock),
             "--workers", "1", "--app-dir", str(HOST_DIR), "--log-level", "warning"],
            env=env,
        )
        host = HostProcess(proc, sock, token, db, {"Authorization": f"Bearer {token}"})
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"host exited with {proc.returncode}")
            if sock.exists():
                try:
                    with host.client() as c:
                        if c.get("/v1/status", headers=host.auth).status_code == 200:
                            return host
                except httpx.TransportError:
                    pass
            time.sleep(0.05)
        host.stop()
        raise RuntimeError("host did not become reachable")

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.HTTPTransport(uds=str(self.socket)),
                            base_url="http://localhost", timeout=10.0)

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
