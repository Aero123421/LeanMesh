"""A small fake of the Host API for the fieldview tests: the endpoints fieldview uses, on a Unix socket, shaped like the
real Host (event kinds/fields of events/journal.py and bridge._store_message, the real MessageRequest validation, the
real rate limiter). It is a test double: what it answers is only as true as these modules."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from leanmesh_host.api.errors import ApiError
from leanmesh_host.api.limits import RateLimiter
from leanmesh_host.api.models import MessageRequest

TOKEN = "fake-token"
DOMAIN = "d0" * 16
ROOT = "99" * 32


def hex_id(n: int, width: int = 32) -> str:
    return f"{n:0{width}x}"


class FakeHost:
    def __init__(self, socket: Path) -> None:
        self.socket = socket
        self.journal = "j1" * 16
        self.nodes: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.floor = 0                      # events <= floor were purged: a reader behind it gets CURSOR_GAP
        self.acks: dict[str, int] = {}
        self.ack_calls = 0
        self.posts: list[dict[str, Any]] = []
        self.ops: dict[str, dict[str, Any]] = {}
        self.responders: dict[str, dict[str, Any]] = {}   # device -> {"mode": ..., "rtt": s, "observed": bool}
        self.get_ops = 0
        self.get_delay = 0.0                # seconds GET /v1/operations/{id} takes
        self.keys: dict[str, tuple[str, str]] = {}    # Idempotency-Key -> (request hash, operation id): a replay is stored
        self.replays = 0
        # failure injection on POST /v1/messages: {"mode": "after" | "before" | "blackhole", "count": n, "delay": s}.
        # "after": the Host admits the request and then the answer is lost (a read timeout on the client); "before": the
        # request is lost on the way and never admitted; "blackhole": admitted, and the answers to its replays are lost too.
        self.fault: dict[str, Any] | None = None
        self.root_connected = True
        self.limiter = RateLimiter(20.0, 40, 100.0, 100)
        self.requests = 0
        self.epochs = 0
        self.epoch_state: dict[str, str] = {}          # epoch id -> OPEN | CLOSED
        self.epoch_keys: dict[str, tuple[str, str]] = {}   # Idempotency-Key -> (request_id, epoch id)
        self.epoch_closes: list[str] = []              # every close call, in order
        self.max_open_epochs = 64                       # the Host's MAX_OPEN_EPOCHS_PER_PRINCIPAL
        self.epoch_fault = 0                            # epoch opens whose answer is lost after they were processed
        self._lock = threading.Lock()
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self.app = self._make_app()

    # ---- control from the test ------------------------------------------------------------------------------
    def add_node(self, device: str, membership: str = "ACTIVE", **extra: Any) -> dict[str, Any]:
        node = {"device_id": device, "domain_id": DOMAIN, "assignment_generation": "1", "membership_generation": "1",
                "membership": membership, "connectivity": "REACHABLE", "confirmed": True, **extra}
        self.nodes = [n for n in self.nodes if n["device_id"] != device] + [node]
        return node

    def append(self, kind: str, **fields: Any) -> int:
        with self._lock:
            seq = len(self.events) + self.floor + 1
            self.events.append({"cursor": f"{self.journal}:{seq}", "kind": kind, "domain_id": DOMAIN, **fields})
            return seq

    def emit_telemetry(self, device: str, payload: bytes, port: int = 210) -> int:
        return self.append("MESSAGE_RECEIVED", origin=device, message_id=os.urandom(16).hex(),
                           payload_b64=base64.b64encode(payload).decode(),
                           evidence={"kind": "ROOT_DELIVERED", "assurance": "END_VERIFIED", "observer": ROOT,
                                     "details": {"app_port": port, "recovered": False}})

    def purge(self, upto: int) -> None:
        """The Host deleted events up to sequence `upto` (a reader behind it is told, never skipped)."""
        with self._lock:
            drop = upto - self.floor
            self.events = self.events[drop:]
            self.floor = upto

    # ---- operations ------------------------------------------------------------------------------------------
    def _op_event(self, op: dict[str, Any]) -> None:
        self.append("OPERATION_UPDATE", message_id=op["message_id"], evidence={
            "kind": "HOST_COMMITTED", "assurance": "SELF_REPORTED",
            "details": {"operation_id": op["id"], "state": op["state"], "outcome": op["outcome"]}})

    def _evidence(self, kind: str, mono: int | None = None, assurance: str = "SELF_REPORTED") -> dict[str, Any]:
        e: dict[str, Any] = {"kind": kind, "assurance": assurance, "observer": ROOT}
        if mono is not None:
            e["observed_mono_ms"] = str(mono)
        return e

    def _start_op(self, body: dict[str, Any]) -> dict[str, Any]:
        n = len(self.ops) + 1
        op = {"id": hex_id(n), "message_id": hex_id(n + 10_000), "state": "HOST_COMMITTED", "outcome": "PENDING",
              "evidence": [], "device": body["destination"]["device_id"], "port": body["app_port"]}
        self.ops[op["id"]] = op
        self._op_event(op)
        resp = self.responders.get(op["device"], {"mode": "apply", "rtt": 0.05})
        loop = asyncio.get_running_loop()
        mode = resp["mode"]
        base = 1_000_000 + n * 1000
        observed = resp.get("observed", False)

        def step(state: str, outcome: str, *evidence: dict[str, Any], reason: str | None = None) -> None:
            op["state"], op["outcome"] = state, outcome
            op["evidence"].extend(evidence)
            if reason:
                op["reason"] = reason
            self._op_event(op)

        def ev(kind: str, ms: int) -> dict[str, Any]:
            return self._evidence(kind, base + ms if observed else None,
                                  "END_VERIFIED" if kind.startswith(("END", "APP")) else "SELF_REPORTED")

        rtt = float(resp.get("rtt", 0.05))
        if mode == "apply":
            loop.call_later(0.01, step, "WAITING_RECEIPT", "PENDING", ev("ROOT_ACCEPTED", 0), ev("ROOT_SENT", 5))
            if op["port"] == 212:  # a display: it has the frame first, draws it a little later
                loop.call_later(rtt / 2, step, "WAITING_RECEIPT", "PENDING", ev("END_RECEIVED", int(rtt * 500)))
            loop.call_later(rtt, step, "FINAL", "APPLIED", ev("APP_APPLIED", 5 + int(rtt * 1000)))
        elif mode == "silent":  # left the root, nothing came back: expires at the deadline
            loop.call_later(0.01, step, "WAITING_RECEIPT", "PENDING", ev("ROOT_ACCEPTED", 0), ev("ROOT_SENT", 5))
            loop.call_later(float(resp.get("after", 1.0)), step, "FINAL", "EXPIRED",
                            {"kind": "ROOT_OUTCOME", "assurance": "SELF_REPORTED", "details": {"outcome": "EXPIRED"}})
        elif mode == "unsent":  # the Host's own deadline passed before it could be sent
            expired = {"kind": "HOST_DEADLINE_EXPIRED", "assurance": "SELF_REPORTED",
                       "details": {"reason": "deadline passed before first transmission"}}
            loop.call_later(float(resp.get("after", 1.0)), lambda: step(
                "FINAL", "EXPIRED", expired, reason="deadline passed before first transmission"))
        elif mode == "app_reject":
            loop.call_later(rtt, step, "FINAL", "REJECTED", ev("ROOT_SENT", 5), ev("END_RECEIVED", 20),
                            ev("APP_REJECTED", 30))
        return op

    # ---- the app -----------------------------------------------------------------------------------------------
    def _make_app(self) -> FastAPI:
        app = FastAPI()

        def error(status: int, code: str, message: str, **extra: Any) -> JSONResponse:
            body: dict[str, Any] = {"code": code, "message": message, "request_id": hex_id(1)}
            for k in ("retry_after_ms", "details"):
                if k in extra:
                    body[k] = extra[k]
            return JSONResponse(body, status_code=status)

        @app.middleware("http")
        async def auth(request: Request, call_next: Any) -> Any:
            self.requests += 1
            header = request.headers.get("authorization", "")
            if header != f"Bearer {TOKEN}":
                return error(401, "UNAUTHENTICATED", "bearer token required")
            try:
                self.limiter.admit("fieldview-test")
            except ApiError as exc:
                return error(429, exc.code, exc.message, retry_after_ms=exc.retry_after_ms)
            return await call_next(request)

        @app.get("/v1/status")
        async def status() -> dict[str, Any]:
            return {"spec_version": "0.2", "ready": True, "root_connected": self.root_connected,
                    "journal_id": self.journal, "capabilities": {}}

        @app.get("/v1/nodes")
        async def nodes(domain_id: str) -> dict[str, Any]:
            return {"items": list(self.nodes)}

        @app.post("/v1/epochs", status_code=201)
        async def epoch(request: Request) -> Any:
            key, body = request.headers.get("idempotency-key", ""), await request.json()
            if key in self.epoch_keys:  # ops.open_epoch: the same key + request_id returns the same epoch
                want, stored = self.epoch_keys[key]
                if want != body["request_id"]:
                    return error(409, "CONFLICT", "Idempotency-Key reused with a different request")
                return {"id": stored, "state": self.epoch_state[stored]}
            if sum(1 for v in self.epoch_state.values() if v == "OPEN") >= self.max_open_epochs:
                return error(429, "NO_CAPACITY", "open_epochs", retry_after_ms=1000)
            self.epochs += 1
            eid = hex_id(0xE0 + self.epochs)
            self.epoch_state[eid] = "OPEN"
            self.epoch_keys[key] = (body["request_id"], eid)
            if self.epoch_fault > 0:
                self.epoch_fault -= 1
                await asyncio.sleep(2.0)
            return {"id": eid, "state": "OPEN"}

        @app.post("/v1/epochs/{epoch_id}/close")
        async def close(epoch_id: str) -> Any:
            if epoch_id not in self.epoch_state:
                return error(404, "NOT_FOUND", "epoch not found")
            self.epoch_closes.append(epoch_id)
            self.epoch_state[epoch_id] = "CLOSED"
            return {"id": epoch_id, "state": "CLOSED"}

        @app.post("/v1/messages", status_code=202)
        async def message(request: Request) -> Any:
            raw = await request.json()
            try:
                MessageRequest.model_validate(raw)  # the real admission rules (LATEST needs BEST_EFFORT, ...)
            except ValidationError as exc:
                return error(400, "INVALID_ARGUMENT", str(exc.errors()[0]["msg"]))
            key = request.headers.get("idempotency-key", "")
            digest = json.dumps(raw, sort_keys=True)
            fault = self.fault if self.fault and self.fault.get("count", 0) > 0 else None
            if fault is not None:
                fault["count"] -= 1
                if fault["mode"] == "before":
                    await asyncio.sleep(float(fault.get("delay", 2.0)))
                    return error(503, "UNAVAILABLE", "lost on the way")
            if key in self.keys:  # an exact replay returns the stored operation (api/routes.py: lookup before checks)
                stored_hash, stored_op = self.keys[key]
                if stored_hash != digest:
                    return error(409, "CONFLICT", "Idempotency-Key reused with a different request")
                self.replays += 1
                op = self.ops[stored_op]
                if fault is not None and fault["mode"] == "blackhole":  # the answer is lost again
                    await asyncio.sleep(float(fault.get("delay", 2.0)))
                return {k: op[k] for k in ("id", "state", "outcome", "evidence")}
            if self.epoch_state.get(raw["client_epoch"]) != "OPEN":
                return error(410, "EPOCH_CLOSED", "client epoch is closed; open a new epoch")
            self.posts.append(raw)
            resp = self.responders.get(raw["destination"]["device_id"], {})
            if resp.get("mode") == "refuse":
                return error(resp.get("status", 507), resp.get("code", "NO_CAPACITY"), "refused")
            op = self._start_op(raw)
            op["epoch"] = raw["client_epoch"]
            self.keys[key] = (digest, op["id"])
            if fault is not None and fault["mode"] in ("after", "blackhole"):
                await asyncio.sleep(float(fault.get("delay", 2.0)))
            return {k: op[k] for k in ("id", "state", "outcome", "evidence")}

        @app.get("/v1/operations/{op_id}")
        async def operation(op_id: str) -> Any:
            self.get_ops += 1
            if self.get_delay:
                await asyncio.sleep(self.get_delay)
            op = self.ops.get(op_id)
            if op is None:
                return error(404, "NOT_FOUND", "operation not found")
            out = {k: op[k] for k in ("id", "state", "outcome", "evidence")}
            if "reason" in op:
                out["reason"] = op["reason"]
            return out

        @app.get("/v1/events")
        async def events(domain_id: str, after: str | None = None, limit: int = 100, wait_ms: int = 0) -> Any:
            deadline = time.monotonic() + wait_ms / 1000
            start = 0
            if after is not None:
                journal, _, seq = after.partition(":")
                start = int(seq)
                if journal != self.journal or start < self.floor or start > self.floor + len(self.events):
                    return error(410, "CURSOR_GAP", "cursor is not readable", details={
                        "journal_id": self.journal, "oldest_cursor": f"{self.journal}:{self.floor}",
                        "latest_cursor": f"{self.journal}:{self.floor + len(self.events)}"})
            while True:
                with self._lock:
                    page = self.events[max(0, start - self.floor):][:limit]
                if page or time.monotonic() >= deadline:
                    break
                await asyncio.sleep(0.02)
            last = int(page[-1]["cursor"].rpartition(":")[2]) if page else start
            return {"events": page, "next_cursor": f"{self.journal}:{last}",
                    "oldest_cursor": f"{self.journal}:{self.floor}"}

        @app.post("/v1/consumers/{name}/ack")
        async def ack(name: str, request: Request) -> Any:
            body = await request.json()
            self.ack_calls += 1
            seq = int(body["sequence"])
            if body["journal_id"] != self.journal:
                return error(410, "CURSOR_GAP", "other journal", details={"journal_id": self.journal})
            if seq > self.floor + len(self.events):
                return error(409, "CONFLICT", "acknowledgement is ahead of the journal")
            self.acks[name] = max(self.acks.get(name, 0), seq)
            return {"events": [], "next_cursor": f"{self.journal}:{self.acks[name]}",
                    "oldest_cursor": f"{self.journal}:{self.floor}"}

        return app

    # ---- lifecycle -------------------------------------------------------------------------------------------
    def start(self) -> None:
        cfg = uvicorn.Config(self.app, uds=str(self.socket), log_level="error", access_log=False)
        self._server = uvicorn.Server(cfg)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        end = time.monotonic() + 10
        while time.monotonic() < end and not (self._server.started and self.socket.exists()):
            time.sleep(0.02)
        assert self._server.started, "the fake Host did not start"

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(5)
