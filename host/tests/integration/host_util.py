"""Helpers for the Host integration tests: OpenAPI response validation, in-process app with a real
SQLite file, and a real uvicorn process that can be killed and restarted on the same database."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx2 as httpx
from fastapi.testclient import TestClient
from leanmesh_host.db import mirror
from leanmesh_host.main import create_app
from leanmesh_host.settings import Settings

REPO = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CONTRACT = json.loads((REPO / "api" / "openapi.json").read_text())
DOMAIN = "d0" * 16
NODE = "aa" * 32
ALL_PERMS = ["READ", "SEND", "APPROVE", "REVOKE", "TRANSFER", "CONFIGURE", "UPDATE_FIRMWARE"]


# ---- minimal JSON-schema validator for the subset api/openapi.json uses ------------------------
def _resolve(ref: str) -> Any:
    node: Any = CONTRACT
    for part in ref.removeprefix("#/").split("/"):
        node = node[part]
    return node


def violations(schema: dict[str, Any], value: Any, path: str = "$") -> list[str]:
    if "$ref" in schema:
        return violations(_resolve(schema["$ref"]), value, path)
    out: list[str] = []
    if "oneOf" in schema:
        ok = [s for s in schema["oneOf"] if not violations(s, value, path)]
        return [] if len(ok) == 1 else [f"{path}: matches {len(ok)} of oneOf"]
    if "const" in schema and value != schema["const"]:
        out.append(f"{path}: {value!r} != const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        out.append(f"{path}: {value!r} not in enum")
    kinds = schema.get("type")
    if kinds is not None:
        names = kinds if isinstance(kinds, list) else [kinds]
        checks = {"string": lambda v: isinstance(v, str), "object": lambda v: isinstance(v, dict),
                  "array": lambda v: isinstance(v, list), "null": lambda v: v is None,
                  "boolean": lambda v: isinstance(v, bool),
                  "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
                  "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)}
        if not any(checks[n](value) for n in names):
            return [f"{path}: {value!r} is not {names}"]
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            out.append(f"{path}: {value!r} does not match {schema['pattern']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            out.append(f"{path}: longer than {schema['maxLength']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            out.append(f"{path}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            out.append(f"{path}: above maximum")
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            out.append(f"{path}: more than {schema['maxItems']} items")
        for i, item in enumerate(value):
            out += violations(schema.get("items", {}), item, f"{path}[{i}]")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        out += [f"{path}: missing {k}" for k in schema.get("required", []) if k not in value]
        if schema.get("additionalProperties") is False:
            out += [f"{path}: unexpected {k}" for k in value if k not in props]
        for k, v in value.items():
            if k in props:
                out += violations(props[k], v, f"{path}.{k}")
    return out


def check(operation_id: str, response: httpx.Response | Any) -> None:
    """The response body must match the OpenAPI schema declared for its status code."""
    for methods in CONTRACT["paths"].values():
        for op in methods.values():
            if op.get("operationId") != operation_id:
                continue
            declared = op["responses"].get(str(response.status_code))
            assert declared is not None, f"{operation_id}: status {response.status_code} undeclared"
            schema = declared.get("content", {}).get("application/json", {}).get("schema")
            if schema is not None:
                bad = violations(schema, response.json())
                assert not bad, f"{operation_id} {response.status_code}: {bad} in {response.json()}"
            return
    raise AssertionError(f"unknown operationId {operation_id}")


# ---- in-process host -----------------------------------------------------------------------------
def write_tokens(path: Path, principals: dict[str, list[str]]) -> None:
    doc = {"principals": [{"id": name, "permissions": perms,
                           "token_sha256": hashlib.sha256(f"tok-{name}".encode()).hexdigest()}
                          for name, perms in principals.items()]}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)


def auth(name: str) -> dict[str, str]:
    return {"Authorization": f"Bearer tok-{name}"}


def make_settings(tmp: Path, principals: dict[str, list[str]] | None = None, **overrides: Any) -> Settings:
    write_tokens(tmp / "tokens.json", principals or {"alice": ALL_PERMS, "bob": ALL_PERMS,
                                                     "reader": ["READ"]})
    # The request-rate limit (test_host_limits.py) is off unless a test asks for it: most tests send
    # hundreds of requests in a burst to reach a capacity limit.
    overrides = {"principal_rps": 0.0, "global_rps": 0.0, **overrides}
    return Settings(db_path=tmp / "host.db", tokens_path=tmp / "tokens.json",
                    schema_path=REPO / "db" / "schema.sql", **overrides)


class Host:
    """TestClient + the pieces tests need to play the bridge (hub, direct DB reads)."""

    def __init__(self, client: TestClient) -> None:
        self.http = client
        self.hub = client.app.state.hub  # type: ignore[attr-defined]

    def db(self, fn: Callable[[sqlite3.Connection], Any]) -> Any:
        """Runs fn as one transaction on the storage thread (what the bridge would do)."""
        return self.hub.storage.submit(fn).result(timeout=10)

    def epoch(self, who: str = "alice", key: str | None = None) -> str:
        key = key or os.urandom(4).hex()
        r = self.http.post("/v1/epochs", json={"request_id": os.urandom(16).hex()},
                           headers={**auth(who), "Idempotency-Key": key})
        check("open_epoch", r)
        assert r.status_code == 201, r.text
        return str(r.json()["id"])

    def post(self, path: str, body: dict[str, Any], key: str, who: str = "alice") -> httpx.Response:
        return self.http.post(path, json=body, headers={**auth(who), "Idempotency-Key": key})

    def get(self, path: str, who: str = "alice", **params: Any) -> httpx.Response:
        return self.http.get(path, params=params, headers=auth(who))


@contextmanager
def running(settings: Settings, domain: bool = True, node: bool = True, fault_hook: Any = None) -> Iterator[Host]:
    with TestClient(create_app(settings, fault_hook)) as client:
        host = Host(client)
        if domain:
            host.db(lambda c: mirror.register_domain(c, bytes.fromhex(DOMAIN), bytes(32)))
        if domain and node:
            host.db(lambda c: mirror.upsert_node(
                c, bytes.fromhex(DOMAIN), bytes.fromhex(NODE), assignment_generation=1,
                membership_generation=1, membership="ACTIVE", connectivity="REACHABLE", confirmed=True,
                extras={"root_depth": 2, "parent_rssi_dbm": None}))
        yield host


def message(epoch: str, **over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "domain_id": DOMAIN, "client_epoch": epoch,
        "destination": {"kind": "node", "device_id": NODE}, "app_port": 7,
        "payload_b64": "aGVsbG8=", "delivery": "RECEIVED", "storage": "DURABLE",
        "queue_mode": "FIFO", "priority": "NORMAL", "deadline": {"mode": "none"}}
    body.update(over)
    return body


def rows(db: Path, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    """Read-only look into the database file from the test process (WAL readers never block)."""
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


# ---- real process --------------------------------------------------------------------------------
class HostProc:
    """uvicorn with crash_app on a Unix socket; restart() reuses the same directory/database."""

    def __init__(self, workdir: Path, crash: str | None = None, **limits: str) -> None:
        self.workdir = workdir
        self.sock = workdir / "api.sock"
        self.db = workdir / "host.db"
        write_tokens(workdir / "tokens.json", {"alice": ALL_PERMS, "bob": ALL_PERMS})
        self.env = dict(os.environ, LEANMESH_DB=str(self.db), LEANMESH_TOKENS=str(workdir / "tokens.json"),
                        PYTHONPATH=str(REPO / "host"), LEANMESH_PRINCIPAL_RPS="0", LEANMESH_GLOBAL_RPS="0", **limits)
        if crash:
            self.env["LEANMESH_CRASH"] = crash
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self, timeout_s: float = 20.0) -> HostProc:
        self.sock.unlink(missing_ok=True)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "--factory", "crash_app:make", "--uds", str(self.sock),
             "--workers", "1", "--app-dir", str(HERE), "--log-level", "warning"], env=self.env)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            assert self.proc.poll() is None, f"host exited with {self.proc.returncode}"
            if self.sock.exists():
                try:
                    with self.client() as c:
                        if c.get("/v1/status", headers=auth("alice")).status_code == 200:
                            return self
                except httpx.TransportError:
                    pass
            time.sleep(0.05)
        raise AssertionError("host did not become reachable")

    def client(self, timeout: float = 10.0) -> httpx.Client:
        return httpx.Client(transport=httpx.HTTPTransport(uds=str(self.sock)),
                            base_url="http://localhost", timeout=timeout)

    def wait_dead(self, timeout_s: float = 10.0) -> int:
        assert self.proc is not None
        return self.proc.wait(timeout=timeout_s)

    def stop(self, sig_kill: bool = False) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill() if sig_kill else self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def signed_object(ctype: int, data: list[Any], domain: str = DOMAIN) -> str:
    """A structurally valid COSE_Sign1 control object (the signature is a placeholder: the root verifies it)."""
    import base64  # noqa: PLC0415

    from leanmesh_host.wire import cbor_encode  # noqa: PLC0415
    from leanmesh_host.wire.control import ControlBody, encode_control_body, encode_cose_sign1  # noqa: PLC0415

    body = encode_control_body(ControlBody(ctype, 1, b"\x01" * 16, bytes.fromhex(domain), 1, b"\x02" * 32,
                                           cbor_encode(data)))
    return base64.b64encode(encode_cose_sign1(b"\x02" * 32, body, b"\x00" * 64)).decode()


TRANSFER_TICKET = [bytes.fromhex(NODE), b"\x03" * 16, b"\x04" * 16, b"\x05" * 16, b"\x06" * 32, 1, 2, b"\x07" * 16, 0,
                   b"\x08" * 16, b"\x09" * 32]
POLICY_OBJECT = [1, 1, bytes(32), b"\x00"]
