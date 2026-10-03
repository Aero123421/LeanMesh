"""BENCH / HIL ONLY: provisioning and console of firmware/hil_node boards (Issue #6).

Run with the Host venv:  PYTHONPATH=host ~/.cache/leanmesh/host-venv/bin/python tools/hil/hil.py <command>

  init                                   new TEST fleet (fresh random key, encrypted store), domain, Host key + kit
  provision root --port P                the board makes its key, the fleet signs, the board writes its records
  provision root --replacement --first-term N --port P
                                         a REPLACEMENT root of a failed one (issue #5): delegation generation + 1, credential
                                         one term below N, no ledger (RECOVERY_REQUIRED until restored)
  handover --term N                      the fleet's RootHandover old root -> replacement root (after `provision root --replacement`)
  backup                                 the Host's newest ledger backup (GET /v1/ledger/backup): sequence, records, root
  restore [--sequence S]                 LEDGER_RESTORE of that backup onto the replacement root through the Host
  install --port P [--file F]            a member board stores an object (default objects/handover.cose, control 31); then
                                         `cmd --port P "join transfer"` makes it follow the replacement root
  provision leaf --port P [--name N]     same for a leaf: DeviceCredential + initial ticket (+ ExpectedSet page)
  cmd --port P "<line>"                  one console command (status, join, send root hi, ...)
  monitor --port P [--seconds S]         print what the board writes
  host-env                               the environment of the Host process for this bench

Everything lives in $LEANMESH_HIL_DIR (default ~/.cache/leanmesh/hil, mode 0700). The fleet store is
environment "test": a key made for this bench, never imported from or exported to anything else. Device keys are made
on the boards (leanmesh_bench.h); only their public keys come here. The Host's key is made here (the Host is this PC).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
import time
from hashlib import sha256
from pathlib import Path

import serial
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from leanmesh_fleet import keys
from leanmesh_fleet.issuer import Issuer
from leanmesh_host.wire.cbor import cbor_encode

ANSWER = re.compile(r"(?:^|\s)((?:OK|ERR)(?:\s|$))")
HIL_DIR = Path(os.environ.get("LEANMESH_HIL_DIR", Path.home() / ".cache/leanmesh/hil"))
FLEET = HIL_DIR / "fleet"
PASSWORD = HIL_DIR / "fleet.pass"
STATE = HIL_DIR / "state.json"
OBJECTS = HIL_DIR / "objects"


# ---- local state -------------------------------------------------------------------------------------------------

def load_state() -> dict:
    return json.loads(STATE.read_text())


def save_state(state: dict) -> None:
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(STATE)


def put_object(name: str, data: bytes) -> Path:
    OBJECTS.mkdir(mode=0o700, exist_ok=True)
    path = OBJECTS / name
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return path


def issuer() -> tuple[Issuer, dict]:
    meta, key = keys.load(FLEET, "test", keys.password_file(PASSWORD))
    return Issuer(bytes.fromhex(meta["fleet_id"]), key), meta


def trust88(meta: dict) -> bytes:
    """The fleet_trust record: fleet_id16 || x32 || y32 || min_credential_generation u64be (src/core/member/records)."""
    pub = serialization.load_pem_public_key(meta["public_key_pem"].encode("ascii"))
    n = pub.public_numbers()
    return bytes.fromhex(meta["fleet_id"]) + n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big") + bytes(8)


# ---- board console -------------------------------------------------------------------------------------------------

class Board:
    def __init__(self, port: str) -> None:
        self.port = serial.Serial(port, 115200, timeout=0.2)
        self.buf = b""

    def lines(self, seconds: float):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.buf += self.port.read(4096)
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                yield line.decode("utf-8", "replace").rstrip("\r")

    def command(self, line: str, seconds: float = 10.0, echo: bool = True) -> str:
        """Sends one line; returns the first answer line ("OK ..." / "ERR ..."), printing the others."""
        self.port.reset_input_buffer()
        self.buf = b""
        # A leading newline ends any partial line; small chunks keep the board's receive buffer from overflowing.
        data = b"\n" + line.encode("ascii") + b"\n"
        for i in range(0, len(data), 256):
            self.port.write(data[i:i + 256])
            self.port.flush()
            time.sleep(0.02)
        for got in self.lines(seconds):
            m = ANSWER.search(got)  # a log line without its newline can precede the answer on the same line
            if m:
                return got[m.start(1):]
            if echo and got:
                print(f"  | {got}")
        raise TimeoutError(f"no answer to {line.split(' ')[0]!r} within {seconds} s")


def fields(answer: str) -> dict[str, str]:
    return dict(p.split("=", 1) for p in answer.split()[1:] if "=" in p)


def require_ok(answer: str, what: str) -> dict[str, str]:
    if not answer.startswith("OK"):
        raise SystemExit(f"{what}: {answer} (LM status code; see api/leanmesh.h)")
    return fields(answer)


def board_key(board: Board) -> tuple[ec.EllipticCurvePublicKey, bytes]:
    info = require_ok(board.command("info"), "info")
    if info.get("state") == "2":
        raise SystemExit("this board is provisioned already: erase it first (scripts/hil.sh flash ...)")
    f = require_ok(board.command("keygen", seconds=20), "keygen")
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(f["pub"]))
    device = bytes.fromhex(f["id"])
    if keys.key_id(public) != device:
        raise SystemExit("the board's DeviceId does not match its public key")
    return public, device


# ---- commands ------------------------------------------------------------------------------------------------------

def cmd_init(_a: argparse.Namespace) -> None:
    if STATE.exists():
        raise SystemExit(f"{HIL_DIR} holds a bench already (remove it to start a new fleet)")
    HIL_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(HIL_DIR, 0o700)
    keys.write_new(PASSWORD, secrets.token_urlsafe(32).encode("ascii"))
    meta = keys.initialize(FLEET, "test", keys.password_file(PASSWORD))
    iss, _ = issuer()
    domain = secrets.token_bytes(16)
    # The Host (this PC): its own key and a fleet DeviceCredential; the USB kit holds both (docs/sdk/host.md).
    host_key = ec.generate_private_key(ec.SECP256R1())
    host_dc = iss.device(host_key.public_key(), "hil-host", 1)
    scalar = host_key.private_numbers().private_value.to_bytes(32, "big")
    kit = cbor_encode([1, scalar + host_dc, trust88(meta), domain])
    keys.write_new(HIL_DIR / "usb-kit.cbor", kit)
    token = secrets.token_urlsafe(24)
    keys.write_new(HIL_DIR / "token", token.encode("ascii"))
    principals = {"principals": [{"id": "hil", "token_sha256": sha256(token.encode()).hexdigest(),
                                  "permissions": ["READ", "SEND", "APPROVE", "REVOKE", "TRANSFER", "CONFIGURE"]}]}
    keys.write_new(HIL_DIR / "tokens.json", json.dumps(principals).encode())
    save_state({"fleet_id": meta["fleet_id"], "domain": domain.hex(), "host_id": keys.key_id(host_key.public_key()).hex(),
                "root": None, "leaves": {}, "assignment": 1, "expected_revision": 0})
    print(json.dumps({"bench": str(HIL_DIR), "fleet_id": meta["fleet_id"], "domain": domain.hex()}))


def cmd_provision(a: argparse.Namespace) -> None:
    state = load_state()
    iss, meta = issuer()
    board = Board(a.port)
    public, device = board_key(board)
    print(f"board key made on the device: id={device.hex()}")
    domain = bytes.fromhex(state["domain"])
    trust = trust88(meta).hex()
    if a.role == "root":
        if a.replacement:
            if state["root"] is None or a.first_term < 2:
                raise SystemExit("--replacement needs a root provisioned before it and --first-term >= 2")
            if state["root"]["device"] == device.hex():
                raise SystemExit("a replacement root is another device than the one it replaces")
            generation = state.get("root_generation", 1) + 1
        elif state["root"] is not None:
            raise SystemExit("this bench has a root already")
        else:
            generation = 1
        dc = iss.device(public, f"hil-root-{device.hex()[:8]}", 1)
        delegation = iss.root(public, domain, generation, 15)
        put_object("root-device.cose" if not a.replacement else "replacement-root-device.cose", dc)
        put_object("root-delegation.cose" if not a.replacement else "replacement-root-delegation.cose", delegation)
        line = f"prov-root {trust} {dc.hex()} {delegation.hex()} {state['host_id']}"
        if a.replacement:
            line += f" {a.first_term}"
            state["old_root"] = {**state["root"], "generation": generation - 1}
        require_ok(board.command(line, seconds=30), "prov-root")
        state["root"] = {"device": device.hex(), "port": a.port}
        state["root_generation"] = generation
        if a.replacement:
            state["replacement_first_term"] = a.first_term
    else:
        if state["root"] is None:
            raise SystemExit("provision the root first (its delegation names the domain the ticket is for)")
        name = a.name or f"leaf{len(state['leaves']) + 1}"
        dc = iss.device(public, f"hil-{name}-{device.hex()[:8]}", 1)
        delegation = (OBJECTS / "root-delegation.cose").read_bytes()
        state["expected_revision"] += 1  # one admission batch per board, never a revision twice
        files = iss.admission([dc], delegation, state["assignment"], state["expected_revision"])
        ticket = files[f"ticket-{device.hex()}.cose"]
        put_object(f"{name}-device.cose", dc)
        put_object(f"{name}-ticket.cose", ticket)
        for fname, data in files.items():
            if fname.startswith("expected-"):
                put_object(f"{name}-{fname}", data)
        save_state(state)  # the revision is used even if the board refuses
        require_ok(board.command(f"prov-leaf {trust} {dc.hex()} {ticket.hex()}", seconds=30), "prov-leaf")
        state["leaves"][name] = {"device": device.hex(), "port": a.port, "role": a.role}
    save_state(state)
    print(f"provisioned ({a.role}); the board restarts and starts the mesh")


def cmd_cmd(a: argparse.Namespace) -> None:
    print(Board(a.port).command(a.line, seconds=a.timeout))


def cmd_install(a: argparse.Namespace) -> None:
    """lm_install_control on a member board: a stored object file (default the fleet's RootHandover, control 31) - the
    member's own evidence that the domain's root changed. Afterwards `cmd --port P "join transfer"` follows the new root."""
    cose = (OBJECTS / a.file).read_bytes()
    print(Board(a.port).command(f"install {a.type} {cose.hex()}", seconds=a.timeout))


def cmd_wait(a: argparse.Namespace) -> None:
    """Polls `status` until <field> starts with <value> (e.g. conn 1 = REACHABLE); prints the last status."""
    board = Board(a.port)
    end = time.monotonic() + a.timeout
    last = ""
    while time.monotonic() < end:
        try:
            last = board.command("status", echo=False)
        except TimeoutError:
            continue
        if fields(last).get(a.field, "").startswith(a.value):
            print(last)
            return
        time.sleep(2)
    raise SystemExit(f"timeout: {a.field} != {a.value}; last: {last}")


def cmd_monitor(a: argparse.Namespace) -> None:
    for line in Board(a.port).lines(a.seconds):
        print(line)


# ---- Host API helpers (the Host of this bench on its Unix socket) ------------------------------------------------

def host_call(method: str, path: str, body: dict | None = None, key: str | None = None) -> dict:
    import http.client
    import socket

    class Conn(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(os.environ.get("LEANMESH_HIL_SOCK", "/tmp/claude-501/lm.sock"))

    headers = {"Authorization": f"Bearer {(HIL_DIR / 'token').read_text().strip()}"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["Idempotency-Key"] = key or secrets.token_hex(8)
        data = json.dumps(body)
    c = Conn("localhost")
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    return json.loads(r.read() or b"{}")


def host_epoch(state: dict) -> str:
    if not state.get("epoch"):
        state["epoch"] = host_call("POST", "/v1/epochs", {"request_id": secrets.token_hex(16)})["id"]
        save_state(state)
    return state["epoch"]


def cmd_approve(_a: argparse.Namespace) -> None:
    """Approves every join request the root reports as PENDING_APPROVAL."""
    state = load_state()
    items = host_call("GET", f"/v1/lifecycle/requests?domain_id={state['domain']}").get("items", [])
    pending = [i for i in items if i["state"] == "PENDING_APPROVAL"]
    for i in pending:
        r = host_call("POST", "/v1/control", {
            "domain_id": state["domain"], "client_epoch": host_epoch(state), "expected_revision": i["revision"],
            "type": "JOIN_DECISION", "device_id": i["device_id"], "decision": "APPROVE",
            "request_id": i["request_id"]})
        print(f"approve {i['device_id'][:16]}.. -> {r.get('state')} {r.get('id')}")
    if not pending:
        print("no pending join request")


def cmd_host_send(a: argparse.Namespace) -> None:
    """Host -> node: RECEIVED + DURABLE, no deadline; waits for the operation to end and prints its evidence."""
    import base64

    state = load_state()
    device = state["leaves"][a.name]["device"] if a.name in state["leaves"] else a.name
    r = host_call("POST", "/v1/messages", {
        "domain_id": state["domain"], "client_epoch": host_epoch(state),
        "destination": {"kind": "node", "device_id": device}, "app_port": 100,
        "payload_b64": base64.b64encode(a.text.encode()).decode(), "delivery": "RECEIVED", "storage": "DURABLE",
        "queue_mode": "FIFO", "priority": "NORMAL", "deadline": {"mode": "none"}})
    op = r.get("id")
    if not op:
        raise SystemExit(f"refused: {r}")
    end = time.monotonic() + a.timeout
    while time.monotonic() < end:
        r = host_call("GET", f"/v1/operations/{op}")
        if r.get("state") == "FINAL":
            break
        time.sleep(0.5)
    print(f"{r.get('state')} outcome={r.get('outcome')} evidence=" +
          ",".join(f"{e['kind']}" + (f"({e['assurance']})" if e['assurance'] != 'SELF_REPORTED' else "")
                   for e in r.get("evidence", [])))


def host_control(state: dict, body: dict, timeout: float = 30.0) -> dict:
    """POST /v1/control and wait for the operation to end."""
    body = {"domain_id": state["domain"], "client_epoch": host_epoch(state), "request_id": secrets.token_hex(16),
            **body}
    r = host_call("POST", "/v1/control", body)
    op = r.get("id")
    if not op:
        raise SystemExit(f"refused: {r}")
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = host_call("GET", f"/v1/operations/{op}")
        if r.get("state") == "FINAL":
            break
        time.sleep(0.5)
    return r


def cmd_expected(a: argparse.Namespace) -> None:
    """Installs the ExpectedSet page(s) of a provisioned board on the root (INSTALL_CONTROL, type 5)."""
    import base64

    state = load_state()
    for page in sorted(OBJECTS.glob(f"{a.name}-expected-*.cose")):
        r = host_control(state, {"type": "INSTALL_CONTROL", "expected_revision": "0",
                                 "signed_cbor_b64": base64.b64encode(page.read_bytes()).decode()})
        print(f"{page.name}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')}")


def cmd_window(a: argparse.Namespace) -> None:
    """A fleet-signed CommissioningWindow (control 30) for the root's current term, installed through the Host.

    root_ms: the root clock now (a member's `status` prints root_ms=earliest..latest)."""
    import base64

    state = load_state()
    iss, _ = issuer()
    domain = bytes.fromhex(state["domain"])
    state["window_revision"] = state.get("window_revision", 0) + 1
    rev = state["window_revision"]
    window = [secrets.token_bytes(16), a.term, a.expected_revision, a.root_ms, a.root_ms + a.minutes * 60000,
              a.max_new, a.roles, rev]
    cose = iss._sign(30, domain, rev, window, 1024)
    save_state(state)
    put_object(f"window-{rev}.cose", cose)
    r = host_control(state, {"type": "COMMISSIONING_WINDOW_SET", "expected_revision": "0",
                             "signed_cbor_b64": base64.b64encode(cose).decode()})
    print(f"window rev {rev}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')}")


def cmd_revoke(a: argparse.Namespace) -> None:
    """A fleet-signed RevokeObject (control 11): every credential of the board below the floors is dead."""
    import base64

    state = load_state()
    iss, _ = issuer()
    device = bytes.fromhex(state["leaves"][a.name]["device"])
    state["revoke_revision"] = state.get("revoke_revision", 0) + 1
    rev = state["revoke_revision"]
    cose = iss._sign(11, bytes(16), rev, [device, a.assignment_floor, a.membership_floor, 0, rev], 1024)
    save_state(state)
    put_object(f"revoke-{a.name}-{rev}.cose", cose)
    r = host_control(state, {"type": "REVOKE", "expected_revision": "0", "device_id": device.hex(),
                             "signed_cbor_b64": base64.b64encode(cose).decode()})
    print(f"revoke {a.name}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')} "
          + ",".join(e["kind"] for e in r.get("evidence", [])))


def cmd_policy(a: argparse.Namespace) -> None:
    """Shows the root's join mode (GET /v1/policy) or sets it (POLICY_SET, compare-and-set on its revision)."""
    state = load_state()
    cur = host_call("GET", f"/v1/policy?domain_id={state['domain']}")
    print("policy:", cur)
    if a.mode:
        r = host_control(state, {"type": "POLICY_SET", "join_mode": a.mode, "expected_revision": cur["revision"]})
        print(f"POLICY_SET {a.mode}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')}")
        time.sleep(1)
        print("policy:", host_call("GET", f"/v1/policy?domain_id={state['domain']}"))


def cmd_handover(a: argparse.Namespace) -> None:
    """The fleet's RootHandover (control 31) old root -> the replacement root `provision root --replacement` set up."""
    state = load_state()
    if "old_root" not in state:
        raise SystemExit("provision the replacement root first (provision root --replacement --first-term N)")
    iss, _ = issuer()
    cose = iss.handover(bytes.fromhex(state["old_root"]["device"]), (OBJECTS / "replacement-root-delegation.cose").read_bytes(),
                        state["old_root"]["generation"], a.term)
    print(f"handover: {put_object('handover.cose', cose)} ({len(cose)} bytes, new term {a.term})")


def cmd_backup(_a: argparse.Namespace) -> None:
    """The newest ledger backup the Host holds (taken from the root after its ledger changed)."""
    state = load_state()
    r = host_call("GET", f"/v1/ledger/backup?domain_id={state['domain']}")
    if "backup_b64" not in r:
        raise SystemExit(f"no backup: {r}")
    print(f"sequence {r['sequence']}, {r['records']} records, root {r['root_device_id'][:16]}.. (term {r['root_term']}), "
          f"taken {r['taken_at']}")


def cmd_restore(a: argparse.Namespace) -> None:
    """LEDGER_RESTORE: the held backup (sequence S, default the newest) onto the replacement root, with the fleet's handover."""
    import base64

    state = load_state()
    held = host_call("GET", f"/v1/ledger/backup?domain_id={state['domain']}")
    if "sequence" not in held:
        raise SystemExit(f"the Host holds no backup: {held}")
    sequence = a.sequence or held["sequence"]
    handover = (OBJECTS / "handover.cose").read_bytes()
    r = host_control(state, {"type": "LEDGER_RESTORE", "expected_revision": str(sequence),
                             "signed_cbor_b64": base64.b64encode(handover).decode()}, timeout=a.timeout)
    print(f"restore of sequence {sequence}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')}")


def cmd_host_env(_a: argparse.Namespace) -> None:
    state = load_state()
    port = (state.get("root") or {}).get("port", "<root port>")
    print(f"export LEANMESH_DB={HIL_DIR}/host.db LEANMESH_TOKENS={HIL_DIR}/tokens.json "
          f"LEANMESH_SERIAL={port} LEANMESH_USB_KIT={HIL_DIR}/usb-kit.cbor")
    print(f"# bearer token: {HIL_DIR}/token   domain: {state['domain']}")


def main() -> int:
    p = argparse.ArgumentParser(description="LeanMesh HIL bench (TEST fleet only)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    q = sub.add_parser("provision")
    q.add_argument("role", choices=("root", "leaf", "relay"))  # a relay board is provisioned like a leaf
    q.add_argument("--port", required=True)
    q.add_argument("--name")
    q.add_argument("--replacement", action="store_true", help="root only: the replacement of a failed root (needs --first-term)")
    q.add_argument("--first-term", type=int, default=0, help="the first root term the replacement root publishes (>= 2)")
    q = sub.add_parser("cmd")
    q.add_argument("--port", required=True)
    q.add_argument("--timeout", type=float, default=10.0)
    q.add_argument("line")
    q = sub.add_parser("wait")
    q.add_argument("--port", required=True)
    q.add_argument("--timeout", type=float, default=120.0)
    q.add_argument("field")
    q.add_argument("value")
    q = sub.add_parser("install")
    q.add_argument("--port", required=True)
    q.add_argument("--file", default="handover.cose")
    q.add_argument("--type", type=int, default=31)
    q.add_argument("--timeout", type=float, default=15.0)
    q = sub.add_parser("monitor")
    q.add_argument("--port", required=True)
    q.add_argument("--seconds", type=float, default=10.0)
    sub.add_parser("host-env")
    q = sub.add_parser("handover")
    q.add_argument("--term", type=int, required=True, help="the first root term the replacement root publishes")
    sub.add_parser("backup")
    q = sub.add_parser("restore")
    q.add_argument("--sequence", type=int, default=0)
    q.add_argument("--timeout", type=float, default=120.0)
    sub.add_parser("approve")
    q = sub.add_parser("policy")
    q.add_argument("mode", nargs="?", choices=("CLOSED", "EXTERNAL", "PREAPPROVED"))
    q = sub.add_parser("revoke")
    q.add_argument("name")
    q.add_argument("--assignment-floor", type=int, default=2)
    q.add_argument("--membership-floor", type=int, default=2)
    q = sub.add_parser("expected")
    q.add_argument("name")
    q = sub.add_parser("window")
    q.add_argument("--term", type=int, required=True)
    q.add_argument("--expected-revision", type=int, required=True)
    q.add_argument("--root-ms", type=int, required=True)
    q.add_argument("--minutes", type=int, default=10)
    q.add_argument("--max-new", type=int, default=1)
    q.add_argument("--roles", type=int, default=3)
    q = sub.add_parser("host-send")
    q.add_argument("name", help="a bench board name (leaf1, ...) or a DeviceId")
    q.add_argument("text")
    q.add_argument("--timeout", type=float, default=60.0)
    a = p.parse_args()
    {"init": cmd_init, "provision": cmd_provision, "cmd": cmd_cmd, "wait": cmd_wait, "monitor": cmd_monitor,
     "host-env": cmd_host_env, "approve": cmd_approve,
     "host-send": cmd_host_send, "expected": cmd_expected, "window": cmd_window,
     "revoke": cmd_revoke, "policy": cmd_policy, "handover": cmd_handover, "backup": cmd_backup,
     "restore": cmd_restore, "install": cmd_install}[a.command](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
