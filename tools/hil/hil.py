"""BENCH / HIL ONLY: provisioning and console of firmware/hil_node boards (Issue #6).

Run with the Host venv:  PYTHONPATH=host ~/.cache/leanmesh/host-venv/bin/python tools/hil/hil.py <command>

  init                                   new TEST fleet (fresh random key, encrypted store), domain, Host key + kit
  init --name netB                       a second network (domain, Host key + kit) under the SAME fleet
  provision root --port P [--net netB]   the board makes its key, the fleet signs, the board writes its records
  provision root --replacement --first-term N --port P
                                         a REPLACEMENT root of a failed one (issue #5): delegation generation + 1, credential
                                         one term below N, no ledger (RECOVERY_REQUIRED until restored)
  provision leaf --port P [--name N] [--net netB]
                                         same for a leaf: DeviceCredential + initial ticket (+ ExpectedSet page)
  handover --term N                      the fleet's RootHandover old root -> replacement root (after `provision root --replacement`)
  backup                                 the Host's newest ledger backup (GET /v1/ledger/backup): sequence, records, root
  restore [--sequence S]                 LEDGER_RESTORE of that backup onto the replacement root through the Host
  install --port P [--file F]            a member board stores an object (default objects/handover.cose, control 31); then
                                         `cmd --port P "join transfer"` makes it follow the replacement root
  transfer <leaf> --to netB [--grant] [--preapproved]
                                         move an ACTIVE leaf to another network (docs/07 §8): nonce from the board,
                                         ticket from the fleet, install, `join transfer`, wait for the new domain
  reconcile <leaf>                       tell the leaf's OLD root about the move (the same ticket)
  cmd --port P "<line>"                  one console command (status, join, nonce, ticket, send root hi, ...)
  monitor --port P [--seconds S]         print what the board writes
  host-env [--net netB]                  the environment of the Host process of a network

Everything lives in $LEANMESH_HIL_DIR (default ~/.cache/leanmesh/hil, mode 0700). The fleet store is
environment "test": a key made for this bench, never imported from or exported to anything else. Device keys are made
on the boards (leanmesh_bench.h); only their public keys come here. The Host's key is made here (the Host is this PC).

Networks: the first one (plain `init`) keeps the original state layout (top-level keys fleet_id, domain, host_id, root,
leaves, assignment, expected_revision, epoch, ...). Others live in state["nets"][name] with the same keys and are chosen
with --net; commands without --net work on the first network exactly as before. Each network has its own root board,
Host process (own USB kit, DB and Unix socket: `host-env --net NAME`) and objects (prefixed with the network's name).
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


NET_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]{0,15}")


class Net:
    """One bench network: the state's top-level keys (the first network, the original layout) or state["nets"][name].

    Same keys either way: domain, host_id, root, leaves, assignment, expected_revision, epoch, window_revision,
    revoke_revision. save() writes the whole state."""

    def __init__(self, state: dict, name: str | None = None) -> None:
        if name is not None and name not in state.get("nets", {}):
            raise SystemExit(f"no network {name!r} in this bench (init --name {name})")
        self.state, self.name = state, name
        self.d = state if name is None else state["nets"][name]

    def __getitem__(self, key: str):
        return self.d[key]

    def __setitem__(self, key: str, value) -> None:
        self.d[key] = value

    def get(self, key: str, default=None):
        return self.d.get(key, default)

    def save(self) -> None:
        save_state(self.state)

    @property
    def tag(self) -> str:
        """Prefix of this network's file names (nothing for the first network: its names are the original ones)."""
        return "" if self.name is None else f"{self.name}-"

    @property
    def label(self) -> str:
        return self.name or "(first network)"

    @property
    def kit(self) -> Path:
        return HIL_DIR / f"usb-kit{'' if self.name is None else '-' + self.name}.cbor"

    @property
    def db(self) -> Path:
        return HIL_DIR / f"host{'' if self.name is None else '-' + self.name}.db"

    @property
    def sock(self) -> str:
        """The Unix socket of this network's Host (hil.py talks to it; start the Host with `--uds` this path)."""
        first = os.environ.get("LEANMESH_HIL_SOCK", "/tmp/claude-501/lm.sock")
        if self.name is None:
            return first
        return os.environ.get(f"LEANMESH_HIL_SOCK_{self.name.upper()}", f"{first.removesuffix('.sock')}-{self.name}.sock")


def all_nets(state: dict) -> list[Net]:
    return [Net(state), *(Net(state, n) for n in state.get("nets", {}))]


def find_leaf(state: dict, name: str) -> tuple[Net, dict]:
    """The network a bench board (by name) belongs to now, and its record."""
    for net in all_nets(state):
        if name in net["leaves"]:
            return net, net["leaves"][name]
    raise SystemExit(f"no board named {name!r} in this bench")


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

def make_host(iss: Issuer, meta: dict, domain: bytes, serial: str, kit_path: Path) -> str:
    """The Host (this PC) of one network: its own key and a fleet DeviceCredential; the USB kit holds both, the
    fleet trust anchor and the network's domain (docs/sdk/host.md). Returns the Host's DeviceId."""
    host_key = ec.generate_private_key(ec.SECP256R1())
    host_dc = iss.device(host_key.public_key(), serial, 1)
    scalar = host_key.private_numbers().private_value.to_bytes(32, "big")
    keys.write_new(kit_path, cbor_encode([1, scalar + host_dc, trust88(meta), domain]))
    return keys.key_id(host_key.public_key()).hex()


def cmd_init(a: argparse.Namespace) -> None:
    if a.name is not None:
        return init_network(a.name)
    if STATE.exists():
        raise SystemExit(f"{HIL_DIR} holds a bench already (remove it to start a new fleet)")
    HIL_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(HIL_DIR, 0o700)
    keys.write_new(PASSWORD, secrets.token_urlsafe(32).encode("ascii"))
    meta = keys.initialize(FLEET, "test", keys.password_file(PASSWORD))
    iss, _ = issuer()
    domain = secrets.token_bytes(16)
    host_id = make_host(iss, meta, domain, "hil-host", HIL_DIR / "usb-kit.cbor")
    token = secrets.token_urlsafe(24)
    keys.write_new(HIL_DIR / "token", token.encode("ascii"))
    principals = {"principals": [{"id": "hil", "token_sha256": sha256(token.encode()).hexdigest(),
                                  "permissions": ["READ", "SEND", "APPROVE", "REVOKE", "TRANSFER", "CONFIGURE"]}]}
    keys.write_new(HIL_DIR / "tokens.json", json.dumps(principals).encode())
    save_state({"fleet_id": meta["fleet_id"], "domain": domain.hex(), "host_id": host_id,
                "root": None, "leaves": {}, "assignment": 1, "expected_revision": 0})
    print(json.dumps({"bench": str(HIL_DIR), "fleet_id": meta["fleet_id"], "domain": domain.hex()}))


def init_network(name: str) -> None:
    """A further network of the same fleet: its own domain, Host key and USB kit (the token file is shared)."""
    if not NET_NAME.fullmatch(name):
        raise SystemExit("a network name is a letter and up to 15 letters/digits")
    if not STATE.exists():
        raise SystemExit("run `init` first: a further network belongs to an existing bench (one fleet)")
    state = load_state()
    if name in state.get("nets", {}):
        raise SystemExit(f"network {name!r} exists already")
    iss, meta = issuer()
    domain = secrets.token_bytes(16)
    nets = state.setdefault("nets", {})
    nets[name] = {"domain": domain.hex(), "host_id": "", "root": None, "leaves": {}, "assignment": 1,
                  "expected_revision": 0}
    net = Net(state, name)
    net["host_id"] = make_host(iss, meta, domain, f"hil-host-{name}", net.kit)
    save_state(state)
    print(json.dumps({"network": name, "domain": domain.hex(), "usb_kit": str(net.kit), "socket": net.sock}))


def cmd_provision(a: argparse.Namespace) -> None:
    state = load_state()
    net = Net(state, a.net)
    iss, meta = issuer()
    board = Board(a.port)
    public, device = board_key(board)
    print(f"board key made on the device: id={device.hex()}")
    domain = bytes.fromhex(net["domain"])
    trust = trust88(meta).hex()
    if a.role == "root":
        if a.replacement:
            if net["root"] is None or a.first_term < 2:
                raise SystemExit("--replacement needs a root provisioned before it and --first-term >= 2")
            if net["root"]["device"] == device.hex():
                raise SystemExit("a replacement root is another device than the one it replaces")
            generation = net.get("root_generation", 1) + 1
        elif net["root"] is not None:
            raise SystemExit(f"network {net.label} has a root already")
        else:
            generation = 1
        dc = iss.device(public, f"hil-root-{net.tag}{device.hex()[:8]}", 1)
        delegation = iss.root(public, domain, generation, 15)
        kind = "replacement-root" if a.replacement else "root"
        put_object(f"{net.tag}{kind}-device.cose", dc)
        put_object(f"{net.tag}{kind}-delegation.cose", delegation)
        line = f"prov-root {trust} {dc.hex()} {delegation.hex()} {net['host_id']}"
        if a.replacement:
            line += f" {a.first_term}"
            net["old_root"] = {**net["root"], "generation": generation - 1}
        require_ok(board.command(line, seconds=30), "prov-root")
        net["root"] = {"device": device.hex(), "port": a.port}
        if a.replacement:  # (a first root is generation 1: its network keeps the original layout)
            net["root_generation"] = generation
            net["replacement_first_term"] = a.first_term
    else:
        if net["root"] is None:
            raise SystemExit("provision the root first (its delegation names the domain the ticket is for)")
        name = a.name or f"leaf{sum(len(n['leaves']) for n in all_nets(state)) + 1}"
        if any(name in n["leaves"] for n in all_nets(state)):
            raise SystemExit(f"a board named {name!r} exists already")
        dc = iss.device(public, f"hil-{name}-{device.hex()[:8]}", 1)
        delegation = (OBJECTS / f"{net.tag}root-delegation.cose").read_bytes()
        net["expected_revision"] += 1  # one admission batch per board, never a revision twice
        files = iss.admission([dc], delegation, net["assignment"], net["expected_revision"])
        ticket = files[f"ticket-{device.hex()}.cose"]
        put_object(f"{net.tag}{name}-device.cose", dc)
        put_object(f"{net.tag}{name}-ticket.cose", ticket)
        for fname, data in files.items():
            if fname.startswith("expected-"):
                put_object(f"{net.tag}{name}-{fname}", data)
        net.save()  # the revision is used even if the board refuses
        require_ok(board.command(f"prov-leaf {trust} {dc.hex()} {ticket.hex()}", seconds=30), "prov-leaf")
        net["leaves"][name] = {"device": device.hex(), "port": a.port, "role": a.role,
                               "dc": f"{net.tag}{name}-device.cose"}
    net.save()
    print(f"provisioned ({a.role}, network {net.label}); the board restarts and starts the mesh")


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


# ---- Host API helpers (the Host of one network on its Unix socket) -----------------------------------------------

def host_call(net: Net, method: str, path: str, body: dict | None = None, key: str | None = None) -> dict:
    import http.client
    import socket

    class Conn(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(net.sock)

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


def host_epoch(net: Net) -> str:
    if not net.get("epoch"):
        net["epoch"] = host_call(net, "POST", "/v1/epochs", {"request_id": secrets.token_hex(16)})["id"]
        net.save()
    return net["epoch"]


def cmd_approve(a: argparse.Namespace) -> None:
    """Approves every join request the root reports as PENDING_APPROVAL."""
    net = Net(load_state(), a.net)
    approve_pending(net, print_none=True)


def approve_pending(net: Net, device: str | None = None, print_none: bool = False) -> int:
    items = host_call(net, "GET", f"/v1/lifecycle/requests?domain_id={net['domain']}").get("items", [])
    pending = [i for i in items if i["state"] == "PENDING_APPROVAL" and (device is None or i["device_id"] == device)]
    for i in pending:
        r = host_call(net, "POST", "/v1/control", {
            "domain_id": net["domain"], "client_epoch": host_epoch(net), "expected_revision": i["revision"],
            "type": "JOIN_DECISION", "device_id": i["device_id"], "decision": "APPROVE",
            "request_id": i["request_id"]})
        print(f"approve {i['device_id'][:16]}.. -> {r.get('state')} {r.get('id')}")
    if not pending and print_none:
        print("no pending join request")
    return len(pending)


def cmd_host_send(a: argparse.Namespace) -> None:
    """Host -> node: RECEIVED + DURABLE, no deadline; waits for the operation to end and prints its evidence."""
    import base64

    state = load_state()
    try:
        net, leaf = find_leaf(state, a.name)  # a board name: its network's Host sends
        device = leaf["device"]
    except SystemExit:
        net, device = Net(state, a.net), a.name  # or a DeviceId, through the Host of --net
    r = host_call(net, "POST", "/v1/messages", {
        "domain_id": net["domain"], "client_epoch": host_epoch(net),
        "destination": {"kind": "node", "device_id": device}, "app_port": 100,
        "payload_b64": base64.b64encode(a.text.encode()).decode(), "delivery": "RECEIVED", "storage": "DURABLE",
        "queue_mode": "FIFO", "priority": "NORMAL", "deadline": {"mode": "none"}})
    op = r.get("id")
    if not op:
        raise SystemExit(f"refused: {r}")
    end = time.monotonic() + a.timeout
    while time.monotonic() < end:
        r = host_call(net, "GET", f"/v1/operations/{op}")
        if r.get("state") == "FINAL":
            break
        time.sleep(0.5)
    print(f"{r.get('state')} outcome={r.get('outcome')} evidence=" +
          ",".join(f"{e['kind']}" + (f"({e['assurance']})" if e['assurance'] != 'SELF_REPORTED' else "")
                   for e in r.get("evidence", [])))


def host_control(net: Net, body: dict, timeout: float = 30.0) -> dict:
    """POST /v1/control and wait for the operation to end."""
    body = {"domain_id": net["domain"], "client_epoch": host_epoch(net), "request_id": secrets.token_hex(16),
            **body}
    r = host_call(net, "POST", "/v1/control", body)
    op = r.get("id")
    if not op:
        raise SystemExit(f"refused: {r}")
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = host_call(net, "GET", f"/v1/operations/{op}")
        if r.get("state") == "FINAL":
            break
        time.sleep(0.5)
    return r


def install_control(net: Net, cose: bytes) -> dict:
    import base64

    return host_control(net, {"type": "INSTALL_CONTROL", "expected_revision": "0",
                              "signed_cbor_b64": base64.b64encode(cose).decode()})


def cmd_expected(a: argparse.Namespace) -> None:
    """Installs the ExpectedSet page(s) of a provisioned board on the root (INSTALL_CONTROL, type 5)."""
    net, _ = find_leaf(load_state(), a.name)
    for page in sorted(OBJECTS.glob(f"{net.tag}{a.name}-expected-*.cose")):
        r = install_control(net, page.read_bytes())
        print(f"{page.name}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')}")


def cmd_window(a: argparse.Namespace) -> None:
    """A fleet-signed CommissioningWindow (control 30) for the root's current term, installed through the Host.

    root_ms: the root clock now (a member's `status` prints root_ms=earliest..latest)."""
    import base64

    state = load_state()
    net = Net(state, a.net)
    iss, _ = issuer()
    domain = bytes.fromhex(net["domain"])
    net["window_revision"] = net.get("window_revision", 0) + 1
    rev = net["window_revision"]
    window = [secrets.token_bytes(16), a.term, a.expected_revision, a.root_ms, a.root_ms + a.minutes * 60000,
              a.max_new, a.roles, rev]
    cose = iss._sign(30, domain, rev, window, 1024)
    net.save()
    put_object(f"{net.tag}window-{rev}.cose", cose)
    r = host_control(net, {"type": "COMMISSIONING_WINDOW_SET", "expected_revision": "0",
                           "signed_cbor_b64": base64.b64encode(cose).decode()})
    print(f"window rev {rev}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')}")


def cmd_revoke(a: argparse.Namespace) -> None:
    """A fleet-signed RevokeObject (control 11): every credential of the board below the floors is dead."""
    import base64

    state = load_state()
    net, leaf = find_leaf(state, a.name)
    iss, _ = issuer()
    device = bytes.fromhex(leaf["device"])
    net["revoke_revision"] = net.get("revoke_revision", 0) + 1
    rev = net["revoke_revision"]
    cose = iss._sign(11, bytes(16), rev, [device, a.assignment_floor, a.membership_floor, 0, rev], 1024)
    net.save()
    put_object(f"{net.tag}revoke-{a.name}-{rev}.cose", cose)
    r = host_control(net, {"type": "REVOKE", "expected_revision": "0", "device_id": device.hex(),
                           "signed_cbor_b64": base64.b64encode(cose).decode()})
    print(f"revoke {a.name}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')} "
          + ",".join(e["kind"] for e in r.get("evidence", [])))


def cmd_policy(a: argparse.Namespace) -> None:
    """Shows the root's join mode (GET /v1/policy) or sets it (POLICY_SET, compare-and-set on its revision)."""
    net = Net(load_state(), a.net)
    cur = host_call(net, "GET", f"/v1/policy?domain_id={net['domain']}")
    print("policy:", cur)
    if a.mode:
        r = host_control(net, {"type": "POLICY_SET", "join_mode": a.mode, "expected_revision": cur["revision"]})
        print(f"POLICY_SET {a.mode}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')}")
        time.sleep(1)
        print("policy:", host_call(net, "GET", f"/v1/policy?domain_id={net['domain']}"))


def cmd_handover(a: argparse.Namespace) -> None:
    """The fleet's RootHandover (control 31) old root -> the replacement root `provision root --replacement` set up."""
    net = Net(load_state(), a.net)
    if net.get("old_root") is None:
        raise SystemExit("provision the replacement root first (provision root --replacement --first-term N)")
    iss, _ = issuer()
    cose = iss.handover(bytes.fromhex(net["old_root"]["device"]),
                        (OBJECTS / f"{net.tag}replacement-root-delegation.cose").read_bytes(),
                        net["old_root"]["generation"], a.term)
    print(f"handover: {put_object(f'{net.tag}handover.cose', cose)} ({len(cose)} bytes, new term {a.term})")


def cmd_backup(a: argparse.Namespace) -> None:
    """The newest ledger backup the Host holds (taken from the root after its ledger changed)."""
    net = Net(load_state(), a.net)
    r = host_call(net, "GET", f"/v1/ledger/backup?domain_id={net['domain']}")
    if "backup_b64" not in r:
        raise SystemExit(f"no backup: {r}")
    print(f"sequence {r['sequence']}, {r['records']} records, root {r['root_device_id'][:16]}.. (term {r['root_term']}), "
          f"taken {r['taken_at']}")


def cmd_restore(a: argparse.Namespace) -> None:
    """LEDGER_RESTORE: the held backup (sequence S, default the newest) onto the replacement root, with the fleet's handover."""
    import base64

    net = Net(load_state(), a.net)
    held = host_call(net, "GET", f"/v1/ledger/backup?domain_id={net['domain']}")
    if "sequence" not in held:
        raise SystemExit(f"the Host holds no backup: {held}")
    sequence = a.sequence or held["sequence"]
    handover = (OBJECTS / f"{net.tag}handover.cose").read_bytes()
    r = host_control(net, {"type": "LEDGER_RESTORE", "expected_revision": str(sequence),
                           "signed_cbor_b64": base64.b64encode(handover).decode()}, timeout=a.timeout)
    print(f"restore of sequence {sequence}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')}")


def cmd_host_env(a: argparse.Namespace) -> None:
    net = Net(load_state(), a.net)
    port = (net["root"] or {}).get("port", "<root port>")
    print(f"export LEANMESH_DB={net.db} LEANMESH_TOKENS={HIL_DIR}/tokens.json "
          f"LEANMESH_SERIAL={port} LEANMESH_USB_KIT={net.kit}")
    print(f"# start: python -m uvicorn leanmesh_host.main:app --uds {net.sock} --workers 1 --app-dir host")
    print(f"# bearer token: {HIL_DIR}/token   network: {net.label}   domain: {net['domain']}")


# ---- transfer (docs/07 §8) ---------------------------------------------------------------------------------------

def board_status(board: Board) -> dict[str, str]:
    return require_ok(board.command("status", echo=False), "status")


def membership_state(status: dict[str, str]) -> int:
    return int(status["membership"].split("(")[0])  # "membership=5(st0)"


LM_ACTIVE = 5
LM_PHASE_FINAL = 3


def wait_operation(board: Board, op: str, timeout: float) -> dict[str, str]:
    """Polls the board's `op <id>` until the operation is final; returns phase/outcome/reason."""
    end = time.monotonic() + timeout
    while True:
        o = require_ok(board.command(f"op {op}", echo=False), "op")
        if int(o["phase"]) == LM_PHASE_FINAL:
            return o
        if time.monotonic() > end:
            raise SystemExit(f"operation {op} not final within {timeout} s: {o}")
        time.sleep(0.5)


def cmd_transfer(a: argparse.Namespace) -> None:
    """Moves an ACTIVE leaf of one network to another (docs/07 §8). The leaf and the target root need to be up;
    the old root may be off. Mode 0 (default): the board's own nonce (`nonce`), valid until the board restarts.
    --grant: a one-time grant ticket (mode 1), no nonce. --preapproved: also an ExpectedSet page for the target
    (installed through the target's Host, whose policy must be PREAPPROVED); else approve at the target
    (`approve --net`, done here when its Host answers)."""
    state = load_state()
    src, leaf = find_leaf(state, a.leaf)
    dst = Net(state, a.to)
    if dst.name == src.name:
        raise SystemExit(f"{a.leaf} is in {dst.label} already")
    if dst["root"] is None:
        raise SystemExit(f"provision the root of {dst.label} first")
    iss, _ = issuer()
    board = Board(leaf["port"])
    st = board_status(board)
    if membership_state(st) != LM_ACTIVE or st.get("domain") != src["domain"]:
        raise SystemExit(f"{a.leaf} is not an ACTIVE member of {src.label} (domain {src['domain']}): "
                         f"membership={st.get('membership')} domain={st.get('domain')}")
    old = int(st["assign"])
    new = a.new_generation or old + 1
    dc = (OBJECTS / leaf.get("dc", f"{a.leaf}-device.cose")).read_bytes()
    delegation = (OBJECTS / f"{dst.tag}root-delegation.cose").read_bytes()
    nonce = None
    if not a.grant:
        # The nonce is RAM only: do not restart the board between this and the join.
        nonce = bytes.fromhex(require_ok(board.command("nonce"), "nonce")["nonce"])
    revision = None
    if a.preapproved:
        dst["expected_revision"] += 1  # never a revision twice
        revision = dst["expected_revision"]
        dst.save()
    files = iss.transfer(dc, bytes.fromhex(src["domain"]), delegation, old, new, nonce=nonce,
                         expected_revision=revision)
    ticket = files[f"ticket-{leaf['device']}.cose"]
    ticket_name = f"{a.leaf}-transfer-to-{dst.name}.cose"
    put_object(ticket_name, ticket)
    print(f"ticket {src.label} -> {dst.label}: expected_old={old} new_generation={new} "
          f"mode={0 if nonce is not None else 1} {len(ticket)} B ({ticket_name})")
    if revision is not None:
        put_object(f"{a.leaf}-transfer-to-{dst.name}-expected.cose", files["expected-00.cose"])
        r = install_control(dst, files["expected-00.cose"])
        print(f"ExpectedSet at {dst.label} (revision {revision}): {r.get('state')} {r.get('outcome')} "
              f"{r.get('reason', '')}")
    done = require_ok(board.command(f"ticket {ticket.hex()}", seconds=20), "ticket")
    o = wait_operation(board, done["op"], 30)
    if o["reason"] != "0":
        raise SystemExit(f"the board refused the ticket: {o} (LM status code; see api/leanmesh.h)")
    print(f"ticket installed on the board (op {done['op']}: {o})")
    require_ok(board.command("join transfer"), "join transfer")
    end = time.monotonic() + a.timeout
    last = ""
    while time.monotonic() < end:
        try:
            st = board_status(board)
        except TimeoutError:
            continue
        last = f"membership={st.get('membership')} assign={st.get('assign')} domain={st.get('domain')}"
        if membership_state(st) == LM_ACTIVE and st.get("domain") == dst["domain"]:
            break
        if not a.preapproved:
            try:
                approve_pending(dst, leaf["device"])
            except OSError:
                pass  # no Host of the target: approve by hand (`approve --net`)
        time.sleep(2)
    else:
        raise SystemExit(f"{a.leaf} did not become ACTIVE in {dst.label} within {a.timeout} s; last: {last}")
    print(f"{a.leaf} is ACTIVE in {dst.label}: {last}")
    del src["leaves"][a.leaf]
    dst["leaves"][a.leaf] = {**leaf, "assignment": int(st["assign"]), "dc": leaf.get("dc", f"{a.leaf}-device.cose"),
                             "transfer": {"from": src.name, "to": dst.name, "ticket": ticket_name}}
    dst.save()
    print(f"the old root of {src.label} does not know yet (old_domain_reconciliation): `reconcile {a.leaf}`")


def cmd_reconcile(a: argparse.Namespace) -> None:
    """Installs the leaf's transfer ticket on its OLD root through that network's Host (INSTALL_CONTROL, type 3):
    the old ledger's ACTIVE entry becomes LEFT and the old generations are floored (docs/07 §8)."""
    state = load_state()
    _, leaf = find_leaf(state, a.leaf)
    moved = leaf.get("transfer")
    if not moved:
        raise SystemExit(f"{a.leaf} has not been moved with `transfer`")
    old = Net(state, moved["from"])
    r = install_control(old, (OBJECTS / moved["ticket"]).read_bytes())
    print(f"reconcile {a.leaf} at {old.label}: {r.get('state')} {r.get('outcome')} {r.get('reason', '')}")


def main() -> int:
    p = argparse.ArgumentParser(description="LeanMesh HIL bench (TEST fleet only)")
    sub = p.add_subparsers(dest="command", required=True)

    def net_option(q: argparse.ArgumentParser) -> None:
        q.add_argument("--net", help="network name (default: the first network)")

    q = sub.add_parser("init")
    q.add_argument("--name", help="a further network of the same fleet (default: the bench's first network)")
    q = sub.add_parser("provision")
    q.add_argument("role", choices=("root", "leaf", "relay"))  # a relay board is provisioned like a leaf
    q.add_argument("--port", required=True)
    q.add_argument("--name")
    net_option(q)
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
    net_option(sub.add_parser("host-env"))
    net_option(sub.add_parser("approve"))
    q = sub.add_parser("handover")
    q.add_argument("--term", type=int, required=True, help="the first root term the replacement root publishes")
    net_option(q)
    net_option(sub.add_parser("backup"))
    q = sub.add_parser("restore")
    q.add_argument("--sequence", type=int, default=0)
    q.add_argument("--timeout", type=float, default=120.0)
    net_option(q)
    q = sub.add_parser("policy")
    q.add_argument("mode", nargs="?", choices=("CLOSED", "EXTERNAL", "PREAPPROVED"))
    net_option(q)
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
    net_option(q)
    q = sub.add_parser("host-send")
    q.add_argument("name", help="a bench board name (leaf1, ...) or a DeviceId (then --net)")
    q.add_argument("text")
    q.add_argument("--timeout", type=float, default=60.0)
    net_option(q)
    q = sub.add_parser("transfer")
    q.add_argument("leaf", help="a bench board name (an ACTIVE member)")
    q.add_argument("--to", required=True, help="the target network (init --name)")
    q.add_argument("--grant", action="store_true", help="mode 1 one-time grant instead of the board's nonce (mode 0)")
    q.add_argument("--preapproved", action="store_true",
                   help="also issue and install the target's ExpectedSet page (its policy: PREAPPROVED)")
    q.add_argument("--new-generation", type=int, help="default: the board's assignment generation + 1")
    q.add_argument("--timeout", type=float, default=240.0)
    q = sub.add_parser("reconcile")
    q.add_argument("leaf")
    a = p.parse_args()
    {"init": cmd_init, "provision": cmd_provision, "cmd": cmd_cmd, "wait": cmd_wait, "monitor": cmd_monitor,
     "host-env": cmd_host_env, "approve": cmd_approve,
     "host-send": cmd_host_send, "expected": cmd_expected, "window": cmd_window,
     "revoke": cmd_revoke, "policy": cmd_policy, "transfer": cmd_transfer,
     "reconcile": cmd_reconcile, "handover": cmd_handover, "backup": cmd_backup,
     "restore": cmd_restore, "install": cmd_install}[a.command](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
