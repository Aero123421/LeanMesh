"""tools/hil/hil.py (BENCH ONLY) without hardware: a fake console stands in for each board.

Checks the state layout of the first network (unchanged), a second network under the same fleet, and `transfer`
(nonce -> fleet ticket -> install -> `join transfer`), with the ticket verified like the SDK's device does.
"""

from __future__ import annotations

import importlib.util
import json
import stat
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from leanmesh_fleet.keys import key_id
from leanmesh_host.wire.cbor import cbor_decode
from leanmesh_host.wire.control import decode_control_body, decode_cose_sign1

REPO = Path(__file__).resolve().parents[3]
LM_ACTIVE = 5


class FakeDevice:
    """One bench board: the console commands hil.py uses, and the SDK rules of a transfer it relies on."""

    devices: dict[str, FakeDevice] = {}

    def __init__(self, hil, port: str, role: str) -> None:
        self.hil, self.port, self.role = hil, port, role
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.state = 1  # not provisioned
        self.domain, self.assign, self.membership = bytes(16), 0, 0
        self.nonce = bytes.fromhex("a0" * 16)
        self.ticket: bytes | None = None
        self.log: list[str] = []

    @property
    def device_id(self) -> bytes:
        return key_id(self.key.public_key())

    def ticket_fields(self, cose: bytes):
        body = decode_control_body(decode_cose_sign1(cose).payload, "signed")
        assert body.type == 3
        return cbor_decode(body.data)

    def command(self, line: str) -> str:
        cmd, _, rest = line.partition(" ")
        self.log.append(cmd)
        if cmd == "info":
            return f"OK state={self.state} role={self.role}"
        if cmd == "keygen":
            pub = self.key.public_key().public_bytes(
                self.hil.serialization.Encoding.X962, self.hil.serialization.PublicFormat.UncompressedPoint)
            return f"OK pub={pub.hex()} id={self.device_id.hex()}"
        if cmd in ("prov-root", "prov-leaf"):
            self.state = 2
            if cmd == "prov-leaf":
                ticket = bytes.fromhex(rest.split()[2])
                f = self.ticket_fields(ticket)
                self.domain, self.assign, self.membership = f[3], f[6], LM_ACTIVE  # joined at once in this fake
            return "OK"
        if cmd == "status":
            return (f"OK role={self.role} membership={self.membership}(st0) reason=0 assign={self.assign} memb=1 "
                    f"conn=1(st0) depth=1 id={self.device_id.hex()} domain={self.domain.hex()}")
        if cmd == "nonce":
            return f"OK nonce={self.nonce.hex()}"
        if cmd == "ticket":  # lm_install_control(3): what Membership::install_ticket checks of a member's ticket
            f = self.ticket_fields(bytes.fromhex(rest))
            if f[0] != self.device_id or f[2] != self.domain or f[5] != self.assign or (f[8] == 0 and f[9] != self.nonce):
                return "ERR 5"
            self.ticket = bytes.fromhex(rest)
            return "OK op=7"
        if cmd == "op":
            return "OK phase=3 outcome=2 reason=0 evidence=0x0"
        if cmd == "join" and rest == "transfer":
            assert self.ticket is not None
            f = self.ticket_fields(self.ticket)
            self.domain, self.assign = f[3], f[6]
            return "OK op=9"
        raise AssertionError(f"unexpected console command {line!r}")


@pytest.fixture
def hil(tmp_path, monkeypatch):
    monkeypatch.setenv("LEANMESH_HIL_DIR", str(tmp_path / "bench"))
    monkeypatch.setenv("LEANMESH_HIL_SOCK", str(tmp_path / "lm.sock"))
    spec = importlib.util.spec_from_file_location("hil_bench_under_test", REPO / "tools/hil/hil.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    boards: dict[str, FakeDevice] = {}

    class FakeBoard:
        def __init__(self, port: str) -> None:
            roles = {"root": "root", "rootb": "root"}
            boards.setdefault(port, FakeDevice(mod, port, roles.get(port, "leaf")))
            self.dev = boards[port]

        def command(self, line: str, seconds: float = 10.0, echo: bool = True) -> str:
            return self.dev.command(line)

    monkeypatch.setattr(mod, "Board", FakeBoard)
    mod.boards = boards
    yield mod
    sys.modules.pop(spec.name, None)


def run(hil, *argv: str) -> None:
    sys.argv = ["hil.py", *argv]
    assert hil.main() == 0


def bench(hil, with_b: bool = True) -> None:
    run(hil, "init")
    run(hil, "provision", "root", "--port", "root")
    run(hil, "provision", "leaf", "--port", "leafport")
    if with_b:
        run(hil, "init", "--name", "netB")
        run(hil, "provision", "root", "--port", "rootb", "--net", "netB")


def test_first_network_keeps_the_original_layout(hil):
    bench(hil, with_b=False)
    state = json.loads(hil.STATE.read_text())
    assert set(state) == {"fleet_id", "domain", "host_id", "root", "leaves", "assignment", "expected_revision"}
    assert set(state["leaves"]["leaf1"]) == {"device", "port", "role", "dc"}
    names = {p.name for p in hil.OBJECTS.iterdir()}
    assert {"root-device.cose", "root-delegation.cose", "leaf1-device.cose", "leaf1-ticket.cose",
            "leaf1-expected-00.cose"} <= names
    assert (hil.HIL_DIR / "usb-kit.cbor").exists() and not list(hil.HIL_DIR.glob("usb-kit-*"))


def test_state_of_an_older_bench_is_still_usable(hil):
    bench(hil, with_b=False)
    state = json.loads(hil.STATE.read_text())
    state["leaves"]["leaf1"].pop("dc")  # records written before `dc` existed
    hil.save_state(state)
    net, leaf = hil.find_leaf(hil.load_state(), "leaf1")
    assert net.name is None and net["domain"] == state["domain"] and "dc" not in leaf
    run(hil, "init", "--name", "netB")  # a further network can be added to it
    assert hil.load_state()["nets"]["netB"]["leaves"] == {}


def test_second_network_shares_the_fleet_and_has_its_own_domain_host_and_objects(hil):
    bench(hil)
    state = json.loads(hil.STATE.read_text())
    b = state["nets"]["netB"]
    assert set(b) == {"domain", "host_id", "root", "leaves", "assignment", "expected_revision"}
    assert b["domain"] != state["domain"] and b["host_id"] and b["host_id"] != state["host_id"]
    assert b["root"]["port"] == "rootb" and state["root"]["port"] == "root"
    kit = hil.HIL_DIR / "usb-kit-netB.cbor"
    assert stat.S_IMODE(kit.stat().st_mode) == 0o600
    assert cbor_decode(kit.read_bytes())[3] == bytes.fromhex(b["domain"])
    delegation = (hil.OBJECTS / "netB-root-delegation.cose").read_bytes()
    iss, meta = hil.issuer()
    assert iss.open(delegation, 2, 448)[0] == bytes.fromhex(b["domain"])  # same fleet signs both
    assert iss.open((hil.OBJECTS / "root-delegation.cose").read_bytes(), 2, 448)[0] == bytes.fromhex(state["domain"])
    with pytest.raises(SystemExit):
        run(hil, "init", "--name", "netB")
    with pytest.raises(SystemExit):
        run(hil, "init", "--name", "bad name")
    with pytest.raises(SystemExit):
        run(hil, "provision", "root", "--port", "x", "--net", "nope")


def test_host_env_is_per_network(hil, capsys):
    bench(hil)
    capsys.readouterr()
    run(hil, "host-env")
    first = capsys.readouterr().out
    run(hil, "host-env", "--net", "netB")
    second = capsys.readouterr().out
    assert "host.db" in first and "usb-kit.cbor" in first and "LEANMESH_SERIAL=root " in first
    assert "host-netB.db" in second and "usb-kit-netB.cbor" in second and "LEANMESH_SERIAL=rootb " in second
    assert "lm.sock" in first and "lm-netB.sock" in second  # two Hosts, two sockets


@pytest.mark.parametrize("flags", [[], ["--grant"]], ids=["mode0-nonce", "mode1-grant"])
def test_transfer_issues_a_ticket_the_board_accepts_and_moves_the_record(hil, flags, monkeypatch):
    bench(hil)
    approvals = []
    monkeypatch.setattr(hil, "approve_pending", lambda net, device=None, print_none=False: approvals.append(
        (net.name, device)) or 0)
    state = json.loads(hil.STATE.read_text())
    leaf_dev = hil.boards["leafport"]
    assert leaf_dev.domain == bytes.fromhex(state["domain"]) and leaf_dev.assign == 1
    run(hil, "transfer", "leaf1", "--to", "netB", *flags, "--timeout", "5")
    after = json.loads(hil.STATE.read_text())
    assert "leaf1" not in after["leaves"] and after["nets"]["netB"]["leaves"]["leaf1"]["assignment"] == 2
    assert after["nets"]["netB"]["leaves"]["leaf1"]["transfer"]["from"] is None
    assert leaf_dev.domain == bytes.fromhex(after["nets"]["netB"]["domain"]) and leaf_dev.assign == 2
    assert ("nonce" in leaf_dev.log) == (not flags)  # --grant never asks the board for its nonce
    assert approvals == []  # the board was ACTIVE in B on the first look: nothing to approve
    # The stored ticket: A -> B, the board's current assignment, bound to the DeviceCredential and B's delegation.
    ticket = (hil.OBJECTS / "leaf1-transfer-to-netB.cose").read_bytes()
    f = leaf_dev.ticket_fields(ticket)
    assert (f[2], f[3], f[5], f[6]) == (bytes.fromhex(after["domain"]), bytes.fromhex(after["nets"]["netB"]["domain"]),
                                        1, 2)
    assert f[8] == (1 if flags else 0) and (flags or f[9] == leaf_dev.nonce)
    assert not (hil.OBJECTS / "leaf1-transfer-to-netB-expected.cose").exists()  # no --preapproved: no page


def test_transfer_preapproved_installs_the_target_expected_set(hil, monkeypatch):
    bench(hil)
    installed = []
    monkeypatch.setattr(hil, "install_control", lambda net, cose: installed.append((net.name, cose)) or {"state": "FINAL"})
    run(hil, "transfer", "leaf1", "--to", "netB", "--grant", "--preapproved", "--timeout", "5")
    state = json.loads(hil.STATE.read_text())
    assert state["nets"]["netB"]["expected_revision"] == 1  # a revision is never used twice
    page = (hil.OBJECTS / "leaf1-transfer-to-netB-expected.cose").read_bytes()
    assert installed == [("netB", page)]
    iss, _ = hil.issuer()
    domain, revision, data = iss.open(page, 5, 1024)
    assert (domain, revision) == (bytes.fromhex(state["nets"]["netB"]["domain"]), 1)
    ticket = (hil.OBJECTS / "leaf1-transfer-to-netB.cose").read_bytes()
    assert data[3][0][2] == hil.sha256(ticket).digest()  # the page grants exactly this ticket
    # Reconcile: the same ticket goes to the OLD network's Host.
    installed.clear()
    run(hil, "reconcile", "leaf1")
    assert installed == [(None, ticket)]


@pytest.mark.parametrize("case", ["same-network", "no-target-root", "not-active", "wrong-domain", "unknown-leaf",
                                  "unknown-network"])
def test_transfer_refusals_touch_nothing(hil, case):
    bench(hil)
    args = ["leaf1", "--to", "netB"]
    leaf_dev = hil.boards["leafport"]
    if case == "same-network":
        run(hil, "transfer", *args, "--grant", "--timeout", "5")  # it moves; moving it there again is refused
    elif case == "no-target-root":
        state = json.loads(hil.STATE.read_text())
        state["nets"]["netB"]["root"] = None
        hil.save_state(state)
    elif case == "not-active":
        leaf_dev.membership = 3
    elif case == "wrong-domain":
        leaf_dev.domain = bytes(range(16))
    elif case == "unknown-leaf":
        args = ["ghost", "--to", "netB"]
    else:
        args = ["leaf1", "--to", "netC"]
    before = hil.STATE.read_text()
    log = list(leaf_dev.log)
    with pytest.raises(SystemExit):
        run(hil, "transfer", *args, "--grant", "--timeout", "5")
    assert hil.STATE.read_text() == before
    assert "ticket" not in leaf_dev.log[len(log):] and "join" not in leaf_dev.log[len(log):]


def test_networks_are_listed_first_network_first(hil):
    bench(hil)
    assert [n.name for n in hil.all_nets(hil.load_state())] == [None, "netB"]
