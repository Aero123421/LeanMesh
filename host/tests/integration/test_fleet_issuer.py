"""Offline issuer custody, refusal cases and independent SDK/PSA/EDHOC interoperability.

All keys are freshly generated ephemeral test material. Plain scalars exist only in a 0700
pytest fixture directory for the simulation driver; no firmware/real device is provisioned.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from leanmesh_fleet import keys
from leanmesh_fleet.issuer import Issuer
from leanmesh_host.wire.cbor import cbor_encode
from leanmesh_host.wire.control import U63

PASSWORD = b"ephemeral test passphrase"
REPO = Path(__file__).resolve().parents[3]


@pytest.fixture
def fleet(tmp_path):
    store = tmp_path / "fleet"
    meta = keys.initialize(store, "test", PASSWORD)
    _, key = keys.load(store, "test", PASSWORD)
    return store, meta, Issuer(bytes.fromhex(meta["fleet_id"]), key)


@pytest.fixture
def objects(fleet):
    _, _, issuer = fleet
    root = ec.generate_private_key(ec.SECP256R1())
    leaf = ec.generate_private_key(ec.SECP256R1())
    dc = issuer.device(leaf.public_key(), "leaf-01", 1)
    delegation = issuer.root(root.public_key(), bytes.fromhex("12" * 16), 1, 15)
    batch = issuer.admission([dc], delegation, 1, 1)
    return root, leaf, dc, delegation, batch


def native_binary():
    native = Path(os.environ.get("LEANMESH_NATIVE_BUILD", Path.home() / ".cache/leanmesh/native"))
    return Path(os.environ.get("LEANMESH_ISSUER_DRIVER", native / "tests/native/issuer_driver"))


def prepare(tmp_path, fleet, objects):
    _, meta, issuer = fleet
    root, leaf, dc, delegation, batch = objects
    folder = tmp_path / "driver"
    folder.mkdir(mode=0o700, exist_ok=True)
    data = {
        "fleet.pub": issuer.key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        ),
        "fleet.id": bytes.fromhex(meta["fleet_id"]),
        "root.cose": issuer.device(root.public_key(), "root-01", 1),
        "leaf.cose": dc,
        "delegation.cose": delegation,
        "ticket.cose": batch[f"ticket-{keys.key_id(leaf.public_key()).hex()}.cose"],
        "expected.cose": batch["expected-00.cose"],
        "root.scalar": root.private_numbers().private_value.to_bytes(32, "big"),
        "leaf.scalar": leaf.private_numbers().private_value.to_bytes(32, "big"),
    }
    for name, value in data.items():
        p = folder / name
        p.write_bytes(value)
        p.chmod(0o600)
    return folder


def driver(tmp_path, fleet, objects, mode="verify"):
    folder = prepare(tmp_path, fleet, objects)
    binary = native_binary()
    # Missing build output is a failure, never a skip (same policy as the existing Host harness).
    result = subprocess.run([str(binary), mode, str(folder)], capture_output=True, text=True,
                            timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "OK"
    return binary, folder


def test_random_key_store_encryption_permissions_and_no_replacement(tmp_path):
    a = keys.initialize(tmp_path / "a", "test", PASSWORD)
    b = keys.initialize(tmp_path / "b", "test", PASSWORD)
    assert a["key_id"] != b["key_id"] and a["fleet_id"] != b["fleet_id"]
    assert stat.S_IMODE((tmp_path / "a").stat().st_mode) == 0o700
    pem = (tmp_path / "a/fleet-key.pem").read_bytes()
    assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(pem, password=None)
    assert stat.S_IMODE((tmp_path / "a/fleet-key.pem").stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        keys.initialize(tmp_path / "a", "production", PASSWORD)
    assert (tmp_path / "a/fleet-key.pem").read_bytes() == pem


@pytest.mark.parametrize("environment,password", [("production", PASSWORD), ("test", b"wrong password")])
def test_store_refuses_environment_or_password_mismatch(fleet, environment, password):
    with pytest.raises(ValueError):
        keys.load(fleet[0], environment, password)


@pytest.mark.parametrize("target,mode", [("", 0o755), ("fleet-key.pem", 0o644), ("fleet.json", 0o644)])
def test_store_refuses_shared_directory_and_files(fleet, target, mode):
    path = fleet[0] / target if target else fleet[0]
    path.chmod(mode)
    with pytest.raises(ValueError):
        keys.load(fleet[0], "test", PASSWORD)


@pytest.mark.parametrize("link", ["directory", "symlink", "hardlink"])
def test_store_refuses_links(tmp_path, fleet, link):
    store = fleet[0]
    if link == "directory":
        alias = tmp_path / "alias"
        alias.symlink_to(store, target_is_directory=True)
        store = alias
    else:
        original = store / "fleet-key.pem"
        copy = tmp_path / "original.pem"
        original.rename(copy)
        if link == "symlink":
            original.symlink_to(copy)
        else:
            os.link(copy, original)
    with pytest.raises((ValueError, OSError)):
        keys.load(store, "test", PASSWORD)


def test_store_refuses_plaintext_key_and_metadata_key_mismatch(fleet):
    store, _, issuer = fleet
    p = store / "fleet-key.pem"
    encrypted = p.read_bytes()
    p.write_bytes(issuer.key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    with pytest.raises(ValueError, match="encrypted"):
        keys.load(store, "test", PASSWORD)
    p.write_bytes(encrypted)
    meta_path = store / "fleet.json"
    meta = json.loads(meta_path.read_bytes())
    meta["key_id"] = "00" * 32
    meta_path.write_text(json.dumps(meta))
    with pytest.raises(ValueError, match="metadata"):
        keys.load(store, "test", PASSWORD)


def test_output_never_follows_links_or_overwrites(tmp_path):
    target = tmp_path / "object"
    keys.write_new(target, b"original")
    for p in (target, tmp_path / "alias"):
        if p != target:
            p.symlink_to(target)
        with pytest.raises(FileExistsError):
            keys.write_new(p, b"replacement")
    assert target.read_bytes() == b"original"


@pytest.mark.parametrize("serial", ["", "x" * 49, "日本語", "line\nbreak", "\x7f"])
def test_invalid_serial_refused(fleet, serial):
    with pytest.raises(ValueError):
        fleet[2].device(ec.generate_private_key(ec.SECP256R1()).public_key(), serial, 1)


@pytest.mark.parametrize("generation", [0, -1, U63 + 1, True])
def test_invalid_generation_refused(fleet, generation):
    with pytest.raises(ValueError):
        fleet[2].device(ec.generate_private_key(ec.SECP256R1()).public_key(), "leaf", generation)


@pytest.mark.parametrize("domain,permissions", [(bytes(16), 15), (b"short", 15), (b"1" * 16, 16)])
def test_invalid_domain_and_unimplemented_permissions_refused(fleet, domain, permissions):
    with pytest.raises(ValueError):
        fleet[2].root(ec.generate_private_key(ec.SECP256R1()).public_key(), domain, 1, permissions)


def test_wrong_curve_refused(fleet):
    with pytest.raises(ValueError, match="P-256"):
        fleet[2].device(ec.generate_private_key(ec.SECP384R1()).public_key(), "leaf", 1)


@pytest.mark.parametrize("bad_input", ["foreign", "corrupt", "trailing", "root-corrupt", "no-approve",
                                        "duplicate", "root-as-member", "empty", "too-many"])
def test_admission_refuses_invalid_or_unauthorized_inputs(fleet, objects, bad_input):
    issuer = fleet[2]
    root, leaf, dc, delegation, _ = objects
    devices = [dc]
    if bad_input == "foreign":
        rogue = Issuer(b"r" * 16, ec.generate_private_key(ec.SECP256R1()))
        devices = [rogue.device(leaf.public_key(), "leaf", 1)]
    elif bad_input == "corrupt":
        devices = [dc[:-1] + bytes([dc[-1] ^ 1])]
    elif bad_input == "trailing":
        devices = [dc + b"\0"]
    elif bad_input == "root-corrupt":
        delegation = delegation[:-1] + bytes([delegation[-1] ^ 1])
    elif bad_input == "no-approve":
        delegation = issuer.root(root.public_key(), b"1" * 16, 1, 2)
    elif bad_input == "duplicate":
        devices = [dc, dc]
    elif bad_input == "root-as-member":
        devices = [issuer.device(root.public_key(), "root", 1)]
    elif bad_input == "empty":
        devices = []
    else:
        devices = [dc] * 65
    with pytest.raises((ValueError, InvalidSignature)):
        issuer.admission(devices, delegation, 1, 1)


def test_sdk_verifies_generated_credentials_ticket_and_expected_page(tmp_path, fleet, objects):
    driver(tmp_path, fleet, objects)


def test_sdk_joins_with_generated_initial_assignment(tmp_path, fleet, objects):
    driver(tmp_path, fleet, objects, "join")


@pytest.mark.parametrize("object_name", ["root.cose", "leaf.cose", "delegation.cose", "ticket.cose",
                                         "expected.cose"])
def test_sdk_refuses_modified_signature(tmp_path, fleet, objects, object_name):
    binary, folder = driver(tmp_path, fleet, objects)
    p = folder / object_name
    raw = p.read_bytes()
    p.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    result = subprocess.run([str(binary), "verify", str(folder)], capture_output=True, timeout=30)
    assert result.returncode == 1
    assert b"AUTH_REJECTED" in result.stdout


@pytest.mark.parametrize("count", [1, 8, 9, 64])
def test_batch_paging_hashes_grants_and_exact_sdk_limits(tmp_path, fleet, objects, count):
    issuer = fleet[2]
    delegation = objects[3]
    devices = [issuer.device(ec.generate_private_key(ec.SECP256R1()).public_key(), f"leaf-{i}", 1)
               for i in range(count)]
    files = issuer.admission(devices, delegation, U63, U63)
    tickets = [v for n, v in files.items() if n.startswith("ticket-")]
    pages = [issuer.open(v, 5, 1024)[2] for n, v in files.items() if n.startswith("expected-")]
    assert len(tickets) == count and len(pages) == (count + 7) // 8
    assert all(len(v) <= 1024 for v in files.values())
    assert [p[0] for p in pages] == list(range(len(pages)))
    assert all(p[1] == len(pages) and len(p[3]) <= 8 for p in pages)
    assert len({p[2] for p in pages}) == 1
    rows = [row for p in pages for row in p[3]]
    domain = issuer.open(delegation, 2, 448)[0]
    assert pages[0][2] == sha256(cbor_encode([domain, U63, rows])).digest()
    assert {row[2] for row in rows} == {sha256(t).digest() for t in tickets}
    grants = [issuer.open(t, 3, 1024)[2][7] for t in tickets]
    assert len(set(grants)) == count


def test_sdk_verifies_every_page_of_full_batch(tmp_path, fleet, objects):
    issuer = fleet[2]
    root, _, _, delegation, _ = objects
    private = [ec.generate_private_key(ec.SECP256R1()) for _ in range(64)]
    creds = {keys.key_id(k.public_key()): issuer.device(k.public_key(), f"leaf-{i}", 1)
             for i, k in enumerate(private)}
    scalars = {keys.key_id(k.public_key()): k for k in private}
    batch = issuer.admission(list(creds.values()), delegation, U63, U63)
    for page in range(8):
        expected = batch[f"expected-{page:02d}.cose"]
        device = issuer.open(expected, 5, 1024)[2][3][0][0]
        selected = {f"ticket-{device.hex()}.cose": batch[f"ticket-{device.hex()}.cose"],
                    "expected-00.cose": expected}
        driver(tmp_path, fleet, (root, scalars[device], creds[device], delegation, selected))


@pytest.mark.parametrize("binding", ["device-key", "ccs-hash", "fleet", "ticket-device",
                                     "ticket-credential", "ticket-delegation", "expected-grant"])
def test_sdk_refuses_valid_signature_with_wrong_semantic_binding(tmp_path, fleet, objects, binding):
    issuer = fleet[2]
    binary, folder = driver(tmp_path, fleet, objects)
    if binding in {"device-key", "ccs-hash", "fleet"}:
        path, typ = folder / "leaf.cose", 1
        index = {"device-key": 0, "ccs-hash": 5, "fleet": 2}[binding]
    elif binding.startswith("ticket-"):
        path, typ = folder / "ticket.cose", 3
        index = {"ticket-device": 0, "ticket-credential": 10, "ticket-delegation": 4}[binding]
    else:
        path, typ, index = folder / "expected.cose", 5, None
    domain, revision, data = issuer.open(path.read_bytes(), typ, 1024)
    if index is None:
        data[3][0][2] = bytes(32)
    else:
        data[index] = bytes(len(data[index]))
    path.write_bytes(issuer._sign(typ, domain, revision, data, 1024))
    result = subprocess.run([str(binary), "verify", str(folder)], capture_output=True, timeout=30)
    assert result.returncode == 1 and b"OK" not in result.stdout


def cli(*args, input=None):
    return subprocess.run([sys.executable, "-m", "leanmesh_fleet", *map(str, args)],
                          cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO / "host")},
                          capture_output=True, text=True, timeout=30, input=input)


def test_cli_generates_complete_batch_without_secrets_or_overwrite(tmp_path):
    password = tmp_path / "passphrase"
    keys.write_new(password, PASSWORD + b"\n")
    store = tmp_path / "fleet"
    args = ["--store", store, "--environment", "test", "--password-file", password]
    result = cli("init", *args)
    assert result.returncode == 0, result.stderr
    meta = json.loads(result.stdout)
    assert set(meta) == {"fleet_id", "key_id", "environment"}
    public = tmp_path / "public.pem"
    dc = tmp_path / "device.cose"
    rd = tmp_path / "root.cose"
    private = []
    for command, output, extra in [("device", dc, ["--serial", "leaf-01"]),
                                   ("root", rd, ["--domain", "12" * 16, "--permissions", "15"])]:
        key = ec.generate_private_key(ec.SECP256R1())
        private.append(key)
        public.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        result = cli(command, *args, "--public-key", public, "--generation", 1,
                     "--output", output, *extra)
        assert result.returncode == 0, result.stderr
    out = tmp_path / "batch"
    admission = ["admit", *args, "--device-credential", dc, "--root-delegation", rd,
                 "--assignment", 1, "--expected-revision", 1, "--output-dir", out]
    result = cli(*admission)
    assert result.returncode == 0, result.stderr
    manifest = json.loads((out / "manifest.json").read_bytes())
    assert manifest["environment"] == "test" and len(manifest["files"]) == 2
    for name, digest in manifest["files"].items():
        assert sha256((out / name).read_bytes()).hexdigest() == digest
    saved_meta, saved_key = keys.load(store, "test", PASSWORD)
    saved_issuer = Issuer(bytes.fromhex(saved_meta["fleet_id"]), saved_key)
    batch = {name: (out / name).read_bytes() for name in manifest["files"]}
    driver(tmp_path, (store, saved_meta, saved_issuer),
           (private[1], private[0], dc.read_bytes(), rd.read_bytes(), batch), "join")
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    assert cli(*admission).returncode == 1
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before
    bad_args = ["--store", store, "--environment", "production", "--password-file", password]
    result = cli("device", *bad_args, "--public-key", public, "--serial", "leaf", "--generation", 1,
                 "--output", tmp_path / "must-not-exist")
    assert result.returncode == 1 and not (tmp_path / "must-not-exist").exists()
    assert "Traceback" not in result.stderr and PASSWORD.decode() not in result.stderr


def test_cli_refuses_readable_password_file_before_creating_store(tmp_path):
    password = tmp_path / "passphrase"
    password.write_bytes(PASSWORD)
    password.chmod(0o644)
    result = cli("init", "--store", tmp_path / "fleet", "--environment", "test",
                 "--password-file", password)
    assert result.returncode == 1 and not (tmp_path / "fleet").exists()
    assert "Traceback" not in result.stderr and PASSWORD.decode() not in result.stderr


def test_cli_refuses_unprotected_stdin_password_before_creating_store(tmp_path):
    result = cli("init", "--store", tmp_path / "fleet", "--environment", "test",
                 input=(PASSWORD.decode() + "\n") * 2)
    assert result.returncode == 1 and not (tmp_path / "fleet").exists()
    assert "GetPassWarning" not in result.stderr and PASSWORD.decode() not in result.stderr


# ---- transfer ticket (docs/07 §8): Python-issued, verified and executed by the SDK in simulation ----

DOMAIN_B = bytes.fromhex("34" * 16)
DOMAIN_C = bytes.fromhex("56" * 16)


@pytest.fixture
def move(fleet):
    """Domain B: its root key, the root's DeviceCredential and its RootDelegation."""
    issuer = fleet[2]
    root_b = ec.generate_private_key(ec.SECP256R1())
    return (root_b, issuer.device(root_b.public_key(), "root-b", 1),
            issuer.root(root_b.public_key(), DOMAIN_B, 1, 15))


def issue_move(issuer, dc, domain_a, delegation_b, nonce):
    """The ticket and ExpectedSet for A -> B, plus the two tickets the device must refuse."""
    device = issuer._device(dc)[0]
    files = issuer.transfer(dc, domain_a, delegation_b, 1, 2, nonce=nonce, expected_revision=1)
    if nonce is None:  # a ticket from another source domain than the device's
        foreign = issuer.transfer(dc, DOMAIN_C, delegation_b, 1, 2, nonce=None)
    else:  # the right transfer under a nonce this device never issued
        foreign = issuer.transfer(dc, domain_a, delegation_b, 1, 2, nonce=os.urandom(16))
    stale = issuer.transfer(dc, domain_a, delegation_b, 5, 6, nonce=nonce)  # not the device's assignment (1)
    return {"transfer.cose": files[f"ticket-{device.hex()}.cose"], "expected-b.cose": files["expected-00.cose"],
            "foreign.cose": foreign[f"ticket-{device.hex()}.cose"],
            "stale.cose": stale[f"ticket-{device.hex()}.cose"]}


def run_transfer(tmp_path, fleet, objects, move, *, nonce_mode, issue=None, tamper=None):
    """The sim run: leaf joins A, A is powered off, the ticket moves it to B. -> (returncode, stdout, stderr)."""
    issuer = fleet[2]
    _, _, dc, delegation, _ = objects
    root_b, rootb_cose, delegation_b = move
    folder = prepare(tmp_path, fleet, objects)
    domain_a = issuer.open(delegation, 2, 448)[0]

    def put(files):
        for name, value in files.items():
            path = folder / name
            path.write_bytes(tamper[name](value) if tamper and name in tamper else value)
            path.chmod(0o600)

    put({"rootb.cose": rootb_cose, "delegation-b.cose": delegation_b,
         "rootb.scalar": root_b.private_numbers().private_value.to_bytes(32, "big")})
    issue = issue or (lambda nonce: issue_move(issuer, dc, domain_a, delegation_b, nonce))
    binary = native_binary()
    if not nonce_mode:
        put(issue(None))
        done = subprocess.run([str(binary), "transfer", str(folder)], capture_output=True, text=True, timeout=300)
        return done.returncode, done.stdout, done.stderr
    proc = subprocess.Popen([str(binary), "transfer-nonce", str(folder)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        first = proc.stdout.readline()
        if not first.startswith("NONCE "):  # the run ended before it could ask
            out, err = proc.communicate(timeout=60)
            return proc.returncode, first + out, err
        put(issue(bytes.fromhex(first.split()[1])))  # issued for the nonce the device just exported
        proc.stdin.write("GO\n")
        proc.stdin.flush()
        out, err = proc.communicate(timeout=300)
        return proc.returncode, first + out, err
    finally:
        proc.kill()


@pytest.mark.parametrize("nonce_mode", [False, True], ids=["mode1-grant", "mode0-nonce"])
def test_sdk_moves_a_device_a_to_b_with_python_issued_ticket(tmp_path, fleet, objects, move, nonce_mode):
    # The driver checks: ACTIVE in A -> A powered off -> stale/foreign/initial tickets refused at the device ->
    # ACTIVE in B at generation 2 (never in both) -> the ticket again refused -> A reconciles from the same
    # ticket and has no session with the device.
    code, out, err = run_transfer(tmp_path, fleet, objects, move, nonce_mode=nonce_mode)
    assert code == 0 and out.strip().splitlines()[-1] == "OK", out + err


@pytest.mark.parametrize("case", ["ticket-signature", "page-signature", "page-for-another-ticket"])
def test_sdk_refuses_transfer_objects_that_do_not_verify_or_grant(tmp_path, fleet, objects, move, case):
    issuer = fleet[2]
    _, _, dc, delegation, _ = objects
    domain_a = issuer.open(delegation, 2, 448)[0]

    def flip(raw):
        return raw[:-1] + bytes([raw[-1] ^ 1])

    issue, tamper = None, None
    if case == "ticket-signature":
        tamper = {"transfer.cose": flip}
    elif case == "page-signature":
        tamper = {"expected-b.cose": flip}
    else:  # a page granting an earlier issue of the same transfer: its grant hash is not this ticket's
        other = issue_move(issuer, dc, domain_a, move[2], None)

        def issue(nonce):
            return {**issue_move(issuer, dc, domain_a, move[2], nonce), "expected-b.cose": other["expected-b.cose"]}
    code, out, err = run_transfer(tmp_path, fleet, objects, move, nonce_mode=False, issue=issue, tamper=tamper)
    assert code == 1 and "AUTH_REJECTED" in out and "OK" not in out.split(), out + err


def cli_key(tmp_path, args, name, command, extra, key=None):
    """Issues one object with the CLI for `key` (a new P-256 key by default); -> (key, cose path)."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    pem = tmp_path / f"{name}.pem"
    pem.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    out = tmp_path / f"{name}.cose"
    result = cli(command, *args, "--public-key", pem, "--generation", 1, "--output", out, *extra)
    assert result.returncode == 0, result.stderr
    return key, out


def cli_store(tmp_path):
    password = tmp_path / "passphrase"
    keys.write_new(password, PASSWORD + b"\n")
    args = ["--store", tmp_path / "fleet", "--environment", "test", "--password-file", password]
    assert cli("init", *args).returncode == 0
    return args


def test_cli_transfer_issues_a_complete_batch_the_sdk_executes(tmp_path):
    args = cli_store(tmp_path)
    leaf, dc = cli_key(tmp_path, args, "leaf", "device", ["--serial", "leaf-01"])
    root_a, rd_a = cli_key(tmp_path, args, "delegation-a", "root", ["--domain", "12" * 16, "--permissions", "15"])
    root_b, rd_b = cli_key(tmp_path, args, "delegation-b", "root", ["--domain", DOMAIN_B.hex(), "--permissions", "15"])
    _, root_b_dc = cli_key(tmp_path, args, "root-b", "device", ["--serial", "root-b"], key=root_b)
    admission = tmp_path / "admission"
    assert cli("admit", *args, "--device-credential", dc, "--root-delegation", rd_a, "--assignment", 1,
               "--expected-revision", 1, "--output-dir", admission).returncode == 0
    meta, key = keys.load(tmp_path / "fleet", "test", PASSWORD)
    saved = Issuer(bytes.fromhex(meta["fleet_id"]), key)
    device = keys.key_id(leaf.public_key())
    names = json.loads((admission / "manifest.json").read_bytes())["files"]
    objects = (root_a, leaf, dc.read_bytes(), rd_a.read_bytes(), {n: (admission / n).read_bytes() for n in names})

    out = tmp_path / "transfer"
    transfer = ["transfer", *args, "--device-credential", dc, "--source-domain", "12" * 16,
                "--root-delegation", rd_b, "--expected-old", 1, "--new-generation", 2,
                "--expected-revision", 1, "--output-dir", out, "--grant"]
    result = cli(*transfer)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"output_dir": str(out), "objects": 2, "target_domain": DOMAIN_B.hex(),
                                         "mode": 1}
    manifest = json.loads((out / "manifest.json").read_bytes())
    assert (manifest["kind"], manifest["source_domain"], manifest["target_domain"], manifest["mode"]) == (
        "transfer", "12" * 16, DOMAIN_B.hex(), 1)
    assert (manifest["expected_old"], manifest["new_generation"], manifest["environment"]) == (1, 2, "test")
    assert set(manifest["files"]) == {f"ticket-{device.hex()}.cose", "expected-00.cose"}
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for name, digest in manifest["files"].items():
        assert sha256((out / name).read_bytes()).hexdigest() == digest
        assert stat.S_IMODE((out / name).stat().st_mode) == 0o600
    # A finished batch is never replaced.
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    assert cli(*transfer).returncode == 1
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before

    # The CLI's own output is what the SDK verifies and executes.
    def from_cli(nonce):
        return {**issue_move(saved, dc.read_bytes(), bytes.fromhex("12" * 16), rd_b.read_bytes(), nonce),
                "transfer.cose": (out / f"ticket-{device.hex()}.cose").read_bytes(),
                "expected-b.cose": (out / "expected-00.cose").read_bytes()}

    move_b = (root_b, root_b_dc.read_bytes(), rd_b.read_bytes())
    code, stdout, stderr = run_transfer(tmp_path, (None, meta, saved), objects, move_b, nonce_mode=False,
                                        issue=from_cli)
    assert code == 0 and stdout.strip() == "OK", stdout + stderr


@pytest.mark.parametrize("bad", [
    {"--source-domain": DOMAIN_B.hex()},                    # source == target
    {"--source-domain": "00" * 16},                         # zero source
    {"--source-domain": "12" * 15},                         # short source
    {"--nonce": "00" * 15},                                 # short nonce
    {"--nonce": "zz" * 16},                                 # not hex
    {"--expected-old": "2"},                                # new generation not above the old one
    {"--expected-old": "0"},                                # not a transfer
    {"--new-generation": str(U63 + 1)},
])
def test_cli_transfer_refuses_bad_input_and_leaves_no_directory(tmp_path, bad):
    args = cli_store(tmp_path)
    _, dc = cli_key(tmp_path, args, "leaf", "device", ["--serial", "leaf-01"])
    _, rd = cli_key(tmp_path, args, "delegation-b", "root", ["--domain", DOMAIN_B.hex(), "--permissions", "15"])
    out = tmp_path / "out"
    options = {"--source-domain": "12" * 16, "--expected-old": "1", "--new-generation": "2", "--nonce": "0f" * 16}
    options.update(bad)
    result = cli("transfer", *args, "--device-credential", dc, "--root-delegation", rd, "--output-dir", out,
                 *[x for pair in options.items() for x in pair])
    assert result.returncode == 1 and not out.exists()
    assert "Traceback" not in result.stderr and PASSWORD.decode() not in result.stderr


def test_cli_transfer_requires_exactly_one_mode(tmp_path):
    args = cli_store(tmp_path)
    _, dc = cli_key(tmp_path, args, "leaf", "device", ["--serial", "leaf-01"])
    _, rd = cli_key(tmp_path, args, "delegation-b", "root", ["--domain", DOMAIN_B.hex(), "--permissions", "15"])
    command = ["transfer", *args, "--device-credential", dc, "--source-domain", "12" * 16, "--root-delegation", rd,
               "--expected-old", 1, "--new-generation", 2]
    for index, mode in enumerate(([], ["--grant", "--nonce", "00" * 16])):
        out = tmp_path / f"out{index}"
        result = cli(*command, "--output-dir", out, *mode)
        assert result.returncode == 2 and not out.exists()  # a usage error: there is no hidden default mode
    out = tmp_path / "ok"
    result = cli(*command, "--output-dir", out, "--nonce", "0f" * 16)  # no --expected-revision: the ticket only
    assert result.returncode == 0 and json.loads(result.stdout)["mode"] == 0
    assert sorted(p.name for p in out.iterdir()) == sorted(
        [*json.loads((out / "manifest.json").read_bytes())["files"], "manifest.json"])
    assert not (out / "expected-00.cose").exists()


def test_root_handover_is_issued_for_the_replacement_root_and_the_sdk_accepts_it(tmp_path, fleet, objects):
    """Issue #5: the fleet's RootHandover for a root exchange. The SDK's own rules (another root, a higher generation, the
    new delegation's hash and generation) accept it; every refusal of the issuer is checked."""
    issuer = fleet[2]
    domain = bytes.fromhex("12" * 16)
    old_root = keys.key_id(objects[0].public_key())
    replacement = ec.generate_private_key(ec.SECP256R1())
    new_delegation = issuer.root(replacement.public_key(), domain, 2, 15)
    cose = issuer.handover(old_root, new_delegation, 1, 2)
    got_domain, revision, data = issuer.open(cose, 31, 1024)
    assert got_domain == domain and revision == 2
    assert data[1:] == [old_root, keys.key_id(replacement.public_key()), 1, 2, sha256(new_delegation).digest(), 2, 1]
    folder = tmp_path / "ho"
    folder.mkdir(mode=0o700)
    files = {"fleet.pub": issuer.key.public_key().public_bytes(serialization.Encoding.X962,
                                                             serialization.PublicFormat.UncompressedPoint),
             "fleet.id": issuer.fleet, "newdeleg.cose": new_delegation, "handover.cose": cose}
    for name, value in files.items():
        (folder / name).write_bytes(value)
    native = Path(os.environ.get("LEANMESH_NATIVE_BUILD", Path.home() / ".cache/leanmesh/native"))
    binary = Path(os.environ.get("LEANMESH_ISSUER_DRIVER", native / "tests/native/issuer_driver"))

    def sdk() -> str:
        return subprocess.run([str(binary), "handover", str(folder)], capture_output=True, text=True,
                              timeout=60).stdout.strip()

    assert sdk() == "OK"
    # the same object for another replacement delegation (a different hash), or tampered, is refused by the SDK
    other = issuer.root(replacement.public_key(), domain, 3, 15)
    (folder / "newdeleg.cose").write_bytes(other)
    assert sdk() == "NETWORK_MISMATCH"
    (folder / "newdeleg.cose").write_bytes(new_delegation)
    (folder / "handover.cose").write_bytes(cose[:-1] + bytes([cose[-1] ^ 1]))
    assert sdk() == "AUTH_REJECTED"
    with pytest.raises(ValueError):  # the old root is the new root
        issuer.handover(keys.key_id(replacement.public_key()), new_delegation, 1, 2)
    with pytest.raises(ValueError):  # the new delegation generation is not above the old one
        issuer.handover(old_root, new_delegation, 2, 2)
    with pytest.raises(ValueError):
        issuer.handover(old_root, new_delegation, 1, 0)
    with pytest.raises(ValueError):
        issuer.handover(old_root, new_delegation, 1, 2**32)
    with pytest.raises(ValueError):
        issuer.handover(old_root[:31], new_delegation, 1, 2)


def test_cli_issues_a_root_handover(tmp_path):
    password = tmp_path / "passphrase"
    keys.write_new(password, PASSWORD + b"\n")
    store = tmp_path / "fleet"
    common = ["--store", store, "--environment", "test", "--password-file", password]
    assert cli("init", *common).returncode == 0
    root = ec.generate_private_key(ec.SECP256R1())
    spare = ec.generate_private_key(ec.SECP256R1())
    pub = tmp_path / "spare.pem"
    pub.write_bytes(spare.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo))
    delegation = tmp_path / "deleg2.cose"
    assert cli("root", *common, "--public-key", pub, "--generation", 2, "--output", delegation,
               "--domain", "12" * 16, "--permissions", 15).returncode == 0
    out = tmp_path / "handover.cose"
    r = cli("handover", *common, "--old-root", keys.key_id(root.public_key()).hex(), "--new-root-delegation", delegation,
            "--old-generation", 1, "--new-term", 2, "--output", out)
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE(out.stat().st_mode) == 0o600 and json.loads(r.stdout)["sha256"] == sha256(out.read_bytes()).hexdigest()
    bad = cli("handover", *common, "--old-root", "00" * 31, "--new-root-delegation", delegation, "--old-generation", 1,
              "--new-term", 2, "--output", tmp_path / "bad.cose")
    assert bad.returncode == 1 and not (tmp_path / "bad.cose").exists()

