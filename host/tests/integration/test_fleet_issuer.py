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


def driver(tmp_path, fleet, objects, mode="verify"):
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
    native = Path(os.environ.get("LEANMESH_NATIVE_BUILD", Path.home() / ".cache/leanmesh/native"))
    binary = Path(os.environ.get("LEANMESH_ISSUER_DRIVER", native / "tests/native/issuer_driver"))
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


def cli(*args):
    return subprocess.run([sys.executable, "-m", "leanmesh_fleet", *map(str, args)],
                          cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO / "host")},
                          capture_output=True, text=True, timeout=30)


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
