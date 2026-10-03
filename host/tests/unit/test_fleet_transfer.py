"""Transfer-ticket issuing (docs/07 §8): field layout, bindings and refusals, without the native driver.

The layout is the one of tools/lmfleet/fleet.cpp Fleet::ticket and member::decode_assignment_ticket;
host/tests/integration/test_fleet_issuer.py hands the same objects to the real SDK.
"""

from __future__ import annotations

from hashlib import sha256

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from leanmesh_fleet.issuer import ZERO_DOMAIN, Issuer
from leanmesh_fleet.keys import key_id
from leanmesh_host.wire.cbor import cbor_decode, cbor_encode
from leanmesh_host.wire.control import U63, decode_control_body, decode_cose_sign1

DOMAIN_A = bytes.fromhex("aa" * 16)
DOMAIN_B = bytes.fromhex("bb" * 16)
NONCE = bytes(range(16))


def pair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def world():
    issuer = Issuer(b"f" * 16, pair())
    leaf, root_b = pair(), pair()
    dc = issuer.device(leaf.public_key(), "leaf-01", 1)
    delegation_b = issuer.root(root_b.public_key(), DOMAIN_B, 1, 15)
    return issuer, dc, delegation_b, key_id(leaf.public_key()), key_id(root_b.public_key())


def ticket_of(files: dict[str, bytes], device: bytes) -> bytes:
    return files[f"ticket-{device.hex()}.cose"]


@pytest.mark.parametrize("nonce", [NONCE, None])
def test_ticket_layout_matches_fleet_ticket(world, nonce):
    issuer, dc, delegation, device, _ = world
    files = issuer.transfer(dc, DOMAIN_A, delegation, 3, 7, nonce=nonce)
    assert set(files) == {f"ticket-{device.hex()}.cose"}  # no ExpectedSet unless asked
    ticket = files[f"ticket-{device.hex()}.cose"]
    signed = decode_cose_sign1(ticket)
    body = decode_control_body(signed.payload, "signed")
    # Envelope: type 3, the TARGET domain, revision = the new generation, issued by the fleet key.
    assert (body.type, body.domain, body.revision, body.issuer) == (3, DOMAIN_B, 7, issuer.kid)
    f = cbor_decode(body.data)
    assert len(f) == 11
    assert f[0] == device and f[1] == issuer.fleet
    assert f[2] == DOMAIN_A and f[3] == DOMAIN_B
    assert f[4] == sha256(delegation).digest()  # the TARGET root's delegation
    assert (f[5], f[6]) == (3, 7)  # expected_old, new_generation
    assert len(f[7]) == 16 and any(f[7])  # grant id
    assert f[8] == (0 if nonce is not None else 1)  # mode
    assert len(f[9]) == 16 and (f[9] == nonce if nonce is not None else f[9] != bytes(16))
    assert f[10] == sha256(dc).digest()  # the DeviceCredential COSE
    assert issuer.open(ticket, 3, 1024)[0] == DOMAIN_B  # signature verifies under the fleet key


def test_mode1_grants_and_filler_are_fresh_and_mode0_nonce_is_verbatim(world):
    issuer, dc, delegation, device, _ = world
    a = cbor_decode(decode_control_body(decode_cose_sign1(
        ticket_of(issuer.transfer(dc, DOMAIN_A, delegation, 1, 2, nonce=None), device)).payload, "signed").data)
    b = cbor_decode(decode_control_body(decode_cose_sign1(
        ticket_of(issuer.transfer(dc, DOMAIN_A, delegation, 1, 2, nonce=None), device)).payload, "signed").data)
    assert a[7] != b[7] and a[9] != b[9]  # a new grant per issue, never reused
    assert a[7] != a[9]
    c = cbor_decode(decode_control_body(decode_cose_sign1(
        ticket_of(issuer.transfer(dc, DOMAIN_A, delegation, 1, 2, nonce=NONCE), device)).payload, "signed").data)
    assert c[9] == NONCE and c[7] not in (a[7], b[7])


def test_expected_set_page_grants_exactly_this_ticket(world):
    issuer, dc, delegation, device, _ = world
    files = issuer.transfer(dc, DOMAIN_A, delegation, 1, 2, nonce=None, expected_revision=5)
    assert set(files) == {f"ticket-{device.hex()}.cose", "expected-00.cose"}
    domain, revision, page = issuer.open(files["expected-00.cose"], 5, 1024)
    entries = [[device, 2, sha256(ticket_of(files, device)).digest(), True]]
    assert (domain, revision) == (DOMAIN_B, 5)
    # Same format as admission(): [page, pages, set hash, entries]; the hash covers [domain, revision, entries].
    assert page == [0, 1, sha256(cbor_encode([DOMAIN_B, 5, entries])).digest(), entries]


def test_maximum_generations_fit_the_sdk_limits(world):
    issuer, dc, delegation, device, _ = world
    files = issuer.transfer(dc, DOMAIN_A, delegation, U63 - 1, U63, nonce=NONCE, expected_revision=U63)
    assert all(len(v) <= 1024 for v in files.values())
    assert issuer.open(ticket_of(files, device), 3, 1024)[1] == U63


@pytest.mark.parametrize("case", [
    "source-zero", "source-short", "source-is-target", "expected-old-zero", "new-not-above", "new-below",
    "new-too-large", "generation-bool", "nonce-short", "nonce-long", "nonce-str", "revision-zero",
    "source-str",
])
def test_invalid_parameters_are_refused(world, case):
    issuer, dc, delegation, _, _ = world
    args = dict(source=DOMAIN_A, old=1, new=2, nonce=NONCE, revision=None)
    args.update({
        "source-zero": dict(source=ZERO_DOMAIN), "source-short": dict(source=DOMAIN_A[:15]),
        "source-is-target": dict(source=DOMAIN_B), "expected-old-zero": dict(old=0),
        "new-not-above": dict(old=2, new=2), "new-below": dict(old=3, new=2),
        "new-too-large": dict(new=U63 + 1), "generation-bool": dict(old=True),
        "nonce-short": dict(nonce=bytes(15)), "nonce-long": dict(nonce=bytes(17)),
        "nonce-str": dict(nonce="00" * 16), "revision-zero": dict(revision=0),
        "source-str": dict(source="aa" * 16),
    }[case])
    with pytest.raises(ValueError):
        issuer.transfer(dc, args["source"], delegation, args["old"], args["new"], nonce=args["nonce"],
                        expected_revision=args["revision"])


@pytest.mark.parametrize("case", [
    "foreign-device", "corrupt-device", "trailing-device", "root-as-device", "no-approve", "foreign-root",
    "corrupt-root", "zero-domain-root", "device-as-delegation", "delegation-as-device", "empty-device",
])
def test_unauthorized_or_inconsistent_inputs_are_refused(world, case):
    issuer, dc, delegation, _, root_key = world
    rogue = Issuer(b"r" * 16, pair())
    root_pub = pair().public_key()
    if case == "foreign-device":
        dc = rogue.device(pair().public_key(), "leaf", 1)
    elif case == "corrupt-device":
        dc = dc[:-1] + bytes([dc[-1] ^ 1])
    elif case == "trailing-device":
        dc += b"\0"
    elif case == "root-as-device":
        # The target root's own DeviceCredential: it cannot be moved into its own domain.
        root_pair = pair()
        delegation = issuer.root(root_pair.public_key(), DOMAIN_B, 1, 15)
        dc = issuer.device(root_pair.public_key(), "root-b", 1)
    elif case == "no-approve":
        delegation = issuer.root(root_pub, DOMAIN_B, 1, 2)  # revoke only: it could not admit anybody
    elif case == "foreign-root":
        delegation = rogue.root(root_pub, DOMAIN_B, 1, 15)
    elif case == "corrupt-root":
        delegation = delegation[:-1] + bytes([delegation[-1] ^ 1])
    elif case == "zero-domain-root":
        delegation = issuer.root(root_pub, DOMAIN_B, 1, 15)
        domain, rev, data = issuer.open(delegation, 2, 448)
        delegation = issuer._sign(2, ZERO_DOMAIN, rev, [*data[:3], ZERO_DOMAIN, *data[4:]], 448)
    elif case == "device-as-delegation":
        delegation = dc
    elif case == "delegation-as-device":
        dc = delegation
    else:
        dc = b""
    with pytest.raises((ValueError, InvalidSignature)):
        issuer.transfer(dc, DOMAIN_A, delegation, 1, 2, nonce=NONCE)


def test_device_credential_binding_is_checked_not_trusted(world):
    issuer, dc, delegation, _, _ = world
    # Valid fleet signature over a DeviceCredential whose CCS hash is wrong: refused like admission().
    domain, rev, data = issuer.open(dc, 1, 448)
    data[5] = bytes(32)
    bad = issuer._sign(1, domain, rev, data, 448)
    with pytest.raises(ValueError, match="binding"):
        issuer.transfer(bad, DOMAIN_A, delegation, 1, 2, nonce=NONCE)
