"""Typed LM1 initial-assignment issuer using the existing deterministic wire codecs."""

from __future__ import annotations

import secrets
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from leanmesh_host.wire.cbor import cbor_decode, cbor_encode
from leanmesh_host.wire.control import (
    U63,
    decode_control_body,
    decode_cose_sign1,
    encode_cose_sign1,
)

from .keys import key_id, public_cose, public_from_cose

ZERO_DOMAIN = bytes(16)


def positive(value: int) -> int:
    if type(value) is not int or not 1 <= value <= U63:
        raise ValueError("generation/revision must be in 1..2^63-1")
    return value


class Issuer:
    def __init__(self, fleet: bytes, key: ec.EllipticCurvePrivateKey):
        if len(fleet) != 16 or not any(fleet):
            raise ValueError("fleet id must be nonzero16")
        self.fleet = fleet
        self.key = key
        self.kid = key_id(key.public_key())

    def _sign(self, typ: int, domain: bytes, revision: int, data: list, maximum: int) -> bytes:
        positive(revision)
        body = cbor_encode([typ, 1, secrets.token_bytes(16), domain, revision, self.kid, data])
        decode_control_body(body, "signed")  # shape/range check before any signature
        prot = cbor_encode({1: -7, 4: self.kid})
        message = cbor_encode(["Signature1", prot, b"LM1-CONTROL", body])
        r, s = decode_dss_signature(self.key.sign(message, ec.ECDSA(hashes.SHA256())))
        cose = encode_cose_sign1(self.kid, body, r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        if len(cose) > maximum:
            raise ValueError("signed object exceeds SDK size limit")
        return cose

    def open(self, cose: bytes, typ: int, maximum: int) -> tuple[bytes, int, list]:
        if len(cose) > maximum:
            raise ValueError("signed object exceeds SDK size limit")
        signed = decode_cose_sign1(cose)
        body = decode_control_body(signed.payload, "signed")
        if signed.kid != self.kid or body.issuer != self.kid or body.type != typ:
            raise ValueError("object type/issuer does not match this fleet")
        sig = encode_dss_signature(int.from_bytes(signed.signature[:32], "big"),
                                  int.from_bytes(signed.signature[32:], "big"))
        self.key.public_key().verify(
            sig, cbor_encode(["Signature1", signed.protected, b"LM1-CONTROL", signed.payload]),
            ec.ECDSA(hashes.SHA256()),
        )
        positive(body.revision)
        return body.domain, body.revision, cbor_decode(body.data)

    def device(self, public: ec.EllipticCurvePublicKey, serial: str, generation: int) -> bytes:
        if not 1 <= len(serial) <= 48 or any(not 0x20 <= ord(c) <= 0x7e for c in serial):
            raise ValueError("serial must be 1..48 printable ASCII characters")
        key = public_cose(public)
        ccs = cbor_encode({2: serial, 8: {1: key}})
        return self._sign(1, ZERO_DOMAIN, generation,
                          [key_id(public), key, self.fleet, serial, generation, sha256(ccs).digest()],
                          448)

    def root(self, public: ec.EllipticCurvePublicKey, domain: bytes, generation: int,
             permissions: int) -> bytes:
        if len(domain) != 16 or not any(domain):
            raise ValueError("root domain must be nonzero16")
        # Only the four permissions implemented by the SDK; no promise of config/root-app support.
        if type(permissions) is not int or not 0 <= permissions <= 15:
            raise ValueError("permissions must contain only approve/revoke/channel/groups bits")
        return self._sign(2, domain, generation,
                          [self.fleet, key_id(public), public_cose(public), domain, generation,
                           permissions], 448)

    def _device(self, cose: bytes) -> list:
        domain, revision, dc = self.open(cose, 1, 448)
        public = public_from_cose(dc[1])
        if (domain != ZERO_DOMAIN or dc[2] != self.fleet or dc[0] != key_id(public)
                or dc[4] != revision or not 1 <= len(dc[3]) <= 48
                or any(not 0x20 <= ord(c) <= 0x7e for c in dc[3])
                or dc[5] != sha256(cbor_encode({2: dc[3], 8: {1: dc[1]}})).digest()):
            raise ValueError("DeviceCredential semantic binding mismatch")
        return dc

    def admission(self, devices: list[bytes], delegation: bytes, assignment: int,
                  revision: int) -> dict[str, bytes]:
        """One immutable initial-assignment batch; mode1 grants, <=64 devices, <=8 per page."""
        positive(assignment)
        positive(revision)
        if not 1 <= len(devices) <= 64:
            raise ValueError("admission batch must contain 1..64 devices")
        domain, generation, root = self.open(delegation, 2, 448)
        public = public_from_cose(root[2])
        if (domain == ZERO_DOMAIN or root[0] != self.fleet or root[1] != key_id(public)
                or root[3] != domain or root[4] != generation or not root[5] & 1
                or root[5] & ~15):
            raise ValueError("RootDelegation semantic binding/approve permission mismatch")
        checked = sorted((self._device(cose)[0], cose) for cose in devices)
        ids = [device for device, _ in checked]
        if len(set(ids)) != len(ids) or root[1] in ids:
            raise ValueError("duplicate device or root in member batch")
        files, entries = {}, []
        for device, dc in checked:
            ticket = self._sign(3, domain, assignment,
                                [device, self.fleet, ZERO_DOMAIN, domain,
                                 sha256(delegation).digest(), 0, assignment, secrets.token_bytes(16),
                                 1, secrets.token_bytes(16), sha256(dc).digest()], 1024)
            files[f"ticket-{device.hex()}.cose"] = ticket
            entries.append([device, assignment, sha256(ticket).digest(), True])
        digest = sha256(cbor_encode([domain, revision, entries])).digest()
        pages = (len(entries) + 7) // 8
        for page in range(pages):
            files[f"expected-{page:02d}.cose"] = self._sign(
                5, domain, revision, [page, pages, digest, entries[page * 8:(page + 1) * 8]], 1024
            )
        return files
