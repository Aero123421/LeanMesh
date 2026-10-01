"""POSIX key custody for the offline issuer; no seed or private-key import path."""

from __future__ import annotations

import json
import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from leanmesh_host.wire.cbor import cbor_encode


def public_cose(key: ec.EllipticCurvePublicKey) -> dict:
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("public key must be P-256")
    n = key.public_numbers()
    return {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def key_id(key: ec.EllipticCurvePublicKey) -> bytes:
    from hashlib import sha256

    return sha256(cbor_encode(public_cose(key))).digest()


def public_from_cose(value: dict) -> ec.EllipticCurvePublicKey:
    if set(value) != {1, -1, -2, -3} or value[1] != 2 or value[-1] != 1:
        raise ValueError("invalid P-256 COSE key")
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(value[-2], "big"), int.from_bytes(value[-3], "big"), ec.SECP256R1()
    ).public_key()


@contextmanager
def private_directory(path: Path):
    """Pin the directory inode for every relative access; refuse links and shared directories."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
            raise ValueError("key/output directory must be owned by this user and mode 0700")
        yield fd
    finally:
        os.close(fd)


def read_private(name: str | Path, *, directory: int | None = None, limit: int = 8192) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid()
                or stat.S_IMODE(s.st_mode) != 0o600):
            raise ValueError("secret/metadata file must be regular, owned, single-link and mode 0600")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file exceeds size limit")
        return data
    finally:
        os.close(fd)


def write_new(name: str | Path, data: bytes, *, directory: int | None = None) -> None:
    """No replacement, including existing files, hard links or symbolic links. fsync before return."""
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                 dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(data)
            f.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def password_file(path: Path) -> bytes:
    password = read_private(path, limit=1024).rstrip(b"\r\n")
    if len(password) < 16:
        raise ValueError("passphrase must contain at least 16 bytes")
    return password


def initialize(path: Path, environment: str, password: bytes) -> dict:
    if environment not in {"production", "test"} or len(password) < 16:
        raise ValueError("explicit environment and a passphrase of at least 16 bytes are required")
    path.mkdir(mode=0o700)  # exclusive: an interrupted initialization is never reused
    with private_directory(path) as fd:
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(password))
        meta = {"format": 1, "environment": environment, "fleet_id": secrets.token_hex(16),
                "key_id": key_id(key.public_key()).hex(),
                "public_key_pem": key.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode("ascii")}
        write_new("fleet-key.pem", pem, directory=fd)
        # The metadata is the completion marker; a store without it cannot sign.
        write_new("fleet.json", (json.dumps(meta, indent=2) + "\n").encode(), directory=fd)
        os.fsync(fd)
    return meta


def load(path: Path, environment: str, password: bytes) -> tuple[dict, ec.EllipticCurvePrivateKey]:
    with private_directory(path) as fd:
        meta = json.loads(read_private("fleet.json", directory=fd))
        pem = read_private("fleet-key.pem", directory=fd)
    if (not isinstance(meta, dict) or type(meta.get("format")) is not int or meta["format"] != 1
            or meta.get("environment") not in {"production", "test"}
            or meta["environment"] != environment):
        raise ValueError("fleet store format/environment mismatch")
    if any(not isinstance(meta.get(k), str) for k in ("fleet_id", "key_id", "public_key_pem")):
        raise ValueError("invalid fleet metadata fields")
    # Reject unencrypted PEM even if somebody replaced the file after initialization.
    if not pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"):
        raise ValueError("fleet private key must be encrypted PKCS#8")
    key = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("fleet key must be P-256")
    public = serialization.load_pem_public_key(meta["public_key_pem"].encode("ascii"))
    if key_id(public) != key_id(key.public_key()) or meta["key_id"] != key_id(public).hex():
        raise ValueError("fleet key does not match its metadata")
    fleet = bytes.fromhex(meta["fleet_id"])
    if len(fleet) != 16 or not any(fleet):
        raise ValueError("invalid fleet id")
    return meta, key
