"""Run with PYTHONPATH=host python -m leanmesh_fleet (locked Host venv)."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import warnings
from hashlib import sha256
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from . import keys
from .issuer import Issuer


def bounded_read(path: Path, limit: int) -> bytes:
    with path.open("rb") as f:
        value = f.read(limit + 1)
    if len(value) > limit:
        raise ValueError("input exceeds size limit")
    return value


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Offline LM1 fleet issuer: initial Join and transfer objects")
    sub = p.add_subparsers(dest="command", required=True)
    for command in ("init", "device", "root", "admit", "transfer", "handover"):
        q = sub.add_parser(command)
        q.add_argument("--store", type=Path, required=True)
        q.add_argument("--environment", choices=("production", "test"), required=True)
        q.add_argument("--password-file", type=Path, help="owned 0600 file; otherwise prompt")
        if command in {"device", "root"}:
            q.add_argument("--public-key", type=Path, required=True)
            q.add_argument("--generation", type=int, required=True)
            q.add_argument("--output", type=Path, required=True)
        if command == "device":
            q.add_argument("--serial", required=True)
        if command == "root":
            q.add_argument("--domain", required=True, help="nonzero 16-byte hex domain")
            q.add_argument("--permissions", type=int, required=True, help="approve1/revoke2/channel4/groups8")
        if command == "handover":
            q.add_argument("--old-root", required=True, help="DeviceId of the root that failed (64 hex)")
            q.add_argument("--new-root-delegation", type=Path, required=True,
                           help="the RootDelegation of the replacement root (generation above the old one)")
            q.add_argument("--old-generation", type=int, required=True)
            q.add_argument("--new-term", type=int, required=True, help="first root term the replacement root publishes")
            q.add_argument("--recovery-mode", type=int, choices=(0, 1), default=1)
            q.add_argument("--output", type=Path, required=True)
        if command == "admit":
            q.add_argument("--device-credential", type=Path, action="append", required=True)
            q.add_argument("--root-delegation", type=Path, required=True)
            q.add_argument("--assignment", type=int, required=True)
            q.add_argument("--expected-revision", type=int, required=True)
            q.add_argument("--output-dir", type=Path, required=True)
        if command == "transfer":
            q.add_argument("--device-credential", type=Path, required=True)
            q.add_argument("--source-domain", required=True, help="nonzero 16-byte hex: the domain it is in now")
            q.add_argument("--root-delegation", type=Path, required=True, help="the TARGET root's delegation")
            q.add_argument("--expected-old", type=int, required=True, help="its current assignment generation")
            q.add_argument("--new-generation", type=int, required=True)
            mode = q.add_mutually_exclusive_group(required=True)
            mode.add_argument("--nonce", help="mode 0: the device's 16-byte transfer nonce (hex)")
            mode.add_argument("--grant", action="store_true", help="mode 1: a fresh one-time grant")
            q.add_argument("--expected-revision", type=int, help="also issue the target's ExpectedSet page")
            q.add_argument("--output-dir", type=Path, required=True)
    return p


def write_batch(directory: Path, files: dict[str, bytes], meta: dict, fields: dict) -> None:
    directory.mkdir(mode=0o700)  # never overwrite or reuse a previous batch
    with keys.private_directory(directory) as fd:
        for name, data in files.items():
            keys.write_new(name, data, directory=fd)
        manifest = {"format": 1, "environment": meta["environment"], "fleet_id": meta["fleet_id"],
                    "key_id": meta["key_id"], **fields,
                    "files": {n: sha256(data).hexdigest() for n, data in files.items()}}
        # Last write: only a directory with this marker is a complete batch.
        keys.write_new("manifest.json", (json.dumps(manifest, indent=2) + "\n").encode(), directory=fd)
        os.fsync(fd)


def run(a: argparse.Namespace) -> None:
    if a.password_file:
        password = keys.password_file(a.password_file)
    else:
        if not sys.stdin.isatty():
            raise ValueError("noninteractive issuance requires a protected password file")
        # getpass otherwise falls back to echoed stdin when it cannot disable terminal echo.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Fleet key passphrase: ").encode("utf-8")
            if a.command == "init" and password != getpass.getpass("Repeat passphrase: ").encode("utf-8"):
                raise ValueError("passphrases do not match")
        if len(password) < 16:
            raise ValueError("passphrase must contain at least 16 bytes")
    if a.command == "init":
        meta = keys.initialize(a.store, a.environment, password)
        print(json.dumps({"fleet_id": meta["fleet_id"], "key_id": meta["key_id"],
                          "environment": meta["environment"]}))
        return
    meta, key = keys.load(a.store, a.environment, password)
    issuer = Issuer(bytes.fromhex(meta["fleet_id"]), key)
    if a.command in {"device", "root"}:
        public = serialization.load_pem_public_key(bounded_read(a.public_key, 4096))
        if a.command == "device":
            cose = issuer.device(public, a.serial, a.generation)
        else:
            cose = issuer.root(public, bytes.fromhex(a.domain), a.generation, a.permissions)
        keys.write_new(a.output, cose)
        print(json.dumps({"output": str(a.output), "sha256": sha256(cose).hexdigest()}))
        return
    if a.command == "transfer":
        delegation = bounded_read(a.root_delegation, 448)
        source = bytes.fromhex(a.source_domain)
        files = issuer.transfer(bounded_read(a.device_credential, 448), source, delegation,
                                a.expected_old, a.new_generation,
                                nonce=bytes.fromhex(a.nonce) if a.nonce is not None else None,
                                expected_revision=a.expected_revision)
        target = issuer.open(delegation, 2, 448)[0]
        write_batch(a.output_dir, files, meta,
                    {"kind": "transfer", "source_domain": source.hex(), "target_domain": target.hex(),
                     "expected_old": a.expected_old, "new_generation": a.new_generation,
                     "mode": 1 if a.nonce is None else 0, "expected_revision": a.expected_revision})
        print(json.dumps({"output_dir": str(a.output_dir), "objects": len(files),
                          "target_domain": target.hex(), "mode": 1 if a.nonce is None else 0}))
    if a.command == "handover":
        cose = issuer.handover(bytes.fromhex(a.old_root), bounded_read(a.new_root_delegation, 448),
                               a.old_generation, a.new_term, a.recovery_mode)
        keys.write_new(a.output, cose)
        print(json.dumps({"output": str(a.output), "sha256": sha256(cose).hexdigest()}))
        return
    if len(a.device_credential) > 64:
        raise ValueError("admission batch must contain 1..64 devices")
    files = issuer.admission([bounded_read(p, 448) for p in a.device_credential],
                             bounded_read(a.root_delegation, 448), a.assignment, a.expected_revision)
    write_batch(a.output_dir, files, meta,
                {"assignment": a.assignment, "expected_revision": a.expected_revision})
    print(json.dumps({"output_dir": str(a.output_dir), "objects": len(files)}))


def main() -> int:
    a = parser().parse_args()
    try:
        run(a)
    except (OSError, ValueError, TypeError, KeyError, InvalidSignature, EOFError, getpass.GetPassWarning):
        # Do not echo a parser/backend exception: inputs may contain secret material.
        print("fleet issuer refused: check inputs, environment, permissions and passphrase", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
