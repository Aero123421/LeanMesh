"""API principals and bearer tokens (docs/11 §1, api/SEMANTICS.md "Permissions").

Tokens are loaded from a 0600 JSON file of the form
    {"principals": [{"id": "ops", "token_sha256": "<64 hex>", "permissions": ["READ", ...]}]}
Only SHA-256 digests are stored; the file is refused when group/other can read it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

PERMISSIONS = frozenset(
    {"READ", "SEND", "APPROVE", "REVOKE", "TRANSFER", "CONFIGURE", "UPDATE_FIRMWARE"}
)


class TokenFileError(RuntimeError):
    """The token file is missing, too permissive or malformed; the service must not start."""


@dataclass(frozen=True)
class Principal:
    id: str
    token_sha256: bytes
    permissions: frozenset[str]


def load_principals(path: Path) -> dict[str, Principal]:
    try:
        st = path.stat()
    except OSError as exc:
        raise TokenFileError(f"cannot read token file {path}: {exc}") from exc
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise TokenFileError(f"token file {path} must be mode 0600")
    try:
        doc = json.loads(path.read_text())
        entries = doc["principals"]
        principals: dict[str, Principal] = {}
        for e in entries:
            digest = bytes.fromhex(e["token_sha256"])
            perms = frozenset(e["permissions"])
            if len(digest) != 32 or not perms <= PERMISSIONS or not e["id"] or e["id"] in principals:
                raise ValueError(f"invalid principal entry {e.get('id')!r}")
            principals[e["id"]] = Principal(e["id"], digest, perms)
    except (ValueError, KeyError, TypeError) as exc:
        raise TokenFileError(f"malformed token file {path}: {exc}") from exc
    return principals


def sync_principals(conn: sqlite3.Connection, principals: dict[str, Principal]) -> None:
    """Storage-thread transaction: upsert file principals, disable the ones no longer listed.

    Rows are never deleted: operations keep a foreign key to their principal.
    """
    conn.execute("UPDATE principals SET enabled=0")
    for p in principals.values():
        conn.execute(
            "INSERT INTO principals(id, token_hash, permissions, enabled) VALUES(?,?,?,1) "
            "ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash, "
            "permissions=excluded.permissions, enabled=1",
            (p.id, p.token_sha256, json.dumps(sorted(p.permissions))),
        )


def authenticate(principals: dict[str, Principal], token: str) -> Principal | None:
    digest = hashlib.sha256(token.encode()).digest()
    found = None
    for p in principals.values():  # constant-time compare against every entry
        if hmac.compare_digest(p.token_sha256, digest):
            found = p
    return found
