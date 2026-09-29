"""Strict value codecs from api/SEMANTICS.md: u63 strings, lowercase hex ids, canonical base64/JSON."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any

from .errors import invalid

U63_MAX = (1 << 63) - 1
_U63 = re.compile(r"^(0|[1-9][0-9]{0,18})$")
_HEX = re.compile(r"^(?:[0-9a-f]{2})+$")
_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def parse_u63(text: str) -> int:
    if not isinstance(text, str) or not _U63.match(text) or int(text) > U63_MAX:
        raise ValueError("not a decimal u63 string")
    return int(text)


def hex_bytes(text: str, size: int, what: str = "id") -> bytes:
    """Lowercase hex of exactly `size` bytes (DeviceId=32, Id16=16); 400 otherwise."""
    if not isinstance(text, str) or len(text) != size * 2 or not _HEX.match(text):
        raise invalid(f"{what} must be {size * 2} lowercase hex characters")
    return bytes.fromhex(text)


def decode_b64(text: str, what: str = "payload") -> bytes:
    """Standard alphabet, mandatory padding, canonical trailing bits (re-encode must match)."""
    if len(text) % 4 != 0 or not _B64.match(text):
        raise ValueError(f"{what} is not strict base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"{what} is not strict base64") from exc
    if base64.b64encode(raw).decode() != text:
        raise ValueError(f"{what} is not canonical base64")
    return raw


def encode_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def canonical_json(obj: Any) -> str:
    """UTF-8, sorted keys, no whitespace, no NaN/float drift (SEMANTICS 'Policy JSON')."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def request_hash(obj: Any) -> bytes:
    return hashlib.sha256(canonical_json(obj).encode()).digest()
