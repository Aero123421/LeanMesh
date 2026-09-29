"""Pure decision functions of api/SEMANTICS.md (strict u63, hex ids, base64, canonical hash)."""

from __future__ import annotations

import pytest
from leanmesh_host.api import codec
from leanmesh_host.api.errors import ApiError


@pytest.mark.parametrize("text", ["0", "1", "9223372036854775807"])
def test_u63_accepts_decimal_strings_in_range(text: str) -> None:
    assert codec.parse_u63(text) == int(text)


@pytest.mark.parametrize("text", ["01", "-1", "9223372036854775808", "1.0", " 1", "", 5, None])
def test_u63_rejects_everything_else(text: object) -> None:
    with pytest.raises(ValueError):
        codec.parse_u63(text)  # type: ignore[arg-type]


@pytest.mark.parametrize("text", ["aGVsbG8", "aGVs bG8=", "_-8=", "aGVsbG9=", "aGVsbG8==", "a===", "\naGVsbG8="])
def test_base64_is_strict_and_canonical(text: str) -> None:
    with pytest.raises(ValueError):
        codec.decode_b64(text)


def test_base64_round_trip_and_empty() -> None:
    assert codec.decode_b64("aGVsbG8=") == b"hello" and codec.decode_b64("") == b""


def test_hex_ids_are_lowercase_and_exact() -> None:
    assert codec.hex_bytes("ab" * 16, 16) == bytes.fromhex("ab" * 16)
    for bad in ("AB" * 16, "ab" * 15, "zz" * 16):
        with pytest.raises(ApiError):
            codec.hex_bytes(bad, 16)


def test_canonical_hash_ignores_key_order_only() -> None:
    a = codec.request_hash({"b": 1, "a": {"y": "ü", "x": [1, 2]}})
    assert a == codec.request_hash({"a": {"x": [1, 2], "y": "ü"}, "b": 1})
    assert a != codec.request_hash({"a": {"x": [2, 1], "y": "ü"}, "b": 1})
    with pytest.raises(ValueError):
        codec.canonical_json({"x": float("nan")})
