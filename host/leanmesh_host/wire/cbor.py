"""Strict deterministic CBOR (RFC 8949 §4.2.1 subset used by control.cddl).

Accepted: definite lengths, shortest heads, uint/nint/bstr/tstr/array/map/bool/null. Rejected:
indefinite lengths, non-minimal heads, floats/undefined/simple values, tags, map keys that are not
int/bytes/str, duplicate or unsorted keys (bytewise order of the encoded keys), invalid UTF-8,
trailing bytes, nesting deeper than MAX_DEPTH, containers above MAX_ARRAY/MAX_MAP.
"""

from __future__ import annotations

from typing import Any

MAX_DEPTH = 16  # item nesting levels 0..16
MAX_ARRAY = 4096
MAX_MAP = 128


class WireError(ValueError):
    """Malformed or unsupported wire input; `status` is the registry status name."""

    def __init__(self, status: str = "BAD_FRAME", message: str = "") -> None:
        super().__init__(f"{status}: {message}" if message else status)
        self.status = status


def _bad(message: str = "") -> WireError:
    return WireError("BAD_FRAME", message)


def _head(major: int, arg: int) -> bytes:
    if not 0 <= arg < 2**64:
        raise WireError("INVALID_ARGUMENT", "CBOR integer out of range")
    if arg < 24:
        return bytes([major << 5 | arg])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < 1 << (8 * width):
            return bytes([major << 5 | ai]) + arg.to_bytes(width, "big")
    raise AssertionError("unreachable")


def cbor_encode(x: Any) -> bytes:
    """Deterministic encoder. Map keys are sorted by their encodings."""
    if x is None:
        return b"\xf6"
    if isinstance(x, bool):
        return b"\xf5" if x else b"\xf4"
    if isinstance(x, int):
        return _head(0, x) if x >= 0 else _head(1, -1 - x)
    if isinstance(x, (bytes, bytearray)):
        return _head(2, len(x)) + bytes(x)
    if isinstance(x, str):
        b = x.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(x, (list, tuple)):
        return _head(4, len(x)) + b"".join(cbor_encode(y) for y in x)
    if isinstance(x, dict):
        items = sorted((cbor_encode(k), cbor_encode(v)) for k, v in x.items())
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(type(x).__name__)


class _Decoder:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n > len(self.data) - self.pos:
            raise _bad("truncated")
        b = self.data[self.pos : self.pos + n]
        self.pos += n
        return b

    def head(self) -> tuple[int, int]:
        first = self.take(1)[0]
        major, ai = first >> 5, first & 31
        if major == 6:
            raise _bad("tag")
        if major == 7:
            if ai not in (20, 21, 22):
                raise _bad("float or simple value")
            return major, ai
        if ai < 24:
            return major, ai
        if ai > 27:
            raise _bad("indefinite or reserved additional info")
        width = 1 << (ai - 24)
        arg = int.from_bytes(self.take(width), "big")
        if arg < (24, 256, 65536, 2**32)[ai - 24]:
            raise _bad("non-minimal head")
        return major, arg

    def item(self, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise _bad("nesting")
        major, arg = self.head()
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return self.take(arg)
        if major == 3:
            try:
                return self.take(arg).decode("utf-8")
            except UnicodeDecodeError as e:
                raise _bad("utf-8") from e
        if major == 4:
            if arg > MAX_ARRAY or arg > len(self.data) - self.pos:
                raise _bad("array size")
            return [self.item(depth + 1) for _ in range(arg)]
        if major == 5:
            return self.map(arg, depth)
        return {20: False, 21: True, 22: None}[arg]

    def map(self, count: int, depth: int) -> dict[Any, Any]:
        if count > MAX_MAP or count * 2 > len(self.data) - self.pos:
            raise _bad("map size")
        out: dict[Any, Any] = {}
        prev: bytes | None = None
        for _ in range(count):
            start = self.pos
            if start >= len(self.data) or self.data[start] >> 5 > 3:
                raise _bad("map key type")
            key = self.item(depth + 1)
            raw = self.data[start : self.pos]
            if prev is not None and raw <= prev:
                raise _bad("map key order or duplicate")
            prev = raw
            out[key] = self.item(depth + 1)
        return out


def cbor_decode(data: bytes) -> Any:
    """Decodes exactly one item; raises WireError(BAD_FRAME) on any rule violation."""
    d = _Decoder(bytes(data))
    x = d.item(0)
    if d.pos != len(data):
        raise _bad("trailing bytes")
    return x


def render(x: Any) -> str:
    """Canonical text shared with tools/lmtool: h'..' bstr, t'<utf-8 hex>' tstr."""
    if x is None:
        return "null"
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        return str(x)
    if isinstance(x, bytes):
        return "h'" + x.hex() + "'"
    if isinstance(x, str):
        return "t'" + x.encode().hex() + "'"
    if isinstance(x, list):
        return "[" + ",".join(render(y) for y in x) + "]"
    return "{" + ",".join(render(k) + ":" + render(v) for k, v in x.items()) + "}"
