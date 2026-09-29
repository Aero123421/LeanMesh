"""RF frame, transfer, serial and power layouts (docs/09). Mirrors src/core/wire/*.cpp rule for
rule; error statuses match too (UNSUPPORTED for an undefined version/kind, BAD_FRAME otherwise).
Decoders check structure only, never authorization or freshness.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

from .cbor import WireError, _bad

LINK = struct.Struct(">2sBBIIQHBB")
ROUTE = struct.Struct(">HHBBBBII")
END = struct.Struct(">IQ16sHBBQH")
HOP_ACK = struct.Struct(">QBBH")
FRAG = struct.Struct(">HHHBB32s")
BITMAP = struct.Struct(">H32sB")
BOOT = struct.Struct(">16sBHHH")
SERIAL = struct.Struct(">2sBBIQH")
POWER_POLL = struct.Struct(">BBHQIIHHI")
POWER_GRANT = struct.Struct(">BBHQIHHI")

MAX_FRAME = 250
MAX_PATH = 40
TAG = 16
BROADCAST = 0xFFFF
# Frame kinds (registry frame_kinds).
DISCOVERY, HOP_ACK_KIND, DATA, ROUTE_KIND, CONTROL, EDHOC, JOIN_PROXY, POWER = range(1, 9)
# Record kinds.
REC_DATA, REC_RECEIPT, REC_FRAGMENT, REC_CONTROL, REC_BITMAP = range(1, 6)


def data_capacity(hops: int) -> int:
    return 136 - 2 * hops if 1 <= hops <= MAX_PATH else 0


def fragment_chunk(hops: int) -> int:
    cap = data_capacity(hops)
    return 0 if cap <= 40 else (cap - 40) // 16 * 16


# ---- link envelope ----
@dataclass
class LinkHeader:
    kind: int
    domain_hint: int
    link_sid: int
    link_counter: int
    body_length: int
    encrypted: bool


def _session_shape_ok(kind: int, sid: int, encrypted: bool) -> bool:
    if kind in (DISCOVERY, JOIN_PROXY):
        return sid == 0 and not encrypted
    if kind == EDHOC:
        return encrypted == (sid != 0)
    return sid != 0 and encrypted


def _body_length_ok(kind: int, n: int) -> bool:
    if kind == HOP_ACK_KIND:
        return n == 12
    if kind == POWER:
        return n in (24, 28)
    if kind == DATA:
        return n >= 16 + 2 + 42 + TAG
    return n >= 1


def decode_link_frame(frame: bytes) -> tuple[LinkHeader, bytes]:
    if len(frame) < LINK.size or len(frame) > MAX_FRAME:
        raise _bad("frame size")
    magic, version, kind, hint, sid, ctr, blen, flags, reserved = LINK.unpack_from(frame)
    if magic != b"LM":
        raise _bad("magic")
    if version != 1 or not 1 <= kind <= 8:
        raise WireError("UNSUPPORTED", "version or kind")
    if flags & ~1 or reserved:
        raise _bad("flags/reserved")
    enc = bool(flags & 1)
    if not _session_shape_ok(kind, sid, enc) or (enc and ctr == 0):
        raise _bad("session shape")
    if len(frame) != LINK.size + blen + (TAG if enc else 0) or not _body_length_ok(kind, blen):
        raise _bad("length")
    return LinkHeader(kind, hint, sid, ctr, blen, enc), frame[LINK.size :]


def encode_link_header(h: LinkHeader) -> bytes:
    return LINK.pack(
        b"LM", 1, h.kind, h.domain_hint, h.link_sid, h.link_counter, h.body_length, int(h.encrypted), 0
    )


def link_aad(prefix24: bytes, ctx_hash: bytes) -> bytes:
    if len(prefix24) != 24 or len(ctx_hash) != 32:
        raise WireError("INVALID_ARGUMENT")
    return prefix24 + ctx_hash


# ---- routed body ----
@dataclass
class RouteHeader:
    origin: int
    final: int
    path_len: int
    next_index: int
    budget: int
    root_term: int
    path_revision: int
    path: list[int] = field(default_factory=list)


def validate_simple_path(origin: int, path: list[int]) -> None:
    if origin in (0, BROADCAST):
        raise _bad("origin")
    seen = {origin}
    for a in path:
        if a in (0, BROADCAST) or a in seen:
            raise _bad("path is not simple")
        seen.add(a)


def decode_route(plain: bytes) -> tuple[RouteHeader, bytes]:
    if len(plain) < ROUTE.size:
        raise _bad("short route header")
    origin, final, n, idx, budget, res, term, rev = ROUTE.unpack_from(plain)
    if res or not 1 <= n <= MAX_PATH or idx >= n or budget != n - idx:
        raise _bad("route fields")
    off = ROUTE.size + 2 * n
    if len(plain) < off + 42 + TAG:
        raise _bad("short route body")
    path = list(struct.unpack_from(">" + "H" * n, plain, ROUTE.size))
    if final != path[-1]:
        raise _bad("final != last path entry")
    validate_simple_path(origin, path)
    return RouteHeader(origin, final, n, idx, budget, term, rev, path), plain[off:]


def encode_route(h: RouteHeader) -> bytes:
    if not 1 <= h.path_len <= MAX_PATH:
        raise WireError("INVALID_ARGUMENT")
    return ROUTE.pack(
        h.origin, h.final, h.path_len, h.next_index, h.budget, 0, h.root_term, h.path_revision
    ) + struct.pack(">" + "H" * h.path_len, *h.path[: h.path_len])


# ---- end record ----
@dataclass
class EndHeader:
    end_sid: int
    end_counter: int
    message_id: bytes
    app_port: int
    record_kind: int
    flags: int
    expires_root_ms: int
    plaintext_length: int

    @property
    def delivery(self) -> int:
        return self.flags & 3

    @property
    def priority(self) -> int:
        return (self.flags >> 2) & 3

    @property
    def durable(self) -> bool:
        return bool(self.flags & 0x10)


def decode_end_record(record: bytes) -> tuple[EndHeader, bytes]:
    if len(record) < END.size:
        raise _bad("short end header")
    h = EndHeader(*END.unpack_from(record))
    if (
        h.end_sid == 0
        or h.end_counter == 0
        or not 1 <= h.record_kind <= 5
        or h.flags & 0xE0
        or h.delivery == 3
        or h.app_port == BROADCAST
    ):
        raise _bad("end header")
    if (
        (h.record_kind == REC_DATA and h.app_port == 0)
        or (h.record_kind == REC_BITMAP and h.plaintext_length != 35)
        or len(record) != END.size + h.plaintext_length + TAG
    ):
        raise _bad("end length")
    return h, record[END.size :]


def encode_end_header(h: EndHeader) -> bytes:
    return END.pack(
        h.end_sid,
        h.end_counter,
        h.message_id,
        h.app_port,
        h.record_kind,
        h.flags,
        h.expires_root_ms,
        h.plaintext_length,
    )


def end_aad(ctx_hash: bytes, root_term: int, header42: bytes) -> bytes:
    if len(ctx_hash) != 32 or len(header42) != END.size:
        raise WireError("INVALID_ARGUMENT")
    return b"LM1-END" + ctx_hash + struct.pack(">I", root_term) + header42


# ---- HOP_ACK ----
@dataclass
class HopAck:
    acked_link_counter: int
    status: int
    credit: int
    retry_after_ms: int


def decode_hop_ack(plain: bytes) -> HopAck:
    if len(plain) != HOP_ACK.size:
        raise _bad("hop ack length")
    a = HopAck(*HOP_ACK.unpack(plain))
    if a.acked_link_counter == 0 or a.status > 2:
        raise _bad("hop ack fields")
    return a


def encode_hop_ack(a: HopAck) -> bytes:
    return HOP_ACK.pack(a.acked_link_counter, a.status, a.credit, a.retry_after_ms)


# ---- fragment / bitmap / bootstrap ----
@dataclass
class FragmentPrefix:
    total_len: int
    offset: int
    fragment_len: int
    original_kind: int
    object_class: int
    intent_hash: bytes


def decode_fragment(plain: bytes) -> tuple[FragmentPrefix, bytes]:
    if len(plain) < FRAG.size:
        raise _bad("short fragment")
    p = FragmentPrefix(*FRAG.unpack_from(plain))
    end = p.offset + p.fragment_len
    if (
        p.original_kind not in (REC_DATA, REC_RECEIPT, REC_CONTROL)
        or p.object_class > 2
        or not 0 < p.total_len <= 4096
        or (p.object_class == 0 and p.total_len > 512)
        or p.fragment_len == 0
        or p.fragment_len > data_capacity(1) - 40
        or p.offset % 16
        or end > p.total_len
        or (end < p.total_len and p.fragment_len % 16)
        or len(plain) != FRAG.size + p.fragment_len
    ):
        raise _bad("fragment rules")
    return p, plain[FRAG.size :]


def encode_fragment_prefix(p: FragmentPrefix) -> bytes:
    return FRAG.pack(
        p.total_len, p.offset, p.fragment_len, p.original_kind, p.object_class, p.intent_hash
    )


@dataclass
class TransferBitmap:
    base_offset: int
    bitmap: bytes
    credit: int

    def test(self, offset: int) -> bool:
        i = offset // 16
        return i < 256 and bool(self.bitmap[i // 8] >> (i % 8) & 1)


def decode_transfer_bitmap(plain: bytes) -> TransferBitmap:
    if len(plain) != BITMAP.size:
        raise _bad("bitmap length")
    b = TransferBitmap(*BITMAP.unpack(plain))
    if b.base_offset != 0:
        raise _bad("bitmap base_offset")
    return b


def encode_transfer_bitmap(b: TransferBitmap) -> bytes:
    return BITMAP.pack(b.base_offset, b.bitmap, b.credit)


@dataclass
class BootstrapCarrier:
    exchange_id: bytes
    object_kind: int
    total: int
    offset: int
    body: bytes


def decode_bootstrap(plain: bytes) -> BootstrapCarrier:
    if len(plain) < BOOT.size:
        raise _bad("short bootstrap")
    xid, kind, total, offset, length = BOOT.unpack_from(plain)
    if (
        not 0 < total <= 1024
        or not 0 < length <= 160
        or offset + length > total
        or len(plain) != BOOT.size + length
    ):
        raise _bad("bootstrap rules")
    return BootstrapCarrier(xid, kind, total, offset, plain[BOOT.size :])


def encode_bootstrap(c: BootstrapCarrier) -> bytes:
    return BOOT.pack(c.exchange_id, c.object_kind, c.total, c.offset, len(c.body)) + c.body


# ---- serial ----
SERIAL_HELLO, SERIAL_EDHOC = 1, 2


@dataclass
class SerialHeader:
    kind: int
    session_id: int
    counter: int
    payload_len: int


def crc32_iso_hdlc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def decode_serial_frame(decoded: bytes) -> tuple[SerialHeader, bytes]:
    if not SERIAL.size + 4 <= len(decoded) <= 8230:
        raise _bad("serial size")
    magic, version, kind, sid, ctr, plen = SERIAL.unpack_from(decoded)
    if magic != b"LS":
        raise _bad("serial magic")
    if version != 1 or not 1 <= kind <= 7:
        raise WireError("UNSUPPORTED", "serial version or kind")
    auth = kind not in (SERIAL_HELLO, SERIAL_EDHOC)
    if (
        (not auth and plen > 1024)
        or plen > 8192
        or len(decoded) != SERIAL.size + plen + (TAG if auth else 0) + 4
    ):
        raise _bad("serial length")
    if crc32_iso_hdlc(decoded[:-4]) != int.from_bytes(decoded[-4:], "big"):
        raise _bad("serial crc")
    return SerialHeader(kind, sid, ctr, plen), decoded[SERIAL.size : -4]


def encode_serial_frame(h: SerialHeader, body: bytes) -> bytes:
    auth = h.kind not in (SERIAL_HELLO, SERIAL_EDHOC)
    if len(body) != h.payload_len + (TAG if auth else 0):
        raise WireError("INVALID_ARGUMENT")
    raw = SERIAL.pack(b"LS", 1, h.kind, h.session_id, h.counter, h.payload_len) + body
    return raw + crc32_iso_hdlc(raw).to_bytes(4, "big")


# ---- power ----
@dataclass
class PowerPoll:
    rx_credit: int
    poll_nonce: int
    revision_hint: int
    planned_interval_ms: int
    window_ms: int


@dataclass
class PowerGrant:
    pending_frames: int
    poll_nonce: int
    window_ttl_ms: int
    granted_credit: int
    reason: int


def decode_power_poll(plain: bytes) -> PowerPoll:
    if len(plain) != POWER_POLL.size or plain[0] != 1:
        raise _bad("power poll shape")
    _, version, credit, nonce, rev, interval, window, flags, reserved = POWER_POLL.unpack(plain)
    if version != 1:
        raise WireError("UNSUPPORTED", "power version")
    if nonce == 0 or interval > 86400000 or window == 0 or flags or reserved:
        raise _bad("power poll fields")
    return PowerPoll(credit, nonce, rev, interval, window)


def decode_power_grant(plain: bytes) -> PowerGrant:
    if len(plain) != POWER_GRANT.size or plain[0] != 2:
        raise _bad("power grant shape")
    _, version, pending, nonce, ttl, credit, reserved, reason = POWER_GRANT.unpack(plain)
    if version != 1:
        raise WireError("UNSUPPORTED", "power version")
    if nonce == 0 or not 1 <= ttl <= 0xFFFF or reserved:
        raise _bad("power grant fields")
    return PowerGrant(pending, nonce, ttl, credit, reason)


def encode_power_poll(p: PowerPoll) -> bytes:
    return POWER_POLL.pack(
        1, 1, p.rx_credit, p.poll_nonce, p.revision_hint, p.planned_interval_ms, p.window_ms, 0, 0
    )


def encode_power_grant(g: PowerGrant) -> bytes:
    return POWER_GRANT.pack(
        2, 1, g.pending_frames, g.poll_nonce, g.window_ttl_ms, g.granted_credit, 0, g.reason
    )


def check_grant_against_poll(poll: PowerPoll, grant: PowerGrant) -> None:
    if not (
        grant.poll_nonce == poll.poll_nonce
        and grant.granted_credit <= poll.rx_credit
        and grant.window_ttl_ms <= poll.window_ms
    ):
        raise _bad("grant does not match poll")
