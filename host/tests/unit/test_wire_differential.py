"""Differential wire tests: C++ codecs (tools/lmtool) vs the Host's Python codec vs the spec
fixture scripts/wire_fixture.py, on valid seeds, every truncation length and random mutations.

The two SDK codecs are implemented independently and must agree on accept/reject, the status name,
every decoded field and the re-encoding. The fixture is a third, older implementation of parts of
the same contract; where it is comparable (CBOR, DATA route/end structure, fragments) it must agree
too, and the few known fixture divergences are listed and asserted explicitly.

Scenarios (software evidence only): R04 (codec part). All randomness is seeded; a failure prints
the codec, the hex input and both outcomes.
"""

from __future__ import annotations

import json
import random
import struct
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from harness import REPO_ROOT, native_build_dir
from leanmesh_host.wire import control as C
from leanmesh_host.wire import frames as F
from leanmesh_host.wire.cbor import WireError, cbor_decode, cbor_encode, render

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import wire_fixture as fx  # noqa: E402  (spec fixture, third oracle)

Outcome = tuple[str, Any]


class LmTool:
    """One long-lived lmtool process; commands are pipelined in bounded chunks."""

    def __init__(self, path: Path) -> None:
        self.proc = subprocess.Popen(
            [str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )

    def run(self, lines: list[str], max_chars: int = 12000) -> list[dict[str, Any]]:
        """Pipelines commands; each batch stays well below the pipe buffers (replies echo the
        input), so neither side can block on a full pipe."""
        out: list[dict[str, Any]] = []
        assert self.proc.stdin is not None and self.proc.stdout is not None
        i = 0
        while i < len(lines):
            j, size = i, 0
            while j < len(lines) and (j == i or size + len(lines[j]) <= max_chars):
                size += len(lines[j]) + 1
                j += 1
            self.proc.stdin.write("\n".join(lines[i:j]) + "\n")
            self.proc.stdin.flush()
            out.extend(json.loads(self.proc.stdout.readline()) for _ in range(i, j))
            i = j
        return out

    def close(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


@pytest.fixture(scope="module")
def lmtool() -> Iterator[LmTool]:
    path = native_build_dir() / "tools/lmtool/lmtool"
    if not path.is_file():
        raise FileNotFoundError(f"{path} not found: build the native tree first")
    tool = LmTool(path)
    yield tool
    tool.close()


# ---- Python-side views: same keys as lmtool output, plus "re" (re-encoding) ----
def _h(b: bytes) -> str:
    return b.hex()


def py_cbor(d: bytes) -> dict[str, Any]:
    return {"v": render(cbor_decode(d))}


def py_link(d: bytes) -> dict[str, Any]:
    h, payload = F.decode_link_frame(d)
    return dict(kind=h.kind, domain_hint=h.domain_hint, sid=h.link_sid, counter=h.link_counter,
                body_length=h.body_length, encrypted=h.encrypted, payload_len=len(payload),
                re=_h(F.encode_link_header(h)))


def py_route(d: bytes) -> dict[str, Any]:
    h, end = F.decode_route(d)
    return dict(origin=h.origin, final=h.final, path_len=h.path_len, next_index=h.next_index,
                budget=h.budget, root_term=h.root_term, path_revision=h.path_revision, path=h.path,
                end_offset=len(d) - len(end), re=_h(F.encode_route(h)))


def py_end(d: bytes) -> dict[str, Any]:
    h, _ = F.decode_end_record(d)
    return dict(end_sid=h.end_sid, end_counter=h.end_counter, message_id=_h(h.message_id),
                app_port=h.app_port, record_kind=h.record_kind, flags=h.flags,
                delivery=h.delivery, priority=h.priority, durable=h.durable,
                expires_root_ms=h.expires_root_ms, plaintext_length=h.plaintext_length,
                re=_h(F.encode_end_header(h)))


def py_hopack(d: bytes) -> dict[str, Any]:
    a = F.decode_hop_ack(d)
    return dict(acked=a.acked_link_counter, status=a.status, credit=a.credit,
                retry_after_ms=a.retry_after_ms, re=_h(F.encode_hop_ack(a)))


def py_frag(d: bytes) -> dict[str, Any]:
    p, _ = F.decode_fragment(d)
    return {"total": p.total_len, "offset": p.offset, "len": p.fragment_len,
            "orig_kind": p.original_kind, "class": p.object_class,
            "intent_hash": _h(p.intent_hash), "re": _h(F.encode_fragment_prefix(p))}


def py_bitmap(d: bytes) -> dict[str, Any]:
    b = F.decode_transfer_bitmap(d)
    return dict(bitmap=_h(b.bitmap), credit=b.credit, re=_h(F.encode_transfer_bitmap(b)))


def py_boot(d: bytes) -> dict[str, Any]:
    c = F.decode_bootstrap(d)
    return dict(exchange_id=_h(c.exchange_id), object_kind=c.object_kind, total=c.total,
                offset=c.offset, body=_h(c.body), re=_h(F.encode_bootstrap(c)))


def py_serial(d: bytes) -> dict[str, Any]:
    h, body = F.decode_serial_frame(d)
    return dict(kind=h.kind, session_id=h.session_id, counter=h.counter,
                payload_len=h.payload_len, body=_h(body), re=_h(F.encode_serial_frame(h, body)))


def py_poll(d: bytes) -> dict[str, Any]:
    p = F.decode_power_poll(d)
    return dict(rx_credit=p.rx_credit, nonce=p.poll_nonce, revision_hint=p.revision_hint,
                interval_ms=p.planned_interval_ms, window_ms=p.window_ms,
                re=_h(F.encode_power_poll(p)))


def py_grant(d: bytes) -> dict[str, Any]:
    g = F.decode_power_grant(d)
    return dict(pending=g.pending_frames, nonce=g.poll_nonce, ttl_ms=g.window_ttl_ms,
                credit=g.granted_credit, reason=g.reason, re=_h(F.encode_power_grant(g)))


def py_cose(d: bytes) -> dict[str, Any]:
    c = C.decode_cose_sign1(d)
    return dict(kid=_h(c.kid), protected=_h(c.protected), payload=_h(c.payload),
                signature=_h(c.signature),
                sig_prefix=_h(C.sig_structure_prefix(c.protected, len(c.payload))),
                re=_h(C.encode_cose_sign1(c.kid, c.payload, c.signature)))


def py_control(carrier: str) -> Callable[[bytes], dict[str, Any]]:
    def view(d: bytes) -> dict[str, Any]:
        b = C.decode_control_body(d, carrier)
        return dict(type=b.type, version=b.version, request_id=_h(b.request_id),
                    domain=_h(b.domain), revision=b.revision, issuer=_h(b.issuer),
                    data=_h(b.data), re=_h(C.encode_control_body(b)))
    return view


# The bytes of the input that the "re" field must reproduce (structural prefix or everything).
def _re_whole(d: bytes, _out: dict[str, Any]) -> str:
    return _h(d)


CODECS: dict[str, tuple[str, Callable[[bytes], dict[str, Any]], Callable[..., str]]] = {
    "link": ("link", py_link, lambda d, o: _h(d[:24])),
    "route": ("route", py_route, lambda d, o: _h(d[: o["end_offset"]])),
    "end": ("end", py_end, lambda d, o: _h(d[:42])),
    "hopack": ("hopack", py_hopack, _re_whole),
    "frag": ("frag", py_frag, lambda d, o: _h(d[:40])),
    "bitmap": ("bitmap", py_bitmap, _re_whole),
    "boot": ("boot", py_boot, _re_whole),
    "serial": ("serial", py_serial, _re_whole),
    "poll": ("poll", py_poll, _re_whole),
    "grant": ("grant", py_grant, _re_whole),
    "cose": ("cose", py_cose, _re_whole),
    "control-signed": ("control signed", py_control("signed"), _re_whole),
    "control-session": ("control session", py_control("session"), _re_whole),
    "cbor": ("cbor", py_cbor, None),
}


def py_outcome(fn: Callable[[bytes], dict[str, Any]], d: bytes) -> Outcome:
    try:
        return "ok", fn(d)
    except WireError as e:
        return "err", e.status


def compare(tool: LmTool, name: str, inputs: list[bytes]) -> tuple[int, int]:
    """Runs every input through lmtool and the Python codec; returns (accepted, rejected)."""
    cmd, py, expect_re = CODECS[name]
    replies = tool.run([f"{cmd} {d.hex() or '-'}" for d in inputs])
    accepted = rejected = 0
    failures: list[str] = []
    for d, reply in zip(inputs, replies, strict=True):
        kind, val = py_outcome(py, d)
        if kind == "err":
            rejected += 1
            if reply != {"ok": False, "e": val}:
                failures.append(f"{name} {d.hex()}: python {val} vs C++ {reply}")
            continue
        accepted += 1
        cpp = {k: v for k, v in reply.items() if k != "ok"}
        if not reply.get("ok") or cpp != val:
            failures.append(f"{name} {d.hex()}: python {val} vs C++ {reply}")
        elif expect_re is not None and cpp["re"] != expect_re(d, cpp):
            failures.append(f"{name} {d.hex()}: re-encoding {cpp['re']} differs from input")
    assert not failures, f"{len(failures)} mismatches; first:\n" + "\n".join(failures[:5])
    return accepted, rejected


# ---- mutation ----
def mutate(rnd: random.Random, d: bytes, fix: Callable[[bytes], bytes] | None = None) -> bytes:
    b = bytearray(d)
    for _ in range(rnd.choice([1, 1, 2, 3])):
        op = rnd.randrange(6)
        if not b:
            b.append(rnd.randrange(256))
        elif op == 0:
            b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
        elif op == 1:
            b[rnd.randrange(len(b))] = rnd.choice([0, 1, 0x7F, 0x80, 0xFF, rnd.randrange(256)])
        elif op == 2:
            del b[rnd.randrange(len(b))]
        elif op == 3:
            b.insert(rnd.randrange(len(b) + 1), rnd.randrange(256))
        elif op == 4:
            del b[rnd.randrange(len(b) + 1) :]
        else:
            b.extend(rnd.randbytes(rnd.randrange(1, 4)))
    out = bytes(b)
    return fix(out) if fix and rnd.random() < 0.7 else out


def edge_substitutions(d: bytes, span: int = 40) -> list[bytes]:
    out = []
    for pos in range(min(len(d), span)):
        for v in (0, 1, 0x80, 0xFF):
            if d[pos] != v:
                out.append(d[:pos] + bytes([v]) + d[pos + 1 :])
    return out


def corpus(seeds: list[bytes], rnd: random.Random, per_seed: int = 40,
           fix: Callable[[bytes], bytes] | None = None, truncate: bool = True) -> list[bytes]:
    out: list[bytes] = []
    for s in seeds:
        out.append(s)
        out.extend(mutate(rnd, s, fix) for _ in range(per_seed))
        out.extend(edge_substitutions(s))
        if truncate:  # every length 0..len(seed)
            out.extend(s[:n] for n in range(len(s)))
    return out


# ---- seed generators (valid or plausible; validity is decided by the codecs) ----
def link_seeds(rnd: random.Random, n: int) -> list[bytes]:
    out = []
    for _ in range(n):
        kind = rnd.randrange(1, 9)
        if kind in (F.DISCOVERY, F.JOIN_PROXY):
            sid, enc = 0, False
        elif kind == F.EDHOC:
            sid = rnd.choice([0, rnd.randrange(1, 2**32)])
            enc = sid != 0
        else:
            sid, enc = rnd.randrange(1, 2**32), True
        counter = rnd.randrange(1, 2**64) if enc else rnd.choice([0, rnd.randrange(2**64)])
        if kind == F.HOP_ACK:
            blen = 12
        elif kind == F.POWER:
            blen = rnd.choice([24, 28])
        elif kind == F.DATA:
            blen = rnd.randrange(76, 211)
        else:
            blen = rnd.randrange(1, 211 if enc else 227)
        h = F.LinkHeader(kind, rnd.randrange(2**32), sid, counter, blen, enc)
        out.append(F.encode_link_header(h) + rnd.randbytes(blen + (16 if enc else 0)))
    return out


def route_seeds(rnd: random.Random, n: int) -> list[bytes]:
    out = []
    for _ in range(n):
        hops = rnd.choice([1, 2, 3, 20, 40, rnd.randrange(1, 41)])
        addrs = rnd.sample(range(1, 65535), hops + 1)
        idx = rnd.randrange(hops)
        h = F.RouteHeader(addrs[0], addrs[-1], hops, idx, hops - idx, rnd.randrange(2**32),
                          rnd.randrange(2**32), addrs[1:])
        out.append(F.encode_route(h) + rnd.randbytes(58 + rnd.randrange(30)))
    return out


def end_seeds(rnd: random.Random, n: int) -> list[bytes]:
    out = []
    for _ in range(n):
        kind = rnd.randrange(1, 6)
        pl = 35 if kind == F.REC_BITMAP else rnd.randrange(0, 100)
        port = rnd.randrange(1, 65535) if kind == F.REC_DATA else rnd.randrange(0, 65535)
        flags = rnd.choice([0x00, 0x01, 0x02, 0x11, 0x16, 0x0D, 0x1E])
        h = F.EndHeader(rnd.randrange(1, 2**32), rnd.randrange(1, 2**64), rnd.randbytes(16), port,
                        kind, flags, rnd.choice([0, rnd.randrange(2**64)]), pl)
        out.append(F.encode_end_header(h) + rnd.randbytes(pl + 16))
    return out


def hopack_seeds(rnd: random.Random, n: int) -> list[bytes]:
    return [F.encode_hop_ack(F.HopAck(rnd.randrange(1, 2**64), rnd.randrange(3),
                                      rnd.randrange(256), rnd.randrange(65536))) for _ in range(n)]


def frag_seeds(rnd: random.Random, n: int) -> list[bytes]:
    out = []
    for _ in range(n):
        total = rnd.choice([1, 16, 17, 94, 200, 512, 513, 4096, rnd.randrange(1, 4097)])
        offset = rnd.randrange(0, total, 16) if total > 1 else 0
        length = min(total - offset, rnd.choice([16, 32, 48, 80, 94, 16 * rnd.randrange(1, 6)]))
        p = F.FragmentPrefix(total, offset, length, rnd.choice([1, 2, 4]),
                             rnd.choice([0, 1, 2]) if total > 512 else rnd.choice([0, 1, 2]),
                             rnd.randbytes(32))
        out.append(F.encode_fragment_prefix(p) + rnd.randbytes(length))
    return out


def bitmap_seeds(rnd: random.Random, n: int) -> list[bytes]:
    return [F.encode_transfer_bitmap(F.TransferBitmap(0, rnd.randbytes(32), rnd.randrange(256)))
            for _ in range(n)]


def boot_seeds(rnd: random.Random, n: int) -> list[bytes]:
    out = []
    for _ in range(n):
        total = rnd.choice([1, 160, 1024, rnd.randrange(1, 1025)])
        length = min(total, rnd.choice([1, 80, 160]))
        offset = rnd.randrange(0, total - length + 1)
        out.append(F.encode_bootstrap(F.BootstrapCarrier(rnd.randbytes(16), rnd.randrange(256),
                                                         total, offset, rnd.randbytes(length))))
    return out


def fix_serial_crc(d: bytes) -> bytes:
    return d[:-4] + F.crc32_iso_hdlc(d[:-4]).to_bytes(4, "big") if len(d) >= 4 else d


def serial_seeds(rnd: random.Random, n: int) -> list[bytes]:
    out = []
    for _ in range(n):
        kind = rnd.randrange(1, 8)
        plen = rnd.choice([0, 1, 30, 1024, 1025, 8192, rnd.randrange(0, 300)])
        auth = kind not in (1, 2)
        body = rnd.randbytes(plen + (16 if auth else 0))
        h = F.SerialHeader(kind, rnd.randrange(2**32), rnd.randrange(2**64), plen)
        out.append(F.encode_serial_frame(h, body))
    return out


def poll_seeds(rnd: random.Random, n: int) -> list[bytes]:
    return [F.encode_power_poll(F.PowerPoll(rnd.choice([0, 2, 65535]),
                                            rnd.choice([1, 2**64 - 1, rnd.randrange(1, 2**64)]),
                                            rnd.randrange(2**32),
                                            rnd.choice([0, 5000, 86400000, 86400001]),
                                            rnd.choice([1, 250, 65535, 0]))) for _ in range(n)]


def grant_seeds(rnd: random.Random, n: int) -> list[bytes]:
    return [F.encode_power_grant(F.PowerGrant(rnd.randrange(65536),
                                              rnd.choice([1, 2**64 - 1, rnd.randrange(1, 2**64)]),
                                              rnd.choice([1, 200, 65535, 65536, 0]),
                                              rnd.randrange(65536), rnd.randrange(2**32)))
            for _ in range(n)]


# ---- control samples from the Python shape table ----
def valid_value(spec: tuple[Any, ...], rnd: random.Random) -> Any:
    k = spec[0]
    if k == "u":
        return rnd.choice([spec[1], spec[2], rnd.randint(spec[1], spec[2])])
    if k == "b":
        return rnd.randbytes(rnd.choice([spec[1], min(spec[2], spec[1] + 20)]))
    if k == "t":
        return "a" * rnd.choice([spec[1], min(spec[2], spec[1] + 5)])
    if k == "bool":
        return rnd.random() < 0.5
    if k == "list":
        n = min(rnd.choice([spec[1], spec[2], spec[1] + 1]), spec[2])
        return [valid_value(spec[3], rnd) for _ in range(n)]
    if k == "tuple":
        return [valid_value(s, rnd) for s in spec[1]]
    if k == "null":
        return rnd.choice([None, valid_value(spec[1], rnd)])
    if k == "key":
        return {1: 2, -1: 1, -2: rnd.randbytes(32), -3: rnd.randbytes(32)}
    return rnd.choice(C.SOCS)


def invalid_values(spec: tuple[Any, ...], rnd: random.Random) -> list[Any]:
    k = spec[0]
    if k == "u":
        v: list[Any] = [-1, "x", b"", True, None, spec[2] + 1]
        return v + ([spec[1] - 1] if spec[1] > 0 else [])
    if k == "b":
        v = [5, "s", None, rnd.randbytes(spec[2] + 1)]
        return v + ([rnd.randbytes(spec[1] - 1)] if spec[1] > 0 else [])
    if k == "t":
        v = [5, b"s", None, "a" * (spec[2] + 1)]
        return v + (["a" * (spec[1] - 1)] if spec[1] > 0 else [])
    if k == "bool":
        return [0, 1, None, "t"]
    if k == "list":
        elem_bad = invalid_values(spec[3], rnd)[0]
        v = [5, [valid_value(spec[3], rnd) for _ in range(spec[2] + 1)], [elem_bad]]
        return v + ([[valid_value(spec[3], rnd) for _ in range(spec[1] - 1)]] if spec[1] > 0 else [])
    if k == "tuple":
        good = [valid_value(s, rnd) for s in spec[1]]
        return [5, good[:-1], [*good, 0], [good[0], *good[1:-1], None]]
    if k == "null":
        return [5, "x", b""]
    if k == "key":
        g = valid_value(spec, rnd)
        return [5, {**g, 1: 3}, {**g, -1: 2}, {**g, -2: b"x"}, {1: 2, -1: 1, -2: g[-2]}, [1, 2]]
    return ["esp32", "ESP32C3", b"esp32c3", 7]


def control_body(typ: Any, version: Any, rid: Any, dom: Any, rev: Any, iss: Any, data: Any) -> bytes | None:
    try:
        return cbor_encode([typ, version, rid, dom, rev, iss, data])
    except (WireError, TypeError):
        return None  # value not encodable (e.g. u64+1): not a wire input at all


def control_seeds(rnd: random.Random) -> tuple[list[bytes], list[bytes]]:
    """(valid samples per type, targeted invalid variants)."""
    ok: list[bytes] = []
    bad: list[bytes] = []
    base = (bytes(16), bytes(range(16)), 1, bytes(range(32)))
    for typ, shape in C.SHAPES.items():
        for _ in range(3):
            data = [valid_value(s, rnd) for s in shape]
            b = control_body(typ, 1, *base, data)
            assert b is not None
            ok.append(b)
        data = [valid_value(s, rnd) for s in shape]
        for i, spec in enumerate(shape):
            for v in invalid_values(spec, rnd):
                b = control_body(typ, 1, *base, [*data[:i], v, *data[i + 1 :]])
                if b is not None:
                    bad.append(b)
        for cut in (data[:-1], [*data, 0], [], 5, None):
            b = control_body(typ, 1, *base, cut)
            if b is not None:
                bad.append(b)
    data = [valid_value(s, rnd) for s in C.SHAPES[16]]
    for typ in (0, 22, 23, 24, 34, 255, 256, 2**32 - 1, 2**32, -1, "x", True):
        b = control_body(typ, 1, *base, data)
        if b is not None:
            bad.append(b)
    for ver in (0, 2, 2**32, -1, "1"):
        b = control_body(16, ver, *base, data)
        if b is not None:
            bad.append(b)
    for rid, dom, rev, iss in ((b"", base[1], 1, base[3]), (base[0], b"x", 1, base[3]),
                               (base[0], base[1], 2**63, base[3]), (base[0], base[1], -1, base[3]),
                               (base[0], base[1], 1, b"\x00" * 31), (base[0], base[1], 1, "s")):
        b = control_body(16, 1, rid, dom, rev, iss, data)
        if b is not None:
            bad.append(b)
    good = cbor_encode([16, 1, *base, data])
    bad += [good[:-1], good + b"\x00", b"\x86" + good[1:]]
    return ok, bad


# ---- CBOR corpus ----
INTS = [0, 1, 23, 24, 25, 255, 256, 65535, 65536, 2**32 - 1, 2**32, 2**64 - 1,
        -1, -24, -25, -256, -257, -(2**32), -(2**64)]


def random_value(rnd: random.Random, depth: int = 0) -> Any:
    kinds = ["int", "int", "bytes", "text", "bool", "null"] + (["list", "map"] if depth < 4 else [])
    k = rnd.choice(kinds)
    if k == "int":
        return rnd.choice(INTS + [rnd.randrange(-1000, 100000)])
    if k == "bytes":
        return rnd.randbytes(rnd.choice([0, 1, 23, 24, 25, 255, 256, rnd.randrange(40)]))
    if k == "text":
        return "".join(rnd.choice(["a", "Z", "é", "€", "\U0001f600", " "])
                       for _ in range(rnd.randrange(30)))
    if k == "bool":
        return rnd.random() < 0.5
    if k == "null":
        return None
    if k == "list":
        return [random_value(rnd, depth + 1) for _ in range(rnd.choice([0, 1, 2, 23, 24, 25]))]
    keys = rnd.sample([*range(-30, 60), b"", b"k", "", "a", "bb"], rnd.randrange(0, 8))
    return {key: random_value(rnd, depth + 1) for key in keys}


def has_bool_map_key(x: Any) -> bool:
    if isinstance(x, list):
        return any(has_bool_map_key(y) for y in x)
    if isinstance(x, dict):
        return any(isinstance(k, bool) for k in x) or any(has_bool_map_key(v) for v in x.values())
    return False


def fixture_outcome(d: bytes) -> Outcome:
    try:
        return "ok", render(fx.decode(d))
    except ValueError:
        return "err", None


HANDCRAFTED_CBOR = [
    "1800", "190000", "1a0000ffff", "1b00000000ffffffff", "5800", "9f01ff", "5f4101ff", "7f6161ff",
    "f90000", "fa3f800000", "fb3ff0000000000000", "f7", "f0", "f820", "c074323030", "d2400000",
    "a2010101", "a1010100", "a201020102", "a202010101", "a1f401", "a1810101", "6180", "62c0af",
    "63eda080", "64f4908080", "8301", "0000", "", "9f", "ff", "a0", "80", "f4", "f5", "f6", "1b",
    "a201020304", "a2616101616202", "a2626161016161 02".replace(" ", ""), "bf", "5fff", "7fff",
    "a2f5f5f4f4", "a3020001f4f5f4", "a20001f401",
]


# ---- tests ----
def test_cbor_differential(lmtool: LmTool) -> None:
    rnd = random.Random(0xC0FFEE)
    values = [random_value(rnd) for _ in range(400)]
    encoded = [cbor_encode(v) for v in values]
    # The three encoders agree byte for byte (Python host vs fixture), and C++ renders the same.
    for v, e in zip(values, encoded, strict=True):
        assert e == fx.cbor(v)
    seeds = encoded + [bytes.fromhex(h) for h in HANDCRAFTED_CBOR]
    inputs = corpus(seeds, rnd, per_seed=12, truncate=False)
    accepted, rejected = compare(lmtool, "cbor", inputs)
    assert accepted > 500 and rejected > 3000
    # Every valid seed decodes back to its value (Python) and is accepted by C++.
    for v, e in zip(values[:200], encoded, strict=False):
        assert cbor_decode(e) == v

    # Fixture as the third oracle: agree on accept/reject and on the value, except the one
    # divergence found: it accepts booleans as map keys (bool is an int subclass in Python and
    # only collides with 0/1). The contract (control.cddl) allows uint/nint/bstr/tstr keys only.
    cpp = lmtool.run([f"cbor {d.hex() or '-'}" for d in inputs])
    known = 0
    for d, reply in zip(inputs, cpp, strict=True):
        fk, fv = fixture_outcome(d)
        if (fk == "ok") == bool(reply["ok"]):
            assert fk == "err" or fv == reply["v"], d.hex()
            continue
        assert fk == "ok", f"fixture rejects what C++ accepts: {d.hex()}"
        assert has_bool_map_key(fx.decode(d)), f"unexplained fixture divergence: {d.hex()}"
        known += 1
    print(f"cbor: {len(inputs)} inputs, {accepted} accepted, fixture bool-key divergences: {known}")


SEED_COUNT = {"link": 60, "route": 50, "end": 60, "hopack": 20, "frag": 60, "bitmap": 15,
              "boot": 30, "serial": 30, "poll": 30, "grant": 30}
GENERATORS: dict[str, Callable[[random.Random, int], list[bytes]]] = {
    "link": link_seeds, "route": route_seeds, "end": end_seeds, "hopack": hopack_seeds,
    "frag": frag_seeds, "bitmap": bitmap_seeds, "boot": boot_seeds, "serial": serial_seeds,
    "poll": poll_seeds, "grant": grant_seeds,
}


@pytest.mark.parametrize("name", list(GENERATORS))
def test_frame_codec_differential(lmtool: LmTool, name: str) -> None:
    rnd = random.Random(f"lm1-{name}")
    seeds = GENERATORS[name](rnd, SEED_COUNT[name])
    fix = fix_serial_crc if name == "serial" else None
    # Long serial seeds are truncated only at the header region: every prefix of an 8 KiB record
    # is rejected by the same length rule and would only slow the pipe.
    seeds_t = [s for s in seeds if len(s) <= 400]
    inputs = corpus(seeds_t, rnd, fix=fix) + corpus(
        [s for s in seeds if len(s) > 400], rnd, per_seed=10, fix=fix, truncate=False
    )
    accepted, rejected = compare(lmtool, name, inputs)
    assert accepted >= len(seeds) // 2, f"{name}: too few valid seeds ({accepted})"
    assert rejected > 100, f"{name}: mutations should be rejected ({rejected})"
    print(f"{name}: {len(inputs)} inputs, {accepted} accepted, {rejected} rejected")


def test_every_length_0_to_250_all_rf_decoders(lmtool: LmTool) -> None:
    rnd = random.Random(250)
    for name in ("link", "route", "end", "hopack", "frag", "bitmap", "boot", "poll", "grant", "cose"):
        inputs = [rnd.randbytes(n) for n in range(251) for _ in range(3)]
        compare(lmtool, name, inputs)  # agreement on random garbage of every length
        replies = lmtool.run([f"{CODECS[name][0]} {d.hex() or '-'}" for d in inputs])
        assert all(r["ok"] is False or r["ok"] is True for r in replies)  # no crash: 1 reply each


def test_control_differential(lmtool: LmTool) -> None:
    rnd = random.Random(0xC0117201)
    ok, bad = control_seeds(rnd)
    for carrier in ("control-signed", "control-session"):
        acc, rej = compare(lmtool, carrier, ok + bad)
        assert rej > 300
        # Valid samples are accepted exactly under the carrier their type belongs to.
        want = len(C.SIGNED_TYPES) * 3 if carrier == "control-signed" else (len(C.SHAPES) - len(C.SIGNED_TYPES)) * 3
        assert acc >= want, (carrier, acc, want)
    mutated = corpus(ok, rnd, per_seed=25, truncate=False)
    compare(lmtool, "control-signed", mutated)
    compare(lmtool, "control-session", mutated)


def test_cose_and_signature_structure_against_fixture(lmtool: LmTool) -> None:
    v = fx.cose_fixture()
    fx.check_cose(v)  # the fixture's own verification (real ECDSA)
    raw = bytes.fromhex(v["cose_sign1_hex"])
    reply = lmtool.run([f"cose {raw.hex()}"])[0]
    assert reply["ok"]
    assert reply["kid"] == v["device_id_hex"]
    assert reply["protected"] == v["protected_hex"]
    assert reply["payload"] == v["payload_hex"]
    assert reply["signature"] == v["signature_raw_hex"]
    assert reply["sig_prefix"] + reply["payload"] == v["sig_structure_hex"]
    assert py_cose(raw)["sig_prefix"] == reply["sig_prefix"]
    payload = bytes.fromhex(v["payload_hex"])
    assert lmtool.run([f"control signed {payload.hex()}"])[0]["type"] == 3
    assert lmtool.run([f"control session {payload.hex()}"])[0] == {"ok": False, "e": "AUTH_REJECTED"}
    # Mutated COSE structures agree between the codecs.
    rnd = random.Random(18)
    seeds = [raw] + [C.encode_cose_sign1(rnd.randbytes(32), rnd.randbytes(rnd.randrange(0, 300)),
                                         rnd.randbytes(64)) for _ in range(20)]
    acc, rej = compare(lmtool, "cose", corpus(seeds, rnd, per_seed=30, truncate=False))
    assert acc >= 21 and rej > 100
    # 4096-byte object limit for the whole COSE_Sign1.
    big = C.encode_cose_sign1(bytes(32), bytes(4096 - 3 - 41 - 70), bytes(64))
    assert len(big) <= 4096
    assert compare(lmtool, "cose", [big, big + b"\x00" * (4097 - len(big))])[0] == 1


def fixture_plain_ok(p: bytes) -> bool:
    """The route/end plaintext checks of fx.open_frame (after the AEAD), for DATA records."""
    try:
        origin, final, n, index, budget, res, _term, _rev = fx.ROUTE.unpack(p[:16])
        if not 1 <= n <= 40 or index >= n or budget != n - index or res != 0:
            return False
        path = list(struct.unpack(">" + "H" * n, p[16 : 16 + 2 * n]))
        if len(set([origin, *path])) != n + 1 or final != path[-1] or any(x in (0, 65535) for x in path):
            return False
        off = 16 + 2 * n
        esid, ectr, _mid, port, rkind, eflags, _exp, length = fx.END.unpack(p[off : off + 42])
        if not esid or not ectr or port in (0, 65535) or rkind != 1 or eflags & 0xE0 or eflags & 3 == 3:
            return False
        return len(p) == off + 42 + length + 16
    except (struct.error, ValueError):
        return False


def sdk_plain_ok(tool: LmTool, p: bytes) -> tuple[bool, int]:
    """Whether the SDK accepts route+end plaintext; returns (accepted, end record kind or 0)."""
    r = tool.run([f"route {p.hex()}"])[0]
    if not r["ok"]:
        return False, 0
    e = tool.run([f"end {p[r['end_offset']:].hex()}"])[0]
    return bool(e["ok"]), e.get("record_kind", 0)


def fixture_link_plain(v: dict[str, Any]) -> bytes:
    packet = bytes.fromhex(v["packet_hex"])
    ctr = struct.unpack(">Q", packet[12:20])[0]
    lc = bytes.fromhex(v["link_context_hex"])
    key, prefix = fx.record_key(bytes.fromhex(v["link_exporter_test_seed_hex"]), lc, 1, 0)
    return fx.AESGCM(key).decrypt(prefix + struct.pack(">Q", ctr), packet[24:],
                                  packet[:24] + fx.hashlib.sha256(lc).digest())


def test_fixture_frames_1_to_40_hops_and_mutated_plaintext(lmtool: LmTool) -> None:
    rnd = random.Random(40)
    mutants: list[bytes] = []
    for hops in range(1, 41):
        v = fx.frame(hops)
        assert len(fx.open_frame(v)) == 136 - 2 * hops == F.data_capacity(hops)
        packet = bytes.fromhex(v["packet_hex"])
        link = lmtool.run([f"link {packet.hex()}"])[0]
        lh = fx.LINK.unpack(packet[:24])
        assert (link["kind"], link["domain_hint"], link["sid"], link["counter"], link["body_length"]) == (
            lh[2], lh[3], lh[4], lh[5], lh[6])
        assert link["encrypted"] and link["payload_len"] == 226
        assert py_link(packet) == {k: val for k, val in link.items() if k != "ok"}

        plain = fixture_link_plain(v)
        route = lmtool.run([f"route {plain.hex()}"])[0]
        rh = fx.ROUTE.unpack(plain[:16])
        assert route["ok"] and (route["origin"], route["final"], route["path_len"],
                                route["next_index"], route["budget"], route["root_term"],
                                route["path_revision"]) == (rh[0], rh[1], rh[2], rh[3], rh[4], rh[6], rh[7])
        assert route["path"] == list(struct.unpack(">" + "H" * hops, plain[16 : 16 + 2 * hops]))
        assert route["end_offset"] == 16 + 2 * hops
        end = lmtool.run([f"end {plain[route['end_offset']:].hex()}"])[0]
        eh = fx.END.unpack(plain[route["end_offset"] : route["end_offset"] + 42])
        assert end["ok"] and (end["end_sid"], end["end_counter"], end["message_id"], end["app_port"],
                              end["record_kind"], end["flags"], end["expires_root_ms"],
                              end["plaintext_length"]) == (eh[0], eh[1], eh[2].hex(), eh[3], eh[4],
                                                           eh[5], eh[6], eh[7])
        assert end["plaintext_length"] == 136 - 2 * hops
        if hops in (1, 3, 20, 40) or hops % 7 == 0:
            mutants += [plain] + [mutate(rnd, plain) for _ in range(60)] + edge_substitutions(plain, 60)
    # SDK vs fixture on mutated (decrypted) routed bodies: the SDK accepts whatever the fixture
    # accepts, and everything the SDK accepts as a DATA record the fixture accepts, with the one
    # documented difference: the SDK also refuses an origin of 0 or 0xFFFF (docs/04 §4), which the
    # fixture does not test.
    both = sdk_only = fixture_only = 0
    for p in mutants:
        fixture_ok = fixture_plain_ok(p)
        sdk_ok, kind = sdk_plain_ok(lmtool, p)
        origin = struct.unpack(">H", p[:2])[0] if len(p) >= 2 else 1
        if fixture_ok and origin in (0, 65535):
            assert not sdk_ok, p.hex()
            fixture_only += 1
            continue
        if fixture_ok:
            assert sdk_ok and kind == 1, f"SDK rejects fixture-valid body: {p.hex()}"
            both += 1
        elif sdk_ok and kind == 1:
            sdk_only += 1
            pytest.fail(f"SDK accepts DATA body the fixture rejects: {p.hex()}")
    assert both > 40, both


def test_fixture_fragments_and_bitmap_layout(lmtool: LmTool) -> None:
    rnd = random.Random(4096)
    for _ in range(60):
        hops = rnd.choice([1, 2, 3, 20, 39, 40, rnd.randrange(1, 41)])
        total = rnd.choice([1, 15, 16, 17, 80, 512, 513, 4096, rnd.randrange(1, 4097)])
        payload = rnd.randbytes(total)
        ih = rnd.randbytes(32)
        chunks = fx.fragments(payload, hops, ih)
        assert fx.reassemble(chunks) == payload
        assert len(chunks[0]) - 40 <= F.fragment_chunk(hops) or len(chunks) == 1
        replies = lmtool.run([f"frag {c.hex()}" for c in chunks])
        rebuilt = bytearray(total)
        for c, r in zip(chunks, replies, strict=True):
            assert r["ok"], (hops, total, r)
            assert (r["total"], r["offset"], r["len"]) == struct.unpack(">HHH", c[:6])
            assert r["intent_hash"] == ih.hex()
            assert r["len"] <= F.fragment_chunk(hops) or r["offset"] + r["len"] == total
            rebuilt[r["offset"] : r["offset"] + r["len"]] = c[40:]
            assert py_frag(c) == {k: v for k, v in r.items() if k != "ok"}
        assert bytes(rebuilt) == payload
    # Fixture bitmap semantics: bit0 of byte0 is offset 0; 16 B units, 256 bits.
    bm = bytearray(32)
    for off in (0, 16, 144, 4080):
        bm[off // 16 // 8] |= 1 << (off // 16 % 8)
    b = F.decode_transfer_bitmap(F.encode_transfer_bitmap(F.TransferBitmap(0, bytes(bm), 3)))
    assert [o for o in range(0, 4096, 16) if b.test(o)] == [0, 16, 144, 4080]


@pytest.mark.scenario("R04")
def test_r04_duplicate_source_route_codec_part(lmtool: LmTool) -> None:
    """R04 (codec part): AEAD-valid DATA with a repeated address never reaches the app. Here the
    routed-body decoder must refuse it; the AEAD result is irrelevant to the structural check."""
    v = fx.frame(3)
    plain = bytearray(fixture_link_plain(v))
    assert lmtool.run([f"route {bytes(plain).hex()}"])[0]["ok"]
    # path [3,4,5] -> [3,4,3]: address 3 twice (final rewritten to stay consistent)
    dup = bytearray(plain)
    dup[16 + 4 : 16 + 6] = struct.pack(">H", 3)
    dup[2:4] = struct.pack(">H", 3)
    assert lmtool.run([f"route {bytes(dup).hex()}"])[0] == {"ok": False, "e": "BAD_FRAME"}
    # origin repeated as a path entry
    loop = bytearray(plain)
    loop[16:18] = struct.pack(">H", struct.unpack(">H", plain[0:2])[0])
    assert lmtool.run([f"route {bytes(loop).hex()}"])[0] == {"ok": False, "e": "BAD_FRAME"}
    with pytest.raises(WireError):
        F.decode_route(bytes(dup))
    with pytest.raises(WireError):
        F.decode_route(bytes(loop))
