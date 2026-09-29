// lmtool: line-oriented codec CLI over the SDK's wire codecs, for differential tests only
// (host/tests/unit/test_wire_differential.py). It reads one command per stdin line
//   <command> [arg] <hex>
// and prints one JSON object per line: {"ok":true,...} or {"ok":false,"e":"<STATUS>"}.
// Successful decodes also print "re", the hex of the SDK's re-encoding of the parsed fields,
// which must equal the input (the whole input, or the structural prefix noted per command).
// Not part of any firmware image; no crypto, no I/O beyond stdin/stdout.
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "core/wire/cbor_reader.hpp"
#include "core/wire/control.hpp"
#include "core/wire/frame.hpp"
#include "core/wire/power_frame.hpp"
#include "core/wire/serial_header.hpp"
#include "core/wire/transfer.hpp"

using namespace lm;
using namespace lm::wire;
using Bytes = std::vector<uint8_t>;

namespace {

std::string hex(ByteView v) {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    for (const uint8_t b : v) {
        s.push_back(digits[b >> 4U]);
        s.push_back(digits[b & 15U]);
    }
    return s;
}

bool parse_hex(const std::string &s, Bytes &out) {
    out.clear();
    if (s.size() % 2 != 0) {
        return false;
    }
    for (std::size_t i = 0; i < s.size(); i += 2) {
        unsigned v = 0;
        if (std::sscanf(s.c_str() + i, "%2x", &v) != 1) {
            return false;
        }
        out.push_back(static_cast<uint8_t>(v));
    }
    return true;
}

// Tiny JSON object builder: every value is a number, bool or hex/plain string.
class Json {
  public:
    Json &num(const char *k, uint64_t v) { return raw(k, std::to_string(v)); }
    Json &flag(const char *k, bool v) { return raw(k, v ? "true" : "false"); }
    Json &str(const char *k, const std::string &v) { return raw(k, "\"" + v + "\""); }
    Json &hexv(const char *k, ByteView v) { return str(k, hex(v)); }
    Json &list(const char *k, const uint16_t *v, std::size_t n) {
        std::string s = "[";
        for (std::size_t i = 0; i < n; ++i) {
            s += (i ? "," : "") + std::to_string(v[i]);
        }
        return raw(k, s + "]");
    }
    [[nodiscard]] std::string done() const { return "{\"ok\":true" + body_ + "}"; }

  private:
    Json &raw(const char *k, const std::string &v) {
        body_ += std::string(",\"") + k + "\":" + v;
        return *this;
    }
    std::string body_;
};

std::string fail(Status s) { return std::string("{\"ok\":false,\"e\":\"") + status_name(s) + "\"}"; }

// Canonical text of a decoded item, shared with the Python side:
// ints as decimal, bstr h'..', tstr t'<hex of utf-8>', [a,b], {k:v,...}, true/false/null.
void render(CborReader &r, std::string &out) {
    CborReader::Item it;
    if (!r.next(it)) {
        out += "?";
        return;
    }
    switch (it.type) {
    case CborType::Uint:
        out += std::to_string(it.arg);
        break;
    case CborType::Nint:
        out += it.arg == UINT64_MAX ? std::string("-18446744073709551616")
                                    : "-" + std::to_string(it.arg + 1);
        break;
    case CborType::Bytes:
        out += "h'" + hex(it.data) + "'";
        break;
    case CborType::Text:
        out += "t'" + hex(it.data) + "'";
        break;
    case CborType::Array:
        out += "[";
        for (uint64_t i = 0; i < it.arg; ++i) {
            out += i ? "," : "";
            render(r, out);
        }
        out += "]";
        break;
    case CborType::Map:
        out += "{";
        for (uint64_t i = 0; i < it.arg; ++i) {
            out += i ? "," : "";
            render(r, out);
            out += ":";
            render(r, out);
        }
        out += "}";
        break;
    case CborType::Bool:
        out += it.arg != 0 ? "true" : "false";
        break;
    case CborType::Null:
        out += "null";
        break;
    }
}

std::string cmd_cbor(ByteView in) {
    const Status s = cbor_validate(in);
    if (s != Status::Ok) {
        return fail(s);
    }
    CborReader r{in};
    std::string text;
    render(r, text);
    return Json{}.str("v", text).done();
}

std::string cmd_link(ByteView in) {
    LinkHeader h;
    ByteView payload;
    const Status s = decode_link_frame(in, h, payload);
    if (s != Status::Ok) {
        return fail(s);
    }
    std::array<uint8_t, k_link_header_bytes> re{};
    if (encode_link_header(h, MutByteView{re}) != Status::Ok) {
        return fail(Status::RecoveryRequired);
    }
    return Json{}
        .num("kind", static_cast<uint8_t>(h.kind))
        .num("domain_hint", h.domain_hint)
        .num("sid", h.link_sid)
        .num("counter", h.link_counter)
        .num("body_length", h.body_length)
        .flag("encrypted", h.encrypted)
        .num("payload_len", payload.size())
        .hexv("re", ByteView{re})
        .done();
}

std::string cmd_route(ByteView in) {
    RouteHeader h;
    ByteView end;
    const Status s = decode_route(in, h, end);
    if (s != Status::Ok) {
        return fail(s);
    }
    Bytes re(k_route_header_bytes + 2 * k_max_path);
    std::size_t n = 0;
    if (encode_route(h, MutByteView{re.data(), re.size()}, n) != Status::Ok) {
        return fail(Status::RecoveryRequired);
    }
    return Json{}
        .num("origin", h.origin)
        .num("final", h.final)
        .num("path_len", h.path_len)
        .num("next_index", h.next_index)
        .num("budget", h.budget)
        .num("root_term", h.root_term)
        .num("path_revision", h.path_revision)
        .list("path", h.path.data(), h.path_len)
        .num("end_offset", in.size() - end.size())
        .hexv("re", ByteView{re.data(), n})
        .done();
}

std::string cmd_end(ByteView in) {
    EndHeader h;
    ByteView sealed;
    const Status s = decode_end_record(in, h, sealed);
    if (s != Status::Ok) {
        return fail(s);
    }
    std::array<uint8_t, k_end_header_bytes> re{};
    if (encode_end_header(h, MutByteView{re}) != Status::Ok) {
        return fail(Status::RecoveryRequired);
    }
    return Json{}
        .num("end_sid", h.end_sid)
        .num("end_counter", h.end_counter)
        .hexv("message_id", ByteView{h.message_id})
        .num("app_port", h.app_port)
        .num("record_kind", static_cast<uint8_t>(h.record_kind))
        .num("flags", h.flags)
        .num("delivery", static_cast<uint8_t>(h.delivery()))
        .num("priority", static_cast<uint8_t>(h.priority()))
        .flag("durable", h.durable())
        .num("expires_root_ms", h.expires_root_ms)
        .num("plaintext_length", h.plaintext_length)
        .hexv("re", ByteView{re})
        .done();
}

std::string cmd_hopack(ByteView in) {
    HopAck a;
    const Status s = decode_hop_ack(in, a);
    if (s != Status::Ok) {
        return fail(s);
    }
    std::array<uint8_t, k_hop_ack_body_bytes> re{};
    std::size_t n = 0;
    (void)encode_hop_ack(a, MutByteView{re}, n);
    return Json{}
        .num("acked", a.acked_link_counter)
        .num("status", static_cast<uint8_t>(a.status))
        .num("credit", a.credit)
        .num("retry_after_ms", a.retry_after_ms)
        .hexv("re", ByteView{re})
        .done();
}

std::string cmd_frag(ByteView in) {
    FragmentPrefix p;
    ByteView bytes;
    const Status s = decode_fragment(in, p, bytes);
    if (s != Status::Ok) {
        return fail(s);
    }
    std::array<uint8_t, k_fragment_prefix_bytes> re{};
    (void)encode_fragment_prefix(p, MutByteView{re});
    return Json{}
        .num("total", p.total_len)
        .num("offset", p.offset)
        .num("len", p.fragment_len)
        .num("orig_kind", static_cast<uint8_t>(p.original_kind))
        .num("class", static_cast<uint8_t>(p.object_class))
        .hexv("intent_hash", ByteView{p.intent_hash})
        .hexv("re", ByteView{re})
        .done();
}

std::string cmd_bitmap(ByteView in) {
    TransferBitmap b;
    const Status s = decode_transfer_bitmap(in, b);
    if (s != Status::Ok) {
        return fail(s);
    }
    std::array<uint8_t, k_transfer_bitmap_body> re{};
    (void)encode_transfer_bitmap(b, MutByteView{re});
    return Json{}
        .hexv("bitmap", ByteView{b.bitmap})
        .num("credit", b.credit)
        .hexv("re", ByteView{re})
        .done();
}

std::string cmd_boot(ByteView in) {
    BootstrapCarrier c;
    const Status s = decode_bootstrap(in, c);
    if (s != Status::Ok) {
        return fail(s);
    }
    Bytes re(in.size());
    std::size_t n = 0;
    (void)encode_bootstrap(c, MutByteView{re.data(), re.size()}, n);
    return Json{}
        .hexv("exchange_id", ByteView{c.exchange_id})
        .num("object_kind", c.object_kind)
        .num("total", c.total)
        .num("offset", c.offset)
        .hexv("body", c.body)
        .hexv("re", ByteView{re.data(), n})
        .done();
}

std::string cmd_serial(ByteView in) {
    SerialHeader h;
    ByteView body;
    const Status s = decode_serial_frame(in, h, body);
    if (s != Status::Ok) {
        return fail(s);
    }
    Bytes re(in.size());
    std::size_t n = 0;
    (void)encode_serial_frame(h, body, MutByteView{re.data(), re.size()}, n);
    return Json{}
        .num("kind", static_cast<uint8_t>(h.kind))
        .num("session_id", h.session_id)
        .num("counter", h.counter)
        .num("payload_len", h.payload_len)
        .hexv("body", body)
        .hexv("re", ByteView{re.data(), n})
        .done();
}

std::string cmd_poll(ByteView in) {
    PowerPoll p;
    const Status s = decode_power_poll(in, p);
    if (s != Status::Ok) {
        return fail(s);
    }
    std::array<uint8_t, 28> re{};
    std::size_t n = 0;
    (void)encode_power_poll(p, MutByteView{re}, n);
    return Json{}
        .num("rx_credit", p.rx_credit)
        .num("nonce", p.poll_nonce)
        .num("revision_hint", p.revision_hint)
        .num("interval_ms", p.planned_interval_ms)
        .num("window_ms", p.window_ms)
        .hexv("re", ByteView{re.data(), n})
        .done();
}

std::string cmd_grant(ByteView in) {
    PowerGrant g;
    const Status s = decode_power_grant(in, g);
    if (s != Status::Ok) {
        return fail(s);
    }
    std::array<uint8_t, 24> re{};
    std::size_t n = 0;
    (void)encode_power_grant(g, MutByteView{re}, n);
    return Json{}
        .num("pending", g.pending_frames)
        .num("nonce", g.poll_nonce)
        .num("ttl_ms", g.window_ttl_ms)
        .num("credit", g.granted_credit)
        .num("reason", g.reason)
        .hexv("re", ByteView{re.data(), n})
        .done();
}

std::string cmd_control(ControlCarrier carrier, ByteView in) {
    ControlBody b;
    const Status s = decode_control_body(in, carrier, b);
    if (s != Status::Ok) {
        return fail(s);
    }
    Bytes re(in.size());
    std::size_t n = 0;
    (void)encode_control_body(b, MutByteView{re.data(), re.size()}, n);
    return Json{}
        .num("type", b.type)
        .num("version", b.version)
        .hexv("request_id", ByteView{b.request_id})
        .hexv("domain", ByteView{b.domain})
        .num("revision", b.revision)
        .hexv("issuer", ByteView{b.issuer})
        .hexv("data", b.data)
        .hexv("re", ByteView{re.data(), n})
        .done();
}

std::string cmd_cose(ByteView in) {
    CoseSign1 c;
    const Status s = decode_cose_sign1(in, c);
    if (s != Status::Ok) {
        return fail(s);
    }
    Bytes re(in.size());
    std::size_t n = 0;
    (void)encode_cose_sign1(c.kid, c.payload, c.signature, MutByteView{re.data(), re.size()}, n);
    std::array<uint8_t, k_sig_prefix_max> prefix{};
    std::size_t pn = 0;
    (void)sig_structure_prefix(c.protected_bytes, c.payload.size(), MutByteView{prefix}, pn);
    return Json{}
        .hexv("kid", ByteView{c.kid})
        .hexv("protected", c.protected_bytes)
        .hexv("payload", c.payload)
        .hexv("signature", c.signature)
        .hexv("sig_prefix", ByteView{prefix.data(), pn})
        .hexv("re", ByteView{re.data(), n})
        .done();
}

std::string dispatch(const std::string &cmd, const std::string &arg, ByteView in) {
    if (cmd == "cbor") return cmd_cbor(in);
    if (cmd == "link") return cmd_link(in);
    if (cmd == "route") return cmd_route(in);
    if (cmd == "end") return cmd_end(in);
    if (cmd == "hopack") return cmd_hopack(in);
    if (cmd == "frag") return cmd_frag(in);
    if (cmd == "bitmap") return cmd_bitmap(in);
    if (cmd == "boot") return cmd_boot(in);
    if (cmd == "serial") return cmd_serial(in);
    if (cmd == "poll") return cmd_poll(in);
    if (cmd == "grant") return cmd_grant(in);
    if (cmd == "cose") return cmd_cose(in);
    if (cmd == "control") {
        return cmd_control(arg == "signed" ? ControlCarrier::Signed : ControlCarrier::Session, in);
    }
    return std::string("{\"ok\":false,\"e\":\"UNKNOWN_COMMAND\"}");
}

} // namespace

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream ss(line);
        std::string cmd;
        std::string arg;
        std::string hexarg;
        ss >> cmd;
        if (cmd == "control") {
            ss >> arg;
        }
        ss >> hexarg; // an empty input is written as "-"
        Bytes in;
        if (hexarg == "-") {
            hexarg.clear();
        }
        if (!parse_hex(hexarg, in)) {
            std::puts("{\"ok\":false,\"e\":\"BAD_HEX\"}");
        } else {
            std::puts(dispatch(cmd, arg, ByteView{in.data(), in.size()}).c_str());
        }
        std::fflush(stdout);
    }
    return 0;
}
