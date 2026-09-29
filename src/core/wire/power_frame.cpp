#include "core/wire/power_frame.hpp"

#include "core/codec.hpp"
#include "gen/registry.hpp"

namespace lm::wire {
namespace {
constexpr uint32_t k_max_interval_ms = 86400000;
}

uint8_t power_subtype(ByteView plain) { return plain.empty() ? 0 : plain[0]; }

Status decode_power_poll(ByteView plain, PowerPoll &out) {
    Reader r{plain};
    PowerPoll p;
    const uint8_t subtype = r.u8();
    const uint8_t version = r.u8();
    p.rx_credit = r.u16be();
    p.poll_nonce = r.u64be();
    p.revision_hint = r.u32be();
    p.planned_interval_ms = r.u32be();
    p.window_ms = r.u16be();
    const uint16_t flags = r.u16be();
    const uint32_t reserved = r.u32be();
    if (!r.ok() || r.finish() != Status::Ok || plain.size() != gen::layout::power_poll_bytes ||
        subtype != k_power_poll_subtype) {
        return Status::BadFrame;
    }
    if (version != k_power_version) {
        return Status::Unsupported;
    }
    if (p.poll_nonce == 0 || p.planned_interval_ms > k_max_interval_ms || p.window_ms == 0 ||
        flags != 0 || reserved != 0) {
        return Status::BadFrame;
    }
    out = p;
    return Status::Ok;
}

Status decode_power_grant(ByteView plain, PowerGrant &out) {
    Reader r{plain};
    PowerGrant g;
    const uint8_t subtype = r.u8();
    const uint8_t version = r.u8();
    g.pending_frames = r.u16be();
    g.poll_nonce = r.u64be();
    g.window_ttl_ms = r.u32be();
    g.granted_credit = r.u16be();
    const uint16_t reserved = r.u16be();
    g.reason = r.u32be();
    if (!r.ok() || r.finish() != Status::Ok || plain.size() != gen::layout::power_grant_bytes ||
        subtype != k_power_grant_subtype) {
        return Status::BadFrame;
    }
    if (version != k_power_version) {
        return Status::Unsupported;
    }
    if (g.poll_nonce == 0 || g.window_ttl_ms < 1 || g.window_ttl_ms > 0xFFFF || reserved != 0) {
        return Status::BadFrame;
    }
    out = g;
    return Status::Ok;
}

Status encode_power_poll(const PowerPoll &p, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(k_power_poll_subtype);
    w.u8(k_power_version);
    w.u16be(p.rx_credit);
    w.u64be(p.poll_nonce);
    w.u32be(p.revision_hint);
    w.u32be(p.planned_interval_ms);
    w.u16be(p.window_ms);
    w.u16be(0);
    w.u32be(0);
    len = w.size();
    return w.finish();
}

Status encode_power_grant(const PowerGrant &g, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(k_power_grant_subtype);
    w.u8(k_power_version);
    w.u16be(g.pending_frames);
    w.u64be(g.poll_nonce);
    w.u32be(g.window_ttl_ms);
    w.u16be(g.granted_credit);
    w.u16be(0);
    w.u32be(g.reason);
    len = w.size();
    return w.finish();
}

Status check_grant_against_poll(const PowerPoll &poll, const PowerGrant &grant) {
    return (grant.poll_nonce == poll.poll_nonce && grant.granted_credit <= poll.rx_credit &&
            grant.window_ttl_ms <= poll.window_ms)
               ? Status::Ok
               : Status::BadFrame;
}

} // namespace lm::wire
