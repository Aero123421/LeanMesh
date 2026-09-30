#include "core/wire/power_frame.hpp"

#include "core/codec.hpp"
#include "gen/registry.hpp"

namespace lm::wire {
namespace {
constexpr uint32_t k_max_interval_ms = 86400000;

// One field list per frame (core/codec.hpp). The version and the must-be-zero fields are read as values: a frame of
// another version is Unsupported before its fields are judged, and only a structurally broken one is BadFrame first.
template <class F> void io(F &f, PowerPoll &p, uint8_t &version, uint16_t &flags, uint32_t &reserved) {
    f.is(k_power_poll_subtype);
    f.u8(version);
    f.u16(p.rx_credit);
    f.u64(p.poll_nonce);
    f.u32(p.revision_hint);
    f.u32(p.planned_interval_ms);
    f.u16(p.window_ms);
    f.u16(flags);
    f.u32(reserved);
}
template <class F> void io(F &f, PowerGrant &g, uint8_t &version, uint16_t &reserved) {
    f.is(k_power_grant_subtype);
    f.u8(version);
    f.u16(g.pending_frames);
    f.u64(g.poll_nonce);
    f.u32(g.window_ttl_ms);
    f.u16(g.granted_credit);
    f.u16(reserved);
    f.u32(g.reason);
}

} // namespace

uint8_t power_subtype(ByteView plain) { return plain.empty() ? 0 : plain[0]; }

Status decode_power_poll(ByteView plain, PowerPoll &out) {
    PowerPoll p;
    uint8_t version = 0;
    uint16_t flags = 0;
    uint32_t reserved = 0;
    if (get_record(plain, p, [&](auto &f, auto &m) { io(f, m, version, flags, reserved); }) != Status::Ok ||
        plain.size() != gen::layout::power_poll_bytes) {
        return Status::BadFrame;
    }
    if (version != k_power_version) {
        return Status::Unsupported;
    }
    if (p.poll_nonce == 0 || p.planned_interval_ms > k_max_interval_ms || p.window_ms == 0 || flags != 0 || reserved != 0) {
        return Status::BadFrame;
    }
    out = p;
    return Status::Ok;
}

Status decode_power_grant(ByteView plain, PowerGrant &out) {
    PowerGrant g;
    uint8_t version = 0;
    uint16_t reserved = 0;
    if (get_record(plain, g, [&](auto &f, auto &m) { io(f, m, version, reserved); }) != Status::Ok ||
        plain.size() != gen::layout::power_grant_bytes) {
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
    uint8_t version = k_power_version;
    uint16_t flags = 0;
    uint32_t reserved = 0;
    return put_record(p, out, len, [&](auto &f, auto &m) { io(f, m, version, flags, reserved); });
}

Status encode_power_grant(const PowerGrant &g, MutByteView out, std::size_t &len) {
    uint8_t version = k_power_version;
    uint16_t reserved = 0;
    return put_record(g, out, len, [&](auto &f, auto &m) { io(f, m, version, reserved); });
}

Status check_grant_against_poll(const PowerPoll &poll, const PowerGrant &grant) {
    return (grant.poll_nonce == poll.poll_nonce && grant.granted_credit <= poll.rx_credit &&
            grant.window_ttl_ms <= poll.window_ms)
               ? Status::Ok
               : Status::BadFrame;
}

} // namespace lm::wire
