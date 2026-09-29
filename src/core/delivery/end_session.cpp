#include "core/delivery/end_session.hpp"

#include <cstring>

namespace lm::delivery {

EndSession *EndSessions::find_peer(const DeviceId &d) {
    for (EndSession &s : slots_) {
        if (s.used && s.peer == d) {
            return &s;
        }
    }
    return nullptr;
}

EndSession *EndSessions::find_rx_sid(uint32_t sid) {
    for (EndSession &s : slots_) {
        if (s.used && s.rx_sid == sid) {
            return &s;
        }
    }
    return nullptr;
}

bool EndSessions::sid_in_use(uint32_t sid) const {
    for (const EndSession &s : slots_) {
        if (s.used && s.rx_sid == sid) {
            return true;
        }
    }
    return false;
}

EndSession &EndSessions::acquire(const EndSession *keep) {
    EndSession *pick = nullptr;
    for (EndSession &s : slots_) {
        if (&s == keep) {
            continue;
        }
        if (!s.used) {
            return s;
        }
        if (pick == nullptr || static_cast<int32_t>(s.last_use - pick->last_use) < 0) {
            pick = &s;
        }
    }
    pick->wipe(); // capacity >= 2 in every profile, so a candidate always exists
    return *pick;
}

std::size_t EndSessions::count() const {
    std::size_t n = 0;
    for (const EndSession &s : slots_) {
        n += s.used ? 1U : 0U;
    }
    return n;
}

Status seal_end_record(sec::RecordSession &rec, const Sha256Digest &ctx_hash, uint32_t sid, RootTerm term,
                       wire::EndHeader h, ByteView plain, MutByteView out, std::size_t &len) {
    const std::size_t total = wire::k_end_header_bytes + plain.size() + wire::k_tag_bytes;
    if (!rec.active() || out.size() < total || plain.size() > 0xFFFF) {
        return Status::InvalidArgument;
    }
    uint64_t counter = 0;
    LM_TRY(rec.next_counter(counter)); // consumed even if sealing fails: a nonce is never reused
    h.end_sid = sid;
    h.end_counter = counter;
    h.plaintext_length = static_cast<uint16_t>(plain.size());
    LM_TRY(wire::encode_end_header(h, out.first(wire::k_end_header_bytes)));
    std::array<uint8_t, sec::k_end_aad_bytes> aad{};
    LM_TRY(sec::end_aad(ctx_hash, term, ByteView{out.data(), wire::k_end_header_bytes}, aad));
    LM_TRY(rec.seal(counter, ByteView{aad}, plain,
                    out.subspan(wire::k_end_header_bytes, plain.size() + wire::k_tag_bytes)));
    len = total;
    return Status::Ok;
}

Status open_end_record(sec::RecordSession &rec, const Sha256Digest &ctx_hash, RootTerm term, ByteView record,
                       OpenedEnd &out) {
    ByteView sealed;
    LM_TRY(wire::decode_end_record(record, out.header, sealed));
    if (out.header.plaintext_length > out.plain.size()) {
        return Status::PayloadTooLarge;
    }
    std::array<uint8_t, sec::k_end_aad_bytes> aad{};
    LM_TRY(sec::end_aad(ctx_hash, term, record.first(wire::k_end_header_bytes), aad));
    out.len = 0;
    return rec.open(out.header.end_counter, ByteView{aad}, sealed, MutByteView{out.plain}, out.len,
                    out.verdict);
}

} // namespace lm::delivery
